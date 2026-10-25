"""TArray / TBitArray / TSparseArray / TSet / TMap 원소 위치 계산.

레이아웃은 전부 PDB 에서 가져온다. 원소 값 해석은 inspect.py 가 원소 타입으로 재귀한다.

희소 배열: 지운 칸을 비워 두는 배열. 데이터 배열 + 할당 비트 배열로 되어 있고, 원소는 할당
비트가 1 인 칸만 읽는다. 빈 칸에는 free list 정보가 들어 있어서 원소로 읽으면 안 된다.
검증: 켜진 비트 수 == ArrayNum - NumFreeIndices.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .context import UEContext, UEDecodeError, template_args, template_name

MAX_ELEMENTS_HARD = 1_000_000  # 이보다 크면 쓰레기 값으로 본다

_BASE_SIZES = {
    "bool": 1, "char": 1, "signed char": 1, "unsigned char": 1, "int8": 1, "uint8": 1, "char8_t": 1,
    "short": 2, "unsigned short": 2, "int16": 2, "uint16": 2, "wchar_t": 2, "char16_t": 2,
    "int": 4, "unsigned int": 4, "long": 4, "unsigned long": 4, "int32": 4, "uint32": 4, "float": 4, "char32_t": 4,
    "__int64": 8, "unsigned __int64": 8, "int64": 8, "uint64": 8, "double": 8, "long long": 8, "unsigned long long": 8,
}


# 크기가 템플릿 인자와 무관한 템플릿. 인스턴스 레이아웃이 PDB 에 없으면 같은 템플릿의 다른 인스턴스 크기를 쓴다.
T_INDEPENDENT = {"TMap", "TSet", "TArray", "TSharedPtr", "TSharedRef", "TWeakPtr", "TObjectPtr", "TWeakObjectPtr"}


# 크기가 기본 할당자와 다른 할당자: 인라인·고정 저장소, 64비트 인덱스 (TArray64)
_NON_DEFAULT_ALLOC = re.compile(r"Inline|Fixed|Allocator<64>")


def default_instance(ctx: UEContext, tname: str) -> str | None:
    """PDB 에 레이아웃이 있는, 기본 할당자를 쓰는 tname<...> 인스턴스 하나.

    인라인·고정 할당자 인스턴스는 크기와 멤버 배치가 달라서 대용으로 쓰면 원소 위치가 틀린다.
    그런데 할당 비트 개수 검증은 칸 크기와 무관해 통과해 버리므로 여기서 걸러야 한다.
    """
    for h in ctx.t.dia.find(ctx.pdb, f"{tname}<*", "type", 100):
        if (h.get("size") or 0) > 0 and template_name(h["name"]) == tname and not _NON_DEFAULT_ALLOC.search(h["name"]):
            return h["name"]
    return None


def surrogate_type(ctx: UEContext, type_name: str) -> str | None:
    tname = template_name(type_name)
    if tname not in T_INDEPENDENT or _NON_DEFAULT_ALLOC.search(type_name):
        return None  # 비기본 할당자 인스턴스는 크기가 달라 대용을 쓸 수 없다
    return default_instance(ctx, tname)


def size_of(ctx: UEContext, type_name: str) -> int:
    t = type_name.strip()
    if t.endswith(("*", "&")):
        return 8
    if t in _BASE_SIZES:
        return _BASE_SIZES[t]
    if t.startswith("enum "):
        t = t[5:]
    try:
        return ctx.size_of(t)
    except LookupError:
        if (s := surrogate_type(ctx, t)) is not None:
            return ctx.size_of(s)
        raise


@dataclass
class ArrayView:
    data: int
    count: int
    capacity: int
    element_type: str
    stride: int


def _allocation(ctx: UEContext, alloc_addr: int, alloc_type: str) -> int:
    """할당자 인스턴스에서 데이터 포인터. 힙: Data, 인라인: SecondaryData.Data 가 있으면 그것, 없으면 InlineData."""
    lay = ctx.layout(alloc_type)
    names = {f["name"] for f in lay["fields"]}
    try:
        if "SecondaryData" in names:
            sec = ctx.field(alloc_type, "SecondaryData")
            heap = ctx.u64(alloc_addr + sec.offset + ctx.field(sec.type, "Data").offset)
            return heap or (alloc_addr + ctx.field(alloc_type, "InlineData").offset)
        return ctx.u64(alloc_addr + ctx.field(alloc_type, "Data").offset)
    except UEDecodeError:
        raise UEDecodeError(f"할당자 '{alloc_type[:80]}' 의 형식을 모릅니다.") from None


def tarray(ctx: UEContext, addr: int, array_type: str) -> ArrayView:
    alloc = ctx.field(array_type, "AllocatorInstance")
    num = ctx.i32(addr + ctx.field(array_type, "ArrayNum").offset)
    cap = ctx.i32(addr + ctx.field(array_type, "ArrayMax").offset)
    if not 0 <= num <= max(cap, 0) or cap > MAX_ELEMENTS_HARD:
        raise UEDecodeError(f"TArray 크기가 이상합니다 (Num={num}, Max={cap}).")
    elem = template_args(array_type)[0]
    data = _allocation(ctx, addr + alloc.offset, alloc.type) if num else 0
    return ArrayView(data, num, cap, elem, size_of(ctx, elem))


def tbitarray(ctx: UEContext, addr: int, bit_type: str) -> tuple[bytes, int]:
    alloc = ctx.field(bit_type, "AllocatorInstance")
    num_bits = ctx.i32(addr + ctx.field(bit_type, "NumBits").offset)
    if not 0 <= num_bits <= MAX_ELEMENTS_HARD:
        raise UEDecodeError(f"TBitArray 비트 수가 이상합니다 ({num_bits}).")
    if num_bits == 0:
        return b"", 0
    data = _allocation(ctx, addr + alloc.offset, alloc.type)
    return ctx.read(data, (num_bits + 31) // 32 * 4), num_bits


def sparse_slots(ctx: UEContext, addr: int, sparse_type: str) -> tuple[list[int], str]:
    """할당된 칸의 주소 목록과 원소 타입."""
    data_f = ctx.field(sparse_type, "Data")
    flags_f = ctx.field(sparse_type, "AllocationFlags")
    free = ctx.i32(addr + ctx.field(sparse_type, "NumFreeIndices").offset)
    arr = tarray(ctx, addr + data_f.offset, data_f.type)  # 원소 타입은 TSparseArrayElementOrFreeListLink<...>
    bits, nbits = tbitarray(ctx, addr + flags_f.offset, flags_f.type)
    if nbits != arr.count:
        raise UEDecodeError(f"희소 배열 검증 실패: 비트 수 {nbits} ≠ 칸 수 {arr.count}")
    slots = [arr.data + i * arr.stride for i in range(arr.count) if bits[i >> 3] >> (i & 7) & 1]
    if len(slots) != arr.count - free:
        raise UEDecodeError(f"희소 배열 검증 실패: 할당 비트 {len(slots)} ≠ ArrayNum−NumFreeIndices {arr.count - free}")
    element_type = template_args(sparse_type)[0] if template_name(sparse_type) == "TSparseArray" else None
    if element_type is None:
        raise UEDecodeError(f"'{sparse_type[:80]}' 에서 원소 타입을 알 수 없습니다.")
    return slots, element_type


def set_elements(ctx: UEContext, addr: int, set_type: str) -> list[tuple[int, str]]:
    """TSet 의 원소 (주소, 타입) 목록. 희소 배열 기반(TSparseSet)과 TCompactSet 둘 다."""
    el = ctx.field(set_type, "Elements")
    if template_name(el.type) == "TSparseArray":
        slots, element_type = sparse_slots(ctx, addr + el.offset, el.type)
        value = ctx.field(element_type, "Value")  # TSparseSetElement<T>::Value
        return [(s + value.offset, value.type) for s in slots]
    return compact_elements(ctx, addr, set_type)


def compact_elements(ctx: UEContext, addr: int, set_type: str) -> list[tuple[int, str]]:
    """TCompactSet: 원소 NumElements 개가 빈틈없이 붙어 있고 그 뒤에 해시 테이블이 온다 (CompactSetBase.h)."""
    try:
        el = ctx.field(set_type, "Elements")
        num = ctx.i32(addr + ctx.field(set_type, "NumElements").offset)
        mx = ctx.i32(addr + ctx.field(set_type, "MaxElements").offset)
    except UEDecodeError:
        raise UEDecodeError(f"'{set_type[:80]}' 는 아는 TSet 형식(TSparseSet/TCompactSet)이 아닙니다.") from None
    if not 0 <= num <= max(mx, 0) or mx > MAX_ELEMENTS_HARD:
        raise UEDecodeError(f"TCompactSet 크기가 이상합니다 (NumElements={num}, MaxElements={mx}).")
    element_type = template_args(set_type)[0]
    if num == 0:
        return []
    data = _allocation(ctx, addr + el.offset, el.type)
    stride = size_of(ctx, element_type)
    return [(data + i * stride, element_type) for i in range(num)]


def _align_up(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def structural_map_pairs(ctx: UEContext, addr: int, key_type: str, value_type: str,
                         key_layout: tuple[int, int] | None = None, value_layout: tuple[int, int] | None = None
                         ) -> list[tuple[int, int]]:
    """정확한 TMap 레이아웃이 PDB 에 없을 때 (엔진 내부 전역 등).

    기본 할당자 TMap 은 컨테이너 멤버 배치가 모두 같으므로, PDB 에 있는 아무 TSparseArray 인스턴스에서
    멤버 오프셋을 가져오고, 원소 크기는 키·값의 크기와 정렬로 계산한다:
      TTuple<K,V>          = K @0, V @align(sizeof K, alignof V)
      TSparseSetElement<T> = T @0, HashNextId(int32), HashIndex(int32)
      칸 크기              = max(sizeof 원소, 8) 을 원소 정렬로 올림
    계산이 틀리면 할당 비트 검증에서 걸린다. 반환: [(키 주소, 값 주소)]
    """
    ref = next((h["name"] for h in ctx.t.dia.find(ctx.pdb, "TSparseArray<TSparseSetElement<*", "type", 100)
                if (h.get("size") or 0) > 0 and not _NON_DEFAULT_ALLOC.search(h["name"])), None)
    if ref is None:
        raise UEDecodeError("구조 계산에 쓸 TSparseArray 기준 레이아웃이 PDB 에 없습니다.")
    ks, ka = key_layout or (size_of(ctx, key_type), ctx.align_of(key_type))
    vs, va = value_layout or (size_of(ctx, value_type), ctx.align_of(value_type))
    tup_align = max(ka, va)
    v_off = _align_up(ks, va)
    tup_size = _align_up(v_off + vs, tup_align)
    elem_align = max(tup_align, 4)
    elem_size = _align_up(tup_size + 8, elem_align)
    stride = _align_up(max(elem_size, 8), elem_align)

    data_f, flags_f = ctx.field(ref, "Data"), ctx.field(ref, "AllocationFlags")
    free = ctx.i32(addr + ctx.field(ref, "NumFreeIndices").offset)
    alloc = ctx.field(data_f.type, "AllocatorInstance")
    num = ctx.i32(addr + data_f.offset + ctx.field(data_f.type, "ArrayNum").offset)
    if not 0 <= num <= MAX_ELEMENTS_HARD:
        raise UEDecodeError(f"맵 칸 수가 이상합니다 ({num}).")
    data = _allocation(ctx, addr + data_f.offset + alloc.offset, alloc.type) if num else 0
    bits, nbits = tbitarray(ctx, addr + flags_f.offset, flags_f.type)
    if nbits != num:
        raise UEDecodeError(f"맵 검증 실패: 비트 수 {nbits} ≠ 칸 수 {num}")
    slots = [data + i * stride for i in range(num) if bits[i >> 3] >> (i & 7) & 1]
    if len(slots) != num - free:
        raise UEDecodeError(f"맵 검증 실패: 할당 비트 {len(slots)} ≠ ArrayNum−NumFreeIndices {num - free}")
    return [(s, s + v_off) for s in slots]


def map_pairs(ctx: UEContext, addr: int, map_type: str) -> list[tuple[tuple[int, str], tuple[int, str]]]:
    """TMap 의 ((키 주소, 키 타입), (값 주소, 값 타입)) 목록."""
    try:
        pairs = ctx.field(map_type, "Pairs")
    except (UEDecodeError, LookupError):
        # 이 인스턴스의 레이아웃이 PDB 에 없으면 템플릿 인자로 구조 계산
        args = template_args(map_type)
        if len(args) < 2:
            raise
        return [((k, args[0]), (v, args[1])) for k, v in structural_map_pairs(ctx, addr, args[0], args[1])]
    out = []
    for elem, tuple_type in set_elements(ctx, addr + pairs.offset, pairs.type):
        k, v = ctx.field(tuple_type, "Key"), ctx.field(tuple_type, "Value")
        out.append(((elem + k.offset, k.type), (elem + v.offset, v.type)))
    return out
