"""언리얼 컨테이너 해석기 단위 테스트 (합성 메모리). 에디터 없이 돈다.

    uv run python tests\\test_unreal_decoders.py

TCompactSet 은 실행 중 에디터에서 인스턴스를 붙잡기 어려워(JSON 역직렬화 중에만 잠깐 존재) 여기서 검증한다.
레이아웃은 5.8 게임 PDB 에서 읽은 실제 값을 옮겨 적었다.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from livedbg_mcp.unreal.containers import compact_elements, set_elements  # noqa: E402
from livedbg_mcp.unreal.context import UEContext, UEDecodeError  # noqa: E402


def f(name, off, size, type_, kind="udt", **kw):
    return {"name": name, "offset": off, "size": size, "type": type_, "kind": kind, **kw}


HEAP = "TSizedHeapAllocator<32,FMemory>::ForAnyElementType"
LAYOUTS = {
    # --- TCompactSet (5.8 PDB: TCompactSet<UE::TSharedString<wchar_t>,...>) ---
    "TCompactSet<int32,K,FDefaultCompactSetAllocator>": {"size": 16, "bases": [{"name": "TCompactSetBase<TSizedDefaultAllocator<32> >", "offset": 0}], "fields": []},
    "TCompactSetBase<TSizedDefaultAllocator<32> >": {"size": 16, "bases": [], "fields": [
        f("Elements", 0, 8, "TSizedHeapAllocator<32,FMemory>::ForElementType<unsigned char>"),
        f("NumElements", 8, 4, "int32", "base", base="int"), f("MaxElements", 12, 4, "int32", "base", base="int")]},
    "TSizedHeapAllocator<32,FMemory>::ForElementType<unsigned char>": {"size": 8, "bases": [{"name": HEAP, "offset": 0}], "fields": []},
    HEAP: {"size": 8, "bases": [], "fields": [f("Data", 0, 8, "FScriptContainerElement*", "pointer")]},
    "int32": {"size": 4, "bases": [], "fields": []},
    # --- 희소 배열 기반 TSet (5.8 PDB: TSet<TObjectPtr<UActorComponent>,...>) ---
    "TSet<int32,K,FDefaultSetAllocator>": {"size": 80, "bases": [], "fields": [
        f("Elements", 0, 56, "TSparseArray<TSparseSetElement<int32>,A>")]},
    "TSparseArray<TSparseSetElement<int32>,A>": {"size": 56, "bases": [{"name": "TSparseArrayBase<16,8,A>", "offset": 0}], "fields": []},
    "TSparseArrayBase<16,8,A>": {"size": 56, "bases": [], "fields": [
        f("Data", 0, 16, "TArray<TSparseArrayElementOrFreeListLink<TAlignedBytes<16,8> >,TSizedDefaultAllocator<32> >"),
        f("AllocationFlags", 16, 32, "TBitArray<FDefaultBitArrayAllocator>"),
        f("FirstFreeIndex", 48, 4, "int32", "base"), f("NumFreeIndices", 52, 4, "int32", "base")]},
    "TArray<TSparseArrayElementOrFreeListLink<TAlignedBytes<16,8> >,TSizedDefaultAllocator<32> >": {"size": 16, "bases": [], "fields": [
        f("AllocatorInstance", 0, 8, HEAP), f("ArrayNum", 8, 4, "int32", "base"), f("ArrayMax", 12, 4, "int32", "base")]},
    "TSparseArrayElementOrFreeListLink<TAlignedBytes<16,8> >": {"size": 16, "bases": [], "fields": []},
    "TBitArray<FDefaultBitArrayAllocator>": {"size": 32, "bases": [], "fields": [
        f("AllocatorInstance", 0, 24, "TSizedInlineAllocator<4,32,TSizedDefaultAllocator<32> >::ForElementType<unsigned int>"),
        f("NumBits", 24, 4, "int32", "base"), f("MaxBits", 28, 4, "int32", "base")]},
    "TSizedInlineAllocator<4,32,TSizedDefaultAllocator<32> >::ForElementType<unsigned int>": {"size": 24, "bases": [], "fields": [
        f("InlineData", 0, 16, "uint8[16]", "array"),
        f("SecondaryData", 16, 8, "TSizedHeapAllocator<32,FMemory>::ForElementType<unsigned int>")]},
    "TSizedHeapAllocator<32,FMemory>::ForElementType<unsigned int>": {"size": 8, "bases": [{"name": HEAP, "offset": 0}], "fields": []},
    "TSparseSetElement<int32>": {"size": 12, "bases": [], "fields": [
        f("Value", 0, 4, "int32", "base"), f("HashNextId", 4, 4, "FSetElementId"), f("HashIndex", 8, 4, "int32", "base")]},
}


class FakeCtx(UEContext):
    """메모리와 PDB 레이아웃을 흉내 낸다. 해석 로직(UEContext.field 등)은 실제 코드를 그대로 쓴다."""

    def __init__(self) -> None:  # noqa: D401 - 부모 초기화(프로세스·PDB)를 건너뛴다
        import threading
        self._lock = threading.RLock()
        self._layouts = {}
        self._uobject = {}
        self.mem: dict[int, bytes] = {}

    def put(self, addr: int, data: bytes) -> None:
        self.mem[addr] = data

    def read(self, addr: int, size: int) -> bytes:
        for base, data in self.mem.items():
            if base <= addr and addr + size <= base + len(data):
                return data[addr - base: addr - base + size]
        raise OSError(f"unmapped 0x{addr:X}+{size}")

    def layout(self, type_name: str) -> dict:
        if type_name not in LAYOUTS:
            raise LookupError(type_name)
        return LAYOUTS[type_name]


def check(cond: bool, msg: str) -> None:
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        raise SystemExit(1)


def test_compact_set() -> None:
    ctx = FakeCtx()
    data = 0x20000
    ctx.put(data, struct.pack("<5i", 10, 20, 30, 40, 50) + b"\xEE" * 32)  # 원소 5개 + 뒤따르는 해시 테이블(쓰레기)
    ctx.put(0x10000, struct.pack("<Qii", data, 5, 8))  # Elements.Data, NumElements, MaxElements
    items = compact_elements(ctx, 0x10000, "TCompactSet<int32,K,FDefaultCompactSetAllocator>")
    values = [struct.unpack("<i", ctx.read(a, 4))[0] for a, _ in items]
    check(values == [10, 20, 30, 40, 50], f"TCompactSet elements read contiguously {values}")
    check(set_elements(ctx, 0x10000, "TCompactSet<int32,K,FDefaultCompactSetAllocator>") == items, "set_elements dispatches to compact")

    ctx.put(0x30000, struct.pack("<Qii", data, 9, 8))  # Num > Max → 쓰레기
    try:
        compact_elements(ctx, 0x30000, "TCompactSet<int32,K,FDefaultCompactSetAllocator>")
        check(False, "bad TCompactSet rejected")
    except UEDecodeError:
        check(True, "bad TCompactSet (Num > Max) rejected")

    ctx.put(0x40000, struct.pack("<Qii", 0, 0, 0))
    check(compact_elements(ctx, 0x40000, "TCompactSet<int32,K,FDefaultCompactSetAllocator>") == [], "empty TCompactSet")


def test_sparse_set() -> None:
    ctx = FakeCtx()
    data = 0x50000
    # 칸 4개(16바이트 간격), 1번 칸은 빈 칸(free list). 원소 값 7, (빈칸), 9, 11
    slots = b"".join(struct.pack("<iii4x", v, -1, 0) for v in (7, 0x7FFF, 9, 11))
    ctx.put(data, slots)
    alloc_bits = struct.pack("<I", 0b1101) + b"\0" * 12  # 인라인 비트: 0,2,3 번 칸만 할당
    sparse = struct.pack("<Qii", data, 4, 4) + alloc_bits + struct.pack("<Qii", 0, 4, 128) + struct.pack("<ii", 1, 1)
    ctx.put(0x60000, sparse + b"\0" * 24)
    items = set_elements(ctx, 0x60000, "TSet<int32,K,FDefaultSetAllocator>")
    values = [struct.unpack("<i", ctx.read(a, 4))[0] for a, _ in items]
    check(values == [7, 9, 11], f"sparse TSet skips free slot {values}")

    bad = struct.pack("<Qii", data, 4, 4) + alloc_bits + struct.pack("<Qii", 0, 4, 128) + struct.pack("<ii", 1, 0)
    ctx.put(0x70000, bad + b"\0" * 24)  # NumFreeIndices=0 인데 빈 칸이 하나 → 검증 실패해야
    try:
        set_elements(ctx, 0x70000, "TSet<int32,K,FDefaultSetAllocator>")
        check(False, "inconsistent sparse set rejected")
    except UEDecodeError:
        check(True, "inconsistent sparse set rejected (bits vs NumFreeIndices)")


if __name__ == "__main__":
    test_compact_set()
    test_sparse_set()
