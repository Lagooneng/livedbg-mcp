"""UObject 신원, 전역 객체 배열, TWeakObjectPtr.

검증: UObject 의 InternalIndex 로 전역 객체 배열 항목을 찾아 그 항목의 Object 가 이 주소인지
확인한다. 쓰레기 포인터나 파괴된 객체는 여기서 걸러진다.
"""

from __future__ import annotations

import struct
import threading

from .context import UEContext, UEDecodeError
from .names import NameResolver

CHUNK = 64 * 1024  # FChunkedFixedUObjectArray::NumElementsPerChunk (enum 이라 PDB 상수로 안 잡힘. 검증으로 보완)
MAX_OUTER_DEPTH = 32


class ObjectResolver:
    def __init__(self, ctx: UEContext, names: NameResolver) -> None:
        self.ctx, self.names = ctx, names
        self._class_names: dict[int, str] = {}
        self._lock = threading.Lock()

        arr_t = "FChunkedFixedUObjectArray"
        self.f_objects = ctx.field(arr_t, "Objects").offset
        self.f_num = ctx.field(arr_t, "NumElements").offset
        self.f_max = ctx.field(arr_t, "MaxElements").offset

        item = ctx.layout("FUObjectItem")
        self.item_size = item["size"]
        obj = ctx.field("FUObjectItem", "Object")
        if obj.size != 8:
            raise UEDecodeError("FUObjectItem.Object 가 압축 포인터 형식입니다 (지원하지 않음).")
        self.f_item_obj = obj.offset
        self.f_item_serial = ctx.field("FUObjectItem", "SerialNumber").offset

        self.f_index = ctx.field("UObjectBase", "InternalIndex").offset
        self.f_class = ctx.field("UObjectBase", "ClassPrivate").offset
        self.f_outer = ctx.field("UObjectBase", "OuterPrivate").offset
        name_priv = ctx.field("UObjectBase", "NamePrivate")
        self.f_name = name_priv.offset + (ctx.field(name_priv.type, "Name").offset if name_priv.type != "FName" else 0)

        # GObjectArrayForDebugVisualizers 는 FChunkedFixedUObjectArray*& (포인터에 대한 참조).
        # 참조 전역의 저장소에는 "포인터 변수의 주소" 가 들어 있다 → 두 번 따라간다.
        ref = ctx.global_addr("GObjectArrayForDebugVisualizers")
        self.array = self._pick_array(ref)

    def _pick_array(self, ref: int) -> int:
        cands = []
        p1 = self.ctx.u64(ref)
        if p1:
            cands.append(self.ctx.u64(p1))
            cands.append(p1)
        for a in cands:
            if not a:
                continue
            try:
                num, mx = self.ctx.i32(a + self.f_num), self.ctx.i32(a + self.f_max)
            except OSError:
                continue
            if 0 < num <= mx <= (1 << 31) - 1:
                return a
        raise UEDecodeError("전역 객체 배열(GObjectArrayForDebugVisualizers)을 해석하지 못했습니다.")

    # ---- 객체 배열 ----------------------------------------------------------------

    @property
    def num_elements(self) -> int:
        return self.ctx.i32(self.array + self.f_num)

    def item(self, index: int) -> tuple[int, int]:
        """(Object 주소, SerialNumber)"""
        if not 0 <= index < self.num_elements:
            raise UEDecodeError(f"객체 인덱스 {index} 가 범위 밖입니다 (NumElements={self.num_elements}).")
        chunks = self.ctx.u64(self.array + self.f_objects)
        chunk = self.ctx.u64(chunks + (index // CHUNK) * 8)
        if not chunk:
            raise UEDecodeError(f"객체 인덱스 {index} 의 청크가 비어 있습니다.")
        raw = self.ctx.read(chunk + (index % CHUNK) * self.item_size, self.item_size)
        obj = struct.unpack_from("<Q", raw, self.f_item_obj)[0]
        serial = struct.unpack_from("<i", raw, self.f_item_serial)[0]
        return obj, serial

    # ---- UObject 신원 --------------------------------------------------------------

    def _check(self, addr: int) -> int:
        """주소가 살아 있는 UObject 인지 검증하고 InternalIndex 를 돌려준다."""
        try:
            index = self.ctx.i32(addr + self.f_index)
        except OSError as e:
            raise UEDecodeError(f"0x{addr:X} 를 읽을 수 없습니다: {e}") from None
        obj, _ = self.item(index) if 0 <= index < self.num_elements else (None, 0)
        if obj != addr:
            raise UEDecodeError(f"0x{addr:X} 는 살아 있는 UObject 가 아닙니다 (객체 배열[{index}] ≠ 이 주소).")
        return index

    def name(self, addr: int) -> str:
        return self.names.at(addr + self.f_name)

    def class_name(self, addr: int) -> str:
        cls = self.ctx.u64(addr + self.f_class)
        with self._lock:
            hit = self._class_names.get(cls)
        if hit is None:
            self._check(cls)
            hit = self.name(cls)
            with self._lock:
                self._class_names[cls] = hit
        return hit

    def path(self, addr: int) -> str:
        """UObject::GetPathName 과 같은 규칙: 패키지 뒤는 '.', 최상위 에셋의 하위 객체 앞은 ':'."""
        chain = []
        cur = addr
        for _ in range(MAX_OUTER_DEPTH):
            if not cur:
                break
            chain.append(cur)
            cur = self.ctx.u64(cur + self.f_outer)
        chain.reverse()
        out = ""
        for i, obj in enumerate(chain):
            n = self.name(obj)
            if i == 0:
                out = n
                continue
            parent = chain[i - 1]
            grand_is_package = i >= 2 and self.class_name(chain[i - 2]) == "Package"
            sep = ":" if (self.class_name(parent) != "Package" and grand_is_package) else "."
            out += sep + n
        return out

    def identity(self, addr: int) -> dict:
        if not addr:
            return None
        index = self._check(addr)
        return {"address": f"0x{addr:X}", "name": self.name(addr), "class": self.class_name(addr),
                "path": self.path(addr), "index": index}

    # ---- TWeakObjectPtr -------------------------------------------------------------

    def weak(self, addr: int) -> dict | None:
        """FWeakObjectPtr(또는 그것을 첫 멤버로 가진 TWeakObjectPtr) 해석."""
        idx_off = self.ctx.field("FWeakObjectPtr", "ObjectIndex").offset
        ser_off = self.ctx.field("FWeakObjectPtr", "ObjectSerialNumber").offset
        raw = self.ctx.read(addr, self.ctx.size_of("FWeakObjectPtr"))
        index, serial = struct.unpack_from("<i", raw, idx_off)[0], struct.unpack_from("<i", raw, ser_off)[0]
        if serial == 0:
            return None  # 한 번도 설정되지 않았거나 명시적으로 비운 약참조
        obj, item_serial = self.item(index)
        if item_serial != serial or not obj:
            return {"stale": True, "index": index, "serial": serial,
                    "note": "가리키던 객체가 파괴됨 (시리얼 불일치)"}
        return self.identity(obj)

    # ---- 검색 -------------------------------------------------------------------

    def find(self, name: str = "", class_name: str = "", limit: int = 50, exact: bool = False) -> dict:
        """전역 객체 배열을 청크 단위로 읽어 이름·클래스로 찾는다."""
        name_l, cls_l = name.lower(), class_name.lower()
        match = (lambda s, q: s.lower() == q) if exact else (lambda s, q: q in s.lower())
        num = self.num_elements
        chunks = self.ctx.u64(self.array + self.f_objects)
        results, scanned, skipped = [], 0, 0
        for c in range((num + CHUNK - 1) // CHUNK):
            chunk = self.ctx.u64(chunks + c * 8)
            if not chunk:
                continue
            count = min(CHUNK, num - c * CHUNK)
            raw = self.ctx.read(chunk, count * self.item_size)
            for i in range(count):
                obj = struct.unpack_from("<Q", raw, i * self.item_size + self.f_item_obj)[0]
                if not obj:
                    continue
                scanned += 1
                try:
                    if cls_l and not match(self.class_name(obj), cls_l):
                        continue
                    n = self.name(obj)
                    if name_l and not match(n, name_l):
                        continue
                    results.append(self.identity(obj))
                except (UEDecodeError, OSError):
                    skipped += 1  # 스캔 도중 파괴된 객체 등
                    continue
                if len(results) >= limit:
                    return {"results": results, "scanned": scanned, "total": num, "truncated": True, "skipped": skipped}
        return {"results": results, "scanned": scanned, "total": num, "truncated": False, "skipped": skipped}
