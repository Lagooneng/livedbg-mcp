"""FName → 문자열.

FName 에는 이름 테이블 인덱스만 있고 문자열은 전역 이름 풀(GNameBlocksDebug)에 있다.
  인덱스 → 블록 = id >> OffsetBits, 블록 안 위치 = (id & mask) * EntryStride → FNameEntry

에디터 빌드(WITH_CASE_PRESERVING_NAME)는 엔트리가 ComparisonId 로 시작한다. 이걸로 검증한다:
비교용 엔트리의 ComparisonId 는 자기 인덱스와 같아야 하고, 표시용 엔트리의 ComparisonId 는
FName 의 ComparisonIndex 와 같아야 한다. 어긋나면 레이아웃 추정이 틀린 것이므로 오류를 낸다.
"""

from __future__ import annotations

import threading

from .context import UEContext, UEDecodeError


def _bits(word: int, f: dict) -> int:
    return (word >> f.get("bit_position", 0)) & ((1 << f.get("bits", f["size"] * 8)) - 1)


class NameResolver:
    def __init__(self, ctx: UEContext) -> None:
        self.ctx = ctx
        self._cache: dict[int, str] = {}
        self._lock = threading.Lock()

        self.blocks = ctx.u64(ctx.global_addr("GNameBlocksDebug"))
        if not self.blocks:
            raise UEDecodeError("GNameBlocksDebug 가 비어 있습니다 (모듈 초기화 전?).")
        self.stride = ctx.constant("FNameDebugVisualizer::EntryStride")
        self.offset_bits = ctx.constant("FNameDebugVisualizer::OffsetBits")
        try:
            self.max_len = ctx.constant("FNameDebugVisualizer::MaxLength")
        except Exception:
            self.max_len = 1024
        self.offset_mask = (1 << self.offset_bits) - 1
        try:  # 인덱스의 블록 부분 비트 수. 이보다 높은 비트가 켜진 id 는 쓰레기다 (NameTypes.h UnusedMask)
            self.id_bits = self.offset_bits + ctx.constant("FNameDebugVisualizer::BlockBits")
        except Exception:
            self.id_bits = None

        entry = ctx.layout("FNameEntry")
        by = {f["name"]: f for f in entry["fields"]}
        self.has_comparison_id = "ComparisonId" in by
        self.off_cid = by["ComparisonId"]["offset"] if self.has_comparison_id else None
        self.off_header = by["Header"]["offset"]
        self.off_chars = by["AnsiName"]["offset"]
        hdr = {f["name"]: f for f in ctx.layout("FNameEntryHeader")["fields"]}
        self.f_wide, self.f_len = hdr["bIsWide"], hdr["Len"]

        fname = {f["name"]: f for f in ctx.layout("FName")["fields"]}
        self.off_cmp = fname["ComparisonIndex"]["offset"]
        self.off_num = fname["Number"]["offset"] if "Number" in fname else None
        self.off_disp = fname["DisplayIndex"]["offset"] if "DisplayIndex" in fname else None
        self.fname_size = ctx.size_of("FName")

    def entry(self, entry_id: int, expect_cid: int | None = None) -> str:
        """이름 풀 엔트리 하나의 문자열. expect_cid 가 있으면 엔트리의 ComparisonId 를 검증한다.

        이름 풀 엔트리는 한 번 만들어지면 바뀌지 않으므로 (문자열, ComparisonId) 를 캐시하고,
        이후 검증은 캐시된 id 로 한다.
        """
        with self._lock:
            hit = self._cache.get(entry_id)
        if hit is None:
            hit = self._read_entry(entry_id)
            with self._lock:
                self._cache[entry_id] = hit
        text, cid = hit
        if expect_cid is not None and cid is not None and cid != expect_cid:
            raise UEDecodeError(
                f"FName 엔트리 0x{entry_id:X} 검증 실패: ComparisonId 0x{cid:X} ≠ 기대 0x{expect_cid:X} "
                "(이름 풀 레이아웃이 예상과 다름)")
        return text

    def _read_entry(self, entry_id: int) -> tuple[str, int | None]:
        if self.id_bits is not None and entry_id >> self.id_bits:
            raise UEDecodeError(f"FName 엔트리 0x{entry_id:X}: 블록 범위를 벗어난 인덱스 (쓰레기 FName)")
        block, offset = entry_id >> self.offset_bits, entry_id & self.offset_mask
        base = self.ctx.u64(self.blocks + block * 8)
        if not base:
            raise UEDecodeError(f"FName 엔트리 0x{entry_id:X}: 블록 {block} 이 비어 있습니다.")
        addr = base + offset * self.stride
        # ComparisonId(있으면) 와 헤더를 한 번에 읽는다
        head = self.ctx.read(addr, self.off_header + 2)
        cid = int.from_bytes(head[self.off_cid:self.off_cid + 4], "little") if self.has_comparison_id else None
        header = int.from_bytes(head[self.off_header:self.off_header + 2], "little")
        wide, length = _bits(header, self.f_wide), _bits(header, self.f_len)
        if length == 0:
            raise UEDecodeError(f"FName 엔트리 0x{entry_id:X}: 길이 0 (outline number 엔트리는 지원하지 않음)")
        if length > self.max_len:
            raise UEDecodeError(f"FName 엔트리 0x{entry_id:X}: 길이 {length} > {self.max_len}")
        raw = self.ctx.read(addr + self.off_chars, length * (2 if wide else 1))
        try:
            text = raw.decode("utf-16-le" if wide else "latin-1")  # utf-16 은 짝 없는 서로게이트면 실패
        except UnicodeDecodeError:
            raise UEDecodeError(f"FName 엔트리 0x{entry_id:X}: 문자열이 올바른 UTF-16 이 아닙니다") from None
        # ComparisonId 가 없는 빌드(패키지 Development 등)는 id 검증을 못 하므로 내용으로라도 걸러낸다
        if not self.has_comparison_id and any(ord(ch) < 0x20 for ch in text):
            raise UEDecodeError(f"FName 엔트리 0x{entry_id:X}: 제어 문자가 섞여 있습니다 (쓰레기 FName)")
        return text, cid

    def resolve(self, comparison: int, number: int = 0, display: int | None = None) -> str:
        if comparison == 0 and number == 0 and (display in (None, 0)):
            return "None"
        # 비교용 엔트리는 자기 자신을 가리켜야 한다 (에디터 빌드에서만 검증 가능)
        base = self.entry(comparison, expect_cid=comparison if self.has_comparison_id else None)
        if display not in (None, comparison):
            base = self.entry(display, expect_cid=comparison if self.has_comparison_id else None)
        return base if number == 0 else f"{base}_{number - 1}"

    def at(self, addr: int) -> str:
        """메모리에 있는 FName 하나."""
        raw = self.ctx.read(addr, self.fname_size)
        u32 = lambda off: int.from_bytes(raw[off:off + 4], "little")
        cmp_ = u32(self.off_cmp)
        num = u32(self.off_num) if self.off_num is not None else 0
        disp = u32(self.off_disp) if self.off_disp is not None else None
        return self.resolve(cmp_, num, disp)
