"""언리얼 해석기의 공통 기반.

- 구조체 오프셋은 전부 PDB(DIA)에서 가져온다. 하드코딩하지 않는다.
- 전역 진입점은 UE 가 디버거용으로 모든 모듈에 심는 심볼(GNameBlocksDebug,
  GObjectArrayForDebugVisualizers)을 쓴다. 그래서 엔진 PDB 없이 게임 모듈 PDB 만으로 된다.
- 메모리는 ReadProcessMemory 로 직접 읽는다.
"""

from __future__ import annotations

import re
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .. import win32

if TYPE_CHECKING:
    from ..target import Target


class UEDecodeError(RuntimeError):
    """구조가 예상과 달라 해석을 신뢰할 수 없을 때. 추정값 대신 이 오류를 낸다."""


@dataclass(frozen=True)
class Field:
    name: str
    offset: int  # 바깥 타입 시작 기준 (베이스 클래스 오프셋 포함)
    size: int
    type: str
    info: dict


def template_args(type_name: str) -> list[str]:
    """'TMap<A<B,C>,D>' → ['A<B,C>', 'D']. 최상위 쉼표로만 나눈다."""
    start = type_name.find("<")
    if start < 0 or not type_name.endswith(">"):
        return []
    body, args, depth, cur = type_name[start + 1:-1], [], 0, []
    for ch in body:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if cur:
        args.append("".join(cur).strip())
    return args


def template_name(type_name: str) -> str:
    return type_name.split("<", 1)[0].strip()


class UEContext:
    def __init__(self, target: Target) -> None:
        self.t = target
        self.pid = target.pid
        self._lock = threading.RLock()
        self._layouts: dict[str, dict] = {}
        self._uobject: dict[str, set[str]] = {}
        self.note: str | None = None  # 기준 모듈 선택에서 알릴 것 (게임 모듈 PDB 불일치 등)
        self.module, self.pdb = self._pick_module()
        self.base = self.module.base
        self.cdb_module = self.module.name.rsplit(".", 1)[0].replace("-", "_")

    # ---- 기준 모듈 ----------------------------------------------------------------

    def _pick_module(self) -> tuple[win32.Module, Path]:
        """PDB 에 GNameBlocksDebug 가 있는 모듈. 프로젝트 모듈을 엔진 모듈보다 먼저 본다."""
        mods = [m for m in win32.list_modules(self.pid) if m.name.lower().endswith((".dll", ".exe"))]
        system = ("\\windows\\", "\\windowsapps\\")
        mods = [m for m in mods if not any(s in m.path.lower() for s in system)]

        def rank(m: win32.Module) -> tuple:
            p = m.path.lower()
            # 게임 본체 모듈 → 프로젝트 플러그인 → 엔진. 본체가 가장 확실하고 PDB 도 우리 빌드다.
            return ("\\engine\\" in p, "\\plugins\\" in p, not m.name.lower().startswith("unrealeditor-"), m.name)

        mods.sort(key=rank)
        tried = []
        for m in mods[:40]:
            try:
                cached = self.t._ensure_module(m.name)
            except Exception as e:
                # 게임 본체 모듈을 못 쓰면 알린다. 조용히 넘기면 게임 클래스 필드가 "PDB 에 없음" 으로만 보여
                # 원인(PDB 불일치 등)을 알 수 없다.
                if rank(m)[:3] == (False, False, False) and self.note is None:
                    self.note = (f"게임 모듈 {m.name} 의 PDB 를 쓸 수 없어 다른 모듈을 기준으로 해석합니다. "
                                 f"게임 클래스의 필드는 보이지 않습니다. 원인: {e}")
                continue
            tried.append(m.name)
            hits = self.t.dia.find(cached.path, "GNameBlocksDebug", "data", 1)
            if any(h["name"] == "GNameBlocksDebug" for h in hits):
                return m, cached.path
        raise UEDecodeError(
            "UE 디버그 심볼(GNameBlocksDebug)을 가진 모듈 PDB 를 찾지 못했습니다. "
            f"PDB 가 있는 모듈: {tried or '없음'}"
        )

    # ---- 메모리 ------------------------------------------------------------------

    def read(self, addr: int, size: int) -> bytes:
        return win32.read_memory(self.pid, addr, size)

    def u8(self, addr: int) -> int:
        return self.read(addr, 1)[0]

    def u16(self, addr: int) -> int:
        return struct.unpack("<H", self.read(addr, 2))[0]

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def i32(self, addr: int) -> int:
        return struct.unpack("<i", self.read(addr, 4))[0]

    def u64(self, addr: int) -> int:
        return struct.unpack("<Q", self.read(addr, 8))[0]

    # ---- PDB --------------------------------------------------------------------

    def layout(self, type_name: str) -> dict:
        with self._lock:
            lay = self._layouts.get(type_name)
            if lay is None:
                lay = self.t.dia.layout(self.pdb, type_name)
                self._layouts[type_name] = lay
            return lay

    def enum_info(self, type_name: str) -> dict | None:
        """열거형이면 {'kind': 'enum', 'size', 'signed'}, 아니면 None."""
        name = type_name.strip()
        name = name[5:] if name.startswith("enum ") else name
        key = f"enum|{name}"
        with self._lock:
            if key in self._layouts:
                return self._layouts[key]
        info = self.t.dia.enum_info(self.pdb, name)
        with self._lock:
            self._layouts[key] = info
        return info

    def has_type(self, type_name: str) -> bool:
        try:
            self.layout(type_name)
            return True
        except LookupError:
            return False

    def size_of(self, type_name: str) -> int:
        return self.layout(type_name)["size"]

    def field(self, type_name: str, name: str) -> Field:
        """직접 멤버와 (비가상) 베이스 클래스 멤버를 모두 찾는다."""
        found = self._find_field(type_name, name, 0, set())
        if found is None:
            raise UEDecodeError(f"'{type_name}' 에 필드 '{name}' 이 없습니다 (엔진 구조가 바뀌었을 수 있음).")
        return found

    def _find_field(self, type_name: str, name: str, base_off: int, seen: set) -> Field | None:
        if type_name in seen:
            return None
        seen.add(type_name)
        lay = self.layout(type_name)
        for f in lay["fields"]:
            if f["name"] == name:
                return Field(name, base_off + f["offset"], f["size"], f["type"], f)
        for b in lay["bases"]:
            if b.get("virtual"):
                continue
            try:
                hit = self._find_field(b["name"], name, base_off + b["offset"], seen)
            except LookupError:
                hit = None
            if hit is not None:
                return hit
        return None

    def base_names(self, type_name: str) -> set[str]:
        """베이스 체인의 모든 타입 이름 (자기 자신 포함). 레이아웃이 없으면 자기 자신만."""
        type_name = type_name.strip()
        with self._lock:
            if type_name in self._uobject:
                return self._uobject[type_name]
        out, stack = set(), [type_name]
        while stack:
            n = stack.pop()
            if n in out:
                continue
            out.add(n)
            try:
                stack.extend(b["name"] for b in self.layout(n)["bases"])
            except LookupError:
                pass
        with self._lock:
            self._uobject[type_name] = out
        return out

    def is_uobject(self, type_name: str) -> bool:
        """베이스 체인에 UObjectBase 가 있는가."""
        return "UObjectBase" in self.base_names(type_name)

    def align_of(self, type_name: str) -> int:
        """정렬. PDB 에 정렬 값이 없으므로 멤버의 최대 정렬로 계산한다 (기본형은 크기, 최대 8)."""
        t = type_name.strip()
        if t.endswith(("*", "&")):
            return 8
        from .containers import _BASE_SIZES, surrogate_type
        if t in _BASE_SIZES:
            return min(_BASE_SIZES[t], 8)
        try:
            lay = self.layout(t)
        except LookupError:
            if (s := surrogate_type(self, t)) is None:
                raise
            lay = self.layout(s)
        best = 1
        for b in lay["bases"]:
            best = max(best, self.align_of(b["name"]))
        for f in lay["fields"]:
            kind = f.get("kind")
            if kind == "base" or kind == "enum":
                best = max(best, min(f["size"], 8))
            elif kind == "pointer":
                best = max(best, 8)
            elif kind == "array":
                es = f.get("element_size") or 1
                best = max(best, self.align_of(f["element_type"]) if f.get("element_kind") == "udt" else min(es, 8))
            elif kind == "udt":
                best = max(best, self.align_of(f["type"]))
            if best == 8:
                break
        return best

    def layout_in(self, pdb: Path, type_name: str) -> dict:
        """다른 모듈 PDB 의 레이아웃 (델리게이트 인스턴스처럼 vtable 모듈 기준으로 봐야 하는 경우)."""
        key = f"{pdb}|{type_name}"
        with self._lock:
            lay = self._layouts.get(key)
        if lay is None:
            lay = self.t.dia.layout(pdb, type_name)
            with self._lock:
                self._layouts[key] = lay
        return lay

    def constant(self, name: str) -> int:
        try:
            return self.t.dia.constant(self.pdb, name)
        except LookupError:
            out = self.t.reader.execute(f"dx -r0 {self.cdb_module}!{name}")
            if m := re.search(r":\s*(0x[0-9a-fA-F]+|\d+)", out):
                return int(m.group(1), 0)
            raise UEDecodeError(f"상수 {name} 을 읽지 못했습니다: {out.strip()[-200:]}")

    def global_addr(self, name: str) -> int:
        for hit in self.t.dia.find(self.pdb, name, "data", 5):
            if hit["name"] == name and hit.get("rva"):
                return self.base + hit["rva"]
        raise UEDecodeError(f"{self.module.name} PDB 에 전역 '{name}' 이 없습니다.")

    def export_addr(self, cdb_symbol: str) -> int:
        """엔진 DLL 의 export 심볼 주소 (예: UnrealEditor_Engine!GEngine). 엔진 PDB 없이도 된다."""
        out = self.t.reader.execute(f"x {cdb_symbol}")
        # 예: 00007ffa`8edea2f8 UnrealEditor_Engine!GWorld = <no type information>
        m = re.search(r"^([0-9a-f]{8}`[0-9a-f]{8})\s+" + re.escape(cdb_symbol) + r"(?:\s|$)", out, re.M | re.I)
        if not m:
            raise UEDecodeError(f"export 심볼 {cdb_symbol} 을 찾지 못했습니다: {out.strip()[-200:]}")
        return int(m.group(1).replace("`", ""), 16)
