"""DIA(msdia140.dll) 를 COM 등록 없이 쓰는 심볼·타입 조회.

DIA 객체의 스레드 안전성은 문서가 보장하지 않으므로 모든 호출을 전용 스레드 하나에서 한다.
세션은 캐시된 PDB 사본만 연다 (symcache 참고). 원본 PDB 를 열면 빌드가 막힌다.
"""

from __future__ import annotations

import ctypes
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .config import msdia_path
from .win32 import PdbId

# SymTag
TAG_FUNCTION, TAG_DATA, TAG_PUBLIC, TAG_UDT, TAG_ENUM = 5, 7, 10, 11, 12
TAG_FUNCTIONTYPE, TAG_POINTER, TAG_ARRAY, TAG_BASETYPE, TAG_TYPEDEF, TAG_BASECLASS = 13, 14, 15, 16, 17, 18
# NameSearchOptions
NSF_CASE_SENSITIVE, NSF_CASE_INSENSITIVE, NSF_REGEX = 0x1, 0x2, 0x8
LOC_BITFIELD = 6

KINDS = {
    "type": (TAG_UDT, TAG_ENUM, TAG_TYPEDEF),
    "function": (TAG_FUNCTION,),
    "data": (TAG_DATA,),
    "public": (TAG_PUBLIC,),
}

_BASETYPES = {
    1: "void", 2: "char", 3: "wchar_t", 10: "bool", 31: "HRESULT", 32: "char16_t", 33: "char32_t", 34: "char8_t",
}
_INT_BY_SIZE = {1: "int8", 2: "int16", 4: "int32", 8: "int64", 16: "int128"}


def _get(sym, attr: str, default: Any = None) -> Any:
    try:
        v = getattr(sym, attr)
    except Exception:
        return default
    return default if v is None else v


def type_name(t) -> str:
    if t is None:
        return "?"
    tag = _get(t, "symTag", 0)
    if tag == TAG_BASETYPE:
        bt, size = _get(t, "baseType", 0), _get(t, "length", 0)
        if bt in (6, 13):  # int, long
            return _INT_BY_SIZE.get(size, f"int{size * 8}")
        if bt in (7, 14):  # uint, ulong
            return "u" + _INT_BY_SIZE.get(size, f"int{size * 8}")
        if bt == 8:
            return {4: "float", 8: "double"}.get(size, f"float{size * 8}")
        return _BASETYPES.get(bt, f"basetype{bt}")
    if tag == TAG_POINTER:
        return type_name(_get(t, "type")) + ("&" if _get(t, "reference", False) else "*")
    if tag == TAG_ARRAY:
        return f"{type_name(_get(t, 'type'))}[{_get(t, 'count', 0)}]"
    if tag == TAG_FUNCTIONTYPE:
        return f"{type_name(_get(t, 'type'))}(*)(...)"
    return _get(t, "name", f"<symtag {tag}>")


def type_info(t) -> dict:
    """해석기가 분기에 쓰는 타입 분류. kind: base | pointer | udt | enum | array | function | other"""
    tag = _get(t, "symTag", 0)
    if tag == TAG_BASETYPE:
        bt = _get(t, "baseType", 0)
        base = ("int" if bt in (6, 13) else "uint" if bt in (7, 14) else "float" if bt == 8
                else "bool" if bt == 10 else "char" if bt in (2, 3, 32, 33, 34) else "void" if bt == 1 else "other")
        return {"kind": "base", "base": base}
    if tag == TAG_POINTER:
        return {"kind": "pointer", "pointee": type_name(_get(t, "type"))}
    if tag == TAG_ARRAY:
        et = _get(t, "type")
        return {"kind": "array", "element_type": type_name(et), "element_size": _get(et, "length", 0),
                "count": _get(t, "count", 0), **{"element_" + k: v for k, v in type_info(et).items()}}
    if tag == TAG_ENUM:
        return {"kind": "enum", "signed": _enum_signed(t)}
    if tag == TAG_UDT:
        return {"kind": "udt"}
    if tag == TAG_FUNCTIONTYPE:
        return {"kind": "function"}
    if tag == TAG_TYPEDEF:
        return type_info(_get(t, "type"))
    return {"kind": "other"}


def _enum_signed(t) -> bool:
    """열거형의 기반 타입이 부호 있는가 (enum class E : uint8 → False)."""
    u = _get(t, "type")
    return u is None or type_info(u).get("base") not in ("uint", "bool")


def _children(parent, tag: int, name: str | None = None, flags: int = 0, limit: int | None = None):
    enum = parent.findChildren(tag, name, flags)
    n = enum.Count if limit is None else min(enum.Count, limit)
    for i in range(n):
        yield enum.Item(i)


class DiaService:
    def __init__(self) -> None:
        self._ex = ThreadPoolExecutor(max_workers=1, thread_name_prefix="dia", initializer=self._init_thread)
        self._sessions: dict[str, Any] = {}
        self._lib = None
        self._factory = None
        self._lock = threading.Lock()

    # ---- 전용 스레드에서만 호출 --------------------------------------------------

    def _init_thread(self) -> None:
        import logging

        import comtypes

        logging.getLogger("comtypes").setLevel(logging.WARNING)  # 타입 라이브러리 캐시 INFO 로그가 시끄럽다
        comtypes.CoInitialize()

    def _source(self):
        import comtypes.client
        from comtypes import GUID
        from comtypes.server import IClassFactory

        if self._factory is None:
            path = str(msdia_path())
            self._lib = comtypes.client.GetModule(path)
            dll = ctypes.OleDLL(path)
            factory = ctypes.POINTER(IClassFactory)()
            clsid = GUID(str(self._lib.DiaSource._reg_clsid_))
            dll.DllGetClassObject(ctypes.byref(clsid), ctypes.byref(IClassFactory._iid_), ctypes.byref(factory))
            self._factory = factory
        return self._factory.CreateInstance(interface=self._lib.IDiaDataSource)

    def _validate(self, path: Path, pdb: PdbId) -> bool:
        from comtypes import GUID, COMError

        ds = self._source()
        guid = GUID("{" + str(pdb.guid) + "}")
        try:
            ds.loadAndValidateDataFromPdb(str(path), ctypes.byref(guid), 0, pdb.age)
            return True
        except COMError:
            return False
        finally:
            del ds  # 세션을 열지 않았으므로 여기서 파일 핸들이 닫힌다

    def _session(self, path: Path):
        key = str(path).lower()
        s = self._sessions.get(key)
        if s is None:
            ds = self._source()
            ds.loadDataFromPdb(str(path))
            s = ds.openSession()
            self._sessions[key] = s
        return s

    def _find(self, path: Path, pattern: str, kind: str, limit: int) -> list[dict]:
        g = self._session(path).globalScope
        tags = KINDS.get(kind) or tuple(t for ts in KINDS.values() for t in ts)
        flags = NSF_REGEX | NSF_CASE_INSENSITIVE if any(c in pattern for c in "*?") else NSF_CASE_SENSITIVE
        out: list[dict] = []
        seen: set[tuple] = set()
        for tag in tags:
            for sym in _children(g, tag, pattern, flags):
                if len(out) >= limit:
                    break
                name = _get(sym, "name")
                # 같은 UDT 가 컴파일 단위마다 여러 번 나온다 (전방 선언 · 정의). 이름+크기+RVA 로 합친다.
                key = (tag, name, _get(sym, "length", 0), _get(sym, "relativeVirtualAddress", 0))
                if key in seen:
                    continue
                seen.add(key)
                item = {"name": name, "kind": _tag_kind(tag)}
                if (rva := _get(sym, "relativeVirtualAddress", 0)):
                    item["rva"] = rva
                if tag in (TAG_UDT, TAG_ENUM):
                    item["size"] = _get(sym, "length", 0)
                elif tag in (TAG_DATA, TAG_FUNCTION, TAG_TYPEDEF):
                    item["type"] = type_name(_get(sym, "type"))
                if tag == TAG_PUBLIC and (u := _get(sym, "undecoratedName")):
                    item["undecorated"] = u
                out.append(item)
            if len(out) >= limit:
                break
        return out

    def _layout(self, path: Path, name: str) -> dict:
        g = self._session(path).globalScope
        # 같은 이름의 UDT 가 전방 선언(크기 0) 레코드로도 나온다. 정의가 있는 것을 고른다.
        udt = None
        for cand in _children(g, TAG_UDT, name, NSF_CASE_SENSITIVE):
            if _get(cand, "length", 0) > 0:
                udt = cand
                break
        if udt is None:
            raise LookupError(f"타입 '{name}' 이 PDB 에 없습니다.")
        return self._udt_dict(udt)

    def _udt_dict(self, udt) -> dict:
        bases = [
            {"name": type_name(_get(b, "type")) if _get(b, "type") is not None else _get(b, "name"),
             "offset": _get(b, "offset", 0), "virtual": bool(_get(b, "virtualBaseClass", False))}
            for b in _children(udt, TAG_BASECLASS)
        ]
        fields = []
        for f in _children(udt, TAG_DATA):
            if _get(f, "dataKind") != 7:  # DataIsMember 만 (정적 멤버 제외)
                continue
            t = _get(f, "type")
            item = {"name": _get(f, "name"), "offset": _get(f, "offset", 0), "size": _get(t, "length", 0), "type": type_name(t)}
            item.update(type_info(t))
            if _get(f, "locationType") == LOC_BITFIELD:
                item["bit_position"] = _get(f, "bitPosition", 0)
                item["bits"] = _get(f, "length", 0)
            fields.append(item)
        fields.sort(key=lambda x: (x["offset"], x.get("bit_position", 0)))
        return {"name": _get(udt, "name"), "size": _get(udt, "length", 0), "bases": bases, "fields": fields}

    def _enum_info(self, path: Path, name: str) -> dict | None:
        g = self._session(path).globalScope
        for e in _children(g, TAG_ENUM, name, NSF_CASE_SENSITIVE, 5):
            if (size := _get(e, "length", 0)) > 0:
                return {"kind": "enum", "size": size, "signed": _enum_signed(e)}
        return None

    def _constant(self, path: Path, name: str) -> int:
        """static constexpr 멤버처럼 PDB 에 값으로만 들어 있는 상수 (LocIsConstant)."""
        g = self._session(path).globalScope
        for sym in _children(g, TAG_DATA, name, NSF_CASE_SENSITIVE, 1):
            v = _get(sym, "value")
            if v is not None:
                return int(v)
        # 클래스 스코프 상수는 전역 검색에 안 잡히는 경우가 있다: Class::Member 로 나눠 찾는다
        if "::" in name:
            cls, member = name.rsplit("::", 1)
            for udt in _children(g, TAG_UDT, cls, NSF_CASE_SENSITIVE):
                for sym in _children(udt, TAG_DATA, member, NSF_CASE_SENSITIVE):
                    v = _get(sym, "value")
                    if v is not None:
                        return int(v)
        raise LookupError(f"상수 '{name}' 이 PDB 에 없습니다.")

    def _at_rva(self, path: Path, rva: int) -> dict | None:
        s = self._session(path)
        for tag in (TAG_FUNCTION, TAG_DATA, TAG_PUBLIC):
            sym = s.findSymbolByRVA(rva, tag)
            if sym is None or _get(sym, "name") is None:
                continue
            base = _get(sym, "relativeVirtualAddress", rva)
            length = _get(sym, "length", 0)
            if tag != TAG_PUBLIC and length and not base <= rva < base + length:
                continue
            item = {"name": _get(sym, "name"), "kind": _tag_kind(tag), "displacement": rva - base}
            if (u := _get(sym, "undecoratedName")) and u != item["name"]:
                item["undecorated"] = u
            if tag == TAG_DATA:
                item["type"] = type_name(_get(sym, "type"))
            return item
        return None

    # ---- 공개 API (어느 스레드에서나) --------------------------------------------

    def _call(self, fn, *args):
        return self._ex.submit(fn, *args).result()

    def validate(self, path: Path, pdb: PdbId) -> bool:
        return self._call(self._validate, path, pdb)

    def find(self, path: Path, pattern: str, kind: str = "any", limit: int = 50) -> list[dict]:
        return self._call(self._find, path, pattern, kind, limit)

    def layout(self, path: Path, type_name_: str) -> dict:
        return self._call(self._layout, path, type_name_)

    def at_rva(self, path: Path, rva: int) -> dict | None:
        return self._call(self._at_rva, path, rva)

    def constant(self, path: Path, name: str) -> int:
        return self._call(self._constant, path, name)

    def enum_info(self, path: Path, name: str) -> dict | None:
        """열거형의 크기와 부호. 없으면 None."""
        return self._call(self._enum_info, path, name)

    def close(self, path: Path | None = None) -> None:
        def _close():
            if path is None:
                self._sessions.clear()
            else:
                self._sessions.pop(str(path).lower(), None)
        self._call(_close)


def _tag_kind(tag: int) -> str:
    return {TAG_UDT: "type", TAG_ENUM: "enum", TAG_TYPEDEF: "typedef", TAG_FUNCTION: "function",
            TAG_DATA: "data", TAG_PUBLIC: "public"}.get(tag, str(tag))
