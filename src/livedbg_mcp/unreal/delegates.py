"""델리게이트 바인딩.

동적  DECLARE_DYNAMIC_(MULTICAST_)DELEGATE   바인딩 = (약참조 객체, 함수 FName). InvocationList 에 그대로 있다.
희소  DECLARE_DYNAMIC_MULTICAST_SPARSE_DELEGATE 객체 안에는 bIsBound 1바이트뿐. 바인딩은 전역
      FSparseDelegateStorage::SparseDelegates[소유 객체][델리게이트 이름] 에 있다 (COREUOBJECT_API 로 export).
네이티브 DECLARE_(MULTICAST_)DELEGATE       바인딩마다 델리게이트 인스턴스 객체. 종류(UObject 메서드, raw 메서드,
      람다, 정적 함수 ...)는 인스턴스의 vtable 심볼로 판별하고, 그 모듈 PDB 레이아웃으로 대상과 함수를 읽는다.
"""

from __future__ import annotations

import re
from pathlib import Path

from .. import win32
from .containers import _allocation, default_instance, structural_map_pairs, tarray
from .context import UEContext, UEDecodeError, template_args, template_name
from .names import NameResolver
from .objects import ObjectResolver

INSTANCE_KINDS = {
    "TBaseUObjectMethodDelegateInstance": "uobject_method",
    "TBaseRawMethodDelegateInstance": "raw_method",
    "TBaseSPMethodDelegateInstance": "sp_method",
    "TBaseSPLambdaDelegateInstance": "sp_lambda",
    "TBaseStaticDelegateInstance": "static",
    "TBaseFunctorDelegateInstance": "lambda",
    "TWeakBaseFunctorDelegateInstance": "weak_lambda",
    "TBaseUFunctionDelegateInstance": "ufunction",
}


def _normalize(name: str) -> str:
    return re.sub(r"\b(class|struct|enum|union)\s+", "", name).replace(" ", "")


class DelegateResolver:
    def __init__(self, ctx: UEContext, names: NameResolver, objects: ObjectResolver) -> None:
        self.ctx, self.names, self.objects = ctx, names, objects
        self._storage: int | None = None
        self._offsets: list[tuple[str, str, int]] | None = None

    # ---- 분류 --------------------------------------------------------------------

    def kind_of(self, type_name: str) -> str | None:
        bases = self.ctx.base_names(type_name)
        tnames = {template_name(b) for b in bases}
        if "FSparseDelegate" in tnames or "TSparseDynamicDelegate" in tnames:
            return "sparse"
        if tnames & {"TMulticastScriptDelegate", "FMulticastScriptDelegate"}:
            return "dynamic_multicast"
        if tnames & {"TScriptDelegate", "FScriptDelegate"}:
            return "dynamic"
        if tnames & {"TMulticastDelegate", "TMulticastDelegateBase"}:
            return "native_multicast"
        if tnames & {"TDelegate", "TDelegateBase"}:
            return "native"
        return None

    # ---- 동적 --------------------------------------------------------------------

    def script_delegate(self, addr: int, type_name: str) -> dict | None:
        obj = self.ctx.field(type_name, "Object")
        fn = self.ctx.field(type_name, "FunctionName")
        function = self.names.at(addr + fn.offset)
        target = self.objects.weak(addr + obj.offset)
        if function == "None" and target is None:
            return None
        return {"object": target, "function": function}

    def multicast_script(self, addr: int, type_name: str) -> list[dict]:
        inv = self.ctx.field(type_name, "InvocationList")
        arr = tarray(self.ctx, addr + inv.offset, inv.type)
        out = []
        for i in range(arr.count):
            b = self.script_delegate(arr.data + i * arr.stride, arr.element_type)
            if b is not None:
                out.append(b)
        return out

    # ---- 희소 --------------------------------------------------------------------

    def _global(self, qualified: str) -> int:
        try:
            return self.ctx.global_addr(qualified)  # 모놀리식 빌드: 기준 모듈 PDB 에 있다
        except UEDecodeError:
            return self.ctx.export_addr(f"UnrealEditor_CoreUObject!{qualified}")

    def sparse_bindings(self, owner: int, delegate_name: str) -> list[dict]:
        if self._storage is None:
            self._storage = self._global("FSparseDelegateStorage::SparseDelegates")
        # TMap<const UObjectBase*, TMap<FName, TSharedPtr<FMulticastScriptDelegate>>> — 인스턴스 레이아웃이 PDB 에 없어 구조 계산
        map_size = self.ctx.size_of(self._surrogate("TMap"))
        for key_addr, value_addr in structural_map_pairs(self.ctx, self._storage, "UObjectBase const *", "TMap",
                                                         (8, 8), (map_size, 8)):
            if self.ctx.u64(key_addr) != owner:
                continue
            fname = self.ctx.size_of("FName")
            for k, v in structural_map_pairs(self.ctx, value_addr, "FName", "TSharedPtr", (fname, 4), (16, 8)):
                if self.names.at(k) != delegate_name:
                    continue
                ptr = self.ctx.u64(v)  # TSharedPtr::Object
                return self.multicast_script(ptr, self._multicast_script_type()) if ptr else []
            return []
        return []

    def _surrogate(self, tname: str) -> str:
        if (name := default_instance(self.ctx, tname)) is None:
            raise UEDecodeError(f"{tname} 기준 레이아웃(기본 할당자)이 PDB 에 없습니다.")
        return name

    def _multicast_script_type(self) -> str:
        for cand in ("TMulticastScriptDelegate<FNotThreadSafeDelegateMode>", "FMulticastScriptDelegate"):
            if self.ctx.has_type(cand):
                return cand
        raise UEDecodeError("TMulticastScriptDelegate 레이아웃이 PDB 에 없습니다.")

    def sparse_owner(self, addr: int) -> tuple[int, str]:
        """희소 델리게이트 필드 주소 → (소유 객체, 델리게이트 이름). 등록 오프셋 맵으로 역산하고 UObject 검증."""
        if self._offsets is None:
            table = self._global("FSparseDelegateStorage::SparseDelegateObjectOffsets")
            fname = self.ctx.size_of("FName")
            rows = []
            for k, v in structural_map_pairs(self.ctx, table, "TTuple<FName,FName>", "unsigned __int64",
                                             (fname * 2, 4), (8, 8)):
                rows.append((self.names.at(k), self.names.at(k + fname), self.ctx.u64(v)))
            self._offsets = rows
        for cls, name, off in self._offsets:
            owner = addr - off
            try:
                self.objects._check(owner)
            except (UEDecodeError, OSError):
                continue
            if cls in self._class_chain(owner):
                return owner, name
        raise UEDecodeError("희소 델리게이트의 소유 객체를 찾지 못했습니다 (등록된 오프셋과 맞는 UObject 없음).")

    def _class_chain(self, obj: int) -> set[str]:
        """객체 클래스와 상위 클래스 이름들 (UStruct::SuperStruct 체인)."""
        out = set()
        cls = self.ctx.u64(obj + self.objects.f_class)
        sup = self.ctx.field("UStruct", "SuperStruct").offset
        for _ in range(64):
            if not cls:
                break
            out.add(self.objects.name(cls))
            cls = self.ctx.u64(cls + sup)
        return out

    # ---- 네이티브 ------------------------------------------------------------------

    def native_multicast(self, addr: int, type_name: str) -> list[dict]:
        inv = self.ctx.field(type_name, "InvocationList")
        arr = tarray(self.ctx, addr + inv.offset, inv.type)
        out = []
        for i in range(arr.count):
            b = self.native_single(arr.data + i * arr.stride, arr.element_type)
            if b is not None:
                out.append(b)
        return out

    def native_single(self, addr: int, type_name: str) -> dict | None:
        alloc = self.ctx.field(type_name, "DelegateAllocator")
        size = self.ctx.i32(addr + self.ctx.field(type_name, "DelegateSize").offset)
        if size == 0:
            return None
        inst = _allocation(self.ctx, addr + alloc.offset, alloc.type)
        return self.instance(inst) if inst else None

    def instance(self, inst: int) -> dict:
        t = self.ctx.t
        vptr = self.ctx.u64(inst)
        try:
            mod = win32.find_module(self.ctx.pid, vptr)
        except LookupError:
            return {"kind": "unknown", "note": f"vptr 0x{vptr:X} 가 모듈 밖입니다 (파괴된 인스턴스?)"}
        try:
            pdb = t._ensure_module(mod.name).path
        except Exception as e:
            return {"kind": "unknown", "module": mod.name, "note": f"이 모듈 PDB 가 없어 종류를 알 수 없습니다 ({str(e)[:80]})"}
        sym = t.dia.at_rva(pdb, vptr - mod.base) or {}
        vt = sym.get("undecorated") or sym.get("name") or ""
        m = re.match(r"(?:const\s+)?(.+)::`vftable'", vt)
        if not m:
            return {"kind": "unknown", "module": mod.name, "vtable": vt or f"0x{vptr:X}"}
        cls = m.group(1)
        kind = INSTANCE_KINDS.get(template_name(_normalize(cls)), "other")
        out = {"kind": kind, "instance_class": _normalize(cls)[:200]}
        lay_name = self._resolve_udt(pdb, cls)
        if lay_name is None:
            out["note"] = "인스턴스 레이아웃을 PDB 에서 찾지 못했습니다"
            return out
        f = lambda n: self._field_in(pdb, lay_name, n)
        if kind in ("uobject_method", "raw_method", "sp_method"):
            uo, mp = f("UserObject"), f("MethodPtr")
            if uo:
                if kind == "uobject_method":
                    out["object"] = self.objects.weak(inst + uo[0])
                elif kind == "raw_method":
                    ptr = self.ctx.u64(inst + uo[0])
                    out["object"] = self._maybe_object(ptr)
                else:  # TWeakPtr: 첫 8바이트가 객체 포인터
                    out["object"] = f"0x{self.ctx.u64(inst + uo[0]):X}"
                    out["object_class"] = _normalize(template_args(_normalize(cls))[1]) if len(template_args(cls)) > 1 else None
            if mp:
                out["function"] = self._code_symbol(self.ctx.u64(inst + mp[0]))
        elif kind == "static":
            if sp := f("StaticFuncPtr"):
                out["function"] = self._code_symbol(self.ctx.u64(inst + sp[0]))
        elif kind in ("lambda", "weak_lambda", "sp_lambda"):
            if fn := f("Functor"):
                out["functor_type"] = fn[1]
            if kind == "weak_lambda" and (co := f("ContextObject")):
                out["object"] = self.objects.weak(inst + co[0])
        elif kind == "ufunction":
            if fnm := f("FunctionName"):
                out["function"] = self.names.at(inst + fnm[0])
            if uo := f("UserObjectPtr"):
                out["object"] = self.objects.weak(inst + uo[0])
        return out

    def _resolve_udt(self, pdb: Path, cls: str) -> str | None:
        for cand in (cls, _normalize(cls)):
            try:
                self.ctx.layout_in(pdb, cand)
                return cand
            except LookupError:
                pass
        want = _normalize(cls)
        for h in self.ctx.t.dia.find(pdb, template_name(want) + "<*", "type", 200):
            if _normalize(h["name"]) == want and (h.get("size") or 0) > 0:
                return h["name"]
        return None

    def _field_in(self, pdb: Path, type_name: str, name: str, base: int = 0, depth: int = 0) -> tuple[int, str] | None:
        if depth > 8:
            return None
        try:
            lay = self.ctx.layout_in(pdb, type_name)
        except LookupError:
            return None
        for fld in lay["fields"]:
            if fld["name"] == name:
                return base + fld["offset"], fld["type"]
        for b in lay["bases"]:
            hit = self._field_in(pdb, b["name"], name, base + b["offset"], depth + 1)
            if hit:
                return hit
        return None

    def _maybe_object(self, ptr: int):
        if not ptr:
            return None
        try:
            return self.objects.identity(ptr)
        except (UEDecodeError, OSError):
            return f"0x{ptr:X}"

    def _code_symbol(self, addr: int) -> str:
        """코드 주소 → module!Function+off. 증분 링크 썽크(jmp rel32)는 따라간다."""
        if not addr:
            return None
        for _ in range(3):
            try:
                b = self.ctx.read(addr, 5)
            except OSError:
                break
            if b[0] != 0xE9:
                break
            addr = addr + 5 + int.from_bytes(b[1:5], "little", signed=True)
        try:
            hit = self.ctx.t.symbol_at(addr)
        except Exception:
            # PDB 없는 모듈(엔진 등): cdb 의 ln 으로 가장 가까운 export 심볼
            try:
                out = self.ctx.t.reader.execute(f"ln 0x{addr:X}")
                if m := re.search(r"\)\s+(\S+!\S+)", out):
                    return m.group(1) + " (export 기준 추정)"
            except Exception:
                pass
            return f"0x{addr:X}"
        s = hit.get("symbol") or {}
        name = s.get("undecorated") or s.get("name")
        if not name:
            return f"{hit['module']}+{hit['rva']}"
        disp = s.get("displacement") or 0
        return f"{hit['module'].rsplit('.', 1)[0]}!{name}" + (f"+0x{disp:X}" if disp else "")
