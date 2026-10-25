"""타입 이름으로 해석기를 골라 재귀적으로 값을 만든다.

해석기 대상(FName, UObject 참조, 약참조, soft 참조, 컨테이너, 문자열)은 직접 읽고,
나머지 구조체는 PDB 필드 목록으로 내려간다. 어느 노드에서 해석이 실패하면 그 노드에만
{"error": ...} 를 남기고 나머지는 계속 보여준다 (추정값을 만들지 않는다).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .containers import map_pairs, set_elements, tarray
from .context import UEContext, UEDecodeError, template_args, template_name
from .delegates import DelegateResolver
from .names import NameResolver
from .objects import ObjectResolver
from .paths import read_string, soft_path

OBJECT_REF = {"TObjectPtr", "TSubclassOf", "ObjectPtr_Private::TNonAccessTrackedObjectPtr", "TLazyObjectPtr"}
WEAK = {"TWeakObjectPtr", "FWeakObjectPtr"}
SOFT = {"TSoftObjectPtr", "TSoftClassPtr", "FSoftObjectPtr", "FSoftObjectPath"}
STRINGS = {"FString", "FUtf8String", "FAnsiString"}

_INT = {1: "b", 2: "h", 4: "i", 8: "q"}
_BASE_NAMES = {
    "bool": ("bool", 1), "float": ("float", 4), "double": ("float", 8),
    "char": ("int", 1), "signed char": ("int", 1), "unsigned char": ("uint", 1), "int8": ("int", 1), "uint8": ("uint", 1),
    "short": ("int", 2), "unsigned short": ("uint", 2), "int16": ("int", 2), "uint16": ("uint", 2),
    "wchar_t": ("uint", 2), "char16_t": ("uint", 2), "char8_t": ("uint", 1), "char32_t": ("uint", 4),
    "int": ("int", 4), "long": ("int", 4), "int32": ("int", 4),
    "unsigned int": ("uint", 4), "unsigned long": ("uint", 4), "uint32": ("uint", 4),
    "__int64": ("int", 8), "long long": ("int", 8), "int64": ("int", 8),
    "unsigned __int64": ("uint", 8), "unsigned long long": ("uint", 8), "uint64": ("uint", 8),
}


@dataclass
class Budget:
    nodes: int = 2000
    max_elements: int = 50
    truncated: list = field(default_factory=list)

    def take(self) -> bool:
        self.nodes -= 1
        return self.nodes >= 0


class UEInspector:
    def __init__(self, ctx: UEContext) -> None:
        self.ctx = ctx
        self.names = NameResolver(ctx)
        self.objects = ObjectResolver(ctx, self.names)
        self.delegates = DelegateResolver(ctx, self.names, self.objects)

    # ---- 진입점 ------------------------------------------------------------------

    def render(self, addr: int, type_name: str, depth: int, budget: Budget, info: dict | None = None):
        if not budget.take():
            budget.truncated.append(f"노드 수 상한 도달 (0x{addr:X} {type_name[:60]})")
            return {"truncated": True}
        try:
            return self._render(addr, type_name.strip(), depth, budget, info or {})
        except (UEDecodeError, OSError, LookupError, KeyError, IndexError, ValueError, struct.error) as e:
            return {"error": str(e), "type": type_name, "address": f"0x{addr:X}"}

    def _render(self, addr: int, t: str, depth: int, budget: Budget, info: dict):
        kind = info.get("kind")
        tname = template_name(t)

        # 기본형 / 열거형
        if t in _BASE_NAMES or kind == "base":
            return self._scalar(addr, t, info)
        if kind == "enum" or t.startswith("enum "):
            return self._enum(addr, t, info)
        if kind == "array":
            return self._c_array(addr, info, depth, budget)

        # 포인터: UObject 파생이면 신원, 아니면 주소만
        if t.endswith("*"):
            ptr = self.ctx.u64(addr)
            pointee = t[:-1].strip()
            if not ptr:
                return None
            if self.ctx.is_uobject(pointee):
                return self._object(ptr, pointee, depth, budget)
            return f"0x{ptr:X}"

        if t == "FName":
            return self.names.at(addr)
        if t in STRINGS:
            return read_string(self.ctx, addr, t)
        if tname in OBJECT_REF:
            ptr = self.ctx.u64(addr)
            if not ptr:
                return None
            args = template_args(t)
            pointee = args[0] if args else "UObject"
            return self._object(ptr, pointee, depth, budget)
        if tname in WEAK:
            return self.objects.weak(addr)
        if tname in SOFT:
            return soft_path(self.ctx, self.names, addr, t)
        if tname == "TArray":
            arr = tarray(self.ctx, addr, t)
            return self._elements(t, arr.count, [(arr.data + i * arr.stride, arr.element_type)
                                                 for i in range(min(arr.count, budget.max_elements))], depth, budget)
        if tname == "TSet":
            items = set_elements(self.ctx, addr, t)
            return self._elements(t, len(items), items[:budget.max_elements], depth, budget)
        if tname == "TMap" or tname == "TSortableMapBase" or tname == "TMapBase":
            pairs = map_pairs(self.ctx, addr, t)
            shown = []
            for (ka, kt), (va, vt) in pairs[:budget.max_elements]:
                shown.append({"key": self.render(ka, kt, depth - 1, budget), "value": self.render(va, vt, depth - 1, budget)})
            out = {"type": t, "count": len(pairs), "pairs": shown}
            if len(pairs) > len(shown):
                out["truncated"] = f"{len(pairs) - len(shown)}개 생략 (max_elements={budget.max_elements})"
            return out
        if tname == "TEnumAsByte":
            return self.ctx.u8(addr)

        if kind != "pointer" and (dk := self._delegate_kind(t)):
            return self._delegate(addr, t, dk, info)

        # 템플릿 인자처럼 'enum ' 없이 온 열거형 (TArray<EFoo> 의 원소 등)
        if kind is None and not self.ctx.has_type(t) and self.ctx.enum_info(t):
            return self._enum(addr, t, info)

        # 일반 구조체
        return self._struct(addr, t, depth, budget)

    def _delegate_kind(self, t: str) -> str | None:
        try:
            return self.delegates.kind_of(t)
        except LookupError:
            return None

    def _delegate(self, addr: int, t: str, dk: str, info: dict):
        d = self.delegates
        if dk == "sparse":
            owner, name = info.get("_owner"), info.get("_field")
            if owner is None or name is None:
                owner, name = d.sparse_owner(addr)
            bound = self.ctx.u8(addr) != 0  # FSparseDelegate::bIsBound
            out = {"delegate": "sparse", "owner": self.objects.identity(owner)["path"], "name": name, "bound": bound}
            out["bindings"] = d.sparse_bindings(owner, name) if bound else []
            return out
        if dk == "dynamic_multicast":
            return {"delegate": "dynamic_multicast", "bindings": d.multicast_script(addr, t)}
        if dk == "dynamic":
            return {"delegate": "dynamic", "binding": d.script_delegate(addr, t)}
        if dk == "native_multicast":
            return {"delegate": "native_multicast", "bindings": d.native_multicast(addr, t)}
        return {"delegate": "native", "binding": d.native_single(addr, t)}

    # ---- 부분 -------------------------------------------------------------------

    def _scalar(self, addr: int, t: str, info: dict):
        base, size = _BASE_NAMES.get(t, (info.get("base", "int"), info.get("size") or 4))
        raw = self.ctx.read(addr, size)
        if "bits" in info:
            v = int.from_bytes(raw, "little") >> info.get("bit_position", 0) & ((1 << info["bits"]) - 1)
            return bool(v) if info["bits"] == 1 else v
        if base == "bool":
            return raw[0] != 0
        if base == "float":
            return struct.unpack("<f" if size == 4 else "<d", raw)[0]
        return int.from_bytes(raw, "little", signed=(base == "int"))

    def _enum(self, addr: int, t: str, info: dict):
        """열거형 값. 크기·부호는 필드 정보(PDB)에서, 없으면 열거형 정의에서 가져온다. 추정하지 않는다."""
        size, signed = info.get("size"), info.get("signed")
        if not size or signed is None:
            if (e := self.ctx.enum_info(t)) is None:
                raise UEDecodeError(f"열거형 '{t[:80]}' 의 정의가 PDB 에 없어 크기·부호를 알 수 없습니다.")
            size = size or e["size"]
            signed = e["signed"] if signed is None else signed
        raw = int.from_bytes(self.ctx.read(addr, size), "little")
        if "bits" in info:  # 열거형 비트필드 (EFoo Mode : 3)
            bits = info["bits"]
            v = raw >> info.get("bit_position", 0) & ((1 << bits) - 1)
            return v - (1 << bits) if signed and v >> (bits - 1) else v
        return raw - (1 << (size * 8)) if signed and raw >> (size * 8 - 1) else raw

    def _c_array(self, addr: int, info: dict, depth: int, budget: Budget):
        et, es, count = info.get("element_type"), info.get("element_size"), info.get("count", 0)
        einfo = {k[len("element_"):]: v for k, v in info.items() if k.startswith("element_")}
        einfo["size"] = es
        if et in ("wchar_t", "char16_t") and count:
            return self.ctx.read(addr, count * 2).decode("utf-16-le", "replace").split("\0", 1)[0]
        if depth <= 0:
            return {"type": f"{et}[{count}]", "address": f"0x{addr:X}"}
        return [self.render(addr + i * es, et, depth - 1, budget, einfo) for i in range(min(count, budget.max_elements))]

    def _elements(self, t: str, count: int, items: list, depth: int, budget: Budget):
        out = {"type": t, "count": count}
        if depth > 0:
            out["elements"] = [self.render(a, et, depth - 1, budget) for a, et in items]
            if count > len(items):
                out["truncated"] = f"{count - len(items)}개 생략 (max_elements={budget.max_elements})"
        return out

    def _object(self, ptr: int, static_type: str, depth: int, budget: Budget):
        ident = self.objects.identity(ptr)
        if depth > 0:
            # 정적 타입(필드 선언 타입)으로 필드를 보여준다. 실제 클래스는 identity.class 에 있다.
            ident["fields"] = self._fields(ptr, static_type, depth - 1, budget)
        return ident

    def _struct(self, addr: int, t: str, depth: int, budget: Budget):
        if self.ctx.is_uobject(t):
            return self._object(addr, t, depth, budget)
        if depth <= 0:
            return {"type": t, "address": f"0x{addr:X}"}
        return {"type": t, "fields": self._fields(addr, t, depth - 1, budget)}

    def _fields(self, addr: int, t: str, depth: int, budget: Budget) -> dict:
        lay = self.ctx.layout(t)
        out = {}
        for b in lay["bases"]:
            # 베이스 클래스는 펼치지 않고 이름만 둔다 (UObject 계층은 필드가 수백 개라 출력이 폭주한다)
            out[f"[base] {b['name']}"] = {"offset": b["offset"]}
        for f in lay["fields"]:
            info = dict(f, _owner=addr, _field=f["name"])  # 희소 델리게이트는 (소유 객체, 필드 이름)으로 찾는다
            out[f["name"]] = self.render(addr + f["offset"], f["type"], depth, budget, info)
        return out
