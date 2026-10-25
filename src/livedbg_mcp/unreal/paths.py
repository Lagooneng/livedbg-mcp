"""FString / TSoftObjectPtr / TSoftClassPtr.

soft 참조의 경로는 FSoftObjectPath = FTopLevelAssetPath(PackageName, AssetName: FName) + SubPathString.
"""

from __future__ import annotations

from .containers import tarray
from .context import UEContext, UEDecodeError
from .names import NameResolver

MAX_STRING = 1 << 20


def read_string(ctx: UEContext, addr: int, string_type: str) -> str:
    """FString(TCHAR=UTF-16) / FUtf8String / FAnsiString."""
    data = ctx.field(string_type, "Data")
    arr = tarray(ctx, addr + data.offset, data.type)
    if arr.count == 0:
        return ""
    if arr.count > MAX_STRING:
        raise UEDecodeError(f"문자열 길이가 이상합니다 ({arr.count}).")
    raw = ctx.read(arr.data, arr.count * arr.stride)
    enc = {2: "utf-16-le", 1: "utf-8", 4: "utf-32-le"}.get(arr.stride)
    if enc is None:
        raise UEDecodeError(f"문자 크기 {arr.stride} 를 모릅니다.")
    return raw.decode(enc, "replace").rstrip("\0")


def find_offset_of_type(ctx: UEContext, type_name: str, wanted: str, depth: int = 0) -> int | None:
    """type_name 안(베이스·멤버 재귀)에서 wanted 타입이 시작하는 오프셋."""
    if type_name == wanted:
        return 0
    if depth > 6:
        return None
    try:
        lay = ctx.layout(type_name)
    except LookupError:
        return None
    for b in lay["bases"]:
        off = find_offset_of_type(ctx, b["name"], wanted, depth + 1)
        if off is not None:
            return b["offset"] + off
    for f in lay["fields"]:
        if f.get("kind") == "udt":
            off = find_offset_of_type(ctx, f["type"], wanted, depth + 1)
            if off is not None:
                return f["offset"] + off
    return None


def soft_path(ctx: UEContext, names: NameResolver, addr: int, soft_type: str) -> str | None:
    off = find_offset_of_type(ctx, soft_type, "FSoftObjectPath")
    if off is None:
        raise UEDecodeError(f"'{soft_type[:80]}' 안에서 FSoftObjectPath 를 찾지 못했습니다.")
    p = addr + off
    asset = ctx.field("FSoftObjectPath", "AssetPath")
    pkg = names.at(p + asset.offset + ctx.field(asset.type, "PackageName").offset)
    name = names.at(p + asset.offset + ctx.field(asset.type, "AssetName").offset)
    sub_f = ctx.field("FSoftObjectPath", "SubPathString")
    sub = read_string(ctx, p + sub_f.offset, sub_f.type)
    if pkg == "None" and name == "None" and not sub:
        return None
    path = pkg if name == "None" else f"{pkg}.{name}"
    return f"{path}:{sub}" if sub else path
