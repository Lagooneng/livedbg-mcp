"""실행 중인 언리얼 에디터로 언리얼 해석기를 확인한다. 읽기 전용(attach mode='read')이라 에디터를 멈추지 않는다.

    uv run python tests\\test_unreal_live.py [pid]

pid 를 생략하면 UnrealEditor.exe 를 찾는다. 엔진을 올린 뒤 이 테스트로 해석기가 깨졌는지 확인한다.
해석기 결과를 dx(natvis 가 정상 동작하는 타입: TArray 개수, FString)와 교차 비교해서 프로젝트에 묶이지 않는다.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]


def body(r):
    t = " ".join(getattr(c, "text", "") for c in r.content)
    if getattr(r, "isError", False) or getattr(r, "is_error", False):
        raise AssertionError("tool error: " + t)
    sc = getattr(r, "structuredContent", None) or getattr(r, "structured_content", None)
    if isinstance(sc, dict) and set(sc) == {"result"}:
        return sc["result"]
    return sc if sc is not None else t


def check(cond: bool, msg: str) -> None:
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        raise SystemExit(1)


def find_editor() -> int:
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq UnrealEditor.exe", "/FO", "CSV", "/NH"], capture_output=True, text=True).stdout
    m = re.search(r'"UnrealEditor\.exe","(\d+)"', out)
    if not m:
        sys.exit("실행 중인 UnrealEditor.exe 가 없습니다.")
    return int(m.group(1))


async def main() -> None:
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_editor()
    params = StdioServerParameters(command=sys.executable, args=["-m", "livedbg_mcp.server"], cwd=str(ROOT),
                                   env={"LIVEDBG_CACHE_DIR": tempfile.mkdtemp(prefix="livedbg-ue-")})
    async with stdio_client(params) as st, ClientSession(*st[:2]) as s:
        await s.initialize()
        call = lambda n, **kw: s.call_tool(n, kw)
        body(await call("attach", pid=pid, mode="read"))

        worlds = body(await call("ue_worlds", pid=pid))
        mod = worlds["type_module"] + "!"
        editor = [w for w in worlds["worlds"] if w["world_type"] == "Editor"]
        check(len(editor) == 1 and editor[0]["world"]["class"] == "World", f"ue_worlds: editor world {editor[0]['world']['path'] if editor else None}")
        w = editor[0]["world"]
        check(w["path"].endswith("." + w["name"]), "world path is Package.Name")

        found = body(await call("ue_find_objects", pid=pid, name=w["name"], class_name="World", exact=True, limit=20))
        check(any(o["address"] == w["address"] for o in found["results"]), f"ue_find_objects finds the editor world (scanned {found['scanned']})")

        world = f"(({mod}UWorld*){w['address']})"
        # TArray: 해석기 개수 == dx natvis 개수
        actors = body(await call("ue_inspect", pid=pid, expression=f"{world}->PersistentLevel.DebugPtr->Actors", depth=1, max_elements=10))
        dx = body(await call("evaluate", pid=pid, expression=f"{world}->PersistentLevel.DebugPtr->Actors", depth=0))["output"]
        dx_num = int(re.search(r"Num=(\d+)", dx).group(1))
        check(actors["value"]["count"] == dx_num, f"TArray count matches dx ({dx_num})")
        elems = [e for e in actors["value"]["elements"] if e]
        check(all(e["path"].startswith(w["path"]) for e in elems), "actor paths are under the world")

        # FName: 레벨 이름
        lvl = body(await call("ue_inspect", pid=pid, expression=f"{world}->PersistentLevel", depth=0))
        check(lvl["value"]["name"] == "PersistentLevel" and lvl["value"]["path"] == w["path"] + ":PersistentLevel",
              "UObject identity + ':' subobject separator")

        # 쓰레기 포인터 거부
        bad = body(await call("ue_inspect", pid=pid, expression=f"*({mod}UObject*)({w['address']} + 8)", depth=0))
        check("error" in bad["value"], "garbage UObject pointer rejected")

        # TSet: 해석기 개수 == 원시 필드로 계산한 개수
        # 컴포넌트가 있는 액터를 고른다 (0 대 0 비교는 검증이 안 된다)
        owned, n = None, 0
        for e in elems:
            owned = body(await call("ue_inspect", pid=pid, expression=f"(({mod}AActor*){e['address']})->OwnedComponents", depth=1, max_elements=500))
            raw = f"(({mod}AActor*){e['address']})->OwnedComponents.Elements"
            n = int(re.search(r":\s*(-?\d+)", body(await call("evaluate", pid=pid, expression=f"{raw}.Data.ArrayNum - {raw}.NumFreeIndices", depth=0))["output"]).group(1))
            if n > 0:
                break
        check(n > 0, "found an actor with owned components")
        check(owned["value"]["count"] == n, f"TSet count matches raw sparse-array math ({n})")
        check(all(c and c.get("class") for c in owned["value"]["elements"]), "TSet elements resolve to components")

        # 희소 델리게이트: 필드 주소만으로 소유 컴포넌트를 역산해야 한다
        comps = [c for c in owned["value"]["elements"] if c]
        prim = None
        for c in comps:
            v = body(await call("ue_inspect", pid=pid, expression=f"(({mod}UPrimitiveComponent*){c['address']})->OnComponentBeginOverlap", depth=1))
            if isinstance(v["value"], dict) and v["value"].get("delegate") == "sparse":
                prim = (c, v["value"])
                break
        if prim:
            c, v = prim
            check(v["owner"] == c["path"] and v["name"] == "OnComponentBeginOverlap", f"sparse delegate owner inferred ({c['name']}, bound={v['bound']})")
        else:
            print("SKIP sparse delegate: 이 액터에 PrimitiveComponent 없음")

        # 네이티브 멀티캐스트: 엔진 전역 PostLoadMapWithWorld (export 주소 + 게임 PDB 의 델리게이트 타입)
        types = body(await call("find_symbols", pid=pid, module=worlds["type_module"].replace("_", "-"),
                                pattern="TMulticastDelegate<void __cdecl(UWorld *),*", kind="type", limit=3))
        x = body(await call("debugger_command", pid=pid, command="x UnrealEditor_CoreUObject!FCoreUObjectDelegates::PostLoadMapWithWorld"))["output"]
        m = re.search(r"^([0-9a-f]{8}`[0-9a-f]{8})\s", x, re.M)
        if types and m:
            v = body(await call("ue_inspect", pid=pid, expression=f"*({mod}{types[0]['name']}*)0x{m.group(1).replace('`', '')}", depth=1, max_elements=50))
            b = v["value"].get("bindings", []) if isinstance(v["value"], dict) else []
            check(v["value"].get("delegate") == "native_multicast" and len(b) > 0, f"native multicast decoded ({len(b)} bindings, kinds {sorted({x['kind'] for x in b})})")
        else:
            print("SKIP native delegate: 게임 PDB 에 TMulticastDelegate<void(UWorld*)> 인스턴스가 없음")

        body(await call("detach", pid=pid))


if __name__ == "__main__":
    anyio.run(main)
