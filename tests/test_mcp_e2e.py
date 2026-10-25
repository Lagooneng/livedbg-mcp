"""실제 MCP 클라이언트(stdio)로 서버를 띄워 테스트 타깃에 붙는 통합 테스트.

    powershell -File tests\\fixtures\\build.ps1
    uv run python tests\\test_mcp_e2e.py

시나리오
  A  핵심 흐름. 타깃이 bp 에 멈춘 채 클라이언트가 끊겨도 서버가 bp 해제 → detach 를 끝내 타깃이 산다.
  B  나머지 도구 전부 (조건부·소스 줄 bp, step, locals, break_in, symbol_at, read_memory, undo ...).
  C  붙어 있는 동안 실제 링커로 같은 PDB 를 덮어쓰는 재빌드가 성공하고, 이후 새 세션이 불일치를 잡는다.
  D  debug attach 가 초기화 도중 실패해도 타깃이 멈춘 채 남지 않고, 다시 붙을 수 있다.
  E  명령이 시간 초과로 끝난 뒤에도 실행/정지 상태가 실제와 맞는다.
  F  debug attach 설정 도중 서버가 종료돼도 등록 전 controller 를 닫아 타깃이 산다.
  G  cdb 가 시간 초과된 명령을 아직 처리 중일 때 detach 해도 멈춘 채 kill 하지 않는다.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
FIXTURES = ROOT / "tests" / "fixtures"
TARGET = FIXTURES / "bin" / "target.exe"
SOURCE = FIXTURES / "target.cpp"


class Target:
    def __init__(self, exe: Path = TARGET) -> None:
        self.log = Path(tempfile.mkstemp(suffix=".log")[1])
        self._f = open(self.log, "w")
        self.p = subprocess.Popen([str(exe)], stdout=self._f, creationflags=subprocess.CREATE_NO_WINDOW)
        self.pid = self.p.pid
        time.sleep(0.5)

    def lines(self) -> int:
        return len(self.log.read_text().splitlines())

    def running(self) -> bool:
        a = self.lines()
        time.sleep(0.8)
        return self.lines() > a

    def last(self) -> str:
        return self.log.read_text().splitlines()[-1]

    def close(self) -> None:
        self.p.kill()
        self._f.close()


def is_error(result) -> bool:
    return bool(getattr(result, "isError", False) or getattr(result, "is_error", False))


def err_text(result) -> str:
    return " ".join(getattr(c, "text", "") for c in result.content)


def text(result) -> str:
    if is_error(result):
        raise AssertionError("tool error: " + err_text(result))
    if (sc := getattr(result, "structuredContent", None) or getattr(result, "structured_content", None)) is not None:
        return json.dumps(sc, ensure_ascii=False)
    return "\n".join(getattr(c, "text", "") for c in result.content)


def data(result):
    v = json.loads(text(result))
    return v.get("result", v) if isinstance(v, dict) and set(v) == {"result"} else v


def check(cond: bool, msg: str) -> None:
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        raise SystemExit(1)


def server(cache: str | None = None) -> StdioServerParameters:
    env = {"LIVEDBG_CACHE_DIR": cache or tempfile.mkdtemp(prefix="livedbg-test-")}
    return StdioServerParameters(command=sys.executable, args=["-m", "livedbg_mcp.server"], env=env, cwd=str(ROOT))


def build(out_dir: Path, exe: str, pdb: Path | None = None) -> subprocess.CompletedProcess:
    args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(FIXTURES / "build.ps1"), "-OutDir", str(out_dir), "-ExeName", exe]
    if pdb:
        args += ["-PdbPath", str(pdb)]
    return subprocess.run(args, capture_output=True, text=True)


def source_line(marker: str) -> int:
    return next(i for i, line in enumerate(SOURCE.read_text().splitlines(), 1) if marker in line)


class Session:
    def __init__(self, s: ClientSession) -> None:
        self.s = s

    async def call(self, name: str, **kw):
        return await self.s.call_tool(name, kw)

    async def ok(self, name: str, **kw) -> str:
        return text(await self.call(name, **kw))

    async def json(self, name: str, **kw):
        return data(await self.call(name, **kw))


# ---- A ----------------------------------------------------------------------------

async def scenario_a() -> None:
    print("== A: 핵심 흐름 + 멈춘 상태로 연결 종료")
    params = server()
    t = Target()
    try:
        async with stdio_client(params) as streams:
            async with ClientSession(*streams[:2]) as cs:
                await cs.initialize()
                s = Session(cs)
                tools = {tool.name for tool in (await cs.list_tools()).tools}
                check({"attach", "set_breakpoint", "write_memory", "detach"} <= tools, f"tools registered ({len(tools)})")

                out = await s.ok("attach", pid=t.pid, mode="debug")
                check('"debugger_owner": true' in out and t.running(), "debug attach, target keeps running")

                out = await s.ok("evaluate", pid=t.pid, expression="target!g_State")
                check("Counter" in out and "live" in out, "live evaluate via reader")

                out = await s.ok("type_layout", pid=t.pid, module="target", type_name="FState")
                check('"Speed"' in out and '"offset": 4' in out, "DIA type layout")

                found = await s.json("find_symbols", pid=t.pid, module="target", pattern="FState", kind="type")
                check(len(found) == 1, f"find_symbols dedupes UDT records ({len(found)})")

                out = await s.ok("evaluate", pid=t.pid, expression="target!g_Object", depth=0)
                ptr = re.search(r":\s*(0x[0-9a-fA-F`]+)", out).group(1).replace("`", "")
                out = await s.ok("dynamic_type", pid=t.pid, object_address=ptr)
                check('"class": "FDerived"' in out, "dynamic_type resolves FDerived without RTTI")

                await s.ok("set_breakpoint", pid=t.pid, location="target!Tick")
                out = await s.ok("wait", pid=t.pid, timeout_seconds=5)
                check('"state": "stopped"' in out and "Breakpoint 0 hit" in out, "breakpoint hit")
                check(not t.running(), "target stopped at breakpoint")

                out = await s.ok("write_memory", pid=t.pid, expression="target!g_State.Speed", value="7.25")
                check("7.250000" in out, "write while stopped + readback")

                out = await s.ok("stack", pid=t.pid, frames=3)
                check("target!Tick" in out, "stack")

                async with stdio_client(params) as streams2:
                    async with ClientSession(*streams2[:2]) as cs2:
                        await cs2.initialize()
                        s2 = Session(cs2)
                        r = await s2.call("attach", pid=t.pid, mode="debug")
                        check(is_error(r) and "다른 세션" in err_text(r), "second session: debug attach refused")
                        out = await s2.ok("attach", pid=t.pid, mode="read")
                        check('"debugger_owner": false' in out and "debugger_held_by" in out, "second session: read attach ok, sees owner")
                        out = await s2.ok("evaluate", pid=t.pid, expression="target!g_State.Speed")
                        check("7.250000" in out, "second session reads value written by first")
                        r = await s2.call("write_memory", pid=t.pid, expression="target!g_State.Speed", value="1")
                        check(is_error(r), "second session: write refused (not owner)")
                check(not t.running(), "target still stopped after second session left")
                t0 = time.monotonic()
        print(f"      client closed while target stopped; shutdown took {time.monotonic() - t0:.2f}s")
        time.sleep(0.5)
        check(t.p.poll() is None, "target alive after client disconnect")
        check(t.running(), "target running after client disconnect")
        check(" 7.25 " in t.last(), f"written value persisted (last line: {t.last()!r})")
    finally:
        t.close()


# ---- B ----------------------------------------------------------------------------

async def scenario_b() -> None:
    print("== B: 나머지 도구")
    t = Target()
    try:
        async with stdio_client(server()) as streams:
            async with ClientSession(*streams[:2]) as cs:
                await cs.initialize()
                s = Session(cs)
                pid = t.pid

                st = await s.json("status")
                check("MISSING" not in json.dumps(st["tools"]), "status: cdb and msdia found")
                procs = await s.json("list_processes", name_filter="target")
                check(any(p["pid"] == pid for p in procs), "list_processes finds target")

                await s.ok("attach", pid=pid, mode="debug")
                mods = await s.json("modules", pid=pid, name_filter="target")
                check(len(mods) == 1 and mods[0].get("pdb"), "modules shows cached PDB")
                prep = await s.json("prepare_symbols", pid=pid, module_names=["target", "nosuchmodule"])
                check(prep["target"].get("pdb") and "error" in prep["nosuchmodule"], "prepare_symbols: ok + missing module reported")

                tick = (await s.json("find_symbols", pid=pid, module="target", pattern="Tick", kind="function"))[0]
                out = await s.json("symbol_at", pid=pid, address=f"target+0x{tick['rva'] + 3:X}")
                check(out["symbol"]["name"] == "Tick" and out["symbol"]["displacement"] == 3, "symbol_at module+offset")

                g = (await s.json("find_symbols", pid=pid, module="target", pattern="g_State", kind="data"))[0]
                out = await s.json("read_memory", pid=pid, address=f"target+0x{g['rva']:X}", size=8)
                check("00 00 c0 3f" in out["dump"], "read_memory shows Speed=1.5 bytes")

                out = await s.json("debugger_command", pid=pid, command="lm m target")
                check(out["session"] == "reader" and "target" in out["output"], "debugger_command while running uses reader")
                r = await s.call("debugger_command", pid=pid, command="dx 1; .kill")
                check(is_error(r) and ".kill" in err_text(r), "debugger_command blocks chained lifecycle command")
                r = await s.call("debugger_command", pid=pid, command=".if (1) { qd }")
                check(is_error(r), "debugger_command blocks lifecycle command hidden in a block")
                r1 = await s.call("debugger_command", pid=pid, command="ed target!g_State 0")
                r2 = await s.call("evaluate", pid=pid, expression="target!g_State.Speed = 99")
                r3 = await s.call("debugger_command", pid=pid, command="~0 g")
                check(is_error(r1) and is_error(r2) and is_error(r3), "raw memory writes, dx assignment, ~N g are refused")
                check(t.running(), "target still running after blocked commands")

                out = await s.json("symbol_at", pid=pid, address=str(int(mods[0]["base"], 16) + tick["rva"] + 3))
                check(out["symbol"]["name"] == "Tick", "symbol_at accepts decimal address")

                # 조건부 bp. 함수 첫 명령어(프롤로그 전)에서는 인자가 아직 스택에 없으므로 전역으로 조건을 건다.
                await s.ok("set_breakpoint", pid=pid, location="target!Accumulate", condition="target!g_State.Counter < 0")
                out = await s.json("wait", pid=pid, timeout_seconds=1.5)
                check(out["timed_out"] and t.running(), "conditional bp (false) does not stop")
                out = await s.ok("clear_breakpoint", pid=pid, breakpoint_id="*")
                check(t.running(), "clear_breakpoint while running keeps target running")

                bp = await s.ok("set_breakpoint", pid=pid, location="target!Accumulate", condition="target!g_State.Counter >= 0", once=True)
                out = await s.json("wait", pid=pid, timeout_seconds=5)
                check(out["state"] == "stopped", "conditional bp (true) stops" + ("" if out["state"] == "stopped" else f"\n{bp}"))

                out = await s.json("locals", pid=pid, frame=0)
                check("Delta" in out and "Sum" in out, "locals shows arg and local")
                out = await s.json("locals", pid=pid, frame=1)
                check("Accumulate" not in out.splitlines()[0] or "Tick" in out, "locals frame 1 (caller)")

                out = await s.json("step", pid=pid, kind="over")
                check(out["state"] == "stopped" and not out["timed_out"], "step over")
                out = await s.json("step", pid=pid, kind="out")
                stk = await s.json("stack", pid=pid, frames=2)
                check(out["state"] == "stopped" and "target!Tick" in stk.splitlines()[1], "step out returns to Tick")
                out = await s.json("step", pid=pid, kind="into")
                check(out["state"] == "stopped", "step into")

                # 쓰기 → 기록 → undo
                w = await s.json("write_memory", pid=pid, expression="target!g_State.Speed", value="3.5")
                hist = await s.json("write_history", pid=pid)
                check(len(hist) == 1 and hist[0]["new"] == w["write"]["new"], "write_history")
                u = await s.json("undo_write", pid=pid, write_id=w["write"]["id"])
                check(u["undone"]["undone"], "undo_write")
                out = await s.ok("evaluate", pid=pid, expression="target!g_State.Speed", depth=0)
                check("1.500000" in out and "snapshot" in out, "value restored after undo (snapshot read)")
                r = await s.call("undo_write", pid=pid, write_id=w["write"]["id"])
                check(is_error(r), "double undo refused")
                r = await s.call("write_memory", pid=pid, expression="target!Tick", value="0")
                check(is_error(r), "write to code refused")
                r = await s.call("write_memory", pid=pid, expression="target!g_State", value="5")
                check(is_error(r) and "구조체" in err_text(r), "integer write to 8-byte struct refused")

                # 비트필드: dx 는 소속 바이트 주소를 주므로, 바이트째 쓰면 같은 바이트의 bA·Mode 가 지워진다
                w = await s.json("write_memory", pid=pid, expression="target!g_Flags.bB", value="1")
                check(w["write"]["old"] == "15" and w["write"]["new"] == "17",
                      f"bitfield write changes only its bit (0x{w['write']['old']} -> 0x{w['write']['new']})")
                r = await s.call("write_memory", pid=pid, expression="target!g_Flags.Mode", value="8")
                check(is_error(r) and "비트" in err_text(r), "value too wide for a 3-bit bitfield refused")
                await s.json("undo_write", pid=pid, write_id=w["write"]["id"])

                # 소스 줄 bp
                line = source_line("LINE_TICK_BODY")
                await s.ok("resume", pid=pid)
                out = await s.ok("set_breakpoint", pid=pid, location=f"target!target.cpp:{line}")
                check(" e " in out or "e 0" in out, f"source-line bp resolved (target.cpp:{line})")
                out = await s.json("wait", pid=pid, timeout_seconds=5)
                stk = await s.json("stack", pid=pid, frames=1)
                check(out["state"] == "stopped" and f"target.cpp @ {line}" in stk, "source-line bp hit at that line")
                await s.ok("clear_breakpoint", pid=pid)

                # break_in / resume
                await s.ok("resume", pid=pid)
                check(t.running(), "resume")
                out = await s.json("break_in", pid=pid)
                check(out["state"] == "stopped" and not t.running(), "break_in stops running target")
                check("note" not in out and "ntdll!DbgBreakPoint" in out.get("last_stop", ""),
                      "break_in stop recognized as our break-in (ntdll!DbgBreakPoint)")
                await s.ok("resume", pid=pid)

                rep = await s.json("detach", pid=pid)
                check(rep.get("controller") == "detached" and t.running(), "detach leaves target running")
                r = await s.call("evaluate", pid=pid, expression="target!g_State")
                check(is_error(r), "tools refuse after detach")
    finally:
        t.close()


# ---- C ----------------------------------------------------------------------------

async def scenario_c() -> None:
    print("== C: 붙어 있는 동안 실제 재빌드")
    work = Path(tempfile.mkdtemp(prefix="livedbg-rebuild-"))
    r = build(work, "rb.exe")
    check(r.returncode == 0, "build rb.exe")
    pdb = work / "rb.pdb"
    t = Target(work / "rb.exe")
    try:
        async with stdio_client(server()) as streams:
            async with ClientSession(*streams[:2]) as cs:
                await cs.initialize()
                s = Session(cs)
                await s.ok("attach", pid=t.pid, mode="debug")
                await s.ok("set_breakpoint", pid=t.pid, location="rb!Tick")
                await s.json("wait", pid=t.pid, timeout_seconds=5)  # 정지 상태로 두고 재빌드
                out = await s.ok("evaluate", pid=t.pid, expression="rb!g_State.Counter", depth=0)
                check("Counter" in out, "attached, stopped, symbols loaded from cache")

                t0 = time.monotonic()
                r = build(work, "rb2.exe", pdb)  # 링커가 실행 중인 모듈의 PDB 경로에 새로 쓴다
                check(r.returncode == 0, f"linker rewrote the attached module's PDB ({time.monotonic() - t0:.1f}s)"
                      + ("" if r.returncode == 0 else "\n" + r.stdout[-800:] + r.stderr[-800:]))

                out = await s.ok("evaluate", pid=t.pid, expression="rb!g_State.Counter", depth=0)
                check("Counter" in out, "existing session keeps working from its cached copy")
                await s.ok("detach", pid=t.pid)

        # 캐시가 빈 새 세션: 디스크 PDB 는 이제 다른 빌드 → 불일치로 잡아야 한다
        async with stdio_client(server()) as streams:
            async with ClientSession(*streams[:2]) as cs:
                await cs.initialize()
                s = Session(cs)
                st = await s.json("attach", pid=t.pid, mode="read")
                notes = " ".join(st.get("notes", []))
                check("빌드가 다릅니다" in notes, "fresh session detects PDB/module mismatch")
                r = await s.call("find_symbols", pid=t.pid, module="rb", pattern="Tick")
                check(is_error(r) and "빌드가 다릅니다" in err_text(r), "symbol lookup refuses mismatched PDB")
        check(t.running(), "target still running")
    finally:
        t.close()


# ---- D ----------------------------------------------------------------------------

def scenario_d() -> None:
    """debug attach 가 초기화 도중 실패해도 타깃이 초기 break 로 멈춘 채 남지 않아야 한다."""
    print("== D: debug attach 도중 실패")
    import os as _os
    _os.environ["LIVEDBG_CACHE_DIR"] = tempfile.mkdtemp(prefix="livedbg-test-")
    from livedbg_mcp import target as target_mod

    t = Target()
    real_setup = target_mod.Target._setup_session

    def failing_setup(self, s):
        real_setup(self, s)
        if s.label.startswith("controller"):
            raise target_mod.CdbError("테스트용 강제 실패")

    target_mod.Target._setup_session = failing_setup
    mgr = target_mod.TargetManager()
    try:
        try:
            mgr.attach(t.pid, "debug", False)
            check(False, "attach should fail")
        except target_mod.CdbError:
            pass
        time.sleep(0.5)
        check(t.p.poll() is None and t.running(), "target keeps running after failed debug attach")
        tg = mgr.targets.get(t.pid)
        check(tg is None or not tg.lock.path.exists(), "lock released after failed debug attach")
        target_mod.Target._setup_session = real_setup
        out = mgr.attach(t.pid, "debug", False)  # 다시 붙을 수 있어야 한다 (디버그 포트가 비었는가)
        check(out["debugger_owner"], "debug attach works again afterwards (debug port was freed)")
        mgr.detach(t.pid)
        check(t.running(), "target running after detach")
    finally:
        target_mod.Target._setup_session = real_setup
        mgr.shutdown()
        t.close()


# ---- E ----------------------------------------------------------------------------

def scenario_e() -> None:
    """명령이 시간 초과로 끝나도 cdb 는 그 명령을 마저 처리하고 늦게 프롬프트를 찍는다.
    그 프롬프트를 resume 뒤의 정지로 오인하면 타깃은 도는데 '멈춤' 상태가 된다."""
    print("== E: 명령 시간 초과 뒤 상태 동기화")
    from livedbg_mcp import win32
    from livedbg_mcp.cdb import CdbError, CdbSession
    from livedbg_mcp.config import cdb_path

    t = Target()
    c = CdbSession(cdb_path(), ["-pd", "-noshell", "-p", str(t.pid)], "e2e-timeout")
    try:
        c.wait_prompt(60)
        try:
            c.execute(".sleep 3000", timeout=0.5)
            check(False, "command should time out")
        except CdbError:
            pass
        c.resume("g")
        time.sleep(0.5)
        check(c.running and t.running(), "after a timed-out command, resume runs the target and state says running")
        win32.debug_break(t.pid)
        check(c.wait_stopped(10) is not None and not c.running and not t.running(), "break-in afterwards stops it")
        c.send_raw("qd")
        check(c.wait_exit(15) and t.running(), "qd detaches, target keeps running")
    finally:
        c.kill()
        t.close()


# ---- F ----------------------------------------------------------------------------

def scenario_f() -> None:
    """debug attach 가 설정(.reload 등) 중일 때 서버가 종료돼도, 등록 전 controller 를 닫아 타깃이 산다."""
    print("== F: debug attach 설정 도중 서버 종료")
    import threading
    from livedbg_mcp import target as target_mod

    t = Target()
    real_setup = target_mod.Target._setup_session

    def slow_setup(self, s):
        real_setup(self, s)
        if s.label.startswith("controller"):
            time.sleep(6)  # 큰 PDB .reload 를 흉내 낸다

    target_mod.Target._setup_session = slow_setup
    mgr = target_mod.TargetManager()
    th = threading.Thread(target=lambda: _swallow(lambda: mgr.attach(t.pid, "debug", False)), daemon=True)
    try:
        th.start()
        deadline = time.monotonic() + 60
        while t.running() and time.monotonic() < deadline:
            pass  # controller 가 붙어 초기 break 로 멈출 때까지
        check(not t.running(), "target stopped at the attach break while setup runs")
        t0 = time.monotonic()
        mgr.shutdown()
        check(t.running(), f"shutdown during attach closes the half-attached controller ({time.monotonic() - t0:.2f}s)")
        th.join(15)
    finally:
        target_mod.Target._setup_session = real_setup
        t.close()


def _swallow(fn) -> None:
    try:
        fn()
    except Exception:
        pass


# ---- G ----------------------------------------------------------------------------

def scenario_g() -> None:
    """앞 명령이 시간 초과돼 cdb 가 아직 바쁜 상태에서 detach 해도, 멈춘 채 kill 하지 않고 끝까지 기다린다."""
    print("== G: 바쁜 cdb 에서 detach (약 35초)")
    from livedbg_mcp import target as target_mod
    from livedbg_mcp.cdb import CdbError

    t = Target()
    mgr = target_mod.TargetManager()
    try:
        mgr.attach(t.pid, "debug", True)  # 멈춘 상태
        c = mgr.get(t.pid).controller
        try:
            c.execute(".sleep 35000", timeout=0.5)  # 이전 코드는 bc 동기화 10초 + qd 대기 15초 뒤 멈춘 채 kill
        except CdbError:
            pass
        rep = mgr.detach(t.pid)
        check(rep.get("controller") == "detached" and t.running(), f"detach waits out a busy cdb ({rep.get('controller')})")
    finally:
        mgr.shutdown()
        t.close()


async def main() -> None:
    if not TARGET.exists():
        sys.exit(f"{TARGET} 가 없습니다. tests\\fixtures\\build.ps1 을 먼저 실행하세요.")
    await scenario_a()
    await scenario_b()
    await scenario_c()
    scenario_d()
    scenario_e()
    scenario_f()
    scenario_g()
    leftover = subprocess.run(["tasklist", "/FI", "IMAGENAME eq cdb.exe", "/NH"], capture_output=True, text=True).stdout
    check("cdb.exe" not in leftover, "no leftover cdb processes")


if __name__ == "__main__":
    anyio.run(main)
