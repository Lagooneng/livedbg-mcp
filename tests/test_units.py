"""순수 로직 단위 테스트. 타깃·cdb 없이 돈다.

    uv run python tests\\test_units.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

os.environ["LIVEDBG_CACHE_DIR"] = tempfile.mkdtemp(prefix="livedbg-unit-")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from livedbg_mcp import symcache  # noqa: E402
from livedbg_mcp.cdb import CdbError, check_command, check_user_input  # noqa: E402
from livedbg_mcp.server import _addr  # noqa: E402
from livedbg_mcp.target import OwnerLock, Target, TargetError, _encode, _encode_bits, _is_breakin_stop  # noqa: E402
from livedbg_mcp.win32 import Module, PdbId  # noqa: E402


def check(cond: bool, msg: str) -> None:
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        raise SystemExit(1)


def raises(fn, exc) -> bool:
    try:
        fn()
    except exc:
        return True
    return False


def test_check_command() -> None:
    allowed = ["dx target!g_State", "lm m target", "kn 5", ".reload /f target.exe",
               '.nvload "C:\\Program Files\\Epic Games\\UE_5.8\\Engine\\Extras\\VisualStudioDebugging\\Unreal.natvis"',
               'bu /w "t > 0" target!Tick', 'bu /1 /w "j == 1" target!Accumulate', "dx g_State.Counter", "r rip"]
    for c in allowed:
        check(not raises(lambda: check_command(c), CdbError), f"allowed: {c[:60]}")
    blocked = ["qd", "dx 1; .kill", ".if (1) { qd }", ".block { .detach }", "$$<c:\\x.txt", "$><c:\\x.txt",
               "as X qd", "aS X qd", "j 1 'qd' ; ''", "z (1)", ".foreach (x {lm}) {qd}", 'bp target!Tick "qd"',
               'bp target!Tick "g"', "g", "gu", "dx 1\nqd",
               "~0 g", "~*e qd", "~0e .kill", "ph", "th", "tb", "~*f", "~0n", ".scriptrun c:\\x.js", ".load x.dll",
               'dx Debugger.Utility.Control.ExecuteCommand("q"+"d")',
               "pct", "tct", "p10", "t5", "~~[1a2c]g", "~~[1a2c]e qd", "!for_each_frame qd", "!for_each_module .kill",
               ".ocommand x"]
    for c in blocked:
        check(raises(lambda: check_command(c), CdbError), f"blocked: {c!r}")
    # 사용자 입력: 메모리·레지스터 쓰기도 거부
    user_ok = ["dx target!g_State.Counter == 5", "dx a != b && c <= d && e >= f", "~0 k", "kn 5",
               'bu /w "t > 0" target!Tick', "dx x.Where(v => v > 1)", "lm m target",
               "bu target!FFoo::operator=", "x target!*operator+=*", "bu target!FFoo::operator++", "dx -r2 g_State",
               "~~[1a2c]k", "peb", "ln target!Tick",
               "dx -r0 &(g_State)", "dx -r0 &(m_Value)", "dx -r0 &(p->Health)", "dx -r0 &(e->x)", "dx -r0 &(as->x)"]
    for c in user_ok:
        check(not raises(lambda: check_user_input(c), CdbError), f"user allowed: {c}")
    user_blocked = ["eb 0x1000 90", "ed target!g_State 1", "f 0x1000 L4 0", "dx target!g_State.Counter = 5",
                    "?? g_State.Counter += 1", "dx x <<= 1", "r rax=1", "~0e r rip=0",
                    'bu /w "g_State.Counter = 0" target!Tick', "m 0x1000 L4 0x2000", "(target!g_State.Counter = 5)",
                    "ed@rsp 0", "eb0x1000 90", "?? g_State.Counter++", "dx --g_State.Counter", 'bu /w "n++ > 3" target!Tick']
    for c in user_blocked:
        check(raises(lambda: check_user_input(c), CdbError), f"user blocked: {c!r}")


def test_addr() -> None:
    cases = {"0x10": 16, "140737488355328": 140737488355328, "00007ff64bc07210": 0x7FF64BC07210,
             "00007ff6`4bc07210": 0x7FF64BC07210, "7ff64bc07210": 0x7FF64BC07210, "1234": 1234, "0000000012345678": 0x12345678}
    for s, want in cases.items():
        check(_addr(s) == want, f"_addr({s!r}) == {want:#x}")


def test_encode() -> None:
    check(_encode("int", 4, "-1", "int") == b"\xff\xff\xff\xff", "int -1")
    check(_encode("int", 4, "0xFFFFFFFF", "int") == b"\xff\xff\xff\xff", "int bit pattern 0xFFFFFFFF")
    check(raises(lambda: _encode("unsigned int", 4, "-1", "uint"), TargetError), "uint rejects negative")
    check(raises(lambda: _encode("int", 4, "99999999999", "int"), TargetError), "int overflow rejected")
    check(_encode("float", 4, "1.5", "float") == b"\x00\x00\xc0\x3f", "float 1.5")
    check(_encode("const float", 4, "1.5", "float") == b"\x00\x00\xc0\x3f", "const float 1.5")
    check(_encode("bool", 1, "true", "bool") == b"\x01", "bool true")
    check(raises(lambda: _encode("TObjectPtr<UFoo>", 8, "5", "struct"), TargetError), "struct (size 8) rejects integer")
    check(_encode("TObjectPtr<UFoo>", 8, "hex:0000000000000000", "struct") == b"\0" * 8, "struct accepts hex:")
    check(_encode("ECollisionEnabled::Type", 1, "3", "enum") == b"\x03", "enum integer")


def test_breakin_detection() -> None:
    brk = "(1a2c.3f0): Break instruction exception - code 80000003 (first chance)\nntdll!DbgBreakPoint:\n00007ffc`11663ab0 cc int 3"
    hit = "Breakpoint 0 hit\ntarget!Tick:\n00007ff6`4bc07210 8b05ea4d0a00 mov eax,dword ptr [target!g_State]"
    check(_is_breakin_stop(brk) and not _is_breakin_stop(hit), "break-in vs breakpoint stop detection")
    ensure = ("(1a2c.3f0): Break instruction exception - code 80000003 (first chance)\n"
              "UnrealEditor_Core!FDebug::EnsureFailed+0x1a3:\n00007ffa`1234abcd cc int 3")
    check(not _is_breakin_stop(ensure), "ensure()/__debugbreak int3 is not our break-in")


def test_owner_lock() -> None:
    pid = 400000 + (os.getpid() % 1000)
    src = str(Path(__file__).resolve().parents[1] / "src")
    code = (f"import sys, time; sys.path.insert(0, {src!r}); from livedbg_mcp.target import OwnerLock; "
            f"l = OwnerLock({pid}); l.acquire(); print('held', flush=True); time.sleep(60)")
    other = subprocess.Popen([getattr(sys, "_base_executable", sys.executable), "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        check(other.stdout.readline().strip() == "held", "other session acquired the lock")
        lock = OwnerLock(pid)
        h = lock.holder()
        check(h is not None and h.get("owner_pid") == other.pid, "holder() reports the other session")
        check(raises(lock.acquire, TargetError), "acquire refused while another live session holds the lock")
        lock.release()  # 잡지 않은 lock 의 release 는 아무것도 하지 않는다
        check(raises(OwnerLock(pid).acquire, TargetError), "release of an unheld lock leaves the other session's lock")
        other.kill()  # 강제 종료해도 OS 가 잠금을 푼다 (stale lock 없음)
        other.wait()
        lock2 = OwnerLock(pid)
        lock2.acquire()
        check(lock2.held and lock2.holder() is None, "lock of a killed owner is free")
        lock3 = OwnerLock(pid)
        check(lock3.holder()["owner_pid"] == os.getpid(), "holder() from another handle shows this process")
        check(raises(lock3.acquire, TargetError), "second handle in the same process is refused too")
        lock2.release()
        lock3.acquire()
        check(lock3.held, "acquire after release")
        lock3.release()
        check(not lock3.path.exists(), "lock file removed on release")
    finally:
        if other.poll() is None:
            other.kill()


def test_symcache_replace_race() -> None:
    work = Path(tempfile.mkdtemp(prefix="livedbg-symrace-"))
    src = work / "race.pdb"
    src.write_bytes(b"PDB" * 100)
    pdb = PdbId(uuid.uuid4(), 1, str(src))
    mod = Module("race.dll", str(work / "race.dll"), 0x1000, 0x1000)
    real_replace = os.replace

    def racing_replace(a, b):
        # 다른 세션이 먼저 같은 사본을 넣고 열어 둔 상황: 대상은 생겼고 교체는 거부된다
        Path(b).parent.mkdir(parents=True, exist_ok=True)
        Path(b).write_bytes(Path(a).read_bytes())
        raise PermissionError(5, "Access is denied", str(b))

    symcache.os.replace = racing_replace
    try:
        got = symcache.ensure_pdb(mod, pdb, lambda p, _: True)
        check(got.path.is_file() and got.path.name == "race.pdb", "ensure_pdb survives concurrent cache creation")
    finally:
        symcache.os.replace = real_replace


def test_internal_paths_and_command_strings() -> None:
    # 따옴표 안 경로는 명령이 아니다: G:\ 를 g 명령, Q:\ 를 q 명령으로 보면 언리얼 attach 가 실패한다
    for drive in "GPQT":
        c = f'.nvload "{drive}:\\Epic Games\\UE_5.8\\Engine\\Extras\\VisualStudioDebugging\\Unreal.natvis"'
        check(not raises(lambda: check_user_input(c), CdbError), f"path on {drive}: drive is not a command")
    # 명령을 담는 따옴표 문자열은 여전히 검사한다
    for c in ['sxe -c "qd" av', '.pcmd -s "g"', 'bu target!Tick "gc"', '~0 bp target!Tick ".kill"']:
        check(raises(lambda: check_user_input(c), CdbError), f"command string checked: {c}")


def test_encode_bits() -> None:
    old = bytes([0x15])  # bA=1 (bit 0), bB=0 (bit 1), Mode=5 (bits 2..4)
    check(_encode_bits("unsigned char", 1, "1", "uint", 1, 1, old) == bytes([0x17]), "set 1-bit field keeps neighbours")
    check(_encode_bits("unsigned char", 1, "0", "uint", 0, 0, old) == bytes([0x14]), "clear bit 0 only")
    check(_encode_bits("unsigned char", 1, "2", "uint", 2, 4, old) == bytes([0x09]), "3-bit field replaced in place")
    check(_encode_bits("bool", 1, "true", "bool", 1, 1, old) == bytes([0x17]), "bool bitfield")
    check(_encode_bits("int", 4, "-1", "int", 4, 6, bytes(4)) == (0x70).to_bytes(4, "little"), "signed -1 in 3 bits")
    check(raises(lambda: _encode_bits("unsigned char", 1, "8", "uint", 2, 4, old), TargetError), "too wide refused")
    check(raises(lambda: _encode_bits("unsigned char", 1, "-1", "uint", 2, 4, old), TargetError), "negative unsigned refused")
    check(raises(lambda: _encode_bits("unsigned char", 1, "hex:01", "uint", 2, 4, old), TargetError), "hex: refused")
    check(raises(lambda: _encode_bits("unsigned char", 1, "1", "uint", 9, 9, old), TargetError), "bit outside storage unit refused")


class _FakeCdb:
    """Target 의 정지 판정 로직만 보려는 가짜 controller."""

    exited = False

    def __init__(self) -> None:
        self.running, self.stop_seq, self.last_stop, self.resumed = False, 0, "", []

    def stop(self, text: str) -> None:
        self.running, self.stop_seq, self.last_stop = False, self.stop_seq + 1, text

    def wait_stopped(self, timeout: float):
        return None if self.running else self.last_stop

    def resume(self, cmd: str = "g") -> None:
        self.resumed.append(cmd)
        self.running = True


def _fake_target(c: _FakeCdb):
    import threading
    t = Target.__new__(Target)
    t.pid, t.controller, t._op, t._pending_reload = 0, c, threading.RLock(), set()
    t._pending_breakins, t._observed_seq, t._stepping, t._attaching = 0, c.stop_seq, False, None
    t.status = lambda: {}
    return t


def test_stray_breakin_accounting() -> None:
    brk = "Break instruction exception - code 80000003 (first chance)\nntdll!DbgBreakPoint:\ncc int 3"
    hit = "Breakpoint 0 hit\ntarget!Tick:"
    # 늦은 break-in 정지를 사용자가 break_in 으로 이미 받았으면, 뒤의 wait 가 그 정지를 풀면 안 된다
    c = _FakeCdb()
    c.stop(hit)
    t = _fake_target(c)
    t._pending_breakins = 1  # 앞서 끼어들기가 bp 에 밀렸다
    t.resume()
    c.stop(brk)  # 그 break-in 이 늦게 도착
    t.break_in()  # 이미 멈춰 있다 → 이 정지를 사용자 정지로 넘긴다
    st = t.wait(0.1)
    check(c.resumed == ["g"] and not st["timed_out"] and t._pending_breakins == 0,
          "late break-in consumed by break_in is not resumed by wait")
    # 아무도 받지 않은 늦은 break-in 은 wait 가 흘려보낸다
    c = _FakeCdb()
    t = _fake_target(c)
    t._pending_breakins = 1
    c.running = True
    c.stop(brk)
    st = t.wait(0.1)
    check(c.resumed == ["g"] and st["timed_out"] and t._pending_breakins == 0, "unclaimed late break-in is absorbed by wait")
    # 스텝 중이면 흘려보내지 않고 알린다
    c = _FakeCdb()
    t = _fake_target(c)
    t._pending_breakins = 1
    c.running = True
    c.stop(brk)
    st = t.wait(0.1, stepping=True)
    check(c.resumed == [] and "note" in st, "late break-in during a step is reported, not resumed")
    # 사용자 bp 정지는 그대로 돌려준다
    c = _FakeCdb()
    t = _fake_target(c)
    t._pending_breakins = 1
    c.running = True
    c.stop(hit)
    st = t.wait(0.1)
    check(c.resumed == [] and not st["timed_out"] and t._pending_breakins == 1, "breakpoint stop returned to the user")
    # 스텝 중에는 끼어들지 않는다 (g 로 재개하면 스텝이 사라진다)
    c = _FakeCdb()
    t = _fake_target(c)
    t.step("over", timeout=0)
    check(t._stepping and c.running, "step marks stepping")
    check(raises(lambda: t._with_stopped(lambda _c: None), TargetError) and c.resumed == ["p"],
          "interrupt during a step is refused")
    c.stop(hit)
    st = t.wait(0.1)
    check(not t._stepping, "stepping cleared when the step's stop is observed")
    # step 의 대기가 시간 초과된 뒤 사용자가 wait 를 직접 불러도, 늦은 break-in 을 g 로 넘기지 않는다
    c = _FakeCdb()
    t = _fake_target(c)
    t._pending_breakins = 1
    st = t.step("out", timeout=0)
    check(st["timed_out"] and t._stepping, "step wait timed out while still stepping")
    c.stop(brk)
    st = t.wait(0.1)
    check(c.resumed == ["gu"] and "note" in st, "plain wait after a timed-out step does not resume a late break-in")


if __name__ == "__main__":
    test_check_command()
    test_addr()
    test_encode()
    test_breakin_detection()
    test_owner_lock()
    test_symcache_replace_race()
    test_internal_paths_and_command_strings()
    test_encode_bits()
    test_stray_breakin_accounting()
