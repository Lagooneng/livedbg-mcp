"""MCP 서버 (stdio). 세션(클라이언트)마다 프로세스 하나가 뜬다 — 데몬 없음.

동기 도구 함수는 SDK 가 워커 스레드에서 실행하므로 wait 같은 긴 호출이 다른 호출을 막지 않는다.
"""

from __future__ import annotations

import atexit
import ctypes
import functools
import re
import signal
import sys
import threading
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import win32
from .config import tool_status
from .target import TargetManager

INSTRUCTIONS = """\
실행 중인 C++ 프로세스(PDB 가 있는 개발 빌드)를 읽고 디버깅한다. cdb + DIA 기반.

흐름: list_processes → attach(pid, mode) → evaluate / find_symbols / type_layout → (debug 모드) set_breakpoint → wait → stack / locals / write_memory → resume → detach.

- mode='read' 는 타깃을 멈추지 않고 여러 세션이 동시에 붙을 수 있다. 실행 중 읽은 값은 필드끼리 시점이 다를 수 있다.
- mode='debug' 는 프로세스당 한 세션만 가능하다. 다른 세션이 갖고 있으면 attach 가 거절되고 read 로 쓰면 된다.
- 심볼은 'module!name' 으로 한정해서 쓴다 (예: target!g_State, UnrealEditor-Engine!GEngine). 비한정 이름은 이미 심볼이 로드된 모듈에서만 찾는다.
- 메모리 쓰기는 debug 소유 + 정지 상태에서만 된다. 가능하면 객체가 조용한 지점(프레임 시작 등)의 bp 에서 쓴다.
- 작업이 끝나면 detach 한다. 서버 종료 시에도 bp 해제 → detach 를 자동으로 한다.
"""

mcp = MCPServer("livedbg-mcp", instructions=INSTRUCTIONS)
manager = TargetManager()


def tool(fn):
    """예상된 실패는 ToolError 로 바꿔 메시지가 모델에 전달되게 한다.
    그 외 예외는 SDK 가 'Error executing tool' 로 가려 버린다."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ToolError:
            raise
        except (RuntimeError, LookupError, OSError, ValueError) as e:
            raise ToolError(str(e)) from e

    return mcp.tool()(wrapper)


def _addr(value: str | int) -> int:
    """주소 문자열. 16진: 0x 접두, cdb 표기(00007ff6`4bc07210), a-f 포함, 0 으로 시작하는 9자리 이상.
    그 밖의 숫자만 있는 문자열은 10진이다 (140737488355328 같은 10진 주소를 16진으로 오해하지 않는다)."""
    if isinstance(value, int):
        return value
    raw = value.strip()
    v = raw.replace("`", "")
    if v.lower().startswith("0x"):
        return int(v, 16)
    if "`" in raw or re.search(r"[a-fA-F]", v) or (len(v) >= 9 and v.startswith("0")):
        return int(v, 16)
    return int(v, 10)


def _module_addr(pid: int, value: str) -> int:
    """'module+0x1234' 형식도 받는다."""
    if (m := re.fullmatch(r"\s*([\w.\-]+)\s*\+\s*(\S+)\s*", value)) and not m.group(1).lower().startswith("0x"):
        return win32.find_module(pid, m.group(1)).base + _addr(m.group(2))
    return _addr(value)


# ---- 세션 --------------------------------------------------------------------------

@tool
def status() -> dict[str, Any]:
    """도구 경로(cdb, msdia), 캐시 위치, 현재 붙어 있는 타깃 상태."""
    return {"tools": tool_status(), "targets": [t.status() for t in manager.targets.values()]}


@tool
def list_processes(name_filter: str = "") -> list[dict[str, Any]]:
    """실행 중인 프로세스 목록. name_filter 는 부분 일치(대소문자 무시)."""
    f = name_filter.lower()
    return [{"pid": pid, "name": name} for pid, name in win32.list_processes() if f in name.lower()]


@tool
def attach(pid: int, mode: Literal["read", "debug"] = "read", stop: bool = False) -> dict[str, Any]:
    """프로세스에 붙는다. read: 비침투(타깃 무정지, 동시 다중 세션 가능). debug: 디버거 소유(bp·스텝·쓰기, 프로세스당 1세션).
    stop=True 면 debug attach 직후 멈춘 상태로 둔다."""
    return manager.attach(pid, mode, stop)


@tool
def detach(pid: int) -> dict[str, Any]:
    """bp 를 모두 지우고 detach 한다. 타깃은 계속 실행된다."""
    return manager.detach(pid)


@tool
def modules(pid: int, name_filter: str = "") -> list[dict[str, Any]]:
    """로드된 모듈 목록 (베이스 주소, 경로, 준비된 PDB)."""
    return manager.get(pid).modules(name_filter)


@tool
def prepare_symbols(pid: int, module_names: list[str]) -> dict[str, Any]:
    """모듈 PDB 를 섀도 캐시에 복사·검증하고 cdb 에 로드한다. 원본 PDB 는 잠그지 않는다."""
    return manager.get(pid).prepare_symbols(module_names)


# ---- 심볼 · 타입 (DIA) --------------------------------------------------------------

@tool
def find_symbols(pid: int, module: str, pattern: str,
                 kind: Literal["any", "type", "function", "data", "public"] = "any", limit: int = 50) -> list[dict[str, Any]]:
    """모듈 PDB 에서 이름으로 심볼을 찾는다. pattern 에 * ? 와일드카드를 쓰면 대소문자 무시 검색."""
    return manager.get(pid).find_symbols(module, pattern, kind, max(1, min(limit, 500)))


@tool
def type_layout(pid: int, module: str, type_name: str) -> dict[str, Any]:
    """구조체/클래스의 크기, 베이스 클래스, 필드 오프셋·크기·타입(비트필드 포함)."""
    return manager.get(pid).type_layout(module, type_name)


@tool
def symbol_at(pid: int, address: str) -> dict[str, Any]:
    """주소가 속한 모듈과 함수/전역 변수 + 오프셋. address 는 0x.., 00007ff6`...., module+0x.. 형식."""
    t = manager.get(pid)
    return t.symbol_at(_module_addr(pid, address))


@tool
def dynamic_type(pid: int, object_address: str) -> dict[str, Any]:
    """객체 주소의 vptr 를 vftable 심볼과 대조해 실제 클래스를 알아낸다. RTTI 가 꺼진(/GR-) 빌드에서도 동작."""
    return manager.get(pid).dynamic_type(_module_addr(pid, object_address))


# ---- 읽기 ---------------------------------------------------------------------------

@tool
def evaluate(pid: int, expression: str, depth: int = 2) -> dict[str, Any]:
    """C++ 식을 cdb dx 로 평가한다 (natvis 적용). 정지 중이면 일관된 스냅숏, 실행 중이면 라이브 값.
    예: target!g_State, ((AActor*)0x1234)->RootComponent, *(FVector*)0x5678"""
    return manager.get(pid).evaluate(expression, depth)


@tool
def read_memory(pid: int, address: str, size: int = 64) -> dict[str, Any]:
    """메모리 hex 덤프 (최대 64KB). 디버거 없이 ReadProcessMemory 로 읽는다."""
    return manager.get(pid).read_memory(_module_addr(pid, address), size)


@tool
def debugger_command(pid: int, command: str) -> dict[str, Any]:
    """cdb 명령을 그대로 실행한다 (예: 'lm', '!peb', 'dt target!FState'). 정지 중이면 디버거 세션, 아니면 읽기 세션에서 돈다.
    실행 명령(g/p/t)과 세션 수명 명령(q/.kill/.detach 등)은 거부된다 — 전용 도구를 쓴다."""
    return manager.get(pid).command(command)


# ---- 언리얼 ------------------------------------------------------------------------

@tool
def ue_inspect(pid: int, expression: str, depth: int = 2, max_elements: int = 50) -> dict[str, Any]:
    """언리얼 값을 해석해서 보여준다. cdb natvis 가 못 푸는 FName, UObject 참조(이름·클래스·경로),
    TWeakObjectPtr, TSoftObjectPtr, TArray/TSet/TMap, FString 을 메모리에서 직접 읽고 검증한다.
    구조체는 PDB 필드로 depth 만큼 내려간다 (베이스 클래스는 이름만). 해석 실패 노드는 error 로 표시된다.
    예: UnrealEditor_ChronoSpace!CVarCSConveyorDebugDraw, *(UnrealEditor_ChronoSpace!ACSCharacterPlayer*)0x1e1d3c6e600"""
    return manager.get(pid).ue_inspect(expression, depth, max_elements)


@tool
def ue_find_objects(pid: int, name: str = "", class_name: str = "", limit: int = 50, exact: bool = False) -> dict[str, Any]:
    """전역 객체 배열에서 이름·클래스 이름(부분 일치, exact=True 면 정확히)으로 UObject 를 찾는다.
    결과의 address 를 ue_inspect 식에 캐스트해서 쓴다. 예: class_name='World', name='PlayerController'"""
    return manager.get(pid).ue_find_objects(name, class_name, limit, exact)


@tool
def ue_worlds(pid: int) -> dict[str, Any]:
    """엔진의 월드 컨텍스트 목록 (에디터 / PIE / 게임 월드와 게임 인스턴스)."""
    return manager.get(pid).ue_worlds()


# ---- 실행 제어 (debug 소유 세션만) ----------------------------------------------------

@tool
def set_breakpoint(pid: int, location: str, condition: str | None = None, once: bool = False) -> dict[str, Any]:
    """bp 를 건다. location: 'module!Function', 'file.cpp:123', 또는 주소. condition: C++ 식(참일 때만 멈춤).
    타깃이 실행 중이면 잠깐 끼어들어 설정하고 다시 실행시킨다."""
    return manager.get(pid).set_breakpoint(location, condition, once)


@tool
def list_breakpoints(pid: int) -> str:
    """bp 목록."""
    return manager.get(pid).list_breakpoints()


@tool
def clear_breakpoint(pid: int, breakpoint_id: str = "*") -> str:
    """bp 를 지운다. 번호, 범위('1-3'), 또는 '*'(전부)."""
    return manager.get(pid).clear_breakpoint(breakpoint_id)


@tool
def wait(pid: int, timeout_seconds: float = 30) -> dict[str, Any]:
    """타깃이 멈출 때까지(bp 적중 등) 기다린다. 이미 멈춰 있으면 바로 돌아온다. timed_out 으로 결과를 알려준다."""
    return manager.get(pid).wait(max(0.0, min(timeout_seconds, 600)))


@tool
def break_in(pid: int) -> dict[str, Any]:
    """실행 중인 타깃을 지금 멈춘다."""
    return manager.get(pid).break_in()


@tool
def resume(pid: int) -> dict[str, Any]:
    """멈춘 타깃을 계속 실행한다."""
    return manager.get(pid).resume()


@tool
def step(pid: int, kind: Literal["over", "into", "out"] = "over") -> dict[str, Any]:
    """한 단계 실행하고 멈출 때까지 기다린다."""
    return manager.get(pid).step(kind)


@tool
def stack(pid: int, frames: int = 30) -> str:
    """현재 스레드의 콜스택 (정지 상태에서만)."""
    return manager.get(pid).stack(frames)


@tool
def locals(pid: int, frame: int = 0) -> str:
    """지정 프레임의 지역 변수와 인자 (정지 상태에서만). 최적화 빌드에서는 일부가 사라져 있을 수 있다."""
    return manager.get(pid).locals(frame)


# ---- 쓰기 (debug 소유 + 정지 상태만) ---------------------------------------------------

@tool
def write_memory(pid: int, expression: str, value: str) -> dict[str, Any]:
    """식이 가리키는 변수에 값을 쓴다. 타입·크기는 PDB 로 확인하고 쓰기 후 되읽어 검증한다.
    value: 정수(10진/0x), 실수, true/false, 또는 'hex:0a0b0c0d' (정확히 그 크기의 바이트).
    코드 페이지나 읽기 전용 페이지는 거부한다. 기록이 남으며 undo_write 로 되돌릴 수 있다."""
    return manager.get(pid).write(expression, value)


@tool
def undo_write(pid: int, write_id: int) -> dict[str, Any]:
    """write_memory 로 쓴 값을 되돌린다. 그 사이 값이 바뀌었으면 덮어쓰지 않는다."""
    return manager.get(pid).undo_write(write_id)


@tool
def write_history(pid: int) -> list[dict[str, Any]]:
    """이 세션에서 한 메모리 쓰기 기록."""
    return [w.as_dict() for w in manager.get(pid).writes]


# ---- 종료 처리 ----------------------------------------------------------------------

_shutdown_lock = threading.Lock()
_shutdown_started = False
_shutdown_finished = threading.Event()


def _shutdown(*_: Any) -> None:
    """어떤 경로로 끝나든 bp 해제 → detach. 멈춘 채 디버거가 죽으면 타깃이 동결되기 때문이다.

    두 번째로 부른 쪽(예: 메인 스레드가 정리하는 중에 온 콘솔 닫기 이벤트)은 먼저 시작한 정리가 끝날 때까지
    기다린다. 바로 돌아가면 콘솔 핸들러가 False 를 돌려주고, OS 가 정리 도중에 프로세스를 끝낸다.
    """
    global _shutdown_started
    with _shutdown_lock:
        first = not _shutdown_started
        _shutdown_started = True
    if not first:
        _shutdown_finished.wait(10)
        return
    try:
        manager.shutdown()
    finally:
        _shutdown_finished.set()


def _install_shutdown_hooks() -> None:
    atexit.register(_shutdown)
    for sig in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGBREAK", None)):
        if sig is not None:
            signal.signal(sig, lambda *a: (_shutdown(), sys.exit(0)))

    # 콘솔 닫기·로그오프·시스템 종료 (CTRL_CLOSE/LOGOFF/SHUTDOWN)
    handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)

    def _console(event: int) -> bool:
        if event in (2, 5, 6):
            _shutdown()
        return False

    _install_shutdown_hooks.handler = handler_type(_console)  # GC 되지 않게 붙잡아 둔다
    ctypes.windll.kernel32.SetConsoleCtrlHandler(_install_shutdown_hooks.handler, True)


def main() -> None:
    _install_shutdown_hooks()
    try:
        mcp.run()  # stdin 이 닫히면(클라이언트 종료) 돌아온다
    finally:
        _shutdown()


if __name__ == "__main__":
    main()
