"""타깃 프로세스 하나에 대한 읽기·디버깅 세션.

세션 구성 (세션별 서버 모델 — 데몬 없음):
  reader     cdb -pvr  비침투·무정지. 누구나 붙을 수 있고 여러 세션이 동시에 붙어도 된다.
  controller cdb -pd   디버거. 프로세스당 하나만 가능(OS 강제). 소유 세션은 lockfile 로 표시한다.

안전 규칙 (실측 근거는 README):
  - controller 는 항상 -pd. 없으면 cdb 가 죽을 때 타깃도 죽는다.
  - 멈춘 채로 controller 가 죽으면 타깃이 영구 동결된다. 그래서 detach 는 반드시
    bp 전부 해제 → qd 순서로 하고, 서버 종료 경로 전부에서 이 절차를 탄다.
  - 메모리 쓰기는 controller 소유 + 정지 상태에서만 한다.
"""

from __future__ import annotations

import json
import msvcrt
import os
import re
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import unreal, win32
from .cdb import CdbError, CdbSession, check_user_input
from .config import cdb_path, settings
from .dia import DiaService
from .symcache import CachedPdb, ensure_pdb

ATTACH_TIMEOUT = 120.0
RELOAD_TIMEOUT = 600.0  # 엔진 모듈 PDB 는 수 GB 라 심볼 로드가 1분을 넘길 수 있다


class TargetError(RuntimeError):
    pass


# ---- 소유권 lockfile -----------------------------------------------------------------

class OwnerLock:
    """디버거 소유 표시. 파일 내용(소유 정보)이 아니라 파일의 바이트 범위 잠금이 소유권이다.

    잠금은 핸들에 묶여 있어 소유 서버가 어떻게 죽든 OS 가 푼다. 그래서 '죽은 소유자' 판정과
    그 판정을 두 세션이 동시에 하는 경합, pid 재사용 오판이 없다.
    """

    _LOCK_AT = 1 << 20  # 내용(앞부분)은 다른 세션이 읽을 수 있게 잠금 범위를 멀리 둔다

    def __init__(self, pid: int) -> None:
        self.path = settings().locks / f"{pid}.json"
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def _lock(self, fd: int) -> bool:
        os.lseek(fd, self._LOCK_AT, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def _unlock(self, fd: int) -> None:
        os.lseek(fd, self._LOCK_AT, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

    def holder(self) -> dict | None:
        """다른 세션이 잡고 있으면 그 소유 정보, 아니면 None."""
        if self.held:
            return None
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_BINARY)
        except OSError:
            return None
        try:
            if self._lock(fd):
                self._unlock(fd)
                return None
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, 4096)
        finally:
            os.close(fd)
        try:
            return json.loads(data.decode("utf-8"))
        except ValueError:
            return {}  # 소유자가 막 쓰는 중

    def acquire(self) -> None:
        if self.held:
            return
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_BINARY)
        # 다른 세션의 holder() 가 확인하느라 잠깐 잡은 순간일 수 있어 몇 번 다시 본다
        for _ in range(5):
            if self._lock(fd):
                break
            time.sleep(0.05)
        else:
            os.close(fd)
            h = self.holder() or {}
            raise TargetError(
                f"다른 세션(서버 pid {h.get('owner_pid', '?')}, {h.get('started', '?')})이 이 프로세스의 디버거를 갖고 있습니다. "
                "읽기 전용(mode='read')으로 붙거나 그 세션에서 detach 하세요.")
        body = json.dumps({"owner_pid": os.getpid(), "started": time.strftime("%Y-%m-%d %H:%M:%S")}).encode("utf-8")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, body)
        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            os.ftruncate(fd, 0)
            self._unlock(fd)
        except OSError:
            pass
        finally:
            os.close(fd)
        try:
            self.path.unlink()  # 다른 세션이 이미 열었으면 공유 위반으로 실패한다. 그대로 둔다.
        except OSError:
            pass


# ---- 메모리 쓰기 기록 ------------------------------------------------------------------

@dataclass
class WriteRecord:
    id: int
    expr: str
    address: int
    type: str
    old: bytes
    new: bytes
    undone: bool = False

    def as_dict(self) -> dict:
        return {"id": self.id, "expr": self.expr, "address": f"0x{self.address:X}", "type": self.type,
                "old": self.old.hex(), "new": self.new.hex(), "undone": self.undone}


# `&(x) : 0x7ff6... : 1.500000 [Type: float *]` — 포인터면 가리키는 값이 중간에 붙는다
_DX_ADDR = re.compile(r":\s*(0x[0-9a-fA-F`]+)\b.*\[Type:\s*(.+?)\s*\*\s*\]\s*$", re.MULTILINE)
_DX_VALUE = re.compile(r":\s*(0x[0-9a-fA-F`]+|\d+)\b")

_FLOATS = {"float": "<f", "double": "<d"}
# dx 가 보여주는 C++ 기본형 이름 → 부호 있음 여부
_INT_TYPES = {
    "char": True, "signed char": True, "unsigned char": False, "short": True, "unsigned short": False,
    "int": True, "unsigned int": False, "long": True, "unsigned long": False,
    "__int64": True, "unsigned __int64": False, "long long": True, "unsigned long long": False,
    "wchar_t": False, "char16_t": False, "char32_t": False, "char8_t": False,
}


def _bare(type_: str) -> str:
    return type_.replace("const ", "").replace("volatile ", "").strip()


def _encode(type_: str, size: int, value: str, kind: str) -> bytes:
    """kind: int | uint | float | bool | pointer | enum | struct (Target._value_kind 가 정한다)."""
    v = value.strip()
    if v.lower().startswith("hex:"):
        data = bytes.fromhex(v[4:])
        if len(data) != size:
            raise TargetError(f"hex 값은 {size} 바이트여야 합니다 ({len(data)} 바이트 받음).")
        return data
    if kind == "struct":
        # 크기가 1·2·4·8 이어도 구조체(TObjectPtr, FIntPoint ...)에 정수를 그대로 쓰면 조용히 망가진다
        raise TargetError(f"'{type_}' ({size} 바이트) 는 구조체입니다. 'hex:...' 로 바이트를 직접 주거나 필드를 지정하세요.")
    if kind == "float" and struct.calcsize(fmt := _FLOATS[_bare(type_)]) == size:
        return struct.pack(fmt, float(v))
    if kind == "bool":
        if v.lower() not in ("0", "1", "true", "false"):
            raise TargetError(f"bool 에 '{v}' 를 쓸 수 없습니다 (true/false/0/1).")
        return (1 if v.lower() in ("1", "true") else 0).to_bytes(size, "little")
    if kind in ("int", "uint", "pointer", "enum"):
        n = int(v.replace("`", ""), 0)
        try:
            # 음수는 부호 있는 타입에만. 양수는 비트 패턴으로 받는다 (0xFFFFFFFF → int32 -1 등)
            return n.to_bytes(size, "little", signed=n < 0 and kind in ("int", "enum"))
        except OverflowError:
            raise TargetError(f"{v} 는 {type_}({size} 바이트)에 들어가지 않습니다.") from None
    raise TargetError(f"'{type_}' ({size} 바이트) 는 자동 인코딩할 수 없습니다. 'hex:...' 로 바이트를 직접 주세요.")


def _encode_bits(type_: str, size: int, value: str, kind: str, lo: int, hi: int, old: bytes) -> bytes:
    """비트필드 쓰기: 저장 단위(old)에서 lo..hi 비트만 바꾼 바이트. 같은 단위의 이웃 비트필드는 그대로 둔다."""
    if kind not in ("int", "uint", "bool", "enum"):
        raise TargetError(f"비트필드 '{type_}' 에는 정수·bool 만 쓸 수 있습니다.")
    v = value.strip()
    if v.lower().startswith("hex:"):
        raise TargetError("비트필드에는 'hex:' 를 쓸 수 없습니다. 정수 값을 주세요.")
    width = hi - lo + 1
    if not 0 <= lo <= hi < size * 8:
        raise TargetError(f"비트필드 위치({lo}..{hi})가 저장 단위({size} 바이트) 밖입니다. "
                          "소속 바이트를 *(unsigned char*)주소 식에 'hex:' 로 직접 쓰세요.")
    if kind == "bool":
        if v.lower() not in ("0", "1", "true", "false"):
            raise TargetError(f"bool 에 '{v}' 를 쓸 수 없습니다 (true/false/0/1).")
        n = 1 if v.lower() in ("1", "true") else 0
    else:
        n = int(v.replace("`", ""), 0)
    if (n < 0 and (kind not in ("int", "enum") or n < -(1 << (width - 1)))) or n >= (1 << width):
        raise TargetError(f"{v} 는 {width} 비트 비트필드에 들어가지 않습니다.")
    mask = ((1 << width) - 1) << lo
    word = int.from_bytes(old, "little")
    return ((word & ~mask) | ((n << lo) & mask)).to_bytes(size, "little")


# ---- 타깃 -------------------------------------------------------------------------

class Target:
    def __init__(self, pid: int, dia: DiaService) -> None:
        if not win32.process_alive(pid):
            raise TargetError(f"pid {pid} 프로세스가 없습니다.")
        self.pid = pid
        self.dia = dia
        self.lock = OwnerLock(pid)
        self.reader: CdbSession | None = None
        self.controller: CdbSession | None = None
        self.pdbs: dict[str, CachedPdb] = {}
        self.writes: list[WriteRecord] = []
        self.notes: list[str] = []
        self._op = threading.RLock()
        self._pending_reload: set[str] = set()
        # 보냈지만 아직 그 정지를 확인하지 못한 break-in 수. 사용자 bp 가 먼저 적중하면 남았다가 나중에 정지로 도착한다.
        # 정지는 확인한 경로가 어디든(_observe) 한 번만 센다. 늦게 도착한 정지를 wait() 가 흘려보내는 근거다.
        self._pending_breakins = 0
        self._observed_seq = 0  # 마지막으로 확인한 controller 정지 순번 (CdbSession.stop_seq)
        self._stepping = False  # 스텝 명령으로 실행 중 (끼어들었다가 g 로 재개하면 스텝이 사라진다)
        self._attaching: CdbSession | None = None  # 설정 중인 controller (등록 전)
        mods = win32.list_modules(pid)
        self.name = mods[0].name if mods else f"pid{pid}"
        self.is_unreal = unreal.is_unreal(mods)
        self._ue = None  # UEInspector, 첫 사용 때 만든다

    # ---- 연결 ---------------------------------------------------------------------

    def _cdb_args(self, *mode: str) -> list[str]:
        return [*mode, "-sicv", "-noshell", "-lines", "-y", settings().cdb_symbol_path(), "-p", str(self.pid)]

    def _setup_session(self, s: CdbSession) -> None:
        # 비한정 이름(`g_State`)은 심볼이 로드된 모듈에서만 찾는다. 이미 캐시한 모듈은 여기서 로드한다.
        for key in self.pdbs:  # .reload 는 확장자까지 있는 이미지 이름이어야 한다
            s.execute(f".reload /f {key}", timeout=RELOAD_TIMEOUT)
        if self.is_unreal and (nv := unreal.natvis_path(win32.list_modules(self.pid))):
            s.execute(f'.nvload "{nv}"')
            if f"natvis: {nv}" not in self.notes:
                self.notes.append(f"natvis: {nv}")

    def attach(self, mode: str, stop: bool = False) -> dict:
        with self._op:
            # 혼자 죽은 세션은 정리하고 다시 붙는다. controller 를 남겨 두면 lock 도 계속 쥐어 다른 세션까지 막힌다.
            if self.reader is not None and self.reader.exited:
                self.reader = None
            if self.controller is not None and self.controller.exited:
                self.controller = None
                self.lock.release()
                self.notes.append("이전 디버거 세션(cdb)이 혼자 종료돼 있어 정리했습니다.")
            if self._attaching is not None and self._attaching.exited:
                self._attaching = None
            main = win32.list_modules(self.pid)[0]
            # cdb 를 띄우기 전에 캐시를 채워 둬야 첫 심볼 로드가 원본 PDB 대신 사본을 찾는다
            try:
                self._ensure_module(main.name)
            except Exception as e:  # PDB 가 없어도 읽기 자체는 된다
                self.notes.append(f"{main.name} PDB 준비 실패: {e}")
            if self.reader is None:
                r = CdbSession(cdb_path(), self._cdb_args("-pvr"), f"reader:{self.pid}")
                try:
                    r.wait_prompt(ATTACH_TIMEOUT)
                    self._setup_session(r)
                except Exception:
                    r.kill()  # 비침투 세션이라 바로 죽여도 타깃에 영향이 없다. 남겨 두면 시도마다 cdb 가 쌓인다.
                    raise
                self.reader = r
            if mode == "debug" and self.controller is None:
                self.lock.acquire()
                c = None
                try:
                    c = CdbSession(cdb_path(), self._cdb_args("-pd"), f"controller:{self.pid}")
                    # 설정(.reload 가 길 수 있다) 도중 서버가 종료되면 detach(quick) 가 이것도 닫아야 한다
                    self._attaching = c
                    c.wait_prompt(ATTACH_TIMEOUT)  # attach 초기 break — 타깃이 멈춰 있다
                    self._setup_session(c)
                    if not stop:
                        c.resume("g")
                except Exception:
                    # 이미 붙었을 수 있다. 그냥 두거나 죽이면 타깃이 초기 break 로 멈춘 채 남는다.
                    if c is not None:
                        self._close_controller(c)
                    self._attaching = None
                    self.lock.release()
                    raise
                # 설정이 전부 끝난 뒤에만 소유 상태가 된다. 이전 cdb 의 대기 상태는 새 세션과 무관하다.
                self.controller, self._attaching = c, None
                self._observed_seq = c.stop_seq
                self._pending_breakins = 0
                self._pending_reload.clear()  # 새 세션은 _setup_session 에서 캐시한 모듈을 전부 로드했다
                self._stepping = False
            return self.status()

    def _close_controller(self, c: CdbSession, quick: bool = False) -> str:
        """멈춤 → bp 해제 → qd. 멈춘 채로 cdb 가 죽으면 타깃이 동결되므로 어떤 경로든 이 순서를 지킨다.

        quick: 서버 종료용. 클라이언트가 약 2초 뒤 프로세스 트리를 강제 종료하므로 짧게만 기다리고,
        다른 스레드가 긴 명령의 응답을 기다리고 있어도 그 명령 뒤에 bc · qd 를 줄 세워 보낸다.
        """
        if c.exited:
            return "already exited"
        note = ""
        try:
            if c.running:
                try:
                    self._break_in(c, 1.5 if quick else 15)  # bp 에 먼저 걸려도 멈춘 건 같다. qd 가 재개한다
                except TargetError as e:
                    # 그래도 bc · qd 는 보낸다. cdb 는 다음 정지(보낸 break-in 이나 bp)에서 처리한다.
                    note = f" (break-in 실패: {e})"
            # 응답을 기다리지 않고 줄 세워 보낸다. 앞 명령이 시간 초과돼 cdb 가 아직 처리 중이어도 그 뒤에
            # 실행된다. (execute 로 보내면 동기화 실패 때 bc 가 아예 안 나가고, 멈춘 채 kill 될 수 있다.)
            c.send_raw("bc *", wait_lock=not quick)
            c.send_raw("qd", wait_lock=not quick)
            if c.running:
                # quick 은 _op 없이 돈다. 확인과 전송 사이에 다른 스레드가 재개했으면 다시 멈춰야 처리된다.
                try:
                    win32.debug_break(self.pid)
                except OSError:
                    pass
            # 멈춘 채 kill 하면 동결이 확정이므로, quick 이 아니면 cdb 가 앞 명령을 마칠 때까지 충분히 기다린다
            wait = 1.5 if quick else (RELOAD_TIMEOUT if c.busy else 30)
            if c.wait_exit(wait):
                return "detached" + note
            return f"qd 무응답 ({wait:.0f}초) — 강제 종료함 (타깃 상태 확인 필요){note}"
        except Exception as e:
            return f"정상 detach 실패: {e}{note}"
        finally:
            if not c.exited:
                c.kill()

    def detach(self, quick: bool = False) -> dict:
        """quick: 서버 종료용. 다른 작업(PDB 복사, 언리얼 초기화, 긴 명령)이 _op 를 쥐고 있어도 기다리지 않는다."""
        report = {}
        got = self._op.acquire(timeout=0.2 if quick else -1)
        try:
            # 설정 중인 controller(attach 진행 중)도 닫는다. 등록 전이라도 타깃은 초기 break 로 멈춰 있다.
            c = self.controller or self._attaching
            if c is not None:
                report["controller"] = self._close_controller(c, quick)
            self.controller = self._attaching = None
            self.lock.release()
            # 비침투 세션은 디버그 포트를 갖지 않으므로 바로 죽여도 타깃에 영향이 없다.
            # MCP 클라이언트는 stdin 을 닫고 2초 뒤 프로세스 트리를 강제 종료하므로 기다리지 않는다.
            if self.reader is not None:
                self.reader.kill()
            self.reader = None
            report["reader"] = "closed"
        finally:
            if got:
                self._op.release()
        return report

    # ---- 상태 ---------------------------------------------------------------------

    @property
    def owner(self) -> bool:
        return self.controller is not None and not self.controller.exited

    def state(self) -> str:
        if not win32.process_alive(self.pid):
            return "exited"
        if not self.owner:
            return "running(not debugging)" if self.reader else "detached"
        return "running" if self.controller.running else "stopped"

    def status(self) -> dict:
        s = {"pid": self.pid, "name": self.name, "state": self.state(),
             "reader": self.reader is not None, "debugger_owner": self.owner,
             "unreal": self.is_unreal, "pdbs": {k: str(v.path) for k, v in self.pdbs.items()}}
        if not self.owner and (h := self.lock.holder()):
            s["debugger_held_by"] = h
        if self.owner and not self.controller.running:
            s["last_stop"] = _tail(self.controller.last_stop, 25)
        if self.notes:
            s["notes"] = self.notes
        return s

    def _require_owner(self) -> CdbSession:
        if not self.owner:
            raise TargetError("이 세션은 디버거 소유자가 아닙니다. attach(mode='debug') 가 필요합니다.")
        return self.controller

    def _require_stopped(self) -> CdbSession:
        """_op 를 쥔 채로 부른다. 지금 정지를 확인한 것으로 기록한다 (늦은 break-in 판정 때문)."""
        c = self._require_owner()
        if c.running:
            raise TargetError("타깃이 실행 중입니다. break_in 또는 bp 로 먼저 멈추세요.")
        self._observe(c)
        return c

    def _flush_reloads(self, s: CdbSession) -> None:
        for mod in sorted(self._pending_reload):
            s.execute(f".reload /f {mod}", timeout=RELOAD_TIMEOUT)
            self._pending_reload.discard(mod)

    def _session_for_read(self) -> tuple[CdbSession, str]:
        """정지 중이면 controller(일관된 스냅숏), 아니면 reader(실행 중 값, 찢어질 수 있음)."""
        if self.owner and not self.controller.running:
            return self.controller, "snapshot (stopped)"
        if self.reader is None:
            raise TargetError("attach 가 필요합니다.")
        return self.reader, "live (target running — 여러 필드가 서로 다른 시점 값일 수 있음)"

    # ---- 심볼 ---------------------------------------------------------------------

    def _ensure_module(self, module: str) -> CachedPdb:
        # _op 안에서 한다: pdbs 를 바꾸는 동안 _setup_session 이 순회하거나, running 확인과 .reload 사이에
        # 다른 호출이 resume 하면 reload 가 실행도 예약도 안 된다.
        with self._op:
            m = win32.find_module(self.pid, module)
            key = m.name.lower()
            if key in self.pdbs:
                return self.pdbs[key]
            pdb = win32.read_pdb_id(self.pid, m.base)
            if pdb is None:
                raise TargetError(f"{m.name} 에 CodeView(RSDS) 디버그 정보가 없습니다.")
            cached = ensure_pdb(m, pdb, self.dia.validate)
            self.pdbs[key] = cached
            if self.reader is not None:
                self.reader.execute(f".reload /f {m.name}", timeout=RELOAD_TIMEOUT)
            if self.controller is not None:
                if self.controller.running:
                    self._pending_reload.add(m.name)
                else:
                    self.controller.execute(f".reload /f {m.name}", timeout=RELOAD_TIMEOUT)
            return cached

    def prepare_symbols(self, modules: list[str]) -> dict:
        out = {}
        with self._op:
            for mod in modules:
                try:
                    c = self._ensure_module(mod)
                    out[mod] = {"pdb": str(c.path), "source": str(c.source), "in_place": c.in_place}
                except Exception as e:
                    out[mod] = {"error": str(e)}
        return out

    def modules(self, filter_: str = "") -> list[dict]:
        out = []
        for m in win32.list_modules(self.pid):
            if filter_ and filter_.lower() not in m.name.lower():
                continue
            item = {"name": m.name, "base": f"0x{m.base:X}", "size": m.size, "path": m.path}
            if (c := self.pdbs.get(m.name.lower())):
                item["pdb"] = str(c.path)
            out.append(item)
        return out

    def find_symbols(self, module: str, pattern: str, kind: str, limit: int) -> list[dict]:
        c = self._ensure_module(module)
        return self.dia.find(c.path, pattern, kind, limit)

    def type_layout(self, module: str, type_name: str) -> dict:
        c = self._ensure_module(module)
        return self.dia.layout(c.path, type_name)

    def symbol_at(self, address: int) -> dict:
        m = win32.find_module(self.pid, address)
        c = self._ensure_module(m.name)
        hit = self.dia.at_rva(c.path, address - m.base)
        return {"module": m.name, "rva": f"0x{address - m.base:X}", "symbol": hit}

    def dynamic_type(self, address: int) -> dict:
        """객체의 vptr 이 가리키는 vftable 심볼로 실제 클래스를 판별한다 (/GR- 에서도 동작)."""
        vptr = struct.unpack("<Q", win32.read_memory(self.pid, address, 8))[0]
        try:
            m = win32.find_module(self.pid, vptr)
        except LookupError:
            return {"vptr": f"0x{vptr:X}", "class": None, "reason": "vptr 가 모듈 안을 가리키지 않습니다 (다형 타입이 아니거나 잘못된 주소)."}
        c = self._ensure_module(m.name)
        hit = self.dia.at_rva(c.path, vptr - m.base) or {}
        name = hit.get("undecorated") or hit.get("name") or ""
        cls = None
        if (mm := re.match(r"(?:const\s+)?(.+?)::`vftable'", name)):
            cls = mm.group(1)
        elif name.startswith("??_7") and "@@6B" in name:
            cls = name[4:name.index("@@6B")]
        return {"vptr": f"0x{vptr:X}", "module": m.name, "vftable_symbol": name, "class": cls,
                "displacement": hit.get("displacement")}

    # ---- 읽기 ---------------------------------------------------------------------

    def evaluate(self, expr: str, depth: int) -> dict:
        cmd = f"dx -r{max(0, min(depth, 10))} {expr}"
        check_user_input(cmd)
        with self._op:
            s, kind = self._session_for_read()
            if s is self.controller:
                self._flush_reloads(s)
            out = s.execute(cmd)
        return {"read": kind, "output": out}

    def read_memory(self, address: int, size: int) -> dict:
        size = max(1, min(size, 64 * 1024))
        data = win32.read_memory(self.pid, address, size)
        lines = []
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{address + off:016X}  {chunk.hex(' '):<47}  {text}")
        return {"read": "live" if not (self.owner and not self.controller.running) else "snapshot (stopped)",
                "dump": "\n".join(lines)}

    def command(self, cmd: str) -> dict:
        check_user_input(cmd)
        with self._op:
            s, kind = self._session_for_read()
            if s is self.controller:
                self._flush_reloads(s)
            return {"session": "controller" if s is self.controller else "reader", "read": kind, "output": s.execute(cmd)}

    # ---- 언리얼 해석기 ----------------------------------------------------------------

    def ue(self):
        from .unreal.context import UEContext
        from .unreal.inspect import UEInspector

        with self._op:
            if self._ue is None:
                if self.reader is None:
                    raise TargetError("attach 가 필요합니다.")
                self._ue = UEInspector(UEContext(self))
                if (n := self._ue.ctx.note) and n not in self.notes:
                    self.notes.append(n)
            return self._ue

    @staticmethod
    def _with_note(insp, out: dict) -> dict:
        if insp.ctx.note:
            out["note"] = insp.ctx.note
        return out

    def _addr_and_type(self, expr: str) -> tuple[int, str, str]:
        # 맨 식이 아니라 실제로 보낼 명령을 검사한다. 맨 식이면 g_State 의 g 를 명령 이름으로 오인한다.
        cmd = f"dx -r0 &({expr})"
        check_user_input(cmd)
        with self._op:
            s, kind = self._session_for_read()
            if s is self.controller:
                self._flush_reloads(s)
            out = s.execute(cmd)
        if not (m := _DX_ADDR.search(out)):
            raise TargetError(f"'{expr}' 의 주소를 구하지 못했습니다:\n{out.strip()[-500:]}")
        return int(m.group(1).replace("`", ""), 16), m.group(2).strip(), kind

    def ue_inspect(self, expr: str, depth: int, max_elements: int) -> dict:
        from .unreal.inspect import Budget

        insp = self.ue()
        addr, type_, kind = self._addr_and_type(expr)
        budget = Budget(max_elements=max(1, min(max_elements, 1000)))
        value = insp.render(addr, type_, max(0, min(depth, 6)), budget)
        out = {"expression": expr, "type": type_, "address": f"0x{addr:X}", "read": kind, "value": value}
        if budget.truncated:
            out["truncated"] = budget.truncated[:5]
        return self._with_note(insp, out)

    def ue_find_objects(self, name: str, class_name: str, limit: int, exact: bool) -> dict:
        insp = self.ue()
        out = insp.objects.find(name, class_name, max(1, min(limit, 500)), exact)
        out["type_module"] = insp.ctx.cdb_module
        return self._with_note(insp, out)

    _WORLD_TYPES = {0: "None", 1: "Game", 2: "Editor", 3: "PIE", 4: "EditorPreview", 5: "GamePreview", 6: "GameRPC", 7: "Inactive"}

    def ue_worlds(self) -> dict:
        insp = self.ue()
        ctx, objs = insp.ctx, insp.objects
        # 식에서 UE 타입을 캐스트할 때 쓸 모듈 한정자 (예: *(UnrealEditor_ChronoSpace!UWorld*)0x...)
        out = {"type_module": ctx.cdb_module, "worlds": []}
        # 모놀리식 빌드는 기준 모듈 PDB 에, 모듈형(에디터)은 엔진 DLL export 에 GEngine 이 있다
        try:
            engine_var = ctx.global_addr("GEngine")
        except Exception:
            engine_var = ctx.export_addr("UnrealEditor_Engine!GEngine")
        engine = ctx.u64(engine_var)
        if not engine:
            raise TargetError("GEngine 이 아직 없습니다 (엔진 초기화 전).")
        wl = ctx.field("UEngine", "WorldList")
        arr_f = ctx.field(wl.type, "Array")
        from .unreal.containers import tarray
        arr = tarray(ctx, engine + wl.offset + arr_f.offset, arr_f.type)
        f_type = ctx.field("FWorldContext", "WorldType")
        f_world = ctx.field("FWorldContext", "ThisCurrentWorld")
        f_gi = ctx.field("FWorldContext", "OwningGameInstance")
        f_pie = ctx.field("FWorldContext", "PIEInstance")
        for i in range(arr.count):
            wc = ctx.u64(arr.data + i * 8)
            wt = ctx.u8(wc + f_type.offset)
            world = ctx.u64(wc + f_world.offset)
            gi = ctx.u64(wc + f_gi.offset)
            entry = {"context": f"0x{wc:X}", "world_type": self._WORLD_TYPES.get(wt, wt),
                     "world": objs.identity(world) if world else None,
                     "game_instance": objs.identity(gi) if gi else None}
            if wt == 3:
                entry["pie_instance"] = ctx.i32(wc + f_pie.offset)
            out["worlds"].append(entry)
        return self._with_note(insp, out)

    # ---- 실행 제어 -------------------------------------------------------------------

    def _observe(self, c: CdbSession) -> bool:
        """_op 를 쥔 채로 부른다. 지금의 정지를 확인한 것으로 기록한다.

        처음 확인하는 정지이고 그것이 보낸 break-in 의 정지면 True (대기 수를 하나 줄인다).
        같은 정지를 여러 경로가 봐도 한 번만 센다. 그래야 다른 경로가 소비한 늦은 break-in 때문에
        나중의 정지를 잘못 흘려보내지 않는다.
        """
        seq = c.stop_seq
        if seq == self._observed_seq:
            return False
        self._observed_seq = seq
        self._stepping = False
        if self._pending_breakins > 0 and _is_breakin_stop(c.last_stop):
            self._pending_breakins -= 1
            return True
        return False

    def _break_in(self, c: CdbSession, timeout: float) -> bool:
        """_op 를 쥔 채로 부른다. 실행 중인 타깃을 멈춘다.

        break-in 정지로 멈췄으면 True, 그 사이 사용자 bp 가 먼저 걸렸으면 False (보낸 break-in 은 대기로 남는다).
        """
        self._pending_breakins += 1
        try:
            win32.debug_break(self.pid)
        except OSError:
            self._pending_breakins -= 1
            raise
        if c.wait_stopped(timeout) is None:
            raise TargetError(f"{timeout}초 안에 멈추지 않았습니다.")  # 보낸 break-in 은 나중에 도착할 수 있다
        return self._observe(c)

    def break_in(self, timeout: float = 15) -> dict:
        with self._op:  # _with_stopped 의 끼어들기·재개와 섞이지 않게
            c = self._require_owner()
            by_us = True
            if c.running:
                by_us = self._break_in(c, timeout)
            else:
                self._observe(c)  # 이미 멈춰 있던 정지(늦은 break-in 포함)를 사용자 정지로 넘긴다
            self._flush_reloads(c)
        st = self.status()
        if not by_us:
            st["note"] = "break-in 과 동시에 bp 가 먼저 적중해 그 bp 에서 멈췄습니다."
        return st

    def resume(self) -> dict:
        with self._op:
            c = self._require_stopped()
            c.resume("g")
            self._stepping = False
        return self.status()

    def wait(self, timeout: float, stepping: bool = False) -> dict:
        # 기다리는 동안 _op 를 잡지 않는다 (읽기 도구가 막히지 않도록). 정지를 판정할 때만 잡고 다시 확인한다.
        c = self._require_owner()
        end = time.monotonic() + timeout
        note = None
        while True:
            stopped = c.wait_stopped(max(0.0, end - time.monotonic()))
            if stopped is None:
                break
            with self._op:
                if c.running:
                    continue  # 다른 호출(_with_stopped 등)이 잠깐 끼어든 정지다. 이미 재개됐다
                if c.stop_seq == self._observed_seq:
                    break  # 다른 경로(break_in 등)가 이미 사용자 정지로 확인한 정지
                # step 의 대기가 시간 초과된 뒤 사용자가 wait 를 직접 불러도 스텝 중일 수 있다.
                # _observe 가 _stepping 을 지우므로 먼저 읽어 둔다.
                was_stepping = stepping or self._stepping
                if not self._observe(c):
                    break  # bp 적중 등 사용자가 기다리던 정지
                # 앞서 bp 에 밀린 break-in 이 늦게 도착한 정지는 사용자가 기다리던 정지가 아니다
                if was_stepping:
                    # g 로 넘기면 스텝이 사라진다. 현재 스레드도 break-in 스레드로 바뀌었다.
                    note = ("스텝 도중 앞서 보낸 break-in 이 늦게 도착해 멈췄습니다. 현재 스레드가 break-in "
                            "스레드로 바뀌었으니 스레드를 확인하고 스텝을 다시 하세요.")
                    break
                c.resume("g")
        st = self.status()
        st["timed_out"] = stopped is None
        if note:
            st["note"] = note
        return st

    def step(self, kind: str, timeout: float = 30) -> dict:
        cmd = {"over": "p", "into": "t", "out": "gu"}[kind]
        with self._op:
            c = self._require_stopped()
            c.resume(cmd)
            self._stepping = True
        return self.wait(timeout, stepping=True)

    def _with_stopped(self, fn) -> tuple[object, str | None]:
        """실행 중이면 잠깐 끼어들어 fn 을 하고 다시 실행시킨다.

        끼어드는 순간 사용자 bp 가 먼저 적중했으면 그 정지를 삼키지 않도록 재개하지 않고 멈춘 채 둔다.
        반환: (fn 결과, 알림 또는 None)
        """
        c = self._require_owner()
        with self._op:
            resume_after, note = False, None
            if c.running and self._stepping:
                # 끼어들었다가 g 로 재개하면 진행 중인 스텝이 사라지고 타깃이 자유 실행된다
                raise TargetError("스텝이 진행 중입니다. 스텝이 끝난 뒤(wait) 다시 시도하세요.")
            if c.running:
                if self._break_in(c, 15):
                    resume_after = True
                else:
                    # 이 정지는 사용자가 아직 보지 못했다. 확인 기록을 되돌려 wait 가 돌려주게 한다.
                    self._observed_seq -= 1
                    note = ("끼어드는 순간 bp 가 먼저 적중해서 그 bp 에서 멈춘 채로 뒀습니다. "
                            "wait 로 정지 사유를 확인하고 resume 하세요.")
            try:
                self._flush_reloads(c)
                return fn(c), note
            finally:
                if resume_after:
                    c.resume("g")

    def set_breakpoint(self, location: str, condition: str | None, once: bool) -> dict:
        note = None
        if (m := re.match(r"^\s*`?([\w.\-]+)!", location)):
            with self._op:
                try:
                    self._ensure_module(m.group(1))
                except (LookupError, TargetError, RuntimeError) as e:
                    # PDB 가 없어도 cdb 는 export 심볼로 bp 를 걸 수 있다 (예: 엔진 PDB 없는 런처 엔진)
                    note = f"PDB 없이 진행 (export 심볼만 사용): {e}"
        parts = ["bu"]
        if once:
            parts.append("/1")
        if condition:
            if '"' in condition:
                raise TargetError('조건식에 큰따옴표를 쓸 수 없습니다.')
            parts.append(f'/w "{condition}"')
        loc = location.strip()
        # 소스 줄: file.cpp:12, module!file.cpp:12, C:\path\file.cpp:12 → cdb 는 백틱으로 감싸야 한다
        if re.fullmatch(r"(?:[\w.\-]+!)?[^`!]+:\d+", loc):
            loc = f"`{loc}`"
        parts.append(loc)
        cmd = " ".join(parts)
        check_user_input(cmd)
        out, stop_note = self._with_stopped(lambda c: c.execute(cmd) + "\n" + c.execute("bl"))
        result = {"command": cmd, "output": out}
        notes = [n for n in (note, stop_note) if n]
        if notes:
            result["note"] = " / ".join(notes)
        return result

    def list_breakpoints(self) -> str:
        out, note = self._with_stopped(lambda c: c.execute("bl"))
        return out + (f"\n[note] {note}" if note else "")

    def clear_breakpoint(self, bp_id: str) -> str:
        if not re.fullmatch(r"\*|\d+(\s*-\s*\d+)?", bp_id.strip()):
            raise TargetError("id 는 숫자, 범위(1-3), 또는 * 입니다.")
        out, note = self._with_stopped(lambda c: c.execute(f"bc {bp_id}") + "\n" + c.execute("bl"))
        return out + (f"\n[note] {note}" if note else "")

    def stack(self, frames: int) -> str:
        with self._op:
            c = self._require_stopped()
            return c.execute(f"kn {max(1, min(frames, 200))}")

    def locals(self, frame: int) -> str:
        with self._op:
            c = self._require_stopped()
            return c.execute(f".frame {int(frame)}") + "\n" + c.execute("dv /t /v")

    # ---- 쓰기 ---------------------------------------------------------------------

    def write(self, expr: str, value: str) -> dict:
        # 대상 식에 대입이 있으면 주소를 구하는 dx 가 먼저 써 버린다. 맨 식이 아니라 보낼 명령 형태로 검사한다.
        check_user_input(f"dx -r0 &({expr})")
        with self._op:
            c = self._require_stopped()
            self._flush_reloads(c)
            addr_out = c.execute(f"dx -r0 &({expr})")
            if not (m := _DX_ADDR.search(addr_out)):
                raise TargetError(f"'{expr}' 의 주소를 구하지 못했습니다:\n{addr_out}")
            address = int(m.group(1).replace("`", ""), 16)
            type_ = m.group(2).strip()
            size_out = c.execute(f"dx -r0 sizeof({expr})")
            if not (s := _DX_VALUE.search(size_out)):
                raise TargetError(f"'{expr}' 의 크기를 구하지 못했습니다:\n{size_out}")
            size = int(s.group(1).replace("`", ""), 0)
            kind = self._value_kind(type_)
            if (bits := self._bitfield_bits(c, expr)) is None:
                data = _encode(type_, size, value, kind)
            else:
                lo, hi = bits
                data = _encode_bits(type_, size, value, kind, lo, hi, win32.read_memory(self.pid, address, size))
                type_ = f"{type_} : bits {lo}..{hi}"
            return self._write_bytes(c, expr, address, type_, data)

    def _bitfield_bits(self, c: CdbSession, expr: str) -> tuple[int, int] | None:
        """비트필드면 (하위 비트, 상위 비트), 아니면 None.

        dx 는 비트필드의 주소를 소속 저장 단위의 주소와 'unsigned char *' 로 돌려줘 일반 필드와 구분되지 않는다(실측).
        C++ 식 평가기(??)는 비트필드의 주소를 거부하므로 그걸로 판별하고, 비트 위치는 부모의 원시 레이아웃
        (dx -r1 (부모),! 의 '[+0x000 ( 4: 2)] Mode') 에서 읽는다.
        """
        no_addr = "No address for operator&" in c.execute(f"?? &({expr})")
        if (m := re.fullmatch(r"\s*(.+)(\.|->)\s*(\w+)\s*", expr)):
            parent = m.group(1) if m.group(2) == "." else f"*({m.group(1)})"
            out = c.execute(f"dx -r1 ({parent}),!")
            pat = r"\[\+0x[0-9a-fA-F]+ \(\s*(\d+):\s*(\d+)\)\]\s+" + re.escape(m.group(3)) + r"\s+:"
            if (b := re.search(pat, out)):
                return int(b.group(2)), int(b.group(1))
        if no_addr:
            raise TargetError(f"'{expr}' 는 비트필드로 보이는데 비트 위치를 알아내지 못했습니다. "
                              "소속 바이트를 *(unsigned char*)주소 식에 'hex:' 로 직접 쓰세요.")
        return None

    def _value_kind(self, type_: str) -> str:
        """dx 타입 이름으로 값 종류를 정한다. 기본형·포인터가 아니면 PDB 에서 열거형인지 확인하고, 나머지는 구조체."""
        t = _bare(type_)
        if t.endswith(("*", "&")):
            return "pointer"
        if t in _FLOATS:
            return "float"
        if t == "bool":
            return "bool"
        if t in _INT_TYPES:
            return "int" if _INT_TYPES[t] else "uint"
        name = t[5:] if t.startswith("enum ") else t
        for pdb in self.pdbs.values():
            try:
                if any(h["name"] == name and h["kind"] == "enum" for h in self.dia.find(pdb.path, name, "type", 5)):
                    return "enum"
            except Exception:
                continue
        return "struct"

    def _write_bytes(self, c: CdbSession, expr: str, address: int, type_: str, data: bytes) -> dict:
        # 쓰는 범위에 걸친 모든 영역을 본다 (시작·끝만 보면 가운데 가드·읽기 전용 페이지를 놓친다)
        a, end = address, address + len(data)
        while a < end:
            region = win32.query_region(self.pid, a)
            if not region.writable:
                raise TargetError(f"0x{a:X} 는 쓰기 가능한 페이지가 아닙니다 (protect=0x{region.protect:X}).")
            if region.executable:
                raise TargetError(f"0x{a:X} 는 실행 가능한 페이지입니다. 코드 영역 쓰기는 허용하지 않습니다.")
            a = region.base + region.size
        old = win32.read_memory(self.pid, address, len(data))
        # dbgeng 의 메모리 뷰와 어긋나지 않도록 cdb 로 쓴다
        c.execute(f"eb 0x{address:X} " + " ".join(f"{b:02x}" for b in data))
        after = win32.read_memory(self.pid, address, len(data))
        if after != data:
            raise TargetError(f"쓰기 확인 실패: 기대 {data.hex()} / 실제 {after.hex()}")
        rec = WriteRecord(len(self.writes) + 1, expr, address, type_, old, data)
        self.writes.append(rec)
        return {"write": rec.as_dict(), "value_now": c.execute(f"dx -r1 {expr}") if expr else None}

    def undo_write(self, write_id: int) -> dict:
        with self._op:
            c = self._require_stopped()
            rec = next((w for w in self.writes if w.id == write_id), None)
            if rec is None or rec.undone:
                raise TargetError(f"되돌릴 쓰기 #{write_id} 가 없습니다.")
            current = win32.read_memory(self.pid, rec.address, len(rec.new))
            if current != rec.new:
                raise TargetError(f"#{write_id} 이후 값이 바뀌었습니다 (현재 {current.hex()}). 덮어쓰지 않습니다.")
            c.execute(f"eb 0x{rec.address:X} " + " ".join(f"{b:02x}" for b in rec.old))
            rec.undone = True
            return {"undone": rec.as_dict()}


def _is_breakin_stop(text: str) -> bool:
    """DebugBreakProcess 로 만든 정지인가 (ntdll!DbgBreakPoint 의 int3). bp 적중이면 False."""
    if re.search(r"Breakpoint \d+ hit", text):
        return False
    # "Break instruction exception" 만으로는 안 된다: ensure()·__debugbreak 도 같은 예외다. 위치로 구분한다.
    return "Break instruction exception" in text and re.search(r"\bntdll!DbgBreakPoint\b", text) is not None


def _tail(text: str, n: int) -> str:
    return "\n".join(text.strip().splitlines()[-n:])


class TargetManager:
    def __init__(self) -> None:
        self.dia = DiaService()
        self.targets: dict[int, Target] = {}
        self._lock = threading.Lock()

    def get(self, pid: int) -> Target:
        t = self.targets.get(pid)
        if t is None:
            raise TargetError(f"pid {pid} 에 attach 하지 않았습니다.")
        return t

    def attach(self, pid: int, mode: str, stop: bool) -> dict:
        with self._lock:
            t = self.targets.get(pid) or Target(pid, self.dia)
            self.targets[pid] = t
        try:
            return t.attach(mode, stop)
        except Exception:
            if t.reader is None and t.controller is None:
                self.targets.pop(pid, None)
            raise

    def detach(self, pid: int, quick: bool = False) -> dict:
        t = self.get(pid)
        report = t.detach(quick)
        self.targets.pop(pid, None)
        return report

    def shutdown(self) -> None:
        """타깃별 detach 를 병렬로 한다. 클라이언트가 주는 유예 시간(보통 2초) 안에 끝내야 한다."""
        threads = [threading.Thread(target=self._detach_quiet, args=(pid,)) for pid in list(self.targets)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(10)

    def _detach_quiet(self, pid: int) -> None:
        try:
            self.detach(pid, quick=True)
        except Exception:
            pass
