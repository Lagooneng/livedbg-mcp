"""cdb.exe 를 파이프로 제어하는 세션.

cdb 는 프롬프트(`0:000> `)를 출력한 뒤에만 입력을 읽는다. 명령 완료는 출력 끝에 프롬프트가
다시 나타나는 것으로 판단한다. 실행 명령(g, p, t ...)은 프롬프트가 사라지므로 resume() 으로만
보내고, 다음 정지는 wait_stopped() 로 받는다.
"""

from __future__ import annotations

import codecs
import locale
import re
import subprocess
import threading
import time
from pathlib import Path

# cdb 는 파이프 입출력을 ANSI 코드 페이지로 처리한다 (실측: 한국어 Windows 에서 '한글' 이 CP949 바이트로 나오고,
# UTF-8 로 보내면 '?' 로 깨진다). 한국어 환경은 ANSI 와 OEM 이 같은 949 라 둘 중 어느 쪽인지는 구분하지 못했다.
CDB_ENCODING = locale.getencoding()
PROMPT = re.compile(r"(?:^|\n)(\d+:\d+(?::x86)?)> $")
# 뒤에 글자가 아닌 것이 오면 명령 이름이 끝난 것이다 (\b 는 p10 · pct 같은 형태를 놓친다)
EXEC_COMMANDS = re.compile(r"^\s*(g[hnu]?|p[acht]?|pct|t[abcht]?|tct|wt|gc)(?![a-z])", re.IGNORECASE)
# 세션 수명은 이 패키지가 관리한다. 우회하면 종료 정리(bp 해제 → detach)가 깨진다.
LIFECYCLE_COMMANDS = re.compile(
    r"^\s*(q[qd]?|\.kill|\.detach|\.abandon|\.restart|\.attach|\.create|\.opendump|\.shell|\.endsrv|\.server)\b",
    re.IGNORECASE,
)
# 다른 명령을 간접 실행해서 위 검사를 우회할 수 있는 구문: 제어 블록, 스크립트 파일, 별칭, 조건 실행
INDIRECT_COMMANDS = re.compile(
    r"^\s*(\.if|\.elsif|\.else|\.block|\.for|\.foreach|\.while|\.do|\.catch|\.leave|\.break|\.continue"
    r"|\$\$?>?a?<|\$<|as|aS|al|ad|j|z|\.script\w*|\.load|\.loadby|\.unload\w*|\.ocommand|!for_each_\w*)(\b|\s|<|$)",
)
# dx 데이터 모델에서 디버거 명령을 문자열로 실행하는 API. 문자열을 조립하면 따옴표 검사를 피한다.
DX_COMMAND_API = re.compile(r"ExecuteCommand|Utility\s*\.\s*Control", re.IGNORECASE)
# ~<스레드> 접두: 뒤 명령을 그 스레드에서 실행한다 (~0 g, ~*e qd, ~~[tid]g). 접두를 떼고 검사한다.
THREAD_PREFIX = re.compile(r"^~\s*(?:~\[[^\]]*\]|\[[^\]]*\]|[.#*]|\d+)?\s*")
# 스레드 동결(f)·일시 중단(n): detach 뒤에도 남아 타깃이 멈춘다
THREAD_STATE = re.compile(r"^[fn]\b", re.IGNORECASE)
# 메모리·레지스터를 바꾸는 명령. write_memory 도구만 쓴다 (정지·소유 확인, 페이지 검사, 기록).
WRITE_COMMANDS = re.compile(
    r"^\s*(e(?:[abdfpquw]|z[au])?|f|fp|m|\.call|\.readmem|\.dvalloc|\.dvfree)(?![a-z])", re.IGNORECASE)


def check_command(command: str) -> None:
    """execute 로 보낼 수 있는 명령인가. 실행·수명 명령과, 그런 명령을 간접 실행할 수 있는 구문을 거부한다."""
    if "\n" in command or "\r" in command:
        raise CdbError("명령은 한 줄이어야 합니다.")
    if "{" in command or "}" in command:
        raise CdbError("중괄호 블록은 허용하지 않습니다 (블록 안 명령은 검사할 수 없음).")
    if DX_COMMAND_API.search(command):
        raise CdbError("dx 로 디버거 명령을 실행하는 API 는 허용하지 않습니다.")
    # bp 의 /w "조건" 은 명령이 아니라 C++ 식이다. 명령 검사 대상에서 뺀다.
    command = re.sub(r'/w\s+"[^"]*"', "/w", command)
    for part in _split_commands(command):
        if part.startswith("~"):
            part = THREAD_PREFIX.sub("", part, count=1)
            if THREAD_STATE.match(part):
                raise CdbError("스레드 동결·일시 중단 명령은 detach 뒤에도 남아 타깃을 멈추므로 허용하지 않습니다.")
            part = re.sub(r"^e\s+", "", part)  # ~*e <명령>
        if not part:
            continue
        if LIFECYCLE_COMMANDS.match(part):
            raise CdbError(f"'{part.split()[0]}' 는 세션 수명을 바꾸는 명령이라 허용하지 않습니다. detach 도구를 쓰세요.")
        if EXEC_COMMANDS.match(part):
            raise CdbError(f"실행 명령 '{part.split()[0]}' 은 resume() 으로 보내야 합니다.")
        if INDIRECT_COMMANDS.match(part):
            raise CdbError(f"'{part.split()[0]}' 는 다른 명령을 간접 실행할 수 있어 허용하지 않습니다.")


def check_user_input(text: str) -> None:
    """사용자(모델)가 준 명령·식. check_command 에 더해 메모리·레지스터 쓰기를 거부한다.

    읽기 세션(-pvr)도 메모리를 쓸 수 있으므로, 쓰기는 write_memory 한 경로로만 한다.
    bp 조건식(/w "...")도 식이므로 대입이 있으면 적중할 때마다 쓰기가 된다.
    """
    check_command(text)
    for cond in re.findall(r'/w\s+"([^"]*)"', text):
        if _has_assignment(cond):
            raise CdbError("bp 조건식에 대입·증감이 있습니다. 조건은 비교식만 씁니다.")
    for part in _split_commands(re.sub(r'/w\s+"[^"]*"', "/w", text)):
        if part.startswith("~"):
            part = re.sub(r"^e\s+", "", THREAD_PREFIX.sub("", part, count=1))
        if WRITE_COMMANDS.match(part):
            raise CdbError(f"'{part.split()[0]}' 는 메모리를 바꾸는 명령입니다. write_memory 도구를 쓰세요.")
        if _has_assignment(part):  # dx/?? 대입, r rax=1 레지스터 쓰기
            raise CdbError("대입·증감(=, +=, ++ 등)이 있습니다. 값 변경은 write_memory 도구를 씁니다 (레지스터 쓰기는 지원하지 않음).")


def _has_assignment(expr: str) -> bool:
    """값을 바꾸는 연산이 있는가: ==, !=, <=, >=, => 가 아닌 = (+=, <<= 포함), ++, --.
    따옴표 안과 심볼 이름의 operator=, operator++ 등은 보지 않는다."""
    s = re.sub(r'"[^"]*"', '""', expr)
    s = re.sub(r"\boperator\s*(?:[-+*/%^&|<>!=]{1,3}|\(\)|\[\])", "operator", s)
    if "++" in s or "--" in s:
        return True
    for i, ch in enumerate(s):
        if ch != "=":
            continue
        prev = s[i - 1] if i else ""
        nxt = s[i + 1] if i + 1 < len(s) else ""
        if nxt and nxt in "=>":  # == 의 앞쪽, 람다 =>
            continue
        if prev in ("=", "!"):  # == 의 뒤쪽, !=
            continue
        if prev and prev in "<>" and (i < 2 or s[i - 2] != prev):  # <=, >= (<<=, >>= 는 대입)
            continue
        return True
    return False


class CdbError(RuntimeError):
    pass


class CdbSession:
    def __init__(self, cdb: Path, args: list[str], label: str) -> None:
        self.label = label
        self._p = subprocess.Popen(
            [str(cdb), *args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW, bufsize=0,
        )
        self._buf = ""
        self._cv = threading.Condition()
        self._cmd_lock = threading.Lock()  # 명령-응답 짝
        self._write_lock = threading.Lock()  # 파이프 쓰기 자체
        self._running = False
        self._last_stop = ""
        self._stop_seq = 0  # 실행 → 정지 전환마다 1 씩. 같은 정지를 두 번 처리하지 않게 하는 데 쓴다
        self._pump_done = False
        # 시간 초과로 끝난 명령이 있다: cdb 는 그 명령을 계속 처리하다 나중에 프롬프트를 찍는다.
        # 그 늦은 프롬프트를 다음 명령(특히 resume 뒤의 정지)의 것으로 오인하지 않도록 다음 요청 전에 동기화한다.
        self._stale = False
        self._prompted = False  # 첫 프롬프트를 받았는가 (attach 완료)
        self._sync_no = 0
        threading.Thread(target=self._pump, name=f"cdb-{label}", daemon=True).start()

    # ---- 출력 펌프 ---------------------------------------------------------------

    def _pump(self) -> None:
        out = self._p.stdout  # bufsize=0 → FileIO. read(n) 은 지금 있는 만큼만 돌려준다
        # 청크 경계에서 멀티바이트 문자가 잘려도 깨지지 않도록 증분 디코더를 쓴다
        decoder = codecs.getincrementaldecoder(CDB_ENCODING)(errors="replace")
        try:
            while chunk := out.read(65536):
                with self._cv:
                    self._buf += decoder.decode(chunk)
                    if self._running and PROMPT.search(self._buf):
                        self._running = False
                        self._stop_seq += 1
                        self._last_stop, self._buf = self._buf, ""
                    self._cv.notify_all()
        except Exception as e:  # 펌프가 죽으면 대기 중인 쪽이 시간 초과까지 멈추지 않게 알린다
            with self._cv:
                self._buf += f"\n[livedbg: 출력 읽기 실패: {e!r}]"
        finally:
            with self._cv:
                self._pump_done = True
                self._cv.notify_all()

    # ---- 상태 --------------------------------------------------------------------

    @property
    def exited(self) -> bool:
        return self._pump_done or self._p.poll() is not None

    @property
    def running(self) -> bool:
        with self._cv:
            return self._running

    @property
    def last_stop(self) -> str:
        with self._cv:
            return self._last_stop

    @property
    def busy(self) -> bool:
        """cdb 가 아직 앞 일을 처리 중일 수 있다: 시간 초과로 끝난 명령, 또는 아직 첫 프롬프트 전(attach 중)."""
        return self._stale or not self._prompted

    @property
    def stop_seq(self) -> int:
        with self._cv:
            return self._stop_seq

    # ---- 명령 --------------------------------------------------------------------

    def wait_prompt(self, timeout: float) -> str:
        """시작 직후의 첫 프롬프트를 기다린다."""
        with self._cv:
            out = self._wait_for(lambda b: PROMPT.search(b) is not None, timeout, "첫 프롬프트 대기")
        self._prompted = True
        return _strip_prompt(out)

    def _write(self, text: str) -> None:
        if self.exited:
            raise CdbError(f"cdb({self.label}) 가 이미 종료됐습니다.")
        try:
            data = (text + "\n").encode(CDB_ENCODING)
        except UnicodeEncodeError as e:
            raise CdbError(f"cdb 입력 인코딩({CDB_ENCODING})으로 표현할 수 없는 문자가 있습니다: {e}") from None
        with self._write_lock:
            self._p.stdin.write(data)
            self._p.stdin.flush()

    def _wait_for(self, done, timeout: float, what: str) -> str:
        """_cv 를 쥔 채로 부른다. done(buf) 가 참이 될 때까지 기다리고, 버퍼를 비우며 그 내용을 돌려준다."""
        end = time.monotonic() + timeout
        while not done(self._buf):
            if self.exited:
                raise CdbError(f"{what} 도중 cdb({self.label}) 가 종료됐습니다:\n{self._buf[-2000:]}")
            if (r := end - time.monotonic()) <= 0:
                raise CdbError(f"{what} 시간 초과 ({timeout}s). 지금까지 출력:\n{self._buf[-2000:]}")
            self._cv.wait(r)
        out, self._buf = self._buf, ""
        return out

    def _sync(self, timeout: float) -> None:
        """_cmd_lock 을 쥔 채로 부른다. 앞서 시간 초과로 끝난 명령이 마저 끝날 때까지 기다린다.

        cdb 는 입력을 순서대로 처리하므로, 표식을 .echo 하고 그 표식 뒤에 프롬프트가 나오면 앞 명령은 끝난 것이다.
        """
        if not self._stale:
            return
        self._sync_no += 1
        mark = f"livedbg_sync_{self._sync_no}"
        self._write(f".echo {mark}")
        with self._cv:
            try:
                self._wait_for(lambda b: mark in b and PROMPT.search(b[b.index(mark):]) is not None,
                               timeout, "앞 명령 마무리 대기")
            except CdbError:
                raise CdbError(f"cdb({self.label}) 가 앞서 시간 초과된 명령을 아직 처리 중입니다. "
                               "잠시 뒤 다시 시도하세요.") from None
        self._stale = False

    def execute(self, command: str, timeout: float = 60.0) -> str:
        """정지 상태에서 명령 하나를 실행하고 출력을 돌려준다.

        명령 검사(check_command)는 하지 않는다. 사용자(모델)가 준 명령·식은 부르는 쪽이 check_user_input 으로
        먼저 검사한다. 내부 명령의 인자(.nvload "G:\\..." 같은 경로)를 검사기가 명령으로 오인하지 않게 하려는 것이다.
        """
        if "\n" in command or "\r" in command:
            raise CdbError("명령은 한 줄이어야 합니다.")
        if EXEC_COMMANDS.match(command):
            raise CdbError(f"실행 명령 '{command}' 은 resume() 으로 보내야 합니다.")
        with self._cmd_lock:
            with self._cv:
                if self._running:
                    raise CdbError("타깃이 실행 중입니다. 먼저 멈추세요.")
            self._sync(timeout)
            with self._cv:
                self._buf = ""
            self._write(command)
            with self._cv:
                try:
                    out = self._wait_for(lambda b: PROMPT.search(b) is not None, timeout, f"'{command}'")
                except CdbError:
                    self._stale = True
                    raise
        return _strip_prompt(out)

    def resume(self, command: str = "g", sync_timeout: float = 60.0) -> None:
        """실행 명령을 보낸다. 다음 정지는 wait_stopped() 로 받는다."""
        if not EXEC_COMMANDS.match(command):
            raise CdbError(f"'{command}' 는 실행 명령이 아닙니다.")
        with self._cmd_lock:
            with self._cv:
                if self._running:
                    raise CdbError("이미 실행 중입니다.")
            # 동기화하지 않으면 시간 초과된 명령의 늦은 프롬프트를 정지로 오인해, 타깃은 도는데 '멈춤' 으로 보인다
            self._sync(sync_timeout)
            with self._cv:
                self._buf = ""
                self._running = True
            try:
                self._write(command)
            except CdbError:
                with self._cv:
                    self._running = False
                raise

    def wait_stopped(self, timeout: float) -> str | None:
        """정지하면 그 시점의 출력(정지 사유)을, 시간 안에 안 멈추면 None."""
        end = time.monotonic() + timeout
        with self._cv:
            while self._running:
                if self.exited:
                    raise CdbError(f"실행 중 cdb({self.label}) 가 종료됐습니다.")
                if (r := end - time.monotonic()) <= 0:
                    return None
                self._cv.wait(r)
            return _strip_prompt(self._last_stop)

    def kill(self) -> None:
        """종료 정리 경로에서 부른다. 예외를 내면 뒤따르는 정리(lock 해제 등)가 건너뛰어지므로 삼킨다."""
        if self._p.poll() is not None:
            return
        try:
            self._p.kill()
            self._p.wait(5)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def wait_exit(self, timeout: float) -> bool:
        try:
            self._p.wait(timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def send_raw(self, command: str, wait_lock: bool = True) -> None:
        """종료 절차용. 응답을 기다리지 않는다 (qd 처럼 프롬프트가 다시 안 나오는 명령).

        wait_lock=False: 다른 스레드가 긴 명령의 응답을 기다리며 _cmd_lock 을 쥐고 있어도 기다리지 않고 쓴다.
        cdb 는 입력을 순서대로 처리하므로 그 명령이 끝난 뒤 실행된다. 서버 종료처럼 시간이 없을 때만 쓴다.
        """
        if wait_lock:
            with self._cmd_lock:
                self._write(command)
        else:
            self._write(command)


# 따옴표 안 문자열을 명령으로 실행하는 명령 (bp 적중 시 명령, 예외 시 명령, 정지할 때마다 명령, 목록 순회 명령)
CMD_STRING_COMMANDS = re.compile(r"^\s*(?:~\S*\s*)?(b[pum]|ba|sx[eidnr]?|\.pcmd|!list)(?![a-z])", re.IGNORECASE)


def _split_commands(command: str) -> list[str]:
    """';' 로 나눈 명령 조각들. bp 의 "명령 문자열" 처럼 명령을 담는 따옴표 문자열은 꺼내서 함께 검사한다.

    그 밖의 따옴표 문자열(.nvload "G:\\..." 같은 경로)은 명령이 아니므로 꺼내지 않는다.
    """
    quoted = re.findall(r'"([^"]*)"', command)
    masked = re.sub(r'"[^"]*"', "\0", command)
    it = iter(quoted)
    parts = []
    for seg in masked.split(";"):
        inner = [next(it) for _ in range(seg.count("\0"))]
        seg = seg.strip()
        if not seg:
            continue
        parts.append(seg.replace("\0", '""'))
        if CMD_STRING_COMMANDS.match(seg):
            for q in inner:
                parts += _split_commands(q)
    return parts


def _strip_prompt(text: str) -> str:
    return PROMPT.sub("", text).rstrip()
