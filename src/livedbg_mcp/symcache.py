"""PDB 섀도 카피 캐시.

dbghelp(cdb) 와 DIA 는 PDB 를 열어 둔 동안 링커의 쓰기를 막는다 (실측). 그래서 빌드 출력의
PDB 는 절대 직접 열지 않고, 짧게 복사한 사본만 연다.

캐시 배치는 심볼 스토어 형식이라 cdb 의 `srv*<cache>` 가 그대로 찾는다.
    <cache>/<name>.pdb/<GUID><Age>/<name>.pdb
"""

from __future__ import annotations

import ctypes
import msvcrt
import os
import time
import uuid
from ctypes import wintypes as wt
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import settings
from .win32 import Module, PdbId

GENERIC_READ = 0x80000000
FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
OPEN_EXISTING = 3
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
ERROR_SHARING_VIOLATION = 32

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateFileW.restype = wt.HANDLE
_k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE]

Validator = Callable[[Path, PdbId], bool]

# (모듈 PDB 서명, 원본 경로) → ((크기, 수정 시각), 오류 메시지). 프로세스 안에서만 유지한다.
_mismatched: dict[tuple[str, str], tuple[tuple[int, int], str]] = {}


class PdbNotFound(LookupError):
    pass


class PdbMismatch(RuntimeError):
    pass


@dataclass(frozen=True)
class CachedPdb:
    path: Path
    source: Path
    in_place: bool  # LIVEDBG_SYMBOL_DIRS 에서 찾아 복사 없이 쓰는 경우


def _candidates(module: Module, pdb: PdbId) -> list[Path]:
    name = Path(pdb.path.replace("/", "\\")).name
    out = []
    if Path(pdb.path).is_absolute():
        out.append(Path(pdb.path))
    out.append(Path(module.path).with_name(name))
    return out


def _open_shared(path: Path):
    """다른 프로세스(링커)의 읽기·쓰기·삭제를 막지 않도록 모든 공유 플래그로 연다."""
    h = _k32.CreateFileW(str(path), GENERIC_READ, FILE_SHARE_ALL, None, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, None)
    if h in (None, wt.HANDLE(-1).value):
        err = ctypes.get_last_error()
        raise OSError(err, ctypes.FormatError(err).strip(), str(path))
    fd = msvcrt.open_osfhandle(h, os.O_RDONLY | os.O_BINARY)
    return os.fdopen(fd, "rb", buffering=0)


def _copy_shared(src: Path, dst: Path) -> None:
    with _open_shared(src) as fin, open(dst, "wb") as fout:
        while chunk := fin.read(8 * 1024 * 1024):
            fout.write(chunk)


def ensure_pdb(module: Module, pdb: PdbId, validate: Validator, retries: int = 3) -> CachedPdb:
    s = settings()
    name = Path(pdb.path.replace("/", "\\")).name

    # 1) 재빌드되지 않는다고 사용자가 지정한 폴더 → 제자리
    for d in s.symbol_dirs:
        p = d / name
        if p.is_file() and validate(p, pdb):
            return CachedPdb(p, p, in_place=True)

    # 2) 캐시 적중 (넣을 때 검증했으므로 다시 검증하지 않는다)
    target = s.symcache / name / pdb.signature / name
    source = next((c for c in _candidates(module, pdb) if c.is_file()), None)
    if target.is_file():
        return CachedPdb(target, source or target, in_place=False)
    if source is None:
        tried = ", ".join(map(str, _candidates(module, pdb)))
        raise PdbNotFound(f"{module.name} 의 PDB 를 찾지 못했습니다 (확인한 경로: {tried})")

    # 이미 불일치로 판정한 PDB 가 그대로면 다시 복사하지 않는다 (큰 PDB 는 복사·재시도에 매번 1~2초 걸렸다).
    # 다시 빌드해서 파일이 바뀌면(크기·수정 시각) 기록을 버리고 다시 확인한다.
    key = (pdb.signature, str(source).lower())
    st = source.stat()
    if (hit := _mismatched.get(key)) is not None and hit[0] == (st.st_size, st.st_mtime_ns):
        raise PdbMismatch(hit[1])

    # 3) 섀도 카피 → 검증 → 원자적 rename
    target.parent.mkdir(parents=True, exist_ok=True)
    last: Exception | None = None
    for attempt in range(retries):
        tmp = target.with_name(f".{uuid.uuid4().hex}.tmp")
        try:
            _copy_shared(source, tmp)
            if not validate(tmp, pdb):
                raise PdbMismatch(
                    f"{source} 는 실행 중인 {module.name} 와 빌드가 다릅니다 "
                    f"(필요: {pdb.guid} age {pdb.age}). 모듈이 로드된 뒤 재빌드됐을 수 있습니다."
                )
            try:
                os.replace(tmp, target)
            except OSError:
                # 다른 세션이 그 사이 같은 사본을 넣고 열어 두면 교체가 거부된다(접근 거부).
                # 경로가 GUID/Age 로 정해지므로 이미 있는 파일은 같은 빌드의 검증된 사본이다.
                if target.is_file():
                    return CachedPdb(target, source, in_place=False)
                raise
            return CachedPdb(target, source, in_place=False)
        except PdbMismatch as e:
            # 링커가 쓰는 도중에 복사했을 수도 있으니 잠깐 기다렸다 한 번 더 본다
            last = e
            if attempt + 1 < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            _mismatched[key] = ((st.st_size, st.st_mtime_ns), str(e))
            raise
        except OSError as e:
            last = e
            if e.errno == ERROR_SHARING_VIOLATION or getattr(e, "winerror", None) == ERROR_SHARING_VIOLATION:
                time.sleep(0.5 * (attempt + 1))
                continue
            raise
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass  # DIA 가 아직 닫지 않았으면 지울 수 없다. 원래 예외를 덮지 않는다.
    raise RuntimeError(f"{source} 복사에 실패했습니다: {last}")
