"""외부 도구 경로와 런타임 설정.

경로 탐지는 두 단계뿐이다: 환경 변수가 있으면 그것, 없으면 기본 설치 위치.
둘 다 없으면 설치 방법을 담은 ToolNotFound 를 던진다.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from functools import cache
from pathlib import Path

ENV_CDB = "LIVEDBG_CDB_PATH"
ENV_MSDIA = "LIVEDBG_MSDIA_PATH"
ENV_CACHE = "LIVEDBG_CACHE_DIR"
ENV_SYMBOL_DIRS = "LIVEDBG_SYMBOL_DIRS"
ENV_MS_SYMBOLS = "LIVEDBG_MS_SYMBOLS"

MS_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"


class ToolNotFound(RuntimeError):
    pass


def _local_appdata() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))


@cache
def cdb_path() -> Path:
    if env := os.environ.get(ENV_CDB):
        p = Path(env)
        if not p.is_file():
            raise ToolNotFound(f"{ENV_CDB}={env} 가 가리키는 파일이 없습니다.")
        return p
    # winget install Microsoft.WinDbg 가 만드는 실행 별칭
    p = _local_appdata() / "Microsoft" / "WindowsApps" / "cdbX64.exe"
    if p.exists():
        return p
    raise ToolNotFound(
        "cdb.exe 를 찾지 못했습니다.\n"
        "  설치: winget install Microsoft.WinDbg\n"
        f"  또는 환경 변수 {ENV_CDB} 에 cdb.exe 경로를 지정하세요."
    )


@cache
def msdia_path() -> Path:
    if env := os.environ.get(ENV_MSDIA):
        p = Path(env)
        if not p.is_file():
            raise ToolNotFound(f"{ENV_MSDIA}={env} 가 가리키는 파일이 없습니다.")
        return p
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if vswhere.is_file():
        out = subprocess.run(
            [str(vswhere), "-latest", "-products", "*", "-property", "installationPath"],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW,
        ).stdout.strip()
        for line in out.splitlines():
            p = Path(line) / "DIA SDK" / "bin" / "amd64" / "msdia140.dll"
            if p.is_file():
                return p
    raise ToolNotFound(
        "msdia140.dll 을 찾지 못했습니다.\n"
        "  Visual Studio 의 'C++를 사용한 데스크톱 개발' 워크로드를 설치하거나\n"
        f"  환경 변수 {ENV_MSDIA} 에 msdia140.dll 경로를 지정하세요."
    )


@dataclass(frozen=True)
class Settings:
    cache_dir: Path
    # 재빌드되지 않는 PDB 폴더 (예: 설치형 엔진 Binaries). 복사 없이 제자리에서 연다.
    symbol_dirs: tuple[Path, ...]
    ms_symbols: bool

    @property
    def symcache(self) -> Path:
        return self.cache_dir / "symcache"

    @property
    def locks(self) -> Path:
        return self.cache_dir / "locks"

    def cdb_symbol_path(self) -> str:
        store = f"srv*{self.symcache}"
        if self.ms_symbols:
            store += f"*{MS_SYMBOL_SERVER}"
        return ";".join([store, *map(str, self.symbol_dirs)])


@cache
def settings() -> Settings:
    cache_dir = Path(os.environ.get(ENV_CACHE) or _local_appdata() / "livedbg-mcp")
    dirs = tuple(Path(p) for p in os.environ.get(ENV_SYMBOL_DIRS, "").split(";") if p.strip())
    s = Settings(
        cache_dir=cache_dir,
        symbol_dirs=dirs,
        ms_symbols=os.environ.get(ENV_MS_SYMBOLS, "") not in ("", "0", "false"),
    )
    s.symcache.mkdir(parents=True, exist_ok=True)
    s.locks.mkdir(parents=True, exist_ok=True)
    return s


def tool_status() -> dict:
    status = {}
    for name, fn in (("cdb", cdb_path), ("msdia", msdia_path)):
        try:
            status[name] = str(fn())
        except ToolNotFound as e:
            status[name] = f"MISSING — {e}"
    s = settings()
    status["cache_dir"] = str(s.cache_dir)
    status["symbol_path"] = s.cdb_symbol_path()
    return status
