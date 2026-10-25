"""ctypes 로 감싼 Win32 호출. 디버거를 붙이지 않고 할 수 있는 일만 여기 둔다."""

from __future__ import annotations

import ctypes
import struct
import uuid
from contextlib import contextmanager
from ctypes import wintypes as wt
from dataclasses import dataclass

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_ALL_ACCESS = 0x1F0FFF
STILL_ACTIVE = 259

MEM_COMMIT = 0x1000
PAGE_WRITABLE = 0x04 | 0x08 | 0x40 | 0x80  # READWRITE, WRITECOPY, EXECUTE_READWRITE, EXECUTE_WRITECOPY
PAGE_EXECUTABLE = 0x10 | 0x20 | 0x40 | 0x80
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, wt.LPVOID, wt.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
k32.DebugBreakProcess.argtypes = [wt.HANDLE]
k32.FlushInstructionCache.argtypes = [wt.HANDLE, wt.LPCVOID, ctypes.c_size_t]
psapi.GetModuleFileNameExW.argtypes = [wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p), ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD), ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD),
    ]


k32.VirtualQueryEx.argtypes = [wt.HANDLE, wt.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t


class Win32Error(OSError):
    pass


def _err(what: str) -> Win32Error:
    code = ctypes.get_last_error()
    return Win32Error(code, f"{what} 실패: {ctypes.FormatError(code).strip()} (err={code})")


@contextmanager
def open_process(pid: int, access: int):
    h = k32.OpenProcess(access, False, pid)
    if not h:
        raise _err(f"OpenProcess(pid={pid})")
    try:
        yield h
    finally:
        k32.CloseHandle(h)


def process_alive(pid: int) -> bool:
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    try:
        code = wt.DWORD()
        return bool(k32.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == STILL_ACTIVE
    finally:
        k32.CloseHandle(h)


def read_memory(pid: int, address: int, size: int) -> bytes:
    with open_process(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) as h:
        return _rpm(h, address, size)


def _rpm(h, address: int, size: int) -> bytes:
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(address), buf, size, ctypes.byref(n)) or n.value != size:
        raise _err(f"ReadProcessMemory(0x{address:X}, {size})")
    return buf.raw


def write_memory(pid: int, address: int, data: bytes) -> None:
    access = PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    with open_process(pid, access) as h:
        n = ctypes.c_size_t()
        if not k32.WriteProcessMemory(h, ctypes.c_void_p(address), data, len(data), ctypes.byref(n)) or n.value != len(data):
            raise _err(f"WriteProcessMemory(0x{address:X}, {len(data)})")
        k32.FlushInstructionCache(h, ctypes.c_void_p(address), len(data))


@dataclass(frozen=True)
class Region:
    base: int
    size: int
    committed: bool
    protect: int

    @property
    def writable(self) -> bool:
        return self.committed and bool(self.protect & PAGE_WRITABLE) and not self.protect & (PAGE_GUARD | PAGE_NOACCESS)

    @property
    def executable(self) -> bool:
        return bool(self.protect & PAGE_EXECUTABLE)


def query_region(pid: int, address: int) -> Region:
    with open_process(pid, PROCESS_QUERY_INFORMATION) as h:
        mbi = MEMORY_BASIC_INFORMATION()
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            raise _err(f"VirtualQueryEx(0x{address:X})")
        return Region(mbi.BaseAddress or 0, mbi.RegionSize, mbi.State == MEM_COMMIT, mbi.Protect)


def debug_break(pid: int) -> None:
    with open_process(pid, PROCESS_ALL_ACCESS) as h:
        if not k32.DebugBreakProcess(h):
            raise _err("DebugBreakProcess")


# ---- 모듈 · PDB 식별 ------------------------------------------------------------

@dataclass(frozen=True)
class PdbId:
    guid: uuid.UUID
    age: int
    path: str  # 링커가 PE 에 기록한 PDB 경로

    @property
    def signature(self) -> str:
        """심볼 스토어 폴더 이름 (GUID 대문자 대시 없음 + Age 16진)."""
        return self.guid.hex.upper() + f"{self.age:X}"


@dataclass(frozen=True)
class Module:
    name: str
    path: str
    base: int
    size: int

    def contains(self, address: int) -> bool:
        return self.base <= address < self.base + self.size


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD), ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p), ("modBaseSize", wt.DWORD), ("hModule", wt.HMODULE),
        ("szModule", wt.WCHAR * 256), ("szExePath", wt.WCHAR * 260),
    ]


TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32 = 0x8, 0x10
ERROR_BAD_LENGTH = 24
k32.Module32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.Module32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]


def list_modules(pid: int) -> list[Module]:
    """로드된 모듈 (첫 항목이 실행 파일).

    Toolhelp 스냅숏 한 번으로 경로·베이스·크기를 받는다. 모듈마다 GetModuleFileNameEx /
    GetModuleInformation 을 부르는 방식은 언리얼 에디터(모듈 약 1,100개)에서 1회 0.9초 걸렸다 (스냅숏은 12ms).
    """
    for _ in range(5):
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if snap in (None, wt.HANDLE(-1).value):
            if ctypes.get_last_error() == ERROR_BAD_LENGTH:  # 스냅숏 도중 모듈 목록이 바뀌었다. 다시 찍는다.
                continue
            raise _err(f"CreateToolhelp32Snapshot(pid={pid})")
        try:
            e = MODULEENTRY32W()
            e.dwSize = ctypes.sizeof(e)
            mods = []
            ok = k32.Module32FirstW(snap, ctypes.byref(e))
            while ok:
                path = e.szExePath
                if len(path) >= 259:  # szExePath 는 MAX_PATH 에서 잘린다. 긴 경로만 따로 묻는다.
                    path = _module_path(pid, e.hModule) or path
                mods.append(Module(path.rsplit("\\", 1)[-1], path, e.modBaseAddr or 0, e.modBaseSize))
                ok = k32.Module32NextW(snap, ctypes.byref(e))
            return mods
        finally:
            k32.CloseHandle(snap)
    raise _err(f"CreateToolhelp32Snapshot(pid={pid}) — 모듈 목록이 계속 바뀌고 있습니다")


def _module_path(pid: int, hmodule) -> str | None:
    with open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as h:
        buf = ctypes.create_unicode_buffer(32768)
        return buf.value if psapi.GetModuleFileNameExW(h, hmodule, buf, len(buf)) else None


def find_module(pid: int, name_or_address: str | int) -> Module:
    mods = list_modules(pid)
    if isinstance(name_or_address, int):
        for m in mods:
            if m.contains(name_or_address):
                return m
        raise LookupError(f"0x{name_or_address:X} 를 포함하는 모듈이 없습니다.")
    # cdb 는 모듈 이름의 '-' 를 '_' 로 바꿔 부른다 (UnrealEditor-Engine → UnrealEditor_Engine)
    key = name_or_address.lower().replace("-", "_")
    for m in mods:
        name = m.name.lower().replace("-", "_")
        if key in (name, name.rsplit(".", 1)[0]):
            return m
    raise LookupError(f"모듈 '{name_or_address}' 가 로드돼 있지 않습니다.")


def read_pdb_id(pid: int, module_base: int) -> PdbId | None:
    """로드된 모듈 이미지(메모리)의 디버그 디렉터리에서 RSDS 레코드를 읽는다.

    디스크 DLL 이 아니라 메모리를 읽는 이유: 실행 중에 재빌드되면 디스크 쪽은 이미 새 빌드다.
    """
    with open_process(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) as h:
        hdr = _rpm(h, module_base, 0x1000)
        if hdr[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", hdr, 0x3C)[0]
        if hdr[pe:pe + 4] != b"PE\0\0":
            return None
        opt = pe + 24
        magic = struct.unpack_from("<H", hdr, opt)[0]
        dd = opt + (112 if magic == 0x20B else 96)
        dbg_rva, dbg_size = struct.unpack_from("<II", hdr, dd + 6 * 8)
        if not dbg_rva:
            return None
        entries = _rpm(h, module_base + dbg_rva, dbg_size)
        for off in range(0, dbg_size - 27, 28):
            # IMAGE_DEBUG_DIRECTORY: +12 Type, +16 SizeOfData, +20 AddressOfRawData
            typ, size, rva = struct.unpack_from("<III", entries, off + 12)
            if typ != 2 or not rva:  # IMAGE_DEBUG_TYPE_CODEVIEW
                continue
            cv = _rpm(h, module_base + rva, size)
            if cv[:4] != b"RSDS":
                continue
            guid = uuid.UUID(bytes_le=cv[4:20])
            age = struct.unpack_from("<I", cv, 20)[0]
            path = cv[24:].split(b"\0", 1)[0].decode("utf-8", "replace")
            return PdbId(guid, age, path)
    return None


# ---- 프로세스 목록 ---------------------------------------------------------------

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD), ("szExeFile", wt.WCHAR * 260),
    ]


k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]


def list_processes() -> list[tuple[int, str]]:
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    if snap in (None, wt.HANDLE(-1).value):
        raise _err("CreateToolhelp32Snapshot")
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        out = []
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            out.append((e.th32ProcessID, e.szExeFile))
            ok = k32.Process32NextW(snap, ctypes.byref(e))
        return out
    finally:
        k32.CloseHandle(snap)
