"""livedbg-mcp: 실행 중인 C++ 프로세스를 PDB 로 읽고 디버깅하는 MCP 서버."""


def main() -> None:
    from .server import main as _main

    _main()
