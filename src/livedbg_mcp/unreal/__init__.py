"""언리얼 애드온. 코어는 범용 C++ 이고, 언리얼 프로세스로 보이면 여기 것을 추가로 쓴다.

- FString/TArray/FName 등을 보여주는 Unreal.natvis 는 PDB 에 임베드되지 않는다 (모듈별 natvis 만 들어감).
  그래서 엔진 설치본의 Engine/Extras/VisualStudioDebugging/Unreal.natvis 를 cdb 에 .nvload 한다.
- UE 모듈은 빌드 구성과 무관하게 기본 /GR- (RTTI 꺼짐)다. 동적 타입은 vftable 심볼로 판별한다.
"""

from __future__ import annotations

from pathlib import Path

from ..win32 import Module

_MARKERS = ("UnrealEditor-Core.dll", "UnrealEditor.exe", "UnrealGame-Core.dll")


def is_unreal(modules: list[Module]) -> bool:
    names = {m.name for m in modules}
    return any(n in names for n in _MARKERS) or any(n.startswith("UnrealEditor-") for n in names)


def natvis_path(modules: list[Module]) -> Path | None:
    for m in modules:
        p = m.path.replace("/", "\\")
        i = p.lower().find("\\engine\\binaries\\")
        if i < 0:
            continue
        cand = Path(p[:i]) / "Engine" / "Extras" / "VisualStudioDebugging" / "Unreal.natvis"
        if cand.is_file():
            return cand
    return None
