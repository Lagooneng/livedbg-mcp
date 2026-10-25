# livedbg-mcp

실행 중인 C++ 프로세스(PDB 가 있는 개발 빌드)를 읽고 디버깅하는 MCP 서버.
cdb 로 실행을 제어하고 값을 보여주며(natvis 적용), DIA 로 심볼·타입을 빠르게 찾는다.

- 코어는 범용 C++ 이고, 언리얼 프로세스면 `Unreal.natvis` 를 자동으로 로드한다.
- 여러 세션이 같은 프로세스를 동시에 읽을 수 있다. 디버거(bp·스텝·쓰기)는 한 세션만 갖는다.
- 원본 PDB 를 잠그지 않는다. 붙어 있는 동안에도 빌드가 된다.

## 요구 사항

| 도구 | 기본 위치 | 없을 때 |
|---|---|---|
| cdb | `%LOCALAPPDATA%\Microsoft\WindowsApps\cdbX64.exe` | `winget install Microsoft.WinDbg` |
| msdia140.dll | vswhere 로 찾은 VS 의 `DIA SDK\bin\amd64\msdia140.dll` | VS 의 "C++를 사용한 데스크톱 개발" 워크로드 설치 |
| uv | PATH | `winget install astral-sh.uv` |

**이 저장소는 cdb.exe 와 msdia140.dll 을 포함하지 않는다.** 두 도구는 Microsoft 소프트웨어라서 각자 설치하고,
각 라이선스(WinDbg 사용 약관, Visual Studio 라이선스)에 따라 사용한다. livedbg-mcp 는 설치된 도구를 호출만 한다.
cdb 는 재배포가 허용되지 않으므로 이 저장소나 플러그인에 넣어 배포하지 않는다.

기본 위치가 아니면 환경 변수로 지정한다. 환경 변수가 있으면 그것이 우선이다.

| 환경 변수 | 뜻 |
|---|---|
| `LIVEDBG_CDB_PATH` | cdb.exe 경로 |
| `LIVEDBG_MSDIA_PATH` | msdia140.dll 경로 |
| `LIVEDBG_CACHE_DIR` | PDB 섀도 캐시·lockfile 위치 (기본 `%LOCALAPPDATA%\livedbg-mcp`) |
| `LIVEDBG_SYMBOL_DIRS` | 재빌드되지 않는 PDB 폴더 (`;` 구분). 복사 없이 제자리에서 연다. 예: 소스 빌드가 아닌 엔진 설치본의 `Engine\Binaries\Win64` |
| `LIVEDBG_MS_SYMBOLS` | `1` 이면 Microsoft 심볼 서버에서 OS 심볼을 받아 캐시한다 (기본 꺼짐, 네트워크 사용) |

`status` 도구가 찾은 경로와 없는 도구를 알려준다.

타깃 빌드는 **`/DEBUG:FULL`** 이어야 한다. `/DEBUG:FASTLINK` PDB 는 타입 정보가 `.obj` 에 남아 있어 사본만으로 읽을 수 없다.

## 설치 (Claude Code 플러그인)

```bash
claude plugin marketplace add <이 저장소 경로 또는 owner/repo>
```

```bash
claude plugin install livedbg-mcp@livedbg-marketplace
```

플러그인은 `uv run --directory ${CLAUDE_PLUGIN_ROOT} livedbg-mcp` 로 서버를 띄운다. 첫 실행 때 uv 가 의존성을 설치한다.

플러그인 없이 쓰려면 MCP 설정에 같은 명령을 넣는다.

## 도구

| 분류 | 도구 |
|---|---|
| 세션 | `status` `list_processes` `attach` `detach` `modules` `prepare_symbols` |
| 심볼 (DIA) | `find_symbols` `type_layout` `symbol_at` `dynamic_type` |
| 읽기 | `evaluate` (cdb `dx` + natvis) `read_memory` `debugger_command` (조회용, 아래 참고) |
| 실행 제어 | `set_breakpoint` `list_breakpoints` `clear_breakpoint` `wait` `break_in` `resume` `step` `stack` `locals` |
| 쓰기 | `write_memory` `undo_write` `write_history` |
| 언리얼 | `ue_inspect` `ue_find_objects` `ue_worlds` |

심볼은 `module!name` 으로 한정해서 쓴다 (`target!g_State`, `UnrealEditor-ChronoSpace!...`).
비한정 이름은 심볼이 이미 로드된 모듈에서만 찾는다.

`debugger_command` 와 `evaluate` 는 cdb 명령·식을 그대로 보내되, 다음은 거부한다. 전용 도구가 안전 절차를 거쳐 처리한다.

| 거부 | 대신 쓸 도구 |
|---|---|
| 실행 명령 (`g` `p` `t` 계열, `~0 g` 처럼 스레드 접두가 붙은 것 포함) | `resume` `step` |
| 세션 수명 명령 (`q` `qd` `.kill` `.detach` ...), 스레드 동결·중단 | `detach` |
| 메모리·레지스터 쓰기 (`eb` `ed` `f` `m`, `dx x = 1`, `++` `--`, 대입이 든 bp 조건식) | `write_memory` |
| 다른 명령을 간접 실행하는 구문 (`.if` 블록, 스크립트, 별칭, `!for_each_*`, dx 의 `ExecuteCommand`) | — |

이 검사는 **실수로 상태를 깨는 것을 막는 장치이지 보안 경계가 아니다.** 일부러 우회하려면 할 수 있다.

## 구조

세션(MCP 클라이언트)마다 서버 프로세스 하나가 뜬다. 데몬은 없다.

```
MCP 세션 A ── livedbg-mcp ─┬─ reader     cdb -pvr  (비침투·무정지, 몇 개든 가능)
                           ├─ controller cdb -pd   (디버거, 프로세스당 1개 — OS 가 강제)
                           └─ DIA (전용 스레드)
MCP 세션 B ── livedbg-mcp ─── reader     cdb -pvr  (A 가 디버거를 가진 동안에도 읽기 가능)
```

- **읽기**: 멈춰 있으면 controller 가 일관된 스냅숏을, 실행 중이면 reader 가 라이브 값을 읽는다.
  실행 중에 읽은 구조체는 필드끼리 시점이 다를 수 있다 (응답의 `read` 에 표시).
- **디버거 소유권**: `%LOCALAPPDATA%\livedbg-mcp\locks\<pid>.json` 파일의 바이트 범위 잠금이 소유권이다.
  다른 세션의 debug attach 는 거절되고, 파일에 적힌 소유 정보(서버 pid, 시작 시각)로 누가 갖고 있는지 알려준다.
  잠금은 핸들에 묶여 있어 소유 서버가 어떻게 죽든 OS 가 풀므로, 죽은 소유자의 lock 이 남지 않는다.
- **PDB**: 로드된 모듈의 **메모리** 에서 RSDS(GUID/Age)를 읽고, 빌드 출력의 PDB 를 모든 공유 플래그로
  짧게 복사한 뒤 DIA 로 GUID/Age 를 검증해 `<cache>\<name>.pdb\<GUID><Age>\<name>.pdb` 에 넣는다.
  cdb 는 `srv*<cache>` 와 `-sicv`(PE 에 박힌 원본 경로 무시)로 이 사본만 연다.
  디스크 DLL 이 아니라 메모리를 보는 이유: 실행 중에 재빌드되면 디스크 쪽은 이미 새 빌드다.
  불일치로 판정한 PDB 는 기억해 두고 다시 복사하지 않는다. 다시 빌드해 파일이 바뀌면(크기·수정 시각) 다시 확인한다.
- **조회 속도**: 심볼·타입 조회는 DIA, 메모리 읽기는 `ReadProcessMemory` 로 직접 한다. cdb 는 식 평가와
  실행 제어에만 쓴다. 언리얼 에디터(모듈 1,138개)에서 잰 값:

  | 조회 | DIA | cdb |
  |---|---|---|
  | 타입 레이아웃 (`AActor`) | 1.7 ms | 8.0 ms (`dt`) |
  | 와일드카드 함수 검색 (`*Tick*`) | 1.6 ms | 83 ms (`x`) |

  도구 응답(모듈 조회 포함)은 15 ms 안팎이다.

## 안전 규칙과 근거

2026-09-30 에 테스트 타깃으로 직접 측정한 결과에 기반한다.

| 측정 | 결과 | 그래서 |
|---|---|---|
| dbghelp·DIA 가 PDB 를 열어 둔 동안 링커처럼 쓰기로 열기 | 둘 다 공유 위반 | 원본은 열지 않고 사본만 연다 |
| `-pd` 없이 실행 중 cdb 강제 종료 | 타깃 종료 | controller 는 항상 `-pd` |
| `-pd`, 실행 중, bp 없음, cdb 강제 종료 | 타깃 생존 | — |
| `-pd`, bp 에 멈춘 상태에서 cdb 종료 | **타깃 영구 동결** (RIP = bp+1, 복구 못 함) | detach 는 반드시 (실행 중이면 멈춤) → `bc *` → `qd` |
| `-pd`, bp 가 박힌 채 실행 중 cdb 종료 | `0xCC` 잔존 → 재개 시 크래시 | 위와 같음 |
| invasive cdb 가 붙어 있을 때 `cdb -pvr` | 읽기 성공, 타깃 영향 없음 | 읽기 세션은 여럿 공존 |
| 멈춘 상태에서 `bc *` → `qd` | 타깃 계속 실행 | 정상 종료 경로 |

MCP 클라이언트는 서버의 stdin 을 닫은 뒤 **2초** 후 프로세스 트리를 강제 종료한다 (Python SDK 기준).
서버는 stdin EOF·시그널·콘솔 종료 이벤트에서 즉시 모든 타깃을 병렬로 detach 한다. 이 종료 경로는 시간이 없으므로:

- 다른 작업(PDB 복사, 언리얼 초기화, 긴 명령)이 타깃을 잡고 있어도 0.2초만 기다리고 진행한다.
- 실행 중이면 break-in 을 1.5초 기다린다. `bc *` · `qd` 는 응답을 기다리지 않고 보낸다. cdb 는 입력을
  순서대로 처리하므로 진행 중인 명령이 끝나면 바로 실행된다.
- attach 가 설정(심볼 로드) 중이라 아직 등록 전인 controller 도 닫는다.

테스트에서 멈춘 상태로 연결을 끊었을 때 0.11초, attach 설정 도중 끊었을 때 1.03초에 끝났다.

평소의 `detach` 는 시간 제약이 없으므로, cdb 가 시간 초과된 명령을 아직 처리 중이면 끝날 때까지 기다린 뒤 종료한다
(멈춘 채 cdb 를 죽이면 동결이 확정이기 때문). 명령이 시간 초과되면 다음 명령 전에 표식을 `.echo` 해서 cdb 와
다시 맞춘다. 맞추지 않으면 늦게 도착한 프롬프트를 정지로 오인해, 타깃은 도는데 '멈춤' 으로 보인다.

**남은 위험**
- 서버가 정리할 틈 없이 강제 종료되면 (작업 관리자 등) 멈춰 있던 타깃은 동결되고,
  bp 가 박혀 있던 타깃은 다음 적중 때 크래시한다.
- 서버 종료 순간 cdb 가 2초 넘게 걸리는 명령(큰 PDB 로드 등)을 처리 중이거나, attach 가 첫 프롬프트를 기다리는
  중이면 클라이언트의 강제 종료 전에 정리를 끝내지 못할 수 있다.
- 디버깅이 끝나면 `detach` 한다.

## 메모리 쓰기

- debug 소유 + 정지 상태에서만 되고, `write_memory` 한 경로로만 한다 (읽기 세션도 메모리를 쓸 수 있으므로
  `debugger_command`·`evaluate` 의 쓰기는 거부한다).
- 타입·크기는 PDB 로 확인하고, 쓰는 범위의 모든 페이지가 쓰기 가능한 비실행 페이지인지 검사하고, 쓴 뒤 되읽어 검증한다.
- 값 형식: 정수(10진·`0x`), 실수, `true`/`false`, `hex:0a0b...`(정확히 그 크기의 바이트). 구조체(크기가 1·2·4·8 이어도,
  예: `TObjectPtr`)에는 정수를 받지 않고 `hex:` 만 받는다.
- 비트필드는 해당 비트만 바꾸고 같은 저장 단위의 이웃 비트는 그대로 둔다. dx 는 비트필드의 주소를 소속 바이트
  주소로 돌려줘 일반 필드와 구분되지 않으므로, C++ 식 평가기(`??`)로 판별하고 비트 위치는 부모의 원시 레이아웃에서 읽는다.
- 모든 쓰기는 기록되고 `undo_write` 로 되돌린다. 그 사이 값이 바뀌었으면 덮어쓰지 않는다.
- 아무 데서나 멈춘 상태는 다른 스레드가 그 객체를 갱신하던 도중일 수 있고, 최적화 코드는 값을
  레지스터에 들고 있을 수 있다. 가능하면 객체가 조용한 지점(프레임 시작 등)에 bp 를 걸고 쓴다.

## 언리얼

> **UE 5.8 에디터(Development, Win64)에서 만들고 검증했다.** 다른 엔진 버전·게임 빌드에서는 테스트하지 않았다.
> 구조체 오프셋은 PDB 에서 읽고 모르는 구조는 추정 대신 오류를 내도록 했지만, 동작은 보장하지 않는다.
> 다른 버전에서 쓰기 전에 `tests\test_unreal_live.py` 를 돌려 본다.

### natvis 는 cdb 에서 일부만 동작한다

`Unreal.natvis`(FString, TArray, FName ...)는 PDB 에 임베드되지 않는다 (모듈별 natvis 만 들어감).
엔진 설치본의 `Engine\Extras\VisualStudioDebugging\Unreal.natvis` 를 자동으로 `.nvload` 한다.

하지만 이 파일은 Visual Studio 디버거 기준으로 작성돼 있고, cdb 의 `dx` 는 natvis 를 따로 구현한 것이라
일부가 깨진다 (5.8 에서 확인).

| 원인 | 깨지는 타입 |
|---|---|
| 참조 캐스트 `(T&)x` 를 dx 가 다르게 해석 | FName → UObject 이름, soft 경로, 게임플레이 태그 |
| dx 가 모르는 서식 지정자 (`X` `Xb` `xb` `na` ...) | FGuid, 해시·ID 타입 |
| TSet 표시 규칙 실패 (원인 미확정) | TSet, TMap |

TArray, FString, 수학 타입은 dx 로 정상 표시된다. VS 디버거 엔진(vsdbg)은 라이선스상 다른 도구에서 쓸 수 없다.

### 언리얼 해석기 (`ue_*`)

자주 쓰는 타입은 natvis 대신 메모리에서 직접 해석한다. 구조체 오프셋은 전부 PDB(DIA)에서 가져오고,
해석마다 검증을 넣어 구조가 바뀌면 조용히 틀린 값 대신 오류를 낸다.

| 타입 | 검증 |
|---|---|
| FName | 이름 풀 엔트리의 ComparisonId 일치, 블록 범위. ComparisonId 가 없는 빌드는 제어 문자·잘못된 UTF-16 거부 |
| 열거형 | 크기·부호를 PDB 의 기반 타입에서 (`enum class E : uint8` 의 200 은 200). 정의가 없으면 추정 대신 오류 |
| UObject 참조 (TObjectPtr, TSubclassOf, 포인터) → 이름·클래스·전체 경로 | 전역 객체 배열[InternalIndex] == 이 주소 |
| TWeakObjectPtr | 객체 배열 항목의 SerialNumber 일치 (다르면 stale) |
| TArray / TSet / TMap | 할당 비트 수 == ArrayNum − NumFreeIndices |
| TCompactSet (5.8 의 새 TSet 구현, `UE_USE_COMPACT_SET_AS_DEFAULT`) | 0 ≤ NumElements ≤ MaxElements |
| TSoftObjectPtr / TSoftClassPtr, FString | FName·배열 검증을 거침 |
| 동적 델리게이트 | 바인딩 = (약참조 객체, 함수 FName) |
| 희소 델리게이트 (`OnComponentBeginOverlap` 등) | 전역 `FSparseDelegateStorage` 에서 조회. 필드만 주면 등록 오프셋 맵으로 소유 객체를 역산하고 UObject 검증 |
| 네이티브 델리게이트 | 바인딩 인스턴스의 vtable 심볼로 종류 판별 → 대상 객체·함수 심볼. PDB 없는 모듈(엔진) 바인딩은 `unknown` |

- 진입점은 UE 가 모든 모듈에 심어 두는 디버그 심볼(`GNameBlocksDebug`, `GObjectArrayForDebugVisualizers`)이라
  **엔진 PDB 없이 게임 모듈 PDB 만으로** 동작한다. 기준 모듈은 게임 본체 → 플러그인 → 엔진 순으로 자동 선택한다.
  게임 본체의 PDB 를 쓸 수 없으면(실행 중인 DLL 과 빌드가 다름 등) 다른 모듈로 해석하고, `ue_*` 결과와 `status` 에
  이유를 표시한다. 이때 엔진 공통 타입(FName, 객체, 컨테이너)은 보이지만 게임 클래스의 필드는 보이지 않는다.
  커밋된 DLL 을 pull 받은 뒤 다시 링크되지 않으면 이렇게 된다. 게임 모듈을 다시 빌드하거나 PDB 를 DLL 과 함께 받는다.
- `ue_worlds` / `ue_find_objects` 결과의 `type_module` 이 식에서 캐스트할 때 쓰는 모듈 한정자다.
  예: `ue_inspect(pid, "*(UnrealEditor_ChronoSpace!ACSCharacterPlayer*)0x1e1d3c6e600", depth=1)`
- 구조체는 PDB 필드로 `depth` 만큼 내려가고, 베이스 클래스는 이름만 둔다 (UObject 계층은 필드가 수백 개).
- 희소 델리게이트 저장소처럼 **인스턴스 레이아웃이 PDB 에 없는 엔진 내부 TMap** 은, 다른 TMap 인스턴스의 컨테이너
  배치 + 키·값 크기·정렬로 원소 위치를 계산한다 (할당 비트 검증이 계산 실수를 잡는다).
- 미지원: FText. 블루프린트 변수(리플렉션)는 다음 단계.

### 그 밖의 주의
- UE 모듈은 빌드 구성과 무관하게 기본 `/GR-` (RTTI 꺼짐)다 (`CppCompileEnvironment.bUseRTTI = false`).
  `dynamic_type` 은 vftable 심볼(`??_7Class@@6B@`)로 실제 클래스를 판별하므로 RTTI 가 필요 없다.
- 런처 엔진은 "디버깅용 에디터 심볼" 옵션을 켜야 엔진 PDB 가 설치된다. 설치했다면
  `LIVEDBG_SYMBOL_DIRS` 에 `Engine\Binaries\Win64` 를 넣어 복사 없이 쓴다 (재빌드되지 않으므로 안전).
- 블루프린트 변수는 PDB 에 없다 (리플렉션에만 있다). 아직 지원하지 않는다.
- 리슨 서버에서 한쪽을 오래 멈추면 상대가 네트워크 타임아웃으로 끊긴다.
- Development 에디터는 최적화 빌드라 `locals` 에서 지역 변수가 사라져 있을 수 있다.
- cdb 는 파이프 입출력을 시스템 ANSI 코드 페이지(한국어 Windows 는 CP949)로 처리하므로 서버도 그 인코딩으로 주고받는다.
  `FString`(UTF-16)의 한글은 `evaluate` 에서 정상으로 보인다. 메모리의 UTF-8 `char*` 문자열과 UTF-8 소스 파일의
  줄 표시(`lsa`)는 cdb 가 이미 깨진 채로 출력한다. `ue_inspect` 는 cdb 를 거치지 않고 직접 디코딩하므로 영향이 없다.

## 개발

테스트는 다섯 단계다. 위에서부터 차례로 돌린다.

| 순서 | 테스트 | 필요한 것 | 보는 것 |
|---|---|---|---|
| 1 | `tests\fixtures\build.ps1` | VS C++ 워크로드 | 통합 테스트용 타깃(`/GR-` 빌드, RTTI 없음)을 `tests\fixtures\bin` 에 빌드한다 |
| 2 | `tests\test_units.py` | 없음 (cdb·타깃 불필요) | 명령 차단, 주소 해석, 값·비트필드 인코딩, 소유 lock, PDB 캐시 경합, 늦은 break-in 판정 |
| 3 | `tests\test_mcp_e2e.py` | 1 의 타깃, cdb, msdia | 실제 MCP 클라이언트(stdio)로 서버를 띄워 타깃에 붙는다. 시나리오는 아래 |
| 4 | `tests\test_unreal_decoders.py` | 없음 | 합성 메모리로 컨테이너 해석 (TCompactSet 은 실행 중 인스턴스를 붙잡기 어려워 여기서 확인) |
| 5 | `tests\test_unreal_live.py [pid]` | 실행 중인 언리얼 에디터 | 에디터에 읽기 전용으로 붙어 해석기 결과를 dx 가 정상 표시하는 값(TArray 개수 등)과 교차 비교한다. 에디터를 멈추지 않는다. 엔진을 올린 뒤 돌린다 |

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\build.ps1
```

```bash
uv run python tests\test_units.py
```

```bash
uv run python tests\test_mcp_e2e.py
```

```bash
uv run python tests\test_unreal_decoders.py
```

```bash
uv run python tests\test_unreal_live.py
```

빌드 스크립트는 실행 정책이 막힌 PC 를 위해 `-ExecutionPolicy Bypass` 로 돌린다 (그 프로세스에만 적용된다).
`test_unreal_live.py` 는 pid 를 생략하면 `UnrealEditor.exe` 를 찾는다.

e2e 시나리오 (G 가 약 35초 걸려 전체는 몇 분 걸린다):

| 시나리오 | 확인하는 것 |
|---|---|
| A | 핵심 흐름: debug attach, 라이브 읽기, 타입 레이아웃, RTTI 없는 동적 타입, bp, 정지 중 쓰기. 두 번째 세션의 debug 거절·read 허용·쓰기 거절. 멈춘 상태로 클라이언트가 끊겨도 타깃이 살아서 계속 실행된다 |
| B | 나머지 도구 전부: 조건부·소스 줄 bp, step, locals, break_in, symbol_at, read_memory, 쓰기·undo, 비트필드 쓰기, 코드·구조체 쓰기 거부, 명령 차단 |
| C | 붙어 있는 동안 실제 링커로 같은 PDB 를 덮어쓰는 재빌드가 성공하고, 새 세션이 PDB 불일치를 잡는다 |
| D | debug attach 가 초기화 도중 실패해도 타깃이 멈춘 채 남지 않고, lock 이 풀리고, 다시 붙을 수 있다 |
| E | 명령이 시간 초과로 끝난 뒤에도 실행/정지 상태가 실제와 맞는다 |
| F | debug attach 설정 도중 서버가 종료돼도 등록 전 controller 를 닫아 타깃이 산다 |
| G | cdb 가 시간 초과된 명령을 아직 처리 중일 때 detach 해도 멈춘 채 kill 하지 않는다 |

끝나면 cdb 프로세스가 남지 않았는지 확인한다.

## 라이선스

MIT (`LICENSE`). 의존 패키지 mcp, comtypes 도 MIT 다.
cdb.exe 와 msdia140.dll 은 이 저장소에 포함되지 않으며 이 라이선스의 대상이 아니다 (요구 사항 참고).
