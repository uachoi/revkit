# RESILIENCE 분석 기준 — 안티리버싱·변조탐지

> 카테고리: **MASVS-RESILIENCE** (리버싱·변조 저항) · 작성 형식: [`_template.md`](./_template.md)
> 적용 레벨: 전부 **R**. **R의 부재 자체는 취약점이 아니다**(OWASP 명시). 여기서의 "발견"은
> "방어가 존재하는가 / 얼마나 강한가 / **어떻게 우회되는가**"에 대한 판단이다. 모의해킹 관점에서 핵심은 **우회 포인트**.

## MASVS-RESILIENCE 통제 (live 확인됨)

| 통제 | 공식 wording | 다루는 criterion 패밀리 |
|---|---|---|
| **MASVS-RESILIENCE-1** | The app validates the integrity of the platform. | 루트, 에뮬레이터, 앱 가상화, 디바이스 attestation |
| **MASVS-RESILIENCE-2** | The app implements anti-tampering mechanisms. | APK 서명검사, 코드/리소스 무결성, 런타임 코드 무결성, 앱 attestation |
| **MASVS-RESILIENCE-3** | The app implements anti-static analysis mechanisms. | 난독화, 리소스 난독화, 디버그 아티팩트 제거 (→ 하단 분석 유의사항) |
| **MASVS-RESILIENCE-4** | The app implements anti-dynamic analysis techniques. | 디버거 탐지, 후킹/계측(Frida 등) 탐지 |

MASWE 매핑(live 확인): R-1 → MASWE-0051~0054, R-2 → MASWE-0055~0058, R-3 → MASWE-0059~0062, R-4 → MASWE-0063~0065.
(참고: R-2의 MASWE-0055는 "Malware Detection", 0057 "App Resources Integrity", 0058 "Runtime Code Integrity". **device binding은 전용 MASWE가 없고** 지식문서 MASTG-KNOW-0034로 다룸.)

---

## ⚑ RASP 유형 판별 — 우회 모델이 갈린다 (모든 criterion에 선행)

아래 criterion들의 `우회 포인트`를 읽기 전에, 이 `.so`/모듈이 **어느 유형의 RASP인지** 먼저 판별한다. 유형에 따라 우회 전략이 근본적으로 다르다.

| 유형 | 동작 | 우회 모델 |
|---|---|---|
| **로컬차단형** | 탐지 즉시 `if (detected) { finish()/kill/차단 }` 로 **앱이 스스로 반응** | **분기 뒤집기** — 탐지 결과 분기를 NOP/반전하거나 탐지 함수 반환값 고정. 전통적 "flip the branch". |
| **증거수집형** | 탐지 흔적을 **문자열/플래그로 수집 → 서명(HMAC 등) → 서버로 업링크**, **판정·차단은 서버**가 함 | 분기가 **없다**. 우회는 ① **수집기(collector) 무력화**(빈 결과 반환 후킹) 또는 ② **서명 키 복원 후 clean 리포트 위조**. 로컬 바이너리 패치만으로는 서버가 거부. |

> **scn00 실측 교훈**: `libscn00monitor.so`는 **증거수집형**이었다 — 루트/Frida/디버거 흔적을 수집해 **HMAC-SHA256 서명 리포트**를 만들고 판정은 서버(`lab.eqst.co.kr`)가 했다. **"뒤집을 분기"가 없어서** 각 criterion의 "분기 뒤집기" 우회가 그대로 적용되지 않았고, 실제 우회 포인트는 **collector 무력화 / 서명키 유출**이었다.
>
> 따라서 아래 criterion의 `우회 포인트`는 **"이 모듈이 어느 유형인가"**를 먼저 정한 뒤 해석한다. 증거수집형이면 "분기 뒤집기" 대신 "수집 경로 차단 + 서명 신뢰근거(키/서버검증) 공략"으로 읽는다.

---

## 패밀리 1 — 루트 탐지 (MASVS-RESILIENCE-1 / MASWE-0051)

### [RES-ROOT-01] Java 레벨 루트 탐지 (경로·패키지·프로퍼티·RootBeer류)
- **표준 매핑**: MASVS-RESILIENCE-1 / MASWE-0051 / MASTG-TEST-0324(References to Root Detection Mechanisms, 정적) · MASTG-TEST-0325(Runtime Use of Root Detection, 동적) ✅ live 확인 (구 MASTG-TEST-0045는 **deprecated**) · 지식: MASTG-KNOW-0027 · 우회기법: MASTG-TECH-0144
- **적용 레벨**: R
- **어디서 보나**: jadx(Java)
- **탐지 신호**:
  - 문자열: `/system/xbin/su`, `/system/bin/su`, `/sbin/su`, `/system/app/Superuser.apk`, `magisk`, `/data/adb/`, `busybox`
  - 패키지명: `com.topjohnwu.magisk`, `eu.chainfire.supersu`, `de.robv.android.xposed.installer`
  - API: `Runtime.exec("su")` / `getRuntime().exec`, `Build.TAGS` 에 `test-keys`, `getprop ro.debuggable`/`ro.secure`, `PackageManager.getInstalledPackages`로 su 앱 조회
  - 라이브러리: RootBeer (`com.scottyab.rootbeer`) — `isRooted()`, `checkForBinary`, `detectRootManagementApps`
- **오탐 함정(FP trap)**: ① 문자열 상수 테이블에만 있고 **호출 흐름에 안 닿는** 죽은 코드/라이브러리 잔재. ② 광고 SDK·크래시리포터가 진단용으로 `test-keys`만 읽는 경우(탐지 아님). ③ RootBeer를 **import만** 하고 결과를 무시하는 코드.
- **검증 방법(oracle)**: ① 정적: 각 su 문자열의 **xref가 실제 분기→동작(앱종료/기능차단/서버보고)**으로 이어지는지 확인. 단순 상수면 기각. ② 동적: Frida로 `RootBeer.isRooted`·`File.exists`·`Runtime.exec` 후킹해 false/throw 유도 → 앱 동작이 바뀌면 탐지 활성. ③ 증거: 탐지→대응 분기의 call graph 1개 이상.
- **우회 포인트**: `isRooted()`/`checkX()` 반환값 `false` 강제, 또는 `File.exists`/`exec` 후킹으로 su 미존재 위장. 대응 분기(`if(rooted) finish()`)를 Frida로 스킵.
- **신뢰도 기본값**: 가설
- **승급(확정) 조건**: su 문자열 xref → 대응 동작 연결을 정적 확인 **AND** (가능 시) Frida 후킹으로 탐지 우회 재현.
- **금융 가중**: 예

### [RES-ROOT-02] 네이티브(.so) 루트 탐지
- **표준 매핑**: MASVS-RESILIENCE-1 / MASWE-0051 / MASTG-TEST-0324·0325 ✅ (구 0045 deprecated) · 우회기법: MASTG-TECH-0144 / MASTG-TECH-0043
- **어디서 보나**: ghidra(.so)
- **탐지 신호**:
  - 문자열 참조: `.rodata`의 `/system/bin/su` 등(암호화됐으면 복호 루틴 뒤 스택에 조립 — 문자열이 안 보여도 `access`/`stat`/`fopen` 인자 추적)
  - syscall/libc: `access()`, `stat()`/`lstat()`, `fopen("/proc/...")`, `__system_property_get("ro.debuggable")`
  - JNI: `JNI_OnLoad`→`RegisterNatives`로 등록된 네이티브 메서드가 boolean 반환하며 위 호출 포함
- **오탐 함정**: ① `access`/`stat`는 **정상 파일 I/O**에도 쓰임 — 경로 인자가 루트 흔적이어야 탐지. ② 난독화 `.so`의 디컴파일 pseudocode가 분기를 **반대로** 보여줄 수 있음(그럴듯한 오답). ③ 복호화된 문자열을 못 읽어 "탐지 없음"으로 **과소판단**(FN) 위험.
- **검증 방법(oracle)**: ① **Listing/어셈블리 교차대조 필수** — pseudocode의 `if`를 실제 `CMP/B.cond` 분기와 대조(CLAUDE.md 규칙). ② 문자열이 런타임 조립형이면 Frida로 `access`/`stat` 인자를 덤프해 실제 검사 경로 확인. ③ 네이티브 함수 반환값을 Frida `Interceptor`로 뒤집어 앱 반응 관찰.
- **우회 포인트**: 네이티브 탐지 함수 `Interceptor.replace`로 0 반환 고정, 또는 `access`/`stat`를 후킹해 ENOENT 반환. 바이너리 패치 시 분기 조건 반전(`B.EQ`↔`B.NE`) — 단 무결성 검사(RES-INTEG) 동반 여부 먼저 확인.
- **신뢰도 기본값**: 가설 (네이티브·난독화는 특히 가설 고정)
- **승급(확정) 조건**: 어셈블리 분기 + 검사 경로 인자(정적/동적) 동시 확인 **AND** 반환값 조작 시 탐지 우회 재현.
- **금융 가중**: 예
- **예시**: Scn00Monitor류 RASP라면 루트 체크가 Java 진입점이 아니라 네이티브 모니터 스레드 안에 숨어 주기적으로 도는 형태일 수 있음 — 단발 분기만 보고 "우회 완료" 단정 금지.

---

## 패밀리 2 — 디버거 / 안티디버깅 (MASVS-RESILIENCE-4 / MASWE-0064, 0063)

### [RES-DBG-01] Java 디버거 탐지
- **표준 매핑**: MASVS-RESILIENCE-4 / MASWE-0064 / MASTG-TEST-0352(References to Debugging Detection APIs, 정적) · MASTG-TEST-0353(Runtime Use of Debugging Detection APIs, 동적) ✅ live 확인 · 지식: MASTG-KNOW-0028
- **어디서 보나**: jadx(Java), manifest
- **탐지 신호**: `Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()`, `ApplicationInfo.FLAG_DEBUGGABLE` 자가검사, manifest `android:debuggable` 확인 로직, JDWP 관련 체크.
- **오탐 함정**: `BuildConfig.DEBUG` 분기는 **개발 편의**일 뿐 방어가 아님 — 탐지로 오인 금지. 로그 게이팅용 `isDebuggerConnected`도 대응(차단)으로 안 이어지면 탐지 아님.
- **검증 방법(oracle)**: ① `isDebuggerConnected` 결과가 **차단/종료/서버보고** 분기로 가는지 xref. ② Frida로 해당 메서드 false 반환시켜 동작 변화 관찰.
- **우회 포인트**: `Debug.isDebuggerConnected` 후킹→false, 대응 분기 스킵.
- **신뢰도 기본값**: 가설 → **승급**: 결과→대응 연결 정적 확인 시.
- **금융 가중**: 예

### [RES-DBG-02] 네이티브 안티디버깅 (ptrace / TracerPid)
- **표준 매핑**: MASVS-RESILIENCE-4 / MASWE-0064 / MASTG-DEMO-0116(Native Anti-Debugging with TracerPid and ptrace) ✅ live 확인
- **어디서 보나**: ghidra(.so)
- **탐지 신호**: `ptrace(PTRACE_TRACEME, ...)` 자가첨부, `/proc/self/status` 읽어 `TracerPid:` 파싱(0 아니면 디버거), `fork()` 후 자식이 부모 ptrace, `/proc/self/task/*/status` 순회. syscall 번호 직접 호출(svc) 형태도 흔함.
- **오탐 함정**: `ptrace`가 **크래시 핸들러/프로파일러**로 쓰이는 정상 사례와 혼동. `/proc/self/status` 읽기가 메모리 통계용일 수 있음 — `TracerPid` 토큰 비교가 있어야 안티디버깅 확정.
- **검증 방법(oracle)**: ① 어셈블리에서 `ptrace` 호출 직후 반환값 분기, 또는 `TracerPid` 문자열 비교 후 분기 확인. ② Frida로 `ptrace` 후킹(0 반환)·`/proc/self/status` 읽기 가로채 `TracerPid: 0` 반환 → 디버거 붙여도 통과하면 확정. MASTG-DEMO-0116 절차 참조.
- **우회 포인트**: `ptrace` `Interceptor.replace`→0, `fopen("/proc/self/status")` 결과 스푸핑, 또는 svc 직호출이면 해당 분기 패치. 자식프로세스 ptrace형은 **부모가 아니라 자식**을 다뤄야 함(놓치기 쉬움).
- **신뢰도 기본값**: 가설 (svc 직호출·난독화 시 pseudocode 신뢰 금지, 어셈블리 필수)
- **승급(확정) 조건**: 어셈블리 분기 확인 **AND** 디버거 attach 상태에서 우회 재현.
- **금융 가중**: 예

### [RES-DBG-03] 타이밍 기반 디버깅/계측 탐지
- **표준 매핑**: MASVS-RESILIENCE-4 / MASWE-0064 · 전용 테스트 ID 없음(타이밍은 안티디버깅 기법의 하나) → 상위 MASTG-TEST-0352/0353 · MASTG-KNOW-0028로 포괄 ✅ live 확인
- **어디서 보나**: ghidra(.so), jadx(Java)
- **탐지 신호**: `clock_gettime`/`gettimeofday`/`System.nanoTime` 쌍으로 구간 측정 후 임계값 비교(계측 시 느려짐 가정).
- **오탐 함정**: 성능 측정·애니메이션 타이밍 등 **정상 시간측정**과 구분 어려움 — 임계값 비교→대응 분기가 있어야 탐지.
- **검증 방법(oracle)**: 측정 구간 결과가 종료/차단으로 가는 분기 확인. 동적으로는 측정 함수 반환을 작은 값으로 고정.
- **우회 포인트**: 타이밍 함수 후킹으로 정상 범위 값 반환.
- **신뢰도 기본값**: 가설. **금융 가중**: 아니오(일반적으로 보조 신호).

---

## 패밀리 3 — 에뮬레이터 / 가상환경 탐지 (MASVS-RESILIENCE-1 / MASWE-0053, 0052)

### [RES-EMU-01] 에뮬레이터·가상 디바이스 탐지
- **표준 매핑**: MASVS-RESILIENCE-1 / MASWE-0053 / MASTG-TEST-0351(Runtime Use of Emulator Detection Techniques) ✅ live 확인 · MASTG-DEMO-0114 ✅
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: `Build.FINGERPRINT`에 `generic`/`vbox`/`goldfish`/`ranchu`, `Build.MODEL`=`sdk`/`Emulator`, `Build.HARDWARE`=`goldfish`/`ranchu`, QEMU 흔적 파일(`/dev/qemu_pipe`, `/dev/socket/qemud`), 센서/통신 부재 체크, `ro.kernel.qemu` 프로퍼티.
- **오탐 함정**: `Build.FINGERPRINT` 참조가 **애널리틱스/기기식별**용일 수 있음 — 에뮬 토큰 비교+대응이 있어야 탐지. 일부 실기기도 `generic` 포함 가능(과탐).
- **검증 방법(oracle)**: 토큰 비교 결과→대응 분기 xref. Frida로 `Build` 필드·프로퍼티 getter 후킹해 실기기 값 위장 → 통과하면 확정.
- **[MASWE-0052] 앱 가상화(VirtualApp/다중계정) 탐지**는 별도 신호: 자기 프로세스가 다른 패키지 샌드박스 안인지(`/proc/self/maps`에 타 패키지 경로, 데이터 경로 불일치) — 함께 점검.
- **우회 포인트**: `Build` 필드/시스템 프로퍼티/파일존재 후킹으로 실기기 위장.
- **신뢰도 기본값**: 가설. **금융 가중**: 예(결제 앱 다수가 에뮬 차단).

---

## 패밀리 4 — 후킹 / 계측 탐지 (MASVS-RESILIENCE-4 / MASWE-0065)

### [RES-HOOK-01] Frida / 동적계측 탐지
- **표준 매핑**: MASVS-RESILIENCE-4 / MASWE-0065(Dynamic Analysis Tools Detection) ✅ live 확인 · MASTG-TECH-0043(Method Hooking) ✅ · MASTG-DEMO-0119(Frida D-Bus Port) ✅(iOS 데모지만 기법 공통)
- **어디서 보나**: ghidra(.so), jadx(Java)
- **탐지 신호**:
  - 문자열: `frida`, `frida-server`, `gum-js-loop`, `gmain`, `re.frida.server`, `LIBFRIDA`, D-Bus 포트 `27042`/`27043`
  - 파일/맵 스캔: `/proc/self/maps`·`/proc/self/task/*/status` 순회해 `frida`/`gadget` 매핑, `/data/local/tmp/` 바이너리
  - 포트: 로컬 `27042` TCP connect 시도
  - 명명 스레드·named pipe 탐지, `pthread` 스레드명 `gum-js-loop` 비교
- **오탐 함정**: `/proc/self/maps` 읽기 자체는 정상(메모리 관리) — **frida/gadget 문자열 비교**가 있어야 탐지. 포트 스캔이 다른 용도일 수 있음.
- **검증 방법(oracle)**: ① maps 순회 루프에서 비교 대상 문자열(복호화 후일 수 있음)을 어셈블리/Frida로 확인. ② Frida로 maps 읽기·strstr·포트 connect 후킹해 음성 반환 → 탐지 함수 통과 재현. ③ 다중 레이어(Java+네이티브 동시)일 수 있으니 하나 우회 후에도 재탐지 되는지 확인.
- **우회 포인트**: 탐지 함수 반환 고정, `strstr`/`strcmp` 후킹으로 frida 토큰 미스, maps read 결과 필터링. 포트형은 connect 후킹. **여러 지점 동시**일 수 있어 단일 후킹으로 끝났다고 단정 금지.
- **신뢰도 기본값**: 가설 (문자열 암호화 흔함 → FN 주의)
- **승급(확정) 조건**: 비교 토큰 확인 **AND** 후킹으로 우회 재현.
- **금융 가중**: 예
- **예시**: Scn00Monitor류 RASP라면 Frida 탐지가 주기적 모니터 루프에 포함돼 1회 우회 후 수 초 뒤 재탐지하는 구조일 수 있음 — 지속성 확인 필요.

### [RES-HOOK-02] Xposed / Substrate / 기타 후킹 프레임워크 탐지
- **표준 매핑**: MASVS-RESILIENCE-4 / MASWE-0065 ✅
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: 패키지 `de.robv.android.xposed`, `XposedBridge.jar`, `/system/framework/XposedBridge.jar`, Substrate `com.saurik.substrate`, 스택트레이스에 후킹 프레임 검사, 로드된 클래스/맵에 `epic`/`sandhook`.
- **오탐 함정**: 문자열만 있고 미사용 라이브러리 잔재 가능. 스택트레이스 검사는 특정 호출경로에서만 동작.
- **검증 방법(oracle)**: 검사 결과→대응 분기 xref, 동적으로 해당 클래스로더/파일 체크 후킹.
- **우회 포인트**: `ClassLoader.loadClass`/`File.exists` 후킹, 스택트레이스 필터.
- **신뢰도 기본값**: 가설. **금융 가중**: 예.

---

## 패밀리 5 — 무결성 / 변조 탐지 (MASVS-RESILIENCE-2 / MASWE-0057 리소스무결성, 0058 런타임코드무결성 · attestation은 0054/0056)

### [RES-INTEG-01] APK 서명 검증 (anti-repackaging)
- **표준 매핑**: MASVS-RESILIENCE-2 / MASWE-0057(App Resources Integrity Not Verified) ✅ live 확인 · 테스트: MASTG-TEST-0081(앱 정상 서명 확인) · 관련 MASTG-TEST-0090(파일 무결성)
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: `PackageManager.getPackageInfo(..., GET_SIGNATURES/GET_SIGNING_CERTIFICATES)`, `signingInfo.apkContentsSigners`, 서명 해시(SHA-256) 상수와 비교, 네이티브에서 APK 파싱해 서명 블록 검증.
- **오탐 함정**: 서명 조회가 **정품 확인·라이선싱**용이고 변조 대응이 없을 수 있음. 비교 대상 해시 상수가 코드에 없고 서버 비교형이면 정적만으로 판단 어려움.
- **검증 방법(oracle)**: ① 서명 해시 비교 결과→종료/차단 분기 xref. ② 네이티브형이면 어셈블리에서 비교 상수/서버전송 확인. ③ Frida로 `getPackageInfo`/서명 getter 후킹해 정품 서명 위장 → 통과 재현(리패키징 우회 핵심).
- **우회 포인트**: 서명 반환 후킹(정품 해시 위장), 비교 결과 분기 뒤집기. **재패키징 분석 시 1순위** — 이게 안 풀리면 변조 APK가 자체 종료.
- **신뢰도 기본값**: 가설 → **승급**: 비교 대상·대응 분기 확인 + 후킹 우회 재현.
- **금융 가중**: 예

### [RES-INTEG-02] 코드/리소스 체크섬 (DEX·so·파일 CRC/해시)
- **표준 매핑**: MASVS-RESILIENCE-2 / MASWE-0058(Runtime Code Integrity Not Verified)·MASWE-0057(App Resources Integrity) ✅ live 확인 · 테스트: MASTG-TEST-0090(파일 무결성) (구 MASTG-TEST-0050 Runtime Integrity는 **deprecated**)
- **어디서 보나**: ghidra(.so), jadx(Java)
- **탐지 신호**: `CRC32`/`MessageDigest`로 `classes.dex`·`.so`·assets 해시 계산 후 상수 비교, `zipEntry.getCrc()` 비교, 네이티브에서 자기 `.text` 세그먼트 해시(런타임 코드 무결성).
- **오탐 함정**: CRC/해시가 **다운로드 검증·캐시 무결성** 등 비보안 용도일 수 있음. `.text` 해시 루틴은 난독화로 식별 어려움(FN).
- **검증 방법(oracle)**: 해시 결과 비교→대응 분기 확인(어셈블리). 동적으로 해시 계산 함수/비교 지점 후킹해 기대값 반환.
- **우회 포인트**: 해시 계산 결과 또는 비교 분기 후킹. **자기 .text 해시형**은 바이너리 패치와 상호검사하므로 후킹 우회가 안전.
- **신뢰도 기본값**: 가설. **금융 가중**: 예.

### [RES-INTEG-03] 디바이스/앱 attestation (Play Integrity · SafetyNet · 키 attestation)
- **표준 매핑**: MASVS-RESILIENCE-1/2 / MASWE-0054(Device Attestation)·MASWE-0056(App Attestation) ✅ live 확인
- **어디서 보나**: jadx(Java), manifest
- **탐지 신호**: `com.google.android.play.core.integrity` / `IntegrityManager`·`StandardIntegrityManager`, (구)SafetyNet `SafetyNetApi.attest`, `KeyStore` 키 attestation 체인 검증, 서버로 integrity 토큰 전송.
- **오탐 함정**: 토큰을 받기만 하고 **서버 검증을 안 하면** 클라이언트 우회로 무력화 가능(이건 오탐이 아니라 **약점 발견 포인트**). 클라이언트 코드만으로 강도 판단 금지.
- **검증 방법(oracle)**: integrity 토큰이 **서버에서 실제 검증**되는지(트래픽·서버 동작) 확인. 클라이언트 측 분기만이면 Frida로 결과 위장 가능성 평가. 서버강제형이면 네이티브/트래픽 변조 난이도 상향.
- **우회 포인트**: 클라이언트 판단형이면 결과 후킹. 서버검증형이면 **우회 불가에 가까움** — "강한 방어"로 보고.
- **신뢰도 기본값**: 가설. **금융 가중**: 예(강한 방어 여부가 리포트 결론 좌우).

---

## 패밀리 6 — 디바이스 바인딩 (MASVS-RESILIENCE-1 보조)

### [RES-BIND-01] 디바이스 바인딩 / 기기 고정
- **표준 매핑**: MASVS-RESILIENCE-1 (device binding) · **전용 MASWE 없음** — MASWE 목록에 미포함, 지식문서 MASTG-KNOW-0034(Device Binding)로 다룸 ✅ live 확인. (기기 attestation은 별개 항목으로 MASWE-0054)
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: `Settings.Secure.ANDROID_ID`, `Build.getSerial`, 하드웨어 기반 Keystore 키(StrongBox), 등록 기기 식별자와 서버 바인딩, IMEI/광고ID 수집 후 바인딩.
- **오탐 함정**: 기기식별자 수집이 **애널리틱스/프라이버시 이슈**(PRIVACY 카테고리)일 수 있음 — 세션/자격증명 바인딩에 쓰여야 RESILIENCE. 둘 다면 양쪽 criterion에 기록.
- **검증 방법(oracle)**: 식별자가 인증 토큰·세션과 **묶여 서버 검증**되는지 흐름 확인. 바인딩 깨고(식별자 위장) 세션 유효한지 동적 확인.
- **우회 포인트**: 식별자 getter 후킹으로 등록기기 위장(세션 탈취/이관 시나리오).
- **신뢰도 기본값**: 가설. **금융 가중**: 예.

---

## 분석 유의사항 — 난독화·안티정적분석 (MASVS-RESILIENCE-3 / MASWE-0059~0062)

이건 개별 "발견 criterion"이라기보다 **위 모든 criterion의 신뢰도를 좌우하는 환경 조건**이다.
RESILIENCE-3 방어가 강할수록 1차 정적 추론의 환각 위험이 커지므로 **신뢰도를 보수적으로** 잡는다.

- **네이티브 문자열 암호화**: `.rodata`에 평문 su/frida 문자열이 안 보여도 "탐지 없음"으로 단정 금지(FN). 복호 루틴 뒤 스택 조립·`memcpy` 인자를 추적하거나 Frida로 런타임 문자열 덤프.
- **제어흐름 난독화(CFG flattening)·opaque predicate**: Ghidra pseudocode의 `if`/루프가 **실제 분기와 다르게** 보일 수 있음 → CLAUDE.md 규칙대로 **Listing/어셈블리 교차대조를 승급 조건에 필수 포함**.
- **패커/안티디컴파일**: 런타임에 DEX/코드 동적 로드·복호화 시 jadx 출력이 비거나 stub만 — 이 경우 정적 1차는 "미확인(공백)"으로 남기고 동적 단계로 넘김. (APKiD로 패커 식별 권장 — 별도 도구)
- **디버그 아티팩트(MASWE-0061)**: 로그·`BuildConfig.DEBUG`·디버그 심볼 잔존은 **분석을 돕는 단서**이자 동시에 앱의 약점 — 발견 시 기록.
- **원칙**: RESILIENCE-3가 강하게 걸린 `.so`의 모든 발견은 **기본 `가설` 고정**, 어셈블리 교차대조 + 동적 재현 전까지 `확정` 금지.

---

## 커버리지 체크리스트 (2차 패스 — 공백 점검용)

2차(`/rev-verify`)에서 아래 각 항목이 **분석됨/미분석**인지 표기한다. 미분석이면 "커버리지 공백"으로 보고.

- [ ] RES-ROOT-01 Java 루트 탐지
- [ ] RES-ROOT-02 네이티브 루트 탐지
- [ ] RES-DBG-01 Java 디버거 탐지
- [ ] RES-DBG-02 네이티브 ptrace/TracerPid
- [ ] RES-DBG-03 타이밍 탐지
- [ ] RES-EMU-01 에뮬레이터/가상환경 (+ 앱 가상화)
- [ ] RES-HOOK-01 Frida/계측 탐지
- [ ] RES-HOOK-02 Xposed/Substrate 탐지
- [ ] RES-INTEG-01 APK 서명 검증
- [ ] RES-INTEG-02 코드/리소스 체크섬
- [ ] RES-INTEG-03 attestation (Play Integrity/SafetyNet/키)
- [ ] RES-BIND-01 디바이스 바인딩
- [ ] (환경) RESILIENCE-3 난독화 수준 평가 → 전체 신뢰도 보정

---

## 출처 (live 확인, 2026-11)

- MASVS-RESILIENCE: [mas.owasp.org/MASVS/11-MASVS-RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
- MASWE-0051 Root/Jailbreak: [mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0051](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0051/)
- MASWE 전체: [mas.owasp.org/MASWE](https://mas.owasp.org/MASWE/)
- MASTG 루트탐지 테스트(현행): [MASTG-TEST-0324](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0324/) · [MASTG-TEST-0325](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0325/) (구 0045 deprecated)
- MASTG 디버거탐지: MASTG-TEST-0352 / 0353 · 지식 [MASTG-KNOW-0028](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0028/)
- MASTG 디바이스 바인딩(지식): [MASTG-KNOW-0034](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0034/)
- MASTG 기법(Method Hooking): [mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/)

> **2026-11 기준 ID 재확인 완료 — 남은 `⚠️ 미검증` 없음.** 루트 0324/0325(구 0045 deprecated),
> 디버거 0352/0353, 에뮬 0351, 무결성 테스트 0081/0090(구 0050 deprecated),
> device binding은 전용 MASWE 없이 MASTG-KNOW-0034. 통제(RESILIENCE-1~4)·MASWE-0051~0065 범위 확인됨.
