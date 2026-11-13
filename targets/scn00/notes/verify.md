# 2차 검증 결과 — scn00 (RESILIENCE)

> 2차 패스일: 2026-11-13 · 입력: `notes/native/libscn00monitor.so.md`(1차, ID 태깅됨), `notes/java_analysis.md`(레거시·태깅 없음), `notes/triage.md`
> 기준: `docs/criteria/10-resilience.md` · Ghidra MCP 연결됨(어셈블리 교차대조 수행)
> 성격: **재검토 패스** — 새 분석 아님. 1차 발견을 criterion의 `오탐함정`/`검증방법`/`승급조건`에 1:1 대조.

## 재분류 요약

| 판정 | 수 | 비고 |
|---|---|---|
| **확정** | 0 | 정적 단계만으로는 승급 불가 — 전 criterion의 승급조건이 **동적(Frida) 재현**을 요구(설계상 당연). |
| **가설** | 4 | RES-ROOT-02, RES-DBG-02, RES-HOOK-01, RES-INTEG-01 — 정적 교차대조는 완료/가능, 동적만 남음. |
| **기각** | 0 | 오탐 없음(전부 평문·실동작 확인). |
| **신규후보/공백** | 1 | NETWORK 피닝(criteria 부재). |

> **핵심 프로세스 소견**: "확정 0"은 실패가 아니라 **파이프라인이 의도대로 작동한 결과**다. 정적 2차는 FP함정 배제 + 어셈블리 교차대조까지가 상한이고, `확정` 승급은 Frida 단계(CLAUDE.md상 수동/후속)의 몫임이 재확인됐다.

## 발견별 판정

### [RES-DBG-02] 네이티브 디버거(TracerPid) — **가설 (정적 교차대조 ✓, 동적만 남음)**
- 오탐함정 대조: "ptrace가 프로파일러/status가 메모리통계" → **배제**. `TracerPid:` 토큰 명시 비교 + 값>0 분기 확인.
- 검증방법 ①(어셈블리): **이번 패스에서 수행** — `0x102c78 cmp x8,x21`/`ccmp w9,w22`/`b.ne`, `0x102ca4 cmp #1; b.lt`가 pseudocode와 일치. 역분기 함정 배제.
- 미충족(승급): ②동적 — 디버거 attach 상태에서 반환 무력화 재현. → 가설 유지.

### [RES-ROOT-02] 네이티브 루트(su/magisk/test-keys) — **가설**
- 오탐함정 대조: "stat이 정상 I/O" → **배제**(인자가 `/system/bin/su` 등 루트 흔적). 평문 문자열이라 복호 FN 위험 없음.
- 미충족: 어셈블리 분기 교차대조(미수행) + Frida 반환조작 재현. → 가설.

### [RES-HOOK-01] Frida(maps·스레드명·D-Bus 포트) — **가설**
- 오탐함정 대조: "maps 읽기 자체는 정상" → **배제**(frida/gum-js/gadget 토큰 비교 명시, 27042/43 포트 connect 확인).
- 미충족: 동적 — 3경로 전부 음성화 후 우회 재현. **다층이라 1곳만 막으면 FN** 경고 유지.

### [RES-INTEG-01] APK 서명 자체검증 — **가설 (교차확인으로 정밀화)**
- **레거시 교차확인**: 1차에선 "native 로컬 비교상수 없음=서버검증형 추정"이라 했으나, `java_analysis.md §4`에 **`OFFICIAL_CERT_SHA256` 상수 + `appLayerDetectsTamper()`(Java층 SHA-256 비교)** 존재 확인 → 비교는 **Java층**, native(F38)는 해시 산출 담당. 1차 추정 보정.
- 미충족: 서버가 실제로 claim의 서명/해시를 강제하는지(트래픽) + Frida 우회 재현. → 가설.

### [NET-PIN-02] 네이티브 레벨 인증서 피닝 — **공백 해소 (criteria 신설됨)**
- (구 `[신규후보]`) NETWORK criteria 신설로 정식 태깅 → **`NET-PIN-02`** ([`50-network.md`](../../../docs/criteria/50-network.md)). `nativeSignedReportPinning`(0x103a1c)이 그 예시로 등재됨. 표준: MASVS-NETWORK-2 / MASWE-0028 / MASTG-KNOW-0015.
- 판정: **가설** — 증거수집형(지문을 HMAC 리포트에 실어 서버 업링크, 로컬 비교 분기 아님). 우회는 Java unpinning 불가 → 네이티브 수집 무력화 또는 HMAC 키 위조. 승급: 네이티브 후킹으로 Burp 중계 성립 재현.

## 레거시 노트 재조정 (★ 폴백 발동 — 태깅 누락 신호)

`java_analysis.md`는 **criterion ID가 없는 구 포맷**이다. rev-verify 폴백(역매핑) 대상이며, 역매핑한 발견은 **신뢰도 상한 `가설`**로 고정한다. 역매핑이 필요했다는 것 자체가 **"1차 태깅 누락"** — 아래는 재태깅 권고 목록:

| 레거시 발견 | 역매핑 criterion | 상한 | 메모 |
|---|---|---|---|
| `appLayerDetectsRoot()` | RES-ROOT-01(Java) | 가설 | rev-jadx 신포맷 재실행 시 정식 태깅 |
| `appLayerDetectsDebugger()`/`Debug.isDebuggerConnected` | RES-DBG-01(Java) | 가설 | 동일 |
| `appLayerDetectsFrida()` | RES-HOOK-01(Java측) | 가설 | 동일 |
| F34 `keyAttestationChain()` 하드웨어 키 attestation | **RES-INTEG-03** | 가설 | **1차 native 노트에서 "미발견"으로 적은 항목 — 실제는 존재. 커버리지 오판 교정.** |
| **HMAC 대칭키 하드코딩** `SCN00-monitor-hmac-key-v1-eqstlb` (ipad⊕0x36 = opad⊕0x5c 2경로 교차검증) | (RESILIENCE 밖 — 서명키 유출/리포트 위조) | 가설(상한) | **정적으로 확정 가능한 성격이나, 폴백 규칙상 상한 가설.** → 아래 프로세스 개선점 참조. |

> 1차 native 노트의 "2차 질문 #1(HMAC 키/서버검증)"은 레거시 노트에서 **이미 해소**됨 — key 추출·서명포맷 `base64(payload).hmac_hex` 확인. 두 노트가 **중복 분석**됐다는 뜻이기도 하다(§프로세스).

## 커버리지 공백 (10-resilience 체크리스트 기준, 이 .so)

| criterion | 상태 | 사유 |
|---|---|---|
| RES-ROOT-02 / DBG-02 / HOOK-01 / INTEG-01 | 분석됨(가설) | 위 |
| RES-INTEG-03 attestation | **분석됨(교정)** | F34 keyAttestationChain — 1차 "미발견" 오판을 레거시로 교정 |
| RES-ROOT-01 / DBG-01 (Java) | 레거시만(태깅누락) | rev-jadx 신포맷 미실행 → 정식 공백 |
| RES-HOOK-02 Xposed / RES-EMU-01 에뮬 / RES-BIND-01 바인딩 | **진짜 공백** | 세 신호 전부 미탐 — 이 앱이 해당 방어 **미구현**으로 추정(2차 단정 아님, 부재 확인 권장) |
| (환경) RESILIENCE-3 난독화 | 해당 없음 | 평문 문자열·`detect_anti_analysis` 빈 결과 → **신뢰도 하향 보정 불필요** |

## 신뢰도 보정 메모
- 난독화 없음 → 정적 추론 환각 위험 낮음. 그럼에도 승급조건이 동적을 요구하므로 **전부 가설 유지**가 맞다.
- `확정` 승급 경로: Frida로 (a) 각 collector 반환 무력화 → 탐지 우회 재현, (b) 추출 HMAC 키로 clean 리포트 위조 → `/scenario00/monitor/claim` 통과 확인. 이게 되면 RES-* 다수 + 서명키 결함이 `확정`.

## 다음 할 일
- **확정 후보 → 동적 단계**: Frida 후킹/키 위조 PoC (CLAUDE.md상 수동/후속 phase).
- **공백 → 1차 재실행**: `/rev-jadx scn00`을 **신포맷으로** 재실행해 Java층(RES-ROOT-01/DBG-01) 정식 태깅.
- **criteria 확장**: NETWORK(피닝) criteria 신설 → 피닝·HMAC키 결함을 정식 태깅.

---
### ⚠ 이번 스모크 테스트가 드러낸 프로세스 개선점 (criteria/커맨드에 반영 후보)
1. **중복 분석**: 기존 `java_analysis.md`가 이미 native까지 깊게 분석(HMAC 키 추출 포함). 1차 `/rev-native`가 이를 **재생산**함. → rev-native가 시작 시 기존 노트를 먼저 읽어 **중복 대신 보완/태깅**하도록 지침 추가 필요.
2. **폴백 상한 규칙의 경직성**: HMAC 키 유출처럼 **정적으로 확정 가능한** 결함도 "태깅 누락"이면 상한 가설로 눌림. → 폴백 규칙에 "정적 증명가능 결함은 재태깅 후 확정 허용" 예외 검토.
3. **커버리지 오판**: 1차 native 단독으로 "attestation 미발견"이라 적었으나 Java층에 존재. → 커버리지 판정은 **native+java 노트 교차** 후 내리도록 2차 기준 명시.
