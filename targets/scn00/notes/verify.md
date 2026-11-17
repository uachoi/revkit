# 2차 검증 결과 — scn00 (RESILIENCE + NETWORK)

> 2차 패스: **재실행 2026-11-17** (최초 2026-11-13). 입력: `notes/native/libscn00monitor.so.md`(1차 태깅), `notes/java_analysis.md §9`(이번엔 **정식 criterion ID 태깅 완료** — 역매핑 폴백 불필요), `notes/triage.md`
> 기준: `docs/criteria/10-resilience.md` + `docs/criteria/50-network.md` · Ghidra MCP 연결됨(`pong`, 네이티브 어셈블리 교차대조는 11-13 패스에서 수행)
> 성격: **재검토 패스** — 새 분석 아님. 각 발견을 criterion의 `오탐함정`/`검증방법`/`승급조건`에 1:1 대조.
>
> **11-13 → 11-17 변경점**: Java 레이어가 `/rev-jadx` 신포맷으로 정식 태깅됨 → 지난 패스의 "레거시 폴백(상한 가설)" 처리가 **해소**. EMU·attestation 공백이 Java층 criterion ID로 정식 편입. NET-TRUST-01 오탐후보 1건 기각 추가.

## 재분류 요약

| 판정 | 수 | 발견 |
|---|---|---|
| **확정** | 0 | 전 criterion의 승급조건이 **동적(Frida) 재현**을 요구 — 정적 2차의 상한. (설계상 정상) |
| **가설** | 11 | native 5(ROOT-02·DBG-02·HOOK-01·INTEG-01·NET-PIN-02) + Java 6(ROOT-01·EMU-01·DBG-01·HOOK-01·INTEG-03·INTEG-01/02·NET-PIN-01) |
| **기각** | 1 | **NET-TRUST-01 후보** — `observedSpki$trustAll$1` TrustAll은 피닝 지문 관측 probe(오탐함정 ②), 실트래픽 취약점 아님 |
| **신규후보/미태깅** | 0 | (11-13의 NET 피닝 신규후보는 criteria 신설로 해소, Java 폴백은 정식 태깅으로 해소) |

> **"확정 0"은 실패가 아니다.** 정적 2차의 상한은 FP함정 배제 + 어셈블리 교차대조까지이며, `확정` 승급은 Frida 동적 단계(CLAUDE.md상 수동/후속)의 몫. 이번 패스의 성과는 **공백 2건(EMU·attestation) 정식 해소 + 오탐 1건(TRUST) 차단 + 레거시 폴백 제거**.

## 발견별 판정 — 네이티브 (`libscn00monitor.so`)

| criterion | 발견 | 판정 | 핵심 사유 |
|---|---|---|---|
| **RES-ROOT-02** | su/magisk/test-keys 수집 `FUN_00102d8c` | 가설 | FP함정(정상 stat) 배제. 미충족: 어셈블리 분기 + Frida 반환조작 |
| **RES-DBG-02** | TracerPid 파싱 `FUN_00102c0c` | 가설 | **어셈블리 교차대조 ✓**(0x102c78 cmp/ccmp/b.ne). 미충족: 디버거 attach 동적 재현 |
| **RES-HOOK-01** | Frida maps·thread·포트27042/3 `FUN_00102640` | 가설 | 3층 토큰 비교 확인. 미충족: 전경로 음성화 동적 |
| **RES-INTEG-01/02** | APK 서명블록 해시 `nativeSignedReport` F38 | 가설 | 비교상수는 Java층(아래). native=해시산출. 미충족: 서버강제+Frida |
| **NET-PIN-02** | 네이티브 SPKI 피닝 `nativeSignedReportPinning` 0x103a1c | 가설 | **증거수집형** — 지문을 HMAC 리포트로 서버 업링크(로컬 비교분기 아님). 우회=HMAC키 위조/수집 무력화 |

## 발견별 판정 — Java (`Scn00MonitorModule.java`, §9 정식 태깅)

| criterion | 발견 | 판정 | 핵심 사유 |
|---|---|---|---|
| **RES-ROOT-01** | `appLayerDetectsRoot()` `:238` | 가설 | FP함정(죽은 상수) 배제 — 실제 소비. native ROOT-02와 쌍 |
| **RES-EMU-01** | `looksLikeEmulator()` `:267` | 가설 ★공백해소 | native-only "미발견" 오판 교정. Build 토큰 비교가 판정에 합류 |
| **RES-DBG-01** | `appLayerDetectsDebugger()`+`tracerPid()` `:431` | 가설 | FP함정(BuildConfig.DEBUG) 배제. native DBG-02 미러 |
| **RES-HOOK-01**(Java) | `appLayerDetectsFrida()` `:423` | 가설 | 포트/maps/스레드명. **다층이라 일부만 막으면 FN** |
| **RES-INTEG-03** | `keyAttestationChain()` `:194` | 가설 ★공백해소 | 하드웨어 키 attestation. 강도=서버검증 여부(미확인) |
| **RES-INTEG-01/02**(Java) | `appLayerDetectsTamper()`+`OFFICIAL_CERT_SHA256` `:554/:65` | 가설(정적강함) | **native F38의 Java 비교상수 확정** → 1차 "서버검증형 추정" 정밀화. 재패키징 1순위 장애물 |
| **NET-PIN-01** | `observedSpki()`+`PINNED_SPKI` `:435/:74` | 가설 | lab.eqst.co.kr:8406 지문 == PINNED_SPKI 비교 |

### 기각 1건 (오탐 차단)
- **[NET-TRUST-01 후보] 기각** — `$observedSpki$trustAll$1`(`:440`)의 TrustAll X509TrustManager + accept HostnameVerifier(`:457`)는 얼핏 NET-TRUST-01(모든 인증서 수락)로 보이나, criterion의 **오탐함정 ②**(핀 지문을 직접 측정하려 TrustManager를 커스텀)에 정확히 해당. 앱 실 API 트래픽이 아니라 **피닝 지문 관측 probe** 전용 → 취약점 아님. criteria의 오탐함정 칸이 실제 오분류를 막은 사례.

## 커버리지 공백 (native + Java 교차 확정)

> 공백 판정은 **두 레이어를 모두 본 뒤** 내린다(11-13 교훈: native 단독이 attestation을 오판했음).

| criterion | 상태 | 사유 |
|---|---|---|
| RES-ROOT-01/02, DBG-01/02, HOOK-01, INTEG-01/02/03, EMU-01 | **분석됨(가설)** | native+Java 양층 태깅 완료 |
| RES-DBG-03 타이밍 | 미발견 | clock_gettime 류 임계비교 신호 없음 — 이 앱 미구현 추정(부재) |
| RES-HOOK-02 Xposed/Substrate | 미발견 | de.robv/substrate 신호 없음 — Frida 중심, Xposed 전용분기 부재 추정 |
| RES-BIND-01 디바이스 바인딩 | 미발견 | ANDROID_ID/Serial 세션바인딩 신호 미탐(단, keyAttestation이 기기성 보증 일부 대체) |
| **NET-CLEAR-01 평문** | **미분석(진짜 공백)** | manifest/network_security_config 미확인 — `/rev-jadx`가 `--no-res`라 NSC 미추출. **manifest·NSC 확인 필요** |
| **NET-TLS-01 약한 TLS** | 미분석 | 앱 실 API 클라이언트(OkHttp 등)의 프로토콜/cipher 미확인(모니터 모듈 밖) |
| NET-TRUST-01 | 분석됨(기각) | 위 — probe 오탐 차단 |
| **NET-MITM-01 프록시탐지** | 미분석 | http.proxyHost/VPN(tun0) 검사 유무 미확인 |
| (환경) RESILIENCE-3 난독화 | 해당 없음 | 평문 문자열·`detect_anti_analysis` 빈 결과 → 신뢰도 하향 보정 불필요 |

## 신뢰도 보정 메모
- 난독화 없음 → 정적 추론 환각 위험 낮음. 그럼에도 승급조건이 동적을 요구하므로 **전부 가설 유지**가 맞다.
- **클라이언트 신뢰근거가 전부 상수 노출**: `OFFICIAL_CERT_SHA256`(`:65`)·`PINNED_SPKI`(`:74`)·`PINNED_HOST:PORT` + 네이티브 HMAC 키 `SCN00-monitor-hmac-key-v1-eqstlb`(native §6). → **리포트 위조의 토대**가 정적으로 갖춰짐. 이 다섯 상수 확보 시 clean 리포트 위조 PoC가 `확정` 승급의 핵심 경로.

## 다음 할 일 (판정별)
- **확정 후보 → 동적(Frida) 단계**: (a) 각 collector 반환 무력화(native+Java 쌍 동시) → 탐지 우회 재현, (b) 추출 HMAC 키로 clean 리포트 위조 → `/scenario00/monitor/claim` 통과 확인. 되면 RES-* 다수 + NET-PIN + 서명키 결함이 `확정`. (CLAUDE.md상 수동/후속 phase)
- **공백 → 1차 보강**: NET-CLEAR-01/TLS-01/MITM-01은 **모니터 모듈 밖 앱 본체** 영역 — manifest(NSC) + 앱 실 네트워크 클라이언트(OkHttp/RN fetch) 확인 필요. `/rev-jadx`를 `--no-res` 없이 재실행하거나 manifest 별도 확인.
- **report → `/rev-report scn00`**: 확정 0이므로 현 report는 "가설 11 + 기각 1 + 공백 3(NET 본체)"를 **단정 없이** 기술. 동적 PoC 후 승급분을 확정 섹션으로 이동.
