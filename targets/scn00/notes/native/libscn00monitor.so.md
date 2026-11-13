# libscn00monitor.so — 네이티브 분석 (RESILIENCE)

> 대상: `targets/scn00/unpacked/lib/arm64-v8a/libscn00monitor.so` · AARCH64 · 함수 115개 · 18,240 bytes
> 분석일: 2026-11-13 · 분석기준: [`docs/criteria/10-resilience.md`](../../../../docs/criteria/10-resilience.md) (메타블록 형식)
> Ghidra 대조: program_name=`libscn00monitor.so`, 5개 JNI export 확인(triage 일치). 난독화 신호 없음(평문 문자열, LLD 18 clang, `detect_anti_analysis` 빈 결과) → pseudocode 신뢰도 상대적으로 높으나 **1차 원칙상 전부 `가설`**.

## 0. 아키텍처 요약 (중요 — 우회 전략을 좌우)

이 모듈은 **"증거 수집 → 서명 리포트 생성"** 전용이다. **로컬 차단 분기가 없다.**
- 5개 `native*Evidence`/`nativeSignedReport*`는 루트·Frida·디버거·서명 흔적을 **문자열로 수집**해 Java로 반환하거나, `scenario|arg|flag|evidence` 페이로드를 **SHA-256 기반으로 서명**해 `base64(payload).hex(mac)` 형태로 돌려준다.
- 즉 `if (detected) finish()` 류의 **"뒤집을 분기"가 이 .so에는 없다.** 탐지 결과의 **판정·차단은 서버(`lab.eqst.co.kr`)** 몫(triage의 "인증 로직은 서버" 서술과 일치).
- **우회 함의**: 바이너리 분기 패치가 아니라 **① 증거 수집기(collector)가 빈 문자열을 반환하도록 후킹**(→ flag `'0'`, 리포트가 정당하게 "clean") 또는 **② Java↔네이티브 경계에서 리포트 자체를 교체**. 단 리포트가 서명돼 있어 **전송 중 변조(MITM)로는 못 바꾼다** → 서명 키/로직(§5)이 관건.

JNI 등록: export가 `Java_kr_co_eqst_pay_s00_Scn00MonitorModule_*` **정적 명명**이라 `JNI_OnLoad`의 `RegisterNatives` 테이블 불필요(이름 기반 동적링크). 단일 소비자 = `Scn00MonitorModule`.

---

## 1. 발견 (메타블록)

### [RES-ROOT-02] 네이티브 루트 탐지 (su 경로 · magisk · test-keys)
- 신뢰도: 가설
- 표준: MASVS-RESILIENCE-1 / MASWE-0051 / MASTG-TEST-0324·0325
- 위치: libscn00monitor.so `FUN_00102d8c` (collector) ← `nativeRootEvidence`(0x00102d3c) 래퍼 (ghidra)
- 근거: `stat()` 로 `/system/bin/su`,`/system/xbin/su`,`/sbin/su`,`/su/bin/su`,`/data/adb/magisk`,`/data/adb/modules`,`/sbin/.magisk` 존재 확인(iVar==0). `__system_property_get("ro.build.tags")` + `strstr("test-keys")`. 히트 시 `"su:%s"`/`"magisk:%s"`/`"prop:test-keys"` 를 `;` 구분자로 버퍼에 누적해 반환. **차단 없음 — 수집만.**
- 우회(가설): `nativeRootEvidence`/`FUN_00102d8c` 반환버퍼를 빈 문자열로 후킹, 또는 `stat` 후킹해 루트 경로에 ENOENT. (루트 숨김 자체는 Magisk DenyList로도 가능)
- 2차 메모: **가설 유지**. FP함정(정상 stat) 배제 — 인자가 su/magisk 경로. 미충족: 어셈블리 교차대조 + Frida 반환조작 재현. [verify.md]

### [RES-DBG-02] 네이티브 디버거 탐지 (TracerPid)
- 신뢰도: 가설
- 표준: MASVS-RESILIENCE-4 / MASWE-0064 / MASTG-TEST-0352·0353 · KNOW-0028
- 위치: libscn00monitor.so `FUN_00102c0c` ← `nativeDebuggerEvidence`(0x00102bbc) 래퍼 (ghidra)
- 근거: `/proc/self/status` 를 fgets하며 라인 선두 8바이트==`0x6950726563617254`(="TracerPi") AND 2바이트==`0x3a64`(="d:") 매칭 → `strtol` 값 >0 이면 `"tracerpid:%ld"` 수집. **ptrace 자가첨부가 아니라 TracerPid 파싱형.** (문자열 상수 리틀엔디안 교차확인 완료)
- 우회(가설): `/proc/self/status` 읽기 후킹해 `TracerPid: 0` 위장, 또는 collector 반환 무력화.
- 2차 메모: **가설 (정적 교차대조 ✓)**. 어셈블리 `0x102c78 cmp/ccmp/b.ne`·`0x102ca4 cmp#1;b.lt` pseudocode 일치 → 역분기 함정 배제. 남은 승급: 동적 재현. [verify.md]

### [RES-HOOK-01] Frida / 동적계측 탐지 (maps · 스레드명 · D-Bus 포트)
- 신뢰도: 가설
- 표준: MASVS-RESILIENCE-4 / MASWE-0065 / MASTG-TECH-0043 · DEMO-0119
- 위치: libscn00monitor.so `FUN_00102640` ← `nativeFridaEvidence`(0x001025f0) 래퍼 (ghidra)
- 근거: 3중 탐지 — ① `/proc/self/maps` 에서 `strstr` `"frida"`,`"gum-js"`,`"gadget"`,`"frida-agent"`,`"linjector"`. ② `/proc/self/task/*/comm` 스레드명 `"gum-js-loop"`,`"gmain"`,`"gdbus"`,`"pool-frida"`,`"pool-spawner"`. ③ `socket`+`connect` 127.0.0.1:**27042**(sa_data=`69 a2`)·**27043**(`69 a3`) = Frida D-Bus 포트. 히트 시 `"maps:%s"`/`"thread:%s"`/`"port:27042"` 수집.
- 우회(가설): collector 반환 무력화, 또는 `strstr`/`fopen(maps)`/`connect` 후킹으로 음성화. **다층(3경로)이라 한 곳만 막으면 FN** — 세 경로 모두 처리 필요. Frida 비표준 포트·스레드명 리네임도 보조.
- 2차 메모: **가설 유지**. FP함정(정상 maps 읽기) 배제 — 토큰 비교·포트 connect 명시. 미충족: 3경로 음성화 후 우회 재현(동적). [verify.md]

### [RES-INTEG-01] APK 서명/무결성 자체검증 (self-APK 파싱)
- 신뢰도: 가설
- 표준: MASVS-RESILIENCE-2 / MASWE-0057(App Resources Integrity)·0058(Runtime Code Integrity) / MASTG-TEST-0081·0090
- 위치: libscn00monitor.so `nativeSignedReport`(0x001031cc) 내 `"F38"` 분기 (ghidra)
- 근거: `/proc/self/maps` 에서 `/data/app/....base.apk` 경로 획득 → 해당 APK를 `rb` 오픈 → 말미 ≤0x10015B 읽어 ZIP EOCD(`50 4b 05 06`) 탐색 → **APK Signing Block** 매직 `"APK Sig Block 42"`(`0x20676953204b5041`/`0x3234206b636f6c42`) 파싱 → 서명 cert 영역 추출 후 `FUN_00104628`/`FUN_001048d8`(SHA-256 update/final 추정)로 해시 → 32바이트 hex. **결과를 리포트에 실어 서버로 보냄(로컬 비교상수 없음 → 서버검증형).**
- 우회(가설): 서버가 서명해시를 검증하는 구조면 **재패키징 시 서버에서 거부** → 로컬 패치만으로 불충분. `nativeSignedReport`/APK 읽기 지점 후킹해 정품 해시 위장 필요. 로컬 비교상수 유무는 §2차에서 확인.
- 2차 메모: **가설 (교정)**. 비교상수 존재 — `java_analysis.md`에 `OFFICIAL_CERT_SHA256` + `appLayerDetectsTamper()`(Java층 비교). native=해시산출, 비교=Java. 서버강제 여부는 트래픽 필요. [verify.md]

### [신규후보] SPKI 인증서 피닝 + 리포트 업링크 (NETWORK 카테고리 — RESILIENCE criteria 밖)
- 신뢰도: 가설
- 표준: (RESILIENCE criteria 미해당) → **MASVS-NETWORK-1 / 피닝** — 커버리지 공백, NETWORK criteria 작성 필요
- 위치: libscn00monitor.so `nativeSignedReportPinning`(0x00103a1c) (ghidra)
- 근거: 문자열 `"lab.eqst.co.kr"`, `"CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"`(프록시 CONNECT 터널), `getaddrinfo`/`setsockopt`/`write`/`freeaddrinfo`, 포맷 `"F37|%s|%s|"`. SPKI 피닝 포함 서명 리포트를 `lab.eqst.co.kr` 로 전송(triage의 `nativeSignedReportPinning` = SPKI 피닝과 일치).
- 우회(가설): 피닝이 네이티브에 있으므로 **Java/SSLContext 후킹(일반 unpinning)으로는 안 풀림** → 네이티브 피닝 비교 지점 후킹 또는 패치. Burp 중계(F28 동적분석) 시 이 피닝이 1차 장애물.
- 2차 메모: **공백(판정 보류)**. NETWORK criteria 부재로 대조 oracle 없음. `java_analysis.md §7`에 `PINNED_SPKI` 상수까지 상세 존재 → NETWORK criteria 신설 시 즉시 태깅. [verify.md]

---

## 2. 커버리지 (이 .so 기준, 2차 입력)

| criterion | 상태 | 비고 |
|---|---|---|
| RES-ROOT-02 | 분석됨 | FUN_00102d8c |
| RES-DBG-02 | 분석됨 | FUN_00102c0c (TracerPid형) |
| RES-HOOK-01 | 분석됨 | FUN_00102640 (3층) |
| RES-INTEG-01/02 | 분석됨 | nativeSignedReport F38 (서버검증형 추정) |
| RES-ROOT-01 / DBG-01 / HOOK-02 | 미해당 | Java 레벨 — 이 .so 아님(rev-jadx 소관) |
| RES-EMU-01 | **미발견** | 이 .so에 에뮬 탐지 없음(FN 아님, 설계상 부재로 보임 — 2차 확인) |
| RES-INTEG-03 (attestation) | **미발견** | Play Integrity/SafetyNet 흔적 없음 — 2차 확인 |
| RES-BIND-01 | **미발견** | 이 .so엔 없음 |
| [신규후보] NETWORK 피닝 | 분석됨 | nativeSignedReportPinning — **NETWORK criteria 부재(커버리지 공백)** |

## 3. 2차(/rev-verify)로 넘길 핵심 질문
1. **서명/MAC 로직** `FUN_00103924`(payload 서명), `FUN_001048d8`가 순수 SHA-256인지 **HMAC(키 내장)**인지 — 키가 .so에 있으면 리포트 위조 가능(약점). 미확인.
2. 각 collector의 **어셈블리 교차대조 + Frida 반환조작 재현**(승급 조건) — 1차는 `가설` 고정.
3. `nativeSignedReport`의 결과가 **서버에서 실제 검증**되는지(F28 트래픽과 연계) — 서버검증형이면 로컬 우회 무력.

> 상태: libscn00monitor.so = **1차 분석 done**. 다음: `/rev-verify scn00`.
