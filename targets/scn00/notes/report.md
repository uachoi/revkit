# scn00 Scn00Monitor RASP 모듈 — 종합 분석 보고서

> 작성: 2026-11-09 · 대상: EQST FinTech App Hacking 워게임 / scn00 (`kr.co.eqst.pay.s00`)
> 범위: 인가된 모의해킹. RN 네이티브 모듈 `Scn00Monitor` + `libscn00monitor.so` 의 기기 무결성(RASP) 로직
> 근거 문서: [`java_analysis.md`](./java_analysis.md)(Java·서버 흐름) · [`native_analysis.md`](./native_analysis.md)(Ghidra 네이티브) · [`triage.md`](./triage.md)

---

## 1. Executive Summary

`Scn00Monitor` 는 M형 문제 **F34(루트)·F35(Frida)·F36(디버거)·F37(인증서피닝)·F38(앱변조)** 을 담당하는
**클라이언트 측 RASP(기기 무결성 증명)** 모듈이다. JS가 서버에서 1회용 nonce를 받아 네이티브로 넘기면,
`libscn00monitor.so` 가 탐지 증거를 수집해 **HMAC-SHA256 으로 서명한 리포트**를 만들고, 이를 서버
(`POST /scenario00/monitor/claim`)가 검증해 "안전한 기기"임을 판정한다.

**핵심 취약점**: 리포트 서명에 쓰는 HMAC 키가 `.so` 바이너리에 **하드코딩된 대칭키**
(`SCN00-monitor-hmac-key-v1-eqstlb`)다. 키를 추출하면 서버가 발급한 어떤 nonce에 대해서도 "탐지 흔적 없음"
리포트를 **임의 위조**할 수 있어, 루팅·Frida·디버거·프록시 환경에서도 F34~F38 전 항목을 우회할 수 있다.
RASP의 신뢰근거가 단일 클라이언트 비밀 하나에 걸려 있는 전형적 설계 결함이다.

| 항목 | 내용 |
|---|---|
| 심각도 | **High** (RASP 전면 우회 → 변조·후킹 환경에서 보호 로직 전부 무력화) |
| 유형 | 하드코딩된 암호 키 / 클라이언트 측 신뢰 (CWE-798, CWE-321, M10) |
| 영향 범위 | F34~F38 기기 무결성 판정 전체 |
| 비고 | F34의 Java 하드웨어 Key Attestation(TEE 기반)은 상대적으로 견고 — §6 |

---

## 2. 대상 아키텍처

```
┌─ React Native (Hermes) JS ──────────────────────────────┐
│  scenario00MonitorNonce  →  GET  /scenario00/monitor/nonce?itemCode=F3x
│  NativeModules.Scn00Monitor.buildMonitorVerdict(itemCode, nonce, apiBaseUrl)
│  scenario00MonitorClaims →  POST /scenario00/monitor/claim  { verdict }
└─────────────────────────┬───────────────────────────────┘
                          │ RN 브리지 (@ReactMethod, 유일 진입점)
┌─ Java/Kotlin (classes3.dex) Scn00MonitorModule ─────────┐
│  buildMonitorVerdict() : itemCode 스위치 → native 호출 + appLayer 병행
│  System.loadLibrary("scn00monitor")                      │
└─────────────────────────┬───────────────────────────────┘
                          │ JNI (5 export)
┌─ Native libscn00monitor.so (arm64) ─────────────────────┐
│  detect_root / frida / debugger_evidence                 │
│  nativeSignedReport(F34/35/36/38) · nativeSignedReportPinning(F37)
│  payload="code|nonce|flag|evidence" → HMAC-SHA256 → base64(pld).hmac_hex
└──────────────────────────────────────────────────────────┘
```

- 서버: 피닝 대상 `https://lab.eqst.co.kr:8406` (apiBaseUrl 유력).
- 앱: React Native + Hermes. JS 호출흐름·엔드포인트는 `assets/index.android.bundle`(Hermes) 문자열에서 확인.

---

## 3. 분석 방법론

| 단계 | 도구 | 산출 |
|---|---|---|
| Java triage | jadx 1.5.0 CLI | `loadLibrary("scn00monitor")`·5개 native 특정 → `triage.md` |
| Java 디컴파일 | jadx (classes.dex/2/3, 10,787 java) | `Scn00MonitorModule` 전체 로직 → `java_analysis.md` |
| JS 호출흐름 | Hermes 번들 문자열 추출 | 엔드포인트·브리지 토큰(`buildMonitorVerdict`, `/scenario00/monitor/*`) |
| 네이티브 | Ghidra 12 + GhidraMCP | 탐지 5종·HMAC·서명포맷·키 복원 → `native_analysis.md` |

> jadx 메모리: 기본 설정에서 대형 멀티덱스(≈9천 클래스) 처리 중 G1 커밋 실패로 72%에서 중단.
> `JAVA_OPTS="-Xmx3g -XX:+UseSerialGC"` + `-j 1`(단일 스레드)로 완주.

---

## 4. 핵심 발견 — RASP 탐지 메커니즘

### 4.1 브리지·디스패처 (단일 진입점)
`buildMonitorVerdict(itemCode, challenge, apiBaseUrl, Promise)` 가 유일한 `@ReactMethod`. itemCode별:

| itemCode | 네이티브 | 앱레이어(Java) | 결과 필드 |
|---|---|---|---|
| F34 루트 | `keyAttestationChain`(TEE) | `appLayerDetectsRoot` | `attestationChain`, `appLayerDetectedRoot` |
| F35 Frida | `nativeSignedReport("F35")` | `appLayerDetectsFrida` | `nativeReport`, `appLayerDetectedFrida` |
| F36 디버거 | `nativeSignedReport("F36")` | `appLayerDetectsDebugger` | `nativeReport`, `appLayerDetectedDebugger` |
| F37 피닝 | `nativeSignedReportPinning` | `observedSpki`(TrustAll+SPKI) | `nativeReport` |
| F38 변조 | `nativeSignedReport("F38")` | `appLayerDetectsTamper` | `nativeReport`, `appLayerDetectedTamper` |

### 4.2 네이티브 탐지 로직 (so 없으면 Java fallback이 동일 수행)
- **루트**: `stat()` su/Magisk 경로 + `ro.build.tags`=`test-keys`.
- **Frida**: `/proc/self/maps`·`/proc/self/task/*/comm` 문자열 매칭 + TCP 27042/27043.
- **디버거**: `/proc/self/status` `TracerPid:` > 0.
- **변조(F38)**: APK Signing Block(v2 `0x7109871a`) 인증서 SHA-256 vs `OFFICIAL_CERT_SHA256`.
- **피닝(F37)**: 직접 TLS ClientHello → 서버 leaf 인증서 DER SHA-256 vs `PINNED_SPKI`. 프록시 시 지문 변화로 탐지.

### 4.3 서명 리포트
`payload = "code|nonce|flag|evidence"` → `HMAC-SHA256` → 반환 `base64(payload).hmac_hex`.
서버는 nonce 일치·HMAC 유효·evidence 비었음을 보고 "안전" 판정.

---

## 5. 취약점 상세 — 하드코딩 HMAC 대칭키 (High)

### 설명
`hmac_sha256`(0x103924)의 키가 `.so` `.rodata` 에 ipad(0x36)/opad(0x5c) 사전 XOR 형태로 저장돼 있다.
XOR 역산으로 **평문 키 복원**: `SCN00-monitor-hmac-key-v1-eqstlb` (두 경로 교차검증 일치).

### 재현 (PoC)
```js
// 1) 키 추출
const b = require('fs').readFileSync('scn00/lib/arm64-v8a/libscn00monitor.so');
const key = Buffer.alloc(32);
for (let i=0;i<16;i++){ key[i]=b[0xe20+i]^0x36; key[16+i]=b[0xdc0+i]^0x36; }
// key = "SCN00-monitor-hmac-key-v1-eqstlb"

// 2) 서버 발급 nonce에 대해 "clean" 리포트 위조 (예: F35 Frida 흔적 없음)
const crypto = require('crypto');
const payload = `F35|${serverNonce}|0|`;          // flag '0' = 증거 없음
const sig = crypto.createHmac('sha256', key).update(payload).digest('hex');
const forged = Buffer.from(payload).toString('base64') + '.' + sig;
// → POST /scenario00/monitor/claim { nativeReport: forged }
```

### 영향
- nonce 1회용이라 단순 리플레이는 막히나, 키가 공개된 이상 **매 nonce마다 유효 서명 생성** 가능.
- 루팅/Frida/디버거/프록시가 켜진 상태에서도 F34~F38 "안전" 통과 → **RASP 전면 무력화**.
- F37 인증서 지문 필드까지 위조 가능해 Burp MITM 탐지도 우회.

### 대응 방안
1. **대칭 HMAC → 서버 검증 가능한 비대칭 서명/원격 증명으로 전환.** 클라이언트에 검증 비밀을 두지 말 것.
   - Android **Play Integrity API** 또는 하드웨어 **Key Attestation**(F34에 이미 존재, TEE 서명)을 1차 신뢰근거로.
2. 불가피하게 클라이언트 서명을 유지한다면 키를 **StrongBox/TEE·Android Keystore** 에 보관(평문 .rodata 금지),
   화이트박스 암호 또는 키 증명 바인딩 적용.
3. 서명 payload에 **기기바운드 값**(attestation 공개키, 인증 세션)·짧은 TTL nonce를 포함해 재사용·전이 차단.
4. 서버는 `nativeReport`(HMAC)와 `attestationChain`(TEE)을 **교차 검증**하고, HMAC 단독 통과를 신뢰하지 않도록.
5. `.so` 에 문자열 암호화·안티탬퍼·무결성 self-check 추가(심층방어. 근본 해결은 1번).

---

## 6. 상대적으로 견고한 부분 — F34 하드웨어 Key Attestation
F34는 네이티브 HMAC 외에 **AndroidKeyStore EC 키 + `setAttestationChallenge(서버challenge)`** 로
하드웨어 attestation 인증서 체인을 Java에서 수집한다(`keyAttestationChain`). 이 체인은 **TEE/StrongBox 개인키로
서명**돼 클라이언트가 위조 불가. 따라서 서버가 F34에서 HMAC 대신 **attestationChain 검증을 신뢰근거로** 쓰면
해당 항목은 §5 결함의 영향을 받지 않는다. 다른 항목(F35~F38)도 이 방식으로 재설계하는 것이 권고안의 핵심.

---

## 7. 데이터 흐름 & 전송 시점 (요약)
```
GET /scenario00/monitor/nonce?itemCode=F3x   → nonce 발급
buildMonitorVerdict(F3x, nonce, apiBaseUrl)   → base64(pld).hmac 서명 생성 (Promise resolve)
POST /scenario00/monitor/claim { verdict }    → 서버 HMAC·nonce 검증 → 문제 정답 처리
```
네이티브/Java는 claim을 직접 호출하지 않고 **서명 문자열만 JS에 반환**, 전송은 JS 뮤테이션이 수행.

---

## 8. 후속 동적 검증 (Frida 단계 제안)
1. **오프라인 위조 경로**: §5 PoC로 키 추출 → nonce 받아 서명 → claim 재전송(서버측 우회 성립 여부 확인).
2. **런타임 후킹 경로**: `buildMonitorVerdict` Promise 결과 또는 네이티브 반환 jstring을 Frida로 치환
   (`Interceptor.attach` on `Java_..._nativeSignedReport` onLeave).
3. Burp(`_work/burp`)로 `/scenario00/monitor/nonce`·`/claim` 요청/응답 캡처해 서버 검증 로직 역추적.

---

## 부록 A — 지표(IOC)·상수
| 항목 | 값 |
|---|---|
| HMAC 키 | `SCN00-monitor-hmac-key-v1-eqstlb` (hex `53434e…746c62`) |
| 피닝 호스트 | `lab.eqst.co.kr:8406` |
| 피닝 SPKI | `2c5c658422c0d205eff9329d9ee2b2c1a4fb4c73bd2ae8af15e16c4e2f1aa77f` |
| 공식 서명 SHA-256 | `fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c` |
| Frida 포트 | 27042, 27043 |
| APK Sig v2/v3 ID | `0x7109871a` / `0xf05368c0` |

## 부록 B — 함수 주소 맵 (libscn00monitor.so)
`nativeFridaEvidence` 0x1025f0 · `nativeDebuggerEvidence` 0x102bbc · `nativeRootEvidence` 0x102d3c ·
`nativeSignedReport` 0x1031cc · `nativeSignedReportPinning` 0x103a1c · `hmac_sha256` 0x103924 ·
`detect_frida_evidence` 0x102640 · `detect_debugger_evidence` 0x102c0c · `detect_root_evidence` 0x102d8c
