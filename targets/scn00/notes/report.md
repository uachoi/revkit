# scn00 종합 분석 보고서 — RASP 모듈 + MASVS 8-카테고리 2-pass

> **앱**: EQST FinTech App Hacking 워게임 / scn00
> **패키지**: `kr.co.eqst.pay.s00.localapi` · **버전**: `1.0-local-api` (versionCode 1) · **minSdk 24 / target 36**
> **아키텍처**: React Native + Hermes (JS 로직은 `assets/index.android.bundle`)
> **타깃 `.so`**: `libscn00monitor.so` (arm64-v8a, 18,240 B, 함수 115개) — 유일 보안 `.so`
> **분석일**: 2026-11-09 착수 → 2026-11-13 네이티브/2차 → **2026-11-18 MASVS 8-카테고리 패스**
> **범위**: 인가된 모의해킹. 사내망 로컬 전용.
> **근거 문서**: [`triage.md`](./triage.md) · [`java_analysis.md`](./java_analysis.md) (§1~§12) · [`native/libscn00monitor.so.md`](./native/libscn00monitor.so.md) · [`verify.md`](./verify.md) (2차 재분류)

---

## 1. 요약 (Executive Summary)

scn00은 M형 문제 **F34(루트)·F35(Frida)·F36(디버거)·F37(인증서피닝)·F38(앱변조)** 를 담당하는
**클라이언트 측 RASP(기기 무결성 증명)** 모듈이 핵심이다. JS가 서버에서 1회용 nonce를 받아 네이티브로 넘기면,
`libscn00monitor.so`가 탐지 증거를 수집·**HMAC-SHA256 서명**해 `base64(payload).hmac_hex`로 반환하고, JS가
`POST /scenario00/monitor/claim`으로 서버 검증을 받는다.

**핵심 위험 (정적 확정 1건)**: RASP 리포트의 신뢰근거가 **클라이언트에 하드코딩된 대칭 HMAC 키 1개**(`SCN00-monitor-hmac-key-v1-eqstlb`)뿐이다. `.so` `.rodata`에서 2경로 교차검증으로 복원됨 → 추출 시 "탐지 흔적 없음(clean)" 리포트를 **임의 위조**해 F34~F38 전면 우회 가능. 전형적 *client-side RASP + symmetric secret* 결함.

**방어가 적절한 부분**: 자격증명은 `react-native-keychain`(하드웨어+생체) = AndroidKeyStore 경로 사용, 백업은 `allowBackup=false` + 전면 exclude, 인증서 피닝은 네이티브까지 이중 구현. 노출 컴포넌트는 최소.

**MASVS 8-카테고리 2차 검증 태세** (정적 2-pass 상한):

| 판정 | 수 | 대표 |
|---|---|---|
| **확정** | 1 | STO-HARDCODE-01 = CRY-HARDKEY-01 (하드코딩 HMAC 키, 정적 증명) |
| **가설** | 다수 | RES-ROOT/DBG/HOOK/INTEG·EMU, NET-PIN/CLEAR/TLS/MITM, PLT-DEEPLINK/WEBVIEW-03/SCREENSHOT/CLIP, STO-PLAIN/KEY/EXT/LOG — 승급은 전부 **동적(Frida/덤프/`am start`) 단계** 몫 |
| **기각(방어적절/오탐)** | 3+ | NET-TRUST-01(피닝 probe 오탐), STO-BACKUP-01(백업 차단), PLT-INTENT-01(노출 최소) |

> ⚠️ **단정 금지 원칙**: scn00은 **난독화가 없고**(평문 문자열) Hermes 바이트코드라 문자열·API는 복원되나 **값/분기/데이터 흐름은 정적 미확정**이다. 하드코딩 HMAC 키 외 모든 항목은 승급 조건이 동적 재현을 요구하므로 **가설**로 유지한다. "확정 0"이 아니라 "정적 확정 1 + 동적 대기 다수"가 정확한 상태.

---

## 2. 타깃 선정 근거 (triage)

- `System.loadLibrary` / `native` 선언 전수 스캔 결과, 보안 로직 `.so`는 **`libscn00monitor.so` 단 1개**. 로드 지점도 앱 전체에서 **1곳**(classes3.dex / `Scn00MonitorModule` companion init).
- 그 외 `.so`(libreactnative/hermes/rn*)는 RN/Hermes 런타임 → **skip**(보안 로직 아님).
- `libscn00monitor.so`의 유일 소비자 = `Scn00MonitorModule`. 주변 보안 클래스(`BiometricKeyModule`·`PinKdfModule`·`OAuthAuthSessionModule`)는 이 `.so`를 쓰지 않는 별도 레이어.
- **ABI**: arm64-v8a만 분석(타 ABI는 동일 로직 중복 컴파일).

---

## 3. Java 분석 (RN 브리지 · 서버 I/O · 하드코딩 상수)

**단일 진입점**: `@ReactMethod buildMonitorVerdict(itemCode, challenge, apiBaseUrl, Promise)` (`Scn00MonitorModule.java:108`) → JS `NativeModules.Scn00Monitor`.

**흐름**:
```
GET  {apiBaseUrl}/scenario00/monitor/nonce?itemCode=F3x   → 1회용 nonce 발급
     buildMonitorVerdict("F3x", nonce, apiBaseUrl)        → native가 base64(payload).hmac_hex 서명 리포트 생성
POST {apiBaseUrl}/scenario00/monitor/claim               → verdict 업로드, 서버가 HMAC·nonce 검증
```
- itemCode 분기(F34~F38)마다 네이티브 호출 + 순수 Java fallback(`appLayerDetects*`) 병행. 네이티브 탐지 = Java fallback과 **거의 1:1 동일**, 차이는 HMAC 서명 추가.
- apiBaseUrl 유력값 = **`https://lab.eqst.co.kr:8406`**(피닝 호스트와 동일 오리진).

**하드코딩 상수** (`Scn00MonitorModule.java:65-74`):

| 상수 | 값 | 성격 |
|---|---|---|
| `OFFICIAL_CERT_SHA256` | `fac61745…033b9c` | 정식 서명 해시(비교상수, F38) |
| `PINNED_HOST`/`PORT` | `lab.eqst.co.kr` / `8406` | 공개 식별자(무해) |
| `PINNED_SPKI` | `2c5c6584…1aa77f` | 피닝 공개키 SHA-256(공개 지문, 무해) |

> 이 세 상수는 공개 가능 식별자/비교값이라 그 자체로는 약점이 아니나, 아래 HMAC 키와 합쳐지면 **clean 리포트 위조의 토대**(verify.md 신뢰도 보정 메모).

---

## 4. 네이티브 분석 (`libscn00monitor.so`) + 우회 포인트

**아키텍처(우회 전략 결정)**: 이 모듈은 **"증거 수집 → 서명 리포트 생성" 전용**이며 **로컬 차단 분기(`if detected finish()`)가 없다**. 판정·차단은 서버 몫. → 바이너리 분기 패치가 아니라 **① collector 반환 무력화** 또는 **② 리포트 교체/위조**가 우회 경로. 리포트가 서명돼 있어 MITM 변조로는 불가 → **서명 키가 관건**.

| criterion | 발견 | 2차 판정 | 우회 포인트 |
|---|---|---|---|
| **RES-ROOT-02** | `detect_root_evidence` 0x102d8c — su/magisk/test-keys `stat` | 가설 | collector 반환 빈 문자열 후킹 / `stat` ENOENT |
| **RES-DBG-02** | `detect_debugger_evidence` 0x102c0c — `/proc/self/status` TracerPid (어셈 교차대조 ✓) | 가설 | `TracerPid: 0` 위장 |
| **RES-HOOK-01** | `detect_frida_evidence` 0x102640 — maps/thread/포트27042·3 **3층** | 가설 | **3경로 모두** 음성화 필요(한 곳만 막으면 FN) |
| **RES-INTEG-01/02** | `nativeSignedReport` F38 — APK Signing Block SHA-256, 비교상수=Java `OFFICIAL_CERT_SHA256` | 가설(정적강함) | 재패키징 1순위 장애물, 정품 해시 위장 필요 |
| **NET-PIN-02** | `nativeSignedReportPinning` 0x103a1c — 직접 TLS ClientHello로 leaf 인증서 SHA-256, `F37|nonce|cert_fp|` | 가설 | **네이티브 피닝** → Java SSLContext 후킹 불가, 네이티브 지점 후킹/패치 |

**★ 치명 결함 — 하드코딩 HMAC 키 (확정)**: `hmac_sha256` 0x103924. key⊕ipad(0x36)·key⊕opad(0x5c) 블록이 `.rodata`에 사전 XOR 저장 → 두 경로 XOR 역산 **일치**로 복원: **`SCN00-monitor-hmac-key-v1-eqstlb`**. `payload = "code|nonce|flag|evidence"`, 반환 = `base64(payload).hmac_hex`. 키 공개 → 매 nonce마다 유효 서명 생성 가능.

---

## 5. NETWORK · PLATFORM · STORAGE 패스 (2026-11-18, manifest + RN 번들)

> `jadx --no-res`로 manifest+리소스+Hermes 번들 디코드(출력은 스크래치패드, gitignore 경계 유지). Hermes라 값/분기 미확정분은 가설.

**NETWORK** (§10): `usesCleartextTraffic="true"` + NSC 부재 = 전역 평문 **허용**(config 정적확정)이나 실 엔드포인트 전부 HTTPS·평문 미관측 → NET-CLEAR-01 가설. NET-TLS-01(포트 8406 HTTPS, 다운그레이드 신호 없음)·NET-MITM-01(프록시 탐지 미발견, 피닝으로 대체) 가설. NET-TRUST-01은 피닝 지문 관측 probe 오탐 → **기각**.

**PLATFORM** (§11):
- **PLT-DEEPLINK-01 (가설, ★최고위험)**: 딥링크 3표면. `kr.co.eqst.pay.s00://mydata/callback` = 마이데이터 OAuth 콜백을 **커스텀 스킴**으로 수신 + **PKCE 흔적 없음** → 악성 앱 스킴 선점으로 **인가코드 가로채기** 위험. `eqstpay://moim/invite?invitationCode=` 파라미터 흐름. App Link `app.eqstpay.local`은 `.local`(비공개 TLD)이라 autoVerify 검증 불가(테스트 구성 추정).
- **PLT-SCREENSHOT-01 (가설, 강함)**: `FLAG_SECURE`·스크린샷 방지 신호 **전무** → 금융/마이데이터 민감 화면 캡처 보호 부재. 재현 쉬워 **확정 승급 유력**.
- **PLT-WEBVIEW-03 (가설)**: `mydata-provider-webview`가 외부 제공자 인가 페이지 로드 + `injectedJavaScript`/`onMessage` 브리지. 설정값은 Hermes라 미확정(01/02 보류).
- **PLT-INTENT-01 (기각)**: exported=true는 MainActivity(RN 단일)·ProfileInstallReceiver(`permission=DUMP` 서명보호)뿐, 무방비 노출 없음.

**STORAGE** (§12):
- **STO-HARDCODE-01 (확정)**: 네이티브 HMAC 키 = CRY-HARDKEY-01 이중태깅(§4). 유일 정적 확정.
- **STO-KEY-01 (가설, 방어적절 ✓)**: `react-native-keychain`(accessControl+SECURE_HARDWARE+BIOMETRY) = AndroidKeyStore 하드웨어 경로 = 긍정.
- **STO-PLAIN-01 (가설)**: `AsyncStorage`(미암호화) 공존. refreshToken/accessToken/transactionPin 리터럴 존재하나 Keychain 경로도 있어 유입 여부 정적 미확정 → 앱 샌드박스 덤프 필요.
- **STO-EXT-01 (가설, 약)**: 외부저장 쓰기 API 미검출. 단 `file_provider_paths.xml` `external-path path="."` = 범위 과다(구성 점검).
- **STO-LOG-01 (저위험)**: `console.error`+`__DEV__`뿐, BODY 로깅/Flipper 없음. **STO-BACKUP-01 (기각)**: allowBackup=false + 전면 exclude.
- 오탐 함정 작동: `pan`=Timespan/PanGesture 노이즈·`ssn`=substring → 불채택.

---

## 6. 다음 단계 (모의해킹 — 동적 PoC)

> CLAUDE.md상 Frida 실행은 수동/후속 phase. 아래는 가설 → 확정 승급 경로.

1. **RASP 전면 우회 (최우선, 확정 결함 활용)**: 추출 키 `SCN00-monitor-hmac-key-v1-eqstlb`로 오프라인 서명 생성 — `payload="F3x|<서버발급nonce>|0|"` → HMAC-SHA256 → `base64(payload).hex` → `POST /scenario00/monitor/claim` 재전송. 루팅/Frida/디버거 환경에서도 F34~F38 clean 통과 재현. (대안: Frida로 `buildMonitorVerdict` 결과 또는 native 반환 문자열 치환 — 스크립트는 `targets/scn00/frida/`.)
2. **네이티브 피닝 우회 (F37/트래픽)**: Java SSLContext 후킹으론 안 풀림 → `nativeSignedReportPinning` 또는 피닝 비교 지점 네이티브 후킹. Burp 중계 1차 장애물.
3. **PLT-SCREENSHOT 캡처 재현**: 민감 화면(결제·마이데이터·PIN)에서 스크린샷/최근앱 썸네일/화면녹화 캡처 성공 → PLT-SCREENSHOT-01 확정 승급.
4. **mydata 콜백 주입**: `adb shell am start -d "kr.co.eqst.pay.s00://mydata/callback?..."` 로 인가코드 가로채기 흐름·PKCE/state 바인딩 실측 → PLT-DEEPLINK-01 승급.
5. **STORAGE 덤프**: 설치 후 `/data/data/kr.co.eqst.pay.s00.localapi/`의 `databases/RKStorage`·`shared_prefs/`·`files/` 덤프 → AsyncStorage 토큰/PIN 평문 여부(STO-PLAIN 승급/기각), Keychain 하드웨어 강제(StrongBox/TEE) 확인(STO-KEY).
6. **재패키징(F38)**: 서버가 서명 해시를 실제 검증하면 로컬 패치만으론 거부 → 1의 키 위조와 병행 필요.

> 비즈니스 로직 우회(F28 송금 인증 우회 등 `SCN00.F28.TXN_AUTH_NOT_VERIFIED`)는 **서버 측·MASVS 밖 별도 트랙** — `biz-logic-security-review` 스킬 소관. 본 리포트(클라 기기무결성)와 별개 레이어.

---

## 7. 대응방안 (방어 권고)

1. **RASP 신뢰근거를 비대칭 전환 (최우선)**: 대칭 HMAC 키 하드코딩 폐기 → 서버 챌린지에 **비대칭 서명**(기기 키는 AndroidKeyStore·하드웨어 attestation 사슬) 또는 Play Integrity/서버 발급 임시키. 현재 구조는 키 1개 추출로 전면 무력화.
2. **민감 화면 `FLAG_SECURE`**(또는 RN 스크린샷 방지 모듈) 적용 — 결제·마이데이터·PIN·OTP 화면.
3. **mydata OAuth를 공개 도메인 App Link + PKCE로**: 커스텀 스킴 콜백 제거(또는 PKCE+state 강제), App Link 호스트를 실제 공개 도메인 + `/.well-known/assetlinks.json`으로 autoVerify.
4. **딥링크 파라미터 검증**: `invitationCode` 등 외부 입력을 인증/민감 동작 전 서버 측 검증.
5. **FileProvider 범위 최소화**: `file_provider_paths.xml`의 `external-path path="."`를 실제 공유 대상 하위 경로로 축소.
6. **WebView 하드닝**: `mydata-provider-webview`의 `originWhitelist`·`javaScriptEnabled`·file-access 플래그 최소화, `onMessage` 브리지 입력 검증.
7. **AsyncStorage 민감값 금지**: 토큰/PIN은 전부 Keychain 경로로(현재 일부 긍정) — AsyncStorage엔 비민감 상태만.
8. **유지(양호)**: `allowBackup=false` + 백업 전면 exclude, 네이티브 피닝, Keychain 하드웨어+생체, target SDK 36.

---

## 부록 — 함수 주소 맵 (`libscn00monitor.so`)

`nativeFridaEvidence` 0x1025f0 · `nativeDebuggerEvidence` 0x102bbc · `nativeRootEvidence` 0x102d3c · `nativeSignedReport` 0x1031cc · `nativeSignedReportPinning` 0x103a1c · `hmac_sha256` 0x103924 · `detect_frida_evidence` 0x102640 · `detect_debugger_evidence` 0x102c0c · `detect_root_evidence` 0x102d8c
