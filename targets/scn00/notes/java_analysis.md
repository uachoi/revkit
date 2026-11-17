# Scn00MonitorModule — Java(RN 브리지) ↔ 네이티브 탐지 전체 분석

> 생성: 2026-11-09 · 대상: EQST FinTech App Hacking 워게임 / scn00
> 앱: React Native + Hermes · 패키지 `kr.co.eqst.pay.s00`
> 분석 산출물: jadx `_work/jadx-out` (classes.dex/2/3, 10,787 java) + Ghidra MCP(`libscn00monitor.so`, 115 func)
> 핵심 소스: `_work/jadx-out/sources/kr/co/eqst/pay/s00/Scn00MonitorModule.java` (classes3.dex)

---

## 0. 한 줄 요약

`Scn00MonitorModule` 은 **RASP(기기 무결성) 전용 RN 네이티브 모듈**이다. JS가 서버에서 nonce를 받아
`buildMonitorVerdict(itemCode, challenge, apiBaseUrl)` 한 메서드를 호출하면, 네이티브
`libscn00monitor.so` 가 루트/Frida/디버거/서명무결성/인증서피닝 증거를 수집·**HMAC-SHA256 서명**해
`base64(payload).hmac_hex` 문자열로 반환한다. JS는 이 결과를 **`POST {apiBaseUrl}/scenario00/monitor/claim`**
으로 서버에 올려 검증받는다. **서명 키가 .so 안에 하드코딩된 대칭키**라 추출 시 임의 리포트 위조가 가능하다(§6).

---

## 1. 브리지(JS↔네이티브) 연결 지점

| 레이어 | 요소 | 근거 |
|---|---|---|
| RN Package 등록 | `Scn00MonitorPackage.createNativeModules()` 가 `Scn00MonitorModule` 1개 반환 | `Scn00MonitorPackage.java`. `MainApplication` 의 `getPackages()` 에 등록(RN 표준) |
| JS 모듈 이름 | `getName()` → **`"Scn00Monitor"`** → JS에서 `NativeModules.Scn00Monitor` 로 접근 | `Scn00MonitorModule.java:104` |
| JS→Java 진입점(유일) | `@ReactMethod buildMonitorVerdict(itemCode, challenge, apiBaseUrl, Promise)` | `Scn00MonitorModule.java:108`. 그 외 메서드는 전부 `private` |
| JS 호출 토큰 | Hermes 번들에 `"Scn00Monitor"`, `"buildMonitorVerdict"`, `"monitorVerdict"` 문자열 존재 | `scn00/assets/index.android.bundle` 문자열 추출 |
| Java→Native | static init `System.loadLibrary("scn00monitor")` → `libscn00monitor.so`, 5개 `native` 선언 | `Scn00MonitorModule.java:589-597`, `:81-89` |
| Native→JNI export | `Java_kr_co_eqst_pay_s00_Scn00MonitorModule_native*` 5종 export | Ghidra `list_exports` |

> 결과 맵 키(`nativeReport`,`attestationChain`,`appLayerDetected*`)는 **번들에 문자열로 없음** →
> JS는 개별 필드를 destructure 하지 않고 **verdict 객체 전체를 claim 바디로 전달**하는 것으로 보인다.

---

## 2. `buildMonitorVerdict` 디스패처 (itemCode = M형 문제 F34~F38)

`Scn00MonitorModule.java:108-192`. itemCode 해시 스위치로 분기, 결과를 `Promise.resolve(map)` 로 **JS에 반환**(이 메서드 자체는 서버 전송 안 함):

| itemCode | 네이티브 호출 | 앱레이어(순수 Java) 병행 | resolve 맵 필드 |
|---|---|---|---|
| **F34** 루트 | `keyAttestationChain(challenge)` (하드웨어 키 attestation, native 아님) | `appLayerDetectsRoot()` | `attestationChain`(Base64 체인), `appLayerDetectedRoot` |
| **F35** Frida | `nativeSignedReport("F35", challenge)` | `appLayerDetectsFrida()` | `nativeReport`, `appLayerDetectedFrida` |
| **F36** 디버거 | `nativeSignedReport("F36", challenge)` | `appLayerDetectsDebugger()` | `nativeReport`, `appLayerDetectedDebugger` |
| **F37** 피닝/MITM | `nativeSignedReportPinning(challenge, http.proxyHost, http.proxyPort)` | `observedSpki(apiBaseUrl)` (TrustAll로 직접 TLS, SPKI 비교) | `nativeReport` (observedSpki≠null일 때만) |
| **F38** 변조 | `nativeSignedReport("F38", challenge)` | `appLayerDetectsTamper()` (서명 SHA-256 ≠ 공식값) | `nativeReport`, `appLayerDetectedTamper` |

- `nativeAvailable == false`(so 로드 실패) 시 `nativeDetects*()` 가 **순수 Java fallback**으로 동작(§5).
- F37은 `System.getProperty("http.proxyHost"/"Port")` 로 프록시 설정을 읽어 네이티브에 넘김.

---

## 3. 서버 엔드포인트 & "언제 전송되는가" (nonce → verdict → claim)

Hermes 번들의 REST 경로/React-Query 훅 이름으로 재구성한 M형 문제 흐름:

```
[JS]  GET  {apiBaseUrl}/scenario00/monitor/nonce?itemCode=F3x     (훅: scenario00MonitorNonce)
          └→ 서버가 1회용 nonce(=challenge) 발급
[JS]  NativeModules.Scn00Monitor.buildMonitorVerdict("F3x", nonce, apiBaseUrl)
          └→ 네이티브가 "base64(payload).hmac_hex" 서명 리포트 생성 → Promise로 JS 반환
[JS]  POST {apiBaseUrl}/scenario00/monitor/claim                  (훅: scenario00MonitorClaims)
          └→ verdict(nativeReport 등)를 바디로 전송 → 서버가 HMAC·nonce 검증 후 문제 정답 처리
```

- **`nativeSignedReport` 결과의 전송처 = `POST /scenario00/monitor/claim`**, 전송 시점 = buildMonitorVerdict
  Promise resolve 직후 JS가 claim 뮤테이션 실행할 때. (Java/네이티브는 claim을 직접 호출하지 않음)
- 번들 확인 경로: `/scenario00/monitor/nonce?itemCode=`, `/scenario00/monitor/claim`,
  `/scenario00/items/F39/keypad`, `/scenario00/transfer-preview`, `/scenario00/auth/approval-challenge`,
  `/scenario00/auth/approval` 등.
- 피닝 호스트(아래)와 동일 오리진 추정: **`https://lab.eqst.co.kr:8406`** (apiBaseUrl 유력값).
- 예외: **F37 피닝 리포트**는 네이티브가 `lab.eqst.co.kr:8406` 로 **직접 TLS 접속**해 서버 인증서 지문을
  수집(§7). 생성된 서명 문자열 자체는 역시 JS→claim 경로로 업로드된다.

---

## 4. 네이티브 핵심 상수 / 피닝 값 (Java 측, `Scn00MonitorModule.java:65-74`)

| 상수 | 값 |
|---|---|
| `OFFICIAL_CERT_SHA256` (정식 서명) | `fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c` |
| `PINNED_HOST` / `PINNED_PORT` | `lab.eqst.co.kr` / `8406` |
| `PINNED_SPKI` (피닝 공개키 SHA-256) | `2c5c658422c0d205eff9329d9ee2b2c1a4fb4c73bd2ae8af15e16c4e2f1aa77f` |

---

## 5. 네이티브 탐지 함수 ↔ Java 호출 흐름 연결표 (Ghidra)

`.so` export JNI 래퍼는 모두 **helper로 1024B 버퍼를 채우고, 비면 null·아니면 `NewStringUTF`(vtable 0x538)** 반환.

| JNI export (addr) | 내부 helper (addr) | 동작 | 대응 Java fallback (so 없을 때) |
|---|---|---|---|
| `nativeRootEvidence` (0x102d3c) | `detect_root_evidence` (0x102d8c) | `stat()` su 경로(`/system/bin/su`,`/system/xbin/su`,`/sbin/su`,`/su/bin/su`), Magisk(`/data/adb/magisk`,`/data/adb/modules`,`/sbin/.magisk`), `__system_property_get("ro.build.tags")` 에 `test-keys` → `su:/… ; magisk:/… ; prop:test-keys` | `appLayerDetectsRoot()`: ROOT_PATHS·ROOT_MANAGER_PACKAGES·`which su`·`getprop`·mountinfo (`:238`) |
| `nativeFridaEvidence` (0x1025f0) | `detect_frida_evidence` (0x102640) | ①`/proc/self/maps` 에 `frida/gum-js/gadget/frida-agent/linjector`→`maps:<kw>` ②`/proc/self/task/*/comm` 에 `gum-js-loop/gmain/gdbus/pool-frida/pool-spawner`→`thread:<kw>` ③`127.0.0.1:27042`,`:27043` connect→`port:2704x` | `nativeDetectsFrida()`/`appLayerDetectsFrida()`: 동일 maps·thread·포트(`:419`,`:423`) |
| `nativeDebuggerEvidence` (0x102bbc) | `detect_debugger_evidence` (0x102c0c) | `/proc/self/status` 의 `TracerPid:` > 0 → `tracerpid:<pid>` | `nativeDetectsDebugger()`/`appLayerDetectsDebugger()`: `tracerPid()`·`Debug.isDebuggerConnected/waitingForDebugger`(`:427`,`:431`) |
| `nativeSignedReport` (0x1031cc) | ↓ §6 디스패처 | F34→root / F35→frida / F36→debugger / F38→APK서명 SHA-256 | — (서명은 네이티브 전용) |
| `nativeSignedReportPinning`(0x103a1c) | ↓ §7 | F37 TLS 인증서 지문 | `observedSpki()` (Java, TrustAll+SPKI 비교, `:435`) |

> 네이티브 탐지 로직은 Java fallback과 **거의 1:1 동일**. 차이는 (a) 네이티브가 결과를 HMAC 서명한다는 점,
> (b) F38 APK 서명검증·F37 TLS 지문은 네이티브가 더 정교하게 raw 파싱한다는 점.

---

## 6. 서명 리포트 포맷 & HMAC 키 (★ 핵심 취약 포인트)

### `nativeSignedReport(code, nonce)` 디스패처 (0x1031cc)
1. `GetStringUTFChars` 로 code/nonce 추출.
2. code 분기로 증거 버퍼(`evidence`) 생성:
   - `F34`→`detect_root_evidence`, `F35`→`detect_frida_evidence`, `F36`→`detect_debugger_evidence`
   - `F38`→ `/proc/self/maps` 에서 `/data/app/...base.apk` 경로를 찾아 열고, ZIP **EOCD(PK\x05\x06)**→
     **APK Signing Block("APK Sig Block 42")** 파싱 → v2 블록 ID **`0x7109871a`**(/v3 `0xf05368c0`) 내
     서명 인증서 바이트의 **SHA-256 hex** 지문 계산.
3. 페이로드 조립: **`payload = "code|nonce|flag|evidence"`** (`flag` = 증거 유무 `'0'`/`'1'`).
4. **`hmac_sha256(payload)`** 서명.
5. 반환 문자열: **`base64(payload) + "." + hex(hmac)`** (`snprintf("%s.%s", ...)`).

### HMAC 키 — 하드코딩 대칭키 (Ghidra `hmac_sha256` 0x103924 + .rodata 추출)
- 구조: 표준 HMAC-SHA256. key⊕ipad(0x36)·key⊕opad(0x5c) 블록이 `.rodata` 에 **사전 XOR 저장**.
  - ipad 복사본 vaddr `0x100e20`(16B)+`0x100dc0`(16B), opad 복사본 `0x100e30`+`0x100de0`.
  - key = (ipad블록 ⊕ 0x36) = (opad블록 ⊕ 0x5c) — **두 경로 교차검증 일치**.
- **복원된 키(32바이트 ASCII): `SCN00-monitor-hmac-key-v1-eqstlb`**
  - hex: `53434e30302d6d6f6e69746f722d686d61632d6b65792d76312d657173746c62`

### 보안 시사점
- RASP 리포트의 신뢰근거가 **클라이언트에 박힌 대칭키 1개**뿐. `.so` 추출 후 위 키로
  `payload="F3x|<서버발급nonce>|0|"` 를 직접 HMAC 서명하면 **"탐지 흔적 없음(clean)" 리포트를 임의 위조** 가능.
- nonce가 1회용이라 단순 리플레이는 막지만, 키가 공개된 이상 **매 nonce마다 유효 서명 생성 → 루팅/Frida/
  디버거/프록시 환경에서도 F34~F38 전부 우회**. (전형적 "client-side RASP + symmetric secret" 결함)

---

## 7. `nativeSignedReportPinning` = F37 인증서 피닝/MITM 탐지 (0x103a1c)

- 인자: `(nonce, proxyHost, proxyPort)`. host/port 미지정 시 기본 **`lab.eqst.co.kr:0x20d6(8406)`**.
- 흐름: `getaddrinfo`→`socket`→`setsockopt(SO_SNDTIMEO/RCVTIMEO)`→`connect`.
  proxyHost 지정 시 **HTTP `CONNECT lab.eqst.co.kr:8406` 터널** 후 `" 200"` 확인.
- **직접 조립한 TLS ClientHello(0x7b바이트, record type 0x16)** 전송 → 핸드셰이크 레코드 수신 →
  `Certificate`(0x0b) 메시지 내 leaf 인증서 **ASN.1 DER(SEQUENCE 0x30)을 수동 파싱** → 인증서 바이트
  **SHA-256 hex** 지문 산출.
- 리포트: `payload="F37|nonce|cert_fp_hex|"` → `hmac_sha256` → `base64(payload).hex` 반환.
- 의미: Burp 등 **중간자/프록시가 끼면 leaf 인증서 지문이 달라져 서버가 탐지**. 단, §6 키로 지문 필드까지
  포함해 위조 가능하므로 서버측 지문 화이트리스트만으로는 방어 한계.

---

## 8. 결론 / 우회 포인트 요약

1. **단일 진입점**: `NativeModules.Scn00Monitor.buildMonitorVerdict` 1개가 F34~F38 전부 처리.
2. **전송**: JS가 `GET /scenario00/monitor/nonce` → buildMonitorVerdict → `POST /scenario00/monitor/claim`.
   네이티브/Java는 claim을 직접 치지 않고 서명 문자열만 만들어 JS에 넘긴다.
3. **네이티브 탐지 = Java fallback과 동일 로직**에 HMAC 서명만 추가.
4. **치명 결함**: HMAC 대칭키(`SCN00-monitor-hmac-key-v1-eqstlb`) 하드코딩 → 리포트 위조로 RASP 전면 우회.
5. 후속(동적): Frida로 `buildMonitorVerdict` 결과(또는 native 반환 문자열) 후킹/치환, 혹은 추출 키로
   오프라인 서명 생성 → claim 재전송. `/scenario00/monitor/claim` 요청/응답은 Burp(`_work/burp`)로 확보 권장.

---

### 참고 — 함수 주소 맵 (libscn00monitor.so)
`nativeFridaEvidence` 0x1025f0 · `nativeDebuggerEvidence` 0x102bbc · `nativeRootEvidence` 0x102d3c ·
`nativeSignedReport` 0x1031cc · `nativeSignedReportPinning` 0x103a1c · `hmac_sha256` 0x103924 ·
`detect_frida_evidence` 0x102640 · `detect_debugger_evidence` 0x102c0c · `detect_root_evidence` 0x102d8c

---

## 9. 정식 criterion 태깅 (Java 레이어 — 2-pass 입력)

> `/rev-jadx scn00` 재태깅(2026-11-13). 개선점 #1대로 **재디컴파일 없이** 기존 분석에 criterion ID 메타블록을 얹음.
> 출처: `jadx-out/sources/kr/co/eqst/pay/s00/Scn00MonitorModule.java` (실소스 라인 근거).
> 구조 주의: Java 탐지는 네이티브의 **fallback 미러**(`nativeAvailable ? nativeX() : javaX()`) — .so 로드 실패 시 동작, 그리고 Java 메서드 후킹이 네이티브보다 쉬운 우회면.

### [RES-ROOT-01] Java 루트 탐지 (경로·패키지·which su·프로퍼티·mount)
- 신뢰도: 가설
- 표준: MASVS-RESILIENCE-1 / MASWE-0051 / MASTG-TEST-0324·0325
- 위치: `Scn00MonitorModule.java:238` `appLayerDetectsRoot()` (+ ROOT_PATHS `:598`, ROOT_MANAGER_PACKAGES `:599`)
- 근거: `Build.TAGS` `test-keys`, ROOT_PATHS 14종(`/system/bin/su`,`/data/adb/magisk`,`Superuser.apk`…), `whichSu()`=`Runtime.exec("which su")` `:393`, ROOT_MANAGER_PACKAGES 12종(magisk/kernelsu/apatch/supersu…) `isPackageInstalled` `:410`, `hasUnsafeBootProperties()`(ro.debuggable/ro.secure) `:303`, `mountsContainRootArtifacts()`.
- 우회(가설): `appLayerDetectsRoot`/`fileExists`/`whichSu`/`isPackageInstalled` 후킹해 false. **단 nativeRootEvidence(네이티브)와 쌍** — 둘 다 무력화 필요.
- 2차 메모: **가설** (정상경로 태깅). FP함정(죽은 상수·import만) 배제 — ROOT_PATHS/패키지가 실제 `fileExists`/`isPackageInstalled` 호출로 소비됨. 미충족(승급): Frida로 네이티브+Java 쌍 동시 무력화 후 탐지 우회 재현. [verify.md 2026-11-17]

### [RES-EMU-01] Java 에뮬레이터/가상환경 탐지  ← (이전 "미발견" 공백 해소)
- 신뢰도: 가설
- 표준: MASVS-RESILIENCE-1 / MASWE-0053 / MASTG-TEST-0351
- 위치: `Scn00MonitorModule.java:267` `looksLikeEmulator()` (appLayerDetectsRoot가 호출)
- 근거: `Build.FINGERPRINT` generic/vbox/test-keys, `MODEL` google_sdk/emulator/"android sdk built for", `MANUFACTURER` genymotion, `HARDWARE` goldfish/ranchu/vbox, `PRODUCT` sdk_gphone, `fileExists("/dev/qemu_pipe")`,`"/dev/socket/qemud")`.
- 우회(가설): `Build` 필드 getter·`fileExists` 후킹으로 실기기 위장.
- 2차 메모: **가설 (공백 해소 확정)**. 1차 native 노트가 "RES-EMU-01 미발견"으로 적었으나 **Java층 `looksLikeEmulator()` 실재** → native-only 커버리지 오판 교정. FP함정(Build가 애널리틱스용) 배제 — generic/vbox/goldfish 토큰 비교가 appLayerDetectsRoot 판정에 합류. 미충족: Frida Build 위장 후 통과 재현. [verify.md 2026-11-17]

### [RES-DBG-01] Java 디버거 탐지
- 신뢰도: 가설
- 표준: MASVS-RESILIENCE-4 / MASWE-0064 / MASTG-TEST-0352·0353
- 위치: `Scn00MonitorModule.java:431` `appLayerDetectsDebugger()` + `tracerPid()` `:687`
- 근거: `Debug.isDebuggerConnected()` ∥ `Debug.waitingForDebugger()` ∥ `tracerPid()>0`(`/proc/self/status` `TracerPid:` 파싱 `:703`). 결과는 buildMonitorVerdict 맵/서명리포트로.
- 우회(가설): `Debug.isDebuggerConnected`·`tracerPid` 후킹→음성.
- 2차 메모: **가설**. FP함정(`BuildConfig.DEBUG`·로그게이팅) 배제 — 결과가 buildMonitorVerdict/서명리포트로 소비됨. native RES-DBG-02(TracerPid)의 Java 미러. 미충족: 디버거 attach 상태에서 Frida로 양측 음성화 재현. [verify.md 2026-11-17]

### [RES-HOOK-01] Java Frida/계측 탐지
- 신뢰도: 가설
- 표준: MASVS-RESILIENCE-4 / MASWE-0065 / MASTG-TECH-0043
- 위치: `Scn00MonitorModule.java:423` `appLayerDetectsFrida()` (+ `nativeDetectsFrida()` fallback `:419`)
- 근거: `tcpPortOpen(27042)`∥`(27043)`, `mapsContainsAny("frida","gum-js","gadget")`, (fallback) `threadNamesContainAny("gum-js-loop","gmain","gdbus")`.
- 우회(가설): 포트/ maps/스레드명 체크 후킹. 네이티브 RES-HOOK-01과 쌍.
- 2차 메모: **가설**. FP함정(maps 읽기 자체) 배제 — frida/gum-js/gadget 토큰 비교·27042/43 포트 명시. **다층(native 3경로 + Java) 이라 일부만 막으면 FN** 경고 유지. 미충족: 전 경로 음성화 후 우회 재현(동적). [verify.md 2026-11-17]

### [RES-INTEG-03] 하드웨어 키 attestation (F34)  ← (이전 "미발견" 공백 해소)
- 신뢰도: 가설
- 표준: MASVS-RESILIENCE-1/2 / MASWE-0054(Device)·0056(App Attestation)
- 위치: `Scn00MonitorModule.java:194` `keyAttestationChain(challenge)` → 맵 `attestationChain`
- 근거: Android Keystore 키 attestation 체인(Base64)을 challenge로 생성해 서버 전송. **서버 검증 여부가 강도 좌우**(FP함정: 클라만으론 판단 금지).
- 우회(가설): 서버검증형이면 우회 난이도 상향. 클라 판단형이면 결과 후킹.
- 2차 메모: **가설 (공백 해소 확정)**. 1차 native 노트의 "RES-INTEG-03 attestation 미발견" 교정 — Java `keyAttestationChain()` 실재. criterion FP함정대로 **서버 검증 여부가 강도를 좌우** → 클라 코드만으론 확정/기각 불가. 미충족: integrity/attestation 토큰이 서버에서 실제 강제되는지 트래픽 확인. [verify.md 2026-11-17]

### [RES-INTEG-01/02] Java APK 서명 자체검증 (F38, anti-tamper)
- 신뢰도: 가설
- 표준: MASVS-RESILIENCE-2 / MASWE-0057·0058 / MASTG-TEST-0081·0090
- 위치: `Scn00MonitorModule.java:554` `appLayerDetectsTamper()` → `signingCertSha256()` `:507`, 비교상수 `OFFICIAL_CERT_SHA256` `:65`
- 근거: 자기 APK 서명 cert SHA-256 ≠ `fac61745…033b9c` 이면 변조로 판정(`StringsKt.equals(..., OFFICIAL_CERT_SHA256)` `:558`). **native F38(해시산출)의 Java측 비교 상수** — 1차 native 노트의 "비교상수 Java층" 추정 확정.
- 우회(가설): `signingCertSha256` 반환을 정품 해시로 후킹, 또는 비교 분기. **재패키징 1순위 장애물**.
- 2차 메모: **가설 (정적 교차확인 강함)**. native F38(해시 산출) ↔ Java `OFFICIAL_CERT_SHA256` 로컬 비교(`:558`)로 **1차 native "서버검증형 추정"을 "로컬 비교 + 서버 이중" 으로 정밀화**. 정적 근거는 확정에 가까우나 승급조건상 ① 서버 강제 여부 ② Frida 서명위장 우회 재현 미충족 → 가설 유지. [verify.md 2026-11-17]

### [NET-PIN-01] Java 인증서 SPKI 피닝 관측 (F37)
- 신뢰도: 가설
- 표준: MASVS-NETWORK-2 / MASWE-0028 / MASTG-KNOW-0015
- 위치: `Scn00MonitorModule.java:435` `observedSpki()` + `appLayerVerifyPinnedCert()` `:497`, 상수 `PINNED_SPKI` `:74`/`PINNED_HOST:PORT` `:68`/`:71`
- 근거: `lab.eqst.co.kr:8406` 로 직접 TLS → 서버 leaf 공개키 SHA-256 == `PINNED_SPKI`(`2c5c6584…aa77f`) 비교.
- **오탐함정 주의**: 여기 `$observedSpki$trustAll$1`(모든 cert 수락 X509TrustManager `:440`) + accept 하는 HostnameVerifier `:457` 는 **NET-TRUST-01 취약점이 아니다** — 앱 실트래픽이 아니라 **피닝 지문 관측용 probe**다. TrustAll이지만 수집한 지문을 PINNED_SPKI와 대조하는 용도. (실 API 트래픽의 TrustManager가 아님)
- 우회(가설): 네이티브 NET-PIN-02와 쌍. Java측은 `appLayerVerifyPinnedCert`/`observedSpki` 후킹. 단 **Burp 중계 시 지문 바뀌어 탐지** → 네이티브/Java 양쪽 피닝 무력화 + HMAC 키 위조 필요.
- 2차 메모: **가설** (NET-PIN-01 정식 태깅). **동반 NET-TRUST-01 후보는 기각** — `$observedSpki$trustAll$1`(`:440`) TrustAll + accept HostnameVerifier(`:457`)는 criterion NET-TRUST-01의 오탐함정 ②(핀 지문을 직접 측정하려는 커스텀 TrustManager)에 정확히 해당. 앱 실 API 트래픽의 TrustManager가 아니라 **피닝 지문 관측 probe** → 취약점 아님. 미충족(PIN-01 승급): Frida unpinning 후 Burp 중계 성립 재현. [verify.md 2026-11-17]

> **하드코딩 상수(참고)**: `OFFICIAL_CERT_SHA256`, `PINNED_HOST/PORT`, `PINNED_SPKI` 모두 Java 상수로 평문 노출(`:65-74`). 네이티브 HMAC 키(`SCN00-monitor-hmac-key-v1-eqstlb`, §6)와 합쳐 **RASP 신뢰근거가 전부 클라이언트에 상수로 존재** → 리포트 위조의 토대.
