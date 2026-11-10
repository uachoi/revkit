# libscn00monitor.so — 네이티브 RASP 모듈 분석 (Ghidra)

> 생성: 2026-11-09 · 대상: EQST FinTech App Hacking 워게임 / scn00
> 바이너리: `scn00/lib/arm64-v8a/libscn00monitor.so` (18,240 B, ELF AARCH64 LE, 함수 115개)
> 도구: Ghidra MCP (port 8765) · image base `0x100000`
> 짝 문서: Java/서버 흐름은 [`java_analysis.md`](./java_analysis.md) 참조

> ⚠️ Ghidra 프로젝트 DB(`_work/ghidra/`)는 .gitignore 제외 대상. 이 파일이 네이티브 분석의
> **커밋되는 텍스트 기록**이다. 리네임·코멘트는 로컬 Ghidra DB에만 존재.

---

## 0. 한 줄 요약

단일 클래스 `kr.co.eqst.pay.s00.Scn00MonitorModule` 전용 **anti-tampering/RASP** 모듈.
루트·Frida·디버거·APK서명·TLS인증서 증거를 네이티브에서 수집하고 **HMAC-SHA256(하드코딩 대칭키)**
으로 서명해 `base64(payload).hmac_hex` 로 반환한다. **서명 키가 .so에 박혀 있어 리포트 위조 가능**(§4).

---

## 1. Export(JNI) ↔ Java native 메서드 매핑

FQN prefix = `Java_kr_co_eqst_pay_s00_Scn00MonitorModule_`

| JNI export | 주소 | Java 선언 | 역할 |
|---|---|---|---|
| `…_nativeFridaEvidence` | `0x1025f0` | `nativeFridaEvidence()` | Frida 흔적 수집 |
| `…_nativeDebuggerEvidence` | `0x102bbc` | `nativeDebuggerEvidence()` | 디버거 attach 탐지 |
| `…_nativeRootEvidence` | `0x102d3c` | `nativeRootEvidence()` | 루트/Magisk 흔적 수집 |
| `…_nativeSignedReport` | `0x1031cc` | `nativeSignedReport(code, nonce)` | 서명 리포트 디스패처(F34/F35/F36/F38) |
| `…_nativeSignedReportPinning` | `0x103a1c` | `nativeSignedReportPinning(nonce, proxyHost, proxyPort)` | F37 인증서 피닝/MITM |

- 3개 Evidence 래퍼는 공통 패턴: 내부 helper로 1024B 버퍼 채움 → 버퍼 비면 `null`, 아니면
  `JNIEnv->NewStringUTF`(vtable off **0x538**) 로 jstring 반환.
- `GetStringUTFChars` = off **0x548**, `ReleaseStringUTFChars` = off **0x550**.

---

## 2. 탐지 함수 5종 — 주소 · 로직

### 2-1. `detect_root_evidence` (0x102d8c) ← nativeRootEvidence
- `stat()` 로 파일 존재 확인 → 발견 시 `키:값` 을 `;` 구분 누적:
  - su 바이너리: `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/su/bin/su` → `su:<경로>`
  - Magisk: `/data/adb/magisk`, `/data/adb/modules`, `/sbin/.magisk` → `magisk:<경로>`
  - `__system_property_get("ro.build.tags")` 에 `test-keys` 포함 → `prop:test-keys`
- 출력 예: `su:/system/xbin/su;magisk:/data/adb/magisk;prop:test-keys`

### 2-2. `detect_frida_evidence` (0x102640) ← nativeFridaEvidence
3단계 검사, `;` 구분 누적:
1. `/proc/self/maps` 라인 매칭: `frida`, `gum-js`, `gadget`, `frida-agent`, `linjector` → `maps:<kw>`
2. `/proc/self/task/<tid>/comm` 스레드명: `gum-js-loop`, `gmain`, `gdbus`, `pool-frida`, `pool-spawner` → `thread:<kw>`
3. `127.0.0.1` TCP **27042**(`sa_data`=0x69a2) / **27043**(0x69a3) connect 성공 → `port:27042` / `port:27043`

### 2-3. `detect_debugger_evidence` (0x102c0c) ← nativeDebuggerEvidence
- `/proc/self/status` 를 fgets, `TracerPid:` 라인(LE 비교 `0x6950726563617254`="TracerPi", `0x3a64`="d:")
- `strtol` 값 > 0(=누군가 ptrace 중) → `tracerpid:<pid>` 누적

### 2-4. `nativeSignedReport` 디스패처 (0x1031cc) — §3
F34→`detect_root_evidence`, F35→`detect_frida_evidence`, F36→`detect_debugger_evidence`,
F38→APK 서명 인증서 SHA-256(아래).

**F38 APK 서명 무결성**:
- `/proc/self/maps` 에서 `/data/app/...base.apk` 경로 추출 → 파일 open
- 끝 0x10015B 이내를 읽어 ZIP **EOCD(`PK\x05\x06`)** 탐색 → central dir offset 획득
- 그 앞의 **APK Signing Block** 매직 `"APK Sig Block 42"`(LE `0x20676953204b5041`,`0x3234206b636f6c42`) 확인
- 블록 내 **v2 ID `0x7109871a`** (/ v3 ID `0xf05368c0`) 파싱 → signed-data 내 인증서 바이트
  → `sha256_update`/`sha256_final` → **SHA-256 hex** 를 evidence 로 사용

### 2-5. `nativeSignedReportPinning` (0x103a1c) = F37 — §3, §5
- 기본 타깃 `lab.eqst.co.kr:0x20d6(8406)`. `getaddrinfo→socket→setsockopt(SO_SND/RCVTIMEO 0x14/0x15)→connect`.
- proxyHost 지정 시 **HTTP `CONNECT lab.eqst.co.kr:8406` 터널** 후 응답 `" 200"` 확인.
- **직접 조립한 TLS ClientHello(0x7b B, record type 0x16)** write → 핸드셰이크 레코드 read →
  `Certificate`(0x0b) 메시지 내 leaf 인증서 **ASN.1 DER(SEQUENCE 0x30) 수동 파싱** → 인증서 바이트
  **SHA-256 hex** 지문 산출. (중간자 프록시 끼면 지문 달라져 서버가 탐지)

---

## 3. 서명 리포트 포맷 (nativeSignedReport / nativeSignedReportPinning 공통)

```
payload  = "code|nonce|flag|evidence"     // nativeSignedReport, flag = 증거 유무 '0'/'1'
payload  = "F37|nonce|cert_fp_hex|"        // nativeSignedReportPinning (flag 자리 없음)
sig      = HMAC_SHA256(key, payload)        // §4
return   = base64(payload) + "." + hex(sig) // snprintf("%s.%s", …), NewStringUTF
```

---

## 4. HMAC 키 (★ 핵심 취약점) — `hmac_sha256` (0x103924)

- 표준 HMAC-SHA256: `inner = SHA256((k⊕ipad)||data)`, `out = SHA256((k⊕opad)||inner)` (ipad=0x36, opad=0x5c, 블록 64B).
- key 는 직접 저장 안 되고 `.rodata` 에 **사전 XOR된 상태**로 보관(블록당 32B 사용, 나머지 0x36/0x5c fill):
  - k⊕ipad: vaddr `0x100e20`(16B) + `0x100dc0`(16B)
  - k⊕opad: vaddr `0x100e30`(16B) + `0x100de0`(16B)
- 복원: `.so` 파일오프셋 = `vaddr − 0x100000`. `(ipad블록 ⊕ 0x36)` == `(opad블록 ⊕ 0x5c)` **교차검증 일치**.

### 복원된 키 (32바이트)
```
ASCII : SCN00-monitor-hmac-key-v1-eqstlb
hex   : 53434e30302d6d6f6e69746f722d686d61632d6b65792d76312d657173746c62
```

### 재현 스니펫 (node)
```js
const b = require('fs').readFileSync('scn00/lib/arm64-v8a/libscn00monitor.so');
const key = Buffer.alloc(32);
for (let i=0;i<16;i++){ key[i]=b[0xe20+i]^0x36; key[16+i]=b[0xdc0+i]^0x36; }
console.log(key.toString()); // SCN00-monitor-hmac-key-v1-eqstlb
```

### 시사점
- RASP 리포트의 신뢰근거가 **클라이언트 대칭키 1개**뿐. 키 추출 후 서버 발급 nonce에 대해
  `"F3x|<nonce>|0|"` 를 직접 서명하면 **"탐지 없음(clean)" 리포트 임의 위조** → F34~F38 전면 우회.
- nonce 1회용이라 단순 리플레이는 차단되나, 키 공개로 매 nonce마다 유효 서명 생성 가능 → 방어 무력.

---

## 5. 하드코딩 상수 / 네트워크 지표

| 항목 | 값 | 위치 |
|---|---|---|
| 피닝 호스트:포트 | `lab.eqst.co.kr:8406` (`0x20d6`) | nativeSignedReportPinning, Java 상수 |
| Frida 탐지 포트 | TCP `27042`, `27043` @127.0.0.1 | detect_frida_evidence |
| APK Signing Block 매직 | `"APK Sig Block 42"` | nativeSignedReport(F38) |
| APK 서명 v2 / v3 블록 ID | `0x7109871a` / `0xf05368c0` | nativeSignedReport(F38) |
| HMAC 키 | `SCN00-monitor-hmac-key-v1-eqstlb` | .rodata 0x100e20/0x100dc0 (XOR) |

Java 측 추가 상수(`Scn00MonitorModule.java`): `OFFICIAL_CERT_SHA256 = fac61745…1033b9c`,
`PINNED_SPKI = 2c5c6584…1aa77f`.

---

## 6. attestation 구조 (F34, Java 레이어 — 네이티브 아님)

F34 루트 항목은 네이티브 서명 외에 **하드웨어 Key Attestation** 을 Java에서 병행 수집
(`Scn00MonitorModule.keyAttestationChain()`):
- `KeyPairGenerator("EC", "AndroidKeyStore")` 로 임시 키 `scn00_f34_attest_<nanoTime>` 생성,
  `KeyGenParameterSpec.setAttestationChallenge(challenge)` 로 서버 challenge 주입.
- `KeyStore.getCertificateChain()` → 각 인증서 `Base64`(NO_WRAP) → `attestationChain` 배열로 반환.
- 하드웨어 attestation 불가 시(에뮬/비TEE) 예외 → 빈 체인("untrusted device" 로그).
- 사용 후 KeyStore 엔트리 `deleteEntry` 로 정리.
- 즉 F34는 **(a) 네이티브 HMAC 루트 리포트 + (b) Java 하드웨어 attestation 체인** 2중 증거.
  단 네이티브 HMAC 키가 뚫리면 (a)는 무력, (b)는 TEE 기반이라 상대적으로 견고.

---

## 7. 함수 주소 맵 (빠른 참조)

| 함수 | 주소 |
|---|---|
| `Java_…_nativeFridaEvidence` | `0x1025f0` |
| `detect_frida_evidence` | `0x102640` |
| `Java_…_nativeDebuggerEvidence` | `0x102bbc` |
| `detect_debugger_evidence` | `0x102c0c` |
| `Java_…_nativeRootEvidence` | `0x102d3c` |
| `detect_root_evidence` | `0x102d8c` |
| `Java_…_nativeSignedReport` | `0x1031cc` |
| `hmac_sha256` | `0x103924` |
| `Java_…_nativeSignedReportPinning` | `0x103a1c` |
| `sha256_update` / `sha256_final` | (helper, hmac·cert 지문 공용) |
