# CRYPTO 분석 기준 — 암호 구현 · 키 관리

> 카테고리: **MASVS-CRYPTO** (암호) · 작성 형식: [`_template.md`](./_template.md)
> 적용 레벨: 대부분 **L1/L2**. NETWORK처럼 **"안전한 암호가 있어야 한다"**가 기본값 — 즉 **약한 알고리즘·하드코딩 키·키 관리 부재 자체가 취약점**이다.
> (MASVS v2에서 L1/L2/R 레벨은 표준 본문에서 빠져 MASTG **Testing Profiles**로 이동했다. 이 문서는 분석 편의상 L1/L2 표기를 유지한다.)

## MASVS-CRYPTO 통제 (live 확인됨, 2026-11)

| 통제 | 공식 wording | 다루는 criterion 패밀리 |
|---|---|---|
| **MASVS-CRYPTO-1** | The app employs current strong cryptography and uses it according to industry best practices. | 하드코딩 키, 약한 알고리즘/모드, 난수, IV/salt, MAC·서명, 커스텀 크립토 |
| **MASVS-CRYPTO-2** | The app performs key management according to industry best practices. | 키 생성·파생(KDF)·저장·접근제어·회전(생명주기) |

MASWE 매핑(live 확인): CRYPTO-1 → **MASWE-0007**(Improper Encryption)·**0008**(Improper Hashing)·**0009**(Improper Use of MAC)·**0010**(Improper Generation of Cryptographic Signatures)·**0011**(Improper Verification of Cryptographic Signature)·**0012**(Improper Random Number Generation). CRYPTO-2 → **MASWE-0014**(Improper Cryptographic Key Derivation)·**0015**(Cryptographic Key Rotation Not Implemented, L2)·**0016**(Cryptographic Key Access Not Restricted)·**0017**(Device Secure Lock Not Enforced).
(**MASWE-0013**은 live 확인 결과 "Improper Cryptographic Key Generation"(키 **생성** 결함)으로 **하드코딩 키와는 별개**다. 하드코딩 키 전용 MASWE는 없고 **MASTG-TEST-0212**(Use of Hardcoded Cryptographic Keys in Code)로 매핑하며, 하드코딩 시크릿 일반은 **MASWE-0004**(Sensitive Data Hardcoded in the App Package, MASVS-STORAGE)와 교차. **MASWE-0047**(Using Non-Standard APIs for Security-Critical Functionality)는 **MASVS-CODE**로 확정 — 커스텀 크립토와 교차.)

> 분석 위치: `jadx`(Java — `javax.crypto`/`java.security`/`SecretKeySpec`/`Cipher`/`MessageDigest`/`KeyStore`), `ghidra`(.so — OpenSSL/BoringSSL·커스텀 루틴·`.rodata` 키 상수), `리소스`(res/raw·assets·strings). 동적: Frida로 `Cipher`/`Mac`/`SecretKeySpec` 인자 덤프가 최종 oracle.

---

## 패밀리 1 — 하드코딩 키/시크릿 (MASVS-CRYPTO-1)

### [CRY-HARDKEY-01] 하드코딩 대칭키/HMAC키/시크릿
- **표준 매핑**: MASVS-CRYPTO-1 / MASWE-0009(Improper Use of MAC — MAC 키일 때)·MASWE-0004(Sensitive Data Hardcoded in the App Package, MASVS-STORAGE 교차) / MASTG-TEST-0212(Use of Hardcoded Cryptographic Keys in Code) ✅ live · MASTG-DEMO-0017(Hardcoded AES Key in SecretKeySpec, semgrep) ✅ (※ 하드코딩 키 전용 MASWE는 없음 — 번호는 TEST-0212로 앵커, MASWE-0013은 "키 생성"이라 비해당)
- **적용 레벨**: L1
- **어디서 보나**: jadx(Java), ghidra(.so), 리소스
- **탐지 신호**:
  - Java: `new SecretKeySpec(byte[]{...}, "AES"/"HmacSHA256")`, 상수 `byte[]`/문자열 키, `"..."` base64/hex 키 리터럴, `Mac.getInstance`+하드코딩 키, `IvParameterSpec(상수)`.
  - 네이티브: `.rodata`의 키처럼 보이는 상수 문자열/바이트열, `EVP_*`/`HMAC_Init` 인자로 넘어가는 고정 버퍼.
  - 리소스: `res/raw`·`assets`·`strings.xml`의 키/시크릿.
- **오탐 함정(FP trap)**: ① 공개키·인증서(공개돼도 무방)를 비밀키로 오인. ② 테스트/샘플 키가 데드코드로만 존재. ③ 서버 공개 파라미터(피닝 SPKI 등 — 그건 NETWORK). ④ 난독화로 키가 런타임 조립되면 상수로는 안 보임(FN).
- **검증 방법(oracle)**: ① 그 키가 **실제 `Cipher`/`Mac` init에 쓰이는지** xref(단순 상수면 기각). ② 네이티브는 2경로 교차검증(예: HMAC ipad⊕0x36 / opad⊕0x5c 양쪽에서 같은 키 복원)으로 **정적 확정 가능**. ③ 동적: Frida로 `SecretKeySpec.$init`/`Mac.init` 인자 덤프.
- **우회 포인트**: (공격자 관점) 키가 유출되면 **서명 위조·복호·리포트 위조**가 성립 — 발견 자체가 취약점. 증거수집형 RASP면 clean 리포트 위조로 직결([10-resilience.md §RASP 유형](./10-resilience.md)).
- **신뢰도 기본값**: 가설 → **승급**: 키가 보안 연산에 쓰임 + 정적 2경로 교차검증(또는 동적 덤프). **하드코딩 키는 정적 증명만으로 `확정` 가능**(동적 불요).
- **금융 가중**: 예
- **예시(scn00)**: `libscn00monitor.so`의 HMAC 키 `SCN00-monitor-hmac-key-v1-eqstlb`가 `.rodata` 평문 상수로 노출 — attestation 리포트 서명(MAC)에 사용. 유출로 clean 리포트 위조 경로 성립([report-forge.js](../frida/templates/report-forge.js)). MAC 오용 측면은 MASWE-0009 교차.

---

## 패밀리 2 — 약한/취약 알고리즘·모드 (MASVS-CRYPTO-1)

### [CRY-ALGO-01] 약한 암호 알고리즘·모드·해시
- **표준 매핑**: MASVS-CRYPTO-1 / MASWE-0007(Improper Encryption)·MASWE-0008(Improper Hashing) / MASTG-TEST-0221(Broken Symmetric Encryption Algorithms) ✅ · MASTG-TEST-0350(Runtime Use of Broken Symmetric Encryption Modes) ✅
- **적용 레벨**: L1
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**:
  - 대칭: `Cipher.getInstance("DES"/"DESede"/"RC4"/"Blowfish")`, 모드 `"AES/ECB/..."`(ECB), `"RSA/ECB/PKCS1Padding"`(패딩 약점).
  - 해시: 보안 용도의 `MessageDigest.getInstance("MD5"/"SHA-1")`, 서명/무결성에 MD5·SHA1.
  - 네이티브: `EVP_des_*`/`EVP_rc4`/`MD5_*`/`SHA1_*` 심볼.
- **오탐 함정**: ① MD5/SHA1이 **비보안 용도**(캐시 키·ETag·중복제거)면 취약 아님 — 용도 확인. ② "ECB"가 문자열 상수로만 있고 실제 미사용. ③ 하위호환 레거시 분기(릴리스 비활성).
- **검증 방법(oracle)**: ① 알고리즘 문자열의 xref가 **실제 민감데이터 암호화/서명 경로**인지 확인. ② 동적: `Cipher.getInstance` 인자 후킹으로 런타임 실제 transformation 확인(MASTG-TEST-0350).
- **우회 포인트**: (공격자 관점) ECB 패턴 노출·DES 무차별·MD5 충돌 등 — 발견 자체가 약점. 분석 측면에선 약한 암호 복호로 평문 복원.
- **신뢰도 기본값**: 가설 → **승급**: 약한 알고리즘이 민감데이터 보호에 실제 사용됨을 xref/동적으로 확인.
- **금융 가중**: 예

### [CRY-IV-01] 고정/재사용 IV · 하드코딩 salt
- **표준 매핑**: MASVS-CRYPTO-1 / MASWE-0007 / MASTG-TEST-0309(References to Reused Initialization Vectors in Symmetric Encryption) ✅ live · MASTG-TEST-0310(Runtime Use of Reused Initialization Vectors in Symmetric Encryption) ✅ live (둘 다 Draft 상태)
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: `IvParameterSpec(상수 byte[])`, 고정 `GCMParameterSpec` nonce, salt 상수, CTR/GCM에서 동일 (key,nonce) 재사용, IV를 0으로 초기화.
- **오탐 함정**: IV가 상수처럼 보여도 **암호문에 prepend돼 매번 난수 생성**될 수 있음 — 생성 경로 확인. 복호 측 코드만 보면 상수로 오인.
- **검증 방법(oracle)**: ① IV/salt 생성이 `SecureRandom`인지 상수인지 xref. ② 동적: `Cipher.init`의 `IvParameterSpec` 인자를 여러 호출에서 덤프해 **동일값 재사용** 확인.
- **우회 포인트**: (공격자) 고정 IV/salt는 사전계산·패턴분석·재생공격 창구. 발견 자체가 약점.
- **신뢰도 기본값**: 가설 → **승급**: IV/salt 고정·재사용을 정적 또는 다회 동적 덤프로 확인.
- **금융 가중**: 예

---

## 패밀리 3 — 난수 (MASVS-CRYPTO-1 / MASWE-0012)

### [CRY-RANDOM-01] 안전치 않은 난수로 보안 값 생성
- **표준 매핑**: MASVS-CRYPTO-1 / MASWE-0012(Improper Random Number Generation) ✅
- **적용 레벨**: L1
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: 보안 용도(토큰·키·IV·salt·OTP·세션ID)에 `java.util.Random`/`Math.random()`, 고정 시드 `new Random(상수)`/`SecureRandom.setSeed(상수)`, 네이티브 `rand()`/`srand(time)`.
- **오탐 함정**: `java.util.Random`이 **비보안 용도**(UI·셔플·샘플링)면 무해. `SecureRandom`에 `setSeed`를 더해도 대개 안전(재시드) — 생성자 시드 고정과 구분.
- **검증 방법(oracle)**: ① 난수 산출물이 **보안 값으로 흘러가는지** xref. ② 동적: 난수 생성 호출 후킹해 예측가능성/시드 확인.
- **우회 포인트**: (공격자) 예측가능 토큰/키 → 세션 예측·키 복원. 발견 자체가 약점.
- **신뢰도 기본값**: 가설 → **승급**: 약한 PRNG 산출물이 보안 값에 쓰임을 xref/동적 확인.
- **금융 가중**: 예

---

## 패밀리 4 — 커스텀/자작 크립토 (MASVS-CRYPTO-1, CODE 교차)

### [CRY-CUSTOM-01] 표준 대신 자작 암호/인코딩을 보안에 사용
- **표준 매핑**: MASVS-CRYPTO-1(크립토 측면) / **MASWE-0047**(Using Non-Standard APIs for Security-Critical Functionality, **MASVS-CODE** — ✅ live 확인) — 커스텀 크립토는 CRYPTO·CODE 교차
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: XOR 루프·바이트 치환·자작 "암호화" 함수, base64/hex를 암호화로 오용, 표준 `javax.crypto` 대신 직접 구현한 블록/스트림 로직, 네이티브의 수제 치환·회전 루틴.
- **오탐 함정**: base64/압축/직렬화는 **암호화가 아님**(기밀성 없음) — "인코딩을 암호로 착각"이 흔한 오탐이자, 반대로 "앱이 인코딩을 암호로 신뢰"하면 그 자체가 약점. 문맥 구분.
- **검증 방법(oracle)**: ① 민감데이터가 자작 루틴만 거쳐 저장/전송되는지 xref. ② 동적: 입출력 덤프로 가역성(키 없이 복원 가능)·약함 확인.
- **우회 포인트**: (공격자) 자작 크립토는 대개 가역/예측가능 → 평문 복원. 발견 자체가 약점.
- **신뢰도 기본값**: 가설 → **승급**: 자작 루틴이 보안 목적(기밀/무결)으로 쓰이고 표준 대체 부재를 확인.
- **금융 가중**: 예

---

## 패밀리 5 — 키 파생 KDF (MASVS-CRYPTO-2 / MASWE-0014)

### [CRY-KDF-01] 약한 키 파생 (낮은 iteration · 무salt · 약한 KDF)
- **표준 매핑**: MASVS-CRYPTO-2 / MASWE-0014(Improper Cryptographic Key Derivation) ✅
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: `PBEKeySpec(pw, salt, iterations, len)`의 **낮은 iteration**(수천 이하), 무salt/고정salt, 비밀번호→키에 단순 해시 1회(`MD5(pw)`), Argon2/scrypt/bcrypt 대신 약한 파생, PIN→키 파생이 서버 없이 로컬.
- **오탐 함정**: iteration이 상수로 낮아 보여도 서버측 추가 강화가 있을 수 있음 — 로컬 KDF 단독 강도로 판단. salt가 상수처럼 보여도 사용자별 생성일 수 있음(생성 경로 확인).
- **검증 방법(oracle)**: ① `PBEKeySpec`/KDF 인자(iteration·salt·length) 정적 확인 + 산출 키 용도 xref. ② 동적: `PBEKeySpec.$init` 인자 덤프.
- **우회 포인트**: (공격자) 약한 KDF + 유출 salt → PIN/비밀번호 오프라인 brute force. 발견 자체가 약점.
- **신뢰도 기본값**: 가설 → **승급**: KDF 파라미터·용도 정적 확인(+동적 인자 덤프).
- **금융 가중**: 예
- **교차**: PIN verifier의 KDF 강도는 [`40-auth.md` AUTH-PIN-01](./40-auth.md)과 교차. 하드코딩 salt는 [CRY-HARDKEY-01] 교차.
- **예시(scn00)**: `PinKdfModule`/`PinKdfEngine`/`PinKdfModule$ParsedVerifier` — PIN KDF·verifier 파라미터와 로컬/서버 검증 경계를 이 criterion으로 점검.

---

## 패밀리 6 — 키 저장·관리 (MASVS-CRYPTO-2)

### [CRY-STORE-01] 키 저장·접근제어 (AndroidKeyStore · StrongBox · 생명주기)
- **표준 매핑**: MASVS-CRYPTO-2 / MASWE-0016(Cryptographic Key Access Not Restricted)·MASWE-0017(Device Secure Lock Not Enforced)·MASWE-0015(Cryptographic Key Rotation Not Implemented, L2) ✅
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java)
- **탐지 신호**: 키를 `AndroidKeyStore` 밖(SharedPrefs·파일·하드코딩)에 보관, `KeyGenParameterSpec` 미사용, `setUserAuthenticationRequired(false)`로 무인증 키 사용, StrongBox(`setIsStrongBoxBacked`) 미사용, 소프트웨어 키, 키 회전/만료 부재.
- **오탐 함정**: 소프트웨어 키라도 위협모델상 허용될 수 있음(비민감). 키 노출 여부와 "KeyStore 미사용"을 구분 — KeyStore를 써도 접근제어(`UserAuthenticationRequired`)가 없으면 약점.
- **검증 방법(oracle)**: ① 키 생성/저장 경로가 AndroidKeyStore인지, 접근제어 플래그가 설정되는지 정적 확인. ② 동적: KeyStore 사용 여부·키 추출 가능성(루팅 환경) 확인.
- **우회 포인트**: (공격자) KeyStore 밖 키·무인증 키 → 키 추출·오남용. 디바이스 바인딩은 [`10-resilience.md` RES-BIND-01](./10-resilience.md) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 키 저장 위치·접근제어 정적 확인(+루팅 환경 추출 재현).
- **금융 가중**: 예

---

## 커버리지 체크리스트 (2차 패스 — 공백 점검용)

- [ ] CRY-HARDKEY-01 하드코딩 키/HMAC키/시크릿
- [ ] CRY-ALGO-01 약한 알고리즘·모드·해시
- [ ] CRY-IV-01 고정/재사용 IV·salt
- [ ] CRY-RANDOM-01 안전치 않은 난수
- [ ] CRY-CUSTOM-01 커스텀/자작 크립토
- [ ] CRY-KDF-01 약한 KDF
- [ ] CRY-STORE-01 키 저장·접근제어·회전

---

## 출처 (live 확인, 2026-11)

- MASVS-CRYPTO: [mas.owasp.org/MASVS/06-MASVS-CRYPTO](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)
- CRYPTO-1: [controls/MASVS-CRYPTO-1](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/) · CRYPTO-2: [controls/MASVS-CRYPTO-2](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/)
- MASWE 전체: [mas.owasp.org/MASWE](https://mas.owasp.org/MASWE/) (CRYPTO: 0007~0017)
- MASTG 하드코딩키: [MASTG-TEST-0212](https://mas.owasp.org/MASTG/tests/) · 데모 [MASTG-DEMO-0017](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0017/MASTG-DEMO-0017/)
- MASTG 약한 대칭/모드: TEST-0221 · [TEST-0350](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0350/) (구 TEST-0013 deprecated)
- MASTG 암호 가이드: [0x04g Testing Cryptography](https://mas.owasp.org/MASTG/0x04g-Testing-Cryptography/)

> **2026-11-17 재확인 완료 (남은 미검증 없음)**: MASWE-0013="Improper Cryptographic Key Generation"(하드코딩키와 별개 — 하드코딩키는 MASTG-TEST-0212 앵커, MASWE-0004 STORAGE 교차), MASTG-TEST-0309·0310(Reused IV, 실존·Draft), MASWE-0047="Using Non-Standard APIs..."=MASVS-CODE 확정, MASWE-0015="Cryptographic Key Rotation Not Implemented". 통제 wording·MASWE 0007~0017 live 확인됨.
