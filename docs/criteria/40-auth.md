# AUTH 분석 기준 — 인증 · 인가 · 로컬 인증

> 카테고리: **MASVS-AUTH** (인증·인가) · 작성 형식: [`_template.md`](./_template.md)
> 적용 레벨: **L1/L2**. **"안전한 인증·세션·인가 통제가 있어야 한다"**가 기본값.
> (MASVS v2에서 L1/L2/R 레벨은 표준 본문에서 빠져 MASTG **Testing Profiles**로 이동. 이 문서는 L1/L2 표기를 유지한다.)

## MASVS-AUTH 통제 (live 확인됨, 2026-11)

| 통제 | 공식 wording | 다루는 criterion 패밀리 |
|---|---|---|
| **MASVS-AUTH-1** | The app uses secure authentication and authorization protocols and follows the relevant best practices. | 인증/인가 프로토콜, 세션 관리, OAuth/OIDC, 클라이언트측 인가 |
| **MASVS-AUTH-2** | The app performs local authentication securely according to the platform best practices. | 생체·로컬 PIN 인증, 키 바인딩, enrollment 무효화 |
| **MASVS-AUTH-3** | The app secures sensitive operations with additional authentication. | 민감작업 step-up 인증, 비가역성(non-repudiation) |

MASWE 매핑(live 확인): AUTH-1 → **MASWE-0018**(Lack of Authentication/Authorization on App Components)·**0019**(Lack of Auto-fill Support for Credential Providers). AUTH-2 → **MASWE-0020**(Local Authentication Can Be Bypassed)·**0021**(Fallback to Non-biometric Credentials Allowed for Sensitive Transactions)·**0022**(Crypto Keys Not Invalidated on New Biometric Enrollment). AUTH-3 → **MASWE-0023**(Step-Up Authentication Not Implemented)·**0024**(Sensitive Data Accessible After Session Termination)·**0025**(Lack of Non-Repudiation for Critical Actions).

> 분석 위치: `jadx`(Java — `BiometricPrompt`/`KeyguardManager`/세션·토큰·OAuth 로직), `manifest`(exported 컴포넌트·딥링크 redirect), 동적(Frida 콜백 위조·토큰 관찰). **서버측 강제가 본질**이므로 클라이언트 코드만으로 강도 단정 금지 — "클라가 뭘 하나"와 "서버가 뭘 강제하나"를 분리해 기록.

---

## ⚑ AUTH vs 비즈니스 로직 — 경계부터 정한다 (모든 criterion에 선행)

**순수 비즈니스 로직 우회는 MASVS-AUTH가 아니다. MASVS 밖 별도 트랙이다.** ([`00-index.md` §별도 트랙](./00-index.md) 일관)

| 구분 | AUTH(이 문서) | 비즈니스 로직(별도 트랙) |
|---|---|---|
| 본다 | 인증·세션·OAuth·생체 **통제가 있나/충분한가** | 앱 흐름 설계·운영정책의 **빈틈** |
| 예 | 생체 콜백만 믿음, 토큰 만료 없음, redirect URI 미검증, 무인증 키 | 송금인증 우회, 소유자·PIN 검증 부재, 번호 brute force, Race/TOCTOU |
| 담당 | 이 criteria | `biz-logic-security-review` 스킬 |

> **억지로 로직 우회를 AUTH 칸에 밀어넣지 말 것.** "코드는 스펙대로 도는데 설계상 구멍"이면 그건 AUTH가 아니라 로직 트랙이다. 분석 중 인증/인가·자산이동 흐름이 나오면 그 스킬의 체크리스트를 **교차 적용**해 별도로 추적한다(특히 금융 가중 흐름). 리포트에서도 구분된 섹션으로 다룬다.

---

## 패밀리 1 — 로컬 인증(생체/PIN) (MASVS-AUTH-2)

### [AUTH-BIO-01] 생체 인증 우회 (콜백 신뢰 · 키 바인딩 부재)
- **표준 매핑**: MASVS-AUTH-2 / MASWE-0020(Local Authentication Can Be Bypassed) / MASTG-TEST-0327(References to APIs for Event-Bound Biometric Authentication) ✅ · 지식 MASTG-KNOW-0001(Biometric Authentication) ✅ · 데모 MASTG-DEMO-0090 · (구 MASTG-TEST-0018 = **deprecated**)
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java)
- **탐지 신호**: `BiometricPrompt.authenticate()` 결과(`onAuthenticationSucceeded`) **콜백만으로 분기**하고 `CryptoObject` 미사용, `FingerprintManager` 레거시, 생체 성공 여부가 `boolean` 하나로 흐름 제어, 인증 결과가 **서버 토큰/키 해제와 암호학적으로 묶이지 않음**(event-bound).
- **오탐 함정**: `CryptoObject`로 **key-bound** 생체(성공 시에만 KeyStore 키 사용 가능)는 **올바른 구현** — 콜백 신뢰형과 구분. 생체가 UX 편의일 뿐 뒤에 서버 인증이 따로면 약점 아님.
- **검증 방법(oracle)**: ① `authenticate` 호출이 `CryptoObject`를 넘기는지, 성공 분기가 키 사용/서버검증과 묶이는지 xref(event-bound면 약점). ② 동적: Frida로 `onAuthenticationSucceeded` 콜백을 **직접 호출/위조**해 생체 없이 통과되면 확정(MASWE-0020).
- **우회 포인트**: `BiometricPrompt$AuthenticationCallback.onAuthenticationSucceeded` 후킹/직접 호출, 성공 `boolean` 반환 고정. key-bound면 콜백 위조로는 안 풀림(키가 안 풀림).
- **신뢰도 기본값**: 가설 → **승급**: 콜백 신뢰(비 key-bound) 정적 확인 **AND** Frida 콜백 위조로 우회 재현.
- **금융 가중**: 예
- **예시(scn00)**: `BiometricKeyModule`(+`$sign$1$prompt$1`) — 생체 성공이 키 서명과 묶이는지(key-bound) 콜백 신뢰형인지 이 criterion으로 점검.

### [AUTH-BIO-02] 생체 enrollment 변경 시 키 무효화 부재 / 키 유효기간 과도
- **표준 매핑**: MASVS-AUTH-2 / MASWE-0022(Crypto Keys Not Invalidated on New Biometric Enrollment) / MASTG-TEST-0328(Detecting Biometric Enrollment Changes) ✅ · MASTG-TEST-0330(Keys with Extended Validity Duration) ✅
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java)
- **탐지 신호**: `KeyGenParameterSpec.setInvalidatedByBiometricEnrollment(false)`, `setUserAuthenticationValidityDurationSeconds(큰 값)`(시간기반 무제한에 가까움), enrollment 변경 감지 미구현.
- **오탐 함정**: 특정 UX 요구로 validity를 길게 둘 수 있으나 민감작업엔 부적절. 기본값(미지정)이 안전측일 수 있어 명시 설정 여부 확인.
- **검증 방법(oracle)**: `KeyGenParameterSpec` 빌더 플래그 정적 확인. 동적으로 새 지문 등록 후 기존 키 사용 가능한지 재현.
- **우회 포인트**: (공격자) 공격자 지문 추가 후에도 기존 키 유효 → 민감작업 접근.
- **신뢰도 기본값**: 가설 → **승급**: 빌더 플래그 정적 확인(+enrollment 변경 재현).
- **금융 가중**: 예

### [AUTH-BIO-03] 민감작업에 비생체 폴백(기기 PIN/패턴) 허용
- **표준 매핑**: MASVS-AUTH-2 / MASWE-0021(Fallback to Non-biometric Credentials for Sensitive Transactions) / MASTG-TEST-0326(References to APIs Allowing Fallback to Non-Biometric Authentication) ✅
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java)
- **탐지 신호**: `BiometricPrompt` `setAllowedAuthenticators(... | DEVICE_CREDENTIAL)`, `setDeviceCredentialAllowed(true)`로 민감작업에 기기 PIN/패턴 폴백 허용.
- **오탐 함정**: 저위험 작업엔 폴백이 적절할 수 있음 — **민감(결제·송금) 작업**에 한해 약점. 작업 민감도와 묶어 판단.
- **검증 방법(oracle)**: 민감작업 경로에서 `DEVICE_CREDENTIAL` 포함 authenticator가 쓰이는지 xref. 동적으로 폴백으로 민감작업 통과 재현.
- **우회 포인트**: (공격자) 약한 기기 PIN으로 생체 보호 작업 우회.
- **신뢰도 기본값**: 가설. **금융 가중**: 예.

---

## 패밀리 2 — 세션 관리 (MASVS-AUTH-1)

### [AUTH-SESSION-01] 세션/토큰 관리 약점
- **표준 매핑**: MASVS-AUTH-1 / MASWE-0024(Sensitive Data Accessible After Session Termination, AUTH-3) ✅ · MASWE-0018(AUTH-1) ✅ · **Android 전용 MASTG-TEST slug 없음** — 세션관리는 MASTG 서술 챕터(*Authentication and Session Management*)로만 다룸(live 확인). MASWE-0024/0018을 앵커로 사용
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java), 동적 트래픽
- **탐지 신호**: 토큰을 평문 SharedPrefs/파일 저장(STORAGE 교차), 만료/갱신 없음, 로그아웃 시 토큰 **무효화 안 함**(로컬만 삭제), 예측가능 세션ID(→[`30-crypto.md` CRY-RANDOM-01](./30-crypto.md)), 로그아웃 후에도 캐시된 민감데이터 접근.
- **오탐 함정**: 토큰 로컬 저장은 흔하고, AndroidKeyStore 보호·짧은 만료면 허용 가능 — 저장 방식+수명 함께 평가. 서버측 무효화가 있으면 로컬 잔존은 경감.
- **검증 방법(oracle)**: ① 토큰 저장 위치·만료·로그아웃 처리 xref. ② 동적: 로그아웃 후 기존 토큰으로 API 호출 성공하면 서버 무효화 부재 확정.
- **우회 포인트**: (공격자) 탈취/잔존 토큰 재사용.
- **신뢰도 기본값**: 가설 → **승급**: 저장·수명·무효화 정적 확인 + 동적 재사용 재현.
- **금융 가중**: 예

---

## 패밀리 3 — OAuth / OIDC (MASVS-AUTH-1)

### [AUTH-OAUTH-01] OAuth/OIDC 구현 약점
- **표준 매핑**: MASVS-AUTH-1 / MASWE-0018 ✅ · **Android 전용 OAuth MASTG-TEST slug 없음** — MASTG 서술 가이드만 존재(live 확인) · 외부 표준: RFC 8252(OAuth 2.0 for Native Apps)·RFC 7636(PKCE)
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java), manifest
- **탐지 신호**: redirect URI를 custom scheme으로 받되 **검증 부실**(아무 앱이 가로챌 수 있는 scheme), **PKCE 미사용**(code_challenge 없음), `state`/`nonce` 미검증(CSRF), 토큰을 클라이언트에 장기 저장, implicit flow 사용, client_secret 하드코딩(→[`30-crypto.md` CRY-HARDKEY-01](./30-crypto.md)).
- **오탐 함정**: custom scheme 자체는 정상 — **검증/PKCE 유무**가 관건. 서버가 state/PKCE를 강제하면 클라 미구현처럼 보여도 경감.
- **검증 방법(oracle)**: ① authorize 요청에 PKCE·state·nonce가 붙는지, redirect 처리가 검증하는지 xref + manifest intent-filter 확인. ② 동적: 인가 요청/응답 트래픽 캡처로 PKCE·state 실재 확인.
- **우회 포인트**: (공격자) redirect 가로채기·code injection·CSRF.
- **신뢰도 기본값**: 가설 → **승급**: 코드·트래픽으로 PKCE/state/redirect 검증 부재 확인.
- **금융 가중**: 예
- **예시(scn00)**: `OAuthAuthSessionModule` — PKCE·state·redirect 검증·토큰 저장을 이 criterion으로 점검.

---

## 패밀리 4 — PIN/패스코드 검증 (MASVS-AUTH-2, CRYPTO 교차)

### [AUTH-PIN-01] 로컬 PIN/패스코드 검증 약점
- **표준 매핑**: MASVS-AUTH-2 / MASWE-0020(Local Authentication Can Be Bypassed) ✅ (확정 앵커) · 관련 MASTG-TEST-0017(Testing Confirm Credentials — KeyguardManager 기기 자격증명)은 레거시 계열이라 번호 재확인 대상, 앵커는 MASWE-0020
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: PIN을 **로컬에서만** 검증(서버 미검증), PIN→키 파생이 약한 KDF(→[`30-crypto.md` CRY-KDF-01](./30-crypto.md)), verifier 상수/해시가 로컬 저장되어 오프라인 대입 가능, 시도횟수 제한 없음.
- **오탐 함정**: 로컬 PIN이 **key-bound**(PIN으로 KeyStore 키 해제, 서버 자원은 그 키로 보호)면 올바른 설계일 수 있음 — 단순 로컬 비교와 구분. 오프라인 대입 가능성(verifier 노출+약한 KDF)이 핵심.
- **검증 방법(oracle)**: ① PIN 검증이 로컬 비교인지 key-bound/서버인지, verifier 저장·KDF 강도 xref. ② 동적: verifier 추출 후 오프라인 대입 가능성 평가, 또는 검증 분기 후킹.
- **우회 포인트**: 로컬 비교 분기 후킹, 약한 KDF+유출 verifier로 PIN brute force.
- **신뢰도 기본값**: 가설 → **승급**: 로컬 검증·verifier·KDF 정적 확인(+대입/후킹 재현).
- **금융 가중**: 예
- **예시(scn00)**: `PinKdfModule`/`PinKdfEngine`/`PinKdfModule$ParsedVerifier` — 로컬/서버 검증 경계와 KDF 강도([CRY-KDF-01](./30-crypto.md)) 교차 점검.

---

## 패밀리 5 — 인가 / step-up (MASVS-AUTH-1, AUTH-3)

### [AUTH-AUTHZ-01] 클라이언트 측 인가/권한 판단
- **표준 매핑**: MASVS-AUTH-1 / MASWE-0018(Lack of Authentication/Authorization on App Components) ✅
- **적용 레벨**: L1
- **어디서 보나**: jadx(Java), manifest
- **탐지 신호**: 권한/역할(관리자·결제한도)을 **클라이언트에서 판단**해 UI/기능 게이팅, exported 컴포넌트가 인증 없이 민감기능 노출(PLATFORM 교차), 서버 재검증 없는 플래그 기반 접근제어.
- **오탐 함정**: 클라 게이팅이 **UX용이고 서버가 재검증**하면 약점 아님 — 서버 강제 여부가 관건. 클라 체크 존재 ≠ 취약.
- **검증 방법(oracle)**: ① 권한 판단이 서버 응답 기반인지 클라 상수/로컬 상태인지 xref. ② 동적: 클라 권한 플래그 후킹/변조 후 서버가 거부하는지 확인(거부 안 하면 확정).
- **우회 포인트**: 권한 플래그/역할 반환 후킹, exported 컴포넌트 직접 호출.
- **신뢰도 기본값**: 가설 → **승급**: 서버 재검증 부재를 동적으로 확인.
- **금융 가중**: 예

### [AUTH-STEPUP-01] 민감작업 추가 인증(step-up) 부재
- **표준 매핑**: MASVS-AUTH-3 / MASWE-0023(Step-Up Authentication Not Implemented)·MASWE-0025(Lack of Non-Repudiation for Critical Actions) ✅
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java), 동적
- **탐지 신호**: 송금·설정변경·결제 등 민감작업에 **추가 인증(생체/PIN/MFA) 없음**, 세션 로그인만으로 모든 작업 수행, 중요작업 서명·감사로그(non-repudiation) 부재.
- **오탐 함정**: 위험도 낮은 작업엔 step-up 불필요 — **민감작업 정의**와 묶어 평가. 서버가 별도 OTP를 요구하면 클라에 안 보여도 존재할 수 있음(트래픽 확인).
- **검증 방법(oracle)**: ① 민감작업 경로에 추가 인증 호출이 있는지 xref. ② 동적: 세션만으로 민감작업 API가 통과하는지 확인.
- **우회 포인트**: (공격자) 세션 탈취만으로 고위험 작업 수행. **단, "인증 자체를 건너뛰는 로직 결함"은 비즈니스 로직 트랙** — 여기선 "step-up 통제 유무"만.
- **신뢰도 기본값**: 가설 → **승급**: 민감작업에 step-up 부재를 코드+트래픽으로 확인.
- **금융 가중**: 예

---

## 커버리지 체크리스트 (2차 패스 — 공백 점검용)

- [ ] AUTH-BIO-01 생체 콜백 신뢰/키 바인딩 부재
- [ ] AUTH-BIO-02 enrollment 무효화 부재/키 유효기간 과도
- [ ] AUTH-BIO-03 민감작업 비생체 폴백 허용
- [ ] AUTH-SESSION-01 세션/토큰 관리
- [ ] AUTH-OAUTH-01 OAuth/OIDC 구현
- [ ] AUTH-PIN-01 로컬 PIN/패스코드 검증
- [ ] AUTH-AUTHZ-01 클라이언트 측 인가
- [ ] AUTH-STEPUP-01 민감작업 step-up 부재
- [ ] (경계) 순수 로직 우회는 **비즈니스 로직 트랙**으로 분리했는지 확인

---

## 출처 (live 확인, 2026-11)

- MASVS-AUTH: [mas.owasp.org/MASVS/07-MASVS-AUTH](https://mas.owasp.org/MASVS/07-MASVS-AUTH/)
- AUTH-1: [controls/MASVS-AUTH-1](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/) · AUTH-2: [controls/MASVS-AUTH-2](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-2/) · AUTH-3: [controls/MASVS-AUTH-3](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-3/)
- MASWE 전체: [mas.owasp.org/MASWE](https://mas.owasp.org/MASWE/) (AUTH: 0018~0025)
- MASTG 생체: [TEST-0326](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0326/) · [TEST-0327](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0327/) · TEST-0328 · TEST-0330 · 지식 MASTG-KNOW-0001 (구 TEST-0018 deprecated)

> **2026-11-17 재확인 완료 (남은 미검증 없음)**: 세션관리·OAuth는 Android 전용 MASTG-TEST slug가 **존재하지 않음**(MASTG 서술 챕터로만 다룸) → MASWE-0024/0018을 앵커로 사용. 로컬 PIN은 MASWE-0020이 확정 앵커(MASTG-TEST-0017 번호는 레거시/재확인 대상). 통제 wording·MASWE 0018~0025 live 확인됨. Android MASVS-AUTH의 현행 태그 TEST는 생체/자격증명 계열(0326~0330)뿐.
