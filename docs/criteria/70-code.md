# CODE 분석 기준 — 코드 품질 · 의존성 · 입력 검증

> 카테고리: **MASVS-CODE** (코드 품질) · 작성 형식: [`_template.md`](./_template.md)
> 적용 레벨: **L1/L2**. 기준값은 **"최신 플랫폼 타깃 + 취약 컴포넌트 없음 + 미신뢰 입력 검증"** — 오래된 SDK·알려진 CVE 라이브러리·입력 미검증·안전치 않은 동적 로딩이 공격면.
> (MASVS v2에서 L1/L2/R 레벨은 MASTG **Testing Profiles**로 이동. 이 문서는 분석 편의상 L1/L2 표기 유지.)

## MASVS-CODE 통제 (live 확인됨, 2026-11-18)

| 통제 | 공식 wording | 다루는 criterion 패밀리 |
|---|---|---|
| **MASVS-CODE-1** | The app requires an up-to-date platform version. | min/target SDK, 최신 플랫폼 보장 |
| **MASVS-CODE-2** | The app has a mechanism for enforcing app updates. | 강제 업데이트 |
| **MASVS-CODE-3** | The app only uses software components without known vulnerabilities. | 취약 의존성(CVE), 컴파일러 보안기능, deprecated API, 악성코드 |
| **MASVS-CODE-4** | The app validates and sanitizes all untrusted inputs. | 동적 코드 로딩, 미신뢰 데이터 처리(인젝션) |

MASWE 매핑(live 확인, MASWE v1.0.0 — CODE는 **0041~0050** 10개):
- **CODE-1** → **0041**(Running on a Recent Platform Version Not Ensured)·**0042**(Latest Platform Version Not Targeted)
- **CODE-2** → **0043**(Enforced Updating Not Implemented)
- **CODE-3** → **0044**(Dependencies with Known Vulnerabilities)·**0045**(Compiler-Provided Security Features Not Used)·**0046**(Use of Deprecated APIs or Functionality)·**0048**(Malicious Code Included in the App)
- **CODE-4** → **0049**(Unsafe Dynamic Code Loading)·**0050**(Unsafe Handling of Untrusted Data) + 교차 0029/0034/0035(PLATFORM)·0057(RESILIENCE)
- **0047**(Using Non-Standard APIs for Security-Critical Functionality) = 커스텀 크립토 → [`30-crypto.md` CRY-CUSTOM-01](./30-crypto.md)에서 다룸(CODE 교차)

> **중요 구분**: `android:debuggable`·디버그 아티팩트(**MASWE-0061 Debug Artifacts Not Removed**)·디버그 메커니즘(**MASWE-0063 Debug Mechanisms Not Disabled**)은 CODE 페이지에 나열되지만 **실제 소속은 MASVS-RESILIENCE** → [`10-resilience.md`](./10-resilience.md)에서 다룬다(앞선 0063 ⚠️ 해소).
> 분석 위치: `manifest`(`minSdkVersion`·`targetSdkVersion`·`debuggable`), `jadx`(Java — `DexClassLoader`/`System.load`/입력 처리/역직렬화), `ghidra`(.so — 컴파일러 하드닝), `의존성`(라이브러리 버전·SBOM). 동적: 입력 퍼징·동적로딩 관찰.

---

## 패밀리 1 — 플랫폼 최신성 (MASVS-CODE-1)

### [COD-PLATFORM-01] 오래된 min/target SDK · 최신 플랫폼 미보장
- **표준 매핑**: MASVS-CODE-1 / MASWE-0041(Running on a Recent Platform Version Not Ensured)·MASWE-0042(Latest Platform Version Not Targeted) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: manifest
- **탐지 신호**: `minSdkVersion`이 지나치게 낮아(구버전 OS 허용) 최신 보안 완화 미적용, `targetSdkVersion`이 낮아 런타임 권한·scoped storage·백그라운드 제한 등 플랫폼 보안기능 미적용.
- **오탐 함정(FP trap)**: ① 비즈니스상 구형 기기 지원이 필요할 수 있음 — 위협모델 대비 판단. ② targetSdk만 최신이면 다수 완화가 적용됨(minSdk 낮음 자체가 치명은 아님). ③ 숫자만 보고 과대평가 금지.
- **검증 방법(oracle)**: ① manifest의 min/target SDK 값 확인 + 해당 버전에서 빠지는 보안기능 목록 대조. ② (⚠️ `--no-res`면 manifest 미추출 — 재추출 필요).
- **우회 포인트**: (공격자) 낮은 targetSdk로 구형 권한모델·레거시 동작을 악용. 방어관점: 최신 타깃 권고.
- **신뢰도 기본값**: 가설 → **승급**: SDK 값 + 미적용 보안기능 구체 확인.
- **금융 가중**: 아니오(일반 core, 금융은 우선순위만 상향)

---

## 패밀리 2 — 강제 업데이트 (MASVS-CODE-2)

### [COD-UPDATE-01] 강제 업데이트 메커니즘 부재
- **표준 매핑**: MASVS-CODE-2 / MASWE-0043(Enforced Updating Not Implemented) ✅ live
- **적용 레벨**: L2
- **어디서 보나**: jadx
- **탐지 신호**: 서버 최소버전 체크·`In-App Updates`(Play Core AppUpdateManager) 미사용, 취약 구버전이 무기한 동작, 클라이언트 버전 검증 분기 부재.
- **오탐 함정**: ① 강제 업데이트는 R/고위험 앱 요구 — 저위험 앱엔 과함. ② 서버측에서 API 버전 게이팅으로 사실상 강제할 수 있음(클라이언트에 안 보여도). ③ 선택적 업데이트 안내와 강제 구분.
- **검증 방법(oracle)**: ① 버전 체크·업데이트 강제 로직의 존재/우회가능성 정적 확인. ② 동적: 구버전으로 민감 기능 동작하는지.
- **우회 포인트**: (공격자) 패치 안 된 구버전을 계속 사용해 알려진 결함 악용.
- **신뢰도 기본값**: 가설 → **승급**: 강제 업데이트 부재 + 구버전 민감기능 동작 확인.
- **금융 가중**: 예

---

## 패밀리 3 — 취약 컴포넌트 (MASVS-CODE-3)

### [COD-DEPS-01] 알려진 취약점 있는 의존성 (CVE)
- **표준 매핑**: MASVS-CODE-3 / MASWE-0044(Dependencies with Known Vulnerabilities) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: jadx(패키지·버전 문자열), 의존성(SBOM)
- **탐지 신호**: 번들된 라이브러리의 알려진 CVE 버전(OkHttp·Gson·Bouncy Castle·OpenSSL·WebView 컴포넌트 등), `.so`에 임베드된 취약 OpenSSL/zlib/libpng 버전 문자열, 오래된 React Native/Flutter 엔진.
- **오탐 함정**: ① 버전 문자열이 fork·백포트 패치됐을 수 있음 — CVE 적용 가능성 실제 확인. ② 취약 함수가 앱에서 미사용 경로일 수 있음. ③ 버전만으로 단정 금지(패치 백포트 여부).
- **검증 방법(oracle)**: ① 라이브러리/`.so` 버전 문자열 추출 → CVE DB 대조. ② 취약 코드경로가 앱에서 실제 호출되는지 xref.
- **우회 포인트**: (공격자) 알려진 CVE로 RCE·메모리 손상·암호 우회. 네이티브 OpenSSL 버전은 [`50-network.md`](./50-network.md) TLS와 교차.
- **신뢰도 기본값**: 가설 → **승급**: 취약 버전 확인 + 해당 경로 사용 확인(+PoC).
- **금융 가중**: 예

### [COD-COMPILER-01] 컴파일러 제공 보안기능 미사용 (네이티브 하드닝)
- **표준 매핑**: MASVS-CODE-3/4 / MASWE-0045(Compiler-Provided Security Features Not Used) ✅ live
- **적용 레벨**: L2
- **어디서 보나**: ghidra(.so), 바이너리 헤더
- **탐지 신호**: `.so`에 Stack Canary(`__stack_chk_*`) 부재, Full RELRO 미적용(GOT 쓰기가능), PIE 미설정, `_FORTIFY_SOURCE` 미적용(`strcpy`/`sprintf` 등 unchecked 변형), NX/실행불가 스택 미설정.
- **오탐 함정**: ① 하드닝 부재 자체가 즉시 익스플로잇은 아님 — 메모리 버그와 결합돼야 위험(심층방어 결함). ② 일부는 라이브러리/NDK 기본 적용. ③ 스트립된 심볼로 canary 탐지 FN 주의.
- **검증 방법(oracle)**: ① `checksec`류/Ghidra로 RELRO·Canary·PIE·NX·FORTIFY 상태 확인. ② 위험 함수(`strcpy`·`memcpy` unbounded) 사용과 결합 평가.
- **우회 포인트**: (공격자) 하드닝 부재 + 메모리 버그 → 익스플로잇 난도 하락. 방어관점: 하드닝 플래그 활성 권고.
- **신뢰도 기본값**: 가설 → **승급**: 바이너리 하드닝 미적용 항목 구체 확인.
- **금융 가중**: 아니오

### [COD-DEPRECATED-01] deprecated/안전치 않은 API 사용
- **표준 매핑**: MASVS-CODE-3 / MASWE-0046(Use of Deprecated APIs or Functionality) ✅ live
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: 보안상 폐기된 API(구 암호·구 TLS·`SSLv3`·`MODE_WORLD_*`·`Runtime.exec` 오용·오래된 WebView 설정), 네이티브 폐기 함수(`gets`·unsafe `system`).
- **오탐 함정**: ① deprecated ≠ 즉시 취약(기능적 폐기와 보안 폐기 구분). ② 하위호환 분기(릴리스 비활성). ③ 정적 신호만으로 과대평가.
- **검증 방법(oracle)**: ① 폐기 API의 보안 영향·실제 사용경로 xref. ② 대체 API 미사용 확인.
- **우회 포인트**: (공격자) 폐기 API의 알려진 약점 악용. 커스텀 크립토는 [CRY-CUSTOM-01](./30-crypto.md)(MASWE-0047) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 보안 영향 있는 폐기 API의 실제 사용 확인.
- **금융 가중**: 아니오

### [COD-MALWARE-01] 앱에 포함된 악성/의심 코드
- **표준 매핑**: MASVS-CODE-3 / MASWE-0048(Malicious Code Included in the App) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: jadx, ghidra, manifest(권한)
- **탐지 신호**: 설명되지 않는 과잉 권한·은닉 기능, 알려진 악성 SDK·광고/트래커 과잉, 외부 C2로의 은밀 통신, 숨겨진 수집 루틴, 재패키징/트로이목마 징후.
- **오탐 함정**: ① 정당한 분석/크래시 SDK를 악성으로 오인. ② 광고 SDK의 정상 수집. ③ "의심"과 "악성 확정"을 구분(근거 필요).
- **검증 방법(oracle)**: ① 권한·SDK·네트워크 목적지·은닉 기능 교차 분석. ② 동적: 실제 통신·수집 행위 관찰.
- **우회 포인트**: (공격자/위협) 공급망·재패키징. 프라이버시 수집 측면은 [`80-privacy.md`](./80-privacy.md) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 악성 행위의 구체 근거(통신·수집·은닉) 확인.
- **금융 가중**: 아니오

---

## 패밀리 4 — 입력 검증 (MASVS-CODE-4)

### [COD-DYNLOAD-01] 안전하지 않은 동적 코드 로딩
- **표준 매핑**: MASVS-CODE-4 / MASWE-0049(Unsafe Dynamic Code Loading) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: `DexClassLoader`/`PathClassLoader`로 외부(다운로드·외부저장소) dex/jar 로드, `System.load`로 미검증 경로 `.so` 로드, 무결성 검증 없는 코드/플러그인 다운로드 실행, 리플렉션으로 동적 클래스 실행.
- **오탐 함정**: ① 번들 내부 dex의 정상 분할 로딩(멀티덱스)·신뢰 경로는 무해 — **로드 소스의 신뢰성**이 핵심. ② 서명/해시 검증이 있으면 완화. ③ 리플렉션 자체는 취약 아님.
- **검증 방법(oracle)**: ① 로드 소스가 외부/쓰기가능 경로인지 + 무결성 검증 유무 xref. ② 동적: 로드 경로 변조로 임의 코드 실행 재현.
- **우회 포인트**: (공격자) 외부 저장소/MITM로 악성 dex·`.so` 주입 → 코드 실행. 앱 리소스 무결성은 MASWE-0057([`10-resilience.md`](./10-resilience.md)) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 미신뢰 소스 + 검증부재 동적 로딩을 정적 + 주입 재현.
- **금융 가중**: 예

### [COD-INPUT-01] 미신뢰 데이터 안전치 않은 처리 (인젝션)
- **표준 매핑**: MASVS-CODE-4 / MASWE-0050(Unsafe Handling of Untrusted Data) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: SQL 쿼리 문자열 연결(`rawQuery`/`execSQL` + 외부입력), 경로 조작(외부입력으로 파일경로 조립 — path traversal), 안전치 않은 역직렬화(`ObjectInputStream`·미신뢰 JSON→객체), 커맨드 조립(`Runtime.exec`+입력), `Intent`/딥링크/IPC/서버응답을 검증 없이 민감 연산에 사용, 네이티브 버퍼 처리(unbounded copy).
- **오탐 함정**: ① 파라미터 바인딩(`?` placeholder)·화이트리스트가 있으면 안전. ② 입력이 신뢰 경계 안(1st-party)일 수 있음 — 출처 확인. ③ 프레임워크가 자동 이스케이프.
- **검증 방법(oracle)**: ① 미신뢰 소스(IPC·딥링크·네트워크·파일)에서 sink(SQL·파일·exec·역직렬화)까지 taint 흐름 xref + sanitization 유무. ② 동적: 변조 입력으로 인젝션 재현.
- **우회 포인트**: (공격자) SQLi·path traversal·역직렬화 RCE·커맨드 인젝션. 딥링크/WebView 입력은 [`60-platform.md`](./60-platform.md)(0029/0034/0035) 교차.
- **신뢰도 기본값**: 가설 → **승급**: taint 흐름 + sanitization 부재 확인(+인젝션 PoC).
- **금융 가중**: 예

---

## 커버리지 체크리스트 (2차 패스 — 공백 점검용)

- [ ] COD-PLATFORM-01 오래된 min/target SDK (MASWE-0041/0042)
- [ ] COD-UPDATE-01 강제 업데이트 부재 (MASWE-0043)
- [ ] COD-DEPS-01 취약 의존성 CVE (MASWE-0044)
- [ ] COD-COMPILER-01 네이티브 하드닝 미사용 (MASWE-0045)
- [ ] COD-DEPRECATED-01 폐기 API (MASWE-0046)
- [ ] COD-MALWARE-01 악성/의심 코드 (MASWE-0048)
- [ ] COD-DYNLOAD-01 안전치 않은 동적 로딩 (MASWE-0049)
- [ ] COD-INPUT-01 미신뢰 입력 처리·인젝션 (MASWE-0050)
- [ ] (MASWE-0047 커스텀 크립토 → CRY-CUSTOM-01 / 0061·0063 디버그 → RESILIENCE)

---

## 출처 (live 확인, 2026-11-18)

- MASVS-CODE: [mas.owasp.org/MASVS/10-MASVS-CODE](https://mas.owasp.org/MASVS/10-MASVS-CODE/)
- CODE-1: [controls/MASVS-CODE-1](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/) · CODE-4: [controls/MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/)
- MASWE-0045: [Compiler-Provided Security Features Not Used](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0045/)
- MASWE 전체: [mas.owasp.org/MASWE](https://mas.owasp.org/MASWE/) (CODE: 0041~0050, v1.0.0)

> **2026-11-18 live 확인**: MASVS-CODE-1~4 wording, MASWE-0041~0050 10개 실존·카테고리 매핑 확인. **0047**=커스텀 크립토(CRY-CUSTOM-01에서 다룸), **0061·0063**(디버그 아티팩트/메커니즘)=**RESILIENCE** 소속(CODE 페이지에 나열되나 홈은 RESILIENCE), CODE-4에 PLATFORM(0029/0034/0035)·RESILIENCE(0057) 교차.
