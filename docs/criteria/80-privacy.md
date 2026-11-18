# PRIVACY 분석 기준 — 데이터 최소화 · 추적 · 투명성 · 사용자 통제

> 카테고리: **MASVS-PRIVACY** (프라이버시, MASVS v2.1.0에서 신설) · 작성 형식: [`_template.md`](./_template.md)
> 적용 레벨: PRIVACY는 L1/L2가 아니라 **P(Privacy) 프로파일**에 매핑(+ MAS-EUDIW). 이 문서는 분석 편의상 criterion별로 "정적 리버싱으로 검증 가능/부분/불가"를 표시한다.
> **범위 한계(중요)**: MASVS-PRIVACY는 GDPR/ENISA 같은 법규 전체를 대체하지 않는다 — **앱 자체에서 정적/동적으로 테스트 가능한 것**에 집중한다. 정책문서·동의 적정성 등은 **리버싱만으로 판정 불가** → "플레이스토어 데이터 안전 섹션·정책문서 대조 필요"로 공백 표기.

## MASVS-PRIVACY 통제 (live 확인됨, 2026-11-18)

| 통제 | 공식 wording | 다루는 criterion 패밀리 |
|---|---|---|
| **MASVS-PRIVACY-1** | The app minimizes access to sensitive data and resources. | 권한 최소화 |
| **MASVS-PRIVACY-2** | The app prevents identification of the user. | 식별자·추적·익명화 |
| **MASVS-PRIVACY-3** | The app is transparent about data collection and usage. | 정책·수집선언·추적도메인·재현빌드 |
| **MASVS-PRIVACY-4** | The app offers user control over their data. | 데이터 관리·가시성·동의 |

MASWE 매핑(live 확인, MASWE v1.0.0 — PRIVACY는 **0066~0078** 13개):
- **PRIVACY-1** → **0066**(Inadequate Permission Management)
- **PRIVACY-2** → **0067**(Lack of Anonymization or Pseudonymisation Measures)·**0068**(Incorrect Use of Identifiers for User Tracking)·**0069**(Usage of Non-Privacy-Preserving Functionality)·**0070**(Inadequate Awareness for Privacy Relevant Actions)·**0071**(Inadequate Defaults for Privacy Relevant Actions)
- **PRIVACY-3** → **0072**(Inadequate Privacy Policy)·**0073**(Inadequate Data Collection Declarations)·**0074**(Inadequate Tracking Domains Declarations)·**0075**(Non-Reproducible Builds)
- **PRIVACY-4** → **0076**(Lack of Proper Data Management Controls)·**0077**(Inadequate Data Visibility Controls)·**0078**(Inadequate or Ambiguous User Consent Mechanisms)

> 교차: 민감 데이터 저장/누수는 [`20-storage.md`](./20-storage.md), 네트워크 전송 목적지는 [`50-network.md`](./50-network.md), 악성/과잉 수집 코드는 [`70-code.md` COD-MALWARE-01](./70-code.md). PRIVACY는 "**수집·추적·투명성·통제**" 관점.
> 분석 위치: `manifest`(권한·`<queries>`·tracking 도메인), `jadx`(트래커 SDK·식별자 수집 API), `동적`(네트워크 트래픽으로 실제 수집·목적지). 많은 항목은 **플레이스토어 데이터 안전 섹션·정책문서** 같은 외부 정보 대조가 필요.

---

## 패밀리 1 — 권한 최소화 (MASVS-PRIVACY-1)

### [PRV-PERM-01] 과잉 권한 (데이터 최소화 위반)
- **표준 매핑**: MASVS-PRIVACY-1 / MASWE-0066(Inadequate Permission Management) ✅ live (MASTG 테스트 다수)
- **적용 레벨**: P (정적 검증 **가능**)
- **어디서 보나**: manifest, jadx
- **탐지 신호**: 기능에 불필요한 위험 권한 선언(`READ_CONTACTS`·`ACCESS_FINE_LOCATION`·`READ_SMS`·`CAMERA`·`READ_MEDIA_*` 등)인데 대응 기능 없음, 런타임 권한 미요청·설명 부재, `<queries>`/`QUERY_ALL_PACKAGES` 과잉, 권한을 선언만 하고 미사용.
- **오탐 함정(FP trap)**: ① 선언됐으나 실제 기능에 쓰이는 정당 권한. ② 서드파티 SDK가 요구하는 권한(앱 본체 무관). ③ 선언 ≠ 사용 — 미사용 권한은 "최소화 위반"이나 즉시 유출은 아님.
- **검증 방법(oracle)**: ① manifest 권한 목록 ↔ 실제 사용 API xref로 "선언됐지만 미사용/기능 불명" 추출. ② 위험 권한별 대응 기능 존재 확인. (⚠️ `--no-res`면 manifest 미추출)
- **우회 포인트**: (프라이버시 영향) 과잉 권한 = 공격면·수집면 확대. 권한 악용 데이터는 STORAGE/NETWORK 교차.
- **신뢰도 기본값**: 가설 → **승급**: 미사용/과잉 권한을 manifest↔코드 xref로 특정.
- **금융 가중**: 아니오

---

## 패밀리 2 — 사용자 식별 방지 · 추적 (MASVS-PRIVACY-2)

### [PRV-TRACKID-01] 지속 식별자의 추적 목적 오용
- **표준 매핑**: MASVS-PRIVACY-2 / MASWE-0068(Incorrect Use of Identifiers for User Tracking)·MASWE-0067(Lack of Anonymization) ✅ live
- **적용 레벨**: P (정적/동적 **가능**)
- **어디서 보나**: jadx, 동적(트래픽)
- **탐지 신호**: 리셋 불가 하드웨어 식별자 수집(IMEI `getDeviceId`·시리얼 `Build.SERIAL`·MAC), `ANDROID_ID`를 광고/추적에 교차앱 식별로 사용, 재설정 광고ID(AAID) 대신 영구 식별자, 식별자를 익명화/가명화 없이 서버·트래커 전송.
- **오탐 함정**: ① 식별자를 **앱 내부 기능**(디바이스 바인딩·세션)에만 쓰고 추적 아님(그건 [`10-resilience.md` RES-BIND-01](./10-resilience.md)). ② 적법 동의 하의 분석. ③ AAID 정상 사용.
- **검증 방법(oracle)**: ① 식별자 수집 API → 전송/트래커 sink까지 xref(추적 목적인지). ② 동적: 트래픽에서 식별자가 제3자로 가는지.
- **우회 포인트**: (프라이버시 영향) 영구 식별자 추적 → 교차앱 프로파일링·재설정 불가. 전송 목적지는 [`50-network.md`](./50-network.md) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 영구 식별자가 추적/제3자 전송에 쓰임을 xref + 트래픽 확인.
- **금융 가중**: 아니오

### [PRV-NONPP-01] 비(非)프라이버시보존 기능 · 부적절 기본값/고지
- **표준 매핑**: MASVS-PRIVACY-2 / MASWE-0069(Usage of Non-Privacy-Preserving Functionality)·MASWE-0070(Inadequate Awareness)·MASWE-0071(Inadequate Defaults) ✅ live
- **적용 레벨**: P (부분 — 코드+동적 **일부**, UX 고지는 외부대조)
- **어디서 보나**: jadx, manifest, 동적
- **탐지 신호**: 프라이버시 침해 SDK/기능(백그라운드 위치·연속 수집·지문화 fingerprinting), 민감 동작(위치·마이크·카메라)이 **기본 on**이거나 사용자 고지 없이 수행, opt-out만 제공(opt-in 미제공).
- **오탐 함정**: ① 기능에 필수적이고 고지된 수집. ② 고지/인식(awareness)·기본값(default) 적정성은 **UI/정책 대조**가 필요 — 코드만으론 부분 판정. ③ 플랫폼 인디케이터(마이크/카메라 점)로 완화.
- **검증 방법(oracle)**: ① 민감 수집 기능의 기본 상태·트리거 코드 확인. ② 동적: 사용자 동작 없이 수집되는지. ③ 고지/기본값 적정성은 정책·UI 대조(외부정보).
- **우회 포인트**: (프라이버시 영향) 은밀/기본 수집으로 사용자 인지 없이 데이터 획득.
- **신뢰도 기본값**: 가설 → **승급**: 코드/동적으로 확인 가능한 부분만. 고지·기본값 정책성은 "외부 대조 필요"로 공백.
- **금융 가중**: 아니오

---

## 패밀리 3 — 투명성 (MASVS-PRIVACY-3)

### [PRV-TRACKDOM-01] 추적 도메인 · 수집 선언 불일치
- **표준 매핑**: MASVS-PRIVACY-3 / MASWE-0074(Inadequate Tracking Domains Declarations)·MASWE-0073(Inadequate Data Collection Declarations) ✅ live
- **적용 레벨**: P (동적+선언 대조 **가능**)
- **어디서 보나**: jadx, manifest, 동적(트래픽)
- **탐지 신호**: 코드/트래픽의 실제 트래커·수집 도메인이 플레이스토어 **데이터 안전 섹션**·`<meta-data>` 선언과 불일치, 미선언 제3자 분석/광고 SDK, 선언보다 많은 데이터 전송.
- **오탐 함정**: ① CDN·기능 도메인을 트래커로 오인. ② 선언과 코드의 범주 매핑 모호 — 보수적 판정. ③ 동의 하의 선언된 수집.
- **검증 방법(oracle)**: ① 코드의 트래커 SDK·도메인 추출 + 동적 트래픽 목적지 → 스토어 데이터안전/정책 선언과 대조. ② 선언 외 전송 식별.
- **우회 포인트**: (프라이버시 영향) 미선언 추적·과다 수집. 전송 암호화/피닝은 [`50-network.md`](./50-network.md) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 실제 수집·목적지 ↔ 선언 불일치를 동적으로 확인.
- **금융 가중**: 아니오

### [PRV-TRANSPARENCY-01] 정책·재현빌드 등 투명성 산출물 부재
- **표준 매핑**: MASVS-PRIVACY-3 / MASWE-0072(Inadequate Privacy Policy)·MASWE-0075(Non-Reproducible Builds) ✅ live
- **적용 레벨**: P (리버싱 **부분/불가** — 주로 외부 산출물)
- **어디서 보나**: 외부(정책문서·스토어), 빌드 메타
- **탐지 신호**: 프라이버시 정책 부재·불명확·수집 실태와 불일치, 재현 가능 빌드 미지원(공급망 투명성).
- **오탐 함정**: 리버싱 범위 밖 — 정책 품질·법적 적정성은 **법무/정책 검토** 영역. 보안 리버싱 리포트에선 "확인 범위 밖"으로 경계.
- **검증 방법(oracle)**: 정책문서·스토어 리스팅 대조(외부). 코드로는 수집 실태만 제공해 불일치 입력으로만 기여.
- **우회 포인트**: 해당 없음(투명성/거버넌스 항목).
- **신뢰도 기본값**: 가설 → **대체로 "리버싱 범위 밖 — 외부 대조 필요"로 공백 표기**.
- **금융 가중**: 아니오

---

## 패밀리 4 — 사용자 통제 (MASVS-PRIVACY-4)

### [PRV-CONSENT-01] 모호/부적절한 동의 메커니즘
- **표준 매핑**: MASVS-PRIVACY-4 / MASWE-0078(Inadequate or Ambiguous User Consent Mechanisms) ✅ live
- **적용 레벨**: P (부분 — 동의 **전** 수집 여부는 동적 검증 가능)
- **어디서 보나**: jadx, 동적
- **탐지 신호**: 동의 획득 **전에** 데이터 수집/전송(앱 최초 실행 트래픽), 동의 UI 부재인데 민감 수집, 동의 철회 경로 없음, 포괄 동의(세분화 부재).
- **오탐 함정**: ① 동의 흐름이 서버/웹뷰에 있어 코드에 안 보일 수 있음. ② 적정성(wording·세분화)은 UX/법무 영역 — 코드는 "동의 전 수집" 사실만. ③ 필수 기능 데이터.
- **검증 방법(oracle)**: ① 앱 최초 실행~동의 시점 사이 네트워크 수집 여부 동적 확인(핵심 oracle). ② 동의 철회 경로 코드 존재 확인.
- **우회 포인트**: (프라이버시 영향) 동의 전 수집·철회 불가.
- **신뢰도 기본값**: 가설 → **승급**: 동의 전 수집/전송을 동적 트래픽으로 확인.
- **금융 가중**: 아니오

### [PRV-DATACTRL-01] 데이터 관리·가시성 통제 부재
- **표준 매핑**: MASVS-PRIVACY-4 / MASWE-0076(Lack of Proper Data Management Controls)·MASWE-0077(Inadequate Data Visibility Controls) ✅ live
- **적용 레벨**: P (부분 — 기능 존재 여부 정적 **가능**)
- **어디서 보나**: jadx
- **탐지 신호**: 사용자 데이터 삭제·내보내기·수정·프라이버시 설정 변경 기능 부재, 수집 데이터 열람 수단 없음.
- **오탐 함정**: ① 기능이 서버측/웹 콘솔에 있을 수 있음(앱 코드에 없다고 부재 단정 금지). ② 계정 삭제가 고객센터 경유일 수 있음.
- **검증 방법(oracle)**: ① 데이터 삭제/내보내기/설정 화면·API 코드 존재 확인. ② 서버측 제공 여부 교차(외부).
- **우회 포인트**: (프라이버시 영향) 사용자가 자기 데이터 통제 불가.
- **신뢰도 기본값**: 가설 → **승급**: 통제 기능 부재를 코드+서버 교차로 확인.
- **금융 가중**: 아니오

---

## 커버리지 체크리스트 (2차 패스 — 공백 점검용)

- [ ] PRV-PERM-01 과잉 권한 (MASWE-0066) — 정적 가능
- [ ] PRV-TRACKID-01 식별자 추적 오용 (MASWE-0067/0068) — 정적+동적
- [ ] PRV-NONPP-01 비프라이버시보존·기본값·고지 (MASWE-0069/0070/0071) — 부분
- [ ] PRV-TRACKDOM-01 추적도메인·수집선언 불일치 (MASWE-0073/0074) — 동적+선언대조
- [ ] PRV-TRANSPARENCY-01 정책·재현빌드 (MASWE-0072/0075) — 리버싱 범위 밖(외부대조)
- [ ] PRV-CONSENT-01 동의 메커니즘 (MASWE-0078) — 동의 전 수집 동적검증
- [ ] PRV-DATACTRL-01 데이터 관리·가시성 (MASWE-0076/0077) — 부분

> ⚠️ **PRIVACY는 리버싱 단독 검증 한계가 큼**: 권한(0066)·식별자(0068)·동의 전 수집(0078)은 정적/동적으로 잡히지만, 정책 적정성(0072)·고지(0070)·선언 일치(0073/0074)는 **플레이스토어 데이터 안전 섹션·정책문서·법무 검토** 대조가 필요. 리포트에선 "리버싱으로 확인된 사실"과 "외부 대조 필요"를 분리 기술.

---

## 출처 (live 확인, 2026-11-18)

- MASVS-PRIVACY: [mas.owasp.org/MASVS/12-MASVS-PRIVACY](https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/) · v2.1.0 신설: [릴리스 노트](https://mas.owasp.org/news/2024/01/18/masvs-v210-release--masvs-privacy/)
- PRIVACY-1: [controls/MASVS-PRIVACY-1](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/) · PRIVACY-3: [controls/MASVS-PRIVACY-3](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/) · PRIVACY-4: [controls/MASVS-PRIVACY-4](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/)
- MASWE 전체: [mas.owasp.org/MASWE](https://mas.owasp.org/MASWE/) (PRIVACY: 0066~0078, v1.0.0)

> **2026-11-18 live 확인**: MASVS-PRIVACY-1~4 wording, MASWE-0066~0078 13개 실존·카테고리 매핑 확인. PRIVACY는 P 프로파일(+MAS-EUDIW) 매핑, L1/L2 아님. 리버싱 검증 가능 범위(권한·식별자·동의전수집)와 외부대조 필요 범위(정책·고지·선언)를 criterion별로 구분 표기.
