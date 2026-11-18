# 분석 기준(criteria) 인덱스 — MASVS v2 기반

이 디렉터리(`docs/criteria/`)는 revkit의 **분석 기준 문서**다. 기존 워크플로우 문서(`docs/APK 리버싱 워크플로우 ...md`)가
"어떻게 돌리나(파이프라인)"라면, 여기는 **"무슨 기준으로 취약/방어를 판단하나"**를 OWASP MAS 표준에 묶어 명문화한다.

- 축: **OWASP MASVS v2.x** 8개 카테고리
- 각 criterion 작성 형식: [`_template.md`](./_template.md)
- 현재 작성 범위: **8개 카테고리 전부 작성됨** — RESILIENCE ([`10`](./10-resilience.md)) · STORAGE ([`20`](./20-storage.md)) · CRYPTO ([`30`](./30-crypto.md)) · AUTH ([`40`](./40-auth.md)) · NETWORK ([`50`](./50-network.md)) · PLATFORM ([`60`](./60-platform.md)) · CODE ([`70`](./70-code.md)) · PRIVACY ([`80`](./80-privacy.md)). (2026-11-18 완비, OWASP ID live 확인)

> ### criteria는 리버싱을 대체하지 않는다 (중요)
> 분석의 **메인 축은 여전히 분석가의 리버싱**이다 — 디컴파일 → 함수명 검색 → 디컴파일 코드·분기 분석 → 우회 지점 특정 → 앱 변조 / Frida 후킹. MASVS criteria는 그 작업을 **대체하는 게 아니라 두 가지로 얹힌다**:
> 1. **사냥 체크리스트(overlay)** — "이 앱에 이 벡터(루트/디버거/에뮬/후킹/무결성/…)가 있나"를 체계적으로 훑어 **놓치는 공격면을 줄인다.**
> 2. **리포트 표준 용어** — 발견에 MASVS/MASWE 이름표를 붙여 **고객·감사에서 통하는 표준 용어**로 보고한다.
>
> 즉 RESILIENCE 검증은 "루트 탐지가 있다"에서 끝나는 게 아니라 **"실제로 우회되는가"를 증명**하는 것이고, 그 증명 방법이 바로 당신이 하던 Ghidra/Frida 리버싱이다 — MASTG-RESILIENCE 테스트가 요구하는 정석 절차와 같다.

---

## MASVS v2 — 8개 카테고리 커버리지

| 카테고리 | 무엇을 보나 | 주 분석 위치 | 적용 레벨 | 커버리지 | 파일 |
|---|---|---|---|---|---|
| **STORAGE** | 민감 데이터 저장(SharedPrefs, SQLite, 파일, 로그, 클립보드, 백업) | jadx, manifest | L1/L2 | **작성됨** | [`20-storage.md`](./20-storage.md) |
| **CRYPTO** | 암호 구현(하드코딩 키, 약한 알고리즘 DES/ECB/MD5, IV 재사용, 안전치 않은 난수, 커스텀 크립토, KDF·키저장) | jadx, ghidra | L1/L2 | **작성됨** | [`30-crypto.md`](./30-crypto.md) |
| **AUTH** | 인증·인가(로컬 인증, 생체, 세션, OAuth, PIN/KDF, step-up) | jadx, ghidra | L1/L2 | **작성됨** | [`40-auth.md`](./40-auth.md) |
| **NETWORK** | TLS, 인증서 피닝, 평문 통신 | jadx, ghidra, manifest | L1/L2 | **작성됨** | [`50-network.md`](./50-network.md) |
| **PLATFORM** | IPC·exported 컴포넌트·WebView·권한·딥링크·인텐트 | manifest, jadx | L1/L2 | **작성됨** | [`60-platform.md`](./60-platform.md) |
| **CODE** | 코드 품질(인젝션, 오래된 라이브러리/CVE, 동적로딩, 네이티브 하드닝) | manifest, jadx, 의존성 | L1/L2 | **작성됨** | [`70-code.md`](./70-code.md) |
| **RESILIENCE** | 안티리버싱·변조탐지(루트/디버거/에뮬/후킹 탐지, 무결성, 난독화, 디바이스 바인딩) | ghidra, jadx | **R** | **작성됨** | [`10-resilience.md`](./10-resilience.md) |
| **PRIVACY** | 데이터 최소화·추적·동의·민감정보 노출 | manifest, jadx, 트래커 | P | **작성됨** | [`80-privacy.md`](./80-privacy.md) |

> **지금 툴의 무게중심은 RESILIENCE**(네이티브 RASP·루트/Frida/디버거 탐지·서명검사)에 있고, **8개 카테고리 criteria가 모두 작성**돼 커버리지 공백 점검이 전 카테고리 대상으로 가능하다.
> 확장 경로였던 (1) RESILIENCE 2-pass 완성 → (2) CRYPTO/NETWORK/AUTH → (3) STORAGE/PLATFORM/CODE/PRIVACY 는 **2026-11-18 완료**.

### 적용 레벨 (MASVS 검증 레벨)

- **L1(표준)**: 모든 앱이 기본으로 만족해야 하는 통제.
- **L2(심화·방어심층)**: 민감 데이터·금융·헬스케어 등 높은 위험 앱에 추가되는 통제.
- **R(resilience)**: 리버싱·변조 저항. **R의 부재 자체는 취약점이 아님**(OWASP 명시) — 위협모델에 따라 "있어야 할 방어가 없다/약하다/우회된다"로 평가한다. RESILIENCE 카테고리가 여기 해당.

---

## 타깃 성격에 따른 가중 (금융 ↔ 일반)

이 키트는 **금융/결제·인증 앱을 주로 다루되 일반 앱에도 쓸 수 있어야** 한다. 모든 criterion은 **일반 앱에도 성립하는 generic core**를 갖고,
금융·결제 맥락에서 특히 중대한 것만 `금융 가중: 예` 플래그로 구분한다. 분석 시작 시 **프로파일**을 하나 고른다:

- **금융/결제·인증 프로파일** — `AUTH` · `CRYPTO` · `NETWORK` · `RESILIENCE`를 우선순위 상단으로 올리고, `금융 가중: 예` criterion을 필수 체크로 승격. (송금·생체·PIN·피닝·RASP 중심 타깃)
- **일반 프로파일** — 8개 카테고리를 균등 가중. `금융 가중` 플래그는 우선순위에만 영향, 체크 범위는 동일.

> 프로파일은 "무엇을 **먼저/반드시** 보나"의 우선순위만 바꾼다. criterion 자체를 끄지 않는다 — 커버리지 공백 점검(2차)이 모든 카테고리를 대상으로 돌기 때문.

---

## 2-pass 분석 흐름

```
[1차: 분석 · 발견]                         [2차: 검증 · 누락점검]
criteria 문서의 '탐지 신호'를 따라        각 발견을 그 criterion의
.so/Java/manifest에서 발견을 수집    →    '오탐 함정'·'검증 방법'에 대조
  · 발견마다 criterion ID 태깅              · 확정 / 가설 / 기각 재분류
  · 신뢰도 = 가설 (기본)                    · (어셈블리 교차대조 + 가능시 Frida)
                                           · 커버리지 공백: 안 본 criterion 목록화
         │                                         │
         └──────────────→  report.md  ←───────────┘
                  (확정만 단정, 가설/기각/공백 명시)
```

- **1차**는 `/rev-jadx`·`/rev-native`가 수행하며 **발견마다 criterion ID를 태깅**한다(배선 완료).
- **2차**는 `/rev-verify`([`.claude/commands/rev-verify.md`](../../.claude/commands/rev-verify.md))가 태깅된 발견을 criterion에 1:1 대조해 재분류한다.
- **동적(확정 승급)**은 `/rev-frida`([워크플로우](../frida/00-workflow.md))가 2차의 `가설`을 런타임 재현해 `확정`으로 올린다 — 수동 게이트(기기·frida-server 필요), `/rev-verify` 뒤·`/rev-report` 앞.

---

## 별도 트랙 — 비즈니스 로직 (MASVS 밖)

**비즈니스 로직 우회는 MASVS 카테고리에 넣지 않는다 — 별도 트랙으로 둔다.** 앱마다 로직이 제각각이라
체크리스트로 못 잡기 때문이다(예: 송금인증 우회, Race/TOCTOU, 소유자·PIN 검증 부재, 번호 brute force,
"번호·코드 하나로 가치가 증명되는 자산"의 결함). 이건 표준 통제 항목이 아니라 **앱 흐름을 이해해 빈틈을 찾는
전통적 모의해킹 추론**이다.

- **MASVS-AUTH와 혼동 금지**: AUTH는 인증·세션·OAuth "통제가 있나/충분한가"를 본다. **순수 로직 우회는 AUTH 밖**이다 — 억지로 MASVS 칸에 밀어넣지 말 것.
- 이 트랙은 `biz-logic-security-review` 스킬이 담당한다. criteria 분석 중 **인증/인가·자산이동 흐름**이 나오면 그 스킬의 체크리스트를 교차 적용해 로직 결함을 **별도로** 추적(특히 금융 가중 흐름).
- 리포트에서는 RESILIENCE/기타 MASVS 발견과 **구분된 섹션**으로 다룬다.

---

## 출처

- MASVS v2: [mas.owasp.org/MASVS](https://mas.owasp.org/MASVS/)
- MASVS-RESILIENCE: [mas.owasp.org/MASVS/11-MASVS-RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
- MASWE: [mas.owasp.org/MASWE](https://mas.owasp.org/MASWE/)
- MASTG Tests: [mas.owasp.org/MASTG/tests](https://mas.owasp.org/MASTG/tests/)
