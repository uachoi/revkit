---
description: "Frida 동적 검증 — 2차 '가설'을 '확정'으로 승급(훅 스크립트 생성, 실행은 수동)"
argument-hint: [대상]
allowed-tools: Read, Glob, Grep, Write, Edit
---

> **전제: 2차(`/rev-verify`)가 끝나 `가설`로 남은 발견이 있다.**
> 이 단계의 본령은 2차에서 `가설`로 남은 발견을 **동적 재현(Frida)으로 `확정` 승급**시키는 것이다.
> 정적 분석(1차)·재분류(2차)가 할 수 없는 "실제로 우회되는가"의 증명 단계다. **스크립트 생성·문서화까지가 이 명령의 몫이고, 실제 frida 실행은 사용자가 수동으로 한다**(CLAUDE.md: "Frida = scripts only, 실행은 수동/후속").

대상 `$1`의 `가설` 발견을 criterion별 훅 템플릿에 매핑해 `targets/$1/frida/*.js` 스크립트를 생성하고, 실행 방법을 안내한다. 사용자가 실행 결과를 주면 해당 발견을 `가설→확정`으로 갱신한다.

## 전제
- 2차 산출물 존재: `targets/$1/notes/verify.md`(재분류 완료, `가설` 목록 있음). **없으면 멈추고 `/rev-verify $1` 먼저 안내.**
- 심볼 출처: `targets/$1/notes/native/*.md`(네이티브 export·주소), `targets/$1/notes/java_analysis.md`(Java 클래스/메서드·하드코딩 상수).
- 템플릿: `docs/frida/templates/`(`_bootstrap.js`, `collector-neutralize.js`, `report-forge.js`). 워크플로우: [`docs/frida/00-workflow.md`](../../docs/frida/00-workflow.md).
- **Frida 16.2.1 고정** — 생성 스크립트는 16.2.x API. 기기 `frida-server`도 **동일 버전**이어야 함(버전 불일치가 spawn 실패 1순위 원인).

## 0. RASP 유형부터 판별 (우회 모델을 좌우)
스크립트를 고르기 전에 대상이 **증거수집형**인지 **로컬차단형**인지 먼저 본다([`docs/criteria/10-resilience.md` §RASP 유형](../../docs/criteria/10-resilience.md) 참조). verify.md/native 노트에 이미 판별돼 있으면 그대로 쓴다.
- **로컬차단형**(`if (detected) finish()/kill`) → **분기 뒤집기**: 탐지 함수 반환 고정 / 대응 분기 스킵.
- **증거수집형**(수집→서명→서버 판정) → 뒤집을 분기가 없다. **① collector 무력화**(빈 결과 반환) 또는 **② 서명키 위조**(clean 리포트). → `collector-neutralize.js` / `report-forge.js`.

## 1. `가설` 발견 + criterion 수집
`verify.md`의 "발견별 판정"에서 **판정=`가설`**인 발견과 그 criterion ID를 전부 모은다. `확정`·`기각`은 제외(재현 불필요). `공백`은 1차 재실행 대상이지 Frida 대상 아님.

## 2. criterion → 훅 템플릿 매핑
| criterion(가설) | 템플릿 | 후킹 대상 |
|---|---|---|
| RES-ROOT-01/02 · RES-DBG-01/02 · RES-HOOK-01/02 · RES-EMU-01 | `collector-neutralize.js` | 네이티브 collector export(`native*Evidence`) onLeave 반환 clean + Java 탐지 메서드(`appLayerDetects*`) 반환 false |
| RES-INTEG-01/02 (서명/무결성) | `collector-neutralize.js`(서명 getter 섹션) | APK 서명 getter(`signingCertSha256`/`getPackageInfo`) 반환을 **정품 해시로 위장**, 또는 네이티브 해시 산출 후킹 |
| RES-INTEG-03 (attestation) | (주석 가이드) | **서버검증형이면 클라 후킹으론 못 뚫음** — 우회 난이도 상향으로 기록. 클라 판단형일 때만 결과 후킹 |
| NET-PIN-01/02 (피닝) | `collector-neutralize.js` + (증거수집형이면)`report-forge.js` | **네이티브 피닝은 Java/SSLContext unpinning으로 안 풀림**([`50-network.md` NET-PIN-02](../../docs/criteria/50-network.md)) — 네이티브 비교/수집 함수 후킹 또는 HMAC 키로 리포트 위조 |
| (증거수집형 RASP 전반) | `report-forge.js` | `nativeSignedReport*`를 후킹해 clean evidence 리포트를 추출 HMAC 키로 재서명 |

## 3. 스크립트 생성 → `targets/$1/frida/*.js`
- 템플릿을 복사해 **대상 심볼로 파라미터화**한다: `_bootstrap.js`의 `TARGET_SO`, `collector-neutralize.js`의 `NATIVE_COLLECTORS`/`JAVA_DETECTORS`, `report-forge.js`의 `HMAC_KEY`·payload 포맷을 native/java 노트의 실제 심볼·상수로 채운다.
- 파일명은 목적별로: `collector-neutralize.js`, `report-forge.js`(필요 시 criterion별 분리). `targets/$1/frida/`는 **커밋 대상**(`.gitignore` 예외).
- **실제 주소 하드코딩 금지** — export 이름/클래스.메서드/상수로 쓴다(주소는 리베이스마다 바뀜). 주소가 꼭 필요하면 `Module.getBaseAddress()` 상대 오프셋으로.
- **네이티브는 풀 JNI export 이름으로 채운다** — `Java_<패키지_언더스코어>_<클래스>_<메서드>`(짧은 이름은 `findExportByName` 실패). RegisterNatives 동적등록형이면 export가 없으니 그 지점을 후킹. (scn00 스모크에서 풀 JNI 이름 resolve 실증됨 — `targets/scn00/frida/smoke.js` 참조.)

## 4. 실행 방법 안내 (사용자가 수동 실행)
- **기본(spawn + 조기후킹)**: `frida -U -f <패키지> -l targets/$1/frida/<script>.js` — CLI가 로드 후 자동 resume. 스크립트 최상단 `android_dlopen_ext` 후킹이 **탐지 루프 전에** 선점(`_bootstrap.js`).
- **폴백(attach)**: 기기에 `frida-server &`(16.2.1) → `frida -U -n "<앱이름>" -l targets/$1/frida/<script>.js`. spawn이 조기 종료되면 사용.
- 연결 확인: `frida-ps -U`. 버전 확인: `frida --version`(16.2.1이어야 함).
- 대상이 Frida를 탐지하면(포트 27042/3·maps·스레드명) **stealth frida-server + 비표준 포트** 필요 — [`00-workflow.md` §탐지 회피](../../docs/frida/00-workflow.md).

## 5. 결과 환류 (가설 → 확정)
사용자가 실행 결과를 주면:
- **탐지 우회 재현 성공**(루팅/디버거/후킹 상태에서 앱이 clean 판정) → 해당 RES-* 발견을 `verify.md`에서 **`가설→확정`**으로 갱신, `2차 메모`에 재현 근거(어떤 훅으로 무엇이 통과) 기록.
- **claim 통과**(위조 리포트가 서버 `/.../claim` 통과) → 서명키 유출·NET-PIN 발견 `확정`.
- 재현 실패/부분 → `가설` 유지하고 **무엇이 막혔는지**(다층 탐지 중 어느 경로) 기록.
> CLAUDE.md 규칙: 동적 재현 근거가 실제로 있어야 `확정`. 추론만으로 올리지 말 것.

## 주의
- **frida-server ↔ 클라이언트 버전 일치(16.2.1).** 불일치면 spawn이 앱 열리기 전 끊김.
- **다층 탐지는 쌍으로 무력화.** native collector와 Java `appLayerDetects*`가 쌍이면 **한쪽만 막으면 FN**(앱이 다른 경로로 재탐지). verify.md의 "쌍" 표기 확인.
- **증거수집형은 분기 패치 무의미.** 로컬 바이너리 패치만으론 서버가 거부 → collector 무력화 또는 서명키 위조로 간다.
- 실행은 수동. 이 명령은 스크립트 생성·안내·결과 환류까지만.

승급된 `확정`은 `/rev-report $1`로 최종 보고서에 반영한다.
