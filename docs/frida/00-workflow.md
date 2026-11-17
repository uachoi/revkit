# Frida 동적 검증 워크플로우 — 가설 → 확정 승급

> 이 문서는 revkit 파이프라인의 **동적 단계**를 정의한다. 정적 분석(1차 `/rev-native`·`/rev-jadx`)과
> 재분류(2차 `/rev-verify`)가 끝난 뒤, `가설`로 남은 발견을 **실제 런타임에서 재현**해 `확정`으로 올린다.
> 명령: [`/rev-frida`](../../.claude/commands/rev-frida.md). 템플릿: [`templates/`](./templates/).

## 목적과 파이프라인상 위치

```
/rev-check → /rev-jadx → /rev-native → /rev-verify → [/rev-frida] → /rev-report
   사전점검    Java 1차     네이티브 1차    2차 재분류     동적 확정       종합
```

- **왜 필요한가**: criteria의 모든 승급조건은 "정적 교차대조 **AND** (가능 시) 동적 재현"을 요구한다. 정적 2차의 상한은 **FP함정 배제 + 어셈블리 교차대조**까지이고, "실제로 우회되는가"는 Frida로만 증명된다. 그래서 2차는 거의 항상 `확정 0 / 가설 N`으로 끝나며, 이 단계가 그 `가설`을 받는다.
- **rev-all과의 관계**: Ghidra처럼 **수동 게이트**다(기기 연결·frida-server 기동이 필요). `rev-all`은 자동으로 여기까지 돌리지 않고, `/rev-verify` 후 사용자에게 넘긴다.
- **레포 방침**: CLAUDE.md상 **"Frida = 스크립트만, 실행은 수동/후속"**. `/rev-frida`는 훅 스크립트를 **생성·문서화**하고, 실제 실행은 분석가가 손으로 한다.

## 환경

- **Frida 16.2.1 고정.** 모든 템플릿·생성 스크립트는 16.2.x API(`Java.perform`/`Java.use`, `Interceptor.attach/replace`, `Module.findExportByName`). **클라이언트와 기기 `frida-server`가 반드시 동일 버전(16.2.1)** — 불일치가 "spawn 시 앱이 열리기 전에 끊김"의 1순위 원인이다.
- 루팅 단말 가정(또는 frida-gadget 임베드 — 아래). 연결 확인: `frida-ps -U`. 버전 확인: `frida --version`.

## 실행 방식 — 2가지

### (기본) spawn + dlopen 조기후킹

```
frida -U -f <패키지명> -l targets/<대상>/frida/<script>.js
```

- CLI가 **스크립트 로드 후 자동 resume**한다(별도 `%resume` 불필요).
- 스크립트 최상단에서 `android_dlopen_ext`(및 `dlopen`)를 후킹해, 대상 `.so`가 로드되는 **그 순간** export에 `Interceptor`를 설치한다([`_bootstrap.js`](./templates/_bootstrap.js)).
- **왜 RASP엔 spawn이 맞나**: RASP의 탐지 루틴은 `JNI_OnLoad`/초기화 근처에서 일찍 돈다. attach는 그 시점을 **이미 지난** 뒤 붙으므로 조기 탐지를 놓친다. spawn+조기후킹은 **탐지 루프가 돌기 전에 선점**한다.
- **spawn 신뢰성 팁**(앱이 안 열리거나 조기 종료될 때):
  1. **버전 일치**(16.2.1) 재확인 — 가장 흔한 원인.
  2. **멀티프로세스**: 실제 로직이 자식/`:remote` 프로세스면 엉뚱한 pid에 붙은 것 — `frida-ps -Ua`로 대상 프로세스 확인.
  3. **조기 self-kill**: RASP가 탐지 즉시 종료 → `_bootstrap.js`의 dlopen 선점이 탐지보다 먼저 걸리는지 확인(로그로 설치 시점 출력).

### (폴백) attach

```
# 기기(루팅)
frida-server &          # 16.2.1
# 로컬 PC
frida -U -n "<앱이름>" -l targets/<대상>/frida/<script>.js
```

- spawn이 반복 실패할 때 사용. 단 **조기 탐지는 놓칠 수 있음** — 주기적 모니터 루프형 RASP라면 다음 탐지 주기를 후킹으로 잡을 수 있다.

## 탐지 회피 (대상이 Frida를 탐지할 때)

RASP가 Frida 자체를 탐지하면(RES-HOOK-01) 위 기본 frida-server가 **먼저 걸린다**. 시그니처:
- **포트**: 로컬 `127.0.0.1:27042`/`27043`(Frida D-Bus) connect 시도 탐지.
- **maps**: `/proc/self/maps`에 `frida`/`gum-js`/`gadget`/`frida-agent` 매핑 문자열.
- **스레드명**: `gum-js-loop`/`gmain`/`gdbus`/`pool-frida`.

회피책:
- **패치된 stealth frida-server**(strongR-frida / florida / hluda 류) — 스레드명·maps 시그니처를 리네임/은닉.
- **비표준 포트**로 기동: `frida-server -l 127.0.0.1:<임의포트>` 후 해당 포트로 접속(27042/3 스캔 회피).
- 그래도 collector를 선점 후킹하면 탐지 결과 자체를 clean으로 만들 수 있으므로, **stealth server + collector 무력화**가 보완 관계다.

## 템플릿 3종

| 템플릿 | 용도 | 핵심 |
|---|---|---|
| [`_bootstrap.js`](./templates/_bootstrap.js) | 공통 부트스트랩(참조본) | `android_dlopen_ext`/`dlopen` 후킹 → 대상 `.so` 로드 선점 → export 후킹 설치 콜백. `frida -l`은 단일 파일만 로드하므로 각 스크립트가 이 패턴을 **인라인 복제**(frida-compile 번들링 시에만 import) |
| [`collector-neutralize.js`](./templates/collector-neutralize.js) | ⓐ collector 무력화 | 네이티브 `native*Evidence` onLeave 반환을 빈 문자열로, Java `appLayerDetects*` 반환을 false로 |
| [`report-forge.js`](./templates/report-forge.js) | ⓑ 서명 리포트 위조 | 추출 HMAC 키로 clean evidence 리포트를 재서명해 서버 claim 통과 |

사용법: 템플릿 상단 상수(`TARGET_SO`, `NATIVE_COLLECTORS`, `JAVA_DETECTORS`, `HMAC_KEY`)를 대상 노트(`native/*.md`, `java_analysis.md`)의 실제 심볼·상수로 채운다. `/rev-frida`가 이 파라미터화를 자동 수행한다.

## 결과 환류 — 승급 규칙

- 실행 결과가 **탐지 우회 재현**(루팅/디버거/후킹 상태에서 앱이 clean 판정) 또는 **claim 통과**(위조 리포트가 서버 검증 통과)이면, 해당 발견을 `verify.md`에서 **`가설→확정`**으로 갱신하고 `2차 메모`에 재현 근거를 적는다.
- **동적 재현 근거가 실제로 있어야 `확정`**(CLAUDE.md). 추론만으론 올리지 않는다. 특히 난독화 `.so`는 어셈블리 교차대조 + 동적 재현 둘 다 전까지 `가설` 유지.
- **다층 탐지는 쌍으로**: native collector와 Java 탐지가 쌍이면 **한쪽만 막으면 FN** — 둘 다 무력화된 상태에서 재현해야 `확정`.

---

## 예시 — scn00 (설명용, 적용 지시 아님)

> 아래는 `libscn00monitor.so`(EQST FinTech 워게임, **증거수집형** RASP)를 두고 이 워크플로우가 어떻게 매핑되는지 보여주는 **설명**이다. 실제 적용/실행은 사용자 판단에 따른다.

- **collector 무력화(ⓐ)**: 네이티브 `nativeRootEvidence`/`nativeFridaEvidence`/`nativeDebuggerEvidence`의 반환 버퍼를 빈 문자열로, Java `appLayerDetectsRoot`/`...Frida`/`...Debugger`(`Scn00MonitorModule`)를 false로 후킹 → 수집 증거가 비어 리포트가 정당하게 "clean". **native+Java가 쌍**이므로 둘 다 처리해야 함.
- **리포트 위조(ⓑ)**: 추출된 HMAC 키 `SCN00-monitor-hmac-key-v1-eqstlb`로 `scenario|arg|flag|evidence` payload를 `base64(payload).hex(hmac)` 형식으로 재서명 → `/scenario00/monitor/claim` 통과. 증거수집형의 신뢰근거(서명키)가 클라이언트 상수로 노출됐기 때문에 성립하는 경로.
- **피닝(NET-PIN-02)**: `nativeSignedReportPinning`이 네이티브 피닝이라 **Java unpinning으론 안 풀린다** — 네이티브 수집 무력화 또는 HMAC 위조로 우회.

자세한 criterion·판정은 [`docs/criteria/10-resilience.md`](../criteria/10-resilience.md)(§RASP 유형), [`docs/criteria/50-network.md`](../criteria/50-network.md)(NET-PIN-02) 참조.
