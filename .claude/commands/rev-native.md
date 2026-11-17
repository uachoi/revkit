---
description: Ghidra MCP로 네이티브 .so 분석 (여러 .so 전수 순회)
argument-hint: [대상]
allowed-tools: Read, Glob, Grep, Write, Edit
---

대상 `$1`의 네이티브 `.so`를 Ghidra MCP로 분석한다. **전제: Ghidra CodeBrowser에 분석할 `.so`가 import·analyze된 채 열려 있어야 한다**(`mcp__ghidra__*` 도구 사용). 안 열려 있으면 멈추고 안내만 한다.

## 분석 순서 — 빠짐없이 + 정확하게
0. **분석 기준 로드** — `docs/criteria/10-resilience.md` 및 `docs/criteria/50-network.md`(네이티브 피닝 `NET-PIN-02`), `docs/criteria/30-crypto.md`(.so의 하드코딩 키 `CRY-HARDKEY-01`·커스텀 크립토 등 — 그 외 해당 카테고리 기준 문서 포함)를 **먼저 읽는다**. 각 criterion의 `탐지 신호`·`오탐 함정`이 "무엇을 어떤 패턴으로 찾을지"의 기준이고, 발견은 반드시 그 criterion ID로 태깅한다.
0b. **기존 노트 먼저 읽기 (중복 분석 금지)** — 분석 전에 이 타깃의 기존 노트(`targets/$1/notes/java_analysis.md`, `notes/native/*.md`, 레거시 `notes/native_analysis.md`)를 **전부 읽는다**. 이미 분석된 내용은 **처음부터 다시 파지 말고**, criterion ID 태깅 + criteria 교차대조를 그 위에 **얹는다(보완·재태깅)**. 새로 확인할 것(미분석 함수·검증 보강)에만 Ghidra를 쓴다.
   > 근거: scn00 실측에서 `/rev-native`가 이미 `java_analysis.md`에 있던 네이티브 분석(HMAC 키 추출 포함)을 재생산했다. 목표는 **기존 분석 위에 태깅·검증 레이어를 입히는 것**이지, 재분석이 아니다.
1. `targets/$1/notes/triage.md`의 **전수 체크리스트**에서 분석 대상 `.so` 목록과 우선순위를 읽는다.
2. **`.so` 하나씩** 우선순위 높은 순으로 처리한다. 현재 CodeBrowser에 열린 `.so`가 목록의 어느 것인지 먼저 확인(함수 수·심볼로 대조).
3. 각 `.so`마다:
   - `JNI_OnLoad` 디컴파일 → `RegisterNatives` 테이블로 네이티브↔Java 메서드 매핑 파악.
   - 인증/방어 관련 함수 pseudocode를 읽고, 루팅·디버거·무결성 탐지 시그니처를 찾는다.
   - 탐지/우회 포인트가 되는 분기(`if (detected != 0)` 류)를 식별하고, 함수 **리네임·코멘트**(리네임 전 백업, 디컴파일 추론은 Listing/어셈블리로 교차검증).
   - 결과를 **`targets/$1/notes/native/<so이름>.md`** 에 1파일로 기록(섞지 말 것). 발견은 반드시 `docs/criteria/_template.md`의 **메타블록 형식**으로 적는다:
     ```
     ### [RES-XXX-NN] <제목>   (NETWORK 발견이면 [NET-XXX-NN], 해당 criterion 없으면 [신규후보])
     - 신뢰도: 가설              ← 1차는 전부 '가설' 고정(2차 rev-verify가 확정/기각으로 갱신)
     - 표준: MASVS-... / MASWE-... / MASTG-...
     - 위치: <so> <함수/주소> (ghidra)
     - 근거: <문자열 xref·분기 형태>
     - 우회(가설): <어느 분기/반환값>
     - 2차 메모: (비워둠 — rev-verify가 채움)
     ```
   - triage.md 체크리스트의 해당 `.so` 상태를 `done`으로 갱신.
4. 목록에 남은 `.so`가 있으면 "다음은 `<so>` — CodeBrowser에 그걸 열고 `/rev-native $1` 재실행" 으로 안내(한 세션에 하나씩).

## 주의
- **모든 발견에 criterion ID 필수.** 기존 criterion에 안 맞는 발견은 버리지 말고 `### [신규후보] <제목>` 으로 적어 둔다(2차 커버리지·FN 점검의 입력이 된다).
- arm64-v8a 한 아키텍처만 분석(32bit 중복 금지).
- MCP가 안 붙었거나 함수 목록이 비면 → CodeBrowser 열림 + Toggle Server + GhidraMCP 버전 일치를 점검하라고 안내하고 중단.

모든 `.so`가 `done`이면 "다음: `/rev-report $1`" 안내.
