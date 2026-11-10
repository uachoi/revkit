---
description: Ghidra MCP로 네이티브 .so 분석 (여러 .so 전수 순회)
argument-hint: [대상]
allowed-tools: Read, Glob, Grep, Write, Edit
---

대상 `$1`의 네이티브 `.so`를 Ghidra MCP로 분석한다. **전제: Ghidra CodeBrowser에 분석할 `.so`가 import·analyze된 채 열려 있어야 한다**(`mcp__ghidra__*` 도구 사용). 안 열려 있으면 멈추고 안내만 한다.

## 분석 순서 — 빠짐없이 + 정확하게
1. `targets/$1/notes/triage.md`의 **전수 체크리스트**에서 분석 대상 `.so` 목록과 우선순위를 읽는다.
2. **`.so` 하나씩** 우선순위 높은 순으로 처리한다. 현재 CodeBrowser에 열린 `.so`가 목록의 어느 것인지 먼저 확인(함수 수·심볼로 대조).
3. 각 `.so`마다:
   - `JNI_OnLoad` 디컴파일 → `RegisterNatives` 테이블로 네이티브↔Java 메서드 매핑 파악.
   - 인증/방어 관련 함수 pseudocode를 읽고, 루팅·디버거·무결성 탐지 시그니처를 찾는다.
   - 탐지/우회 포인트가 되는 분기(`if (detected != 0)` 류)를 식별하고, 함수 **리네임·코멘트**(리네임 전 백업, 디컴파일 추론은 Listing/어셈블리로 교차검증).
   - 결과를 **`targets/$1/notes/native/<so이름>.md`** 에 1파일로 기록(섞지 말 것).
   - triage.md 체크리스트의 해당 `.so` 상태를 `done`으로 갱신.
4. 목록에 남은 `.so`가 있으면 "다음은 `<so>` — CodeBrowser에 그걸 열고 `/rev-native $1` 재실행" 으로 안내(한 세션에 하나씩).

## 주의
- arm64-v8a 한 아키텍처만 분석(32bit 중복 금지).
- MCP가 안 붙었거나 함수 목록이 비면 → CodeBrowser 열림 + Toggle Server + GhidraMCP 버전 일치를 점검하라고 안내하고 중단.

모든 `.so`가 `done`이면 "다음: `/rev-report $1`" 안내.
