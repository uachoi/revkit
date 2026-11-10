---
description: 전체 리버싱 파이프라인 오케스트레이션 (check→jadx→native→report)
argument-hint: [대상]
allowed-tools: Bash(jadx:*), Bash(java:*), Read, Glob, Grep, Write, Edit
---

대상 `$1`에 대해 리버싱 자동분석 전체 흐름을 순서대로 실행한다. 각 단계는 해당 커맨드 지침(`/rev-check`, `/rev-jadx`, `/rev-native`, `/rev-report`)을 그대로 따른다.

## 실행 흐름
1. **환경 체크** (`rev-check` 지침) — ❌가 있으면 **여기서 멈추고** 해결법을 알려준다. 통과 시 다음으로.
2. **jadx 자동** (`rev-jadx` 지침) — 디컴파일 + `triage.md` + `java_analysis.md` 생성. 완전 자동이라 끝까지 진행.
3. **Ghidra 게이트** — 네이티브는 사람이 CodeBrowser에 `.so`를 열어야 한다. `mcp__ghidra__*`가 붙어 있고 `.so`가 열려 있으면 4로. **아니면 여기서 멈추고** "CodeBrowser에 `targets/$1/unpacked/lib/arm64-v8a/<타깃>.so` 열고 `/rev-native $1` 실행" 으로 안내(파이프라인의 유일한 수동 지점).
4. **네이티브 분석** (`rev-native` 지침) — triage 체크리스트의 `.so`를 순회. 여러 개면 한 번에 하나씩(열린 것부터), 나머지는 안내.
5. **보고서** (`rev-report` 지침) — 모든 `.so`가 `done`이면 `report.md` 종합 + INDEX 갱신.

## 사용자가 보게 되는 것
- 환경 체크 ✅/❌ 표 → jadx 결과 요약(로드 `.so`·native·우선순위) → (필요 시 Ghidra 준비 안내에서 일시정지) → `.so`별 네이티브 분석 요약 → 최종 `report.md` 경로.
- 즉 "한 줄로 전체를 돌리되, 사람 손이 필요한 Ghidra 지점에서만 멈춰 다음 할 일을 알려주는" 커맨드다.
