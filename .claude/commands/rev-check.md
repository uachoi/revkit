---
description: 리버싱 자동분석 사전 환경 체크 (MCP·Ghidra·APK·Java·jadx 버전)
argument-hint: [대상]
allowed-tools: Bash(jadx:*), Bash(java:*), Bash(ls:*), Bash(find:*), Read, Glob
---

리버싱 자동분석을 시작하기 전 환경을 점검한다. 대상: `$1` (비면 `targets/` 밑 폴더 중 사용자에게 확인).

다음을 각각 확인하고 **✅/❌ 표 하나**로 요약 출력한다. ❌면 바로 밑에 해결법 한 줄.

1. **대상 폴더** — `targets/$1/apk/` 에 `.apk`(또는 `.zip`) 존재? 없으면 "APK를 `targets/$1/apk/`에 넣어라".
2. **jadx CLI** — `jadx --version` 실행. PATH에 없으면 릴리스 zip `bin`을 PATH 등록 안내.
3. **Java** — `java -version`. jadx 구동용 17+ 권장.
4. **Ghidra MCP 연결** — `ghidra` MCP 서버 도구가 이 세션에 붙어 있는지 확인(툴 목록에 `mcp__ghidra__*`). 안 보이면: CodeBrowser 열림 + MCP Toggle Server 켜짐 + `.mcp.json` 확인 안내.
5. **Ghidra ↔ MCP 버전 일치** — 자동 확인 불가. 사용자에게 GhidraMCP 플러그인 버전과 서버 버전이 같은지 수동 확인하라고 명시(불일치 시 함수 목록이 비거나 오동작).
6. **CodeBrowser에 타깃 `.so` 열림** — 자동 확인 불가. 네이티브 단계 전제 조건임을 안내(안 열려 있으면 `/rev-native`는 실패).

마지막에 "모두 ✅ → `/rev-jadx $1` 로 진행" 또는 "❌ 해결 후 재실행" 한 줄로 결론.
