---
description: 단계별 노트를 종합해 최종 보고서(report.md) 생성 + INDEX 갱신
argument-hint: [대상]
allowed-tools: Read, Glob, Grep, Write, Edit
---

대상 `$1`의 분석 노트를 종합해 최종 보고서를 만든다.

## 1. 입력 취합
`targets/$1/notes/` 의 `triage.md`, `java_analysis.md`, `native/*.md` (여러 `.so`면 전부)를 읽는다.

## 2. `targets/$1/notes/report.md` 생성
맨 위에 **메타**(앱명 / 버전 / 분석일 / 타깃 `.so` 목록)를 두고, 다음 구성:
- **요약** — 무엇을 발견했나, 핵심 위험.
- **타깃 선정 근거** — triage 결과(어떤 `.so`가 왜 선택됐나).
- **Java 분석** — 호출흐름·서버전송·하드코딩 시크릿.
- **네이티브 분석** — `.so`별 탐지/방어 로직과 **우회 포인트**(어느 분기를 뒤집으면 되는지).
- **다음 단계(모의해킹)** — Frida 우회, SSL Pinning, 트래픽 변조, 재패키징, Secrets 악용 PoC 중 해당되는 것.
- **대응방안** — 방어 관점 권고.

## 3. `targets/INDEX.md` 갱신
전체 대상 표(대상 / 앱 / 분석일 / 상태 / report 링크)에서 `$1` 행을 추가·갱신한다. 파일이 없으면 새로 만든다.

끝나면 `targets/$1/notes/report.md` 경로를 반환한다.
