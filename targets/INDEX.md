# 분석 대상 인덱스

revkit으로 분석한 대상 전체 목록. 새 대상은 `targets/<대상>/apk/`에 APK를 넣고 `/rev-all <대상>`으로 시작한다.

| 대상 | 앱 | 타깃 .so | 분석일 | 상태 | 보고서 |
| --- | --- | --- | --- | --- | --- |
| scn00 | kr.co.eqst.pay.s00.localapi (RN 간편결제 실습) | libscn00monitor.so | 2026-11-18 | 2차검증+8카테고리 완료 (동적 PoC 대기) | [report](scn00/notes/report.md) |

## 상태 범례
- `환경체크` → `jadx완료` → `네이티브진행` → `자동분석 완료` → `우회/PoC`
