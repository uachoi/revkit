---
description: jadx 완전 자동 디컴파일 + Java triage (대상 .so 특정)
argument-hint: [대상]
allowed-tools: Bash(jadx:*), Read, Glob, Grep, Write, Edit
---

대상 `$1`의 APK를 jadx로 디컴파일하고 Java 레벨 triage까지 자동 수행한다. 이 단계는 **MCP 불필요, 완전 자동**이다.

## 1. 디컴파일
- 입력: `targets/$1/apk/` 의 `.apk` (없으면 같은 폴더 `.zip`). APK를 직접 넘기면 jadx가 내부 dex를 알아서 처리한다.
- 출력: `targets/$1/jadx-out/`
- 명령 (리소스·디버그정보 생략으로 가볍게):
  ```
  jadx --no-res --no-debug-info -d targets/$1/jadx-out/ targets/$1/apk/<파일>
  ```
- 대형 멀티덱스에서 메모리로 중단되면 `JAVA_OPTS=-Xmx4g` 주고 재시도. `jadx-out`이 이미 차 있으면 사용자에게 재생성 여부 확인.
- ⚠️ `--no-res`를 쓰면 `.so`가 안 풀린다. Ghidra용 `.so`는 `targets/$1/unpacked/lib/arm64-v8a/` 또는 APK에서 별도 추출로 확보한다(없으면 `--no-res` 빼고 재실행).

## 2. Java triage → `targets/$1/notes/triage.md`
- `jadx-out/sources`에서 `System.loadLibrary` / `System.load` 를 **전부** 찾아, 로드되는 `.so`와 호출 클래스를 표로.
- `native` 메서드 선언을 전부 찾아 어느 `.so`에 속하는지 매핑.
- 각 `.so`를 **인증/암호/anti-tamper 관련 신호**(문자열, 메서드명, JNI 등록 수)로 점수화해 **분석 우선순위**를 매긴다.
- 각 신호를 **criterion 패밀리에 매핑**한다(예: su 문자열→RES-ROOT, ptrace→RES-DBG, frida 문자열→RES-HOOK, 서명검사→RES-INTEG, `SecretKeySpec`/하드코딩키→CRY-HARDKEY, DES/ECB/MD5→CRY-ALGO, `BiometricPrompt`→AUTH-BIO, OAuth/redirect→AUTH-OAUTH, PIN KDF→CRY-KDF·AUTH-PIN). 기준(`docs/criteria/`)의 어떤 criterion에도 안 걸리는 신호는 `미매핑`으로 표시(2차 커버리지 입력).
- `.so`가 여러 개면 **전수 체크리스트**(so 이름 / 신호 / 우선순위 / 상태 pending)를 triage.md 맨 아래에 둬서 이후 누락을 방지한다.

## 3. Java 호출흐름 → `targets/$1/notes/java_analysis.md`
- 우선순위 상위 `.so`를 부르는 클래스의 호출 흐름, 서버 전송 로직, 하드코딩 시크릿/엔드포인트를 정리.
- Java 레벨 발견(Java 루트/디버거 탐지, 하드코딩 시크릿 등)은 `docs/criteria/_template.md`의 **메타블록 형식**(`### [RES-XXX-NN]` + 신뢰도 `가설` + 표준/위치/근거/우회(가설)/2차 메모)으로 적고 criterion ID를 붙인다. 안 맞으면 `### [신규후보]`.

끝나면 "다음: Ghidra CodeBrowser에 타깃 `.so` 열고 `/rev-native $1`" 안내.
