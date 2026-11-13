# scn00 네이티브 라이브러리 트리아지 (libscn00monitor.so)

> 생성: 2026-11-09 · 대상: EQST FinTech App Hacking 워게임 / scn00
> 앱: React Native + Hermes · 패키지: `kr.co.eqst.pay.s00`
> 분석 타깃: `scn00/lib/arm64-v8a/libscn00monitor.so` (18,240 bytes)

---

## 0. 한 줄 요약

`libscn00monitor.so` 는 **단일 클래스 `kr.co.eqst.pay.s00.Scn00MonitorModule`** 전용의
**anti-tampering / RASP(기기 무결성) 모듈**이다. 루트·Frida·디버거 탐지 + 서명된 attestation 리포트(SPKI 피닝 포함)를 네이티브에서 생성한다.
인증(송금 승인) 로직 자체는 이 .so 가 아니라 서버에 있으며, 이 모듈은 "기기 상태 증거"를 서명해 올리는 역할이다.

> ⚠️ **jadx 디컴파일은 이번 세션에서 실행이 차단됨**(auto-mode 안전 분류기). 아래 표는 `.so`/`.dex`의 **문자열 레벨 정적 추출**로 도출. 정확한 호출 라인·companion init 본문 확인은 jadx 실행 권한 또는 Ghidra 필요. §4 참조.

---

## 1. .so 가 export 하는 JNI 심볼 (확정)

`grep -a` 로 `libscn00monitor.so` 에서 추출한 JNI export:

| JNI 심볼 | 대응 Java/Kotlin 네이티브 메서드 | 역할(추정) |
|---|---|---|
| `Java_..._Scn00MonitorModule_nativeRootEvidence` | `nativeRootEvidence` | 루팅 흔적 수집 |
| `Java_..._Scn00MonitorModule_nativeFridaEvidence` | `nativeFridaEvidence` | Frida/후킹 흔적 수집 |
| `Java_..._Scn00MonitorModule_nativeDebuggerEvidence` | `nativeDebuggerEvidence` | 디버거 attach 탐지 |
| `Java_..._Scn00MonitorModule_nativeSignedReport` | `nativeSignedReport` | 수집 증거를 서명한 리포트 생성 |
| `Java_..._Scn00MonitorModule_nativeSignedReportPinning` | `nativeSignedReportPinning` | SPKI 피닝 포함 서명 리포트 |

(전체 FQN prefix = `Java_kr_co_eqst_pay_s00_Scn00MonitorModule_`)

---

## 2. System.loadLibrary / native 메서드 → 라이브러리 매핑 (핵심 표)

| 항목 | 값 | 근거 |
|---|---|---|
| 로드되는 라이브러리 | `scn00monitor` → `libscn00monitor.so` | `.dex` 내 `"scn00monitor"` 문자열 = **classes3.dex에 1회만** 존재 |
| `System.loadLibrary("scn00monitor")` 호출 위치 | **classes3.dex**, `Scn00MonitorModule`(및 `$Companion`) 내부 static/companion init | `scn00monitor` 문자열·`Scn00MonitorModule`(12회 참조)·5개 native 메서드가 **모두 classes3.dex에만** 동거. Kotlin RN 모듈의 전형적 `companion object { init { System.loadLibrary(...) } }` 패턴 |
| native 메서드 선언 클래스 | `kr.co.eqst.pay.s00.Scn00MonitorModule` | 5개 `native*` 심볼이 이 클래스 FQN으로 export |
| 이 .so 를 호출하는 **다른** 인증 클래스 | **없음 (단일 소비자)** | `Scn00MonitorModule` 외 클래스에서 해당 native/문자열 참조 미발견 |

### dex별 `loadLibrary` 분포 (참고)
- classes.dex: `loadLibrary` 1회 (scn00monitor 아님 → RN/Hermes 등 타 라이브러리)
- classes2.dex: `loadLibrary` 9회 (scn00monitor 아님)
- classes3.dex: `loadLibrary` 1회 + `scn00monitor` 1회 → **이 1회가 타깃 .so 로드**

즉 **libscn00monitor.so 로드 지점은 앱 전체에서 단 1곳**(classes3.dex / Scn00MonitorModule)이다.

---

## 3. 주변 인증·보안 클래스 지도 (`kr.co.eqst.pay.s00`)

| 클래스 | 성격 | .so 와의 관계 |
|---|---|---|
| `Scn00MonitorModule` (+ `$Companion`, `$observedSpki$trustAll$1`) | RASP/attestation (root·frida·debugger·서명리포트·SPKI피닝) | **유일한 .so 소비자** |
| `Scn00MonitorPackage` | 위 모듈의 RN Package 등록 | 간접 |
| `BiometricKeyModule` (+ `$sign$1$prompt$1`) | 생체인증 키 서명 | .so 미사용(별도) |
| `PinKdfModule` / `PinKdfEngine` / `PinKdfModule$ParsedVerifier` | PIN KDF·verifier | .so 미사용 |
| `OAuthAuthSessionModule` | OAuth 세션 | .so 미사용 |
| `SecurityStatusModule` | 보안상태 노출 모듈 | Monitor 결과 소비 가능성(미확인) |

> F28(송금 인증 우회, `SCN00.F28.TXN_AUTH_NOT_VERIFIED`)의 승인 검증 공백은 **서버 측** 문제로, 이 .so(클라 기기무결성)와는 별개 레이어. 단, `nativeSignedReportPinning`의 SPKI 피닝은 Burp 중계(§F28 동적분석)에 영향을 줄 수 있어 우회 대상이 될 수 있음.

---

## 4. 막힌 단계 / 다음 작업

1. **jadx 디컴파일 (step 3·4) — 실행 차단됨.**
   jadx 1.5.0 을 받아 `_work/jadx-out`에 디컴파일하려 했으나 auto-mode 안전 분류기가 실행을 거부함(두 번).
   - 받아둔 위치: `...scratchpad/jadx/bin/jadx.bat` (Java 17 설치 확인됨, 실행만 하면 됨)
   - 진행하려면: 사용자가 Bash(jadx) 실행을 허용하거나, 직접 아래를 실행:
     ```
     "...\scratchpad\jadx\bin\jadx.bat" --no-res --no-debug-info -d "_work\jadx-out" scn00\classes.dex scn00\classes2.dex scn00\classes3.dex
     ```
   - 디컴파일 후 확인할 것: `Scn00MonitorModule` companion init의 정확한 `loadLibrary` 라인, 5개 native 메서드 호출부, `observedSpki`(피닝 대상 공개키), `SecurityStatusModule` 연동.
2. **Ghidra (step: ✅ done 2026-11-13)** — `libscn00monitor.so` 1차 분석 완료 → [`notes/native/libscn00monitor.so.md`](native/libscn00monitor.so.md) (메타블록/criterion ID 태깅 포맷). 발견: RES-ROOT-02, RES-DBG-02, RES-HOOK-01, RES-INTEG-01 + [신규후보] NETWORK 피닝. 다음: `/rev-verify scn00`.

## 네이티브 전수 체크리스트 (우선순위/상태)

| .so | 신호 | 우선순위 | 상태 |
|---|---|---|---|
| `libscn00monitor.so` | 루트·Frida·디버거·서명리포트·SPKI피닝 (RASP 단일 소비자) | 1 | ✅ done (2026-11-13) |
| 그 외 (libreactnative/hermes/rn* 등) | React Native/Hermes 런타임 — 보안로직 아님 | — | skip (분석 불필요) |

---

## 5. 작업 환경 상태 (step 1·2)

- `_work/{jadx-out,ghidra,frida,notes,burp}` 생성 완료.
- 이동 완료: `F28_송금인증우회_분석정리.md`, `1번 오답.png` → `notes/`; `2026-11-09.burp.backup` → `burp/`.
- **미이동**: `2026-11-09.burp` (실행 중 프로세스가 파일 잠금 — Burp 종료 후 이동 필요).
- **의도적으로 제외**: `scn00/res/*.png` ≈200개는 APK 리소스(drawable)이며 분석파일 아님.
