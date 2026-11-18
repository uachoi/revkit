# PLATFORM 분석 기준 — 플랫폼 상호작용 (IPC · WebView · UI)

> 카테고리: **MASVS-PLATFORM** (플랫폼 상호작용) · 작성 형식: [`_template.md`](./_template.md)
> 적용 레벨: **L1/L2**. 기준값은 **"플랫폼 IPC·WebView·UI를 안전하게 쓴다"** — 노출된 컴포넌트·인텐트·딥링크·WebView 브리지·화면 누수가 공격면이 된다.
> (MASVS v2에서 L1/L2/R 레벨은 MASTG **Testing Profiles**로 이동. 이 문서는 분석 편의상 L1/L2 표기 유지.)

## MASVS-PLATFORM 통제 (live 확인됨, 2026-11-18)

| 통제 | 공식 wording | 다루는 criterion 패밀리 |
|---|---|---|
| **MASVS-PLATFORM-1** | The app uses IPC mechanisms securely. | 딥링크, 인텐트, 클립보드, (iOS)앱 확장 |
| **MASVS-PLATFORM-2** | The app uses WebViews securely. | JS 브리지, 로컬 리소스 접근, 미신뢰 콘텐츠 로드, WebView 디버그 |
| **MASVS-PLATFORM-3** | The app uses the user interface securely. | UI/알림 민감노출, 스크린샷/녹화, 오버레이, 접근성 누수 |

MASWE 매핑(live 확인, MASWE v1.0.0 — PLATFORM은 **0029~0040** 12개):
- **PLATFORM-1** → **0029**(Insecure Deep Links)·**0030**(Improper Use of the Clipboard)·**0031**(Allowing Untrusted App Extensions, **iOS 전용**)·**0032**(Insecure Intents, Android)
- **PLATFORM-2** → **0033**(Sensitive Native Functionality Exposed in WebViews)·**0034**(WebViews Allow Access to Local Resources with Untrusted Content)·**0035**(WebViews Loading Untrusted Content) + 관련 **0063**(Debug Mechanisms Not Disabled — WebView 디버깅, ⚠️ 홈 카테고리 CODE 가능성 재확인 대상)
- **PLATFORM-3** → **0036**(Unnecessary Exposure of Sensitive Data via the User Interface)·**0037**(via Notifications)·**0038**(Insufficient Protection from Screenshots/Screen Recordings)·**0039**(App Vulnerable to Overlay Attacks)·**0040**(Sensitive Data Leaked via Accessibility Services)

> **중요 교차**: exported 컴포넌트의 **인증/인가 부재**(service/receiver/provider/activity 무인증 노출)는 v1.0.0에서 **MASWE-0018(MASVS-AUTH)로 병합**됐다 — PLATFORM이 아니라 [`40-auth.md`](./40-auth.md)에서 다룬다. PLATFORM-1은 "IPC를 **안전하게 쓰나**"(인텐트 형태·딥링크 검증·클립보드), AUTH-0018은 "노출 컴포넌트에 **인증이 있나**" 관점으로 분리. 스크린샷/접근성 누수는 [`20-storage.md` STO-LEAK-01](./20-storage.md)과 교차(저장누수 vs 플랫폼UI 관점).
> 분석 위치: `manifest`(`<activity/service/receiver/provider>` exported·intent-filter·`<data>` scheme/host·permission), `jadx`(Java — `WebView`/`addJavascriptInterface`/`loadUrl`/`getIntent`/`ClipboardManager`/`FLAG_SECURE`/`Notification`). 동적: `adb am start`로 인텐트/딥링크 주입, WebView 브리지 호출, 화면 캡처가 최종 oracle.

---

## 패밀리 1 — IPC (MASVS-PLATFORM-1)

### [PLT-DEEPLINK-01] 안전하지 않은 딥링크
- **표준 매핑**: MASVS-PLATFORM-1 / MASWE-0029(Insecure Deep Links) ✅ live / MASTG-TEST-0028(Testing Deep Links) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: manifest, jadx
- **탐지 신호**: `<intent-filter>`의 커스텀 scheme(`myapp://`)을 아무 앱이 선점 가능, App Links `android:autoVerify="true"` + Digital Asset Links(`assetlinks.json`) **미설정**, 딥링크 파라미터를 검증 없이 네비게이션/WebView/쿼리/인증토큰에 사용(`getIntent().getData()` → 그대로 사용).
- **오탐 함정(FP trap)**: ① 딥링크가 비민감 화면 라우팅만 하고 파라미터가 권한/데이터에 안 닿으면 영향 제한적. ② autoVerify 미설정이어도 민감 동작이 없으면 경미. ③ scheme 선점 가능성과 "실제로 악용되는 파라미터 흐름"을 구분(선점만으론 미완).
- **검증 방법(oracle)**: ① manifest의 intent-filter scheme/host·autoVerify·assetlinks 여부 확인. ② 딥링크 파라미터의 xref가 인증 우회·민감 동작·WebView 로드에 닿는지. ③ 동적: `adb shell am start -d "<deeplink>"`로 미검증 파라미터 주입 재현.
- **우회 포인트**: (공격자) 악성 앱/웹페이지가 딥링크로 민감 동작 트리거·인증 우회·피싱 WebView 로드. 파라미터가 WebView에 닿으면 PLT-WEBVIEW-03 연쇄.
- **신뢰도 기본값**: 가설 → **승급**: 미검증 딥링크 파라미터가 민감 흐름에 도달함을 정적 xref + `am start` 재현.
- **금융 가중**: 예

### [PLT-INTENT-01] 안전하지 않은 인텐트 · 노출 컴포넌트 (Android)
- **표준 매핑**: MASVS-PLATFORM-1 / MASWE-0032(Insecure Intents) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: manifest, jadx
- **탐지 신호**: `android:exported="true"`(또는 intent-filter로 암묵 노출)인 activity/service/receiver가 민감 동작 수행, **암묵적(implicit) 인텐트**로 민감 데이터 브로드캐스트/전송, **인텐트 리다이렉션**(`getParcelableExtra("intent")` 받아 그대로 `startActivity`), `PendingIntent`를 mutable/implicit로 생성, `setData`/extra를 검증 없이 신뢰.
- **오탐 함정**: ① `exported="true"`여도 런처/딥링크 목적의 정상 노출이며 민감 동작이 없으면 무해 — 노출 자체 ≠ 취약. ② **인증/인가 부재**로 보이면 그건 [MASWE-0018 AUTH](./40-auth.md)로 분리(여긴 인텐트 "형태"의 안전성). ③ signature permission으로 보호되는 노출.
- **검증 방법(oracle)**: ① manifest에서 exported 컴포넌트·permission·intent-filter 열거 → 각 컴포넌트가 수행하는 동작의 민감도 xref. ② 암묵 인텐트·리다이렉션·mutable PendingIntent 패턴 정적 확인. ③ 동적: `am start`/`am broadcast`로 외부에서 호출 재현.
- **우회 포인트**: (공격자) 타앱이 노출 컴포넌트 호출·암묵 인텐트 가로채기·인텐트 리다이렉션으로 내부 컴포넌트 접근. **인증 부재** 측면은 AUTH-0018 교차.
- **신뢰도 기본값**: 가설 → **승급**: 노출 컴포넌트/인텐트가 외부 호출로 민감 동작을 일으킴을 정적 + 동적 재현.
- **금융 가중**: 예

### [PLT-CLIP-01] 클립보드 부적절 사용
- **표준 매핑**: MASVS-PLATFORM-1 / MASWE-0030(Improper Use of the Clipboard) ✅ live
- **적용 레벨**: L2
- **어디서 보나**: jadx
- **탐지 신호**: 민감 값(PIN·OTP·카드번호·토큰)을 `ClipboardManager.setPrimaryClip`으로 복사, 민감 `EditText`에 복사/붙여넣기 허용, 클립보드 리스너로 타앱 복사물 수집.
- **오탐 함정**: ① 비민감 텍스트 복사는 정상 UX. ② Android 13+는 민감 플래그(`ClipDescription.EXTRA_IS_SENSITIVE`)로 완화 가능 — 설정 여부 확인. ③ 사용자가 명시 복사한 경우와 앱이 자동 복사한 경우 구분.
- **검증 방법(oracle)**: ① 민감 값이 클립보드 API로 흘러드는지 xref + 민감 플래그 유무. ② 동적: 민감 화면에서 클립보드 덤프로 평문 확인.
- **우회 포인트**: (공격자) 타앱 클립보드 스니핑으로 민감값 수집. [STO-LEAK-01](./20-storage.md) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 민감값이 클립보드에 플래그 없이 올라감을 정적 + 동적 확인.
- **금융 가중**: 예

> **MASWE-0031 (Allowing Untrusted App Extensions)**: **iOS 전용** — Android APK 분석 대상에는 **해당 없음**. (iOS 타깃 시 PLATFORM-1에 추가.)

---

## 패밀리 2 — WebView (MASVS-PLATFORM-2)

### [PLT-WEBVIEW-01] WebView JS 브리지로 네이티브 기능 노출
- **표준 매핑**: MASVS-PLATFORM-2 / MASWE-0033(Sensitive Native Functionality Exposed in WebViews) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: jadx
- **탐지 신호**: `addJavascriptInterface(obj, "name")`로 네이티브 객체를 JS에 노출(특히 민감 메서드), `@JavascriptInterface` 메서드가 파일·계정·결제·토큰 접근, `setJavaScriptEnabled(true)` + 미신뢰 콘텐츠 조합.
- **오탐 함정**: ① API 17+ 는 `@JavascriptInterface` 명시 메서드만 노출 — 노출 메서드의 민감도로 판정. ② 신뢰된 1st-party 콘텐츠만 로드하면 위험 완화(단, 미신뢰 로드와 결합 시 치명 → PLT-WEBVIEW-03 확인). ③ 브리지가 비민감 기능만.
- **검증 방법(oracle)**: ① `addJavascriptInterface` 노출 객체의 메서드 민감도 + 해당 WebView가 로드하는 콘텐츠 출처 교차. ② 동적: JS로 브리지 메서드 호출해 네이티브 기능 도달 재현.
- **우회 포인트**: (공격자) WebView에 JS 주입(미신뢰 콘텐츠·MITM·딥링크) → 브리지로 네이티브 기능 실행. MASTG-BEST-0058(브리지 노출 제한) 위반.
- **신뢰도 기본값**: 가설 → **승급**: 민감 브리지 + 미신뢰 콘텐츠 로드 가능성 동시 확인(+JS 호출 재현).
- **금융 가중**: 예

### [PLT-WEBVIEW-02] WebView 로컬 리소스 접근 + 미신뢰 콘텐츠
- **표준 매핑**: MASVS-PLATFORM-2 / MASWE-0034(WebViews Allow Access to Local Resources with Untrusted Content) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: jadx
- **탐지 신호**: `setAllowFileAccess(true)`(기본값 주의)·`setAllowFileAccessFromFileURLs(true)`·`setAllowUniversalAccessFromFileURLs(true)`·`setAllowContentAccess(true)`, `file://` 로드 + 미신뢰 콘텐츠, `WebViewAssetLoader` 미사용으로 로컬 파일 직접 노출.
- **오탐 함정**: ① 로컬 리소스 접근이 신뢰된 번들 asset만 대상이고 미신뢰 콘텐츠를 안 로드하면 위험 제한적. ② 최신 Android는 일부 플래그 기본 false — 실제 설정값 확인. 
- **검증 방법(oracle)**: ① file access 플래그 설정값 + 로드 콘텐츠 출처 교차. ② 동적: 미신뢰 콘텐츠에서 `file://`로 앱 샌드박스/민감 파일 접근 재현.
- **우회 포인트**: (공격자) universal access로 same-origin 우회 → 로컬 파일(토큰·DB) 탈취. MASTG-BEST(파일 콘텐츠 안전 로드) 위반.
- **신뢰도 기본값**: 가설 → **승급**: 위험 플래그 + 미신뢰 콘텐츠 로드로 로컬 파일 접근 재현.
- **금융 가중**: 예

### [PLT-WEBVIEW-03] WebView 미신뢰 콘텐츠 로드 (URL 검증·디버그)
- **표준 매핑**: MASVS-PLATFORM-2 / MASWE-0035(WebViews Loading Untrusted Content) ✅ live · 관련 MASWE-0063(Debug Mechanisms Not Disabled — `setWebContentsDebuggingEnabled`) ⚠️ 홈 카테고리 재확인
- **적용 레벨**: L1
- **어디서 보나**: jadx
- **탐지 신호**: `loadUrl`/`loadData`에 외부·동적 URL을 검증 없이 전달, `WebViewClient` 지정 후 `shouldOverrideUrlLoading`에서 URL 검증 부재(모든 네비게이션을 WebView가 처리), 혼합 콘텐츠 `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)`, 릴리스에서 `setWebContentsDebuggingEnabled(true)`.
- **오탐 함정**: ① WebViewClient **미지정** 시 기본 브라우저가 네비게이션 처리(쿠키·바인딩 미공유)라 상대적으로 안전 — 지정+검증부재 조합이 최악. ② 고정된 1st-party HTTPS URL만 로드하면 위험 낮음. ③ 디버그 플래그가 DEBUG 가드로 릴리스 비활성인지.
- **검증 방법(oracle)**: ① 로드 URL의 출처·검증 로직(`shouldOverrideUrlLoading` 화이트리스트) + 혼합콘텐츠/디버그 플래그 정적 확인. ② 동적: MITM/딥링크로 미신뢰 URL 주입해 로드되는지 재현.
- **우회 포인트**: (공격자) 미신뢰 콘텐츠 로드 → JS 주입으로 PLT-WEBVIEW-01/02 연쇄, chrome://inspect 디버깅. 피닝/평문은 [`50-network.md`](./50-network.md) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 미신뢰 URL이 검증 없이 WebView에 로드됨을 정적 + 동적 재현.
- **금융 가중**: 예

---

## 패밀리 3 — UI (MASVS-PLATFORM-3)

### [PLT-UIEXPOSE-01] UI에 민감 데이터 불필요 노출
- **표준 매핑**: MASVS-PLATFORM-3 / MASWE-0036(Unnecessary Exposure of Sensitive Data via the User Interface) ✅ live
- **적용 레벨**: L2
- **어디서 보나**: jadx
- **탐지 신호**: 비밀번호/PIN/카드번호를 마스킹 없이 평문 표시, 민감 필드 `inputType`에 `textPassword`/`numberPassword` 미적용, 전체 PAN/계좌 표시(부분 마스킹 미적용), 자동완성 민감필드.
- **오탐 함정**: ① 사용자가 "표시" 토글로 명시 요청한 경우. ② 비민감 데이터. ③ 부분 마스킹이 정책상 허용 범위인지.
- **검증 방법(oracle)**: ① 민감 데이터 표시 지점의 마스킹/`inputType` 정적 확인. ② 동적: 화면에서 평문 노출 관찰.
- **우회 포인트**: (공격자) 숄더서핑·화면공유·캡처로 수집. 스크린샷 측면은 PLT-SCREENSHOT-01 교차.
- **신뢰도 기본값**: 가설 → **승급**: 민감 데이터가 불필요하게 평문 표시됨 확인.
- **금융 가중**: 예

### [PLT-NOTIF-01] 알림으로 민감 데이터 노출
- **표준 매핑**: MASVS-PLATFORM-3 / MASWE-0037(Unnecessary Exposure of Sensitive Data via Notifications) ✅ live
- **적용 레벨**: L2
- **어디서 보나**: jadx
- **탐지 신호**: `NotificationCompat.Builder`에 OTP·거래내역·잔액·메시지 본문 평문 포함, 잠금화면 노출 레벨 `VISIBILITY_PUBLIC`/`setVisibility` 미제한, 민감 알림에 `setPublicVersion` 미사용.
- **오탐 함정**: ① 비민감 알림. ② 사용자가 잠금화면 알림을 켠 설정. ③ 요약만 표시하고 상세는 앱 내에서만.
- **검증 방법(oracle)**: ① 알림 빌더 내용·visibility 정적 확인. ② 동적: 잠금화면에서 민감 내용 노출 관찰.
- **우회 포인트**: (공격자) 잠금화면·알림 접근으로 OTP/거래정보 수집 → 2FA 우회 가능.
- **신뢰도 기본값**: 가설 → **승급**: 민감 데이터가 알림/잠금화면에 노출됨 확인.
- **금융 가중**: 예

### [PLT-SCREENSHOT-01] 스크린샷/화면녹화 보호 부재
- **표준 매핑**: MASVS-PLATFORM-3 / MASWE-0038(Insufficient Protection from Screenshots/Screen Recordings) ✅ live
- **적용 레벨**: L2
- **어디서 보나**: jadx
- **탐지 신호**: 민감 화면(로그인·PIN·결제·OTP)에 `getWindow().setFlags(FLAG_SECURE)` 미설정 → 스크린샷·최근앱 썸네일·화면녹화·화면공유 캡처 허용.
- **오탐 함정**: ① 모든 화면에 FLAG_SECURE가 필요한 건 아님 — 민감 화면만 대상. ② 일부 화면만 보호돼도 다른 민감 화면 누락이면 FN. ③ 접근성/캐스팅 예외.
- **검증 방법(oracle)**: ① 민감 Activity/화면의 FLAG_SECURE 설정 정적 확인. ② 동적: 해당 화면에서 스크린샷/최근앱 썸네일 캡처 시도.
- **우회 포인트**: (공격자) 화면 캡처·녹화·최근앱 썸네일로 민감 화면 수집. [STO-LEAK-01](./20-storage.md) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 민감 화면에 FLAG_SECURE 부재 + 캡처 재현.
- **금융 가중**: 예

### [PLT-OVERLAY-01] 오버레이(탭재킹) 공격 취약
- **표준 매핑**: MASVS-PLATFORM-3 / MASWE-0039(App Vulnerable to Overlay Attacks) ✅ live
- **적용 레벨**: L2
- **어디서 보나**: jadx
- **탐지 신호**: 민감 입력/확인 UI에 `android:filterTouchesWhenObscured="true"` 또는 `View.setFilterTouchesWhenObscured` 미설정, `onFilterTouchEventForSecurity` 미구현 → 타앱 오버레이(SYSTEM_ALERT_WINDOW) 위에서 탭 가로채기.
- **오탐 함정**: ① 비민감 화면은 불필요. ② 최신 Android 버전의 기본 보호·플랫폼 완화 고려. ③ 결제/권한부여 등 고위험 동작 화면에 집중.
- **검증 방법(oracle)**: ① 고위험 동작 뷰의 touch filtering 설정 정적 확인. ② 동적: 오버레이 앱으로 탭재킹 재현.
- **우회 포인트**: (공격자) 투명 오버레이로 사용자 탭을 가로채 민감 동작(이체 승인·권한 부여) 유도.
- **신뢰도 기본값**: 가설 → **승급**: 고위험 화면의 touch filtering 부재 + 오버레이 재현.
- **금융 가중**: 예

### [PLT-A11Y-01] 접근성 서비스 경유 민감 데이터 누수
- **표준 매핑**: MASVS-PLATFORM-3 / MASWE-0040(Sensitive Data Leaked via Accessibility Services) ✅ live
- **적용 레벨**: L2
- **어디서 보나**: jadx, manifest
- **탐지 신호**: 민감 뷰 내용이 접근성 트리에 그대로 노출(민감 필드에 `importantForAccessibility`/콘텐츠 설명 과다), 앱이 민감 데이터를 접근성 이벤트로 방출, (방어 관점) 악성 접근성 서비스가 화면 텍스트·입력 수집 가능.
- **오탐 함정**: ① 접근성은 정당한 보조기술 용도 — 과잉 차단은 접근성 저해. ② 플랫폼이 민감 입력(비밀번호)은 일부 보호. ③ "앱이 노출" vs "악성 서비스가 수집"의 위협주체 구분.
- **검증 방법(oracle)**: ① 민감 화면의 접근성 노출 속성 정적 확인. ② 동적: 접근성 서비스로 민감 텍스트/입력이 읽히는지 재현.
- **우회 포인트**: (공격자) 악성 접근성 서비스로 화면 스크랩·키 입력 수집. [STO-LEAK-01](./20-storage.md) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 민감 데이터가 접근성 경유로 노출됨 확인.
- **금융 가중**: 예

---

## 커버리지 체크리스트 (2차 패스 — 공백 점검용)

- [ ] PLT-DEEPLINK-01 안전하지 않은 딥링크 (MASWE-0029)
- [ ] PLT-INTENT-01 안전하지 않은 인텐트·노출 컴포넌트 (MASWE-0032) ※인증부재는 AUTH-0018
- [ ] PLT-CLIP-01 클립보드 부적절 사용 (MASWE-0030)
- [ ] (iOS 전용 MASWE-0031 앱 확장 — Android 해당없음)
- [ ] PLT-WEBVIEW-01 JS 브리지 네이티브 노출 (MASWE-0033)
- [ ] PLT-WEBVIEW-02 로컬 리소스 접근 + 미신뢰 (MASWE-0034)
- [ ] PLT-WEBVIEW-03 미신뢰 콘텐츠 로드·디버그 (MASWE-0035, 관련 0063)
- [ ] PLT-UIEXPOSE-01 UI 민감 노출 (MASWE-0036)
- [ ] PLT-NOTIF-01 알림 민감 노출 (MASWE-0037)
- [ ] PLT-SCREENSHOT-01 스크린샷/녹화 보호 부재 (MASWE-0038)
- [ ] PLT-OVERLAY-01 오버레이/탭재킹 (MASWE-0039)
- [ ] PLT-A11Y-01 접근성 누수 (MASWE-0040)

> ⚠️ **manifest 의존**: PLT-DEEPLINK-01·PLT-INTENT-01은 manifest(exported·intent-filter·scheme)가 핵심. `/rev-jadx`가 `--no-res`면 미추출 → `--no-res` 없이 재실행 또는 manifest 별도 추출 필요.

---

## 출처 (live 확인, 2026-11-18)

- MASVS-PLATFORM: [mas.owasp.org/MASVS/09-MASVS-PLATFORM](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/)
- PLATFORM-1: [controls/MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/) · PLATFORM-2: [controls/MASVS-PLATFORM-2](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/) · PLATFORM-3: [controls/MASVS-PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/)
- MASWE-0029 딥링크: [MASWE-0029](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/) · MASTG-TEST-0028: [Testing Deep Links](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/)
- MASWE 전체: [mas.owasp.org/MASWE](https://mas.owasp.org/MASWE/) (PLATFORM: 0029~0040, v1.0.0)
- WebView 지식: [MASTG-KNOW-0018 WebViews](https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018/)

> **2026-11-18 live 확인**: MASVS-PLATFORM-1/2/3 wording, MASWE-0029~0040 12개 실존·카테고리 매핑 확인. **MASWE-0031=iOS 전용**(Android 해당없음), **exported 컴포넌트 인증부재=MASWE-0018(AUTH)로 병합**(PLATFORM 아님), **MASWE-0063(WebView 디버그)**는 PLATFORM-2 관련으로 명시되나 홈 카테고리(CODE 가능성)는 ⚠️ 재확인 대상.
