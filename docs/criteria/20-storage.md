# STORAGE 분석 기준 — 민감 데이터 저장 · 누수

> 카테고리: **MASVS-STORAGE** (저장) · 작성 형식: [`_template.md`](./_template.md)
> 적용 레벨: **L1/L2**. 기준값은 **"민감 데이터는 안전하게 저장되고, 의도치 않게 새지 않아야 한다"** — 즉 평문 저장·외부 노출·로그/백업 누수 자체가 취약점이다.
> (MASVS v2에서 L1/L2/R 레벨은 표준 본문에서 빠져 MASTG **Testing Profiles**로 이동했다. 이 문서는 분석 편의상 L1/L2 표기를 유지한다. 예: STORAGE-1은 앱 내부 저장소 평문이 MAS-L1에선 허용, MAS-L2에선 암호화 요구.)

## MASVS-STORAGE 통제 (live 확인됨, 2026-11-18)

| 통제 | 공식 wording | 다루는 criterion 패밀리 |
|---|---|---|
| **MASVS-STORAGE-1** | The app securely stores sensitive data. | 평문 저장(내부/외부), 키/시크릿 저장 위치, 하드코딩 시크릿 |
| **MASVS-STORAGE-2** | The app prevents leakage of sensitive data. | 로그·백업·클립보드·스크린샷·키보드 캐시·프로세스 메모리 등 부수 누수 |

MASWE 매핑(live 확인, MASWE v1.0.0 — STORAGE는 **0001~0006** 6개):
- **STORAGE-1** → **MASWE-0001**(Sensitive Data Stored Unencrypted in Private Storage)·**MASWE-0002**(Sensitive Data Stored Unencrypted Outside of Private Storage)·**MASWE-0003**(Cryptographic Keys Stored Outside Platform Keystore)·**MASWE-0004**(Sensitive Data Hardcoded in the App Package)
- **STORAGE-2** → **MASWE-0005**(Insertion of Sensitive Data into Logs)·**MASWE-0006**(Sensitive Data Not Excluded From Backup)

> 교차: 하드코딩 **암호키**는 [`30-crypto.md` CRY-HARDKEY-01](./30-crypto.md), 키 저장·접근제어는 [`30-crypto.md` CRY-STORE-01](./30-crypto.md)과 교차(STORAGE는 "어디에 저장됐나/노출됐나", CRYPTO는 "키 관리가 적절한가" 관점). 클립보드·스크린샷·접근성 누수는 [`60-platform.md`](./60-platform.md) 교차.
> 분석 위치: `jadx`(Java — `SharedPreferences`/`SQLiteDatabase`/`FileOutputStream`/`openFileOutput`/`getExternal*`/`Log`/`KeyStore`/`ClipboardManager`), `manifest`(`android:allowBackup`·`fullBackupContent`·`dataExtractionRules`), `리소스`(res/raw·assets). 동적: 설치 후 앱 샌드박스(`/data/data/<pkg>/`)·외부경로·`logcat`·백업 아카이브 덤프가 최종 oracle.

---

## 패밀리 1 — 평문 저장 (MASVS-STORAGE-1)

### [STO-PLAIN-01] 앱 전용(private) 저장소에 민감 데이터 평문 저장
- **표준 매핑**: MASVS-STORAGE-1 / MASWE-0001(Sensitive Data Stored Unencrypted in Private Storage) ✅ live
- **적용 레벨**: L1(무해 데이터)·L2(민감 데이터 암호화 요구)
- **어디서 보나**: jadx(Java)
- **탐지 신호**:
  - `getSharedPreferences(...).edit().putString("token"/"pw"/"pin"/"card", ...)` — 토큰·비밀번호·PIN·PAN·PII를 SharedPrefs 평문으로.
  - `SQLiteDatabase`(SQLCipher 아님)·`Room` DB에 민감 컬럼 평문, `openFileOutput(..., MODE_PRIVATE)`로 민감 파일.
  - `EncryptedSharedPreferences`/SQLCipher **미사용**인데 민감 데이터 저장.
- **오탐 함정(FP trap)**: ① 비민감 데이터(UI 상태·캐시·플래그)는 평문 저장이 정상 — 데이터 민감도부터 판정. ② 값이 이미 암호화/해시된 산출물일 수 있음(저장 직전 `Cipher`/KeyStore 경유 확인). ③ `MODE_PRIVATE`는 "타앱 차단"일 뿐 루팅·백업 노출은 별개(미암호화면 여전히 STORAGE-1 약점).
- **검증 방법(oracle)**: ① 저장 값의 출처를 xref — 민감 소스(로그인 응답·PIN 입력)가 암호화 없이 `put*`/`insert`에 닿나. ② 동적: 설치 후 `/data/data/<pkg>/shared_prefs/*.xml`·`databases/*`를 열어 **평문으로 보이는지** 확인(최종 oracle). ③ `EncryptedSharedPreferences`/SQLCipher 경유 여부.
- **우회 포인트**: (공격자) 루팅·`adb backup`·기기 분실 시 평문 추출 → 자격증명·PII 탈취. 발견 자체가 취약점.
- **신뢰도 기본값**: 가설 → **승급**: 민감 데이터가 평문으로 저장됨을 정적 xref + 설치 파일 덤프로 확인.
- **금융 가중**: 예

### [STO-EXT-01] 외부(공유) 저장소에 민감 데이터 저장
- **표준 매핑**: MASVS-STORAGE-1 / MASWE-0002(Sensitive Data Stored Unencrypted Outside of Private Storage) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: jadx(Java), manifest
- **탐지 신호**: `getExternalStorageDirectory()`·`getExternalFilesDir()`(공유 영역)·`MediaStore`·`Downloads`에 민감 파일 기록, `MODE_WORLD_READABLE/WRITEABLE`(구버전), `Environment.getExternalStoragePublicDirectory`, 공유 캐시 디렉터리에 토큰/문서.
- **오탐 함정**: ① `getExternalFilesDir()` 앱 전용 하위경로는 타앱 접근이 제한적이나 **백업·루팅 노출은 여전**(민감이면 암호화 필요). ② 사용자가 명시적으로 내보내는 파일(사용자 의도 저장)은 맥락상 허용될 수 있음. ③ 이미 암호화된 산출물.
- **검증 방법(oracle)**: ① 외부경로 쓰기 API의 인자·데이터 민감도 xref. ② 동적: `/sdcard/`·공유 경로에서 평문 민감 파일 확인.
- **우회 포인트**: (공격자) 외부 저장소는 타앱·USB·백업으로 광범위 노출 → 평문이면 즉시 탈취. 발견 자체가 취약점.
- **신뢰도 기본값**: 가설 → **승급**: 민감 데이터가 외부/공유 경로에 평문 기록됨을 xref + 동적 확인.
- **금융 가중**: 예

---

## 패밀리 2 — 키/시크릿 저장 위치 (MASVS-STORAGE-1)

### [STO-KEY-01] 암호키를 플랫폼 KeyStore 밖에 저장
- **표준 매핑**: MASVS-STORAGE-1 / MASWE-0003(Cryptographic Keys Stored Outside Platform Keystore) ✅ live
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: 키·키재료를 SharedPrefs·파일·DB·`String`/`byte[]`로 보관, `AndroidKeyStore` 미사용, 키를 코드/리소스에서 로드해 메모리 상주, 네이티브 `.rodata` 키 상수.
- **오탐 함정**: ① 공개키·인증서는 KeyStore 밖에 있어도 무방(기밀 아님). ② 키가 KeyStore 래핑된 상태로 저장될 수 있음(저장 전 wrap 확인). ③ 세션 전용 임시키(짧은 수명)와 장기키 구분.
- **검증 방법(oracle)**: ① 키 생성·로드 경로가 `KeyStore.getInstance("AndroidKeyStore")`/`KeyGenParameterSpec`인지 vs 평문 저장인지 정적 확인. ② 동적: KeyStore 사용 여부·저장소에서 키 추출 가능성(루팅).
- **우회 포인트**: (공격자) KeyStore 밖 키는 추출·오남용 가능 → 복호·서명 위조. 하드코딩 **암호키**는 [CRY-HARDKEY-01](./30-crypto.md), 접근제어는 [CRY-STORE-01](./30-crypto.md) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 비공개 키가 KeyStore 밖 평문/추출가능 상태로 저장됨을 확인.
- **금융 가중**: 예

### [STO-HARDCODE-01] 앱 패키지에 민감 데이터 하드코딩
- **표준 매핑**: MASVS-STORAGE-1 / MASWE-0004(Sensitive Data Hardcoded in the App Package) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: jadx(Java), ghidra(.so), 리소스
- **탐지 신호**: 소스/리소스에 API 키·시크릿·비밀번호·토큰·엔드포인트 자격증명 리터럴, `strings.xml`/`res/raw`/`assets`/`BuildConfig` 상수, `.so` `.rodata` 평문 시크릿, 하드코딩된 백도어/테스트 계정.
- **오탐 함정**: ① 공개 식별자(앱ID·공개 가능 클라이언트ID·피닝 SPKI 지문)는 하드코딩돼도 무방 — 비밀성 판정. ② 테스트/데모 시크릿이 릴리스에 남았는지(여전히 노출이면 약점). ③ 난독화로 런타임 조립되면 상수 검색만으론 FN.
- **검증 방법(oracle)**: ① 리터럴이 **실제 비밀**로서 인증/암호/서버접속에 쓰이는지 xref. ② 문자열/리소스 전수 grep + `.so` `.rodata` 스캔. ③ 네이티브 키는 2경로 교차검증(→ CRY-HARDKEY-01 절차).
- **우회 포인트**: (공격자) 패키지만 뜯으면 시크릿 획득 → 서버 인증 위조·복호. **암호키**는 [CRY-HARDKEY-01](./30-crypto.md) 교차(동일 사실을 CRYPTO·STORAGE 양 관점으로).
- **신뢰도 기본값**: 가설 → **승급**: 하드코딩 값이 실제 비밀이고 보안 연산/인증에 쓰임을 확인. **정적 증명만으로 `확정` 가능**.
- **금융 가중**: 예
- **예시(scn00)**: HMAC 키 `SCN00-monitor-hmac-key-v1-eqstlb`가 `.so` `.rodata` 평문 — STORAGE 관점(패키지 내 하드코딩 시크릿)으로도 STO-HARDCODE-01, 암호 관점으론 CRY-HARDKEY-01로 이중 태깅.

---

## 패밀리 3 — 누수: 로그 · 백업 (MASVS-STORAGE-2)

### [STO-LOG-01] 민감 데이터가 로그로 누출
- **표준 매핑**: MASVS-STORAGE-2 / MASWE-0005(Insertion of Sensitive Data into Logs) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: jadx(Java)
- **탐지 신호**: `Log.d/v/i/w/e(..., token/pw/pin/card/pii ...)`, `System.out.println`/`printStackTrace`에 민감 값, HTTP 요청·응답 바디 통째 로깅(OkHttp `HttpLoggingInterceptor.Level.BODY`), 예외 메시지에 자격증명 포함.
- **오탐 함정**: ① `BuildConfig.DEBUG` 가드로 릴리스 비활성 로그(실제 릴리스 APK에서 제거되는지 확인). ② 로깅 문자열에 민감해 보이는 **변수명**만 있고 실제 값은 마스킹될 수 있음. ③ 비민감 디버그 로그.
- **검증 방법(oracle)**: ① 로그 인자에 민감 소스가 **마스킹 없이** 흘러드는지 xref + DEBUG 가드 유무. ② 동적: 릴리스 빌드 실행 중 `logcat`에 민감 값이 실제로 찍히는지(최종 oracle).
- **우회 포인트**: (공격자) 같은 기기 타앱(권한 따라)·버그리포트·`adb logcat`로 수집 → 토큰/PII 탈취. 발견 자체가 취약점.
- **신뢰도 기본값**: 가설 → **승급**: 민감 값이 릴리스 로그에 마스킹 없이 기록됨을 정적 + `logcat`으로 확인.
- **금융 가중**: 예

### [STO-BACKUP-01] 민감 데이터가 백업에서 제외되지 않음
- **표준 매핑**: MASVS-STORAGE-2 / MASWE-0006(Sensitive Data Not Excluded From Backup) ✅ live
- **적용 레벨**: L1
- **어디서 보나**: manifest, jadx
- **탐지 신호**: `android:allowBackup="true"`(또는 기본값 방치)인데 민감 파일 백업 제외 규칙 없음, `android:fullBackupContent`/`android:dataExtractionRules`(API 31+) 미정의 또는 민감 경로 미제외, `BackupAgent` 커스텀 로직에서 민감 데이터 포함.
- **오탐 함정**: ① `allowBackup`이 true여도 민감 데이터가 **애초에 저장 안 되거나** KeyStore 래핑/암호화돼 있으면 영향 제한적(저장 criterion과 함께 판정). ② API 31+ 기본 동작·제외 규칙 존재 여부를 manifest로 정확히 확인(추정 금지). ③ 디바이스 투 디바이스 전송과 클라우드 백업 구분.
- **검증 방법(oracle)**: ① manifest의 `allowBackup`·`fullBackupContent`·`dataExtractionRules` 값과 제외 규칙 파일을 **실제로** 확인(⚠️ `/rev-jadx`가 `--no-res`면 manifest/리소스 미추출 — `--no-res` 없이 재실행 또는 별도 추출 필요). ② 동적: `adb backup`(또는 autobackup) 아카이브를 풀어 민감 파일 포함 여부.
- **우회 포인트**: (공격자) 백업 아카이브 추출 → 평문/암호 데이터 획득. 발견 자체가 취약점.
- **신뢰도 기본값**: 가설 → **승급**: manifest 설정 + 백업 아카이브에서 민감 데이터 노출 확인.
- **금융 가중**: 예

---

## 패밀리 4 — 누수: UI·시스템 부수 채널 (MASVS-STORAGE-2, PLATFORM 교차)

### [STO-LEAK-01] 클립보드 · 스크린샷 · 키보드 캐시 · 프로세스 메모리 노출
- **표준 매핑**: MASVS-STORAGE-2(부수 누수 일반) / MASWE: STORAGE 지식문서가 다루는 영역이나 **개별 MASWE 번호는 일부 MASVS-PLATFORM로 분산**(예: 접근성 경유 누수 MASWE-0040=PLATFORM) ⚠️ 항목별 정확 MASWE는 발견 시 live 재확인 — STORAGE-2 통제 자체는 확정
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java), manifest
- **탐지 신호**: 민감 입력에 클립보드 복사 허용(`ClipboardManager.setPrimaryClip`)·붙여넣기 민감 필드, 민감 화면에 `FLAG_SECURE` 미설정(스크린샷·최근앱 썸네일 노출), 민감 `EditText`에 `inputType`의 `textNoSuggestions`/`textPassword` 미적용(키보드 학습 캐시), 민감 데이터가 프로세스 메모리에 장기 상주(가변 버퍼 미소거).
- **오탐 함정**: ① 클립보드/스크린샷 허용이 UX상 필요한 비민감 화면이면 무해 — 화면의 데이터 민감도로 판정. ② `FLAG_SECURE` 부재가 모든 화면에 문제는 아님(로그인·결제·PIN 등 민감 화면만). ③ 메모리 상주는 측정 난도 높아 과소/과대평가 주의.
- **검증 방법(oracle)**: ① 민감 화면(로그인·PIN·결제)에서 `FLAG_SECURE`·클립보드 제한·`inputType` 설정을 정적 확인. ② 동적: 클립보드 덤프·최근앱 스크린샷·키보드 캐시·메모리 스크랩으로 실제 노출 확인.
- **우회 포인트**: (공격자) 클립보드 스니핑·화면 캡처·키보드 캐시·메모리 덤프로 민감값 수집. 접근성 서비스 경유는 [`60-platform.md`](./60-platform.md)(MASWE-0040) 교차.
- **신뢰도 기본값**: 가설 → **승급**: 민감 화면/필드에서 부수 채널 노출이 정적+동적으로 확인됨.
- **금융 가중**: 예

---

## 커버리지 체크리스트 (2차 패스 — 공백 점검용)

- [ ] STO-PLAIN-01 앱 전용 저장소 평문 (MASWE-0001)
- [ ] STO-EXT-01 외부/공유 저장소 평문 (MASWE-0002)
- [ ] STO-KEY-01 키를 KeyStore 밖 저장 (MASWE-0003)
- [ ] STO-HARDCODE-01 패키지 내 하드코딩 시크릿 (MASWE-0004)
- [ ] STO-LOG-01 로그 누수 (MASWE-0005)
- [ ] STO-BACKUP-01 백업 미제외 (MASWE-0006)
- [ ] STO-LEAK-01 클립보드·스크린샷·키보드캐시·메모리 (STORAGE-2, PLATFORM 교차)

> ⚠️ **manifest/리소스 의존 항목 주의**: STO-BACKUP-01(allowBackup·백업규칙)과 STO-LEAK-01(FLAG_SECURE 등 일부)은 **manifest/리소스가 있어야** 판정 가능. `/rev-jadx`가 `--no-res`로 돌면 미추출 → `--no-res` 없이 재실행하거나 manifest·리소스만 별도 추출해 확인.

---

## 출처 (live 확인, 2026-11-18)

- MASVS-STORAGE: [mas.owasp.org/MASVS/05-MASVS-STORAGE](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
- STORAGE-1: [controls/MASVS-STORAGE-1](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/) · STORAGE-2: [controls/MASVS-STORAGE-2](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/)
- MASWE-0001: [Sensitive Data Stored Unencrypted in Private Storage](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0001/)
- MASWE-0005: [Insertion of Sensitive Data into Logs](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0005/) · MASWE-0006: [Sensitive Data Not Excluded From Backup](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0006/)
- MASWE 전체: [mas.owasp.org/MASWE](https://mas.owasp.org/MASWE/) (STORAGE: 0001~0006, v1.0.0)

> **2026-11-18 live 확인 완료**: MASVS-STORAGE-1/2 wording, MASWE-0001(private 평문)·0002(외부 평문)·0003(키 KeyStore 밖)·0004(하드코딩)·0005(로그)·0006(백업) 6개 실존·카테고리 매핑 확인. STO-LEAK-01의 개별 부수채널 MASWE는 일부 PLATFORM(MASWE-0040 등)로 분산되어 발견 시 재확인 대상으로 ⚠️ 표기.
