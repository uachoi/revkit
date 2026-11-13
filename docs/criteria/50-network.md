# NETWORK 분석 기준 — 전송 보안 · 인증서 검증 · 피닝

> 카테고리: **MASVS-NETWORK** (네트워크 통신) · 작성 형식: [`_template.md`](./_template.md)
> 적용 레벨: 대부분 **L1/L2**. RESILIENCE와 달리 **"안전한 통제가 있어야 한다"**가 기본값 — 즉 **부재·약화 자체가 취약점**이다(피닝 부재=MASWE-0028, 평문=MASWE-0026).
> 단, **피닝이 "존재"하는 경우**의 발견은 RESILIENCE처럼 **"어떻게 우회하는가"**가 핵심(예: 네이티브 피닝 → Burp 중계 장애물).

## MASVS-NETWORK 통제 (live 확인됨, 2026-11)

| 통제 | 공식 wording | 다루는 criterion 패밀리 |
|---|---|---|
| **MASVS-NETWORK-1** | The app secures all network traffic according to the current best practices. | 평문 통신, TLS 설정, 인증서 검증(TrustAll/호스트네임) |
| **MASVS-NETWORK-2** | The app performs identity pinning for all remote endpoints under the developer's control. | 인증서/SPKI 피닝 (존재·부재·우회) |

MASWE 매핑(live 확인): **MASWE-0026** Network Traffic Not Encrypted(평문, NETWORK-1), **MASWE-0027** Insecure Certificate Validation(NETWORK-1), **MASWE-0028** Insecure Identity Pinning(NETWORK-2).

> 분석 위치: `manifest`(network_security_config, usesCleartextTraffic) + `jadx`(OkHttp/TrustManager/HostnameVerifier/SSLContext) + `ghidra`(네이티브 TLS·피닝). 동적: Burp/mitmproxy 중계 가능 여부가 최종 oracle.

---

## 패밀리 1 — 평문(Cleartext) 통신 (MASVS-NETWORK-1 / MASWE-0026)

### [NET-CLEAR-01] HTTP 평문 전송 허용
- **표준 매핑**: MASVS-NETWORK-1 / MASWE-0026 / MASTG-TEST-0235(Android 설정상 평문 허용)·0236(네트워크에서 평문 관찰)·0237(크로스플랫폼 프레임워크 설정)·0238(런타임 네트워크 API 평문)
- **적용 레벨**: L1
- **어디서 보나**: manifest, jadx(Java/JS), 동적 트래픽
- **탐지 신호**: `AndroidManifest.xml` `android:usesCleartextTraffic="true"`, `res/xml/network_security_config.xml` 의 `<base-config cleartextTrafficPermitted="true">`/`<domain-config cleartextTrafficPermitted="true">`, 코드의 `http://` URL 상수, OkHttp `ConnectionSpec.CLEARTEXT`, React Native/웹뷰의 `http://` 엔드포인트, `WebView` `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)`.
- **오탐 함정(FP trap)**: ① `http://` 가 **localhost/루프백·개발빌드 전용**이거나 스킴 문자열 상수로만 있고 실제 전송 경로 아님. ② `network_security_config` 가 특정 도메인만 cleartext 허용(스코프 확인 필요). ③ 광고/애널리틱스 3rd-party 트래픽(앱 자체 민감데이터 아님 — 그래도 기록).
- **검증 방법(oracle)**: ① manifest/NSC 정적 파싱으로 허용 범위 확인. ② **동적**: 프록시로 평문 HTTP 요청이 실제로 관찰되는지(MASTG-TEST-0236). 민감 데이터(인증토큰·PII) 평문 전송이면 확정.
- **우회 포인트**: (공격자 관점) 평문이면 **중간자가 바로 열람·변조** — 별도 우회 불필요. 발견 자체가 취약점.
- **신뢰도 기본값**: 가설 → **승급**: 동적으로 민감 데이터 평문 전송 관찰.
- **금융 가중**: 예

---

## 패밀리 2 — 인증서 검증 약화 (MASVS-NETWORK-1 / MASWE-0027)

### [NET-TRUST-01] TrustAll / 커스텀 TrustManager (모든 인증서 수락)
- **표준 매핑**: MASVS-NETWORK-1 / MASWE-0027 / MASTG-KNOW-0015(Certificate Pinning — trust-all 금지)
- **적용 레벨**: L1
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: `X509TrustManager` 구현의 `checkServerTrusted()` **빈 바디**(예외 미발생), `HostnameVerifier` 가 `verify(){ return true; }`, `SSLContext.init` 에 커스텀 trust-all 주입, OkHttp `hostnameVerifier((h,s)->true)`, `setDefaultHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER)`, (scn00 예) `observedSpki$trustAll$1` 류 TrustAll 익명클래스.
- **오탐 함정**: ① TrustAll 이 **테스트/디버그 플레이버 전용**(`BuildConfig.DEBUG` 가드) — 릴리스에선 비활성. ② 사설 CA 핀셋을 **직접 검증하려고** TrustManager 를 커스텀했으나 실제론 올바르게 검증(빈 바디인지 확인). 
- **검증 방법(oracle)**: ① `checkServerTrusted` 바디가 실제로 비었는지/무조건 통과인지 디컴파일 확인, 릴리스 분기인지 교차. ② **동적**: 임의(자가서명) 인증서로 프록시 중계 시 연결 성립하면 확정.
- **우회 포인트**: (분석가 관점) TrustAll 이면 **Burp 중계가 그냥 됨** — 피닝 없는 통로. 반대로 "취약점 발견 포인트"로 보고.
- **신뢰도 기본값**: 가설 → **승급**: 빈 검증 바디 + 릴리스 적용 확인(+동적 자가서명 통과).
- **금융 가중**: 예

### [NET-TLS-01] 약한 TLS 설정 (프로토콜/cipher/호스트네임)
- **표준 매핑**: MASVS-NETWORK-1 / MASWE-0027 / MASTG-TEST(네트워크 TLS 계열) `⚠️ 세부 테스트 slug는 live 재확인 권장` ([mas.owasp.org/MASTG/tests](https://mas.owasp.org/MASTG/tests/))
- **적용 레벨**: L2
- **어디서 보나**: jadx(Java), ghidra(.so), 동적
- **탐지 신호**: 구 프로토콜 강제(`SSLv3`/`TLSv1.0`/`TLSv1.1`), 약한 cipher suite 허용, `ConnectionSpec.COMPATIBLE_TLS` 과도 허용, 네이티브 BoringSSL/커스텀 TLS 에서 검증 생략, 호스트네임 검증 누락(위 NET-TRUST 와 교차).
- **오탐 함정**: 하위호환용으로 구 버전을 **목록에 두되 실제 협상은 최신**일 수 있음 — 실제 핸드셰이크 확인 필요. 
- **검증 방법(oracle)**: ① 코드의 enabled protocols/ciphers 상수 확인. ② **동적**: TLS 핸드셰이크 캡처로 실제 협상 버전/cipher 확인(testssl 류).
- **우회 포인트**: 약한 협상 강제 가능 시 다운그레이드 MITM.
- **신뢰도 기본값**: 가설. **금융 가중**: 예.

---

## 패밀리 3 — 인증서/SPKI 피닝 (MASVS-NETWORK-2 / MASWE-0028)

> 피닝은 **양면**이다. **부재**면 MASWE-0028 취약점(발견). **존재**면 분석가의 중계(Burp)를 막는 방어 → "어떻게 우회하나"가 핵심(RESILIENCE 성격). 아래 두 criterion으로 구현 레이어를 구분한다.

### [NET-PIN-01] Java/설정 레벨 피닝 (NSC · OkHttp · TrustManager)
- **표준 매핑**: MASVS-NETWORK-2 / MASWE-0028 / MASTG-TEST-0242(NSC 피닝 부재)·0244(트래픽상 피닝 부재) · KNOW-0015
- **적용 레벨**: L2
- **어디서 보나**: manifest, jadx(Java)
- **탐지 신호**: `network_security_config.xml` 의 `<pin-set><pin digest="SHA-256">...</pin>`, OkHttp `CertificatePinner.Builder().add(host, "sha256/...")`, 커스텀 TrustManager 내 공개키/인증서 해시 상수 비교, `res/raw`·`assets` 의 `.cer`/`.pem` 핀 파일.
- **오탐 함정**: ① 피닝 상수는 있으나 **적용 안 된 OkHttpClient 인스턴스**가 따로 있어 실트래픽은 미피닝(부분피닝). ② NSC 핀이 **특정 도메인만** — 다른 엔드포인트는 미피닝.
- **검증 방법(oracle)**: ① 핀셋이 실제 사용되는 클라이언트/도메인에 적용되는지 xref. ② **동적**: Frida unpinning 스크립트(OkHttp CertificatePinner/ TrustManager 후킹)로 Burp 중계 성립하면 "Java 레벨 피닝"으로 확정, 성립 안 하면 네이티브 피닝(NET-PIN-02) 의심.
- **우회 포인트**: Frida 범용 unpinning(objection `android sslpinning disable`), NSC 핀 제거 후 재패키징, `CertificatePinner` 후킹.
- **신뢰도 기본값**: 가설 → **승급**: 핀 적용 범위 확인 + Frida unpinning 으로 중계 성립 재현.
- **금융 가중**: 예

### [NET-PIN-02] 네이티브(.so) 레벨 피닝 (SPKI/인증서 지문 비교)
- **표준 매핑**: MASVS-NETWORK-2 / MASWE-0028 / MASTG-KNOW-0015(피닝은 네이티브 코드로도 구현 가능)
- **적용 레벨**: L2
- **어디서 보나**: ghidra(.so)
- **탐지 신호**: 네이티브에서 직접 `socket`/`getaddrinfo`/TLS ClientHello 조립·전송, 수신 `Certificate`(TLS record 0x16, handshake 0x0b) ASN.1 DER(SEQUENCE 0x30) 수동 파싱, leaf 인증서/공개키의 **SHA-256 지문 상수 비교**, SPKI 핀 상수(`.rodata` 32바이트 해시), HTTP `CONNECT host:port` 프록시 터널 문자열.
- **오탐 함정**: ① 네이티브 해시 계산이 **무결성(RES-INTEG)·서명**용이고 피닝이 아닐 수 있음 — **TLS 핸드셰이크/인증서 파싱 맥락**이 있어야 피닝. ② 지문을 수집만 하고 **서버가 비교**(증거수집형, → [10-resilience.md §RASP 유형](./10-resilience.md)) 일 수 있음 — 로컬 비교 분기 유무 확인.
- **검증 방법(oracle)**: ① 어셈블리에서 **지문 비교 분기**(일치 시 통과 / 불일치 시 차단)가 로컬에 있는지, 아니면 수집→서버전송인지 구분. ② **동적**: Java unpinning 으로 **안 풀리면** 네이티브 피닝 확정 → 네이티브 비교 함수 후킹/패치.
- **우회 포인트**: **Java/SSLContext 후킹으로는 안 풀림.** 네이티브 피닝 비교 함수 `Interceptor.replace`/반환 고정, 또는 지문 상수 패치. 증거수집형이면 §RASP 유형대로 서명 공략.
- **신뢰도 기본값**: 가설 → **승급**: 어셈블리 비교 분기 확인 + 네이티브 후킹으로 중계 성립 재현.
- **금융 가중**: 예
- **예시(scn00)**: `nativeSignedReportPinning`(`libscn00monitor.so` 0x103a1c) — `lab.eqst.co.kr:8406` 로 직접 TLS 접속해 leaf 인증서 SHA-256 지문 수집, `PINNED_SPKI` 상수 보유, `CONNECT %s:%d` 터널. **증거수집형**(지문을 HMAC 리포트에 실어 서버 업링크) → 우회는 분기 뒤집기가 아니라 **HMAC 키 위조 또는 네이티브 수집 무력화**.

---

## 패밀리 4 — MITM/프록시 탐지 (방어 통제, RESILIENCE 교차)

### [NET-MITM-01] 프록시/중간자 탐지
- **표준 매핑**: MASVS-NETWORK-1 (보조) · 탐지 메커니즘 측면은 MASVS-RESILIENCE-4 와 교차 → [10-resilience.md](./10-resilience.md) RES-HOOK/증거수집형 참조
- **적용 레벨**: L2 / R
- **어디서 보나**: jadx(Java), ghidra(.so)
- **탐지 신호**: `System.getProperty("http.proxyHost"/"http.proxyPort")` 검사, `ConnectivityManager`/`ProxyInfo` 조회, VPN 인터페이스(`tun0`) 탐지, 인증서 체인에 사용자설치 CA 존재 여부 검사.
- **오탐 함정**: 프록시 프로퍼티 조회가 **정상 네트워크 설정**용일 수 있음 — 탐지→대응/서버보고 분기가 있어야 방어.
- **검증 방법(oracle)**: 프록시/VPN 검사 결과가 차단·리포트로 가는지 확인. 동적으로 프록시 설정 후킹해 미탐 유도.
- **우회 포인트**: 프록시 getter·VPN 인터페이스 조회 후킹, 또는 투명 프록시(iptables redirect)로 앱이 프록시 설정을 못 보게.
- **신뢰도 기본값**: 가설. **금융 가중**: 예.

---

## 커버리지 체크리스트 (2차 패스 — 공백 점검용)

- [ ] NET-CLEAR-01 평문 HTTP 통신
- [ ] NET-TRUST-01 TrustAll / 커스텀 TrustManager
- [ ] NET-TLS-01 약한 TLS 설정
- [ ] NET-PIN-01 Java/설정 레벨 피닝 (존재/부재/우회)
- [ ] NET-PIN-02 네이티브 레벨 피닝
- [ ] NET-MITM-01 프록시/중간자 탐지

---

## 출처 (live 확인, 2026-11)

- MASVS-NETWORK: [mas.owasp.org/MASVS/08-MASVS-NETWORK](https://mas.owasp.org/MASVS/08-MASVS-NETWORK/)
- MASVS-NETWORK-1: [controls/MASVS-NETWORK-1](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/) · NETWORK-2: [controls/MASVS-NETWORK-2](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/)
- MASWE-0026/0027/0028 (MASWE v1.0.0): [mas.owasp.org/MASWE](https://mas.owasp.org/MASWE/)
- MASTG 평문: TEST-0235/0236/0237/0238 · 피닝: TEST-0242/0244, [KNOW-0015 Certificate Pinning](https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015/)
- (참고) MASTG-TEST-0022 Custom Cert Stores/Pinning = **deprecated**
