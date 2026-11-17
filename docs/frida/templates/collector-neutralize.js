/*
 * collector-neutralize.js — ⓐ collector 무력화 (Frida 16.2.1)
 * ---------------------------------------------------------------------------
 * 증거수집형 RASP 대상. 탐지 "분기"가 없고 흔적을 수집→서명→서버 업링크하므로,
 * 우회는 "분기 뒤집기"가 아니라 **수집기(collector)가 빈/clean 결과를 반환**하게 만드는 것.
 * 네이티브 collector의 반환 문자열을 비우고, 그 Java 미러 탐지 메서드를 false로 돌린다.
 *
 * ❗ native + Java가 쌍이면 한쪽만 막으면 FN(앱이 다른 경로로 재탐지). 둘 다 처리.
 * ❗ 버전 16.2.1 API. _bootstrap.js 패턴(dlopen 선점) 재사용. frida-server도 16.2.1.
 * 실행: frida -U -f <패키지> -l collector-neutralize.js   (spawn 기본)
 *       frida -U -n "<앱이름>" -l collector-neutralize.js  (attach 폴백)
 * 매핑 criterion: RES-ROOT-01/02, RES-DBG-01/02, RES-HOOK-01/02, RES-EMU-01,
 *                 RES-INTEG-01/02(서명 getter 섹션).
 * ---------------------------------------------------------------------------
 */

'use strict';

// ── 파라미터 (대상 노트 native/*.md · java_analysis.md 에서 채운다) ──────────
var TARGET_SO = 'libXXX.so';   // 예시: 'libscn00monitor.so'
var VERBOSE   = true;

// 네이티브 collector export: 반환이 "수집된 증거 문자열"인 함수들.
// 예시(scn00): ['nativeRootEvidence','nativeFridaEvidence','nativeDebuggerEvidence']
var NATIVE_COLLECTORS = [
  // 'nativeRootEvidence',
  // 'nativeFridaEvidence',
  // 'nativeDebuggerEvidence'
];

// Java 탐지 메서드: {클래스, 메서드, 반환값}. 반환 타입에 맞게 clean 값 지정.
// 예시(scn00): Scn00MonitorModule.appLayerDetectsRoot()->false 등
var JAVA_DETECTORS = [
  // { clazz: 'kr.co.eqst.pay.s00.Scn00MonitorModule', method: 'appLayerDetectsRoot',  ret: false },
  // { clazz: 'kr.co.eqst.pay.s00.Scn00MonitorModule', method: 'appLayerDetectsFrida', ret: false },
  // { clazz: 'kr.co.eqst.pay.s00.Scn00MonitorModule', method: 'appLayerDetectsDebugger', ret: false }
];

// APK 서명 getter 위장(RES-INTEG-01/02). 정품 해시를 반환하게.
// 예시(scn00): Scn00MonitorModule.signingCertSha256() -> OFFICIAL_CERT_SHA256 값
var SIGNING_SPOOF = [
  // { clazz: 'kr.co.eqst.pay.s00.Scn00MonitorModule', method: 'signingCertSha256', ret: 'fac61745...033b9c' }
];

function log(m) { if (VERBOSE) console.log('[neutralize] ' + m); }

// ── 네이티브 collector 반환을 빈 문자열로 ───────────────────────────────────
// 대개 char* / jstring 반환. jstring은 Java.vm로 NewStringUTF("")를 새로 만들어 교체.
function installNativeHooks() {
  NATIVE_COLLECTORS.forEach(function (name) {
    var p = Module.findExportByName(TARGET_SO, name);
    if (p === null) { log('native export not found: ' + name); return; }
    Interceptor.attach(p, {
      onLeave: function (retval) {
        // (A) 반환이 C 문자열 포인터면: 빈 문자열 버퍼로 교체.
        //     var empty = Memory.allocUtf8String(''); retval.replace(empty);
        // (B) 반환이 jstring(JNI)이면: 새 빈 jstring으로 교체.
        try {
          var env = Java.vm.tryGetEnv();
          if (env !== null) {
            // jstring 반환: newStringUtf 결과는 이미 NativePointer(jstring).
            // ptr()로 감싸면 16.2.1에서 타입 오류 — 그대로 replace.
            retval.replace(env.newStringUtf(''));
          } else {
            retval.replace(Memory.allocUtf8String(''));
          }
          log('cleaned native return of ' + name);
        } catch (e) { log('native clean error ' + name + ': ' + e); }
      }
    });
    log('hooked native collector ' + name + ' @ ' + p);
  });
}

// ── Java 탐지 메서드 clean 반환 ─────────────────────────────────────────────
function installJavaHooks() {
  if (!Java.available) { log('Java VM unavailable'); return; }
  Java.perform(function () {
    JAVA_DETECTORS.concat(SIGNING_SPOOF).forEach(function (d) {
      try {
        var C = Java.use(d.clazz);
        // 오버로드가 여러 개면 모두 교체.
        var overloads = C[d.method].overloads;
        overloads.forEach(function (ov) {
          ov.implementation = function () {
            log('Java ' + d.clazz + '.' + d.method + ' -> ' + d.ret);
            return d.ret;
          };
        });
      } catch (e) { log('java hook error ' + d.clazz + '.' + d.method + ': ' + e); }
    });
  });
}

// ── 엔트리: .so 로드 선점 후 네이티브 설치 + Java 설치 ──────────────────────
(function main() {
  // Java 탐지는 VM 준비 후 바로 설치(클래스 로드 전이면 재시도 필요할 수 있음).
  installJavaHooks();

  // 네이티브는 .so 로드 시점에 선점.
  var base = Module.findBaseAddress(TARGET_SO);
  if (base !== null) { installNativeHooks(); return; }

  var armed = false;
  ['android_dlopen_ext', 'dlopen'].forEach(function (sym) {
    var p = Module.findExportByName(null, sym);
    if (p === null) return;
    Interceptor.attach(p, {
      onEnter: function (a) {
        try { var s = a[0].readUtf8String(); this.hit = (s && s.indexOf(TARGET_SO) !== -1); }
        catch (e) { this.hit = false; }
      },
      onLeave: function () {
        if (this.hit && !armed && Module.findBaseAddress(TARGET_SO) !== null) {
          armed = true; log(TARGET_SO + ' loaded — installing native hooks'); installNativeHooks();
        }
      }
    });
  });
  log('armed dlopen watcher for ' + TARGET_SO);
})();
