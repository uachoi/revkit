/*
 * smoke.js — scn00 비공격 프로세스 스모크 (Frida 16.2.1)
 * ---------------------------------------------------------------------------
 * 목적: revkit Frida 단계의 "프로세스가 도는가"만 검증. 공격/우회 아님.
 *   ① 스크립트 로드 → ② libscn00monitor.so 로드 포착(dlopen 선점)
 *   → ③ 네이티브 export·Java 탐지 메서드 resolve/attach → ④ 로그 출력.
 *
 * ❗ READ-ONLY: 반환값을 바꾸지 않는다(retval.replace 없음). Java 메서드도
 *    implementation을 교체하지 않고 "존재 확인"만 한다. 앱 동작 불변.
 * ❗ 이 .so는 증거수집형(로컬 차단 분기 없음 — notes 확인) → Frida를 탐지해도
 *    앱을 죽이지 않는다. 따라서 stealth frida-server 없이도 이 스모크는 성립.
 *    (탐지 흔적이 수집될 뿐, resolve/attach 로그 목표엔 지장 없음.)
 * ❗ Frida 16.2.1 / 기기 frida-server도 16.2.1.
 *
 * 실행(기본): frida -U -f kr.co.eqst.pay.s00 -l targets/scn00/frida/smoke.js
 * 실행(폴백): frida -U -n "<앱이름>" -l targets/scn00/frida/smoke.js   (frida-server &)
 * ---------------------------------------------------------------------------
 */

'use strict';

var TARGET_SO  = 'libscn00monitor.so';
// 이 .so는 풀 JNI 이름으로 정적 export됨(RegisterNatives 아님). 풀네임 우선 resolve.
var JNI_PREFIX = 'Java_kr_co_eqst_pay_s00_Scn00MonitorModule_';
var NATIVE_SHORT = [
  'nativeRootEvidence',
  'nativeFridaEvidence',
  'nativeDebuggerEvidence',
  'nativeSignedReport',
  'nativeSignedReportPinning'
];
var JAVA_CLASS   = 'kr.co.eqst.pay.s00.Scn00MonitorModule';
var JAVA_METHODS = [
  'appLayerDetectsRoot',
  'appLayerDetectsFrida',
  'appLayerDetectsDebugger',
  'looksLikeEmulator'
];
var VERBOSE = true;

function log(m) { if (VERBOSE) console.log('[smoke] ' + m); }

// 네이티브 심볼 resolve: 풀 JNI 이름 → 짧은 이름 순으로 시도.
function resolveNative(shortName) {
  var full = JNI_PREFIX + shortName;
  var p = Module.findExportByName(TARGET_SO, full);
  if (p !== null) return { form: 'JNI-full', name: full, addr: p };
  p = Module.findExportByName(TARGET_SO, shortName);
  if (p !== null) return { form: 'short', name: shortName, addr: p };
  return null;
}

// 네이티브: resolve 후 read-only attach(호출/반환 로그만, 변경 없음).
function attachNativeReadonly(soBase) {
  log('── native: ' + TARGET_SO + ' base @ ' + soBase);
  NATIVE_SHORT.forEach(function (sn) {
    var r = resolveNative(sn);
    if (r === null) { log('  ✗ unresolved: ' + sn); return; }
    log('  ✓ resolved ' + sn + ' [' + r.form + '] @ ' + r.addr);
    Interceptor.attach(r.addr, {
      onEnter: function () { log('    → called ' + sn); },
      onLeave: function (retval) {
        log('    ← ' + sn + ' returned (ptr ' + retval + ') [read-only, 미변경]');
      }
    });
  });
}

// Java: 클래스/메서드 존재만 확인(implementation 미교체).
function checkJava() {
  if (!Java.available) { log('Java VM 불가'); return; }
  Java.perform(function () {
    try {
      var C = Java.use(JAVA_CLASS);
      log('── java: class resolved ' + JAVA_CLASS);
      JAVA_METHODS.forEach(function (m) {
        try {
          var n = C[m].overloads.length;
          log('  ✓ method ' + m + ' (overloads ' + n + ') — 존재(미후킹)');
        } catch (e) { log('  ✗ method 없음: ' + m); }
      });
    } catch (e) {
      log('class 미해결(아직 로드 전일 수 있음): ' + e);
    }
  });
}

(function main() {
  log('=== scn00 비공격 스모크 시작 (read-only) ===');
  checkJava();

  var base = Module.findBaseAddress(TARGET_SO);
  if (base !== null) { attachNativeReadonly(base); return; }

  // 아직 미로드 → dlopen 선점으로 로드 시점에 설치.
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
        if (this.hit && !armed) {
          var b = Module.findBaseAddress(TARGET_SO);
          if (b !== null) { armed = true; log(TARGET_SO + ' 로드 포착'); attachNativeReadonly(b); }
        }
      }
    });
    log('dlopen watcher armed on ' + sym);
  });
  log(TARGET_SO + ' 아직 미로드 — dlopen 대기 중');
})();
