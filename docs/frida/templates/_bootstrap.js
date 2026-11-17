/*
 * _bootstrap.js — 공통 부트스트랩 (Frida 16.2.1 가정)
 * ---------------------------------------------------------------------------
 * revkit Frida 단계 공통 패턴. 대상 .so가 로드되는 "그 순간" export에 Interceptor를
 * 선점 설치해, RASP의 탐지 루프(JNI_OnLoad/초기화 근처)가 돌기 전에 가로챈다.
 *
 * ❗ 버전: Frida 16.2.1 전용 API만 사용(Module.findExportByName / Module.getExportByName,
 *    Interceptor.attach/replace, Java.perform/Java.use). 17의 Module.getGlobalExportByName 금지.
 * ❗ frida-server와 클라이언트가 동일 16.2.1이어야 spawn이 안정적.
 * ❗ 안티탐지: 이 스크립트를 올리는 frida-server 자체가 gum-js-loop 스레드·27042/3 포트·
 *    maps 시그니처를 노출한다. 대상이 Frida를 탐지하면(RES-HOOK-01) stealth frida-server
 *    (strongR-frida/florida/hluda 류) + 비표준 포트를 먼저 쓸 것. (docs/frida/00-workflow.md)
 *
 * 실행(기본): frida -U -f <패키지> -l <이 스크립트를 include한 파일>
 * 실행(폴백): frida -U -n "<앱이름>" -l <...>      (기기에 frida-server & )
 * ---------------------------------------------------------------------------
 * 사용법: `frida -l` 은 단일 파일만 로드하므로 이 파일을 import 하지 않는다 —
 *         collector-neutralize.js / report-forge.js 는 이 dlopen 선점 패턴을 각자
 *         인라인 복제한다. 이 파일은 그 **표준 참조본**이다(frida-compile로 번들링할
 *         때만 하단 Bootstrap export를 실제 import해 쓴다).
 *         TARGET_SO를 대상 .so 이름으로 바꾸고 onTargetSoReady(installFn)에 설치
 *         콜백을 넘긴다(installFn은 so base를 인자로 받음).
 */

'use strict';

// ── 파라미터 (대상별로 교체) ────────────────────────────────────────────────
var TARGET_SO = 'libXXX.so';          // 예시: 'libscn00monitor.so'
var VERBOSE   = true;

function log(msg) { if (VERBOSE) console.log('[bootstrap] ' + msg); }

// ── .so 로드 선점: android_dlopen_ext / dlopen 후킹 ─────────────────────────
// 대상 .so가 이미 로드돼 있으면 즉시 설치, 아니면 로드 시점에 설치.
function onTargetSoReady(installFn) {
  var already = Module.findBaseAddress(TARGET_SO);
  if (already !== null) {
    log(TARGET_SO + ' already loaded @ ' + already);
    safeInstall(installFn);
    return;
  }

  var hooked = false;
  ['android_dlopen_ext', 'dlopen'].forEach(function (sym) {
    var p = Module.findExportByName(null, sym);
    if (p === null) return;
    Interceptor.attach(p, {
      onEnter: function (args) {
        try {
          var path = args[0].readUtf8String();
          this.isTarget = (path !== null && path.indexOf(TARGET_SO) !== -1);
        } catch (e) { this.isTarget = false; }
      },
      onLeave: function (retval) {
        if (this.isTarget && !hooked) {
          var base = Module.findBaseAddress(TARGET_SO);
          if (base !== null) {
            hooked = true;
            log(TARGET_SO + ' loaded via dlopen @ ' + base);
            safeInstall(installFn);
          }
        }
      }
    });
    log('dlopen watcher armed on ' + sym);
  });
}

function safeInstall(installFn) {
  try { installFn(Module.findBaseAddress(TARGET_SO)); }
  catch (e) { console.log('[bootstrap] install error: ' + e); }
}

// ── 네이티브 export 후킹 헬퍼 ───────────────────────────────────────────────
// 이름 기반(권장, 리베이스 무관). 주소가 꼭 필요하면 base.add(offset)로.
function hookExport(name, callbacks) {
  var p = Module.findExportByName(TARGET_SO, name);
  if (p === null) { log('export not found: ' + name); return false; }
  Interceptor.attach(p, callbacks);
  log('hooked export ' + name + ' @ ' + p);
  return true;
}

// ── Java 후킹 래퍼 ──────────────────────────────────────────────────────────
function whenJavaReady(fn) {
  if (!Java.available) { log('Java VM not available'); return; }
  Java.perform(function () {
    try { fn(); } catch (e) { console.log('[bootstrap] java hook error: ' + e); }
  });
}

/* frida-compile로 번들링할 때만 쓰는 export. 단일 `-l` 로드 시엔 위 함수들을
   스크립트에 복사해 사용한다(collector-neutralize.js / report-forge.js 참고). */
var Bootstrap = {
  TARGET_SO: TARGET_SO,
  log: log,
  onTargetSoReady: onTargetSoReady,
  hookExport: hookExport,
  whenJavaReady: whenJavaReady
};
