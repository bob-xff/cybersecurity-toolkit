'use strict';

/**
 * TLS / 证书探测（零依赖，基于 node:tls）
 * 注意：协议与套件探测受本地 OpenSSL 版本限制（OpenSSL 3.x 可能拒绝协商部分遗留套件），
 *      无法确认时在结果中标记 limited，报告中如实说明。
 */
const tls = require('tls');

const WEAK_CIPHERS = ['RC4-SHA', 'RC4-MD5', 'DES-CBC3-SHA', 'NULL-SHA', 'EXP-RC4-MD5'];
const PROTOCOLS = [
  ['TLSv1.3', 'TLSv1.3'],
  ['TLSv1.2', 'TLSv1.2'],
  ['TLSv1.1', 'TLSv1.1'],
  ['TLSv1', 'TLSv1'],
];

function tlsConnect(host, opts = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':');
    const options = {
      host,
      port: opts.port || 443,
      rejectUnauthorized: opts.rejectUnauthorized === true, // 默认 false：总是尝试拿证书
      timeout: opts.timeout || 10000,
    };
    if (!isIp) options.servername = host;
    if (opts.minVersion) options.minVersion = opts.minVersion;
    if (opts.maxVersion) options.maxVersion = opts.maxVersion;
    if (opts.ciphers) options.ciphers = opts.ciphers;
    let socket;
    try {
      socket = tls.connect(options, () => {
        let cert = null;
        try { cert = socket.getPeerCertificate(true); } catch (e) {}
        done({
          ok: true,
          cert,
          cipher: safe(() => socket.getCipher()),
          protocol: safe(() => socket.getProtocol()),
          authorized: socket.authorized,
          authError: socket.authorizationError ? socket.authorizationError.message : null,
        });
        try { socket.destroy(); } catch (e) {}
      });
    } catch (e) {
      return done({ ok: false, error: e.message });
    }
    socket.on('error', (err) => done({ ok: false, error: err.message, code: err.code }));
    socket.setTimeout(opts.timeout || 10000, () => {
      try { socket.destroy(new Error('TLS 连接超时')); } catch (e) {}
    });
  });
}

function safe(fn) { try { return fn(); } catch (e) { return null; } }

function normalizeCert(cert) {
  if (!cert || !cert.subject) return null;
  const altNames = String(cert.subjectaltname || '')
    .split(',')
    .map((s) => s.trim().replace(/^(DNS|IP Address):/i, ''))
    .filter(Boolean);
  return {
    subject: cert.subject || {},
    issuer: cert.issuer || {},
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    daysRemaining: daysUntil(cert.valid_to),
    altNames,
    fingerprint: cert.fingerprint256 || cert.fingerprint,
    selfSigned: !!(cert.issuer && cert.subject && cert.issuer.CN === cert.subject.CN && !cert.issuerCertificate),
    serialNumber: cert.serialNumber,
  };
}

function daysUntil(dateStr) {
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return null;
  return Math.floor((d.getTime() - Date.now()) / 86400000);
}

/**
 * 探测目标主机 TLS 状况
 */
async function probeTls(host, port) {
  port = port || 443;
  const result = { host, port, reachable: false, cert: null, trusted: null, trustError: null, protocols: {}, weakCiphers: [], negotiated: null, notes: [], limited: false, error: null };

  const base = await tlsConnect(host, { port });
  if (!base.ok) {
    result.error = base.error;
    result.errorCode = base.code;
    return result;
  }
  result.reachable = true;
  result.cert = normalizeCert(base.cert);
  result.negotiated = { cipher: base.cipher, protocol: base.protocol };

  // 证书链可信校验
  const trust = await tlsConnect(host, { port, rejectUnauthorized: true });
  result.trusted = !!trust.ok;
  result.trustError = trust.ok ? null : trust.error;

  // 协议版本矩阵
  // 注意：区分「服务端拒绝该协议」（可下结论）与「网络层失败/超时」（不可下结论，记 null）
  const isProtoReject = (err) => /unsupported|no protocols|protocol version|wrong version|tlsv1 alert|sslv3 alert|handshake failure/i.test(String(err || ''));
  const isNetError = (err) => /timeout|超时|ECONNRESET|ECONNREFUSED|EPIPE|EAI_AGAIN|socket hang up/i.test(String(err || ''));
  for (const [label, ver] of PROTOCOLS) {
    const r = await tlsConnect(host, { port, minVersion: ver, maxVersion: ver });
    if (r.ok) {
      result.protocols[label] = true;
    } else if (isProtoReject(r.error)) {
      result.protocols[label] = false;
    } else if (isNetError(r.error)) {
      result.protocols[label] = null; // 未知，不计入结论
      result.limited = true;
      result.notes.push(label + ' 探测因网络错误未完成（' + (r.error || '未知') + '），不计入结论');
    } else {
      result.protocols[label] = false;
    }
  }

  // 弱套件探测
  for (const c of WEAK_CIPHERS) {
    const r = await tlsConnect(host, { port, ciphers: c, minVersion: 'TLSv1', maxVersion: 'TLSv1.2' });
    if (r.ok) {
      result.weakCiphers.push(c);
    } else if (/no ciphers|no cipher match|unsupported/i.test(String(r.error || ''))) {
      result.limited = true;
      result.notes.push('弱套件探测受本地 OpenSSL 限制（部分遗留套件客户端不可用）');
      break;
    }
  }

  return result;
}

module.exports = { probeTls, tlsConnect, normalizeCert };
