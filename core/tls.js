'use strict';

/**
 * TLS / 证书探测（零依赖，基于 node:tls）
 *
 * 注意：协议与套件探测受本地 OpenSSL 版本限制（OpenSSL 3.x 可能拒绝协商部分遗留套件），
 *      无法确认时在结果中标记 limited，报告中如实说明。
 *
 * 性能：协议矩阵与弱套件矩阵彼此独立，用带并发上限的并行探测代替此前 10+ 次串行握手。
 */
const tls = require('tls');
const CONFIG = require('./config');
const { CODES, appError } = require('./errors');
const { mapLimit } = require('./util');
const logger = require('./logger');

const WEAK_CIPHERS = ['RC4-SHA', 'RC4-MD5', 'DES-CBC3-SHA', 'NULL-SHA', 'EXP-RC4-MD5'];
const PROTOCOLS = [
  ['TLSv1.3', 'TLSv1.3'],
  ['TLSv1.2', 'TLSv1.2'],
  ['TLSv1.1', 'TLSv1.1'],
  ['TLSv1', 'TLSv1'],
];

/** URL.hostname 对 IPv6 会带方括号，socket host 需要去掉；SNI 对 IP 无意义 */
function cleanHost(host) {
  const h = String(host || '').trim();
  if (/^\[[0-9a-fA-F:]+\]$/.test(h)) return h.slice(1, -1);
  return h;
}
const isIpLike = (h) => /^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':');

function tlsConnect(host, opts = {}) {
  return new Promise((resolve) => {
    let settled = false;
    let socket = null;
    let timer = null;
    const timeout = opts.timeout || CONFIG.timeouts.tls;
    const done = (v) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(v);
      // 握手成功后主动断开；失败时也要确保句柄释放
      try { if (socket) socket.destroy(); } catch (e) { /* ignore */ }
    };

    const peer = cleanHost(host);
    const options = {
      host: peer,
      port: opts.port || 443,
      rejectUnauthorized: opts.rejectUnauthorized === true, // 默认 false：总是尝试拿证书
      timeout,
    };
    if (!isIpLike(peer)) options.servername = peer;
    if (opts.minVersion) options.minVersion = opts.minVersion;
    if (opts.maxVersion) options.maxVersion = opts.maxVersion;
    if (opts.ciphers) options.ciphers = opts.ciphers;

    // 硬兜底：即使 tls.connect 同步抛错、或所有事件都没触发，也必定结算
    timer = setTimeout(() => {
      done({ ok: false, error: appError(CODES.TIMEOUT, 'TLS 握手超时(' + (timeout + CONFIG.guardBufferMs) + 'ms)') });
    }, timeout + CONFIG.guardBufferMs);
    // 同 fetcher：兜底定时器必须维持事件循环，否则「所有事件都没来」时进程会直接退出

    try {
      socket = tls.connect(options, () => {
        let cert = null;
        try { cert = socket.getPeerCertificate(true); } catch (e) { /* ignore */ }
        done({
          ok: true,
          cert,
          cipher: safe(() => socket.getCipher()),
          protocol: safe(() => socket.getProtocol()),
          authorized: socket.authorized,
          authError: socket.authorizationError ? socket.authorizationError.message : null,
        });
      });
      socket.on('error', (err) => done({ ok: false, error: appError(CODES.TLS_FAIL, err.message, err) }));
      socket.on('close', () => done({ ok: false, error: appError(CODES.TLS_FAIL, 'TLS 连接在握手完成前关闭') }));
      socket.setTimeout(timeout, () => {
        done({ ok: false, error: appError(CODES.TIMEOUT, 'TLS 连接超时(' + timeout + 'ms)') });
      });
    } catch (e) {
      done({ ok: false, error: appError(CODES.TLS_FAIL, 'TLS 连接构造失败：' + e.message, e) });
    }
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

const isProtoReject = (err) => /unsupported|no protocols|protocol version|wrong version|tlsv1 alert|sslv3 alert|handshake failure/i.test(String(err || ''));
const isNetError = (err) => /timeout|超时|ECONNRESET|ECONNREFUSED|EPIPE|EAI_AGAIN|socket hang up/i.test(String(err || ''));

/** 取错误信息文本（兼容旧的字符串形态与新的标准错误对象） */
const errText = (r) => (r && r.error ? r.error.message : null);

/**
 * 探测目标主机 TLS 状况
 */
async function probeTls(host, port, options = {}) {
  port = port || 443;
  const started = Date.now();
  const result = {
    host, port, reachable: false, cert: null, trusted: null, trustError: null,
    protocols: {}, weakCiphers: [], negotiated: null, notes: [], limited: false,
    error: null, durationMs: null,
  };

  const base = await tlsConnect(host, { port, timeout: options.timeout });
  if (!base.ok) {
    result.error = errText(base);
    result.errorCode = base.error ? base.error.code : (base.code || null);
    result.durationMs = Date.now() - started;
    return result;
  }
  result.reachable = true;
  result.cert = normalizeCert(base.cert);
  result.negotiated = { cipher: base.cipher, protocol: base.protocol };

  /* 证书链可信校验 + 协议矩阵 + 弱套件矩阵：彼此独立，一次性并行提交，
   * 用并发上限避免瞬时建连过多（对端限流/本机 fd）。 */
  const tasks = [];
  tasks.push({ kind: 'trust', run: () => tlsConnect(host, { port, rejectUnauthorized: true, timeout: options.timeout }) });
  for (const [label, ver] of PROTOCOLS) {
    tasks.push({
      kind: 'protocol', label,
      run: () => tlsConnect(host, { port, minVersion: ver, maxVersion: ver, timeout: options.timeout }),
    });
  }
  for (const c of WEAK_CIPHERS) {
    tasks.push({
      kind: 'cipher', label: c,
      run: () => tlsConnect(host, { port, ciphers: c, minVersion: 'TLSv1', maxVersion: 'TLSv1.2', timeout: options.timeout }),
    });
  }

  const settled = await mapLimit(tasks, CONFIG.concurrency.tls, async (t) => {
    try { return await t.run(); }
    catch (e) { return { ok: false, error: appError(CODES.TLS_FAIL, e.message, e) }; }
  });

  const noteSet = new Set();
  tasks.forEach((t, i) => {
    const r = settled[i] || { ok: false, error: appError(CODES.TLS_FAIL, '探测未返回结果') };
    const msg = errText(r);
    if (t.kind === 'trust') {
      result.trusted = !!r.ok;
      result.trustError = r.ok ? null : msg;
      return;
    }
    if (t.kind === 'protocol') {
      if (r.ok) result.protocols[t.label] = true;
      else if (isProtoReject(msg)) result.protocols[t.label] = false;
      else if (isNetError(msg)) {
        result.protocols[t.label] = null; // 未知，不计入结论
        result.limited = true;
        noteSet.add(t.label + ' 探测因网络错误未完成（' + (msg || '未知') + '），不计入结论');
      } else {
        result.protocols[t.label] = false;
      }
      return;
    }
    if (t.kind === 'cipher') {
      if (r.ok) result.weakCiphers.push(t.label);
      else if (/no ciphers|no cipher match|unsupported/i.test(String(msg || ''))) {
        result.limited = true;
        noteSet.add('弱套件探测受本地 OpenSSL 限制（部分遗留套件客户端不可用）');
      }
    }
  });
  result.notes = Array.from(noteSet);
  result.durationMs = Date.now() - started;
  logger.debug('TLS', '探测完成', { host: logger.redact(host), port, durationMs: result.durationMs });
  return result;
}

module.exports = { probeTls, tlsConnect, normalizeCert, cleanHost };
