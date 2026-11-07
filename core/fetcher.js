'use strict';

/**
 * 底层 HTTP 抓取器（零依赖，基于 node:http/https/zlib）
 *
 *  - 手动跟随重定向并记录链路，含次数上限与循环检测
 *  - 限制「压缩后」与「解压后」两道体积上限，防超大页面与压缩炸弹
 *  - 自动解压 gzip / deflate / br / zstd（按运行时能力）
 *  - 按 Content-Type 与 <meta charset> 解码（GBK/GB18030/Big5 等），避免中文站点乱码误判
 *  - 任何路径都 settle：同步构造异常、socket 早退、对端 FIN、超时均有兜底
 */
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const { URL } = require('url');
const { TextDecoder } = require('util');
const CONFIG = require('./config');
const { CODES, appError } = require('./errors');
const logger = require('./logger');

const USER_AGENT = 'Mozilla/5.0 (compatible; SiteSecAudit/1.0; +website-security-assessment)';
const REDIRECT_CODES = [301, 302, 303, 307, 308];

/** 只声明运行时真正支持的编码，避免服务端返回解不开的字节流 */
const CAN_ZSTD = typeof zlib.zstdDecompressSync === 'function';
const ACCEPT_ENCODING = ['gzip', 'deflate', 'br'].concat(CAN_ZSTD ? ['zstd'] : []).join(', ');

/** 从 Content-Type 与 HTML 头部推断字符集；只在 HTML/XML/文本类上做 meta 推断 */
function sniffCharset(buf, contentType) {
  const ct = String(contentType || '').toLowerCase();
  const fromHeader = /charset\s*=\s*["']?([\w-]+)/.exec(ct);
  if (fromHeader && fromHeader[1]) return fromHeader[1].toLowerCase();
  if (!/(html|xml|text\/|javascript|json)/.test(ct)) return 'utf-8';
  const head = buf.subarray(0, 4096).toString('latin1');
  const metaCharset = /<meta[^>]+charset\s*=\s*["']?\s*([\w-]+)/i.exec(head)
    || /<meta[^>]+content\s*=\s*["'][^"']*charset\s*=\s*([\w-]+)/i.exec(head);
  return metaCharset && metaCharset[1] ? metaCharset[1].toLowerCase() : 'utf-8';
}

/** 统一解码：优先 TextDecoder（支持非 UTF-8），不支持的编码回退 utf8 并标记 */
function decodeText(buf, charset) {
  const cs = String(charset || 'utf-8').toLowerCase();
  if (cs === 'utf-8' || cs === 'utf8' || cs === 'us-ascii' || cs === 'ascii') {
    return { text: buf.toString('utf8'), charset: 'utf-8', decoded: true };
  }
  try {
    const dec = new TextDecoder(cs, { fatal: false });
    return { text: dec.decode(buf), charset: cs, decoded: true };
  } catch (e) {
    return { text: buf.toString('utf8'), charset: 'utf-8', decoded: false };
  }
}

/**
 * 解压 + 解码。返回 { text, charset, truncatedByDecompression, decompressFailed }
 * maxOutputLength 由 zlib 在解压过程中强制，避免 1MB 压缩包膨胀成数百 MB。
 */
function decodeBody(buf, encoding, contentType) {
  const empty = { text: '', charset: 'utf-8', truncatedByDecompression: false, decompressFailed: false };
  if (!buf || !buf.length) return empty;
  const enc = String(encoding || '').toLowerCase();
  const maxOut = CONFIG.limits.maxDecompressed;
  let b = buf;
  let decompressFailed = false;
  let truncatedByDecompression = false;
  try {
    if (enc.includes('br')) {
      if (!zlib.brotliDecompressSync) throw new Error('运行时不支持 brotli');
      b = zlib.brotliDecompressSync(buf, { maxOutputLength: maxOut });
    } else if (enc.includes('gzip') || enc.includes('x-gzip')) {
      b = zlib.gunzipSync(buf, { maxOutputLength: maxOut });
    } else if (enc.includes('deflate')) {
      try { b = zlib.inflateSync(buf, { maxOutputLength: maxOut }); }
      catch (e) { b = zlib.inflateRawSync(buf, { maxOutputLength: maxOut }); }
    } else if (enc.includes('zstd')) {
      if (!CAN_ZSTD) throw new Error('运行时不支持 zstd');
      b = zlib.zstdDecompressSync(buf, { maxOutputLength: maxOut });
    }
  } catch (e) {
    // ERR_BUFFER_TOO_LARGE：解压后超限，保留原始字节并标记；其余解压失败也按原文处理
    if (e && (e.code === 'ERR_BUFFER_TOO_LARGE' || /maxOutputLength/i.test(e.message || ''))) {
      truncatedByDecompression = true;
    } else {
      logger.debug('FETCH', '解压失败，按原始字节解码', { encoding: enc, reason: e.message });
    }
    decompressFailed = true;
    b = buf;
  }
  const charset = sniffCharset(b, contentType);
  const decoded = decodeText(b, charset);
  return {
    text: decoded.text,
    charset: decoded.charset,
    charsetDecoded: decoded.decoded,
    truncatedByDecompression,
    decompressFailed,
  };
}

/**
 * 单次请求。始终 resolve，不 reject；失败时 { ok:false, error:{ code, message } }
 */
function rawRequest(urlStr, options = {}) {
  const opts = Object.assign({
    method: 'GET',
    timeout: CONFIG.timeouts.page,
    maxBody: CONFIG.limits.maxBody,
    headers: {},
    rejectUnauthorized: true,
    followRedirect: false,
  }, options);

  return new Promise((resolve) => {
    let settled = false;
    let guard = null;
    let req = null;
    const done = (v) => {
      if (settled) return;
      settled = true;
      if (guard) clearTimeout(guard);
      resolve(v);
    };

    /* 兜底定时器必须在最前面就位：覆盖 URL 解析、mod.request 同步抛错、
     * 以及「连接建立了但所有事件都没来」的悬挂场景 */
    guard = setTimeout(() => {
      done({
        ok: false,
        error: appError(CODES.TIMEOUT, '请求超时(' + (opts.timeout + CONFIG.guardBufferMs) + 'ms 兜底)'),
        url: urlStr,
      });
      try { if (req) req.destroy(); } catch (e) { /* ignore */ }
    }, opts.timeout + CONFIG.guardBufferMs);
    // 保持引用：这是防止 Promise 永久悬挂的最后一道保险，不能因无其它句柄而被跳过

    let u;
    try { u = new URL(urlStr); }
    catch (e) {
      return done({ ok: false, error: appError(CODES.INVALID_URL, '无效 URL: ' + logger.redact(urlStr)), url: urlStr });
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return done({ ok: false, error: appError(CODES.UNSUPPORTED_PROTOCOL, '不支持的协议: ' + u.protocol), url: urlStr });
    }
    if (u.username || u.password) {
      // 不接受内嵌凭据：既不发到对端，也不让凭据进入日志/报告
      return done({ ok: false, error: appError(CODES.INVALID_URL, 'URL 不允许包含内嵌用户名或密码'), url: urlStr });
    }

    try {
      const mod = u.protocol === 'https:' ? https : http;
      req = mod.request(u, {
        method: opts.method,
        headers: Object.assign({
          'User-Agent': USER_AGENT,
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Encoding': ACCEPT_ENCODING,
          Connection: 'close',
        }, opts.headers),
        timeout: opts.timeout,
        rejectUnauthorized: opts.rejectUnauthorized,
      }, (res) => {
        const chunks = [];
        let size = 0;
        let truncated = false;
        let ended = false;
        const finish = (forced) => {
          if (ended) return;
          ended = true;
          const raw = Buffer.concat(chunks);
          const dec = decodeBody(raw, res.headers['content-encoding'], res.headers['content-type']);
          done({
            ok: true,
            status: res.statusCode,
            statusText: res.statusMessage,
            headers: res.headers,
            rawHeaders: res.rawHeaders,
            url: u.toString(),
            contentType: String(res.headers['content-type'] || ''),
            contentLength: res.headers['content-length'] != null ? Number(res.headers['content-length']) : null,
            bodyRaw: raw,
            body: dec.text,
            charset: dec.charset,
            charsetDecoded: dec.charsetDecoded,
            truncated,
            truncatedByDecompression: dec.truncatedByDecompression,
            decompressFailed: dec.decompressFailed,
            incomplete: !!forced,
          });
        };
        res.on('data', (c) => {
          if (truncated || ended) return;
          size += c.length;
          if (size > opts.maxBody) {
            // 保留已读部分并标记截断：页面过大 ≠ 不可达，但内容类结论需标注不完整。
            // 立即结算，不依赖 req/res 后续事件顺序（destroy 后事件顺序在不同 Node 版本不一致）。
            truncated = true;
            finish(true);
            try { req.destroy(); } catch (e) { /* ignore */ }
            return;
          }
          chunks.push(c);
        });
        res.on('error', (err) => {
          if (truncated) finish(true);
          else done({ ok: false, error: appError(CODES.FETCH_FAIL, err.message, err), url: u.toString() });
        });
        res.on('aborted', () => { if (truncated) finish(true); else done({ ok: false, error: appError(CODES.FETCH_FAIL, '响应被对端提前中断'), url: u.toString() }); });
        res.on('close', () => {
          if (ended) return;
          // 正常 end 会先置 ended；走到这里说明连接未完整结束
          if (truncated) finish(true);
          else done({ ok: false, error: appError(CODES.FETCH_FAIL, '连接在响应完成前关闭'), url: u.toString() });
        });
        res.on('end', () => finish(false));
      });
      req.on('error', (err) => done({ ok: false, error: appError(CODES.FETCH_FAIL, err.message, err), url: u.toString() }));
      req.on('timeout', () => {
        try { req.destroy(new Error('请求超时(' + opts.timeout + 'ms)')); } catch (e) { /* ignore */ }
      });
      req.end();
    } catch (e) {
      done({ ok: false, error: appError(CODES.FETCH_FAIL, '请求构造失败：' + e.message, e), url: u.toString() });
    }
  });
}

/**
 * 抓取页面并跟随重定向。
 * 返回 { ok, final, finalUrl, chain, redirects, ... }；失败时带 error.code
 */
async function fetchPage(startUrl, opts = {}) {
  const maxRedirects = opts.maxRedirects != null ? opts.maxRedirects : CONFIG.limits.maxRedirects;
  const timeout = opts.timeout || CONFIG.timeouts.page;
  const chain = [];
  const visited = new Set();
  let current = startUrl;
  visited.add(current);

  for (let i = 0; ; i++) {
    const res = await rawRequest(current, { timeout, maxBody: opts.maxBody });
    if (!res.ok) {
      return { ok: false, error: res.error, chain, finalUrl: current };
    }
    chain.push({ url: current, status: res.status });

    const loc = res.headers.location;
    const isRedirect = REDIRECT_CODES.includes(res.status) && !!loc;
    if (!isRedirect) {
      return { ok: true, final: res, finalUrl: current, chain, redirects: chain.length - 1 };
    }
    if (i >= maxRedirects) {
      return {
        ok: false,
        error: appError(CODES.TOO_MANY_REDIRECTS, '重定向次数过多（>' + maxRedirects + '），已中止跟踪'),
        chain, finalUrl: current, redirectExceeded: true,
      };
    }
    let next;
    try { next = new URL(loc, current).toString(); }
    catch (e) {
      return { ok: true, redirectBroken: true, final: res, finalUrl: current, chain, redirects: chain.length - 1 };
    }
    if (!/^https?:/i.test(next)) {
      return {
        ok: false,
        error: appError(CODES.UNSUPPORTED_PROTOCOL, '重定向到不支持的协议：' + next.split(':')[0]),
        chain, finalUrl: current,
      };
    }
    if (visited.has(next)) {
      return {
        ok: false,
        error: appError(CODES.REDIRECT_LOOP, '检测到重定向循环：' + logger.redact(next)),
        chain, finalUrl: current, redirectLoop: true,
      };
    }
    visited.add(next);
    current = next;
  }
}

module.exports = { rawRequest, fetchPage, decodeBody, sniffCharset, USER_AGENT, ACCEPT_ENCODING };
