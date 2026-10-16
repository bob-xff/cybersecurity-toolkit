'use strict';

/**
 * 底层 HTTP 抓取器（零依赖，基于 node:http/https）
 * - 手动跟随重定向并记录链路
 * - 限制响应体大小与超时
 * - 自动解压 gzip/deflate/br
 */
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const { URL } = require('url');

const USER_AGENT = 'Mozilla/5.0 (compatible; SiteSecAudit/1.0; +website-security-assessment)';
const MAX_BODY = 1024 * 1024; // 1MB
const DEFAULT_TIMEOUT = 15000;

function decodeBody(buf, encoding) {
  if (!buf || !buf.length) return '';
  try {
    const enc = String(encoding || '').toLowerCase();
    let b = buf;
    if (enc.includes('br') && zlib.brotliDecompressSync) b = zlib.brotliDecompressSync(buf);
    else if (enc.includes('gzip')) b = zlib.gunzipSync(buf);
    else if (enc.includes('deflate')) {
      try { b = zlib.inflateSync(buf); } catch (e) { b = zlib.inflateRawSync(buf); }
    }
    return b.toString('utf8');
  } catch (e) {
    return buf.toString('utf8');
  }
}

/**
 * 单次请求。始终 resolve，不 reject；失败时 { ok:false, error }
 */
function rawRequest(urlStr, options = {}) {
  const opts = Object.assign(
    { method: 'GET', timeout: DEFAULT_TIMEOUT, maxBody: MAX_BODY, headers: {}, rejectUnauthorized: true },
    options
  );
  return new Promise((resolve) => {
    let settled = false;
    let guard = null;
    const done = (v) => {
      if (settled) return;
      settled = true;
      if (guard) clearTimeout(guard);
      resolve(v);
    };
    let u;
    try { u = new URL(urlStr); } catch (e) { return done({ ok: false, error: { message: '无效 URL: ' + urlStr } }); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return done({ ok: false, error: { message: '不支持的协议: ' + u.protocol }, url: urlStr });
    }
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(
      u,
      {
        method: opts.method,
        headers: Object.assign(
          {
            'User-Agent': USER_AGENT,
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            Connection: 'close',
          },
          opts.headers
        ),
        timeout: opts.timeout,
        rejectUnauthorized: opts.rejectUnauthorized,
      },
      (res) => {
        const chunks = [];
        let size = 0;
        let truncated = false;
        const finish = () => {
          const raw = Buffer.concat(chunks);
          done({
            ok: true,
            status: res.statusCode,
            statusText: res.statusMessage,
            headers: res.headers,
            rawHeaders: res.rawHeaders,
            url: u.toString(),
            bodyRaw: raw,
            body: decodeBody(raw, res.headers['content-encoding']),
            truncated,
          });
        };
        res.on('data', (c) => {
          if (truncated) return;
          size += c.length;
          if (size > opts.maxBody) {
            // 超过大小上限：保留已读部分并标记截断，不得因页面过大判为"不可达"
            truncated = true;
            req.destroy();
            return;
          }
          chunks.push(c);
        });
        res.on('error', (err) => {
          if (truncated) finish();
          else done({ ok: false, error: { message: err.message, code: err.code }, url: u.toString() });
        });
        res.on('aborted', () => { if (truncated) finish(); });
        res.on('close', () => { if (truncated) finish(); });
        res.on('end', finish);
      }
    );
    /* 兜底：任何异常路径都不得让 Promise 悬空——否则整个评估会永久卡住。
     * 比内建 timeout 多留 2s 作为收尾缓冲；settle 时自动清理。 */
    guard = setTimeout(() => {
      done({ ok: false, error: { message: '请求超时(' + (opts.timeout + 2000) + 'ms 兜底)', code: 'ETIMEDOUT' }, url: urlStr });
      try { req.destroy(); } catch (e) { /* ignore */ }
    }, opts.timeout + 2000);
    req.on('error', (err) => done({ ok: false, error: { message: err.message, code: err.code }, url: u.toString() }));
    req.on('timeout', () => req.destroy(new Error('请求超时(' + opts.timeout + 'ms)')));
    req.end();
  });
}

/**
 * 抓取页面并跟随重定向
 */
async function fetchPage(startUrl, opts = {}) {
  const maxRedirects = opts.maxRedirects != null ? opts.maxRedirects : 5;
  const chain = [];
  let current = startUrl;

  for (let i = 0; ; i++) {
    const res = await rawRequest(current, { timeout: opts.timeout || 15000, maxBody: opts.maxBody });
    if (!res.ok) {
      return { ok: false, error: res.error, chain, finalUrl: current };
    }
    chain.push({ url: current, status: res.status });

    const loc = res.headers.location;
    const isRedirect = [301, 302, 303, 307, 308].includes(res.status) && !!loc;

    // 非重定向（或 3xx 但无 Location）→ 这就是最终页
    if (!isRedirect) {
      return { ok: true, final: res, finalUrl: current, chain, redirects: chain.length - 1 };
    }
    // 重定向预算耗尽：必须显式报错，不能把 3xx 响应当成正常页面返回
    if (i >= maxRedirects) {
      return {
        ok: false,
        error: { message: '重定向次数过多（>' + maxRedirects + '），已中止跟踪' },
        chain, finalUrl: current, redirectExceeded: true
      };
    }

    let next;
    try {
      next = new URL(loc, current).toString();
    } catch (e) {
      return { ok: true, redirectBroken: true, final: res, finalUrl: current, chain, redirects: chain.length - 1 };
    }
    // 重定向成环（同一 URL 再次出现）→ 立即判定，避免耗满预算
    if (chain.some((c) => c.url === next)) {
      return {
        ok: false,
        error: { message: '检测到重定向循环：' + next },
        chain, finalUrl: current, redirectLoop: true
      };
    }
    current = next;
  }
}

module.exports = { rawRequest, fetchPage, USER_AGENT };
