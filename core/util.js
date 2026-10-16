'use strict';

/**
 * 通用工具函数
 */

function normalizeUrl(input) {
  let s = String(input == null ? '' : input).trim();
  if (!s) throw new Error('网址不能为空');
  // 去掉可能的尖括号/引号包裹
  s = s.replace(/^[<"']+/, '').replace(/[>"']+$/, '');
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s)) {
    s = 'https://' + s;
  }
  const u = new URL(s);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error('仅支持 http/https 协议的网址');
  }
  if (!u.hostname) throw new Error('网址缺少主机名');
  return u;
}

function hostnameOf(u) {
  return String(u.hostname || '').toLowerCase().replace(/\.$/, '');
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** semver 粗略比较：a<b 返回 -1 */
function compareVersions(a, b) {
  const pa = String(a).split('.').map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split('.').map((x) => parseInt(x, 10) || 0);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const da = pa[i] || 0;
    const db = pb[i] || 0;
    if (da < db) return -1;
    if (da > db) return 1;
  }
  return 0;
}

function versionLt(a, b) {
  return compareVersions(a, b) < 0;
}

/** 带并发限制的映射执行 */
async function mapLimit(items, limit, fn) {
  const ret = new Array(items.length);
  let idx = 0;
  async function worker() {
    while (idx < items.length) {
      const cur = idx++;
      ret[cur] = await fn(items[cur], cur);
    }
  }
  const workers = [];
  for (let i = 0; i < Math.min(limit, items.length); i++) workers.push(worker());
  await Promise.all(workers);
  return ret;
}

function safe(fn, fallback) {
  try {
    const v = fn();
    return v === undefined ? fallback : v;
  } catch (e) {
    return fallback;
  }
}

module.exports = { normalizeUrl, hostnameOf, sleep, compareVersions, versionLt, mapLimit, safe };
