'use strict';

/**
 * 通用工具函数（零依赖）
 * 所有模块共用的 URL 归一化、版本比较、并发控制、容错执行。
 */
const CONFIG = require('./config');
const { CODES, appError } = require('./errors');

/**
 * URL 归一化。
 * 边界处理：空值、包裹字符、控制字符、超长输入、内嵌凭据、非 http(s) 协议、
 * 末尾点域名、IPv6 字面量、以及用户省略协议时的默认 https。
 */
function normalizeUrl(input) {
  let s = String(input == null ? '' : input).trim();
  if (!s) throw new Error('网址不能为空');
  if (s.length > CONFIG.limits.maxUrlLength) {
    throw new Error('网址过长（超过 ' + CONFIG.limits.maxUrlLength + ' 字符）');
  }
  // 控制字符（含 \0 / 换行）会让 URL 解析结果出乎意料，直接拒绝
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(s)) throw new Error('网址包含非法控制字符');
  // 去掉可能的尖括号/引号包裹
  s = s.replace(/^[<"']+/, '').replace(/[>"']+$/, '');
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s)) s = 'https://' + s;

  let u;
  try { u = new URL(s); }
  catch (e) { throw new Error('网址格式无效：' + e.message); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error('仅支持 http/https 协议的网址');
  }
  if (!u.hostname) throw new Error('网址缺少主机名');
  if (u.username || u.password) throw new Error('网址不允许包含内嵌用户名或密码');
  return u;
}

/** 主机名归一化：小写、去末尾点、去 IPv6 字面量的方括号（供 socket 连接使用） */
function hostnameOf(u) {
  const raw = String((u && u.hostname) || '').toLowerCase().replace(/\.+$/, '');
  return /^\[[0-9a-f:]+\]$/.test(raw) ? raw.slice(1, -1) : raw;
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

/**
 * 带并发限制的映射执行。
 * @param {Array} items
 * @param {number} limit 并发数（会被夹到 [1, items.length]）
 * @param {Function} fn
 * @param {object} [options] { settle:true } 时单项异常不会中断整体，返回标准错误对象
 */
async function mapLimit(items, limit, fn, options = {}) {
  const list = Array.isArray(items) ? items : [];
  if (!list.length) return [];
  const ret = new Array(list.length);
  const n = Math.max(1, Math.min(Math.floor(limit) || 1, list.length));
  let idx = 0;
  const settle = options.settle === true;
  async function worker() {
    while (idx < list.length) {
      const cur = idx++;
      if (settle) {
        try { ret[cur] = await fn(list[cur], cur); }
        catch (e) { ret[cur] = appError(CODES.INTERNAL, (e && e.message) || '子任务异常', e); }
      } else {
        ret[cur] = await fn(list[cur], cur);
      }
    }
  }
  const workers = [];
  for (let i = 0; i < n; i++) workers.push(worker());
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

/** 限制证据文本长度，避免超长正文/畸形响应把报告撑爆 */
function truncate(s, max) {
  const str = String(s == null ? '' : s);
  const lim = max || 300;
  return str.length > lim ? str.slice(0, lim) + '…' : str;
}

module.exports = {
  normalizeUrl, hostnameOf, sleep, compareVersions, versionLt, mapLimit, safe, truncate,
};
