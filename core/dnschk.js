'use strict';

/**
 * DNS 与邮件安全探测（零依赖，基于 node:dns）
 *
 * 关键设计：
 * 1. SPF / CAA / MX 查询「可注册域」（www.example.com → example.com），
 *    DMARC 查询 _dmarc.<可注册域>——直接查子域几乎必然得到"无记录"的假阴性。
 * 2. 严格区分三种状态：
 *    - found：明确查到记录
 *    - none ：权威确认无记录（ENODATA / NXDOMAIN）
 *    - error：查询失败（解析器不可用等）——不得解读为"未配置"
 * 3. 系统 DNS（c-ares 直查）不可用时，自动回退 DoH（阿里/腾讯/Google），
 *    回退是否生效记录在 out.doh，报告中如实说明。
 */

const dns = require('dns').promises;
const { rawRequest } = require('./fetcher');
const CONFIG = require('./config');
const logger = require('./logger');

/**
 * 给系统 DNS 查询加超时。c-ares 在某些网络下会长时间不 settle（既不返回也不报错），
 * 超时后 reject 成 ETIMEDOUT，让 queryRecord 走既有的 DoH 回退通道，而不是把整个评估挂住。
 */
function withDeadline(promise, ms) {
  let timer = null;
  const guard = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const e = new Error('系统 DNS 查询超时(' + ms + 'ms)');
      e.code = 'ETIMEDOUT';
      reject(e);
    }, ms);
    // 不 unref：c-ares 卡住时本机可能已无其它活动句柄，兜底定时器必须仍被等待
  });
  return Promise.race([promise, guard]).finally(() => { if (timer) clearTimeout(timer); });
}

/* DoH 端点（JSON 接口）。国内用户优先阿里/腾讯，Google 兜底 */
const DOH_ENDPOINTS = [
  'https://dns.alidns.com/resolve',
  'https://doh.pub/dns-query',
  'https://dns.google/resolve',
];

const TYPE_NUM = { TXT: 16, MX: 15, CAA: 257, DNSKEY: 48, A: 1, AAAA: 28 };

/* 常见多级后缀（简化 PSL，覆盖主流场景） */
const MULTI_SUFFIX = [
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn', 'mil.cn', 'bj.cn', 'sh.cn', 'gd.cn',
  'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk',
  'com.tw', 'net.tw', 'org.tw',
  'com.mo', 'net.mo', 'org.mo',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz',
  'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
  'co.kr', 'or.kr', 'ne.kr',
  'com.br', 'net.br', 'org.br',
  'com.mx', 'com.ar', 'com.ru', 'com.ua', 'com.tr',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in',
  'co.za', 'org.za', 'web.za',
  'com.my', 'net.my', 'org.my',
  'co.th', 'in.th',
  'com.vn', 'net.vn', 'org.vn',
  'com.ph', 'net.ph', 'org.ph',
  'com.id', 'net.id', 'org.id', 'ac.id',
  'com.co', 'net.co', 'nom.co',
  'com.pe', 'com.ve', 'com.ec', 'com.uy', 'com.py', 'com.bo',
];

/** 提取可注册域（简化公共后缀列表） */
function registrableDomain(host) {
  const h = String(host || '').toLowerCase().replace(/\.+$/, '');
  if (!h) return h;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':')) return h; // IP 原样返回
  const labels = h.split('.');
  if (labels.length <= 2) return h;
  const last2 = labels.slice(-2).join('.');
  const last3 = labels.slice(-3).join('.');
  if (MULTI_SUFFIX.indexOf(last3) >= 0) return labels.slice(-4).join('.') || h;
  if (MULTI_SUFFIX.indexOf(last2) >= 0) return labels.slice(-3).join('.') || h;
  return last2;
}

/* ---------------- DoH 回退 ---------------- */

/**
 * DoH 查询（JSON 接口），多端点合并取并集。
 * 可靠性策略：系统 DNS 不可用时才触发；并集可容忍单端点偶发的空响应/截断，
 * 避免把「一次空响应」误判为「无记录」。正常网络下走系统 DNS，完全不触发本路径。
 */
async function dohQueryAll(name, type) {
  // 并行查询全部端点（任一端点超时/失败不影响其余），合并取并集
  const results = await Promise.all(DOH_ENDPOINTS.map(async (ep) => {
    const r = await rawRequest(ep + '?name=' + encodeURIComponent(name) + '&type=' + type, {
      timeout: CONFIG.timeouts.doh,
      headers: { accept: 'application/dns-json' },
      maxBody: 262144,
    });
    if (!r.ok) return null;
    try {
      const j = JSON.parse(r.body);
      if (!j || typeof j.Status !== 'number') return null;
      return j;
    } catch (e) { return null; }
  }));

  let anyReachable = false;
  let sawNxdomain = false;
  const merged = [];
  const seen = new Set();
  for (const j of results) {
    if (!j) continue;
    anyReachable = true;
    if (j.Status === 3) { sawNxdomain = true; continue; } // NXDOMAIN 权威
    for (const a of j.Answer || []) {
      if (a.type !== TYPE_NUM[type]) continue;
      const key = String(a.data);
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(a);
    }
  }
  if (!anyReachable) return null; // 全部端点不可达
  if (merged.length) return { status: 0, answers: merged };
  return { status: sawNxdomain ? 3 : 0, answers: [] };
}

/** 归一化 TXT 记录值。
 *  DoH（Cloudflare/Google）返回的是 DNS「呈现格式」，长 TXT 会被拆成多个带引号的片段，
 *  形如 `"v=spf1 include:a.com " "include:b.com -all"`。
 *  只掐头去尾会留下中间的内层引号，破坏 SPF/DMARC 等记录的语义，故按片段完整解引号后拼接。 */
function unquoteTxt(s) {
  const str = String(s == null ? '' : s).trim();
  if (str.charAt(0) === '"') {
    const parts = [];
    const re = /"((?:[^"\\]|\\.)*)"/g;
    let m;
    while ((m = re.exec(str)) !== null) {
      parts.push(m[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\'));
    }
    if (parts.length) return parts.join('');
  }
  return str.replace(/\\"/g, '"');
}

/**
 * 通用记录查询：系统 DNS 优先，失败回退 DoH
 * 返回 { state: 'found'|'none'|'error', records, error }
 * meta.doh 标记是否发生了 DoH 回退（供报告透明度说明）
 */
async function queryRecord(name, type, sysFn, meta) {
  try {
    const r = await withDeadline(Promise.resolve().then(() => sysFn(name)), CONFIG.timeouts.dns);
    return { state: 'found', records: r };
  } catch (e) {
    const code = e && e.code;
    if (code === 'ENODATA' || code === 'ENOTFOUND') {
      return { state: 'none', records: [] }; // 权威确认无记录
    }
    // 系统 DNS 不可用 / 超时 / 服务端错误 → DoH 回退
    const doh = await dohQueryAll(name, type);
    if (doh === null) {
      return { state: 'error', records: [], error: code || (e && e.message) || 'DNS 查询失败' };
    }
    if (meta) meta.doh = true;
    logger.debug('DNS', '系统 DNS 不可用，已回退 DoH', { name: logger.redact(name), type, cause: code || (e && e.message) });
    if (doh.status === 3) return { state: 'none', records: [] }; // NXDOMAIN
    const answers = doh.answers.filter((a) => a.type === TYPE_NUM[type]);
    return { state: answers.length ? 'found' : 'none', records: answers };
  }
}

/* ---------------- 各记录类型 ---------------- */

async function queryTxt(name, meta) {
  const r = await queryRecord(name, 'TXT', (n) => dns.resolveTxt(n).then((a) => a.map((x) => x.join(''))), meta);
  if (r.state === 'found') {
    // 系统 DNS 返回字符串数组；DoH 返回 {data} 对象数组
    r.records = r.records.map((a) => unquoteTxt(typeof a === 'string' ? a : a.data));
  }
  return r;
}

async function queryMx(name, meta) {
  const r = await queryRecord(name, 'MX', (n) => dns.resolveMx(n).then((a) => a.map((m) => ({ exchange: m.exchange, priority: m.priority }))), meta);
  if (r.state === 'found' && r.records.length && typeof r.records[0] === 'object' && !r.records[0].data) return r;
  if (r.state === 'found') {
    // DoH 返回：data 形如 "10 mx.example.com."
    r.records = r.records
      .map((a) => {
        const m = /^\s*(\d+)\s+(\S+?)\s*\.?\s*$/.exec(String((a && a.data) || a || ''));
        return m ? { exchange: m[2], priority: parseInt(m[1], 10) } : null;
      })
      .filter(Boolean);
  }
  return r;
}

async function queryCaa(name, meta) {
  const r = await queryRecord(name, 'CAA', (n) => dns.resolveCaa(n).then((a) => a.map((c) => ({ critical: c.critical, issue: c.issue, issuewild: c.issuewild, iodef: c.iodef }))), meta);
  if (r.state === 'found' && r.records.length && typeof r.records[0] === 'object' && !r.records[0].data) return r;
  if (r.state === 'found') {
    // DoH 返回：data 形如 '0 issue "letsencrypt.org"'
    r.records = r.records
      .map((a) => {
        const m = /^\s*(\d+)\s+(\S+)\s+"([^"]*)"/.exec(String(a.data || ''));
        if (!m) return null;
        const tag = m[2].toLowerCase();
        const o = { critical: m[1] === '128' || m[1] === '1' };
        if (tag === 'issue') o.issue = m[3];
        else if (tag === 'issuewild') o.issuewild = m[3];
        else if (tag === 'iodef') o.iodef = m[3];
        return o;
      })
      .filter(Boolean);
  }
  return r;
}

async function queryDnskey(name, meta) {
  // 系统 DNSKEY；DoH 回退（type=48）
  try {
    const r = await withDeadline(dns.resolve(name, 'DNSKEY'), CONFIG.timeouts.dns);
    return { state: r && r.length ? 'found' : 'none', records: r || [] };
  } catch (e) {
    const code = e && e.code;
    if (code === 'ENODATA' || code === 'ENOTFOUND') return { state: 'none', records: [] };
    const doh = await dohQueryAll(name, 'DNSKEY');
    if (doh === null) {
      // 区分「解析器根本不支持该查询类型」与「查询通道均不可用」
      const err = code === 'ERR_INVALID_ARG_VALUE'
        ? '解析器不支持 DNSKEY 查询'
        : (code || (e && e.message) || 'DNSKEY 查询失败');
      return { state: 'error', records: [], error: err };
    }
    if (meta) meta.doh = true;
    if (doh.status === 3) return { state: 'none', records: [] };
    const keys = doh.answers.filter((a) => a.type === 48);
    return { state: keys.length ? 'found' : 'none', records: keys };
  }
}

/* ---------------- 主入口 ---------------- */

async function probeDns(host) {
  const out = {
    host,
    domain: registrableDomain(host),
    doh: false, // 是否发生了 DoH 回退（透明度）
    states: {}, // 每类记录: found / none / error
    spf: null,
    dmarc: null,
    mx: [],
    caa: [],
    dnssec: null,
    errors: [],
  };
  const dom = out.domain;
  const isSub = dom && dom !== host;
  const meta = { doh: false };

  /* 六路并行查询（SPF 可注册域 + SPF 子域回退 + DMARC + MX + CAA + DNSSEC，互不依赖） */
  const EMPTY = { state: 'none', records: [] };
  const [spfDom, spfHost, dmarc, mx, caa, dk] = await Promise.all([
    queryTxt(dom, meta),
    isSub ? queryTxt(host, meta) : Promise.resolve(EMPTY),
    queryTxt('_dmarc.' + dom, meta),
    queryMx(dom, meta),
    queryCaa(dom, meta),
    // DNSKEY 位于区顶点（apex），必须查可注册域；查 www 等子域几乎必然得到"无记录"的假阴性
    queryDnskey(dom, meta),
  ]);

  /* SPF：可注册域优先，无记录时采纳子域自身（少数站点把 SPF 放在 www 等子域） */
  const tidyTxt = (s) => String(s == null ? '' : s).replace(/^\uFEFF/, '').trimStart();
  const pickSpf = (res, at) => {
    if (res.state !== 'found') return null;
    // TXT 可能带前导空白或 BOM（部分 DNS 面板/DoH 呈现格式），归一后再识别
    const raw = res.records.find((s) => /^v=spf1(?:\s|$)/i.test(tidyTxt(s)));
    if (!raw) return null;
    const rec = tidyTxt(raw);
    return {
      record: rec.slice(0, 300),
      mechanism: /\s-ALL\s*$/i.test(rec) ? 'hard' : /\s~ALL\s*$/i.test(rec) ? 'soft' : /\s\?ALL\s*$/i.test(rec) ? 'neutral' : 'none',
      at,
    };
  };
  const spfFromDom = pickSpf(spfDom, dom);
  const spfFromHost = isSub ? pickSpf(spfHost, host) : null;
  if (spfFromDom) { out.spf = spfFromDom; out.states.spf = 'found'; }
  else if (spfFromHost) { out.spf = spfFromHost; out.states.spf = 'found'; }
  else if (spfDom.state === 'found' || (isSub && spfHost.state === 'found')) {
    out.states.spf = 'none'; // 查询成功但确实没有 v=spf1 记录
  } else if (spfDom.state === 'error' && (!isSub || spfHost.state === 'error' || spfHost.state === 'none')) {
    // 可注册域查询失败且子域也无权威结论 → 查询失败，不得解读为"未配置"
    out.states.spf = 'error';
    out.errors.push('SPF 查询失败: ' + (spfDom.error || spfHost.error || '未知错误'));
  } else {
    out.states.spf = 'none';
  }

  /* DMARC：_dmarc.<可注册域> */
  if (dmarc.state === 'found') {
    const rec = dmarc.records.map(tidyTxt).find((s) => /^v=DMARC1(?:\s|;|$)/i.test(s));
    if (rec) {
      const p = /(?:^|;)\s*p\s*=\s*([a-z]+)/i.exec(rec);
      out.dmarc = { record: rec.slice(0, 300), policy: p ? p[1].toLowerCase() : 'none', at: '_dmarc.' + dom };
      out.states.dmarc = 'found';
    } else {
      out.states.dmarc = 'none';
    }
  } else {
    out.states.dmarc = dmarc.state;
    if (dmarc.state === 'error') out.errors.push('DMARC 查询失败: ' + dmarc.error);
  }

  /* MX：可注册域 */
  out.states.mx = mx.state;
  if (mx.state === 'found') out.mx = mx.records;
  else if (mx.state === 'error') out.errors.push('MX 查询失败: ' + mx.error);

  /* CAA：可注册域 */
  out.states.caa = caa.state;
  if (caa.state === 'found') out.caa = caa.records;
  else if (caa.state === 'error') out.errors.push('CAA 查询失败: ' + caa.error);

  /* DNSSEC：DNSKEY 存在性 */
  out.states.dnssec = dk.state;
  out.dnssec = dk.state === 'found' ? true : dk.state === 'none' ? false : null;
  if (dk.state === 'error') out.errors.push('DNSSEC 查询失败: ' + dk.error);

  out.doh = meta.doh;
  return out;
}

module.exports = { probeDns, registrableDomain, unquoteTxt };
