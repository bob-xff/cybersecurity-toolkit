'use strict';

/**
 * 暴露面探测：敏感文件、目录列表、security.txt、robots、错误页、HTTP 方法
 * 仅执行少量公开路径 GET/OPTIONS/TRACE 探测，不注入、不爆破。
 *
 * 优化：
 *  - 所有互不依赖的请求统一提交到并发池（此前 9 个串行阶段，慢站最坏耗时 9×timeout）；
 *  - 保留 checked 全量清单：区分「探测过且未发现」与「根本没探测」，杜绝"没测=通过"；
 *  - 探测基址取最终 URL 所在目录，兼容部署在子路径的站点。
 */
const { rawRequest } = require('./fetcher');
const { mapLimit, truncate } = require('./util');
const CONFIG = require('./config');
const logger = require('./logger');
const { URL } = require('url');

const SENSITIVE_PATHS = [
  { path: '/.git/config', label: 'Git 仓库配置', confirm: /repositoryformatversion|\[core\]/i },
  { path: '/.git/HEAD', label: 'Git 仓库', confirm: /^ref:/im },
  // .env 确认收紧：行首 KEY=value 且该行不含 HTML 标签（防止 <INPUT TYPE=...> 之类大写属性误报）
  { path: '/.env', label: '环境配置文件', confirm: /^[A-Z][A-Z0-9_]{2,}\s*=\s*["']?[\w\-./@:+]{3,}/m },
  { path: '/.svn/entries', label: 'SVN 版本库', confirm: /\d{1,2}\s*\n?dir/ },
  { path: '/.DS_Store', label: 'DS_Store 文件', confirm: /Bud1/ },
  { path: '/phpinfo.php', label: 'phpinfo 页面', confirm: /phpinfo\(\)|PHP Version/i },
  { path: '/info.php', label: 'phpinfo 页面', confirm: /phpinfo\(\)|PHP Version/i },
  { path: '/server-status', label: 'Apache 状态页', confirm: /Apache Server Status/i },
  { path: '/nginx_status', label: 'Nginx 状态页', confirm: /Active connections\s*:\s*\d+/i },
];

/** 探测基址：最终 URL 所在目录（去掉文件名与查询串），兼容子路径部署 */
function probeBaseOf(originUrl) {
  try {
    const u = new URL(originUrl);
    u.hash = '';
    u.search = '';
    if (!u.pathname.endsWith('/')) u.pathname = u.pathname.replace(/[^/]*$/, '');
    return u.toString().replace(/\/$/, '');
  } catch (e) {
    return String(originUrl || '').replace(/\/$/, '');
  }
}

function confirmPasses(item, body) {
  if (!item.confirm.test(body)) return false;
  // .env 追加防护：至少一行「KEY=value」且不含 HTML 标签字符
  if (item.path === '/.env') {
    return body.split(/\r?\n/).some((l) => item.confirm.test(l) && !/[<>]/.test(l));
  }
  return true;
}

async function probeExposure(originUrl, options = {}) {
  const timeout = options.timeout || CONFIG.timeouts.exposure;
  const base = probeBaseOf(originUrl);
  let origin;
  try { origin = new URL(base).origin; } catch (e) { origin = base; }
  const rnd = '/sec-audit-probe-' + Math.random().toString(36).slice(2, 10);

  const out = {
    base,
    files: [],       // 仅命中项（保持既有数据契约，standards E2 依赖）
    checked: [],     // 全量检查清单（含未命中与失败），新增字段
    failedRequests: 0,
    securityTxt: false,
    securityTxtUrl: null,
    robots: null,
    sitemap: null,
    dirListing: null,
    errorLeak: null,
    trace: null,
    options: null,
    durationMs: null,
  };
  const started = Date.now();

  /* 把所有请求描述成任务，统一并发执行。
   * RFC 9116 要求 security.txt 位于站点根，故用 origin；其余用最终 URL 所在目录。 */
  const tasks = [];
  const add = (key, url, extra) => tasks.push(Object.assign({ key, url }, extra || {}));
  add('securityWellKnown', origin + '/.well-known/security.txt');
  add('securityRoot', origin + '/security.txt');
  add('robots', origin + '/robots.txt', { maxBody: 131072 });
  add('sitemap', origin + '/sitemap.xml', { maxBody: 131072 });
  for (const item of SENSITIVE_PATHS) add('file:' + item.path, base + item.path, { item, maxBody: 131072 });
  add('root', base + '/', { maxBody: 262144 });
  add('notFound', base + rnd, { path: rnd, maxBody: 131072 });
  add('trace', base + '/', { method: 'TRACE', maxBody: 65536 });
  add('options', base + '/', { method: 'OPTIONS', maxBody: 65536 });

  const results = await mapLimit(tasks, CONFIG.concurrency.exposure, async (t) => {
    const r = await rawRequest(t.url, {
      timeout,
      maxBody: t.maxBody || 65536,
      method: t.method || 'GET',
    });
    return { task: t, res: r };
  }, { settle: true });

  const byKey = {};
  // mapLimit 保证结果顺序与 tasks 一致
  tasks.forEach((t, i) => {
    const entry = results[i];
    const r = entry && entry.res && entry.res.ok ? entry.res : null;
    if (!r) {
      out.failedRequests++;
      logger.debug('EXPOSURE', '探测请求失败', {
        key: t.key,
        error: entry && entry.res && entry.res.error ? entry.res.error.message : (entry && entry.message) || '未知',
      });
    }
    byKey[t.key] = r;
  });

  // security.txt（优先 /.well-known/）
  for (const key of ['securityWellKnown', 'securityRoot']) {
    const r = byKey[key];
    if (r && r.status === 200 && /contact\s*:/i.test(r.body || '')) {
      out.securityTxt = true;
      out.securityTxtUrl = key === 'securityWellKnown' ? origin + '/.well-known/security.txt' : origin + '/security.txt';
      break;
    }
  }

  // robots.txt
  const rob = byKey['robots'];
  if (rob && rob.status === 200 && /(^|\n)\s*(?:disallow|allow)\s*:/i.test(rob.body || '')) {
    const disallows = (rob.body.match(/^\s*Disallow:\s*(\S+)/gmi) || [])
      .map((s) => s.replace(/^\s*Disallow:\s*/i, '').trim());
    out.robots = {
      disallowAll: disallows.some((d) => d === '/'),
      sensitive: disallows.filter((d) => /\b(admin|manage|backup|config|internal|test|staging|private|api)\b/i.test(d)),
      count: disallows.length,
    };
  }

  // sitemap（只在明确命中标记；请求失败时保持 null，与"确认不存在"区分）
  const sm = byKey['sitemap'];
  if (sm && sm.status === 200) out.sitemap = /<urlset|<sitemapindex/i.test(sm.body || '');

  // 敏感文件：checked 保留全量，files 只留命中
  for (const item of SENSITIVE_PATHS) {
    const r = byKey['file:' + item.path];
    const found = !!(r && r.status === 200 && r.body && r.body.length > 0 && confirmPasses(item, r.body));
    const row = { path: item.path, label: item.label, found, status: r ? r.status : null };
    out.checked.push(row);
    if (found) out.files.push(Object.assign({}, row, { sample: truncate(r.body, 120) }));
  }

  // 根目录列表
  const root = byKey['root'];
  if (root && /Index of\s+\/|<title>\s*Index of|<h1>\s*Index of|Parent Directory<\/a>/i.test(root.body || '')) {
    out.dirListing = { path: '/', status: root.status };
  }

  // 404/500 错误页泄露
  const nf = byKey['notFound'];
  if (nf && [400, 404, 500, 502, 503].includes(nf.status)) {
    const body = nf.body || '';
    const leak = /Traceback \(most recent call last\)|Stack trace|\bat\s+[\w$.]+\s*\(.*?:\d+:\d+\)|SQL syntax|Warning:.*on line|Fatal error|Exception in thread|未捕获异常|Microsoft OLE DB Provider|org\.springframework/i.test(body);
    if (leak) out.errorLeak = { path: rnd, status: nf.status, sample: truncate(body, 200) };
  }

  // TRACE（XST 风险）：要求有回显，避免把「200 空响应」误判为已启用
  const tr = byKey['trace'];
  out.trace = tr
    ? { status: tr.status, enabled: tr.status === 200 && /TRACE|HTTP\/1\.[01]|\bHost\s*:/i.test(tr.body || '') }
    : { status: null, enabled: false };

  // OPTIONS
  const op = byKey['options'];
  out.options = op ? { status: op.status, allow: op.headers.allow || op.headers['access-control-allow-methods'] || null } : null;

  out.durationMs = Date.now() - started;
  logger.debug('EXPOSURE', '探测完成', { base: logger.redact(base), durationMs: out.durationMs, failed: out.failedRequests });
  return out;
}

module.exports = { probeExposure, SENSITIVE_PATHS, probeBaseOf };
