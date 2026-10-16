'use strict';

/**
 * 暴露面探测：敏感文件、目录列表、security.txt、robots、错误页、HTTP 方法
 * 仅执行少量公开路径 GET/OPTIONS/TRACE 探测，不注入、不爆破。
 */
const { rawRequest } = require('./fetcher');
const { mapLimit } = require('./util');
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
  // server-status / nginx_status 确认收紧：只认状态页特征串，
  // 不接受裸关键词（页面正文出现 "nginx"/"Server Version" 一词极易误报）
  { path: '/server-status', label: 'Apache 状态页', confirm: /Apache Server Status/i },
  { path: '/nginx_status', label: 'Nginx 状态页', confirm: /Active connections\s*:\s*\d+/i },
];

async function probeExposure(originUrl, options = {}) {
  const u = new URL(originUrl);
  const base = u.origin;
  const timeout = options.timeout || 8000;
  const out = {
    files: [],
    securityTxt: false,
    securityTxtUrl: null,
    robots: null,
    sitemap: null,
    dirListing: null,
    errorLeak: null,
    trace: null,
    options: null,
  };

  // security.txt（RFC 9116）
  for (const p of ['/.well-known/security.txt', '/security.txt']) {
    const r = await rawRequest(base + p, { timeout, maxBody: 65536 });
    if (r.ok && r.status === 200 && /contact\s*:/i.test(r.body || '')) {
      out.securityTxt = true;
      out.securityTxtUrl = base + p;
      break;
    }
  }

  // robots.txt
  const rob = await rawRequest(base + '/robots.txt', { timeout, maxBody: 131072 });
  if (rob.ok && rob.status === 200 && /(^|\n)\s*disallow\s*:/i.test(rob.body || '')) {
    const disallows = (rob.body.match(/^\s*Disallow:\s*(\S+)/gmi) || []).map((s) => s.replace(/^\s*Disallow:\s*/i, '').trim());
    out.robots = {
      disallowAll: disallows.some((d) => d === '/'),
      // 词边界匹配，避免 latest 误中 test、apiary 误中 api
      sensitive: disallows.filter((d) => /\b(admin|manage|backup|config|internal|test|staging|private|api)\b/i.test(d)),
      count: disallows.length,
    };
  } else {
    out.robots = null;
  }

  // sitemap
  const sm = await rawRequest(base + '/sitemap.xml', { timeout, maxBody: 131072 });
  out.sitemap = !!(sm.ok && sm.status === 200 && /<urlset|<sitemapindex/i.test(sm.body || ''));

  // 敏感文件（并发 3，温和探测）
  const confirmPasses = (item, body) => {
    if (!item.confirm.test(body)) return false;
    // .env 追加防护：至少有一行「KEY=value」命中且该行不含 HTML 标签字符，
    // 防止压缩 / XHTML 页面里的大写属性（TYPE="text" 之类）被误判为配置文件
    if (item.path === '/.env') {
      return body.split(/\r?\n/).some((l) => item.confirm.test(l) && !/[<>]/.test(l));
    }
    return true;
  };
  const files = await mapLimit(SENSITIVE_PATHS, 3, async (item) => {
    const r = await rawRequest(base + item.path, { timeout, maxBody: 131072 });
    if (!r.ok) return { ...item, found: false, status: null };
    const body = r.body || '';
    const found = r.status === 200 && body.length > 0 && (item.confirm ? confirmPasses(item, body) : true);
    return { ...item, found, status: r.status };
  });
  out.files = files.filter((f) => f.found);

  // 根目录列表
  const root = await rawRequest(base + '/', { timeout, maxBody: 262144 });
  if (root.ok && (/Index of\s+\//i.test(root.body || '') || /<title>\s*Index of/i.test(root.body || ''))) {
    out.dirListing = { path: '/', status: root.status };
  }

  // 404/500 错误页泄露
  const rnd = '/sec-audit-probe-' + Math.random().toString(36).slice(2, 10);
  const nf = await rawRequest(base + rnd, { timeout, maxBody: 131072 });
  if (nf.ok && [400, 404, 500, 503].includes(nf.status)) {
    const body = nf.body || '';
    const leak = /Traceback \(most recent call last\)|Stack trace|\bat\s+[\w$.]+\s*\(.*?:\d+:\d+\)|SQL syntax|Warning:.*on line|Fatal error|Exception in thread|未捕获异常/i.test(body);
    if (leak) {
      out.errorLeak = { path: rnd, status: nf.status, sample: body.slice(0, 200) };
    }
  }

  // TRACE（XST 风险）
  const tr = await rawRequest(base + '/', { method: 'TRACE', timeout, maxBody: 65536 });
  out.trace = tr.ok ? { status: tr.status, enabled: tr.status === 200 && /trace/i.test(tr.body || '') } : { status: null, enabled: false };

  // OPTIONS
  const op = await rawRequest(base + '/', { method: 'OPTIONS', timeout, maxBody: 65536 });
  out.options = op.ok ? { status: op.status, allow: op.headers.allow || op.headers['access-control-allow-methods'] || null } : null;

  return out;
}

module.exports = { probeExposure, SENSITIVE_PATHS };
