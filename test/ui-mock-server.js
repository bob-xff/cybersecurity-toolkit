'use strict';
/**
 * UI 视觉/交互回归用的确定性 mock 服务（零依赖，不联网）
 *
 * 为什么需要：真实评估含 DNS / TLS / 暴露面探测，耗时数秒且随网络波动，
 * 无头浏览器的 --virtual-time-budget 下 fetch 往往来不及完成就 dump-dom。
 * 这里用固定的「罐头报告」即时返回，让结果态渲染可重复验证。
 *
 * 用法: node test/ui-mock-server.js --port 8904
 * 然后打开 http://127.0.0.1:8904/?url=https://example.com&auto=1
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const { CHECKS, CATEGORIES } = require('../core/standards');

const UI_DIR = path.join(__dirname, '..', 'ui');
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.ico': 'image/x-icon',
};

const STATUS_CYCLE = ['fail', 'warn', 'pass', 'na', 'info'];
const checks = CHECKS.map((c, i) => ({
  id: c.id, category: c.cat, title: c.title, severity: c.severity,
  weight: { high: 3, medium: 2, low: 1, info: 0.5 }[c.severity] || 1,
  status: STATUS_CYCLE[i % STATUS_CYCLE.length],
  evidence: 'mock 证据 ' + c.id + ' <script>alert(1)</script>', // 顺带验证 XSS 转义
  detail: null, cnStandards: c.cn || [], intlStandards: c.intl || [],
  remediation: c.remediation || '',
}));
const categories = CATEGORIES.map((c, i) => ({
  id: c.id, code: c.code, name: c.name, weight: c.weight,
  score: [62.5, 40, 80, 55, 70, 91.7, 50][i] || null,
  counts: { pass: 2, warn: 1, fail: 2, info: 1, na: 1 },
}));

const REPORT = {
  ok: true, tool: '网站网络安全评估工具', toolVersion: '1.0.0',
  target: {
    input: 'https://example.com', url: 'https://example.com', hostname: 'example.com',
    finalUrl: 'https://example.com/', finalStatus: 200,
    redirectChain: [{ url: 'https://example.com', status: 301 }],
  },
  startedAt: new Date().toISOString(), durationMs: 8568,
  warnings: ['暴露面探测有 2 个请求失败（超时/连接错误），相关结论可能不完整'],
  score: 69.2, level: { grade: 'C', label: '合格' },
  categories, checks,
  tls: {
    host: 'example.com', port: 443, reachable: true, trusted: true, trustError: null,
    cert: { subject: { CN: 'example.com' }, issuer: { O: 'DigiCert Inc' }, validFrom: 'Jan 1 00:00:00 2026 GMT', validTo: 'Dec 31 23:59:59 2026 GMT', daysRemaining: 70, altNames: ['example.com', 'www.example.com'] },
    negotiated: { protocol: 'TLSv1.3', cipher: { name: 'TLS_AES_256_GCM_SHA384' } },
    protocols: { 'TLSv1.3': true, 'TLSv1.2': true, 'TLSv1.1': false, TLSv1: false },
    weakCiphers: [], notes: [], limited: false, durationMs: 320,
  },
  dns: {
    host: 'example.com', domain: 'example.com', doh: true,
    states: { spf: 'found', dmarc: 'found', mx: 'found', caa: 'none', dnssec: 'found' },
    spf: { record: 'v=spf1 -all', mechanism: 'hard', at: 'example.com' },
    dmarc: { record: 'v=DMARC1; p=reject', policy: 'reject', at: '_dmarc.example.com' },
    mx: [{ exchange: 'mail.example.com', priority: 10 }], caa: [], dnssec: true, errors: [],
  },
  tech: {
    cms: ['WordPress'], frameworks: ['Vue', 'React'], generator: 'WordPress 6.4',
    icp: null, isHtml: true, charset: 'utf-8', scanLimited: false, scriptCount: 4,
    libs: [{ lib: 'jQuery', version: '1.12.4', vulnerable: true, eol: false, hasSri: false, via: 'url', severity: 'high', cve: 'CVE-2020-11022', src: 'https://example.com/jquery-1.12.4.min.js' }],
  },
  exposure: {
    enabled: true, checkedFiles: 9, failedRequests: 2,
    foundFiles: [{ path: '/.git/config', label: 'Git 仓库配置', status: 200 }],
    securityTxt: false, securityTxtUrl: null, robots: { count: 2, sensitive: ['/admin'], disallowAll: false },
    sitemap: true, dirListing: null, errorLeak: null, trace: { status: 405, enabled: false },
  },
  performance: { pageMs: 817, probesMs: 7173, checksMs: 2, tlsMs: 6387, exposureMs: 7167 },
  markdown: '# mock 报告\n\n用于 UI 渲染验证。',
};

const NDJSON = [
  JSON.stringify({ type: 'progress', step: 'page', text: '正在抓取页面…' }),
  JSON.stringify({ type: 'progress', step: 'done', text: '评估完成' }),
  JSON.stringify({ type: 'result', report: REPORT }),
].join('\n') + '\n';

const server = http.createServer((req, res) => {
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname); }
  catch (e) { res.writeHead(400); res.end(); return; }
  if (pathname === '/api/assess') {
    res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(NDJSON);
    return;
  }
  if (pathname === '/api/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, version: '1.0.0', running: 0, concurrency: 2 }));
    return;
  }
  const file = path.join(UI_DIR, pathname === '/' ? 'index.html' : pathname);
  const rel = path.relative(UI_DIR, file);
  if (rel.startsWith('..') || path.isAbsolute(rel)) { res.writeHead(403); res.end(); return; }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream' });
    res.end(data);
  });
});

const port = Number((process.argv[process.argv.indexOf('--port') + 1]) || 8904);
server.listen(port, '127.0.0.1', () => console.log('[ui-mock] http://127.0.0.1:' + port));
