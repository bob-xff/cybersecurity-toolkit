'use strict';

/**
 * 网页版：零依赖 Node HTTP 服务
 *  - 静态托管 ui/（与桌面版共用同一套前端）
 *  - POST /api/assess  调用 core 引擎，以 NDJSON 流式返回进度与最终报告
 *  - GET  /api/health  健康检查
 *  - GET  /docs/<file> 只读托管标准清单文档
 *
 * 安全说明：
 *  - 默认只监听 127.0.0.1。若用 --host 0.0.0.0 暴露到网络，等于开放了一个
 *    「让服务端抓取任意 URL」的入口（SSRF 风险），请务必先加访问控制再暴露。
 *  - 内置并发上限（默认 2）与请求体大小上限（64KB），防止资源耗尽。
 *
 * 用法：node server.js [--port 8080] [--host 127.0.0.1] [--lib-limit 6]
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { assess, TOOL_VERSION } = require('../core');
const CONFIG = require('../core/config');
const logger = require('../core/logger');

const ROOT = __dirname;
const UI_DIR = path.join(ROOT, '..', 'ui');
const DOCS_DIR = path.join(ROOT, '..', 'docs');

/* ---------- 参数解析 ---------- */
function parseIntArg(name, raw, fallback, min, max) {
  const n = parseInt(raw, 10);
  if (!(n >= min && n <= max)) {
    logger.warn('CONFIG', '启动参数无效，已回退默认值', { param: name, value: String(raw), fallback });
    return fallback;
  }
  return n;
}
function parseArgs(argv) {
  const out = { port: 8080, host: '127.0.0.1', libLimit: 6, concurrency: 2, open: false, idleExit: 30 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--port') out.port = parseIntArg('port', argv[++i], 8080, 1, 65535);
    else if (a === '--host') out.host = argv[++i];
    else if (a === '--lib-limit') out.libLimit = parseIntArg('lib-limit', argv[++i], 6, 0, 100);
    else if (a === '--concurrency') out.concurrency = parseIntArg('concurrency', argv[++i], 2, 1, 16);
    else if (a === '--open') out.open = true;
    else if (a === '--idle-exit') out.idleExit = parseIntArg('idle-exit', argv[++i], 30, 0, 1440);
    else if (a === '--help' || a === '-h') {
      console.log('用法: node server.js [--port 8080] [--host 127.0.0.1] [--lib-limit 6] [--concurrency 2] [--open] [--idle-exit 30]');
      process.exit(0);
    }
  }
  if (out.idleExit < 0) { logger.error('CONFIG', 'idle-exit 参数无效，服务退出'); process.exit(1); }
  return out;
}
const opts = parseArgs(process.argv);

/* ---------- 并发闸门 ---------- */
let running = 0;
const waiters = [];
/** 排队设上限：某个评估异常卡住时，后续请求不能无限期挂起（表现为"点了没反应"） */
function acquire() {
  if (running < opts.concurrency) { running++; return Promise.resolve(); }
  return new Promise((resolve, reject) => {
    const entry = { resolve, timer: null };
    entry.timer = setTimeout(() => {
      const i = waiters.indexOf(entry);
      if (i >= 0) waiters.splice(i, 1);
      logger.warn('QUEUE', '评估请求排队超时', { waitMs: CONFIG.limits.maxRequestQueueWait, queued: waiters.length });
      reject(new Error('评估请求排队超时，服务繁忙，请稍后重试'));
    }, CONFIG.limits.maxRequestQueueWait);
    waiters.push(entry);
  });
}
function release() {
  running--;
  const next = waiters.shift();
  if (next) { running++; clearTimeout(next.timer); next.resolve(); }
}

/* ---------- MIME ---------- */
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.png': 'image/png', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  // style-src 需要 'unsafe-inline'：仪表盘弧线/进度条宽度等为 JS 动态内联样式。
  // script-src 保持严格（无 unsafe-inline），前端无内联脚本与事件处理器属性。
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'none'"
].join('; ');

/* ---------- 工具 ---------- */
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(body);
}

/** 目标文件是否确实位于 dir 之内（相对路径判定，避免 dir-同级目录前缀绕过） */
function isInside(dir, file) {
  const rel = path.relative(dir, file);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function serveStatic(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) { sendJson(res, 404, { error: 'Not Found' }); return; }
    const ext = path.extname(filePath).toLowerCase();
    const headers = {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-cache'
    };
    if (ext === '.html') headers['Content-Security-Policy'] = CSP;
    res.writeHead(200, headers);
    res.end(data);
  });
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('请求体过大')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/* ---------- 评估接口（NDJSON 流） ---------- */
let lastActiveAt = Date.now();
async function handleAssess(req, res) {
  lastActiveAt = Date.now();
  let payload;
  try {
    payload = JSON.parse(await readBody(req, 64 * 1024));
  } catch (e) {
    sendJson(res, 400, { error: '请求格式错误：' + e.message });
    return;
  }
  const url = typeof payload.url === 'string' ? payload.url.trim() : '';
  if (!url) { sendJson(res, 400, { error: '缺少 url 参数' }); return; }

  /* 高级选项由前端透传；未提供时沿用服务端默认（都开启） */
  const detectLibs = payload.detectLibs === undefined ? true : !!payload.detectLibs;
  const detectExposure = payload.detectExposure === undefined ? true : !!payload.detectExposure;

  try {
    await acquire();
  } catch (e) {
    sendJson(res, 503, { error: e.message });
    return;
  }
  /* 并发槽必须无泄漏释放：acquire() 之后的任何异常都不能把槽吞掉，
   * 否则累积到 concurrency 次后所有请求会永久排队（表现为服务假死）。 */
  let released = false;
  const doRelease = () => { if (!released) { released = true; release(); } };

  let clientGone = false;
  const push = (evt) => {
    if (clientGone) return;
    try { res.write(JSON.stringify(evt) + '\n'); } catch (e) { clientGone = true; }
  };

  try {
    res.writeHead(200, {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Cache-Control': 'no-cache',
      'X-Accel-Buffering': 'no',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'"
    });
    res.on('close', () => { clientGone = true; });

    const report = await assess(url, {
      libLimit: detectLibs ? opts.libLimit : 0,
      detectExposure: detectExposure,
      onProgress: (step, text) => push({ type: 'progress', step: step, text: text })
    });
    if (!report || report.ok !== true) {
      push({ type: 'error', message: (report && report.error) || '评估失败' });
    } else {
      push({ type: 'result', report: report });
    }
  } catch (e) {
    const msg = (e && e.message) ? e.message : String(e);
    if (!res.headersSent) sendJson(res, 500, { error: msg });
    else push({ type: 'error', message: msg });
  } finally {
    if (!clientGone) { try { res.end(); } catch (e) { /* ignore */ } }
    doRelease();
  }
}

/* ---------- 路由 ---------- */
const server = http.createServer((req, res) => {
  lastActiveAt = Date.now(); // 任意请求都视为活动（含静态资源与健康检查）
  let pathname;
  try {
    const u = new URL(req.url, 'http://localhost');
    pathname = decodeURIComponent(u.pathname); // 畸形百分号编码会抛 URIError，必须兜住
  } catch (e) {
    sendJson(res, 400, { error: '请求路径无法解析' });
    return;
  }

  logger.debug('HTTP', '收到请求', { method: req.method, path: logger.redact(pathname, 120) });
  if (req.method === 'HEAD' && pathname === '/api/health') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end();
    return;
  }
  if (req.method === 'GET' && (pathname === '/api/health')) {
    sendJson(res, 200, { ok: true, tool: '网站网络安全评估工具', version: TOOL_VERSION, running: running, concurrency: opts.concurrency });
    return;
  }
  if (req.method === 'POST' && pathname === '/api/assess') {
    handleAssess(req, res).catch((e) => {
      if (!res.headersSent) sendJson(res, 500, { error: e.message });
    });
    return;
  }
  if (req.method === 'GET' && pathname.indexOf('/docs/') === 0) {
    const rel = pathname.slice('/docs/'.length).replace(/\.\.+/g, '');
    const file = path.normalize(path.join(DOCS_DIR, rel));
    if (!isInside(DOCS_DIR, file)) { sendJson(res, 403, { error: 'Forbidden' }); return; }
    serveStatic(res, file);
    return;
  }
  if (req.method === 'GET') {
    if (pathname === '/') { serveStatic(res, path.join(UI_DIR, 'index.html')); return; }
    const file = path.normalize(path.join(UI_DIR, pathname));
    if (!isInside(UI_DIR, file)) { sendJson(res, 403, { error: 'Forbidden' }); return; }
    serveStatic(res, file);
    return;
  }
  sendJson(res, 405, { error: 'Method Not Allowed' });
});

server.listen(opts.port, opts.host, () => {
  const shown = 'http://' + opts.host + ':' + opts.port + '/';
  /* 以下是面向操作者的 CLI 提示（不是诊断日志），保留 stdout 便于直接运行时看到地址；
   * 运行期诊断全部走结构化 logger(stderr)，不污染 NDJSON/JSON 输出。 */
  console.log('网站网络安全评估工具（网页版）已启动');
  console.log('  访问地址: ' + shown);
  console.log('  并发上限: ' + opts.concurrency + '，组件检测上限: ' + opts.libLimit);
  logger.info('SERVER', '服务已启动', { host: opts.host, port: opts.port, concurrency: opts.concurrency });
  if (opts.host !== '127.0.0.1' && opts.host !== 'localhost' && opts.host !== '::1') {
    console.log('  ⚠️ 已绑定非本机地址：请确认已配置访问控制，否则等同于开放 SSRF 入口');
    logger.warn('SECURITY', '绑定非本机地址，未配置访问控制时等同开放 SSRF 入口', { host: opts.host });
  }
  /* --open：监听成功后自动打开浏览器（仅对本机地址生效） */
  if (opts.open && (opts.host === '127.0.0.1' || opts.host === 'localhost')) {
    const { spawn } = require('child_process');
    try {
      if (process.platform === 'win32') spawn('cmd', ['/c', 'start', '', shown], { detached: true, stdio: 'ignore' }).unref();
      else if (process.platform === 'darwin') spawn('open', [shown], { detached: true, stdio: 'ignore' }).unref();
      else spawn('xdg-open', [shown], { detached: true, stdio: 'ignore' }).unref();
    } catch (e) { /* 打不开就算了，地址已打印 */ }
  }
});

server.on('error', (e) => {
  logger.error('SERVER', '服务启动失败：' + e.message, { code: e.code });
  process.exit(1);
});

/* 空闲自动退出兜底：防止 launcher 被强杀后服务残留占端口（0 = 禁用） */
if (opts.idleExit > 0) {
  setInterval(() => {
    if (running > 0) { lastActiveAt = Date.now(); return; } // 有评估在跑就不算空闲
    if (Date.now() - lastActiveAt > opts.idleExit * 60 * 1000) {
      logger.info('SERVER', '空闲超时，服务自动退出', { idleMinutes: opts.idleExit });
      process.exit(0);
    }
  }, 60 * 1000).unref();
}

/* 最后防线：请求路径均已防护；此处仅兜住未知异常，避免本地工具因单点错误整体退出 */
process.on('uncaughtException', (e) => {
  logger.error('UNCAUGHT', '未捕获异常', { reason: e && e.message ? e.message : String(e) });
});
process.on('unhandledRejection', (e) => {
  logger.error('UNHANDLED', '未处理的 Promise 拒绝', { reason: e && e.message ? e.message : String(e) });
});
