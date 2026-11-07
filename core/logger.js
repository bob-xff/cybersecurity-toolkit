'use strict';

/**
 * 结构化日志（零依赖）。
 *
 * 设计要点：
 *  - 输出到 **stderr**：网页版的 NDJSON 进度流走 HTTP 响应、CLI 的 JSON 报告走 stdout，
 *    日志走 stderr 才不会污染机器可读输出。
 *  - 单行 JSON，字段固定（ts/level/code/msg/meta），便于采集与检索。
 *  - 默认级别 warn：本地工具安静为宜；排障时 SITESEC_LOG_LEVEL=debug 打开全量。
 *  - 不打印目标 URL 的查询串、Cookie、响应正文等敏感内容，调用方需自行脱敏。
 */

const LEVELS = Object.freeze({ silent: 0, error: 1, warn: 2, info: 3, debug: 4 });

function currentLevel() {
  const raw = String((process.env && process.env.SITESEC_LOG_LEVEL) || 'warn').toLowerCase();
  return Object.prototype.hasOwnProperty.call(LEVELS, raw) ? LEVELS[raw] : LEVELS.warn;
}

let threshold = currentLevel();

function write(level, code, msg, meta) {
  if (LEVELS[level] > threshold) return;
  const rec = { ts: new Date().toISOString(), level, code: code || 'GENERAL', msg: String(msg == null ? '' : msg) };
  if (meta && typeof meta === 'object') {
    // 只保留可 JSON 序列化的浅层标量，防止把整份报告 / 循环对象塞进日志
    const safe = {};
    for (const [k, v] of Object.entries(meta)) {
      if (v == null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') safe[k] = v;
      else if (v instanceof Error) safe[k] = v.message;
    }
    if (Object.keys(safe).length) rec.meta = safe;
  }
  try {
    process.stderr.write(JSON.stringify(rec) + '\n');
  } catch (e) { /* 日志失败绝不能影响主流程 */ }
}

/** 截断可能在日志里出现的用户输入（URL / 证据文本） */
function redact(s, max) {
  const str = String(s == null ? '' : s);
  const lim = max || 160;
  // 去掉查询串与片段，避免 token / session 落到日志
  const clean = str.split(/[?#]/)[0];
  return clean.length > lim ? clean.slice(0, lim) + '…' : clean;
}

const logger = Object.freeze({
  LEVELS,
  setLevel(name) {
    if (Object.prototype.hasOwnProperty.call(LEVELS, name)) threshold = LEVELS[name];
    return threshold;
  },
  level: () => threshold,
  redact,
  error: (code, msg, meta) => write('error', code, msg, meta),
  warn: (code, msg, meta) => write('warn', code, msg, meta),
  info: (code, msg, meta) => write('info', code, msg, meta),
  debug: (code, msg, meta) => write('debug', code, msg, meta),
});

module.exports = logger;
