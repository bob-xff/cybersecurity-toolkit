'use strict';

/**
 * 统一错误模型（零依赖）。
 *
 * 约定：所有探测类函数「始终 resolve」，失败时返回
 *   { ok:false, error: { code, message, cause? } }
 * 或把错误对象挂在结果字段上。禁止抛出未包装的原生 Error 穿越模块边界。
 *
 * code 是稳定字符串，供 UI / 日志 / 测试断言使用，不随文案改动。
 */

const CODES = Object.freeze({
  INVALID_URL: 'INVALID_URL',
  URL_TOO_LONG: 'URL_TOO_LONG',
  UNSUPPORTED_PROTOCOL: 'UNSUPPORTED_PROTOCOL',
  MISSING_HOST: 'MISSING_HOST',
  DNS_FAIL: 'DNS_FAIL',
  TLS_FAIL: 'TLS_FAIL',
  FETCH_FAIL: 'FETCH_FAIL',
  TIMEOUT: 'TIMEOUT',
  TOO_MANY_REDIRECTS: 'TOO_MANY_REDIRECTS',
  REDIRECT_LOOP: 'REDIRECT_LOOP',
  BODY_TOO_LARGE: 'BODY_TOO_LARGE',
  DECOMPRESS_FAIL: 'DECOMPRESS_FAIL',
  PROBE_SKIPPED: 'PROBE_SKIPPED',
  INTERNAL: 'INTERNAL',
});

/**
 * 构造标准错误对象。不抛异常，只返回可序列化对象。
 * @param {string} code CODES 之一
 * @param {string} message 面向用户的中文说明
 * @param {Error|string|object} [cause] 原始错误（只取 message/code，避免循环引用）
 */
function appError(code, message, cause) {
  const out = { code: code || CODES.INTERNAL, message: String(message || '未知错误') };
  if (cause != null) {
    if (cause instanceof Error) {
      out.cause = cause.message;
      if (cause.code) out.causeCode = String(cause.code);
    } else if (typeof cause === 'object') {
      out.cause = String(cause.message || '');
      if (cause.code) out.causeCode = String(cause.code);
    } else {
      out.cause = String(cause);
    }
  }
  return out;
}

/** 把任意抛出值归一化成标准错误对象，永不抛错、永不产生循环引用 */
function normalizeError(e, fallbackCode) {
  if (e && typeof e === 'object' && typeof e.code === 'string' && typeof e.message === 'string' && CODES[e.code]) {
    return e;
  }
  const message = e && e.message ? e.message : String(e || '未知错误');
  return appError(fallbackCode || CODES.INTERNAL, message, e);
}

/** 给异步探测加超时保护；超时返回标准错误对象而不是抛异常 */
function withTimeout(promise, ms, code, message) {
  let timer = null;
  const guard = new Promise((resolve) => {
    // 不要 unref：当调用方没有其它 I/O 句柄时（纯 CPU / CLI / 单测），
    // unref 会让进程直接静默退出，兜底定时器反而永不触发。
    timer = setTimeout(() => resolve(appError(code || CODES.TIMEOUT, message || '操作超时（' + ms + 'ms）')), ms);
  });
  return Promise.race([promise, guard]).finally(() => { if (timer) clearTimeout(timer); });
}

module.exports = Object.freeze({ CODES, appError, normalizeError, withTimeout });
