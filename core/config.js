'use strict';

/**
 * 全局配置（零依赖）。
 *
 * 目的：把此前散落在 fetcher / tls / dnschk / exposure / libcheck / engine / server
 * 各处的超时、体积上限、并发数与重试参数收敛到单一事实源，便于：
 *   - 按访问环境调参（弱网、内网、慢站），不必改代码；
 *   - 用环境变量 SITESEC_* 覆盖，且不引入 dotenv 之类的依赖；
 *   - 测试里精确控制边界值。
 *
 * 所有导出均为不可变冻结对象；需要动态值请用 get()。
 */

const TOOL_VERSION = '1.0.0';

const DEFAULTS = Object.freeze({
  timeouts: Object.freeze({
    page: 15000,       // 主页面抓取（单次请求）
    httpRedirect: 6000, // HTTP→HTTPS 跳转探测
    tls: 6000,         // 单次 TLS 握手
    dns: 5000,         // 系统 DNS 查询兜底超时
    doh: 5000,         // 单个 DoH 端点
    exposure: 6000,    // 暴露面单次请求
    lib: 6000,         // 单个外部脚本
  }),
  limits: Object.freeze({
    maxBody: 1024 * 1024,          // 单响应体（压缩后）上限
    maxDecompressed: 4 * 1024 * 1024, // 解压后上限，防压缩炸弹
    maxRedirects: 8,               // 重定向链最大长度
    maxUrlLength: 2048,            // 输入 URL 最大长度
    maxLibFetch: 6,                // 抓取外部脚本内容的最大数量
    maxContentScan: 256 * 1024,    // 内容分析扫描的最大字符数
    maxBannerScan: 64 * 1024,      // 组件 banner 识别扫描的最大字符数
    maxCommentLength: 2000,        // 单条 HTML 注释分析上限（超出按片段分析）
    maxRequestQueueWait: 120000,   // 网页版并发排队最长等待
  }),
  concurrency: Object.freeze({
    tls: 4,       // TLS 协议/套件矩阵
    exposure: 6,  // 暴露面探测
    libs: 3,      // 外部脚本抓取
  }),
  guardBufferMs: 2000, // 请求兜底定时器相对 timeout 的额外缓冲
});

/** 环境变量覆盖：SITESEC_TIMEOUT_PAGE / SITESEC_LIMIT_MAXBODY 等 */
function envNum(name, raw, fallback) {
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) {
    if (raw != null && raw !== '') {
      // 配置写错要能看见，但不能让工具启动失败
      try { process.stderr.write('[config] 忽略无效的环境变量 ' + name + '=' + raw + '\n'); } catch (e) { /* ignore */ }
    }
    return fallback;
  }
  return n;
}

const ENV_MAP = Object.freeze({
  SITESEC_TIMEOUT_PAGE: ['timeouts', 'page'],
  SITESEC_TIMEOUT_REDIRECT: ['timeouts', 'httpRedirect'],
  SITESEC_TIMEOUT_TLS: ['timeouts', 'tls'],
  SITESEC_TIMEOUT_DNS: ['timeouts', 'dns'],
  SITESEC_TIMEOUT_DOH: ['timeouts', 'doh'],
  SITESEC_TIMEOUT_EXPOSURE: ['timeouts', 'exposure'],
  SITESEC_TIMEOUT_LIB: ['timeouts', 'lib'],
  SITESEC_LIMIT_MAXBODY: ['limits', 'maxBody'],
  SITESEC_LIMIT_MAXDECOMPRESSED: ['limits', 'maxDecompressed'],
  SITESEC_LIMIT_MAXREDIRECTS: ['limits', 'maxRedirects'],
  SITESEC_LIMIT_MAXLIBFETCH: ['limits', 'maxLibFetch'],
  SITESEC_LIMIT_QUEUEWAIT: ['limits', 'maxRequestQueueWait'],
  SITESEC_CONCURRENCY_TLS: ['concurrency', 'tls'],
  SITESEC_CONCURRENCY_EXPOSURE: ['concurrency', 'exposure'],
  SITESEC_CONCURRENCY_LIBS: ['concurrency', 'libs'],
});

function build() {
  const cfg = {
    toolVersion: TOOL_VERSION,
    timeouts: Object.assign({}, DEFAULTS.timeouts),
    limits: Object.assign({}, DEFAULTS.limits),
    concurrency: Object.assign({}, DEFAULTS.concurrency),
    guardBufferMs: DEFAULTS.guardBufferMs,
  };
  const env = (typeof process !== 'undefined' && process.env) || {};
  for (const [key, [group, field]] of Object.entries(ENV_MAP)) {
    if (env[key] != null && env[key] !== '') {
      cfg[group][field] = envNum(key, env[key], cfg[group][field]);
    }
  }
  return cfg;
}

const CONFIG = build();

/** 读取单项配置，支持 'timeouts.page' 形式的路径 */
function get(path, fallback) {
  const parts = String(path || '').split('.');
  let cur = CONFIG;
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return fallback;
    cur = cur[p];
  }
  return cur === undefined ? fallback : cur;
}

module.exports = Object.freeze({
  TOOL_VERSION,
  DEFAULTS,
  timeouts: Object.freeze(CONFIG.timeouts),
  limits: Object.freeze(CONFIG.limits),
  concurrency: Object.freeze(CONFIG.concurrency),
  guardBufferMs: CONFIG.guardBufferMs,
  get,
});
