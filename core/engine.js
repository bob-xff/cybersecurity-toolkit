'use strict';

/**
 * 评估引擎编排：采集 → 检测 → 评分
 *
 * 编排原则：能并行的探测绝不串行。页面抓取完成后，
 * HTTP 跳转 / TLS / DNS / 组件 / 暴露面五路互不依赖，统一提交并行组；
 * 内容分析是同步的，检查结果只依赖上面全部产物。
 */
const { normalizeUrl, hostnameOf } = require('./util');
const { fetchPage, rawRequest } = require('./fetcher');
const { probeTls } = require('./tls');
const { probeDns } = require('./dnschk');
const { analyzeContent } = require('./content');
const { checkLibs } = require('./libcheck');
const { probeExposure } = require('./exposure');
const { CHECKS, CATEGORIES, SEV_WEIGHT } = require('./standards');
const { buildMarkdown } = require('./report');
const { TOOL_VERSION } = require('./config');
const CONFIG = require('./config');
const logger = require('./logger');
const { normalizeError } = require('./errors');

const STATUS_SCORE = { pass: 1, warn: 0.5, fail: 0 };
const phaseTimings = () => ({ page: null, probes: null, checks: null });

function gradeOf(score) {
  if (score >= 90) return { grade: 'A', label: '优秀' };
  if (score >= 75) return { grade: 'B', label: '良好' };
  if (score >= 60) return { grade: 'C', label: '合格' };
  if (score >= 40) return { grade: 'D', label: '高风险' };
  return { grade: 'E', label: '严重' };
}

function scoreResults(results) {
  const cats = {};
  for (const c of CATEGORIES) {
    cats[c.id] = { id: c.id, code: c.code, name: c.name, weight: c.weight, score: null, counts: { pass: 0, warn: 0, fail: 0, info: 0, na: 0 } };
  }
  for (const r of results) {
    const cat = cats[r.category];
    if (!cat) continue;
    cat.counts[r.status] = (cat.counts[r.status] || 0) + 1;
  }
  // 一次分组，避免每个维度都全量遍历 results（原实现 O(维度×检查项)）
  const grouped = {};
  for (const r of results) (grouped[r.category] || (grouped[r.category] = [])).push(r);
  for (const cat of Object.values(cats)) {
    let ws = 0;
    let wsum = 0;
    for (const r of grouped[cat.id] || []) {
      if (r.status === 'info' || r.status === 'na') continue;
      ws += r.weight * (STATUS_SCORE[r.status] || 0);
      wsum += r.weight;
    }
    if (wsum > 0) cat.score = Math.round((ws / wsum) * 1000) / 10;
  }
  let ws = 0;
  let wsum = 0;
  for (const cat of Object.values(cats)) {
    if (cat.score == null) continue;
    ws += cat.score * cat.weight;
    wsum += cat.weight;
  }
  const overall = wsum > 0 ? Math.round((ws / wsum) * 10) / 10 : null;
  return { score: overall, level: overall == null ? { grade: 'N/A', label: '无法评估' } : gradeOf(overall), categories: Object.values(cats) };
}

/** 由 https 目标推导等价的 http URL：443 → 默认 80，自定义端口保留 */
function toHttpUrl(u) {
  try {
    const h = new URL(u.toString());
    h.protocol = 'http:';
    if (!h.port || h.port === '443') h.port = '';
    return h.toString();
  } catch (e) {
    return u.toString().replace(/^https:/, 'http:');
  }
}

async function assess(input, options = {}) {
  const startedAt = new Date();
  const t0 = Date.now();
  const timings = phaseTimings();
  let url;
  try {
    url = normalizeUrl(input);
  } catch (e) {
    return { ok: false, error: e.message };
  }
  const hostname = hostnameOf(url);
  const ctx = { url: url.toString(), hostname, warnings: [], toolVersion: TOOL_VERSION, exposureDisabled: options.detectExposure === false };

  const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
  const prog = (step, text) => { if (onProgress) { try { onProgress(step, text); } catch (e) { /* 回调异常不影响评估 */ } } };
  prog('start', '开始评估 ' + url.toString());

  /* 1. 页面抓取（https 优先；连接级失败时回退 http 以完成其余评估） */
  prog('page', '正在抓取页面并跟踪重定向…');
  const pageT0 = Date.now();
  let page;
  try {
    page = await fetchPage(url.toString(), { timeout: options.timeout || CONFIG.timeouts.page });
  } catch (e) {
    page = { ok: false, error: { message: e.message }, chain: [], finalUrl: url.toString() };
    ctx.warnings.push('页面抓取异常：' + e.message);
    logger.warn('FETCH', '页面抓取异常', { host: logger.redact(hostname), reason: e.message });
  }
  if (!page.ok && url.protocol === 'https:') {
    const retry = await fetchPage(toHttpUrl(url), { timeout: options.timeout || CONFIG.timeouts.page });
    if (retry.ok) {
      page = retry;
      ctx.warnings.push('HTTPS 访问失败，已回退至 HTTP 完成评估（传输类结论按 HTTP 判定）');
    }
  }
  timings.page = Date.now() - pageT0;
  if (!page.ok) {
    /* 抓取失败必须显式告知：否则「页面拿不到」会被误读为「页面没有这些问题」 */
    const em = (page.error && page.error.message) || '未知错误';
    ctx.warnings.push('页面抓取失败（' + em + '）：依赖页面内容/响应头的检查项已标记为「无法检测」，请勿据此判断站点无此问题');
  }
  ctx.page = page;

  const finalUrl = page.ok ? page.final.url : url.toString();
  const finalRes = page.ok ? page.final : null;

  /* 响应不是 HTML（JSON / 图片 / 空响应）时，内容类结论必须降级 */
  const contentType = finalRes ? finalRes.contentType : '';
  prog('content', '正在分析页面内容与前端组件…');
  ctx.content = analyzeContent(finalRes ? finalRes.body : '', finalUrl, { contentType });
  if (page.ok && !ctx.content.isHtml) {
    ctx.warnings.push('目标响应并非 HTML 文档（Content-Type: ' + (contentType || '未知') + '），内容类检查项已标记为不适用');
  }
  if (finalRes && finalRes.truncated) {
    ctx.warnings.push('页面正文超过大小上限，内容分析基于已读取的前半部分，结论可能不完整');
  }
  if (finalRes && finalRes.truncatedByDecompression) {
    ctx.warnings.push('响应解压后超过大小上限（疑似压缩膨胀），内容分析基于截断数据');
  }
  if (finalRes && finalRes.charset && finalRes.charset !== 'utf-8') {
    ctx.warnings.push('页面使用 ' + finalRes.charset + ' 编码，已按该字符集解码分析');
  }

  /* 2. 五路独立探测并行执行。
   * 进度事件按原有 step 顺序先发出，保证 UI 步骤导轨语义不变。 */
  prog('redirect', '正在检测 HTTP→HTTPS 跳转…');
  prog('tls', '正在探测 TLS 协议与证书…');
  prog('dns', '正在检查 DNS 与邮件安全记录…');
  prog('libs', '正在比对前端组件漏洞库…');
  prog('exposure', ctx.exposureDisabled ? '已按设置跳过暴露面探测' : '正在探测敏感路径暴露面…');

  const probeT0 = Date.now();

  /* TLS 端口取自目标本身：自定义端口（如 :8443）仍探 443 会把整站误判为不支持 HTTPS */
  let tlsPort = url.port ? parseInt(url.port, 10) : 443;
  if (finalRes) {
    try {
      const fu = new URL(finalUrl);
      if (fu.port) tlsPort = parseInt(fu.port, 10);
      else if (fu.protocol === 'https:') tlsPort = 443;
    } catch (e) { /* 保持默认 */ }
  }

  const redirectTask = (async () => {
    try {
      // HTTP 跳转探测走默认 80；仅当输入本身就是带端口的 http 目标时沿用该端口
      let httpTarget;
      const h = toHttpUrl(url);
      if (url.protocol === 'http:' && url.port) httpTarget = h;
      else {
        const hu = new URL(h);
        hu.port = '';
        httpTarget = hu.toString();
      }
      const r = await rawRequest(httpTarget, { timeout: CONFIG.timeouts.httpRedirect, maxBody: 131072 });
      if (!r.ok) return { ok: false, error: r.error };
      let target = null;
      if (r.headers.location) {
        try { target = new URL(r.headers.location, httpTarget).toString(); } catch (e) { /* 保持 null */ }
      }
      return { ok: true, status: r.status, location: target, redirected: !!(target && /^https:/i.test(target)) };
    } catch (e) {
      return { ok: false, error: normalizeError(e) };
    }
  })();

  const tlsTask = (async () => {
    const tls = await probeTls(hostname, tlsPort);
    if (!tls.reachable && tlsPort !== 443) {
      const alt = await probeTls(hostname, 443);
      if (alt.reachable) {
        ctx.warnings.push('目标端口 ' + tlsPort + ' 未启用 TLS，但 443 端口可用；TLS 相关结论以 443 端口为准');
        return alt;
      }
      tls.notes.push('同时补探 443 端口亦未成功（' + (alt.error || '未知') + '）');
    }
    return tls;
  })();

  const dnsTask = probeDns(hostname);

  const libsTask = (async () => {
    if (options.detectLibs === false) {
      ctx.warnings.push('已按设置关闭「前端组件深度检测」：未抓取外部脚本，组件漏洞相关结论不完整');
      return [];
    }
    try {
      return ctx.content.scripts.length
        ? await checkLibs(ctx.content.scripts, { libLimit: options.libLimit != null ? options.libLimit : CONFIG.limits.maxLibFetch })
        : [];
    } catch (e) {
      ctx.warnings.push('组件检测异常：' + e.message);
      return [];
    }
  })();

  const exposureTask = (async () => {
    if (ctx.exposureDisabled) {
      ctx.warnings.push('已按设置关闭「敏感路径暴露面探测」：暴露面相关检查项将标记为不适用');
      return null;
    }
    try {
      return await probeExposure(finalUrl, { timeout: options.exposureTimeout || CONFIG.timeouts.exposure });
    } catch (e) {
      ctx.warnings.push('暴露面探测异常：' + e.message);
      return null;
    }
  })();

  const [httpRedirect, tls, dns, libs, exposure] = await Promise.all([
    redirectTask, tlsTask, dnsTask, libsTask, exposureTask,
  ]);
  timings.probes = Date.now() - probeT0;
  ctx.httpRedirect = httpRedirect;
  ctx.tls = tls;
  ctx.dns = dns;
  ctx.libs = libs;
  ctx.exposure = exposure;

  if (dns && dns.errors && dns.errors.length) {
    ctx.warnings.push('DNS 查询存在问题：' + dns.errors.join('；') + '。相关检查项已标记为「无法检测」，请勿解读为未配置');
  }
  if (dns && dns.doh) {
    ctx.warnings.push('系统 DNS 解析不可用，已回退 DoH（阿里/腾讯/Google）完成记录查询，结论以 DoH 返回为准');
  }
  if (exposure && exposure.failedRequests > 0) {
    ctx.warnings.push('暴露面探测有 ' + exposure.failedRequests + ' 个请求失败（超时/连接错误），相关结论可能不完整');
  }

  /* 3. 逐项执行检查（前置条件由 standards.prerequisite 统一守卫） */
  prog('checks', '正在执行 ' + CHECKS.length + ' 项标准检查…');
  const checkT0 = Date.now();
  const results = [];
  for (const c of CHECKS) {
    let r;
    try {
      r = c.evaluate(ctx);
    } catch (e) {
      logger.warn('CHECK', '检查项执行异常', { id: c.id, reason: e.message });
      r = { status: 'na', evidence: '检测异常：' + e.message, detail: null };
    }
    results.push({
      id: c.id,
      category: c.cat,
      title: c.title,
      severity: c.severity,
      weight: SEV_WEIGHT[c.severity] || 1,
      status: r.status,
      evidence: r.evidence || '',
      detail: r.detail || null,
      cnStandards: c.cn,
      intlStandards: c.intl,
      remediation: c.remediation,
    });
  }
  timings.checks = Date.now() - checkT0;

  const scored = scoreResults(results);
  prog('score', '正在汇总评分与生成报告…');
  const report = {
    ok: true,
    tool: '网站网络安全评估工具',
    toolVersion: TOOL_VERSION,
    target: {
      input: String(input),
      url: url.toString(),
      hostname,
      finalUrl: page.ok ? page.final.url : null,
      finalStatus: page.ok ? page.final.status : null,
      redirectChain: page.chain,
    },
    startedAt: startedAt.toISOString(),
    durationMs: Date.now() - t0,
    warnings: ctx.warnings,
    score: scored.score,
    level: scored.level,
    categories: scored.categories,
    checks: results,

    /* 采集证据一并入报告，供复核结论 */
    tls: ctx.tls,
    dns: ctx.dns,
    tech: {
      cms: ctx.content.cms,
      frameworks: ctx.content.frameworks,
      generator: ctx.content.generator,
      icp: ctx.content.icp,
      isHtml: ctx.content.isHtml,
      charset: finalRes ? finalRes.charset : 'utf-8',
      scanLimited: ctx.content.scanLimited,
      scriptCount: ctx.content.scripts.length,
      libs: (ctx.libs || []).map((l) => ({
        lib: l.lib, version: l.version, vulnerable: l.vulnerable, eol: l.eol,
        hasSri: l.hasSri, via: l.via, severity: l.severity, cve: l.cve, src: l.src,
      })),
    },
    exposure: ctx.exposure ? {
      checkedFiles: (ctx.exposure.checked || []).length,
      failedRequests: ctx.exposure.failedRequests,
      foundFiles: (ctx.exposure.files || []).map((f) => ({ path: f.path, label: f.label, status: f.status })),
      securityTxt: ctx.exposure.securityTxt,
      securityTxtUrl: ctx.exposure.securityTxtUrl,
      robots: ctx.exposure.robots,
      sitemap: ctx.exposure.sitemap,
      dirListing: ctx.exposure.dirListing,
      errorLeak: ctx.exposure.errorLeak,
      trace: ctx.exposure.trace,
      enabled: true,
    } : { enabled: false },
    performance: {
      pageMs: timings.page,
      probesMs: timings.probes,
      checksMs: timings.checks,
      tlsMs: ctx.tls ? ctx.tls.durationMs : null,
      exposureMs: ctx.exposure ? ctx.exposure.durationMs : null,
    },
  };
  report.markdown = buildMarkdown(report);
  logger.info('ASSESS', '评估完成', {
    host: logger.redact(hostname), score: report.score, grade: report.level.grade,
    durationMs: report.durationMs, probesMs: timings.probes,
  });
  prog('done', '评估完成');
  return report;
}

module.exports = { assess, scoreResults, gradeOf, TOOL_VERSION };
