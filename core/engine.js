'use strict';

/**
 * 评估引擎编排：采集 → 检测 → 评分
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

const TOOL_VERSION = '1.0.0';
const STATUS_SCORE = { pass: 1, warn: 0.5, fail: 0 };

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
  for (const cat of Object.values(cats)) {
    let ws = 0;
    let wsum = 0;
    for (const r of results) {
      if (r.category !== cat.id) continue;
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

async function assess(input, options = {}) {
  const startedAt = new Date();
  const t0 = Date.now();
  let url;
  try {
    url = normalizeUrl(input);
  } catch (e) {
    return { ok: false, error: e.message };
  }
  const hostname = hostnameOf(url);
  const ctx = { url: url.toString(), hostname, warnings: [], toolVersion: TOOL_VERSION };

  // 进度回调（网页版 NDJSON 流 / 桌面版 IPC 推送复用同一钩子）
  const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
  const prog = (step, text) => { if (onProgress) { try { onProgress(step, text); } catch (e) { /* 回调异常不影响评估 */ } } };
  prog('start', '开始评估 ' + url.toString());

  // 1. 页面抓取（https 优先；连接级失败时回退 http 以完成其余评估）
  prog('page', '正在抓取页面并跟踪重定向…');
  let page;
  try {
    page = await fetchPage(url.toString(), { timeout: options.timeout || 15000 });
  } catch (e) {
    page = { ok: false, error: { message: e.message }, chain: [], finalUrl: url.toString() };
    ctx.warnings.push('页面抓取异常：' + e.message);
  }
  if (!page.ok && url.protocol === 'https:') {
    const httpUrl = url.toString().replace(/^https:/, 'http:');
    const retry = await fetchPage(httpUrl, { timeout: options.timeout || 15000 });
    if (retry.ok) {
      page = retry;
      ctx.warnings.push('HTTPS 访问失败，已回退至 HTTP 完成评估');
    }
  }
  if (!page.ok) {
    /* 抓取失败必须显式告知：否则「页面拿不到」会被误读为「页面没有这些问题」 */
    const em = (page.error && page.error.message) || '未知错误';
    ctx.warnings.push('页面抓取失败（' + em + '）：内容类检查项结论不完整，请勿据此判断站点无此问题');
  }
  ctx.page = page;

  // 2. HTTP → HTTPS 跳转探测（保留非默认端口）
  prog('redirect', '正在检测 HTTP→HTTPS 跳转…');
  let httpRedirect = null;
  try {
    const path = url.pathname && url.pathname !== '/' ? url.pathname : '/';
    const port = url.port && url.port !== '443' && url.port !== '80' ? ':' + url.port : '';
    const httpUrl = 'http://' + hostname + port + path;
    const r = await rawRequest(httpUrl, { timeout: 8000, maxBody: 131072 });
    if (r.ok) {
      let target = null;
      if (r.headers.location) {
        try { target = new URL(r.headers.location, httpUrl).toString(); } catch (e) {}
      }
      httpRedirect = { ok: true, status: r.status, location: target, redirected: !!(target && /^https:/i.test(target)) };
    } else {
      httpRedirect = { ok: false, error: r.error };
    }
  } catch (e) {
    httpRedirect = { ok: false, error: { message: e.message } };
  }
  ctx.httpRedirect = httpRedirect;

  // 3. TLS / 证书
  prog('tls', '正在探测 TLS 协议与证书…');
  /* TLS 端口必须取自目标本身：若目标跑在自定义端口（如 https://host:8443），
   * 仍然探测 443 会把整站误判成「不支持 HTTPS」。 */
  let tlsPort = url.port ? parseInt(url.port, 10) : 443;
  if (page.ok && page.finalUrl) {
    try {
      const fu = new URL(page.finalUrl);
      if (fu.port) tlsPort = parseInt(fu.port, 10);
      else if (fu.protocol === 'https:') tlsPort = 443;
    } catch (e) { /* 保持默认 */ }
  }
  ctx.tls = await probeTls(hostname, tlsPort);
  /* 非 443 端口握手失败时，补探一次标准 443：明确区分「该端口无 TLS」与「全站无 TLS」 */
  if (!ctx.tls.reachable && tlsPort !== 443) {
    const alt = await probeTls(hostname, 443);
    if (alt.reachable) {
      ctx.tls = alt;
      ctx.warnings.push('目标端口 ' + tlsPort + ' 未启用 TLS，但 443 端口可用；TLS 相关结论以 443 端口为准');
    } else {
      ctx.tls.notes.push('同时补探 443 端口亦未成功（' + (alt.error || '未知') + '）');
    }
  }

  // 4. DNS 与邮件安全
  prog('dns', '正在检查 DNS 与邮件安全记录…');
  ctx.dns = await probeDns(hostname);
  // DNS 查询失败必须显式告知（否则"未发现 SPF"会被误读为未配置）
  if (ctx.dns && ctx.dns.errors && ctx.dns.errors.length) {
    ctx.warnings.push('DNS 查询存在问题：' + ctx.dns.errors.join('；') + '。相关检查项已标记为「无法检测」，请勿解读为未配置');
  }
  // DoH 回退透明度：结论来自 DoH 而非系统解析器，报告中如实说明
  if (ctx.dns && ctx.dns.doh) {
    ctx.warnings.push('系统 DNS 解析不可用，已回退 DoH（阿里/腾讯/Google）完成记录查询，结论以 DoH 返回为准');
  }

  // 5. 内容分析
  prog('content', '正在分析页面内容与前端组件…');
  const body = page.ok ? page.final.body : '';
  ctx.content = analyzeContent(body, page.ok ? page.final.url : url.toString());

  // 6. 前端组件漏洞检测
  prog('libs', '正在比对前端组件漏洞库…');
  if (options.detectLibs === false) {
    ctx.libs = [];
    ctx.warnings.push('已按设置关闭「前端组件深度检测」：未抓取外部脚本，组件漏洞相关结论不完整');
  } else {
    try {
      ctx.libs = ctx.content.scripts.length ? await checkLibs(ctx.content.scripts, options) : [];
    } catch (e) {
      ctx.libs = [];
      ctx.warnings.push('组件检测异常：' + e.message);
    }
  }

  // 7. 暴露面探测
  if (options.detectExposure === false) {
    prog('exposure', '已按设置跳过暴露面探测');
    ctx.exposure = null;
    ctx.warnings.push('已按设置关闭「敏感路径暴露面探测」：暴露面相关检查项将标记为不适用');
  } else {
    prog('exposure', '正在探测敏感路径暴露面…');
    try {
      ctx.exposure = await probeExposure(page.ok ? page.final.url : url.toString(), { timeout: options.exposureTimeout || 8000 });
    } catch (e) {
      ctx.exposure = null;
      ctx.warnings.push('暴露面探测异常：' + e.message);
    }
  }

  // 8. 逐项执行检查
  prog('checks', '正在执行 ' + CHECKS.length + ' 项标准检查…');
  const results = [];
  for (const c of CHECKS) {
    let r;
    try {
      r = c.evaluate(ctx);
    } catch (e) {
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

    /* 采集到的证据一并入报告。
     * 此前只把结论写进各检查项的 evidence，导致「到底检测到哪些组件 / 证书细节 /
     * DNS 记录 / 暴露面清单」在 JSON 导出与报告中完全不可见，用户无法自行复核结论。 */
    tls: ctx.tls,
    dns: ctx.dns,
    tech: {
      cms: ctx.content.cms,
      generator: ctx.content.generator,
      icp: ctx.content.icp,
      scriptCount: ctx.content.scripts.length,
      libs: (ctx.libs || []).map((l) => ({
        lib: l.lib,
        version: l.version,
        vulnerable: l.vulnerable,
        eol: l.eol,
        hasSri: l.hasSri,
        via: l.via,
        severity: l.severity,
        cve: l.cve,
        src: l.src,
      })),
    },
    exposure: ctx.exposure ? {
      checkedFiles: (ctx.exposure.files || []).length,
      foundFiles: (ctx.exposure.files || [])
        .filter((f) => f.found)
        .map((f) => ({ path: f.path, label: f.label, status: f.status })),
      securityTxt: ctx.exposure.securityTxt,
      securityTxtUrl: ctx.exposure.securityTxtUrl,
      robots: ctx.exposure.robots,
      sitemap: ctx.exposure.sitemap,
      dirListing: ctx.exposure.dirListing,
      errorLeak: ctx.exposure.errorLeak,
      trace: ctx.exposure.trace,
      enabled: true,
    } : { enabled: false },
  };
  report.markdown = buildMarkdown(report);
  prog('done', '评估完成');
  return report;
}

module.exports = { assess, scoreResults, gradeOf, TOOL_VERSION };
