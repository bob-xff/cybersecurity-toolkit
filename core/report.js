'use strict';

/**
 * Markdown 报告生成
 */

const STATUS_LABEL = { pass: '通过', warn: '警告', fail: '不通过', info: '提示', na: '不适用' };
const SEV_LABEL = { high: '高', medium: '中', low: '低', info: '提示' };
const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
const TIME_LIMIT = { high: '7 日内', medium: '14 日内', low: '30 日内', info: '按计划' };

function fmtStd(list) {
  return (list || []).join('；') || '—';
}

/**
 * 表格单元格消毒：URL/证据等外部数据可能含 |、换行、制表符，
 * 直接拼接会破坏 Markdown 表格结构（甚至注入伪表格行）。统一转义+压平。
 */
function cell(v, max) {
  let s = String(v == null ? '' : v)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\|/g, '\\|')
    .replace(/\s+/g, ' ')
    .trim();
  if (max && s.length > max) s = s.slice(0, Math.max(0, max - 1)) + '…';
  return s || '—';
}

/** 普通行消毒（标题/列表项）：压平换行，防止结构注入 */
function line(v) {
  const s = String(v == null ? '' : v).replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim();
  return s || '—';
}

function buildMarkdown(r) {
  const L = [];
  const push = (s) => L.push(s);

  push('# 网站网络安全评估报告');
  push('');
  push('> 本报告由《网站网络安全评估工具》自动生成，评判依据为《网站网络安全评估标准清单 V1.0》（国内：网络安全法〔2025 修正〕/数据安全法/个人信息保护法、GB/T 22239-2019 等；国际：OWASP Top 10:2021、OWASP ASVS、ISO/IEC 27001:2022、CIS Controls v8.1、PCI DSS v4.0.1 等现行标准）。');
  push('> 自动化外部暴露面评估结论，不等同于等级保护测评或授权渗透测试结论。');
  push('');

  // 概要
  push('## 一、评估概要');
  push('');
  push('| 项目 | 内容 |');
  push('|---|---|');
  push('| 目标网址 | ' + cell(r.target.url, 200) + ' |');
  push('| 最终访问 | ' + (r.target.finalUrl ? cell(r.target.finalUrl, 200) + '（HTTP ' + r.target.finalStatus + '）' : '不可达') + ' |');
  push('| 重定向链路 | ' + (r.target.redirectChain && r.target.redirectChain.length > 1 ? r.target.redirectChain.map((c) => c.status + ' ' + cell(c.url, 120)).join(' → ') : '无') + ' |');
  push('| 评估时间 | ' + r.startedAt + ' |');
  push('| 评估耗时 | ' + (r.durationMs / 1000).toFixed(1) + ' 秒 |');
  push('| 工具版本 | ' + r.tool + ' v' + r.toolVersion + ' |');
  push('| **综合评分** | **' + (r.score == null ? '无法评估' : r.score + ' / 100') + '** |');
  push('| **合规等级** | **' + r.level.grade + '（' + r.level.label + '）** |');
  push('');

  const counts = { pass: 0, warn: 0, fail: 0, info: 0, na: 0 };
  r.checks.forEach((c) => { counts[c.status] = (counts[c.status] || 0) + 1; });
  push('检查项统计：共 ' + r.checks.length + ' 项 —— 通过 ' + counts.pass + '、警告 ' + counts.warn + '、不通过 ' + counts.fail + '、提示 ' + counts.info + '、不适用 ' + counts.na + '。');
  push('');
  if (r.warnings && r.warnings.length) {
    push('评估提示：' + r.warnings.map(line).join('；'));
    push('');
  }

  // 维度得分
  push('## 二、维度得分');
  push('');
  push('| 维度 | 权重 | 得分 | 通过 | 警告 | 不通过 | 提示 | 不适用 |');
  push('|---|---|---|---|---|---|---|---|');
  for (const cat of r.categories) {
    push('| ' + cat.code + ' ' + cat.name + ' | ' + cat.weight + '% | ' + (cat.score == null ? '—' : cat.score) + ' | ' + cat.counts.pass + ' | ' + cat.counts.warn + ' | ' + cat.counts.fail + ' | ' + cat.counts.info + ' | ' + cat.counts.na + ' |');
  }
  push('');

  // 详细发现
  push('## 三、详细发现');
  push('');
  const fails = r.checks.filter((c) => c.status === 'fail').sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  const warns = r.checks.filter((c) => c.status === 'warn').sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  const passes = r.checks.filter((c) => c.status === 'pass');
  const infos = r.checks.filter((c) => c.status === 'info' || c.status === 'na');

  if (fails.length) {
    push('### 3.1 不通过项（' + fails.length + '）');
    push('');
    for (const c of fails) {
      push('#### [' + c.id + '] ' + line(c.title));
      push('- 状态：**不通过** | 风险等级：' + SEV_LABEL[c.severity]);
      push('- 证据：' + line(c.evidence));
      push('- 国内标准：' + fmtStd(c.cnStandards));
      push('- 国际标准：' + fmtStd(c.intlStandards));
      push('- 整改建议：' + line(c.remediation));
      push('');
    }
  }
  if (warns.length) {
    push('### 3.2 警告项（' + warns.length + '）');
    push('');
    for (const c of warns) {
      push('#### [' + c.id + '] ' + line(c.title));
      push('- 状态：**警告** | 风险等级：' + SEV_LABEL[c.severity]);
      push('- 证据：' + line(c.evidence));
      push('- 国内标准：' + fmtStd(c.cnStandards));
      push('- 国际标准：' + fmtStd(c.intlStandards));
      push('- 整改建议：' + line(c.remediation));
      push('');
    }
  }
  if (passes.length) {
    push('### 3.3 通过项（' + passes.length + '）');
    push('');
    for (const c of passes) {
      push('- [' + c.id + '] ' + line(c.title) + '：' + line(c.evidence));
    }
    push('');
  }
  if (infos.length) {
    push('### 3.4 提示与不适用项（' + infos.length + '）');
    push('');
    for (const c of infos) {
      push('- [' + c.id + '] ' + line(c.title) + '：' + line(c.evidence));
    }
    push('');
  }

  // 整改优先级
  push('## 四、整改优先级清单');
  push('');
  const todo = fails.concat(warns).sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  if (todo.length) {
    push('| 优先级 | 编号 | 事项 | 风险 | 建议时限 | 整改要点 |');
    push('|---|---|---|---|---|---|');
    todo.forEach((c, i) => {
      push('| ' + (i + 1) + ' | ' + c.id + ' | ' + cell(c.title, 40) + ' | ' + SEV_LABEL[c.severity] + ' | ' + TIME_LIMIT[c.severity] + ' | ' + cell(c.remediation, 80) + ' |');
    });
  } else {
    push('未发现需要整改的项。');
  }
  push('');

  // 标准映射汇总
  push('## 五、标准映射汇总');
  push('');
  push('本次评估引用的评判依据分布：');
  push('');
  push('- 国内法律与标准：网络安全法（2025 修正）、数据安全法、个人信息保护法、GB/T 22239-2019（等保 2.0）、GB/T 35273-2020、GB/T 43698-2024（软件供应链）、GB/T 43697-2024（数据分类分级）、《互联网信息服务管理办法》等');
  push('- 国际标准：OWASP Top 10:2021（A01–A10）、OWASP ASVS、ISO/IEC 27001:2022、CIS Controls v8.1、PCI DSS v4.0.1、NIST SP 800-53 Rev.5、RFC 6797/7208/7489/8659/9116 等');
  push('');
  push('逐项映射见「详细发现」各条目的国内/国际标准字段，可按编号回溯至《网站网络安全评估标准清单》。');
  push('');

  // 技术栈与探测证据
  const tech = r.tech || {};
  const libs = tech.libs || [];
  const tls = r.tls || null;
  const dns = r.dns || null;
  const exp = r.exposure || null;
  const hasEvidence = !!tls || libs.length > 0 || (tech.cms || []).length > 0 ||
    !!tech.generator || !!(dns && dns.domain) || !!(exp && exp.enabled);

  if (hasEvidence) {
    push('## 六、技术栈与探测证据');
    push('');
    push('> 以下为工具实际采集到的原始信息，用于人工复核结论；它们本身不是「结论」。');
    push('');

    // TLS / 证书
    push('### 6.1 TLS 与证书');
    push('');
    if (tls && tls.reachable) {
      const cert = tls.cert || {};
      const neg = tls.negotiated || {};
      push('| 项目 | 内容 |');
      push('|---|---|');
      push('| 探测端口 | ' + cell(tls.port) + ' |');
      push('| 协商协议 / 套件 | ' + cell((neg.protocol || '?') + ' / ' + ((neg.cipher && neg.cipher.name) || '?')) + ' |');
      push('| 证书主体 | ' + cell((cert.subject && cert.subject.CN) || '') + ' |');
      push('| 签发机构 | ' + cell((cert.issuer && (cert.issuer.O || cert.issuer.CN)) || '') + ' |');
      push('| 有效期 | ' + cell(cert.validFrom) + ' ~ ' + cell(cert.validTo) + '（剩余 ' + (cert.daysRemaining == null ? '—' : cert.daysRemaining) + ' 天） |');
      push('| 证书链可信 | ' + (tls.trusted ? '是' : '否（' + cell(tls.trustError, 80) + '）') + ' |');
      push('| 自签名 | ' + (cert.selfSigned ? '是' : '否') + ' |');
      push('| SAN 条目数 | ' + ((cert.altNames || []).length) + ' |');
      push('| 协议支持情况 | ' + (Object.keys(tls.protocols || {}).map((k) => k + '=' + (tls.protocols[k] === true ? '支持' : tls.protocols[k] === false ? '不支持' : '未知')).join('、') || '—') + ' |');
      push('| 检出弱套件 | ' + ((tls.weakCiphers || []).join('、') || '未检出') + ' |');
      push('');
      if ((tls.notes || []).length) { push('探测说明：' + tls.notes.map(line).join('；')); push(''); }
    } else {
      push('未能在端口 ' + cell(tls && tls.port) + ' 建立 TLS 连接' +
        (tls && tls.error ? '（' + cell(tls.error, 120) + '）' : '') + '。');
      push('');
    }

    // 技术栈
    push('### 6.2 技术栈与前端组件');
    push('');
    push('- CMS 指纹：' + ((tech.cms || []).join('、') || '未识别'));
    push('- 前端框架：' + ((tech.frameworks || []).join('、') || '未识别'));
    push('- Generator：' + (tech.generator ? line(tech.generator) : '未识别'));
    push('- ICP 备案：' + (tech.icp ? line(tech.icp) : '未识别'));
    push('- 页面引用脚本数：' + (tech.scriptCount == null ? '—' : tech.scriptCount));
    push('- 响应类型：' + (tech.isHtml === false ? '非 HTML 文档（内容类检查已标记不适用）' : 'HTML 文档') +
      '；字符集：' + cell(tech.charset || 'utf-8') + (tech.scanLimited ? '；内容分析仅覆盖前 ' + (256 * 1024) + ' 字节' : ''));
    push('');
    if (libs.length) {
      push('| 组件 | 版本 | 判定 | 严重度 | 漏洞 / 备注 | 识别方式 |');
      push('|---|---|---|---|---|---|');
      for (const l of libs) {
        const verdict = l.vulnerable === true ? '**受影响**'
          : l.eol ? '已停止维护'
          : l.vulnerable === false ? '版本安全' : '版本未知';
        const note = l.cve || (l.hasSri ? '已启用 SRI' : '');
        push('| ' + cell(l.lib) + ' | ' + cell(l.version || '未识别') + ' | ' + verdict + ' | ' +
          (SEV_LABEL[l.severity] || '—') + ' | ' + cell(note, 70) + ' | ' + cell(l.via) + ' |');
      }
      push('');
    } else {
      push('未识别到漏洞库中的前端组件（可能未使用，或外部脚本不可达）。');
      push('');
    }

    // DNS
    if (dns && dns.domain) {
      const st = dns.states || {};
      push('### 6.3 DNS 与邮件安全记录');
      push('');
      push('| 记录 | 内容 |');
      push('|---|---|');
      push('| 可注册域 | ' + cell(dns.domain) + ' |');
      push('| SPF | ' + (dns.spf
        ? cell(dns.spf.record, 200) + '（' + cell(dns.spf.at) + '，机制 ' + cell(dns.spf.mechanism) + '）'
        : (st.spf === 'error' ? '查询失败，无法判定' : '未配置')) + ' |');
      push('| DMARC | ' + (dns.dmarc
        ? cell(dns.dmarc.record, 200) + '（策略 ' + cell(dns.dmarc.policy) + '）'
        : (st.dmarc === 'error' ? '查询失败，无法判定' : '未配置')) + ' |');
      push('| MX | ' + ((dns.mx || []).map((m) => cell(m.exchange) + '（优先级 ' + m.priority + '）').join('、') || '无') + ' |');
      push('| CAA | ' + ((dns.caa || []).map((c) => cell(typeof c === 'string' ? c : JSON.stringify(c)), 60).join('、') || '无') + ' |');
      push('| DNSSEC | ' + (dns.dnssec == null ? '未检测' : (dns.dnssec ? '已启用' : '未启用')) + ' |');
      push('');
      if (dns.doh) { push('> 注：系统 DNS 不可用，以上记录由 DoH（阿里 / 腾讯 / Google）返回。'); push(''); }
      if ((dns.errors || []).length) { push('DNS 查询异常：' + dns.errors.map(line).join('；')); push(''); }
    }

    // 暴露面
    if (exp && exp.enabled) {
      push('### 6.4 暴露面探测明细');
      push('');
      push('- 已探测公开路径：' + (exp.checkedFiles || 0) + ' 条；命中敏感内容：' + ((exp.foundFiles || []).length) + ' 条' +
        (exp.failedRequests ? '；失败请求：' + exp.failedRequests + ' 条（相关结论可能不完整）' : ''));
      if ((exp.foundFiles || []).length) {
        push('');
        for (const f of exp.foundFiles) {
          push('- ⚠ `' + line(f.path) + '` —— ' + line(f.label) + '（HTTP ' + f.status + '）');
        }
      }
      push('- security.txt：' + (exp.securityTxt ? '存在（' + line(exp.securityTxtUrl || '') + '）' : '未发现'));
      push('- robots.txt：' + (exp.robots == null ? '未获取 / 不存在' : '已获取'));
      push('- sitemap：' + (exp.sitemap == null ? '未获取 / 不存在' : '已获取'));
      push('');
    }

    // 检测范围与耗时：便于判断本次结论的置信度与复现性能
    const perf = r.performance || {};
    if (perf.pageMs != null || perf.probesMs != null) {
      push('### 6.5 检测范围与耗时');
      push('');
      push('| 阶段 | 耗时 |');
      push('|---|---|');
      push('| 页面抓取（含重定向） | ' + (perf.pageMs == null ? '—' : perf.pageMs + ' ms') + ' |');
      push('| 五路并行探测 | ' + (perf.probesMs == null ? '—' : perf.probesMs + ' ms') + ' |');
      push('| 其中 TLS 探测 | ' + (perf.tlsMs == null ? '—' : perf.tlsMs + ' ms') + ' |');
      push('| 其中暴露面探测 | ' + (perf.exposureMs == null ? '—' : perf.exposureMs + ' ms') + ' |');
      push('| 检查项计算 | ' + (perf.checksMs == null ? '—' : perf.checksMs + ' ms') + ' |');
      push('| 总计 | ' + (r.durationMs == null ? '—' : r.durationMs + ' ms') + ' |');
      push('');
    }
  }

  // 局限
  push('## 七、说明与局限');
  push('');
  push('1. 本评估基于外部可见面（公开页面抓取、响应头、DNS、少量公开路径探测），不覆盖代码层、内网、业务逻辑与运维配置；');
  push('2. TLS 协议/套件探测受本地 OpenSSL 版本限制，关键结论建议以 testssl.sh / SSL Labs 交叉验证；');
  push('3. 前端组件漏洞库为高频高危库子集，不等同于完整 SCA；');
  push('4. **「无法检测 / 不适用」与「通过」严格区分**：页面不可达、响应非 HTML、探测被关闭或请求失败时，相关检查项记为「无法检测」且不计入评分，不代表站点不存在该问题；');
  push('5. DNSSEC 仅依据区顶点 DNSKEY 是否存在判断，未验证 DS 信任链与 RRSIG；');
  push('6. 本结论不构成等级保护测评、渗透测试或合规认证结论。');
  push('');

  return L.join('\n');
}

module.exports = { buildMarkdown, STATUS_LABEL, SEV_LABEL };
