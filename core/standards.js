'use strict';

/**
 * 评估标准定义：43 项自动化评估检查
 * 每项包含：编号、维度、风险等级、国内/国际标准映射、整改建议、检测逻辑
 * 与《docs/网站网络安全评估标准清单.md》同源维护
 */

const CATEGORIES = [
  { id: 'transport', code: 'T', name: '传输与加密安全', weight: 25 },
  { id: 'headers', code: 'H', name: '安全响应头', weight: 20 },
  { id: 'content', code: 'D', name: '内容与代码安全', weight: 15 },
  { id: 'exposure', code: 'E', name: '信息泄露与暴露面', weight: 15 },
  { id: 'cookies', code: 'C', name: 'Cookie 安全', weight: 10 },
  { id: 'dns', code: 'N', name: 'DNS 与邮件安全', weight: 10 },
  { id: 'privacy', code: 'P', name: '隐私与合规标识', weight: 5 },
];

const SEV_WEIGHT = { high: 3, medium: 2, low: 1, info: 0.5 };

/* ---------------- 工具函数 ---------------- */

function parseCookies(setCookieHeaders) {
  return (setCookieHeaders || []).map((h) => {
    const parts = String(h).split(';');
    const pair = parts.shift() || '';
    const attrStr = parts.join(';');
    const idx = pair.indexOf('=');
    const name = (idx > -1 ? pair.slice(0, idx) : pair).trim();
    // 属性必须是完整片段（Path=/httponly-guide 不得误判为 HttpOnly）
    const hasAttr = (re) => new RegExp('(^|;)\\s*' + re + '\\s*(;|$)', 'i').test(attrStr);
    return {
      name,
      value: idx > -1 ? pair.slice(idx + 1).trim() : '',
      secure: hasAttr('secure'),
      httpOnly: hasAttr('httponly'),
      sameSite: (/\bsamesite\s*=\s*([a-zA-Z]+)/i.exec(attrStr) || [])[1] || null,
      hasPrefix: /^__(Secure|Host)-/i.test(name),
      raw: h,
    };
  });
}

function parseCsp(value) {
  const out = {};
  String(value || '')
    .split(';')
    .forEach((part) => {
      const t = part.trim().split(/\s+/);
      if (t[0]) out[t[0].toLowerCase()] = t.slice(1);
    });
  return out;
}

function hostMatch(pattern, host) {
  pattern = String(pattern || '').toLowerCase().replace(/\.$/, '');
  if (!pattern) return false;
  if (pattern === host) return true;
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2);
    // 通配符只覆盖子域，不覆盖裸域（*.example.com 不含 example.com）
    return host.endsWith('.' + suffix) && host.length > suffix.length + 1;
  }
  return false;
}

function cookiesOf(ctx) {
  if (!ctx.page || !ctx.page.ok) return [];
  return parseCookies(ctx.page.final.headers['set-cookie']);
}

function hdr(ctx, name) {
  if (!ctx.page || !ctx.page.ok) return null;
  return ctx.page.final.headers[String(name).toLowerCase()] || null;
}

function isHttpsPage(ctx) {
  return !!(ctx.page && ctx.page.ok && /^https:/i.test(ctx.page.final.url));
}

/* 状态快捷函数 */
const pass = (evidence, detail) => ({ status: 'pass', evidence, detail: detail || null });
const warn = (evidence, detail) => ({ status: 'warn', evidence, detail: detail || null });
const fail = (evidence, detail) => ({ status: 'fail', evidence, detail: detail || null });
const na = (evidence) => ({ status: 'na', evidence, detail: null });
const info = (evidence, detail) => ({ status: 'info', evidence, detail: detail || null });

/* ---------------- 检查项定义 ---------------- */

const CHECKS = [
  /* ============ T 传输与加密安全 ============ */
  {
    id: 'T1', cat: 'transport', title: 'HTTPS 加密传输可用性', severity: 'high',
    cn: ['《网络安全法》第21条（安全保护义务）', 'GB/T 22239-2019 安全通信网络（通信传输保密性）'],
    intl: ['OWASP Top 10:2021 A02', 'OWASP ASVS V9.1', 'PCI DSS 4.0.1 Req.4.2', 'CIS v8.1 Control 3.10', 'NIST SP 800-53 SC-8'],
    remediation: '为全站部署可信 CA 签发的证书并启用 HTTPS（国内可同步部署国密 SM2 双证书），将 HTTP 流量全部收敛至 HTTPS。',
    evaluate(ctx) {
      if (isHttpsPage(ctx)) return pass('站点经 HTTPS 正常访问：' + ctx.page.final.url);
      if (ctx.tls && ctx.tls.reachable) {
        return warn('443 端口 TLS 可握手，但默认访问未落在 HTTPS（最终 URL：' + (ctx.page.ok ? ctx.page.final.url : '不可达') + '）');
      }
      if (ctx.page && ctx.page.ok && !ctx.tls.reachable) return fail('站点仅提供 HTTP 访问，443 端口不可达，未启用 HTTPS');
      return fail('目标不可达：' + ((ctx.page && ctx.page.error && ctx.page.error.message) || '未知错误') + (ctx.tls && ctx.tls.reachable ? '（但 443 端口 TLS 可握手）' : ''));
    },
  },
  {
    id: 'T2', cat: 'transport', title: 'HTTP 强制跳转 HTTPS', severity: 'medium',
    cn: ['GB/T 22239-2019 安全区域边界（访问控制）'],
    intl: ['OWASP Top 10:2021 A05', 'OWASP ASVS V9.1', 'CIS v8.1 Control 4.1'],
    remediation: '在 Web 服务器 / 负载均衡 / CDN 层配置 80 端口全站 301 跳转至 HTTPS，并配合 HSTS 防止首次明文访问。',
    evaluate(ctx) {
      const r = ctx.httpRedirect;
      if (isHttpsPage(ctx) && r && r.redirected) return pass('HTTP 访问已强制跳转：' + r.status + ' → ' + String(r.location).slice(0, 120));
      if (isHttpsPage(ctx) && r && r.ok === false) return warn('80 端口不可达，无法验证明文跳转（需确认 CDN/WAF 层是否统一跳转）');
      if (isHttpsPage(ctx) && r && r.redirected === false) return fail('HTTP 访问返回 ' + r.status + ' 而非跳转 HTTPS，明文通道仍然开放');
      if (!isHttpsPage(ctx)) return fail('站点为纯 HTTP 访问，不存在 HTTPS 跳转');
      return warn('跳转探测未完成');
    },
  },
  {
    id: 'T3', cat: 'transport', title: 'HSTS 响应头', severity: 'medium',
    cn: ['GB/T 22239-2019 安全通信网络'],
    intl: ['RFC 6797', 'OWASP Top 10:2021 A02', 'OWASP ASVS V14.4'],
    remediation: '添加 Strict-Transport-Security: max-age=31536000; includeSubDomains，验证无问题后可加入 preload 清单。',
    evaluate(ctx) {
      const v = hdr(ctx, 'strict-transport-security');
      if (!v) return fail('未配置 Strict-Transport-Security（HSTS）');
      const m = /max-age\s*=\s*(\d+)/i.exec(v);
      const maxAge = m ? parseInt(m[1], 10) : 0;
      const includeSub = /includeSubDomains/i.test(v);
      if (maxAge < 15552000) return warn('HSTS max-age=' + maxAge + ' 低于 180 天，保护窗口不足');
      if (!includeSub) return warn('HSTS 缺少 includeSubDomains，子域不受保护');
      return pass('HSTS 配置良好（max-age=' + maxAge + (includeSub ? '; includeSubDomains' : '') + (/preload/i.test(v) ? '; preload' : '') + '）');
    },
  },
  {
    id: 'T4', cat: 'transport', title: 'TLS 协议版本', severity: 'high',
    cn: ['GB/T 22239-2019 安全通信网络', '商用密码应用相关要求'],
    intl: ['OWASP Top 10:2021 A02', 'PCI DSS 4.0.1 Req.4.2.1', 'CIS v8.1 Control 4.2', 'NIST SP 800-53 SC-8'],
    remediation: '服务端仅开放 TLS 1.2 / TLS 1.3，禁用 SSLv3、TLS 1.0、TLS 1.1（Nginx: ssl_protocols TLSv1.2 TLSv1.3）。',
    evaluate(ctx) {
      if (!ctx.tls || !ctx.tls.reachable) return na('443 端口不可达，无法评估 TLS 协议');
      const p = ctx.tls.protocols || {};
      const legacy = [];
      if (p['TLSv1']) legacy.push('TLS 1.0');
      if (p['TLSv1.1']) legacy.push('TLS 1.1');
      const modern = p['TLSv1.2'] || p['TLSv1.3'];
      if (legacy.length) return fail('仍支持遗留协议：' + legacy.join('、') + '（存在 BEAST/POODLE 类降级与合规风险）');
      if (!modern) {
        if (ctx.tls.limited) return warn('现代协议支持情况未能确认（探测受本地 OpenSSL 限制或网络错误），建议用 testssl.sh / SSL Labs 交叉验证');
        return fail('未探测到 TLS 1.2/1.3 支持');
      }
      return pass('仅支持现代 TLS 协议（TLS 1.2：' + (p['TLSv1.2'] ? '是' : '否') + '，TLS 1.3：' + (p['TLSv1.3'] ? '是' : '否') + '）' + (ctx.tls.limited ? '；遗留协议探测受本地限制，仅供参考' : ''));
    },
  },
  {
    id: 'T5', cat: 'transport', title: '证书有效期', severity: 'high',
    cn: ['GB/T 22239-2019', 'CA/Browser Forum 基线要求'],
    intl: ['OWASP Top 10:2021 A02', 'CIS v8.1 Control 4.2'],
    remediation: '部署 ACME（如 certbot / acme.sh）自动续期，并对证书到期时间建立监控告警（提前 30 天）。',
    evaluate(ctx) {
      const cert = ctx.tls && ctx.tls.cert;
      if (!cert) return na('未获取到证书');
      if (cert.daysRemaining == null) return na('证书有效期无法解析');
      if (new Date(cert.validFrom) > new Date()) return fail('证书尚未生效（valid_from：' + cert.validFrom + '）');
      if (cert.daysRemaining < 0) return fail('证书已过期（valid_to：' + cert.validTo + '），浏览器将拦截访问');
      if (cert.daysRemaining <= 30) return warn('证书即将过期，剩余 ' + cert.daysRemaining + ' 天（' + cert.validTo + '）');
      return pass('证书有效，剩余 ' + cert.daysRemaining + ' 天（到期：' + cert.validTo + '）');
    },
  },
  {
    id: 'T6', cat: 'transport', title: '证书可信链 / 自签名', severity: 'high',
    cn: ['GB/T 22239-2019 安全通信网络'],
    intl: ['OWASP Top 10:2021 A02', 'PCI DSS 4.0.1 Req.4.2.1'],
    remediation: '使用公共信任 CA 签发的证书；内网系统使用企业 CA 并确保客户端信任分发到位。',
    evaluate(ctx) {
      if (!ctx.tls || !ctx.tls.reachable) return na('443 端口不可达');
      if (ctx.tls.trusted) {
        const issuer = ctx.tls.cert ? ctx.tls.cert.issuer.CN || JSON.stringify(ctx.tls.cert.issuer) : '';
        return pass('证书链可验证至受信任根（颁发者：' + issuer + '）');
      }
      const selfSigned = ctx.tls.cert && ctx.tls.cert.selfSigned;
      return fail('证书链不受信：' + (ctx.tls.trustError || '未知错误') + (selfSigned ? '（自签名证书）' : ''));
    },
  },
  {
    id: 'T7', cat: 'transport', title: '证书-域名匹配', severity: 'high',
    cn: ['GB/T 22239-2019', 'CA/Browser Forum 基线要求'],
    intl: ['CA/Browser Forum BR', 'OWASP Top 10:2021 A02'],
    remediation: '证书 SAN 覆盖全部业务域名（多域名证书或通配符证书），上线新域名前先确认证书覆盖。',
    evaluate(ctx) {
      const cert = ctx.tls && ctx.tls.cert;
      if (!cert) return na('未获取到证书');
      const names = cert.altNames.length ? cert.altNames : [cert.subject.CN].filter(Boolean);
      const hit = names.find((n) => hostMatch(n, ctx.hostname));
      if (hit) return pass('证书覆盖当前域名（' + hit + '，证书名称：' + names.slice(0, 4).join(', ') + '）');
      return fail('证书未覆盖当前域名 ' + ctx.hostname + '（证书名称：' + names.slice(0, 5).join(', ') + '）');
    },
  },
  {
    id: 'T8', cat: 'transport', title: '弱加密套件', severity: 'high',
    cn: ['GB/T 22239-2019 安全通信网络'],
    intl: ['OWASP Top 10:2021 A02', 'PCI DSS 4.0.1 Req.4.2.1', 'NIST SP 800-53 SC-13'],
    remediation: '禁用 RC4/3DES/NULL/EXPORT 等弱套件，按 Mozilla intermediate 指南或 GB/T 36844（SM2/SM3/SM4）配置密码套件顺序。',
    evaluate(ctx) {
      if (!ctx.tls || !ctx.tls.reachable) return na('443 端口不可达');
      if (ctx.tls.weakCiphers.length) return fail('可协商弱加密套件：' + ctx.tls.weakCiphers.join('、'));
      if (ctx.tls.limited) return warn('未探测到弱套件，但部分遗留套件受本地 OpenSSL 限制无法确认（建议用 testssl.sh / SSL Labs 交叉验证）');
      const neg = ctx.tls.negotiated && ctx.tls.negotiated.cipher ? ctx.tls.negotiated.cipher.name : '未知';
      return pass('未探测到 RC4/3DES/NULL/EXPORT 等弱套件（当前协商：' + neg + '）');
    },
  },
  {
    id: 'T9', cat: 'transport', title: '混合内容', severity: 'medium',
    cn: ['GB/T 22239-2019 安全通信网络'],
    intl: ['OWASP Top 10:2021 A02/A05', 'OWASP ASVS V9.2'],
    remediation: '全站子资源改用 https 或相对协议，并配置 CSP upgrade-insecure-requests 作为兜底。',
    evaluate(ctx) {
      if (!isHttpsPage(ctx)) return na('页面非 HTTPS，混合内容不适用');
      if (ctx.content.mixedActive.length) {
        return fail('HTTPS 页面引用 ' + ctx.content.mixedActive.length + ' 个 HTTP 活动资源（可被中间人篡改）：' + ctx.content.mixedActive.slice(0, 3).join('；'));
      }
      if (ctx.content.mixedPassive.length) return warn('HTTPS 页面引用 ' + ctx.content.mixedPassive.length + ' 个 HTTP 被动资源（图片/字体等）');
      return pass('未发现混合内容');
    },
  },

  /* ============ H 安全响应头 ============ */
  {
    id: 'H1', cat: 'headers', title: 'Content-Security-Policy', severity: 'high',
    cn: ['《网络安全法》第21条', 'GB/T 22239-2019 安全计算环境'],
    intl: ['OWASP Top 10:2021 A05', 'OWASP ASVS V5.3/V14.4', 'CIS v8.1 Control 16.10'],
    remediation: '部署严格 CSP：default-src \'self\'；script-src 使用 nonce/hash 替代 \'unsafe-inline\'；禁用 \'unsafe-eval\'；限制 frame-ancestors 与 object-src \'none\'。',
    evaluate(ctx) {
      const enforced = hdr(ctx, 'content-security-policy');
      const reportOnly = hdr(ctx, 'content-security-policy-report-only');
      if (!enforced && reportOnly) {
        return warn('仅配置了 Content-Security-Policy-Report-Only（仅监控不拦截，无实际防护）：' + String(reportOnly).slice(0, 120));
      }
      const csp = enforced || reportOnly;
      if (!csp) return fail('未配置 Content-Security-Policy');
      const dirs = parseCsp(csp);
      const def = dirs['default-src'] || [];
      const script = dirs['script-src'] || def;
      const bad = [];
      if (script.includes("'unsafe-inline'")) bad.push("script-src 含 'unsafe-inline'");
      if (script.includes("'unsafe-eval'")) bad.push("script-src 含 'unsafe-eval'");
      if (def.includes('*')) bad.push('default-src 含通配符 *');
      if (!dirs['default-src'] && !script.length) bad.push('未定义 default-src / script-src');
      if (bad.length) return warn('CSP 已配置但存在弱点：' + bad.join('；') + '（' + csp.slice(0, 120) + '）');
      return pass('CSP 配置合理（' + csp.slice(0, 120) + '）');
    },
  },
  {
    id: 'H2', cat: 'headers', title: '点击劫持防护', severity: 'medium',
    cn: ['GB/T 22239-2019 安全区域边界'],
    intl: ['OWASP Top 10:2021 A05', 'OWASP ASVS V14.4', 'RFC 7034'],
    remediation: '配置 X-Frame-Options: DENY（或 SAMEORIGIN），并优先使用 CSP frame-ancestors \'self\'。',
    evaluate(ctx) {
      const xfo = hdr(ctx, 'x-frame-options');
      const csp = hdr(ctx, 'content-security-policy');
      const fa = csp ? parseCsp(csp)['frame-ancestors'] || [] : [];
      if (fa.length && !fa.includes('*')) return pass('CSP frame-ancestors 已限制（' + fa.join(' ') + '）');
      if (xfo && /deny|sameorigin/i.test(xfo)) return pass('X-Frame-Options: ' + xfo);
      if (fa.includes('*')) return fail('CSP frame-ancestors 为通配符 *，等同未防护');
      return fail('未配置点击劫持防护（缺少 X-Frame-Options / CSP frame-ancestors）');
    },
  },
  {
    id: 'H3', cat: 'headers', title: 'X-Content-Type-Options', severity: 'medium',
    cn: ['GB/T 22239-2019'],
    intl: ['OWASP Top 10:2021 A05', 'OWASP ASVS V14.4'],
    remediation: '全站响应添加 X-Content-Type-Options: nosniff，防止 MIME 类型嗅探。',
    evaluate(ctx) {
      const v = hdr(ctx, 'x-content-type-options');
      if (v && /nosniff/i.test(v)) return pass('X-Content-Type-Options: nosniff');
      return fail('未配置 X-Content-Type-Options: nosniff');
    },
  },
  {
    id: 'H4', cat: 'headers', title: 'Referrer-Policy', severity: 'low',
    cn: ['GB/T 35273-2020（个人信息保护）'],
    intl: ['W3C Referrer-Policy', 'OWASP ASVS V14.4'],
    remediation: '配置 Referrer-Policy: strict-origin-when-cross-origin 或更严格策略，避免 URL 中的敏感参数外泄。',
    evaluate(ctx) {
      const v = hdr(ctx, 'referrer-policy');
      if (!v) return fail('未配置 Referrer-Policy');
      if (/unsafe-url/i.test(v)) return fail('Referrer-Policy: ' + v + '（unsafe-url 会完整泄露 URL）');
      return pass('Referrer-Policy: ' + v);
    },
  },
  {
    id: 'H5', cat: 'headers', title: 'Permissions-Policy', severity: 'low',
    cn: ['GB/T 35273-2020'],
    intl: ['W3C Permissions-Policy', 'OWASP ASVS V14.4'],
    remediation: '按业务最小化声明浏览器能力权限，如 Permissions-Policy: camera=(), microphone=(), geolocation=()。',
    evaluate(ctx) {
      const v = hdr(ctx, 'permissions-policy');
      if (!v) return warn('未配置 Permissions-Policy（敏感能力权限未显式收敛）');
      return pass('Permissions-Policy 已配置（' + v.slice(0, 100) + '）');
    },
  },
  {
    id: 'H6', cat: 'headers', title: 'X-XSS-Protection（提示级）', severity: 'info',
    cn: ['—'],
    intl: ['OWASP Top 10:2021 A05（遗留）'],
    remediation: '该响应头已被现代浏览器弃用，依赖 CSP 即可；如保留建议 1; mode=block。',
    evaluate(ctx) {
      const v = hdr(ctx, 'x-xss-protection');
      if (!v) return info('未配置 X-XSS-Protection（该头已弃用，不影响评分，防护依赖 CSP）');
      if (/^1\s*;\s*mode\s*=\s*block/i.test(v)) return info('X-XSS-Protection: ' + v + '（可保留，非必需）');
      if (/^0/i.test(v)) return info('X-XSS-Protection: 0（已显式关闭浏览器 XSS 过滤器）');
      return info('X-XSS-Protection: ' + v);
    },
  },
  {
    id: 'H7', cat: 'headers', title: '跨源隔离策略（COOP/CORP/COEP）', severity: 'low',
    cn: ['GB/T 22239-2019'],
    intl: ['OWASP Top 10:2021 A05', 'OWASP ASVS V14.4'],
    remediation: '按需配置 Cross-Origin-Opener-Policy: same-origin、Cross-Origin-Resource-Policy: same-origin。',
    evaluate(ctx) {
      const coop = hdr(ctx, 'cross-origin-opener-policy');
      const corp = hdr(ctx, 'cross-origin-resource-policy');
      const coep = hdr(ctx, 'cross-origin-embedder-policy');
      const found = [coop && 'COOP: ' + coop, corp && 'CORP: ' + corp, coep && 'COEP: ' + coep].filter(Boolean);
      if (found.length) return pass('跨源策略已配置（' + found.join('；') + '）');
      return warn('未配置 COOP/CORP/COEP（Spectre 类侧信道防护缺失）');
    },
  },
  {
    id: 'H8', cat: 'headers', title: '敏感响应缓存控制', severity: 'medium',
    cn: ['GB/T 22239-2019', 'GB/T 35273-2020'],
    intl: ['OWASP Top 10:2021 A05', 'OWASP ASVS V8.3', 'PCI DSS 4.0.1 Req.3'],
    remediation: '含会话 Cookie / 个人信息的响应设置 Cache-Control: no-store，并在 CDN 与代理层同步禁用缓存。',
    evaluate(ctx) {
      const cookies = cookiesOf(ctx);
      const cc = hdr(ctx, 'cache-control');
      if (cookies.length) {
        const loose = !cc || (/public|max-age|s-maxage/i.test(cc) && !/no-store|no-cache/i.test(cc));
        if (loose) return warn('响应包含 Set-Cookie 且缓存策略宽松（Cache-Control: ' + (cc || '未设置') + '），存在敏感信息被缓存风险');
        return pass('含会话 Cookie 的响应已禁用缓存（Cache-Control: ' + cc + '）');
      }
      return info('主页未设置 Cookie（Cache-Control: ' + (cc || '未设置') + '），敏感页面缓存策略需人工确认');
    },
  },

  /* ============ C Cookie 安全 ============ */
  {
    id: 'C1', cat: 'cookies', title: 'Cookie Secure 属性', severity: 'high',
    cn: ['GB/T 22239-2019', '《网络安全法》第21条'],
    intl: ['OWASP Top 10:2021 A05/A07', 'RFC 6265bis', 'PCI DSS 4.0.1 Req.6.4'],
    remediation: 'HTTPS 站点所有 Cookie 必须标记 Secure，杜绝明文传输。',
    evaluate(ctx) {
      const cookies = cookiesOf(ctx);
      if (!cookies.length) return na('未观察到 Set-Cookie');
      if (!isHttpsPage(ctx)) return na('页面非 HTTPS，Secure 属性不适用（本身即为更高风险）');
      const bad = cookies.filter((c) => !c.secure);
      if (bad.length) return fail('以下 Cookie 缺少 Secure 属性：' + bad.map((c) => c.name).join('、'));
      return pass('全部 ' + cookies.length + ' 个 Cookie 均带 Secure 属性');
    },
  },
  {
    id: 'C2', cat: 'cookies', title: 'Cookie HttpOnly 属性', severity: 'high',
    cn: ['GB/T 22239-2019 安全计算环境'],
    intl: ['OWASP Top 10:2021 A05', 'RFC 6265bis', 'OWASP ASVS V3.4'],
    remediation: '会话类 Cookie 一律标记 HttpOnly，阻断 XSS 后的会话窃取链。',
    evaluate(ctx) {
      const cookies = cookiesOf(ctx);
      if (!cookies.length) return na('未观察到 Set-Cookie');
      const sessionLike = cookies.filter((c) => /session|sess|sid|token|auth|login|phpsessid|jsessionid|user/i.test(c.name));
      const badSession = sessionLike.filter((c) => !c.httpOnly);
      const badOther = cookies.filter((c) => !c.httpOnly && !sessionLike.includes(c));
      if (badSession.length) return fail('会话类 Cookie 缺少 HttpOnly：' + badSession.map((c) => c.name).join('、'));
      if (badOther.length) return warn('以下非会话 Cookie 未标记 HttpOnly：' + badOther.map((c) => c.name).join('、'));
      return pass('全部 Cookie 均带 HttpOnly 属性');
    },
  },
  {
    id: 'C3', cat: 'cookies', title: 'Cookie SameSite 属性', severity: 'medium',
    cn: ['GB/T 22239-2019'],
    intl: ['OWASP Top 10:2021 A01', 'RFC 6265bis', 'OWASP ASVS V3.4'],
    remediation: '默认 SameSite=Lax，敏感操作用 Strict；跨站场景必须 SameSite=None; Secure。',
    evaluate(ctx) {
      const cookies = cookiesOf(ctx);
      if (!cookies.length) return na('未观察到 Set-Cookie');
      const none = cookies.filter((c) => c.sameSite && /none/i.test(c.sameSite) && !c.secure);
      if (none.length) return fail('以下 Cookie 为 SameSite=None 但缺少 Secure：' + none.map((c) => c.name).join('、'));
      const missing = cookies.filter((c) => !c.sameSite);
      if (missing.length) return warn('以下 Cookie 未显式设置 SameSite：' + missing.map((c) => c.name).join('、') + '（浏览器默认 Lax，建议显式声明）');
      return pass('全部 Cookie 均显式设置 SameSite（' + cookies.map((c) => c.name + '=' + c.sameSite).join('，') + '）');
    },
  },
  {
    id: 'C4', cat: 'cookies', title: 'Cookie 名称前缀（__Secure-/__Host-）', severity: 'low',
    cn: ['—'],
    intl: ['RFC 6265bis §5.5'],
    remediation: '敏感 Cookie 采用 __Secure- / __Host- 前缀，利用浏览器强制作安全属性。',
    evaluate(ctx) {
      const cookies = cookiesOf(ctx);
      if (!cookies.length) return na('未观察到 Set-Cookie');
      const sensitive = cookies.filter((c) => /session|sess|sid|token|auth/i.test(c.name));
      const noPrefix = sensitive.filter((c) => !c.hasPrefix);
      if (noPrefix.length) return info('敏感 Cookie 未使用 __Secure-/__Host- 前缀：' + noPrefix.map((c) => c.name).join('、'));
      return info('已使用 Cookie 前缀规范或无敏感命名 Cookie');
    },
  },

  /* ============ D 内容与代码安全 ============ */
  {
    id: 'D1', cat: 'content', title: 'CSRF 防护', severity: 'high',
    cn: ['GB/T 22239-2019 安全计算环境（访问控制）'],
    intl: ['OWASP Top 10:2021 A01', 'OWASP ASVS V4.2', 'PCI DSS 4.0.1 Req.6.4'],
    remediation: '所有状态变更接口启用 CSRF Token（同步器 / 加密令牌模式）+ SameSite Cookie + 关键操作二次确认。',
    evaluate(ctx) {
      const forms = ctx.content.forms;
      if (!forms.length) return na('未发现表单');
      const postForms = forms.filter((f) => f.method === 'post');
      if (!postForms.length) return info('未发现 POST 表单（' + forms.length + ' 个 GET 表单），GET 变更需人工复核');
      const noCsrf = postForms.filter((f) => !f.hasCsrf);
      if (noCsrf.length) return fail(noCsrf.length + '/' + postForms.length + ' 个 POST 表单未检测到 CSRF 令牌（首个 action：' + noCsrf[0].action + '）');
      return pass('全部 ' + postForms.length + ' 个 POST 表单均包含 CSRF 令牌');
    },
  },
  {
    id: 'D2', cat: 'content', title: '前端组件已知漏洞', severity: 'high',
    cn: ['GB/T 43698-2024 软件供应链安全要求'],
    intl: ['OWASP Top 10:2021 A06', 'OWASP ASVS V14.2/V10.3', 'CIS v8.1 Control 7', 'CWE-1104'],
    remediation: '建立前端 SCA 机制，将 jQuery/lodash/Bootstrap 等组件升级至修复版本以上，并纳入 CI 卡点。',
    evaluate(ctx) {
      const libs = ctx.libs || [];
      if (!libs.length) return na('未识别到已知前端组件（或脚本内容不可达）');
      const vuln = libs.filter((l) => l.vulnerable === true);
      const eol = libs.filter((l) => l.vulnerable === false && l.eol === true);
      const unknown = libs.filter((l) => l.vulnerable === null);
      if (vuln.length) {
        return fail('发现受影响组件：' + vuln.map((l) => l.lib + '@' + l.version + '（<' + l.below + '，' + l.cve + '：' + l.title + '）').join('；'));
      }
      if (eol.length) {
        return warn('组件版本已 EOL（无在维护的安全修复）：' + eol.map((l) => l.lib + '@' + l.version).join('、') + '，建议升级');
      }
      if (unknown.length) return warn('组件版本无法自动识别：' + unknown.map((l) => l.lib).join('、') + '，建议人工确认');
      return pass('已识别组件均在安全版本：' + libs.map((l) => l.lib + '@' + l.version).join('、'));
    },
  },
  {
    id: 'D3', cat: 'content', title: '子资源完整性（SRI）', severity: 'medium',
    cn: ['GB/T 43698-2024'],
    intl: ['OWASP Top 10:2021 A08', 'W3C SRI'],
    remediation: '外部 CDN 脚本添加 integrity（SRI）与 crossorigin 属性，防止 CDN 内容被篡改后注入。',
    evaluate(ctx) {
      const scripts = ctx.content.scripts || [];
      if (!scripts.length) return na('未发现外链脚本');
      let pageOrigin = '';
      try { pageOrigin = ctx.page.ok ? new URL(ctx.page.final.url).origin : new URL(ctx.url).origin; } catch (e) {}
      const external = scripts.filter((s) => {
        try { return new URL(s.src).origin !== pageOrigin; } catch (e) { return true; }
      });
      if (!external.length) return pass('脚本均为同源引用，无外部供应链暴露');
      const noSri = external.filter((s) => !s.integrity);
      if (noSri.length) return warn(noSri.length + '/' + external.length + ' 个外部脚本缺少 SRI：' + noSri.slice(0, 2).map((s) => s.src).join('；'));
      return pass('全部 ' + external.length + ' 个外部脚本均带 SRI 完整性校验');
    },
  },
  {
    id: 'D4', cat: 'content', title: '密码框 autocomplete', severity: 'low',
    cn: ['GB/T 35273-2020'],
    intl: ['OWASP Top 10:2021 A07', 'OWASP ASVS V2.1'],
    remediation: '登录 / 修改密码输入框设置 autocomplete="off" / "new-password" / "current-password"。',
    evaluate(ctx) {
      if (!ctx.content.passwordInputs) return na('未发现密码输入框');
      const bad = ctx.content.forms.filter((f) => f.passwordAutocompleteMissing);
      if (bad.length) return warn(bad.length + ' 个表单的密码输入框未设置 autocomplete 限制');
      return pass('密码输入框均已设置 autocomplete 限制');
    },
  },
  {
    id: 'D5', cat: 'content', title: 'HTML 注释敏感信息', severity: 'medium',
    cn: ['GB/T 22239-2019', '《数据安全法》第27条'],
    intl: ['OWASP Top 10:2021 A05', 'OWASP ASVS V14.4'],
    remediation: '生产构建剥离 HTML 注释与调试信息，扫描源码库中的硬编码密钥并轮换。',
    evaluate(ctx) {
      const comments = ctx.content.sensitiveComments || [];
      if (!comments.length) return pass('未发现含敏感信息的 HTML 注释');
      const strong = comments.filter((c) => c.strong);
      if (strong.length) return fail('发现 ' + strong.length + ' 处高危注释（含密钥/密码/内网 IP）：' + strong.slice(0, 2).map((c) => c.text.slice(0, 60)).join('；'));
      return warn('发现 ' + comments.length + ' 处疑似调试注释（TODO/FIXME 等）：' + comments.slice(0, 2).map((c) => c.text.slice(0, 60)).join('；'));
    },
  },
  {
    id: 'D6', cat: 'content', title: '内联脚本依赖', severity: 'low',
    cn: ['GB/T 22239-2019'],
    intl: ['OWASP Top 10:2021 A05', 'OWASP ASVS V5.3'],
    remediation: '脚本外联化 + nonce/hash 白名单，逐步收敛 unsafe-inline，提升 CSP 有效性。',
    evaluate(ctx) {
      const n = ctx.content.inlineHandlers || 0;
      if (n === 0) return pass('无内联事件处理器（有利于收紧 CSP）');
      if (n > 10) return warn('检测到 ' + n + ' 处内联事件处理器，CSP 难以收紧');
      return info('检测到 ' + n + ' 处内联事件处理器');
    },
  },
  {
    id: 'D7', cat: 'content', title: 'CMS 指纹与版本暴露', severity: 'medium',
    cn: ['GB/T 43698-2024'],
    intl: ['OWASP Top 10:2021 A06', 'CIS v8.1 Control 2.1'],
    remediation: '隐藏 CMS 版本信息，建立 CMS 核心与插件更新机制，必要时部署 WAF 虚拟补丁。',
    evaluate(ctx) {
      const parts = [];
      if (ctx.content.generator) parts.push('generator: ' + ctx.content.generator);
      if (ctx.content.cms && ctx.content.cms.length) parts.push('指纹: ' + ctx.content.cms.join('/'));
      if (parts.length) return warn('识别到 CMS / 框架信息（' + parts.join('，') + '），版本暴露会增加被定向利用风险');
      return pass('未发现明显 CMS 指纹');
    },
  },

  /* ============ E 信息泄露与暴露面 ============ */
  {
    id: 'E1', cat: 'exposure', title: '服务端版本泄露', severity: 'medium',
    cn: ['GB/T 22239-2019 安全区域边界'],
    intl: ['OWASP Top 10:2021 A05', 'CIS v8.1 Control 4.1'],
    remediation: 'Nginx: server_tokens off; Apache: ServerTokens Prod; 移除 X-Powered-By 头。',
    evaluate(ctx) {
      if (!ctx.page || !ctx.page.ok) return na('页面不可达');
      const server = ctx.page.final.headers['server'];
      const powered = ctx.page.final.headers['x-powered-by'];
      const leaks = [];
      if (server && /\d/.test(server)) leaks.push('Server: ' + server);
      if (powered) leaks.push('X-Powered-By: ' + powered);
      if (leaks.length) return warn('服务端版本信息泄露：' + leaks.join('；'));
      if (server || powered) return info('存在 Server/X-Powered-By 头但未含版本号');
      return pass('未发现 Server/X-Powered-By 版本泄露');
    },
  },
  {
    id: 'E2', cat: 'exposure', title: '敏感文件暴露', severity: 'high',
    cn: ['GB/T 22239-2019', '《数据安全法》第27条'],
    intl: ['OWASP Top 10:2021 A05/A01', 'CIS v8.1 Control 4.1'],
    remediation: '部署时排除 .git/.svn/.env 等文件，Web 层禁止访问隐藏文件与备份文件，CI 增加暴露面扫描。',
    evaluate(ctx) {
      if (!ctx.page || !ctx.page.ok) return na('页面不可达，无法探测');
      const found = (ctx.exposure && ctx.exposure.files) || [];
      if (found.length) return fail('发现公开可达的敏感文件：' + found.map((f) => f.path + '（' + f.label + '）').join('、'));
      return pass('未发现公开可达的敏感文件（已探测版本库/配置/状态页等常见路径）');
    },
  },
  {
    id: 'E3', cat: 'exposure', title: '目录列表', severity: 'high',
    cn: ['GB/T 22239-2019'],
    intl: ['OWASP Top 10:2021 A05', 'OWASP ASVS V14.4'],
    remediation: '关闭 autoindex / directory browsing，或在各目录放置空白 index.html。',
    evaluate(ctx) {
      const d = ctx.exposure && ctx.exposure.dirListing;
      if (d) return fail('根目录开启目录列表（Index of /），可被遍历文件');
      return pass('未发现目录列表');
    },
  },
  {
    id: 'E4', cat: 'exposure', title: 'robots.txt 检查', severity: 'low',
    cn: ['—'],
    intl: ['OWASP Top 10:2021 A05'],
    remediation: '敏感路径不写入 robots.txt（等同暴露入口），应以认证与访问控制收敛。',
    evaluate(ctx) {
      const r = ctx.exposure && ctx.exposure.robots;
      if (!r) return info('未发现 robots.txt');
      if (r.sensitive.length) return warn('robots.txt 暴露敏感路径：' + r.sensitive.slice(0, 5).join('、'));
      if (r.disallowAll) return info('robots.txt 全站禁止抓取（Disallow: /）');
      return pass('robots.txt 未暴露敏感路径');
    },  },
  {
    id: 'E5', cat: 'exposure', title: 'security.txt（RFC 9116）', severity: 'low',
    cn: ['—'],
    intl: ['RFC 9116', 'CISA 安全联系人建议'],
    remediation: '发布 /.well-known/security.txt，提供安全联系邮箱与漏洞披露政策，便于白帽子报告问题。',
    evaluate(ctx) {
      if (ctx.exposure && ctx.exposure.securityTxt) return pass('已发布 security.txt（' + ctx.exposure.securityTxtUrl + '）');
      return warn('未发现 security.txt（/.well-known/security.txt）');
    },
  },
  {
    id: 'E6', cat: 'exposure', title: '错误页信息泄露', severity: 'medium',
    cn: ['GB/T 22239-2019'],
    intl: ['OWASP Top 10:2021 A05', 'OWASP ASVS V7.4'],
    remediation: '统一错误页，生产环境关闭调试输出与详细堆栈。',
    evaluate(ctx) {
      const e = ctx.exposure && ctx.exposure.errorLeak;
      if (e) return fail('错误页泄露调试信息（' + e.path + ' → ' + e.status + '）：' + String(e.sample).slice(0, 100).replace(/\s+/g, ' '));
      return pass('错误页未泄露堆栈 / SQL 等调试信息');
    },
  },
  {
    id: 'E7', cat: 'exposure', title: 'HTTP 方法暴露', severity: 'medium',
    cn: ['GB/T 22239-2019 安全区域边界'],
    intl: ['OWASP Top 10:2021 A05', 'CIS v8.1 Control 4.1'],
    remediation: '禁用 TRACE（XST 风险），OPTIONS 仅暴露业务必需的方法白名单。',
    evaluate(ctx) {
      const t = ctx.exposure && ctx.exposure.trace;
      const o = ctx.exposure && ctx.exposure.options;
      if (t && t.enabled) return fail('TRACE 方法可用（存在 XST 跨站脚本追踪风险）');
      if (o && o.allow) {
        const methods = String(o.allow).toUpperCase();
        if (/\bTRACE\b/.test(methods)) return fail('Allow 头暴露 TRACE 方法');
        if (/\bPUT\b|\bDELETE\b/.test(methods)) return warn('Allow 头暴露写操作方法：' + o.allow);
      }
      return pass('未发现危险的 HTTP 方法暴露');
    },
  },

  /* ============ N DNS 与邮件安全 ============ */
  {
    id: 'N1', cat: 'dns', title: 'SPF 记录', severity: 'medium',
    cn: ['GB/T 22239-2019 安全区域边界'],
    intl: ['RFC 7208', 'OWASP Top 10:2021 A05', 'DMARC.org 指南'],
    remediation: '发布 v=spf1 记录并使用 -all 硬失败；注意 include 数量不超过 10 次查找限制。',
    evaluate(ctx) {
      const s = ctx.dns && ctx.dns.spf;
      const st = ctx.dns && ctx.dns.states && ctx.dns.states.spf;
      if (st === 'error') return na('SPF 查询失败（系统 DNS 与 DoH 均不可用），无法检测，请勿解读为未配置');
      if (!s) return fail('未发现 SPF 记录，域名可被伪造发信');
      if (s.mechanism === 'hard') return pass('SPF 记录存在且为 -all 硬失败');
      if (s.mechanism === 'none') return warn('SPF 记录缺少 all 机制（' + s.record.slice(0, 80) + '）');
      return warn('SPF 为 ' + s.mechanism + ' 机制（建议收紧至 -all）：' + s.record.slice(0, 80));
    },
  },
  {
    id: 'N2', cat: 'dns', title: 'DMARC 记录', severity: 'high',
    cn: ['GB/T 22239-2019', '《网络安全法》第21条'],
    intl: ['RFC 7489', 'OWASP Top 10:2021 A05'],
    remediation: '发布 DMARC 记录并逐步收紧至 p=reject，配置 rua/ruf 接收报告。',
    evaluate(ctx) {
      const d = ctx.dns && ctx.dns.dmarc;
      const st = ctx.dns && ctx.dns.states && ctx.dns.states.dmarc;
      if (st === 'error') return na('DMARC 查询失败（系统 DNS 与 DoH 均不可用），无法检测，请勿解读为未配置');
      if (!d) return fail('未发现 DMARC 记录（_dmarc.' + ((ctx.dns && ctx.dns.domain) || ctx.hostname) + '），品牌域名易被仿冒');
      if (d.policy === 'reject') return pass('DMARC p=reject（' + d.record.slice(0, 80) + '）');
      if (d.policy === 'quarantine') return warn('DMARC p=quarantine，建议最终收紧至 reject（' + d.record.slice(0, 80) + '）');
      return warn('DMARC p=none（仅监控模式，未提供实际防护）：' + d.record.slice(0, 80));
    },
  },
  {
    id: 'N3', cat: 'dns', title: 'DNSSEC', severity: 'medium',
    cn: ['GB/T 22239-2019'],
    intl: ['RFC 4033-4035', 'CIS v8.1 Control 4.4'],
    remediation: '在注册局与权威 DNS 双侧启用 DNSSEC 签名，防御 DNS 缓存投毒。',
    evaluate(ctx) {
      const d = ctx.dns && ctx.dns.dnssec;
      const st = ctx.dns && ctx.dns.states && ctx.dns.states.dnssec;
      if (d === true) return pass('检测到 DNSSEC 签名（DNSKEY 存在）');
      if (d === null) return na('DNSSEC 无法检测（DNSKEY 查询失败：' + (st === 'error' ? '系统 DNS 与 DoH 均不可用' : '解析器不支持') + '）');
      return warn('未检测到 DNSSEC 签名');
    },
  },
  {
    id: 'N4', cat: 'dns', title: 'CAA 记录', severity: 'low',
    cn: ['—'],
    intl: ['RFC 8659', 'CA/Browser Forum 基线要求'],
    remediation: '发布 CAA 记录限定可为本域名签发证书的 CA，防止误签 / 恶意签发的证书被滥用。',
    evaluate(ctx) {
      const c = ctx.dns && ctx.dns.caa;
      const st = ctx.dns && ctx.dns.states && ctx.dns.states.caa;
      if (st === 'error') return na('CAA 查询失败（系统 DNS 与 DoH 均不可用），无法检测');
      if (c && c.length) return pass('已配置 CAA（' + c.map((x) => x.issue || x.issuewild || '').filter(Boolean).slice(0, 3).join('，') + '）');
      return warn('未发现 CAA 记录');
    },
  },
  {
    id: 'N5', cat: 'dns', title: 'MX 记录', severity: 'info',
    cn: ['—'],
    intl: ['RFC 5321'],
    remediation: '业务域应具备 MX 记录并配套 SPF/DKIM/DMARC 邮件安全体系。',
    evaluate(ctx) {
      const mx = ctx.dns && ctx.dns.mx;
      const st = ctx.dns && ctx.dns.states && ctx.dns.states.mx;
      if (st === 'error') return na('MX 查询失败（系统 DNS 与 DoH 均不可用），无法检测');
      if (mx && mx.length) return info('已配置 MX（' + mx.slice(0, 3).map((m) => m.exchange).join('，') + '），需确认配套 DKIM（人工项）');
      return info('未配置 MX 记录（如该域不用于邮件则无碍）');
    },
  },

  /* ============ P 隐私与合规标识 ============ */
  {
    id: 'P1', cat: 'privacy', title: 'ICP 备案标识', severity: 'medium',
    cn: ['《互联网信息服务管理办法》', '工信部 ICP 备案管理要求'],
    intl: ['—'],
    remediation: '完成 ICP 备案（非经营性/经营性），并在网站首页页脚公示备案号。',
    evaluate(ctx) {
      if (ctx.content && ctx.content.icp) return pass('检测到 ICP 备案号：' + ctx.content.icp);
      // 中文站点判定看整个正文（备案号常在页脚，20KB 切片会漏）
      const body = ctx.page && ctx.page.ok ? ctx.page.final.body : '';
      const isChineseSite = ctx.hostname.endsWith('.cn') || /[\u4e00-\u9fa5]/.test(body);
      if (isChineseSite) return fail('未在页面中检测到 ICP 备案号（境内网站依法需备案并公示）');
      return na('非中文站点，ICP 备案不适用');
    },
  },
  {
    id: 'P2', cat: 'privacy', title: '隐私政策链接', severity: 'low',
    cn: ['《个人信息保护法》第17条', 'GB/T 35273-2020'],
    intl: ['GDPR Art.13/14'],
    remediation: '在显著位置公示隐私政策（处理目的、方式、种类、权利渠道），并保持版本更新。',
    evaluate(ctx) {
      if (ctx.content && ctx.content.privacyLink) return pass('检测到隐私政策入口');
      return warn('未检测到隐私政策 / 个人信息保护链接');
    },
  },
  {
    id: 'P3', cat: 'privacy', title: 'Cookie 同意机制（人工项）', severity: 'info',
    cn: ['《个人信息保护法》第13/14条', 'GB/T 35273-2020'],
    intl: ['GDPR Art.6/7', 'ePrivacy 指令'],
    remediation: '部署 Cookie 同意管理平台（CMP），提供拒绝与撤回同等等量便捷选项。',
    evaluate: () => info('需人工确认站点是否提供 Cookie 同意 / 管理机制（自动化无法可靠检测）'),
  },
];

module.exports = { CHECKS, CATEGORIES, SEV_WEIGHT, parseCookies, parseCsp, hostMatch };
