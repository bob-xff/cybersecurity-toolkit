'use strict';

/**
 * HTML 内容分析：脚本/表单/混合内容/注释/CMS 指纹/ICP/隐私政策
 */
const { URL } = require('url');

const CMS_SIGNATURES = [
  { name: 'WordPress', re: /wp-content|wp-includes|wordpress/i },
  { name: 'Joomla', re: /joomla|\/media\/jui/i },
  { name: 'Drupal', re: /drupal|\/sites\/default\/files/i },
  { name: 'Discuz!', re: /discuz|forum\.php\?mod=/i },
  { name: 'phpCMS', re: /phpcms/i },
  { name: 'ThinkPHP', re: /thinkphp/i },
  { name: 'Vue', re: /vue(?:\.runtime)?(?:\.min)?\.js|data-v-[0-9a-f]{8}/i },
  { name: 'React', re: /react(?:\.production\.min)?\.js|data-reactroot/i },
];

/* 强特征：密钥/密码类字样 + 内网 IP（公网 IP 出现在注释里很常见，只算弱特征） */
const SENS_STRONG = /password|passwd|pwd|api[_-]?key|secret|private[_-]?key|access[_-]?key|(?:10\.\d{1,3}\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.\d{1,3}\.)\d{1,3}\.\d{1,3}/i;
const SENS_WEAK = /todo|fixme|xxx|hack|debug|temp|internal|admin|(?:\d{1,3}\.){3}\d{1,3}/i;

function analyzeContent(html, baseUrl) {
  const out = {
    scripts: [],
    inlineScripts: 0,
    forms: [],
    mixedActive: [],
    mixedPassive: [],
    sensitiveComments: [],
    inlineHandlers: 0,
    generator: null,
    cms: [],
    icp: null,
    privacyLink: false,
    passwordInputs: 0,
  };
  if (!html) return out;
  const htmlStr = String(html);

  // 脚本（src / inline）
  const scriptRe = /<script\b([^>]*)>/gi;
  let m;
  while ((m = scriptRe.exec(htmlStr))) {
    const attrs = m[1] || '';
    const srcM = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(attrs);
    if (srcM) {
      let abs = srcM[1];
      try { abs = new URL(srcM[1], baseUrl).toString(); } catch (e) {}
      out.scripts.push({
        src: abs,
        integrity: /\bintegrity\s*=/i.test(attrs),
        crossorigin: /\bcrossorigin\s*=/i.test(attrs),
      });
    } else {
      out.inlineScripts++;
    }
  }

  // 内联事件处理器
  out.inlineHandlers = (htmlStr.match(/<[a-zA-Z][^>]*\son[a-z]+\s*=/gi) || []).length;

  // 表单
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  while ((m = formRe.exec(htmlStr))) {
    const attrs = m[1] || '';
    const inner = m[2] || '';
    const action = (/\baction\s*=\s*["']([^"']*)["']/i.exec(attrs) || [])[1] || '';
    const method = (/\bmethod\s*=\s*["']?(\w+)/i.exec(attrs) || [])[1] || 'get';
    let absAction = action;
    try { absAction = action ? new URL(action, baseUrl).toString() : baseUrl; } catch (e) {}
    const inputRe = /<input\b([^>]*)>/gi;
    let im;
    const inputAttrs = [];
    while ((im = inputRe.exec(inner))) inputAttrs.push(im[1]);
    const hiddenNames = inputAttrs
      .filter((a) => /\btype\s*=\s*["']?hidden/i.test(a))
      .map((a) => (/\bname\s*=\s*["']([^"']*)["']/i.exec(a) || [])[1] || '')
      .filter(Boolean);
    const hasCsrf =
      hiddenNames.some((n) => /csrf|token|_token|nonce|authenticity/i.test(n)) ||
      /name\s*=\s*["'][^"']*(csrf|token|nonce|authenticity)[^"']*["']/i.test(inner);
    const pwdInput = /<input\b[^>]*type\s*=\s*["']?password[^>]*>/i.exec(inner);
    const pwdAutocompleteMissing = pwdInput
      ? !/autocomplete\s*=\s*["']?(off|new-password|current-password)/i.test(pwdInput[0])
      : null;
    out.forms.push({
      action: absAction,
      method: String(method).toLowerCase(),
      hasCsrf,
      passwordAutocompleteMissing: pwdAutocompleteMissing,
      overHttp: /^http:/i.test(absAction),
    });
  }

  out.passwordInputs = (htmlStr.match(/<input\b[^>]*type\s*=\s*["']?password/gi) || []).length;

  // 混合内容
  if (/^https:/i.test(baseUrl || '')) {
    const urlAttrRe = /\b(?:src|href|action|data)\s*=\s*["'](http:\/\/[^"']+)["']/gi;
    while ((m = urlAttrRe.exec(htmlStr))) {
      const u = m[1];
      let tag = '';
      try {
        const tagRe = new RegExp('<[a-zA-Z][^>]*' + u.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
        const tagM = tagRe.exec(htmlStr);
        tag = tagM ? tagM[0].toLowerCase() : '';
      } catch (e) {}
      const isActive = /<(?:script|iframe|link|style|form)\b/i.test(tag) || /rel\s*=\s*["']?stylesheet/i.test(tag);
      (isActive ? out.mixedActive : out.mixedPassive).push(u);
    }
  }

  // HTML 注释
  const commentRe = /<!--([\s\S]*?)-->/g;
  while ((m = commentRe.exec(htmlStr))) {
    const c = m[1].trim();
    if (!c || c.length > 500) continue;
    if (SENS_STRONG.test(c) || SENS_WEAK.test(c)) {
      out.sensitiveComments.push({ text: c, strong: SENS_STRONG.test(c) });
    }
  }

  // CMS 指纹
  for (const sig of CMS_SIGNATURES) {
    if (sig.re.test(htmlStr.slice(0, 200000))) out.cms.push(sig.name);
  }

  // generator meta（HTML 属性顺序任意，逐标签解析而非固定顺序正则）
  const metaTags = htmlStr.match(/<meta\b[^>]*>/gi) || [];
  for (const tag of metaTags) {
    if (!/\bname\s*=\s*["']generator["']/i.test(tag)) continue;
    const c = /\bcontent\s*=\s*["']([^"']*)["']/i.exec(tag);
    if (c && c[1].trim()) { out.generator = c[1].trim(); break; }
  }

  // ICP 备案号
  const icpM = /ICP备\s*\d{5,}\s*号/i.exec(htmlStr) || /icp\.?\s*\d{5,}\s*号/i.exec(htmlStr);
  out.icp = icpM ? icpM[0].replace(/\s+/g, '') : null;

  // 隐私政策入口
  out.privacyLink =
    /href\s*=\s*["'][^"']*(?:privacy|隐私|个人信息保护)[^"']*["']/i.test(htmlStr) ||
    /<a\b[^>]*>[^<]*(?:隐私政策|个人信息保护|privacy policy)[^<]*<\/a>/i.test(htmlStr);

  return out;
}

module.exports = { analyzeContent };
