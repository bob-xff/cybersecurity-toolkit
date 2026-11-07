'use strict';

/**
 * HTML 内容分析：脚本/表单/混合内容/注释/CMS 指纹/ICP/隐私政策
 *
 * 准确性要点：
 *  1. 标签解析前先剥离 HTML 注释，避免注释里的 `<script>` / `onload=` 被当成真实代码（误报）。
 *  2. 混合内容按「标签→属性」单次遍历判定，不再对每个 URL 重扫全文（原实现 O(n²)，
 *     且通用 data 属性会把 JSON 里的 http 链接误判为混合内容）。
 *  3. 敏感注释区分「赋值型凭据」与「普通 TODO」，弱特征需多信号命中，长注释做分段而非整体丢弃。
 *  4. 区分 CMS 与前端框架；标记响应是否真的是 HTML，供引擎把内容类检查降级为不适用。
 */
const { URL } = require('url');
const CONFIG = require('./config');

const CMS_SIGNATURES = [
  { name: 'WordPress', re: /wp-content|wp-includes|wordpress/i },
  { name: 'Joomla', re: /joomla|\/media\/jui/i },
  { name: 'Drupal', re: /drupal|\/sites\/default\/files/i },
  { name: 'Discuz!', re: /discuz|forum\.php\?mod=/i },
  { name: 'phpCMS', re: /phpcms/i },
  { name: 'ThinkPHP', re: /thinkphp/i },
];
/* 前端框架不是 CMS，单独归类，避免「检测到 CMS: Vue」这类分类错误 */
const FRAMEWORK_SIGNATURES = [
  { name: 'Vue', re: /vue(?:\.runtime)?(?:\.min)?\.js|data-v-[0-9a-f]{8}/i },
  { name: 'React', re: /react(?:dom)?(?:\.production\.min)?\.js|data-reactroot/i },
  { name: 'Angular', re: /angular(?:\.min)?\.js|ng-version=/i },
];

/* 强特征：必须是「凭据赋值」或 PEM 私钥头或完整内网 IP；
 * 单独出现 password / key 这类词（如「修改密码的说明」）不再算高危。 */
const CREDENTIAL_ASSIGN = /(?:password|passwd|pwd|api[_-]?key|secret|private[_-]?key|access[_-]?key|token|access[_-]?token)\s*[:=]\s*["']?[^\s"'<>,;]{4,}/i;
const PRIVATE_KEY_HEAD = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/;
const INTERNAL_IP = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;
/* 弱特征：至少命中 2 个不同关键词才提示，避免单个 TODO / admin 单词刷警告 */
const WEAK_WORDS = /\b(?:todo|fixme|xxx|hack|debug|temp|internal|staging|admin|backdoor)\b/gi;

function analyzeContent(html, baseUrl, options = {}) {
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
    frameworks: [],
    icp: null,
    privacyLink: false,
    passwordInputs: 0,
    isHtml: true,
    contentType: String(options.contentType || ''),
    scanLimited: false,
  };
  if (!html) return out;
  const htmlStr = String(html);

  /* 响应是否真是 HTML：JSON / 纯文本 / 图片响应不应进入内容类检查 */
  const ct = out.contentType.toLowerCase();
  const head = htmlStr.slice(0, 512);
  // 页面以 HTML 注释开头很常见（条件注释 / 构建注入），必须算 HTML；
  // 否则会把整页误判为「非 HTML 文档」并跳过全部内容类检查（严重漏报）。
  // 只要头部出现任意标签即视为标记文档；JSON / 数组字面量由 looksJson 排除。
  // 不要求「以特定标签开头」——页面片段、注释开头、条件注释都应当被正常分析。
  // 只要求「以 < 开头」或「出现标签」：长注释可能到 512 字之后才闭合，
  // 若要求 head 内出现完整 `>...>`，会把这类页面误判成非 HTML。
  const looksHtml = /^\s*</.test(head) || /<[a-zA-Z!][^>]*>/.test(head);
  const looksJson = /^\s*[\[{]/.test(head);
  const ctIsMarkup = /html|xml/i.test(ct);
  out.isHtml = ctIsMarkup ? !looksJson : (looksHtml && !looksJson);
  if (!out.isHtml) return out;

  // 注释单独分析，标签解析用「注释已剥离」的副本
  const comments = [];
  const clean = htmlStr.replace(/<!--([\s\S]*?)-->/g, (all, inner) => {
    comments.push(inner);
    return ' '.repeat(Math.min(all.length, 64)); // 不保留内容，避免二次匹配
  });
  const tagSource = clean.length > CONFIG.limits.maxContentScan ? clean.slice(0, CONFIG.limits.maxContentScan) : clean;
  if (clean.length > CONFIG.limits.maxContentScan) out.scanLimited = true;

  /* 一次性收集所有开标签：后续脚本/表单/混合内容/元信息都复用它，避免多次全文正则 */
  const tags = tagSource.match(/<[a-zA-Z][^>]*>/g) || [];
  const RESOURCE_ATTRS = /\b(src|href|action|formaction|poster|data-src|srcset)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  const ACTIVE_TAG = /^<(?:script|iframe|link|style|form|object|embed|video|audio)\b/i;

  // 脚本（src / inline）
  const scriptTags = [...tags].filter((t) => /^<script\b/i.test(t));
  for (const tag of scriptTags) {
    const attrs = tag.replace(/^<script\b/i, '').replace(/>$/, '');
    const srcM = /\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
    if (srcM) {
      const raw = srcM[1] || srcM[2] || srcM[3] || '';
      let abs = raw;
      try { abs = new URL(raw, baseUrl).toString(); } catch (e) { /* 保留原值 */ }
      out.scripts.push({
        src: abs,
        integrity: /\bintegrity\s*=/i.test(attrs),
        crossorigin: /\bcrossorigin\s*=/i.test(attrs),
      });
    } else {
      out.inlineScripts++;
    }
  }

  // 内联事件处理器（只统计真实标签，注释已剥离）
  for (const tag of tags) {
    const m = tag.match(/\son[a-z]+\s*=/gi);
    if (m) out.inlineHandlers += m.length;
  }

  // 表单：按 <form …>…</form> 配对，属性含 > 的极端情况用标签扫描降级
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(tagSource))) {
    const attrs = fm[1] || '';
    const inner = fm[2] || '';
    const action = (/\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs) || []).slice(1).find(Boolean) || '';
    const method = (/\bmethod\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs) || []).slice(1).find(Boolean) || 'get';
    let absAction = baseUrl;
    try { absAction = action ? new URL(action, baseUrl).toString() : baseUrl; } catch (e) { /* 保留默认 */ }
    const inputTags = inner.match(/<input\b[^>]*>/gi) || [];
    const hiddenNames = inputTags
      .filter((a) => /\btype\s*=\s*["']?hidden/i.test(a))
      .map((a) => (/\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(a) || []).slice(1).find(Boolean) || '')
      .filter(Boolean);
    const hasCsrf =
      hiddenNames.some((n) => /csrf|token|_token|nonce|authenticity/i.test(n)) ||
      /name\s*=\s*["'][^"']*(csrf|token|nonce|authenticity)[^"']*["']/i.test(inner);
    const pwdTag = inputTags.find((t) => /^<input\b[^>]*\btype\s*=\s*["']?password/i.test(t));
    const pwdAutocompleteMissing = pwdTag
      ? !/autocomplete\s*=\s*["']?(off|new-password|current-password)/i.test(pwdTag)
      : null;
    out.forms.push({
      action: absAction,
      method: String(method).toLowerCase(),
      hasCsrf,
      passwordAutocompleteMissing: pwdAutocompleteMissing,
      overHttp: /^http:/i.test(absAction),
    });
  }
  out.passwordInputs = tags.filter((t) => /^<input\b[^>]*\btype\s*=\s*["']?password/i.test(t)).length;

  // 混合内容：单次遍历标签+属性，按标签类型区分主动/被动，排除通用 data 属性误报
  if (/^https:/i.test(baseUrl || '')) {
    for (const tag of tags) {
      RESOURCE_ATTRS.lastIndex = 0;
      let am;
      const active = ACTIVE_TAG.test(tag) || /<link\b[^>]*\brel\s*=\s*["']?stylesheet/i.test(tag);
      while ((am = RESOURCE_ATTRS.exec(tag))) {
        const value = am[2] || am[3] || am[4] || '';
        if (!/^http:\/\//i.test(value.trim())) continue;
        const attr = am[1].toLowerCase();
        // 普通超链接指向 http 不属于混合内容（浏览器不会拦截），排除以消除误报
        if (attr === 'href' && /^<a\b/i.test(tag)) continue;
        // src/href 仅在主动标签算主动；img/source 等属被动
        const isActive = active || /\b(?:data-src|srcset)\b/.test(attr);
        (isActive ? out.mixedActive : out.mixedPassive).push(value.trim());
      }
    }
  }

  // HTML 注释：强特征需「赋值凭据 / 私钥 / 内网 IP」，弱特征需多信号
  for (const raw of comments) {
    const full = String(raw).trim();
    if (!full) continue;
    // 长注释不再整体跳过（此前 >500 字直接丢弃，反而漏掉藏在长注释里的密钥）
    const c = full.length > CONFIG.limits.maxCommentLength ? full.slice(0, CONFIG.limits.maxCommentLength) : full;
    const strong = CREDENTIAL_ASSIGN.test(c) || PRIVATE_KEY_HEAD.test(c) || INTERNAL_IP.test(c);
    const weakHits = new Set((c.match(WEAK_WORDS) || []).map((w) => w.toLowerCase()));
    const weak = !strong && weakHits.size >= 2;
    if (strong || weak) out.sensitiveComments.push({ text: c.slice(0, 300), strong, weakSignals: weakHits.size });
  }

  // CMS / 框架指纹：全文只切片一次
  const scan = htmlStr.slice(0, 200000);
  for (const sig of CMS_SIGNATURES) if (sig.re.test(scan)) out.cms.push(sig.name);
  for (const sig of FRAMEWORK_SIGNATURES) if (sig.re.test(scan)) out.frameworks.push(sig.name);

  // generator meta（属性顺序任意，且支持无引号值）
  for (const tag of tags) {
    if (!/^<meta\b/i.test(tag)) continue;
    if (!/\bname\s*=\s*(?:"generator"|'generator'|generator\b)/i.test(tag)) continue;
    const c = /\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag);
    const value = (c && (c[1] || c[2] || c[3]) || '').trim();
    if (value) { out.generator = value.slice(0, 200); break; }
  }

  // ICP 备案号：覆盖「京ICP备…号」「粤ICP备…号-1」与「ICP证」两类
  const icpM = /(?:[\u4e00-\u9fa5]?ICP备\s*\d{5,}\s*号(?:-\d+)?)|(?:ICP证\s*\d{5,}\s*号)/i.exec(htmlStr);
  out.icp = icpM ? icpM[0].replace(/\s+/g, '') : null;

  // 隐私政策入口
  out.privacyLink =
    /href\s*=\s*["'][^"']*(?:privacy|隐私|个人信息保护)[^"']*["']/i.test(htmlStr) ||
    /<a\b[^>]*>[^<]*(?:隐私政策|个人信息保护|privacy policy)[^<]*<\/a>/i.test(htmlStr);

  return out;
}

module.exports = { analyzeContent };
