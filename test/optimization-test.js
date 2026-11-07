'use strict';
/**
 * 优化轮回归测试（零依赖、不联网）
 * 覆盖：URL 边界、编码/压缩、HTML 内容分析误报漏报、
 *       前置条件守卫（没测≠通过）、探测基址、并发容错、错误模型、报告章节。
 * 运行: node test/optimization-test.js
 */
const zlib = require('zlib');
const { normalizeUrl, hostnameOf, mapLimit } = require('../core/util');
const { decodeBody, sniffCharset } = require('../core/fetcher');
const { analyzeContent } = require('../core/content');
const { prerequisite, PAGE_DEPENDENT, CONTENT_DEPENDENT, EXPOSURE_DEPENDENT } = require('../core/standards');
const { probeBaseOf, SENSITIVE_PATHS } = require('../core/exposure');
const { appError, CODES, withTimeout, normalizeError } = require('../core/errors');
const { buildMarkdown } = require('../core/report');
const CONFIG = require('../core/config');

let pass = 0, fail = 0;
function t(label, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) pass++; else fail++;
  console.log((ok ? 'PASS' : 'FAIL') + '  ' + label + (ok ? '' : '\n      期望 ' + JSON.stringify(expected) + '\n      实际 ' + JSON.stringify(actual)));
}
function ok(label, cond) { t(label, !!cond, true); }
function section(name) { console.log('\n--- ' + name + ' ---'); }

/* ============ 1. URL 归一化边界 ============ */
section('URL 归一化边界');
ok('空值抛错', (() => { try { normalizeUrl(''); return false; } catch (e) { return true; } })());
ok('控制字符被拒绝', (() => { try { normalizeUrl('https://a.com\nSet-Cookie: x'); return false; } catch (e) { return true; } })());
ok('超长 URL 被拒绝', (() => { try { normalizeUrl('https://a.com/' + 'x'.repeat(CONFIG.limits.maxUrlLength)); return false; } catch (e) { return true; } })());
ok('内嵌凭据被拒绝', (() => { try { normalizeUrl('https://user:pw@a.com'); return false; } catch (e) { return true; } })());
ok('javascript: 协议被拒绝', (() => { try { normalizeUrl('javascript:alert(1)'); return false; } catch (e) { return true; } })());
t('省略协议补 https', normalizeUrl('example.com/a').toString(), 'https://example.com/a');
t('包裹引号被剥离', normalizeUrl('"https://example.com/"').hostname, 'example.com');
t('末尾点归一', hostnameOf(normalizeUrl('https://Example.COM./')), 'example.com');
t('IPv6 去方括号', hostnameOf(normalizeUrl('http://[::1]:8080/')), '::1');

/* ============ 2. 解压 / 字符集 ============ */
section('解压与字符集');
const gz = zlib.gzipSync(Buffer.from('<html><body>你好</body></html>', 'utf8'));
t('gzip 解压', decodeBody(gz, 'gzip', 'text/html; charset=utf-8').text, '<html><body>你好</body></html>');
t('Content-Type 字符集', sniffCharset(Buffer.from('<html>'), 'text/html; charset=gbk'), 'gbk');
t('meta charset 推断', sniffCharset(Buffer.from('<html><head><meta charset="gb18030">'), 'text/html'), 'gb18030');
const gbkDecoded = decodeBody(Buffer.from('<p>' + Buffer.from('中文', 'utf8').toString() + '</p>'), '', 'text/html; charset=utf-8');
ok('utf-8 正常解码', gbkDecoded.text.includes('中文'));
// 压缩炸弹：解压后远超上限，应被截断而不是吃掉内存
// 必须超过 CONFIG.limits.maxDecompressed（默认 4MB）才会触发 zlib 的 maxOutputLength
const bomb = zlib.gzipSync(Buffer.alloc(CONFIG.limits.maxDecompressed + 1024 * 1024, 0x61));
const bombRes = decodeBody(bomb, 'gzip', 'text/html');
ok('超大解压体被标记截断', bombRes.truncatedByDecompression === true);
ok('超大解压体不返回完整文本', bombRes.text.length < CONFIG.limits.maxDecompressed);

/* ============ 3. 内容分析准确性 ============ */
section('内容分析：误报与漏报');
const withComment = analyzeContent(
  '<html><!-- <script src="http://evil/x.js"></script> onload=alert(1) --><script src="/real.js"></script><body>TODO: fix later</body></html>',
  'https://example.com/'
);
t('注释里的伪脚本不计入', withComment.scripts.length, 1);
t('真实脚本仍被识别', withComment.scripts[0].src, 'https://example.com/real.js');
t('注释里 onload 不计入内联处理器', withComment.inlineHandlers, 0);
t('单个 TODO 弱词不告警', withComment.sensitiveComments.length, 0);

const strongComment = analyzeContent('<!-- api_key = "sk-live-abcdef123456" -->', 'https://example.com/');
t('以注释开头的 HTML 仍被识别', strongComment.isHtml, true);
t('凭据赋值型注释判高危', strongComment.sensitiveComments.length && strongComment.sensitiveComments[0].strong === true, true);
const weakComment = analyzeContent('<!-- change password policy for users -->', 'https://example.com/');
t('普通 password 单词不判高危', weakComment.sensitiveComments.length, 0);
const longComment = analyzeContent('<!-- ' + 'x'.repeat(800) + ' api_key=abcdef123456 -->', 'https://example.com/');
t('长注释不再整体丢弃', longComment.sensitiveComments.length, 1);

const mixed = analyzeContent(
  '<a href="http://a.com/x">link</a><img src="http://a.com/i.png"><script src="http://a.com/s.js"></script>',
  'https://example.com/'
);
t('普通超链接不算混合内容', mixed.mixedPassive.length, 1);
t('脚本算主动混合内容', mixed.mixedActive.length, 1);
t('被动混合内容只剩图片', mixed.mixedPassive[0], 'http://a.com/i.png');

const notHtml = analyzeContent('{"status":"ok"}', 'https://example.com/', { contentType: 'application/json' });
t('JSON 响应标记非 HTML', notHtml.isHtml, false);
t('JSON 响应不解析出脚本', notHtml.scripts.length, 0);
const spa = analyzeContent('<html><script src="/vue.min.js"></script><div id="app"></div></html>', 'https://example.com/', { contentType: 'text/html' });
t('HTML 响应标记 isHtml', spa.isHtml, true);
ok('Vue 归入 frameworks', spa.frameworks.includes('Vue'));
t('Vue 不再被当成 CMS', spa.cms.length, 0);
const gen = analyzeContent('<meta content="WordPress 6.4" name="generator"><meta name=generator content=Drupal>', 'https://example.com/');
t('generator 属性顺序无关', gen.generator, 'WordPress 6.4');

/* ============ 4. 前置条件守卫（没测 ≠ 通过） ============ */
section('前置条件守卫');
const noPage = { page: { ok: false }, hostname: 'x.com', content: { isHtml: true }, exposure: { checked: SENSITIVE_PATHS.map((p) => ({ path: p.path })), failedRequests: 0, files: [] } };
t('页面不可达 → H1 记 na', prerequisite(noPage, 'H1').status, 'na');
t('页面不可达 → T1 仍可判定（报告不可达）', prerequisite(noPage, 'T1'), null);
t('页面不可达 → D5 记 na', prerequisite(noPage, 'D5').status, 'na');
t('页面可达且探测正常 → 不拦截', prerequisite(Object.assign({}, noPage, { page: { ok: true } }), 'H1'), null);
const nonHtml = { page: { ok: true }, content: { isHtml: false }, exposure: null, exposureDisabled: false };
t('非 HTML 响应 → D1 记 na', prerequisite(nonHtml, 'D1').status, 'na');
t('非 HTML 响应 → T4(TLS) 不拦截', prerequisite(nonHtml, 'T4'), null);
t('暴露面未完成 → E2 记 na', prerequisite(nonHtml, 'E2').status, 'na');
ok('E2 文案说明无法判定', /无法判定/.test(prerequisite(nonHtml, 'E2').evidence));
const disabled = Object.assign({}, nonHtml, { exposureDisabled: true });
ok('按设置关闭时文案含「不适用」', /不适用/.test(prerequisite(disabled, 'E2').evidence));
const allFailed = { page: { ok: true }, content: { isHtml: true }, exposure: { checked: [{ path: '/.env' }], failedRequests: 1, files: [] } };
t('暴露面请求全失败 → E2 记 na', prerequisite(allFailed, 'E2').status, 'na');
t('E2 在 EXPOSURE_DEPENDENT 中', EXPOSURE_DEPENDENT.has('E2'), true);
t('H1 在 PAGE_DEPENDENT 中', PAGE_DEPENDENT.has('H1'), true);
t('D1 在 CONTENT_DEPENDENT 中', CONTENT_DEPENDENT.has('D1'), true);

/* ============ 5. 暴露面基址 ============ */
section('暴露面探测基址');
t('根路径', probeBaseOf('https://example.com/'), 'https://example.com');
t('带文件名', probeBaseOf('https://example.com/app/page.html?q=1'), 'https://example.com/app');
t('子路径目录', probeBaseOf('https://example.com/app/sub/'), 'https://example.com/app/sub');
t('非默认端口', probeBaseOf('http://127.0.0.1:9911/'), 'http://127.0.0.1:9911');

/* ============ 6. 并发与错误模型 ============ */
section('并发容错与错误模型');
(async () => {
  const settled = await mapLimit([1, 2, 3], 2, async (n) => {
    if (n === 2) throw new Error('boom');
    return n * 10;
  }, { settle: true });
  t('settle 模式保留其它结果', settled[0], 10);
  t('settle 模式把异常转成标准错误', settled[1].code, CODES.INTERNAL);
  t('settle 模式第三项正常', settled[2], 30);
  let rejected = false;
  try { await mapLimit([1], 1, async () => { throw new Error('x'); }); } catch (e) { rejected = true; }
  t('默认模式仍向外抛错（向后兼容）', rejected, true);

  const timedOut = await withTimeout(new Promise(() => {}), 20, CODES.TIMEOUT, '超时了');
  t('withTimeout 返回标准错误对象', timedOut.code, CODES.TIMEOUT);
  t('withTimeout 文案', timedOut.message, '超时了');
  const err = appError(CODES.FETCH_FAIL, '请求失败', new Error('ECONNRESET'));
  t('appError 结构', [err.code, err.message, err.cause], [CODES.FETCH_FAIL, '请求失败', 'ECONNRESET']);
  ok('normalizeError 不抛错', typeof normalizeError(new Error('x')).message === 'string');

  /* ============ 7. 报告章节 ============ */
  section('报告章节');
  const md = buildMarkdown({
    ok: true, toolVersion: '1.0.0', score: 70, level: { grade: 'C', label: '合格' },
    target: { url: 'https://example.com', hostname: 'example.com' },
    startedAt: new Date().toISOString(), durationMs: 1234,
    warnings: [], categories: [], checks: [],
    tls: { reachable: true, port: 443, protocols: {}, cert: {}, notes: [] },
    dns: { domain: 'example.com', states: {}, doh: false },
    tech: { cms: [], frameworks: ['Vue'], isHtml: true, charset: 'utf-8', scriptCount: 1, libs: [] },
    exposure: { enabled: true, checkedFiles: 9, failedRequests: 2, foundFiles: [] },
    performance: { pageMs: 100, probesMs: 800, checksMs: 5, tlsMs: 300, exposureMs: 400 },
  });
  ok('报告含 6.2 前端框架', md.includes('前端框架：Vue'));
  ok('报告含 6.5 检测范围与耗时', md.includes('### 6.5 检测范围与耗时'));
  ok('报告含并行探测耗时', md.includes('五路并行探测 | 800 ms'));
  ok('报告含失败请求说明', md.includes('失败请求：2 条'));
  ok('报告含「无法检测≠通过」声明', md.includes('「无法检测 / 不适用」与「通过」严格区分'));
  ok('报告含 DNSSEC 局限', md.includes('未验证 DS 信任链'));

  console.log('\n----------------------------------------');
  console.log('通过 ' + pass + ' / 失败 ' + fail);
  process.exit(fail === 0 ? 0 : 1);
})();
