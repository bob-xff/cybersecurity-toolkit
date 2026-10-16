'use strict';
/* standards.js 纯函数边界回归测试 */
const path = require('path');
const src = require('fs').readFileSync(path.join(__dirname, '..', 'core', 'standards.js'), 'utf8');

// 从模块源码中提取内部函数做单测（不改变导出面）
function extractFn(name) {
  const m = new RegExp('function ' + name + '\\([\\s\\S]*?\\n}').exec(src);
  if (!m) throw new Error('fn not found: ' + name);
  // eslint-disable-next-line no-eval
  return eval('(' + m[0] + ')');
}
const parseCookies = extractFn('parseCookies');
const hostMatch = extractFn('hostMatch');
const parseCsp = extractFn('parseCsp');

let failed = 0;
function t(label, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failed++;
  console.log((ok ? 'PASS' : 'FAIL') + '  ' + label + (ok ? '' : '  期望 ' + JSON.stringify(expected) + ' 实际 ' + JSON.stringify(actual)));
}

/* ---- parseCookies ---- */
t('Path=/secure 不误判 Secure', parseCookies(['sid=1; Path=/secure; HttpOnly'])[0].secure, false);
t('真实 Secure 属性', parseCookies(['sid=1; Path=/; Secure; HttpOnly'])[0].secure, true);
t('Path=/httponly-guide 不误判 HttpOnly', parseCookies(['sid=1; Path=/httponly-guide'])[0].httpOnly, false);
t('真实 HttpOnly 属性', parseCookies(['sid=1; HttpOnly'])[0].httpOnly, true);
t('securepages 不误判 Secure', parseCookies(['sid=1; Path=/securepages'])[0].secure, false);
t('SameSite 解析', parseCookies(['sid=1; SameSite=Lax'])[0].sameSite, 'Lax');
t('__Secure- 前缀', parseCookies(['__Secure-sid=1; Secure'])[0].hasPrefix, true);
t('__Host- 前缀', parseCookies(['__Host-sid=1; Secure; Path=/'])[0].hasPrefix, true);
t('普通无前缀', parseCookies(['sid=1'])[0].hasPrefix, false);
t('无 = 的 cookie 名', parseCookies(['flag'])[0].name, 'flag');
t('空输入', parseCookies(null), []);

/* ---- hostMatch ---- */
t('通配符不含裸域', hostMatch('*.example.com', 'example.com'), false);
t('通配符含子域', hostMatch('*.example.com', 'www.example.com'), true);
t('通配符含多级子域', hostMatch('*.example.com', 'a.b.example.com'), true);
t('精确匹配', hostMatch('example.com', 'example.com'), true);
t('不同域不匹配', hostMatch('*.example.com', 'example.org'), false);
t('结尾点归一', hostMatch('example.com.', 'example.com'), true);
t('空前缀', hostMatch('*.', 'example.com'), false);

/* ---- parseCsp ---- */
const csp = parseCsp("default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'");
t('CSP default-src', csp['default-src'], ["'self'"]);
t('CSP script-src', csp['script-src'], ["'self'", 'https://cdn.example.com']);
t('CSP object-src', csp['object-src'], ["'none'"]);
t('CSP 大小写归一', parseCsp('Default-Src self')['default-src'], ['self']);
t('CSP 空值', parseCsp(null), {});

console.log(failed === 0 ? '\n全部通过' : '\n失败 ' + failed + ' 项');
process.exit(failed === 0 ? 0 : 1);
