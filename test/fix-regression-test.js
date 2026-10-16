'use strict';
/* 本轮修复的针对性回归：
 *  - libcheck 别名识别（angular.min.js / angular-1.8.0.min.js / 不误伤 angular-ui-router）
 *  - 压缩版 angular banner 版本识别
 *  - exposure 确认正则收紧（.env 大写属性不误报、nginx 关键词不误报）
 */
const { detectFromUrl, detectFromContent } = require('../core/libcheck');
const { SENSITIVE_PATHS } = require('../core/exposure');

let bad = 0;
const t = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) bad++;
  console.log((ok ? 'PASS' : 'FAIL') + '  ' + label + ' => ' + JSON.stringify(got) + (ok ? '' : '（期望 ' + JSON.stringify(want) + '）'));
};

/* ---- URL 识别 ---- */
t('angular.min.js 可识别（无版本）', detectFromUrl('https://cdn.example.com/js/angular.min.js'), { lib: 'angularjs', version: null, via: 'url' });
t('angular-1.8.0.min.js 版本提取', detectFromUrl('https://cdn.example.com/js/angular-1.8.0.min.js'), { lib: 'angularjs', version: '1.8.0', via: 'url' });
t('angular-ui-router 不误伤', detectFromUrl('https://cdn.example.com/js/angular-ui-router.min.js'), null);
t('jquery 路径版本', detectFromUrl('https://cdn.example.com/ajax/libs/jquery/3.5.1/jquery.min.js'), { lib: 'jquery', version: '3.5.1', via: 'url' });
t('jquery-ui 最长优先', detectFromUrl('https://cdn.example.com/ajax/libs/jquery-ui/1.12.1/jquery-ui.min.js'), { lib: 'jquery-ui', version: '1.12.1', via: 'url' });
t('127.0.0.1 不当版本号', detectFromUrl('http://127.0.0.1:8080/js/jquery.js'), { lib: 'jquery', version: null, via: 'url' });
t('jquerymigrate 不误伤', detectFromUrl('https://cdn.example.com/js/jquerymigrate-3.4.0.min.js'), null);

/* ---- 内容识别：压缩版 angular banner ---- */
const mini = 'var v={full:"1.7.8",major:1,minor:7,dot:0,codeName:"x"};angular.module("ng",[]);';
t('压缩版 angular banner', detectFromContent(mini), { lib: 'angularjs', version: '1.7.8', via: 'content' });

/* ---- exposure 确认正则 ---- */
const env = SENSITIVE_PATHS.find((p) => p.path === '/.env');
const ngx = SENSITIVE_PATHS.find((p) => p.path === '/nginx_status');
const ap = SENSITIVE_PATHS.find((p) => p.path === '/server-status');
t('真 .env 命中', env.confirm.test('DB_PASSWORD=secret123'), true);
t('大写 HTML 属性不命中', env.confirm.test('<INPUT TYPE="TEXT">'), false);
t('普通 HTML 不命中', env.confirm.test('<html><body>hello</body></html>'), false);
t('nginx 关键词不误报', ngx.confirm.test('we use nginx server for hosting'), false);
t('nginx_status 真状态页命中', ngx.confirm.test('Active connections: 291 '), true);
t('server-status 误报收敛', ap.confirm.test('our Server Version is great'), false);
t('server-status 真页命中', ap.confirm.test('<h1>Apache Server Status</h1>'), true);

console.log(bad === 0 ? '\n全部通过' : '\n失败 ' + bad + ' 项');
process.exit(bad === 0 ? 0 : 1);
