#!/usr/bin/env node
'use strict';

/**
 * 第三轮深度自查的针对性回归测试
 *   node test/round3-fix-test.js
 *
 * 覆盖本轮的每一处修复，其中「重定向」「抓取悬挂兜底」「高级选项透传」
 * 都起真实本地 HTTP 服务实测，不依赖公网。
 */
const http = require('http');
const assert = require('assert');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const { fetchPage, rawRequest } = require(path.join(ROOT, 'core', 'fetcher'));
const { analyzeContent } = require(path.join(ROOT, 'core', 'content'));
const { unquoteTxt, registrableDomain } = require(path.join(ROOT, 'core', 'dnschk'));
const { assess } = require(path.join(ROOT, 'core', 'engine'));

let pass = 0;
let fail = 0;
function check(name, fn) {
  try { fn(); console.log('  PASS  ' + name); pass++; }
  catch (e) { console.log('  FAIL  ' + name + '  :: ' + e.message); fail++; }
}
async function checkAsync(name, fn) {
  try { await fn(); console.log('  PASS  ' + name); pass++; }
  catch (e) { console.log('  FAIL  ' + name + '  :: ' + e.message); fail++; }
}

/* ---------- 测试用本地服务 ---------- */
function startServer() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const u = req.url;
      if (u === '/ok') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<!doctype html><html><head>' +
          '<meta content="WordPress 6.5.2" name="generator">' +
          '</head><body>ok</body></html>');
        return;
      }
      if (u === '/gen-name-first') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><head><meta name="generator" content="Drupal 10"></head><body>x</body></html>');
        return;
      }
      if (u === '/r1') { res.writeHead(302, { Location: '/r2' }); res.end(); return; }
      if (u === '/r2') { res.writeHead(301, { Location: '/ok' }); res.end(); return; }
      if (u === '/loop') { res.writeHead(302, { Location: '/loop' }); res.end(); return; }
      if (u === '/forever') { res.writeHead(302, { Location: '/forever-' + Math.random() }); res.end(); return; }
      if (u.startsWith('/forever-')) { res.writeHead(302, { Location: '/forever-' + Math.random() }); res.end(); return; }
      if (u === '/hang') { /* 故意不响应，测试兜底超时 */ return; }
      res.writeHead(404); res.end('nope');
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port }));
  });
}

(async function main() {
  const { srv, port } = await startServer();
  const base = 'http://127.0.0.1:' + port;

  console.log('\n=== A. fetchPage 重定向逻辑（此前的「重定向过多」是死代码） ===');
  await checkAsync('正常跳转链 302→301→200 应成功且 redirects=2', async () => {
    const r = await fetchPage(base + '/r1');
    assert.strictEqual(r.ok, true, '应 ok=true');
    assert.strictEqual(r.redirects, 2, 'redirects 应为 2，实际 ' + r.redirects);
    assert.strictEqual(r.final.status, 200, 'final.status 应为 200');
  });
  await checkAsync('自环重定向应判定为循环，不得返回 302 当页面', async () => {
    const r = await fetchPage(base + '/loop');
    assert.strictEqual(r.ok, false, '应 ok=false');
    assert.strictEqual(r.redirectLoop, true, '应标记 redirectLoop');
  });
  await checkAsync('无限重定向应报「次数过多」（此前该分支不可达）', async () => {
    const r = await fetchPage(base + '/forever', { maxRedirects: 3 });
    assert.strictEqual(r.ok, false, '应 ok=false');
    assert.strictEqual(r.redirectExceeded, true, '应标记 redirectExceeded');
    assert.ok(/重定向次数过多/.test(r.error.message), '错误文案应说明次数过多');
  });

  console.log('\n=== B. rawRequest 悬挂兜底（任何异常路径都必须 settle） ===');
  await checkAsync('服务端不响应时，兜底超时必须在 timeout+2s 内返回 ok=false', async () => {
    const t0 = Date.now();
    const r = await rawRequest(base + '/hang', { timeout: 1200 });
    const dt = Date.now() - t0;
    assert.strictEqual(r.ok, false, '应 ok=false');
    assert.ok(dt < 5000, '应在 5s 内返回，实际 ' + dt + 'ms');
  });

  console.log('\n=== C. TXT 记录归一化（DoH 多字符串曾被破坏） ===');
  check('单段 TXT 去引号', () => {
    assert.strictEqual(unquoteTxt('"v=spf1 include:a.com -all"'), 'v=spf1 include:a.com -all');
  });
  check('多段 TXT 拼接为完整语义（不再残留内层引号）', () => {
    const out = unquoteTxt('"v=spf1 include:a.com " "include:b.com -all"');
    assert.strictEqual(out, 'v=spf1 include:a.com include:b.com -all');
    assert.ok(out.indexOf('"') < 0, '不应残留引号');
  });
  check('无引号输入原样返回', () => {
    assert.strictEqual(unquoteTxt('v=spf1 -all'), 'v=spf1 -all');
  });
  check('registrableDomain 多级后缀仍正确', () => {
    assert.strictEqual(registrableDomain('www.foo.com.cn'), 'foo.com.cn');
    assert.strictEqual(registrableDomain('a.b.example.com'), 'example.com');
    assert.strictEqual(registrableDomain('www.example.com.sg'), 'example.com.sg');
    assert.strictEqual(registrableDomain('127.0.0.1'), '127.0.0.1');
  });

  console.log('\n=== D. generator 元标签属性顺序 ===');
  check('name 在前可识别', () => {
    const r = analyzeContent('<meta name="generator" content="Drupal 10">', 'https://x.test');
    assert.strictEqual(r.generator, 'Drupal 10');
  });
  check('content 在前亦可识别（此前漏检）', () => {
    const r = analyzeContent('<meta content="WordPress 6.5.2" name="generator">', 'https://x.test');
    assert.strictEqual(r.generator, 'WordPress 6.5.2');
  });

  console.log('\n=== E. 高级选项真正透传到引擎 ===');
  await checkAsync('detectExposure=false 应跳过暴露面并给出提示', async () => {
    const rep = await assess(base + '/ok', { detectExposure: false, detectLibs: false, timeout: 4000 });
    assert.strictEqual(rep.ok, true, '评估应成功');
    const w = rep.warnings.join(' | ');
    assert.ok(/已按设置关闭「敏感路径暴露面探测」/.test(w), '缺暴露面跳过提示：' + w);
    assert.ok(/已按设置关闭「前端组件深度检测」/.test(w), '缺组件跳过提示：' + w);
    const exposureChecks = rep.checks.filter((c) => c.category === 'exposure');
    assert.ok(exposureChecks.length > 0, '暴露面检查项应仍然存在（标记为不适用）');
    assert.ok(exposureChecks.every((c) => c.status === 'na' || c.status === 'info' || c.status === 'pass' || c.status === 'warn'),
      '关闭探测后不应把暴露面判为「不通过」（那是误报）');
  });
  await checkAsync('默认（不传选项）仍执行完整探测', async () => {
    const rep = await assess(base + '/ok', { timeout: 4000 });
    const w = rep.warnings.join(' | ');
    assert.ok(!/已按设置关闭/.test(w), '不应出现跳过提示');
  });

  console.log('\n=== F. TLS 端口取自目标，不再硬编码 443 ===');
  await checkAsync('非常规端口目标：TLS 端口应等于目标端口', async () => {
    const rep = await assess(base + '/ok', { timeout: 4000, detectExposure: false });
    assert.ok(rep.tls, '应有 tls 结果');
    assert.strictEqual(rep.tls.port, port,
      'TLS 端口应为目标端口 ' + port + '，实际 ' + rep.tls.port);
  });

  srv.close();
  console.log('\n----------------------------------------');
  console.log('通过 ' + pass + ' / 失败 ' + fail);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => {
  console.error('测试框架异常：' + (e && e.stack || e));
  process.exit(2);
});
