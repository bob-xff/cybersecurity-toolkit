'use strict';
/* 验证「系统 DNS + DoH 全部失败」时，N 类检查项必须为 na（无法检测），绝不误报 fail */
const fetcher = require('../core/fetcher');
// 在 dnschk 加载前劫持 rawRequest：模拟 DoH 全部不可达
fetcher.rawRequest = async () => ({ ok: false, error: { message: 'DoH 模拟不可达' } });

const { probeDns } = require('../core/dnschk');
const { assess } = require('../core');

(async () => {
  const r = await probeDns('example.com');
  console.log('states:', JSON.stringify(r.states));
  console.log('errors:', JSON.stringify(r.errors));
  console.log('spf:', r.spf, '| dmarc:', r.dmarc, '| dnssec:', r.dnssec, '| doh:', r.doh);

  const allError = ['spf', 'dmarc', 'mx', 'caa', 'dnssec'].every((k) => r.states[k] === 'error');
  console.log('全部记录 error 态:', allError ? 'PASS' : 'FAIL');

  // 走完整评估，验证 N1/N2/N3/N4/N5 全部 na 而非 fail
  const report = await assess('https://example.com', { libLimit: 0, timeout: 8000 });
  const n = {};
  for (const id of ['N1', 'N2', 'N3', 'N4', 'N5']) {
    const c = report.checks.find((x) => x.id === id);
    n[id] = c.status + ' | ' + (c.evidence || '').slice(0, 46);
  }
  console.log(JSON.stringify(n, null, 1));
  const anyFail = ['N1', 'N2', 'N3', 'N4', 'N5'].some((id) => report.checks.find((x) => x.id === id).status === 'fail');
  console.log('无一项误报 fail:', !anyFail ? 'PASS' : 'FAIL');
  console.log('warnings 含 DNS 失败说明:', report.warnings.some((w) => /DNS/.test(w)) ? 'PASS' : 'FAIL');
  process.exit(allError && !anyFail ? 0 : 1);
})().catch((e) => { console.error('ERR', e); process.exit(1); });
