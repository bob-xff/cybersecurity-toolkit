'use strict';
/* 漏洞库判定模型回归测试（阈值均对照公开 CVE 公告核实） */
const { vulnState } = require('../core/libcheck');
const { VULN_DB } = require('../core/vulndb');

const lib = (n) => VULN_DB.find((l) => l.name === n);

/* [库, 版本, 是否受 CVE 影响, 是否 EOL] */
const cases = [
  // jQuery：CVE-2020-11022/11023 修复于 3.5.0
  ['jquery', '1.12.4', true, false],
  ['jquery', '3.4.1', true, false],
  ['jquery', '3.5.0', false, false],
  ['jquery', '3.6.0', false, false],
  // AngularJS：CVE-2020-7676 修复于 1.8.0；CVE-2024-8373/ReDoS 影响全版本且 EOL
  ['angularjs', '1.5.8', true, false],
  ['angularjs', '1.6.0', true, false],
  ['angularjs', '1.7.8', true, false],
  ['angularjs', '1.8.0', true, false],
  // Bootstrap：CVE-2019-8331 修复于 4.3.1；CVE-2018-14041 修复于 3.4.1；3.x EOL
  ['bootstrap', '3.3.7', true, true],
  ['bootstrap', '3.4.1', false, true],
  ['bootstrap', '4.0.0', true, false],
  ['bootstrap', '4.3.1', false, false],
  ['bootstrap', '5.3.0', false, false],
  // 其余库：单一修复线
  ['lodash', '4.17.20', true, false],
  ['lodash', '4.17.21', false, false],
  ['moment', '2.29.1', true, false],
  ['moment', '2.29.2', false, false],
  ['handlebars', '4.7.6', true, false],
  ['handlebars', '4.7.7', false, false],
];

let bad = 0;
for (const [n, v, expectVuln, expectEol] of cases) {
  const r = vulnState(v, lib(n));
  const ok = r.vulnerable === expectVuln && r.eol === expectEol;
  if (!ok) bad++;
  console.log((ok ? 'PASS' : 'FAIL') + '  ' + n + '@' + v + ' => vulnerable=' + r.vulnerable + ' eol=' + r.eol +
    (ok ? '' : '（期望 vulnerable=' + expectVuln + ' eol=' + expectEol + '）'));
}
// 版本缺失 → unknown
const unk = vulnState(null, lib('jquery'));
const unkOk = unk.vulnerable === null;
if (!unkOk) bad++;
console.log((unkOk ? 'PASS' : 'FAIL') + '  版本缺失 => vulnerable=null');

console.log(bad === 0 ? '\n全部通过（' + (cases.length + 1) + ' 例）' : '\n失败 ' + bad + ' 项');
process.exit(bad === 0 ? 0 : 1);
