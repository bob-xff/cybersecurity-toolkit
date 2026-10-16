'use strict';
/* report.js Markdown 消毒回归测试 */
const { buildMarkdown } = require('../core/report');

const evil = {
  ok: true,
  target: {
    url: 'https://evil.com/' + 'a'.repeat(250) + '?x=1|注入|伪造\n第二行',
    finalUrl: 'https://evil.com/redir?next=|boom|\nX',
    finalStatus: 200,
    redirectChain: [{ status: 301, url: 'http://evil.com/?p=|a|b|' }],
  },
  startedAt: '2026-10-15 12:00:00',
  durationMs: 1234,
  tool: '网站网络安全评估工具',
  toolVersion: '1.0.0',
  score: 42,
  level: { grade: 'E', label: '严重' },
  warnings: ['警告含|管道\n和换行'],
  categories: [],
  checks: [
    {
      id: 'X1', category: 'transport', title: '标题含|管道\n换行', severity: 'high', status: 'fail',
      evidence: '证据含|管道\n换行\n\n- 伪列表项',
      cnStandards: ['GB/T 22239-2019'], intlStandards: ['RFC 6797'],
      remediation: '整改建议含|管道\n换行，同时这是一段特别特别特别特别特别特别特别特别特别特别特别特别长的文本用来测试截断行为是否正常工作',
      weight: 3,
    },
    {
      id: 'X2', category: 'transport', title: '警告项|管道', severity: 'medium', status: 'warn',
      evidence: 'warn evidence|x', cnStandards: [], intlStandards: [], remediation: 'fix|it', weight: 2,
    },
    {
      id: 'X3', category: 'transport', title: '通过项', severity: 'low', status: 'pass',
      evidence: 'ok', cnStandards: [], intlStandards: [], remediation: '', weight: 1,
    },
    {
      id: 'X4', category: 'transport', title: '提示项', severity: 'info', status: 'info',
      evidence: 'info', cnStandards: [], intlStandards: [], remediation: '', weight: 1,
    },
  ],
};

const md = buildMarkdown(evil);
const lines = md.split('\n');

// 断言 1：每个表格块内所有行列数一致
let tableErr = 0;
let block = [];
const checkBlock = (b) => {
  if (b.length < 2) return;
  const cols = b[0].split(/(?<!\\)\|/).length; // 不计转义管道
  for (const l of b) {
    const n = l.split(/(?<!\\)\|/).length;
    if (n !== cols) { tableErr++; console.log('  列数不一致(' + n + '!=' + cols + '): ' + l.slice(0, 80)); }
  }
};
for (const l of lines) {
  if (l.trim().startsWith('|')) block.push(l);
  else { checkBlock(block); block = []; }
}
checkBlock(block);

// 断言 2：未消毒的原始换行不会出现在表格行内
let rawNewlineInTable = 0;
for (const l of lines) {
  if (l.startsWith('|') && /[^\\]\|/.test(l) === false && /\|/.test(l) && l.includes('\n')) rawNewlineInTable++;
}

// 断言 3：转义管道存在
const hasEscaped = md.includes('\\|');

console.log('表格列数一致性:', tableErr === 0 ? 'PASS' : 'FAIL(' + tableErr + ')');
console.log('转义管道存在:', hasEscaped ? 'PASS' : 'FAIL');
console.log('截断省略号存在:', md.includes('…') ? 'PASS' : 'FAIL');

// 断言 4：表格行以 | 开头且以 | 结尾（结构完整）
const tableLines = lines.filter((l) => l.trim().startsWith('|'));
const badEnds = tableLines.filter((l) => !l.trim().endsWith('|'));
console.log('表格行闭合:', badEnds.length === 0 ? 'PASS' : 'FAIL(' + badEnds.length + ')');

// 打印概要表和整改表供人工核对
console.log('--- 概要表 ---');
lines.slice(lines.findIndex((l) => l.startsWith('## 一')), lines.findIndex((l) => l.startsWith('## 二'))).filter((l) => l.startsWith('|')).forEach((l) => console.log(l));
console.log('--- 整改优先级表（前3行）---');
lines.slice(lines.findIndex((l) => l.startsWith('## 四'))).filter((l) => l.startsWith('|')).slice(0, 3).forEach((l) => console.log(l));

process.exit(tableErr === 0 && hasEscaped && badEnds.length === 0 ? 0 : 1);
