'use strict';

/**
 * 高频前端组件已知漏洞库（Retire.js 风格的轻量子集）
 * below = 修复版本，检测到版本低于该值即视为受影响
 * 说明：这是高危高频库的子集，不等同于完整 SCA（软件成分分析）
 */
const VULN_DB = [
  {
    name: 'jquery',
    below: '3.5.0',
    severity: 'high',
    cve: 'CVE-2020-11022 / CVE-2020-11023',
    title: 'jQuery < 3.5.0：htmlPrefilter 可被绕过导致 XSS（自我 XSS / 存储型 XSS 风险）',
    contentPatterns: [
      /jQuery JavaScript Library v(\d+\.\d+\.\d+)/i,
      /jQuery v(\d+\.\d+\.\d+)/i,
      /\* jQuery (\d+\.\d+\.\d+)/i,
      /jquery["']?\s*[:=]\s*["'](\d+\.\d+\.\d+)["']/i,
    ],
  },
  {
    name: 'jquery-ui',
    below: '1.13.2',
    severity: 'medium',
    cve: 'CVE-2021-41184 等',
    title: 'jQuery UI < 1.13.2：多个组件存在 XSS / 原型链污染问题',
    contentPatterns: [
      /jQuery UI (\d+\.\d+\.\d+)/i,
      /jQuery UI - v(\d+\.\d+\.\d+)/i,
      /jquery-ui[.-](\d+\.\d+\.\d+)/i,
    ],
  },
  {
    name: 'angularjs',
    below: '1.8.0',
    // CVE-2024-8373（[srcset] 消毒绕过）与 CVE-2023-26116/26117/26118（ReDoS）
    // 影响全部已发布版本且不再修复；1.x 已于 2021-12-31 EOL。
    allVersions: true,
    // URL 别名：angular.min.js / angular-1.8.0.min.js 可识别；
    // 用正则而非子串，避免误伤 angular-ui-router 等衍生库
    aliasName: 'angular',
    aliasRe: /(?:^|[^\w-])angular(?:\.min)?\.js/i,
    aliasRe2: /(?:^|[^\w-])angular[.-]v?\d+\.\d+(?:\.\d+)?/i,
    severity: 'medium',
    cve: 'CVE-2020-7676 / CVE-2019-10768 / CVE-2024-8373 / CVE-2023-26116 等',
    title: 'AngularJS 1.x 全线 EOL：<1.8.0 另有 CVE-2020-7676（XSS）/ CVE-2019-10768（原型链污染），且 srcset 消毒绕过与多个 ReDoS 影响所有版本、已无修复，建议制定迁移至现代框架的计划',
    contentPatterns: [
      /AngularJS v(\d+\.\d+\.\d+)/i,
      /angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
      // 压缩版 banner 被剥离时，angular 模块元数据仍带 full 版本号
      /full\s*:\s*["'](\d+\.\d+\.\d+)["']\s*,\s*major\s*:\s*\d+/i,
    ],
  },
  {
    name: 'bootstrap',
    below: '4.3.1',
    // 3.4.1 已修复 CVE-2018-14041，且不受影响 4.x 的 CVE-2019-8331；3.x 整线已 EOL
    excludeBelow: '3.4.1',
    excludeUntil: '4.0.0',
    eolBefore: '4.0.0',
    severity: 'medium',
    cve: 'CVE-2019-8331 / CVE-2018-14041',
    title: 'Bootstrap < 4.3.1：data-template 属性 XSS（3.x < 3.4.1 另有 CVE-2018-14041）；3.x 整线已 EOL 建议升级',
    contentPatterns: [
      /Bootstrap v(\d+\.\d+\.\d+)/i,
      /bootstrap[.-](\d+\.\d+\.\d+)/i,
    ],
  },
  {
    name: 'lodash',
    below: '4.17.21',
    severity: 'high',
    cve: 'CVE-2021-23337 / CVE-2019-10744',
    title: 'lodash < 4.17.21：原型链污染与命令注入风险',
    contentPatterns: [
      /lodash (\d+\.\d+\.\d+)/i,
      /VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/,
    ],
  },
  {
    name: 'moment',
    below: '2.29.2',
    severity: 'medium',
    cve: 'CVE-2022-24785',
    title: 'moment < 2.29.2：locale 处理存在 ReDoS 拒绝服务风险',
    contentPatterns: [
      /moment\.version\s*=\s*["'](\d+\.\d+\.\d+)["']/i,
      /moment (\d+\.\d+\.\d+)/i,
    ],
  },
  {
    name: 'handlebars',
    below: '4.7.7',
    severity: 'medium',
    cve: 'CVE-2021-23383',
    title: 'Handlebars < 4.7.7：原型链污染，可能导致远程代码执行',
    contentPatterns: [
      /Handlebars VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/i,
      /Handlebars v(\d+\.\d+\.\d+)/i,
      /handlebars[.-](\d+\.\d+\.\d+)/i,
    ],
  },
];

module.exports = { VULN_DB };
