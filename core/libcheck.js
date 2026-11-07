'use strict';

/**
 * 前端组件漏洞检测：URL 指纹 + 脚本内容版本识别 + 漏洞库比对
 *
 * 版本提取优先级：
 *   1. 文件名中的版本（jquery-1.12.4.min.js → 1.12.4）
 *   2. 库名后紧跟的路径段（.../jquery/3.6.0/jquery.min.js → 3.6.0）
 *   3. 查询参数（?ver=1.2.3）
 *   4. 脚本内容 banner（读真实文件字节，最权威，优先于 URL 猜测）
 * 注意：不可在完整 URL 上裸跑版本正则——主机名/端口里的数字（127.0.0.1）
 * 会被误当成版本号。
 *
 * 漏洞判定模型（vulnState）：
 *   - vulnerable：受具体 CVE 影响（below 为修复版本；allVersions 表示全线受影响）
 *   - excludeBelow：高于该版本的旧产品线分支不受主 CVE 影响（如 Bootstrap 3.4.1）
 *   - eol：版本低于 eolBefore，产品线已终止维护（无 CVE 也算风险，降级为警告）
 */
const { rawRequest } = require('./fetcher');
const { versionLt, mapLimit } = require('./util');
const { VULN_DB } = require('./vulndb');
const CONFIG = require('./config');

/** 边界匹配 + 最长库名优先（jquery-ui 先于 jquery，且不误伤 jquerymigrate）
 *  aliasRe / aliasRe2：库的 URL 别名正则（如 angular → angular.min.js / angular-1.8.0.js），
 *  用正则匹配而非裸子串，避免误伤 angular-ui-router 这类衍生库。
 *  命中项携带 nameEnd：库名部分在 URL 中的结束位置，供 extractVersion 提取后续版本号 */
function findLibMatch(lower) {
  const hits = [];
  for (const lib of VULN_DB) {
    const idx = lower.indexOf(lib.name);
    if (idx >= 0) {
      const before = idx === 0 ? '/' : lower[idx - 1];
      const afterPos = idx + lib.name.length;
      const after = afterPos >= lower.length ? '/' : lower[afterPos];
      // 前后均不能是字母/数字（允许 / . - _ ? # = @ 等分隔）
      if (!/[a-z0-9]/.test(before) && !/[a-z0-9]/.test(after)) {
        hits.push({ lib, nameEnd: idx + lib.name.length });
        continue;
      }
    }
    if (lib.aliasRe) {
      const m = lib.aliasRe.exec(lower) || (lib.aliasRe2 ? lib.aliasRe2.exec(lower) : null);
      if (m) {
        // 从匹配串中定位库名起点（跳过前导分隔符），库名长度取 aliasName
        const lead = m[0].length - m[0].replace(/^[^\w-]+/, '').length;
        hits.push({ lib, nameEnd: m.index + lead + (lib.aliasName || lib.name).length });
      }
    }
  }
  if (!hits.length) return null;
  hits.sort((a, b) => b.lib.name.length - a.lib.name.length);
  return hits[0];
}

function extractVersion(src, nameEnd) {
  // 1) 文件名中的版本
  const file = (src.split('/').pop() || '').toLowerCase();
  let vm = /(\d+\.\d+(?:\.\d+)?)/.exec(file);
  if (vm) return vm[1];
  // 2) 库名之后紧跟的路径段（仅接受直接相邻，避免 /jquery/ui/1.12 这类误配）
  const after = src.toLowerCase().slice(nameEnd);
  vm = /^[\/\-_.@]*(\d+\.\d+(?:\.\d+)?)/.exec(after);
  if (vm) return vm[1];
  // 3) 查询参数
  const q = src.split('?')[1] || '';
  vm = /(?:^|&)(?:ver|version|v)=(\d+\.\d+(?:\.\d+)?)/i.exec(q);
  if (vm) return vm[1];
  return null;
}

function detectFromUrl(src) {
  const lower = String(src).toLowerCase();
  const hit = findLibMatch(lower);
  if (!hit) return null;
  return { lib: hit.lib.name, version: extractVersion(src, hit.nameEnd), via: 'url' };
}

function detectFromContent(body) {
  // 库版本 banner 几乎总在文件头部；只扫前 64KB，避免对 512KB 压缩脚本反复跑全量正则
  const head = String(body || '').slice(0, CONFIG.limits.maxBannerScan);
  for (const lib of VULN_DB) {
    for (const p of lib.contentPatterns) {
      p.lastIndex = 0; // 共享正则对象带 g 标志时复位，避免跨调用的状态污染
      const m = p.exec(head);
      if (m && m[1]) return { lib: lib.name, version: m[1], via: 'content' };
    }
  }
  return null;
}

/**
 * 漏洞状态判定。version 为 null（无法识别）时返回 unknown。
 * excludeBelow/excludeUntil 构成半开区间 [excludeBelow, excludeUntil)：
 * 该区间内的旧产品线分支不受主 CVE 影响（如 Bootstrap 3.4.1–3.x 已单独修复）。
 * 返回 { vulnerable: true|false|null, eol: boolean }
 */
function vulnState(version, lib) {
  if (!version) return { vulnerable: null, eol: false };
  let vulnerable = lib.allVersions ? true : versionLt(version, lib.below);
  if (vulnerable && lib.excludeBelow && !versionLt(version, lib.excludeBelow) && (!lib.excludeUntil || versionLt(version, lib.excludeUntil))) {
    vulnerable = false;
  }
  const eol = !!(lib.eolBefore && versionLt(version, lib.eolBefore));
  return { vulnerable, eol };
}

async function checkLibs(scripts, options = {}) {
  // 引擎传 libLimit；maxLibFetch 为兼容旧调用方的别名
  const max = options.libLimit != null ? options.libLimit : (options.maxLibFetch != null ? options.maxLibFetch : CONFIG.limits.maxLibFetch);
  const httpScripts = (scripts || []).filter((s) => s.src && /^https?:/i.test(s.src));

  // 并行抓取脚本内容（并发受限，温和探测）；内容识别优先于 URL 猜测
  const fetchTargets = httpScripts.slice(0, Math.max(0, max));
  const bodies = await mapLimit(fetchTargets, CONFIG.concurrency.libs, async (s) => {
    try {
      const r = await rawRequest(s.src, { timeout: CONFIG.timeouts.lib, maxBody: 512 * 1024 });
      return r.ok ? r.body : null;
    } catch (e) {
      return null;
    }
  }, { settle: true });

  const out = [];
  const push = (s, detected) => {
    if (!detected) return;
    const lib = VULN_DB.find((l) => l.name === detected.lib);
    if (!lib) return;
    const st = vulnState(detected.version, lib);
    out.push({
      src: s.src,
      lib: lib.name,
      version: detected.version,
      vulnerable: st.vulnerable,
      eol: st.eol,
      below: lib.below,
      severity: lib.severity,
      cve: lib.cve,
      title: lib.title,
      hasSri: !!s.integrity,
      via: detected.via,
    });
  };

  fetchTargets.forEach((s, i) => {
    const body = bodies[i];
    push(s, (body && body.length > 32 ? detectFromContent(body) : null) || detectFromUrl(s.src));
  });
  // 超出抓取上限的脚本仍做 URL 识别（低置信但不漏报）
  for (const s of httpScripts.slice(fetchTargets.length)) {
    push(s, detectFromUrl(s.src));
  }
  return out;
}

module.exports = { checkLibs, detectFromUrl, detectFromContent, vulnState };
