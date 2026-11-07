'use strict';
/**
 * 新旧引擎耗时对比（零依赖）
 * 用法: node test/bench-compare.js <core目录绝对路径> [目标URL]
 * 输出单行 JSON，供对比脚本采集。
 */
const path = require('path');
const coreDir = process.argv[2];
const target = process.argv[3] || 'https://example.com';
if (!coreDir) { console.error('用法: node bench-compare.js <core目录> [URL]'); process.exit(2); }

const { assess } = require(path.join(coreDir, 'index.js'));
const t0 = Date.now();
assess(target, { detectLibs: false, detectExposure: true })
  .then((r) => {
    const wall = Date.now() - t0;
    console.log(JSON.stringify({
      ok: r.ok, score: r.score, grade: r.level && r.level.grade,
      wallMs: wall,
      durationMs: r.durationMs,
      tlsMs: r.performance ? r.performance.tlsMs : null,
      probesMs: r.performance ? r.performance.probesMs : null,
      exposureMs: r.performance ? r.performance.exposureMs : null,
      checks: r.checks ? r.checks.length : 0,
    }));
  })
  .catch((e) => { console.log(JSON.stringify({ ok: false, error: e.message, wallMs: Date.now() - t0 })); });
