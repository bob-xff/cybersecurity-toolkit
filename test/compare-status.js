'use strict';
/** 导出逐项状态，供新旧引擎 diff：node test/compare-status.js <core目录> [URL] */
const path = require('path');
const { assess } = require(path.join(process.argv[2], 'index.js'));
assess(process.argv[3] || 'http://127.0.0.1:9911/', { detectLibs: false, detectExposure: true })
  .then((r) => {
    if (!r.ok) { console.log('ERROR: ' + r.error); return; }
    console.log('score=' + r.score + ' grade=' + r.level.grade);
    for (const c of r.checks) console.log(c.id + ' | ' + c.status + ' | ' + String(c.evidence).slice(0, 90));
  })
  .catch((e) => console.log('ERROR: ' + e.message));
