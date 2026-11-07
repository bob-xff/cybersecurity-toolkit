/* 网站网络安全评估工具 - 共享前端逻辑（网页版 / 桌面版复用）
 * 运行环境自适应：
 *  - 桌面版（Electron）：window.assessTool（preload 注入），IPC 调用 core 引擎
 *  - 网页版：POST /api/assess，NDJSON 流式返回进度与结果
 */
(function () {
  'use strict';

  function $(s) { return document.querySelector(s); }

  var state = { report: null, busy: false };
  var desktop = !!window.assessTool;
  var reduceMotion = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

  /* ---------- 常量 ---------- */
  var STEP_ORDER = ['start', 'page', 'redirect', 'tls', 'dns', 'content', 'libs', 'exposure', 'checks', 'score', 'done'];
  var STEP_NAMES = {
    start: '准备', page: '页面抓取', redirect: '跳转检测', tls: 'TLS 探测',
    dns: 'DNS 检查', content: '内容分析', libs: '组件检测', exposure: '暴露面探测',
    checks: '标准检查', score: '评分汇总', done: '完成'
  };
  var STATUS_LABEL = { pass: '通过', warn: '警告', fail: '不通过', na: '不适用', info: '提示' };
  var SEV_LABEL = { high: '高危', medium: '中危', low: '低危' };
  /* 维度名称一律取引擎返回的 c.name —— 前端不再维护第二份映射，
   * 避免界面与导出的 Markdown 报告出现「同一维度两个名字」。 */
  function catName(c) { return (c && c.name) || (c && c.id) || '未知维度'; }
  var STAT_DEFS = [
    { key: 'fail', label: '不通过', cls: 's-fail' },
    { key: 'warn', label: '警告', cls: 's-warn' },
    { key: 'pass', label: '通过', cls: 's-pass' },
    { key: 'na', label: '不适用 / 提示', cls: 's-na' }
  ];

  /* ---------- 工具 ---------- */
  function esc(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function fmtTime(iso) {
    try { return new Date(iso).toLocaleString('zh-CN', { hour12: false }); } catch (e) { return iso; }
  }
  function fmtDur(ms) {
    if (ms == null) return '–';
    return ms >= 1000 ? (ms / 1000).toFixed(1) + ' s' : ms + ' ms';
  }
  function gradeClass(grade) {
    return /^[A-E]$/.test(String(grade || '')) ? 'g-' + grade : 'g-N';
  }

  /* ---------- Toast ---------- */
  var toastTimer = null;
  function showToast(msg) {
    var el = $('#toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('show');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.remove('show'); }, 2200);
  }

  /* ---------- 步骤导轨（进度用） ---------- */
  (function buildStepsRail() {
    var rail = $('#stepsRail');
    if (!rail) return;
    rail.innerHTML = STEP_ORDER.map(function () { return '<span class="step-seg"></span>'; }).join('');
  })();
  function paintSteps(step) {
    var rail = $('#stepsRail');
    if (!rail) return;
    var idx = STEP_ORDER.indexOf(step);
    if (idx < 0) idx = 0;
    var segs = rail.children;
    for (var i = 0; i < segs.length; i++) {
      segs[i].className = 'step-seg' + (i < idx ? ' done' : (i === idx ? ' current' : ''));
    }
  }

  /* ---------- 平台初始化 ---------- */
  (function initPlatform() {
    var pb = $('#platformBadge');
    if (pb) pb.textContent = desktop ? '桌面版' : '网页版';

    if (desktop) {
      try {
        window.assessTool.getVersion().then(function (v) {
          var vb = $('#versionBadge');
          if (vb) vb.textContent = 'v' + v;
        }).catch(function () { /* 忽略 */ });
      } catch (e) { /* 忽略 */ }
      return;
    }
    if (location.protocol === 'file:') {
      /* 文件直开：fetch 本地 API 必然失败，直接给醒目指引 */
      var fb = $('#fileModeBanner');
      if (fb) fb.classList.remove('hidden');
      var sb = $('#startBtn');
      if (sb) { sb.disabled = true; sb.title = '文件直开模式下不可用，请运行启动脚本'; }
      return;
    }
    /* 从服务端拿真实版本号（失败则保留 HTML 里的占位值） */
    fetch('api/health').then(function (r) { return r.json(); }).then(function (j) {
      var vb = $('#versionBadge');
      if (j && j.version && vb) vb.textContent = 'v' + j.version;
    }).catch(function () { /* 忽略 */ });
  })();

  /* ---------- 高级选项 ---------- */
  /* 这两个开关必须真正透传到引擎，否则就是「点了没用」的摆设 */
  function readOptions() {
    var libEl = $('#libOpt');
    var expEl = $('#exposureOpt');
    return {
      detectLibs: libEl ? !!libEl.checked : true,
      detectExposure: expEl ? !!expEl.checked : true
    };
  }

  /* ---------- 评估执行 ---------- */
  function runAssess(url, opts, onProgress) {
    if (desktop) {
      // 先清掉上一次的监听，避免重复评估时进度事件叠加触发
      if (window.assessTool.offProgress) window.assessTool.offProgress();
      window.assessTool.onProgress(function (p) { onProgress(p.step, p.text); });
      return window.assessTool.assess(url, opts);
    }
    return fetch('api/assess', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, detectLibs: opts.detectLibs, detectExposure: opts.detectExposure })
    }).then(function (res) {
      var ct = res.headers.get('content-type') || '';
      if (ct.indexOf('application/json') >= 0) {
        return res.json().then(function (j) { throw new Error((j && j.error) || ('HTTP ' + res.status)); });
      }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      if (!res.body || !res.body.getReader) throw new Error('当前浏览器不支持流式响应，请换用 Chrome / Edge / Firefox 最新版');
      return readNdjson(res, onProgress);
    }).catch(function (e) {
      /* fetch 在连接失败时抛 TypeError("Failed to fetch")，翻译成用户能行动的话 */
      if (e instanceof TypeError || /failed to fetch|networkerror|load failed/i.test(e.message || '')) {
        throw new Error('无法连接本地评估服务（' + location.origin + '）。\n'
          + '请先运行项目根目录的「启动网页版.bat」启动服务，然后刷新本页；'
          + '或使用「启动桌面版.bat」打开桌面版。');
      }
      throw e;
    });
  }

  function readNdjson(res, onProgress) {
    return new Promise(function (resolve, reject) {
      var reader = res.body.getReader();
      var decoder = new TextDecoder();
      var buf = '';
      function pump() {
        return reader.read().then(function (r) {
          if (r.done) { reject(new Error('连接中断，未收到评估结果')); return; }
          buf += decoder.decode(r.value, { stream: true });
          var idx;
          while ((idx = buf.indexOf('\n')) >= 0) {
            var line = buf.slice(0, idx).trim();
            buf = buf.slice(idx + 1);
            if (!line) continue;
            var evt;
            try { evt = JSON.parse(line); } catch (e) { continue; }
            if (evt.type === 'progress') onProgress(evt.step, evt.text);
            else if (evt.type === 'result') { resolve(evt.report); return; }
            else if (evt.type === 'error') { reject(new Error(evt.message || '评估失败')); return; }
          }
          return pump();
        });
      }
      pump().catch(reject);
    });
  }

  /* ---------- 交互 ---------- */
  var startBtn = $('#startBtn');
  var EXPORT_SELECTORS = ['#exportBtn', '#copyBtn', '#jsonBtn'];

  function setExportEnabled(on) {
    EXPORT_SELECTORS.forEach(function (s) {
      var el = $(s);
      if (el) el.disabled = !on;
    });
  }

  function showError(title, msg) {
    var box = $('#errorCard');
    if (!box) return;
    box.innerHTML = '<div class="err-title">' + esc(title) + '</div><div>' + esc(msg) + '</div>';
    box.classList.remove('hidden');
    // 重新触发 shake 动画
    box.style.animation = 'none';
    void box.offsetHeight;
    box.style.animation = '';
  }

  function start() {
    if (state.busy) return;
    // 无论输入是否合法，都先清掉上一轮结果，避免「失败后仍可导出旧报告」
    state.report = null;
    setExportEnabled(false);
    var resultArea = $('#resultArea');
    if (resultArea) resultArea.classList.add('hidden');

    var urlInput = $('#urlInput');
    var url = urlInput ? urlInput.value.trim() : '';
    if (!url) { showError('请输入目标网址', '例如：https://www.example.com'); return; }

    var opts = readOptions();
    state.busy = true;
    if (startBtn) { startBtn.disabled = true; startBtn.textContent = '评估中…'; }
    var ec = $('#errorCard'); if (ec) ec.classList.add('hidden');
    var pc = $('#progressCard'); if (pc) pc.classList.remove('hidden');
    setProgress('start', '正在初始化…');

    runAssess(url, opts, function (step, text) { setProgress(step, text); })
      .then(function (r) {
        var p2 = $('#progressCard'); if (p2) p2.classList.add('hidden');
        if (!r || r.ok !== true) {
          showError('评估失败', (r && r.error) || '引擎未返回有效结果');
          return;
        }
        renderReport(r);
      })
      .catch(function (e) {
        var p3 = $('#progressCard'); if (p3) p3.classList.add('hidden');
        showError('评估出错', e && e.message ? e.message : String(e));
      })
      .then(function () {
        state.busy = false;
        if (startBtn) { startBtn.disabled = false; startBtn.textContent = '开始评估'; }
      });
  }

  function setProgress(step, text) {
    var pt = $('#progressText');
    if (pt) pt.textContent = text || STEP_NAMES[step] || step;
    var ps = $('#progressStep');
    if (ps) ps.textContent = '当前阶段：' + (STEP_NAMES[step] || step);
    var i = STEP_ORDER.indexOf(step);
    var pct = i < 0 ? 8 : Math.round(((i + 1) / STEP_ORDER.length) * 100);
    var fill = $('#pbarFill');
    if (fill) fill.style.width = pct + '%';
    var pctEl = $('#progressPct');
    if (pctEl) pctEl.textContent = pct + '%';
    paintSteps(step);
  }

  if (startBtn) startBtn.addEventListener('click', start);
  var urlInputEl = $('#urlInput');
  if (urlInputEl) {
    urlInputEl.addEventListener('keydown', function (e) { if (e.key === 'Enter') start(); });
  }
  Array.prototype.forEach.call(document.querySelectorAll('[data-sample]'), function (b) {
    b.addEventListener('click', function () {
      var el = $('#urlInput');
      if (el) el.value = b.getAttribute('data-sample');
      start();
    });
  });

  /* ---------- 渲染 ---------- */
  function renderReport(r) {
    state.report = r;
    setExportEnabled(true);
    var area = $('#resultArea');
    if (area) area.classList.remove('hidden');

    /* 总览 */
    var score = r.score;
    var grade = (r.level && r.level.grade) ? r.level.grade : 'N';
    animateNumber($('#scoreNum'), score == null ? null : score);

    var gb = $('#gradeBadge');
    if (gb) {
      gb.textContent = grade;
      gb.className = 'grade-badge ' + gradeClass(grade);
      void gb.offsetWidth;           // 重新触发 pop 动画
      gb.classList.add('pop');
    }
    var gl = $('#gradeLabel');
    if (gl) gl.textContent = (r.level && r.level.label) || '';

    var arc = $('#gaugeArc');
    if (arc) {
      var C = 2 * Math.PI * 60;
      var frac = score == null ? 0 : Math.max(0, Math.min(100, score)) / 100;
      // 先回到 0 再过渡到目标值，保证重复评估时也有生长动画
      arc.style.strokeDashoffset = String(C);
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { arc.style.strokeDashoffset = String(C * (1 - frac)); });
      });
      arc.setAttribute('class', 'gauge-arc ' + gradeClass(grade));
    }

    var t = r.target || {};
    var redirects = (t.redirectChain || []).length;
    var ti = $('#targetInfo');
    if (ti) {
      ti.innerHTML =
        '<dt>目标网址</dt><dd>' + esc(t.url) + '</dd>' +
        '<dt>最终网址</dt><dd>' + esc(t.finalUrl || t.url) + '</dd>' +
        '<dt>HTTP 状态</dt><dd>' + esc(t.finalStatus == null ? '–' : t.finalStatus) + '（重定向 ' + redirects + ' 次）</dd>' +
        '<dt>评估耗时</dt><dd>' + fmtDur(r.durationMs) +
        ((r.performance && r.performance.probesMs != null) ? '（并行探测 ' + fmtDur(r.performance.probesMs) + '）' : '') + '</dd>' +
        '<dt>评估时间</dt><dd>' + esc(fmtTime(r.startedAt)) + '</dd>';
    }

    renderStats(r);
    renderTech(r);

    /* 引擎提示 */
    var wb = $('#warningsBox');
    if (wb) {
      if (r.warnings && r.warnings.length) {
        wb.innerHTML = '<div class="w-title">⚠ 评估过程中的提示</div><ul>' +
          r.warnings.map(function (w) { return '<li>' + esc(w) + '</li>'; }).join('') + '</ul>';
        wb.classList.remove('hidden');
        wb.classList.add('enter');
      } else {
        wb.classList.add('hidden');
        wb.classList.remove('enter');
      }
    }

    /* 维度 */
    var grid = $('#catGrid');
    if (grid) {
      grid.innerHTML = '';
      (r.categories || []).forEach(function (c, i) {
        var pct = c.score == null ? 0 : Math.max(0, Math.min(100, c.score));
        var color = c.score == null ? 'var(--border-strong)'
          : c.score >= 90 ? 'var(--green)'
          : c.score >= 75 ? 'var(--teal)'
          : c.score >= 60 ? 'var(--amber)'
          : c.score >= 40 ? 'var(--orange)' : 'var(--red)';
        var counts = c.counts || {};
        var countStr = ['pass', 'warn', 'fail', 'na', 'info']
          .filter(function (k) { return counts[k]; })
          .map(function (k) { return STATUS_LABEL[k] + ' ' + counts[k]; }).join(' · ');
        var el = document.createElement('div');
        el.className = 'card cat-card enter';
        el.style.animationDelay = (i * 60) + 'ms';
        el.innerHTML =
          '<div class="cat-head"><span class="cat-name">' + esc(catName(c)) +
          ' <span class="cat-weight">权重 ' + c.weight + '%</span></span>' +
          '<span class="cat-score' + (c.score == null ? ' na' : '') + '">' +
          (c.score == null ? '不适用' : c.score.toFixed(1)) + '</span></div>' +
          '<div class="bar-track"><div class="bar-fill" style="width:0%;background:' + color + '"></div></div>' +
          '<div class="cat-counts" style="margin-top:6px">' + esc(countStr || '无计分项') + '</div>';
        grid.appendChild(el);
        // 进度条从 0 生长到目标值
        var fill = el.querySelector('.bar-fill');
        var target = pct + '%';
        requestAnimationFrame(function () {
          requestAnimationFrame(function () { fill.style.width = target; });
        });
      });
    }

    /* 明细筛选器 */
    var fCat = $('#fCat');
    if (fCat) {
      fCat.innerHTML = '<option value="">全部维度</option>' +
        (r.categories || []).map(function (c) {
          return '<option value="' + esc(c.id) + '">' + esc(catName(c)) + '</option>';
        }).join('');
    }
    resetFilters();
    renderFindings();

    bindFilterEvents();

    /* 平滑滚动到结果区（尊重减少动态偏好） */
    try {
      if (area) area.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    } catch (e) { /* 老浏览器忽略 */ }
  }

  /* 统计磁贴：点击即按状态筛选明细 */
  function renderStats(r) {
    var row = $('#statRow');
    if (!row) return;
    var checks = r.checks || [];
    function count(k) {
      if (k === 'na') return checks.filter(function (c) { return c.status === 'na' || c.status === 'info'; }).length;
      return checks.filter(function (c) { return c.status === k; }).length;
    }
    row.innerHTML = '';
    STAT_DEFS.forEach(function (def, i) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'stat enter ' + def.cls;
      b.style.animationDelay = (i * 55) + 'ms';
      b.setAttribute('data-status', def.key);
      b.innerHTML = '<div class="s-num">' + count(def.key) + '</div>' +
        '<div class="s-label">' + esc(def.label) + '</div>';
      b.addEventListener('click', function () {
        var sel = $('#fStatus');
        if (!sel) return;
        var want = def.key === 'na' ? 'na' : def.key;
        sel.value = (sel.value === want) ? '' : want;   // 再次点击取消
        renderFindings();
        var card = $('.filter-card');
        if (card) {
          try { card.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' }); } catch (e) { /* ignore */ }
        }
      });
      row.appendChild(b);
    });
    syncStatActive();
  }

  function syncStatActive() {
    var sel = $('#fStatus');
    var cur = sel ? sel.value : '';
    Array.prototype.forEach.call(document.querySelectorAll('#statRow .stat'), function (el) {
      var k = el.getAttribute('data-status');
      var on = (k === 'na') ? (cur === 'na') : (cur === k);
      el.classList.toggle('is-active', on);
    });
  }

  function resetFilters() {
    ['#fStatus', '#fCat', '#fSev', '#fText'].forEach(function (s) {
      var el = $(s);
      if (el) el.value = '';
    });
  }

  /* 技术栈与探测证据：把引擎采集到的原始信息展示出来，供人工复核结论 */
  function renderTech(r) {
    var box = $('#techCard');
    if (!box) return;
    var tech = r.tech || {};
    var libs = tech.libs || [];
    var tls = r.tls || null;
    var dns = r.dns || null;
    var exp = r.exposure || null;
    var chips = [];

    function chip(label, value, cls) {
      if (value == null || value === '') return;
      chips.push('<span class="tech-chip ' + (cls || '') + '"><b>' + esc(label) + '</b> ' + esc(value) + '</span>');
    }

    if (tls && tls.reachable) {
      var cert = tls.cert || {};
      chip('TLS', (tls.negotiated && tls.negotiated.protocol) || '已启用', 'ok');
      chip('证书剩余', cert.daysRemaining == null ? '未知' : cert.daysRemaining + ' 天',
        (cert.daysRemaining != null && cert.daysRemaining < 30) ? 'bad' : 'ok');
      chip('签发机构', (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || '未知');
      if (!tls.trusted) chip('证书链', '不受信任', 'bad');
      if ((tls.weakCiphers || []).length) chip('弱套件', tls.weakCiphers.join('、'), 'bad');
      chip('探测端口', String(tls.port));
    } else if (tls) {
      chip('TLS', '未启用', 'bad');
    }
    chip('CMS', (tech.cms || []).join('、') || '未识别');
    chip('前端框架', (tech.frameworks || []).join('、') || '未识别');
    if (tech.isHtml === false) chip('响应类型', '非 HTML（内容类检查不适用）', 'warn');
    if (tech.charset && tech.charset !== 'utf-8') chip('页面编码', tech.charset);
    if (tech.scanLimited) chip('内容分析', '仅覆盖前 256KB', 'warn');
    chip('Generator', tech.generator || '未识别');
    chip('ICP 备案', tech.icp || '未识别', tech.icp ? 'ok' : 'warn');
    chip('引用脚本', tech.scriptCount == null ? '—' : (tech.scriptCount + ' 个'));
    if (dns) {
      var st = dns.states || {};
      chip('SPF', dns.spf
        ? (dns.spf.mechanism === 'hard' ? '已配置（-all）' : '已配置')
        : (st.spf === 'error' ? '查询失败' : '未配置'),
        dns.spf ? 'ok' : (st.spf === 'error' ? 'warn' : 'bad'));
      chip('DMARC', dns.dmarc
        ? ('策略 ' + dns.dmarc.policy)
        : (st.dmarc === 'error' ? '查询失败' : '未配置'),
        dns.dmarc ? 'ok' : (st.dmarc === 'error' ? 'warn' : 'bad'));
      if (dns.doh) chip('DNS 来源', 'DoH 回退', 'warn');
    }
    if (exp && exp.enabled) {
      var hit = (exp.foundFiles || []).length;
      chip('暴露面', hit ? ('命中 ' + hit + ' 条') : '未命中', hit ? 'bad' : 'ok');
      if (exp.failedRequests) chip('探测失败', exp.failedRequests + ' 个请求', 'warn');
    } else {
      chip('暴露面', '已按设置跳过 / 未完成', 'warn');
    }

    var html = '<div class="tech-head"><h3>技术栈与探测证据</h3>' +
      '<span class="sub">工具实际采集到的原始信息，供人工复核（并非结论本身）</span></div>' +
      '<div class="tech-grid">' + chips.join('') + '</div>';

    if (libs.length) {
      html += '<div class="lib-list">' + libs.map(function (l) {
        var verdict = l.vulnerable === true ? '<span class="chip st-fail">受影响</span>'
          : l.eol ? '<span class="chip st-warn">已停止维护</span>'
          : l.vulnerable === false ? '<span class="chip st-pass">版本安全</span>'
          : '<span class="chip st-na">版本未知</span>';
        return '<div class="lib-row"><span class="lib-name">' + esc(l.lib) + '</span>' +
          '<span class="lib-ver">' + esc(l.version || '未识别版本') + '</span>' + verdict +
          (l.cve ? '<span class="chip sev-' + esc(l.severity || 'low') + '">' + esc(l.cve) + '</span>' : '') +
          '</div>';
      }).join('') + '</div>';
    } else {
      html += '<div class="sub" style="margin-top:10px">未识别到漏洞库中的前端组件（可能未使用，或外部脚本不可达）。</div>';
    }

    var rows = [];
    if (dns && dns.domain) {
      rows.push(['可注册域', dns.domain]);
      if (dns.spf) rows.push(['SPF 记录', dns.spf.record + '（' + dns.spf.at + '）']);
      if (dns.dmarc) rows.push(['DMARC 记录', dns.dmarc.record]);
      rows.push(['MX', (dns.mx || []).map(function (m) { return m.exchange + '(' + m.priority + ')'; }).join('、') || '无']);
      if ((dns.errors || []).length) rows.push(['DNS 异常', (dns.errors || []).join('；')]);
      if (dns.doh) rows.push(['DNS 来源', '系统 DNS 不可用，已回退 DoH']);
    }
    if (tls && tls.reachable) {
      var protos = Object.keys(tls.protocols || {}).map(function (k) {
        return k + '=' + (tls.protocols[k] === true ? '支持' : tls.protocols[k] === false ? '不支持' : '未知');
      });
      if (protos.length) rows.push(['协议矩阵', protos.join('、')]);
      var san = (tls.cert && tls.cert.altNames) || [];
      if (san.length) rows.push(['SAN 域名', san.join('、')]);
      if ((tls.notes || []).length) rows.push(['探测说明', tls.notes.join('；')]);
    }
    if (exp && exp.enabled) {
      rows.push(['已探测公开路径', (exp.checkedFiles || 0) + ' 条']);
      rows.push(['security.txt', exp.securityTxt ? String(exp.securityTxtUrl || '存在') : '未发现']);
      if ((exp.foundFiles || []).length) {
        rows.push(['命中的敏感路径', (exp.foundFiles || []).map(function (f) { return f.path; }).join('、')]);
      }
    }
    var perf = r.performance || {};
    if (perf.probesMs != null) {
      rows.push(['阶段耗时', '页面 ' + (perf.pageMs == null ? '—' : perf.pageMs + ' ms') +
        ' ／ 五路并行探测 ' + perf.probesMs + ' ms ／ 检查项 ' + (perf.checksMs == null ? '—' : perf.checksMs + ' ms')]);
      if (perf.tlsMs != null) rows.push(['其中 TLS 探测', perf.tlsMs + ' ms']);
      if (perf.exposureMs != null) rows.push(['其中暴露面探测', perf.exposureMs + ' ms']);
    }
    if (rows.length) {
      html += '<details class="tech-more"><summary>展开完整采集明细</summary><dl>' +
        rows.map(function (p) { return '<dt>' + esc(p[0]) + '</dt><dd>' + esc(p[1]) + '</dd>'; }).join('') +
        '</dl></details>';
    }

    box.innerHTML = html;
    box.classList.remove('hidden');
    box.classList.add('enter');
  }

  var filtersBound = false;
  function bindFilterEvents() {
    if (filtersBound) return;
    filtersBound = true;
    ['#fStatus', '#fCat', '#fSev'].forEach(function (s) {
      var el = $(s);
      if (el) el.addEventListener('change', renderFindings);
    });
    var ft = $('#fText');
    if (ft) ft.addEventListener('input', renderFindings);
    var fr = $('#fReset');
    if (fr) {
      fr.addEventListener('click', function () {
        resetFilters();
        renderFindings();
      });
    }
  }

  /* 数字滚动动画（0 → 目标分） */
  function animateNumber(el, target) {
    if (!el) return;
    if (el._raf) cancelAnimationFrame(el._raf);
    if (target == null || reduceMotion) { el.textContent = target == null ? 'N/A' : target.toFixed(1); return; }
    var t0 = null;
    var DUR = 800;
    function frame(ts) {
      if (!t0) t0 = ts;
      var p = Math.min(1, (ts - t0) / DUR);
      var eased = 1 - Math.pow(1 - p, 3); // easeOutCubic
      el.textContent = (target * eased).toFixed(1);
      if (p < 1) el._raf = requestAnimationFrame(frame);
      else el.textContent = target.toFixed(1);
    }
    el._raf = requestAnimationFrame(frame);
  }

  function renderFindings() {
    var r = state.report;
    if (!r) return;
    var fStatus = $('#fStatus');
    var fCat = $('#fCat');
    var fSev = $('#fSev');
    var fText = $('#fText');
    var st = fStatus ? fStatus.value : '';
    var cat = fCat ? fCat.value : '';
    var sev = fSev ? fSev.value : '';
    var q = fText ? fText.value.trim().toLowerCase() : '';
    var checks = r.checks || [];

    var list = checks.filter(function (c) {
      if (st && c.status !== st) return false;
      if (cat && c.category !== cat) return false;
      if (sev && c.severity !== sev) return false;
      if (q) {
        var hay = (c.id + ' ' + c.title + ' ' + (c.evidence || '')).toLowerCase();
        if (hay.indexOf(q) < 0) return false;
      }
      return true;
    });

    var fail = checks.filter(function (c) { return c.status === 'fail'; }).length;
    var warn = checks.filter(function (c) { return c.status === 'warn'; }).length;
    var fc = $('#findCount');
    if (fc) {
      fc.textContent = '共 ' + checks.length + ' 项（不通过 ' + fail + ' · 警告 ' + warn + '），当前显示 ' + list.length + ' 项';
    }
    syncStatActive();

    var box = $('#findList');
    if (!box) return;
    box.innerHTML = '';
    if (!list.length) {
      box.innerHTML = '<div class="card empty-tip">没有符合筛选条件的检查项</div>';
      return;
    }
    list.forEach(function (c, i) {
      var item = document.createElement('div');
      item.className = 'card find-item enter';
      item.style.animationDelay = Math.min(i * 35, 400) + 'ms';

      var head = document.createElement('button');
      head.type = 'button';
      head.className = 'find-head';
      head.setAttribute('aria-expanded', 'false');
      head.innerHTML =
        '<span class="find-caret" aria-hidden="true">▶</span>' +
        '<span class="find-id">' + esc(c.id) + '</span>' +
        '<span class="find-title">' + esc(c.title) + '</span>' +
        '<span class="chip sev-' + esc(c.severity) + '">' + esc(SEV_LABEL[c.severity] || c.severity) + '</span>' +
        '<span class="chip st-' + esc(c.status) + '">' + esc(STATUS_LABEL[c.status] || c.status) + '</span>';

      var body = document.createElement('div');
      body.className = 'find-body';

      var html = '<dl class="kv"><dt class="k">证据</dt><dd class="evidence" style="margin:0">' +
        esc(c.evidence || '（无）') + '</dd></dl>';
      if (c.detail) {
        var d = typeof c.detail === 'string' ? c.detail : JSON.stringify(c.detail, null, 2);
        html += '<div class="k" style="font-weight:700;color:var(--text-3);margin-bottom:2px">详情</div>' +
          '<pre class="detail">' + esc(d) + '</pre>';
      }
      if (c.cnStandards && c.cnStandards.length) {
        html += '<div class="k" style="font-weight:700;color:var(--text-3);margin-bottom:2px">国内标准依据</div>' +
          '<ul class="std-list">' + c.cnStandards.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ul>';
      }
      if (c.intlStandards && c.intlStandards.length) {
        html += '<div class="k" style="font-weight:700;color:var(--text-3);margin:8px 0 2px">国际标准依据</div>' +
          '<ul class="std-list intl">' + c.intlStandards.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ul>';
      }
      if (c.remediation) {
        html += '<dl class="kv" style="margin-top:10px"><dt class="k">整改建议</dt>' +
          '<dd class="remediation" style="margin:0">' + esc(c.remediation) + '</dd></dl>';
      }
      var inner = document.createElement('div');
      inner.className = 'find-body-inner';
      inner.innerHTML = html;
      body.appendChild(inner);

      function toggle() {
        var open = item.classList.toggle('open');
        head.setAttribute('aria-expanded', open ? 'true' : 'false');
      }
      head.addEventListener('click', toggle);
      head.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
          e.preventDefault();
          toggle();
        }
      });

      item.appendChild(head);
      item.appendChild(body);
      box.appendChild(item);
    });
  }

  /* 筛选栏吸顶时的投影提示 */
  (function stickyFilterShadow() {
    var card = $('.filter-card');
    if (!card || typeof window.addEventListener !== 'function') return;
    var ticking = false;
    window.addEventListener('scroll', function () {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(function () {
        ticking = false;
        // 仅在结果区可见时有意义
        var area = $('#resultArea');
        if (!area || area.classList.contains('hidden')) { card.classList.remove('is-stuck'); return; }
        var top = card.getBoundingClientRect().top;
        card.classList.toggle('is-stuck', top <= 11 && top > -60);
      });
    }, { passive: true });
  })();

  /* ---------- 导出 ---------- */
  function reportName(r) {
    var host = (r.target && r.target.hostname) || 'report';
    return '安全评估报告_' + host + '_' + (r.startedAt || '').slice(0, 10) + '.md';
  }
  function downloadBlob(name, content, mime) {
    var blob = new Blob([content], { type: mime || 'text/markdown;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  var exportBtn = $('#exportBtn');
  if (exportBtn) {
    exportBtn.addEventListener('click', function () {
      var r = state.report;
      if (!r) return;
      var name = reportName(r);
      if (desktop && window.assessTool.saveReport) {
        window.assessTool.saveReport(name, r.markdown || '').then(function (res) {
          if (res && res.ok === true) showToast('报告已保存：' + res.path);
        }).catch(function (e) { showError('保存失败', (e && e.message) || String(e)); });
      } else {
        downloadBlob(name, r.markdown || '');
        showToast('已开始下载 ' + name);
      }
    });
  }

  var copyBtn = $('#copyBtn');
  if (copyBtn) {
    copyBtn.addEventListener('click', function () {
      var r = state.report;
      if (!r) return;
      var btn = this;
      var done = function () {
        btn.textContent = '已复制 ✓';
        showToast('Markdown 已复制到剪贴板');
        setTimeout(function () { btn.textContent = '复制 Markdown'; }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(r.markdown || '').then(done, function () { fallbackCopy(r.markdown || '', done); });
      } else {
        fallbackCopy(r.markdown || '', done);
      }
    });
  }
  function fallbackCopy(text, done) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { /* ignore */ }
    ta.remove();
  }

  var jsonBtn = $('#jsonBtn');
  if (jsonBtn) {
    jsonBtn.addEventListener('click', function () {
      var r = state.report;
      if (!r) return;
      var copy = JSON.parse(JSON.stringify(r));
      delete copy.markdown;
      var name = reportName(r).replace(/\.md$/, '.json');
      downloadBlob(name, JSON.stringify(copy, null, 2), 'application/json;charset=utf-8');
      showToast('已开始下载 ' + name);
    });
  }

  /* ---------- URL 参数：?url=xxx 只预填，不自动开始 ----------
   * 自动开始会让「别人发一个链接」等同于「本机立刻向该地址发起探测」，
   * 在网页版监听地址被放宽时风险尤其明显。自动化场景请显式加 &auto=1。 */
  (function () {
    var q = null;
    try { q = new URLSearchParams(location.search); } catch (e) { return; }
    var u = q.get('url');
    if (!u) return;
    var el = $('#urlInput');
    if (el) el.value = u;
    if (q.get('auto') === '1') setTimeout(start, 300);
    else showToast('已填入目标网址，请确认后点击「开始评估」');
  })();

})();
