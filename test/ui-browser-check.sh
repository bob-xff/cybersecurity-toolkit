#!/bin/sh
# 新 UI 浏览器实测脚本：初始态 → 评估 → 结果态 → 交互断言
set -x
NP=$(npm prefix -g)
AB="$NP/agent-browser.cmd"
SHOTS="C:/Users/hwff/Desktop/网安工具/test/shots"
BASE="http://127.0.0.1:8903"
TARGET="http://127.0.0.1:9911"

"$AB" open "$BASE/" || exit 1
"$AB" screenshot "$SHOTS/14-ui2-initial.png" || exit 1

# logo 是否为内联 SVG（新的粉色轨道标志）
"$AB" eval "(function(){var l=document.querySelector('svg.logo');return 'logo=' + (!!l) + ' orbits=' + (l?l.querySelectorAll('.lm-orbit ellipse').length:-1) + ' dots=' + (l?l.querySelectorAll('.lm-dots circle').length:-1);})()"
# 高级选项开关存在且默认为勾选
"$AB" eval "(function(){var a=document.getElementById('libOpt'),b=document.getElementById('exposureOpt');return 'libOpt=' + (a&&a.checked) + ' exposureOpt=' + (b&&b.checked);})()"

"$AB" fill "#urlInput" "$TARGET" || exit 1
"$AB" click "#startBtn" || exit 1
"$AB" wait --timeout 700
"$AB" screenshot "$SHOTS/15-ui2-progress.png"
"$AB" wait "#scoreNum" --timeout 40000 || exit 1
"$AB" wait --timeout 1800
"$AB" screenshot "$SHOTS/16-ui2-result.png" || exit 1

# 数据核对
"$AB" eval "document.querySelector('#scoreNum').textContent + ' | ' + document.querySelector('#gradeBadge').textContent + ' | ' + document.querySelector('#findCount').textContent"
# 步骤导轨 / 统计磁贴
"$AB" eval "(function(){return 'segs=' + document.querySelectorAll('#stepsRail .step-seg').length + ' done=' + document.querySelectorAll('#stepsRail .step-seg.done').length + ' stats=' + document.querySelectorAll('#statRow .stat').length;})()"

# 交互 1：点击「不通过」磁贴 → 应写入 fStatus 且磁贴高亮
"$AB" click "#statRow .stat.s-fail" || exit 1
"$AB" wait --timeout 700
"$AB" eval "(function(){return 'fStatus=' + document.querySelector('#fStatus').value + ' active=' + document.querySelectorAll('#statRow .stat.is-active').length + ' shown=' + document.querySelectorAll('#findList .find-item').length;})()"
"$AB" screenshot "$SHOTS/17-ui2-statfilter.png" || exit 1

# 交互 2：展开第一条明细，量测动画前后高度 + aria
"$AB" eval "(async function(){var h=document.querySelector('#findList .find-head');var it=h.closest('.find-item');var inner=it.querySelector('.find-body-inner');var h0=inner.getBoundingClientRect().height;h.click();var h1=inner.getBoundingClientRect().height;await new Promise(function(r){setTimeout(r,600)});var h2=inner.getBoundingClientRect().height;return 'h0='+Math.round(h0)+' h1='+Math.round(h1)+' h2='+Math.round(h2)+' open='+it.classList.contains('open')+' aria='+h.getAttribute('aria-expanded');})()"
"$AB" wait --timeout 400
"$AB" screenshot "$SHOTS/18-ui2-finding-open.png" || exit 1

# 交互 3：键盘可达（Enter 触发折叠）
"$AB" eval "(function(){var h=document.querySelector('#findList .find-head');h.focus();h.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));return 'after-enter open=' + h.closest('.find-item').classList.contains('open');})()"

# 技术栈/证据卡片（本轮新增）
"$AB" eval "(function(){var c=document.getElementById('techCard');var chips=c?c.querySelectorAll('.tech-chip').length:-1;var libs=c?c.querySelectorAll('.lib-row').length:-1;var d=c?c.querySelector('details.tech-more'):null;return 'techCard=' + (!!c && !c.classList.contains('hidden')) + ' chips=' + chips + ' libRows=' + libs + ' hasDetails=' + (!!d);})()"
"$AB" scrollintoview "#techCard"
"$AB" wait --timeout 500
"$AB" screenshot "$SHOTS/19-ui2-techcard.png"

# 端到端：高级选项真的透传到引擎（关闭两项后应出现「已按设置关闭」提示）
"$AB" eval "(async function(){var r=await fetch('api/assess',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:'$TARGET',detectLibs:false,detectExposure:false})});var t=await r.text();var lines=t.trim().split('\n');var last=JSON.parse(lines[lines.length-1]);var rep=last.report||{};var w=rep.warnings||[];return 'ok='+rep.ok+' exposureChecks='+((rep.checks||[]).filter(function(c){return c.category==='exposure';}).length)+' skipWarn='+w.filter(function(x){return x.indexOf('已按设置关闭')>=0;}).length+' exposureEnabled='+(rep.exposure&&rep.exposure.enabled);})()"

# 控制台错误
"$AB" eval "(function(){return 'title=' + document.title + ' findList=' + document.querySelectorAll('#findList .find-item').length;})()"
"$AB" close
