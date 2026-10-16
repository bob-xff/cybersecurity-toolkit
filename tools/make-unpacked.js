#!/usr/bin/env node
'use strict';

/**
 * 构建 Electron 应用目录（win-unpacked），不依赖 electron-builder 的拷贝流程。
 *
 * 背景：在受限/被拦截的文件系统环境里，electron-builder 内部拷贝 Electron
 * 运行时时会卡死（长时间停在 copying Electron）。本脚本用标准 fs.cpSync
 * 完成同样的布局，随后可交给 electron-builder --prepackaged 生成单文件 exe。
 *
 * 产出布局（与 electron-builder 一致，main.js 的 app.isPackaged 分支可正确解析）：
 *   <out>/
 *     <productName>.exe          ← 由 electron.exe 改名
 *     *.dll / *.pak / locales/ ...
 *     resources/
 *       app/{main.js,preload.js,package.json}
 *       core/  ui/  docs/
 *
 * 用法: node tools/make-unpacked.js [outDir]
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DESKTOP = path.join(ROOT, 'desktop');
const ELECTRON_DIST = path.join(DESKTOP, 'node_modules', 'electron', 'dist');
const OUT = path.resolve(process.argv[2] || path.join(ROOT, 'dist', 'win-unpacked'));

const pkg = require(path.join(DESKTOP, 'package.json'));
const PRODUCT = pkg.build.productName || pkg.name;
const APP_EXE = path.join(OUT, PRODUCT + '.exe');

function log(msg) { process.stdout.write(`[make-unpacked] ${msg}\n`); }

/**
 * 同步、逐文件递归拷贝。
 * 不使用 fs.cpSync：在受限文件系统环境下，其内部并行的 uv 工作线程拷贝
 * 会在启动后立刻被环境终止（进程被杀，无任何报错）。顺序同步拷贝稳定可行。
 */
function copyTreeSync(src, dst) {
  const st = fs.statSync(src);
  if (st.isDirectory()) {
    fs.mkdirSync(dst, { recursive: true });
    for (const name of fs.readdirSync(src)) {
      copyTreeSync(path.join(src, name), path.join(dst, name));
    }
    return;
  }
  fs.copyFileSync(src, dst);
}

function fail(msg) {
  process.stderr.write(`[make-unpacked] ERROR: ${msg}\n`);
  process.exit(1);
}

function rmrf(p) {
  fs.rmSync(p, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}

function assertDir(p, label) {
  if (!fs.existsSync(p) || !fs.statSync(p).isDirectory()) fail(`${label} 不存在: ${p}`);
}

/* ---------- 前置检查 ---------- */
assertDir(ELECTRON_DIST, 'Electron 运行时');
if (!fs.existsSync(path.join(ELECTRON_DIST, 'electron.exe'))) {
  fail('缺少 electron.exe，请先在 desktop/ 执行 npm install');
}
assertDir(path.join(ROOT, 'core'), 'core');
assertDir(path.join(ROOT, 'ui'), 'ui');

/* ---------- 1. 清空输出目录 ---------- */
log(`清空 ${OUT}`);
rmrf(OUT);
fs.mkdirSync(OUT, { recursive: true });

/* ---------- 2. 拷贝 Electron 运行时 ---------- */
log('拷贝 Electron 运行时...');
const t0 = Date.now();
copyTreeSync(ELECTRON_DIST, OUT);
log(`完成，用时 ${((Date.now() - t0) / 1000).toFixed(1)}s`);

/* ---------- 3. 应用资源 ---------- */
const RES = path.join(OUT, 'resources');
fs.mkdirSync(path.join(RES, 'app'), { recursive: true });

for (const f of ['main.js', 'preload.js', 'package.json']) {
  const src = path.join(DESKTOP, f);
  if (!fs.existsSync(src)) fail(`缺少 desktop/${f}`);
  fs.copyFileSync(src, path.join(RES, 'app', f));
}

// 依赖已无需打进包（桌面壳只用 Electron 内置模块 + 本地 core）
const appPkgPath = path.join(RES, 'app', 'package.json');
const appPkg = JSON.parse(fs.readFileSync(appPkgPath, 'utf8'));
delete appPkg.devDependencies;
delete appPkg.scripts;
delete appPkg.build;
fs.writeFileSync(appPkgPath, JSON.stringify(appPkg, null, 2), 'utf8');

for (const dir of ['core', 'ui', 'docs']) {
  const src = path.join(ROOT, dir);
  if (!fs.existsSync(src)) continue;
  copyTreeSync(src, path.join(RES, dir));
  log(`已复制 ${dir}/ → resources/${dir}`);
}

/* 窗口/任务栏图标（内层 exe 未做 rcedit，运行时由 main.js 显式指定） */
const iconSrc = path.join(DESKTOP, 'build', 'icon.png');
if (fs.existsSync(iconSrc)) {
  fs.copyFileSync(iconSrc, path.join(RES, 'app', 'icon.png'));
  log('已复制 build/icon.png → resources/app/icon.png');
}

/* ---------- 4. 重命名主程序 ---------- */
if (fs.existsSync(APP_EXE)) fs.rmSync(APP_EXE, { force: true });
fs.renameSync(path.join(OUT, 'electron.exe'), APP_EXE);
log(`主程序: ${path.basename(APP_EXE)}`);

/* ---------- 5. 自检 ---------- */
const must = [
  APP_EXE,
  path.join(RES, 'app', 'main.js'),
  path.join(RES, 'app', 'preload.js'),
  path.join(RES, 'core', 'index.js'),
  path.join(RES, 'ui', 'index.html'),
];
for (const p of must) {
  if (!fs.existsSync(p)) fail(`产物缺失: ${p}`);
}

// 冒烟：确认 core 引擎能在脱离源码树的情况下被 require
try {
  const core = require(path.join(RES, 'core', 'index.js'));
  if (typeof core.assess !== 'function') fail('core.assess 不可用');
  log(`core 引擎自检通过（TOOL_VERSION=${core.TOOL_VERSION || 'n/a'}）`);
} catch (e) {
  fail(`core 引擎加载失败: ${e.message}`);
}

log(`OK → ${OUT}`);
