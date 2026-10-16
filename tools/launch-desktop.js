'use strict';

/**
 * 桌面版启动器（由「启动桌面版.bat」调用，也可直接 node tools/launch-desktop.js）
 *  - 检查 Electron 运行时；缺失时自动执行 npm install（需联网）
 *  - 以前台方式启动桌面应用（关闭本窗口即退出应用）
 */
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const DESKTOP = path.join(ROOT, 'desktop');
const ELECTRON_EXE = path.join(DESKTOP, 'node_modules', 'electron', 'dist', 'electron.exe');
const NPM_CMD = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function run(cmd, args, opts) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, Object.assign({ stdio: 'inherit' }, opts || {}));
    p.on('error', reject);
    p.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(cmd + ' 退出码 ' + code))));
  });
}

(async () => {
  console.log('============================================');
  console.log('  网站网络安全评估工具 · 桌面版');
  console.log('============================================');

  if (!fs.existsSync(ELECTRON_EXE)) {
    console.log('[提示] 首次运行需要安装 Electron（约 100MB，需联网），安装中请耐心等待…');
    try {
      await run(NPM_CMD, ['install', '--no-audit', '--no-fund'], { cwd: DESKTOP });
    } catch (e) {
      console.error('[错误] Electron 安装失败：' + e.message);
      console.error('请检查网络后重试；或手动执行：');
      console.error('  cd desktop');
      console.error('  npm install');
      console.error('  npm start');
      process.exit(1);
    }
    if (!fs.existsSync(ELECTRON_EXE)) {
      console.error('[错误] 安装后仍未找到 Electron 运行时，请手动执行 npm install 检查。');
      process.exit(1);
    }
    console.log('[完成] Electron 安装成功。');
  }

  console.log('[启动] 正在打开桌面应用窗口…');
  console.log('（关闭本窗口 = 退出应用）');
  console.log('');

  const child = spawn(ELECTRON_EXE, [DESKTOP, '--disable-gpu'], { stdio: 'inherit' });
  child.on('error', (e) => {
    console.error('[错误] 桌面版启动失败：' + e.message);
    process.exit(1);
  });
  child.on('exit', (code) => process.exit(code == null ? 0 : code));
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => { try { child.kill(sig); } catch (e) { /* ignore */ } });
  }
})().catch((e) => {
  console.error('[错误] ' + (e && e.message ? e.message : String(e)));
  process.exit(1);
});
