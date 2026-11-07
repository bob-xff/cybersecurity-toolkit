'use strict';

/**
 * 桌面版主进程：Electron 壳
 *  - 加载与网页版共用的 ui/index.html
 *  - IPC 调用 ../core 评估引擎（同一套标准与评分，结果与网页版一致）
 *  - 报告保存走原生对话框
 *
 * 资源路径双模式：
 *  - 开发模式（electron . / npm start）：core/ui/docs 在 ../ 目录
 *  - 打包模式（electron-builder）：extraResources 将其复制到 process.resourcesPath
 */
const path = require('path');
const fs = require('fs');
const { app, BrowserWindow, ipcMain, dialog, Menu, shell } = require('electron');

/* 无 GPU / 虚拟化 / 远程桌面环境下，GPU 进程反复崩溃会触发
 * "GPU process isn't usable" FATAL 直接杀死整个应用（表现为「双击没反应」）。
 * 禁用硬件加速后走软件渲染，任何环境都能开窗。 */
app.disableHardwareAcceleration();

const CORE_DIR = app.isPackaged
  ? path.join(process.resourcesPath, 'core')
  : path.join(__dirname, '..', 'core');
const UI_DIR = app.isPackaged
  ? path.join(process.resourcesPath, 'ui')
  : path.join(__dirname, '..', 'ui');
const { assess, TOOL_VERSION } = require(path.join(CORE_DIR, 'index.js'));
const logger = require(path.join(CORE_DIR, 'logger.js'));

const UI_ENTRY = path.join(UI_DIR, 'index.html');

/* 窗口/任务栏图标。
 * 打包产物出于「不重写 exe 资源」的考虑（本地自用不签名、不做 rcedit），
 * 内层可执行文件仍是 Electron 默认图标；这里显式指定，保证运行时
 * 任务栏与窗口标题栏显示本工具图标。 */
const APP_ICON = app.isPackaged
  ? path.join(__dirname, 'icon.png')
  : path.join(__dirname, 'build', 'icon.png');

/* 单实例锁：避免多开窗口互相抢焦点、评估结果串窗口 */
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    const wins = BrowserWindow.getAllWindows();
    if (wins.length) {
      if (wins[0].isMinimized()) wins[0].restore();
      wins[0].focus();
    }
  });
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1240,
    height: 860,
    minWidth: 960,
    minHeight: 680,
    title: '网站网络安全评估工具',
    backgroundColor: '#fdf2f8',
    icon: fs.existsSync(APP_ICON) ? APP_ICON : undefined,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false // preload 需要 require('electron')
    }
  });
  win.loadFile(UI_ENTRY);

  /* 报告里的外链一律交给系统默认浏览器，不在应用内开新窗 */
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  return win;
}

/* ---------- IPC ---------- */
ipcMain.handle('get-version', () => TOOL_VERSION);

ipcMain.handle('assess', async (event, url, options) => {
  const win = BrowserWindow.fromWebContents(event.sender);
  if (typeof url !== 'string' || !url.trim()) {
    return { ok: false, error: 'url 参数无效' };
  }
  const o = (options && typeof options === 'object') ? options : {};
  try {
    return await assess(url.trim(), {
      detectLibs: o.detectLibs !== false,
      detectExposure: o.detectExposure !== false,
      onProgress: (step, text) => {
        if (win && !win.isDestroyed()) {
          win.webContents.send('assess-progress', { step, text });
        }
      }
    });
  } catch (e) {
    // IPC 通道上不允许出现未包装的 reject：渲染层需要统一的可展示错误
    logger.error('IPC', '评估执行异常', { reason: e && e.message ? e.message : String(e) });
    return { ok: false, error: '评估执行异常：' + (e && e.message ? e.message : String(e)) };
  }
});

ipcMain.handle('save-report', async (event, { name, content }) => {
  const win = BrowserWindow.fromWebContents(event.sender);
  // 文件名消毒：去掉路径分隔符与控制字符，空名回退
  const safeName = String(name || 'report.md')
    .replace(/[\\/:*?"<>|]/g, '_')
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1f\x7f]/g, '')
    .trim() || 'report.md';
  const { canceled, filePath } = await dialog.showSaveDialog(win, {
    title: '保存评估报告',
    defaultPath: path.join(app.getPath('documents'), safeName),
    filters: [
      { name: 'Markdown 报告', extensions: ['md'] },
      { name: '所有文件', extensions: ['*'] }
    ]
  });
  if (canceled || !filePath) return { ok: false, canceled: true };
  try {
    fs.writeFileSync(filePath, String(content || ''), 'utf8');
    return { ok: true, path: filePath };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

/* ---------- 生命周期 ---------- */
if (gotLock) {
  app.whenReady().then(() => {
    Menu.setApplicationMenu(null); // 去掉默认菜单栏，界面更接近原生应用
    createWindow();
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
