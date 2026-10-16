'use strict';

/**
 * 桌面版 IPC 冒烟测试（无需 GUI）：
 * mock 'electron' 模块 → require desktop/main.js → 触发各 ipcMain.handle 处理器
 * 验证：get-version / assess（含进度推送）/ save-report（取消路径）
 */
const path = require('path');
const Module = require('module');

const sent = [];       // win.webContents.send 记录
let savedFile = null;  // fs.writeFileSync 记录

const created = [];    // BrowserWindow 实例记录
const fakeWin = {
  isDestroyed: () => false,
  webContents: { send: (ch, payload) => sent.push({ ch, payload }) },
  loadFile: (p) => { fakeWin.loadedFile = p; }
};

const handlers = {};
const mockElectron = {
  app: {
    whenReady: () => Promise.resolve(),
    disableHardwareAcceleration: () => {},
    requestSingleInstanceLock: () => true,
    on: () => {},
    getPath: () => 'C:\\Users\\test\\Documents',
    quit: () => {}
  },
  BrowserWindow: class {
    constructor(opts) {
      this.opts = opts;
      this.webContents = { setWindowOpenHandler: () => {}, send: () => {} };
      created.push(this);
    }
    loadFile(p) { fakeWin.loadedFile = p; }
    static fromWebContents() { return fakeWin; }
    static getAllWindows() { return []; }
  },
  ipcMain: {
    handle: (ch, fn) => { handlers[ch] = fn; }
  },
  dialog: {
    showSaveDialog: async () => ({ canceled: true }) // 模拟用户取消
  },
  Menu: { setApplicationMenu: () => {} },
  shell: { openExternal: () => {} }
};

// 拦截 require('electron')
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'electron') return mockElectron;
  return origLoad.apply(this, arguments);
};

// 拦截 fs.writeFileSync（save-report 成功路径另测）
const origWrite = require('fs').writeFileSync;
require('fs').writeFileSync = (p, data) => { savedFile = { p, len: String(data).length }; };

(async () => {
  require(path.join(__dirname, '..', 'desktop', 'main.js'));
  await new Promise((r) => setTimeout(r, 50));

  const results = [];
  const ok = (name, cond, extra) => results.push((cond ? 'PASS' : 'FAIL') + ' ' + name + (extra ? ' | ' + extra : ''));

  // 1. 处理器注册
  ok('handlers registered', ['get-version', 'assess', 'save-report'].every((h) => typeof handlers[h] === 'function'),
    Object.keys(handlers).join(','));

  // 2. get-version
  const ver = await handlers['get-version']();
  ok('get-version', ver === '1.0.0', 'v=' + ver);

  // 3. assess（真实调用 core 引擎，目标是本地靶站）
  const fakeEvent = { sender: {} };
  const report = await handlers['assess'](fakeEvent, 'http://127.0.0.1:9911');
  ok('assess returns report', !!(report && report.ok === true), 'score=' + (report && report.score));
  ok('assess grade', report && report.level.grade === 'E', 'grade=' + (report && report.level.grade));
  ok('assess checks count', report && report.checks.length === 43, 'n=' + (report && report.checks.length));
  ok('assess markdown', typeof report.markdown === 'string' && report.markdown.length > 500, 'len=' + (report && report.markdown && report.markdown.length));
  ok('progress pushed via IPC', sent.length >= 8 && sent.every((s) => s.ch === 'assess-progress'),
    'events=' + sent.length + ' last=' + (sent[sent.length - 1] && sent[sent.length - 1].payload.step));
  ok('window loaded shared UI', fakeWin.loadedFile && /ui[\\/]index\.html$/.test(fakeWin.loadedFile), fakeWin.loadedFile);
  ok('contextIsolation on', created.length > 0 && created[0].opts.webPreferences.contextIsolation === true,
    created.length ? JSON.stringify(created[0].opts.webPreferences) : 'no window');

  // 4. assess 空参数防护
  const bad = await handlers['assess'](fakeEvent, '   ');
  ok('assess rejects empty url', bad && bad.ok === false && /url/.test(bad.error), bad && bad.error);

  // 5. save-report 取消路径（不写文件）
  const canceled = await handlers['save-report'](fakeEvent, { name: 'x.md', content: 'hello' });
  ok('save-report cancel path', canceled && canceled.ok === false && canceled.canceled === true && savedFile === null,
    JSON.stringify(canceled));

  // 6. save-report 成功路径（改 mock 为确认）
  mockElectron.dialog.showSaveDialog = async () => ({ canceled: false, filePath: 'C:\\Users\\test\\Documents\\r.md' });
  const saved = await handlers['save-report'](fakeEvent, { name: '安全评估报告_x.md', content: '# report body' });
  ok('save-report writes file', saved && saved.ok === true && savedFile && savedFile.p.endsWith('r.md') && savedFile.len === 13,
    JSON.stringify(saved) + ' file=' + (savedFile && savedFile.p));

  // 恢复
  require('fs').writeFileSync = origWrite;
  Module._load = origLoad;

  console.log(results.join('\n'));
  const fails = results.filter((r) => r.startsWith('FAIL')).length;
  console.log('---');
  console.log(fails === 0 ? 'ALL PASS (' + results.length + ')' : fails + ' FAILED');
  process.exit(fails === 0 ? 0 : 1);
})().catch((e) => { console.error('SMOKE ERROR', e); process.exit(1); });
