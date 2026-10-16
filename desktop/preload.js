'use strict';

/**
 * 桌面版 preload：以 contextBridge 向渲染层暴露最小能力面
 *  - assess(url, options)   调用 core 引擎执行评估（主进程侧）
 *      options: { detectLibs?: boolean, detectExposure?: boolean }
 *  - onProgress(cb)         接收阶段进度推送
 *  - offProgress()          取消进度监听
 *  - saveReport(name, text) 原生保存对话框写文件
 *  - getVersion()           工具版本号
 */
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('assessTool', {
  assess: (url, options) => ipcRenderer.invoke('assess', url, options || {}),
  onProgress: (cb) => {
    const handler = (_e, p) => cb(p);
    ipcRenderer.on('assess-progress', handler);
    // 返回退订函数，调用方可精确移除自己的监听
    return () => ipcRenderer.removeListener('assess-progress', handler);
  },
  offProgress: () => ipcRenderer.removeAllListeners('assess-progress'),
  saveReport: (name, content) => ipcRenderer.invoke('save-report', { name, content }),
  getVersion: () => ipcRenderer.invoke('get-version')
});
