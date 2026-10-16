'use strict';

/**
 * 网页版启动器（由「启动网页版.bat」调用，也可直接 node tools/launch-web.js）
 *  - 自动寻找空闲端口（默认 8901，被占则顺延至 8949）
 *  - 前台启动 web/server.js（关闭本窗口即停止服务）
 *  - 服务就绪后自动打开浏览器（--open）
 */
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SERVER = path.join(ROOT, 'web', 'server.js');

function findPort(start, end) {
  return new Promise((resolve, reject) => {
    if (start > end) return reject(new Error('端口 ' + '8901-' + end + ' 全部被占用'));
    const srv = net.createServer();
    srv.once('error', () => {
      srv.close(() => findPort(start + 1, end).then(resolve, reject));
    });
    srv.once('listening', () => srv.close(() => resolve(start)));
    srv.listen(start, '127.0.0.1');
  });
}

(async () => {
  let port;
  try {
    port = await findPort(8901, 8949);
  } catch (e) {
    console.error('[错误] ' + e.message + '，请释放端口后重试。');
    process.exit(1);
  }
  if (port !== 8901) console.log('[提示] 8901 已被占用，自动改用端口 ' + port);

  console.log('============================================');
  console.log('  网站网络安全评估工具 · 网页版');
  console.log('============================================');
  console.log('  访问地址: http://127.0.0.1:' + port + '/');
  console.log('  关闭本窗口 = 停止服务（或按 Ctrl+C）');
  console.log('============================================');
  console.log('');

  const child = spawn(process.execPath, [SERVER, '--port', String(port), '--lib-limit', '6', '--open'], {
    cwd: path.join(ROOT, 'web'),
    stdio: 'inherit',
  });
  child.on('exit', (code) => process.exit(code == null ? 0 : code));
  child.on('error', (e) => {
    console.error('[错误] 服务启动失败：' + e.message);
    process.exit(1);
  });
  /* 父进程收到终止信号时一并结束子进程，避免服务残留 */
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => { try { child.kill(sig); } catch (e) { /* ignore */ } });
  }
})().catch((e) => {
  console.error('[错误] ' + (e && e.message ? e.message : String(e)));
  process.exit(1);
});
