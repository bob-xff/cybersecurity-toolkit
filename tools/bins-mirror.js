#!/usr/bin/env node
/**
 * 本地二进制镜像（离线打包用）
 *
 * electron-builder 打包 Windows 目标时需从 GitHub 下载 NSIS 工具链；
 * 内网/受限网络下会失败（Get ...: EOF）。本脚本把 electron-builder
 * 缓存目录中已存在、且 sha512 已校验通过的 .7z 包，按 electron-builder
 * 期望的路径结构（/<name>-<ver>/<name>-<ver>.7z）暴露为本地 HTTP 镜像，
 * 配合 ELECTRON_BUILDER_BINARIES_MIRROR 即可完全离线完成打包。
 *
 * 用法:
 *   node tools/bins-mirror.js [cacheRoot] [port]
 *   cacheRoot 默认 %LOCALAPPDATA%\electron-builder\Cache
 *   port      默认 8732
 *
 * 之后:
 *   ELECTRON_BUILDER_BINARIES_MIRROR=http://127.0.0.1:8732/ npx electron-builder --win
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

const defaultRoot = path.join(
  process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'),
  'electron-builder', 'Cache'
);
const ROOT = path.resolve(process.argv[2] || defaultRoot);
const PORT = parseInt(process.argv[3] || '8732', 10);

const server = http.createServer((req, res) => {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, 'http://127.0.0.1').pathname);
  } catch {
    res.writeHead(400); return res.end('bad request');
  }
  const target = path.resolve(path.join(ROOT, pathname));
  if (!target.startsWith(ROOT + path.sep)) {
    res.writeHead(403); return res.end('forbidden');
  }
  fs.stat(target, (err, st) => {
    if (err || !st.isFile()) {
      process.stdout.write(`[mirror] 404 ${pathname}\n`);
      res.writeHead(404); return res.end('not found');
    }
    process.stdout.write(`[mirror] 200 ${pathname} (${st.size} bytes)\n`);
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': st.size,
    });
    fs.createReadStream(target).pipe(res);
  });
});

server.listen(PORT, '127.0.0.1', () => {
  process.stdout.write(`[mirror] serving ${ROOT}\n[mirror] http://127.0.0.1:${PORT}/\n`);
});

// 收到终止信号即退出（供脚本编排使用）
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { server.close(() => process.exit(0)); });
}
