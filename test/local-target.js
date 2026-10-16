'use strict';

/**
 * 本地低安全靶站（仅用于测试引擎检出能力）：
 * HTTP only、无安全头、内联事件、混合内容、无 CSRF 表单、
 * 弱 Cookie、敏感注释、伪造旧版 jQuery、/.git/config、/.env、
 * 开启 TRACE、目录列表、404 泄露堆栈。
 */
const http = require('http');

const PORT = parseInt(process.argv[2] || '9911', 10);

const HTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Insecure Test Target</title>
<!-- Index of /var/www/html (autoindex on) -->
<!-- TODO: remove before production. db password: SuperSecret123 admin/123456 -->
<link rel="stylesheet" href="http://127.0.0.1:${PORT}/style.css">
</head>
<body onload="initApp()">
<h1>Insecure Test Target</h1>
<img src="http://127.0.0.1:${PORT}/logo.png" alt="logo">
<a href="http://example.com/" target="_blank">external</a>
<form action="/login" method="post">
  <input type="text" name="user">
  <input type="password" name="pass" autocomplete="on">
  <input type="submit" value="login">
</form>
<script src="http://127.0.0.1:${PORT}/jquery-1.12.4.min.js"></script>
<script>var API_KEY = "sk-live-abcdef123456"; function initApp(){ document.title = "app"; }</script>
<script src="/app.js"></script>
</body>
</html>`;

const JQUERY_OLD = `/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */
(function(global,factory){...})(window);`;

const server = http.createServer((req, res) => {
  const u = req.url.split('?')[0];
  const set = (k, v) => res.setHeader(k, v);

  if (req.method === 'TRACE') {
    res.writeHead(200, { 'Content-Type': 'message/http' });
    res.end('TRACE enabled');
    return;
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(200, { 'Allow': 'GET,HEAD,POST,OPTIONS,TRACE', 'Access-Control-Allow-Origin': '*' });
    res.end();
    return;
  }

  switch (u) {
    case '/':
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Server': 'Apache/2.4.49 (Unix)',
        'X-Powered-By': 'PHP/7.4.3'
      });
      res.end(HTML);
      return;
    case '/jquery-1.12.4.min.js':
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end(JQUERY_OLD);
      return;
    case '/app.js':
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end('function initApp(){}');
      return;
    case '/style.css':
      res.writeHead(200, { 'Content-Type': 'text/css' });
      res.end('body{color:red}');
      return;
    case '/.git/config':
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:acme/app.git\n');
      return;
    case '/.env':
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('DB_PASSWORD=SuperSecret123\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG\n');
      return;
    case '/list/':
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<html><head><title>Index of /list/</title></head><body><h1>Index of /list/</h1><a href="backup.zip">backup.zip</a></body></html>');
      return;
    case '/login':
      if (req.method === 'POST') {
        res.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': 'session=abc123; Path=/' });
        res.end('<html><body>ok</body></html>');
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end('<html><body>404 - /login<br>Error: at Object.login (/srv/app/routes/user.js:42:15)<br>at Layer.handle (express/lib/router/layer.js:95:5)</body></html>');
      return;
    default:
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>404 Not Found</h1><pre>Traceback (most recent call last):\n  File "/srv/app/server.py", line 128, in handler\n    raise RuntimeError("boom")\nRuntimeError: boom</pre></body></html>');
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('insecure target listening on http://127.0.0.1:' + PORT);
});
