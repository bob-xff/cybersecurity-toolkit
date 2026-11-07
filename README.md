# 网站网络安全评估工具

依据现行国内 / 国际网络安全标准，对企业网站进行**自动化安全评判**，输出评分、合规等级与针对性整改建议。

- 标准清单：[`docs/网站网络安全评估标准清单.md`](docs/网站网络安全评估标准清单.md)（V1.0，43 项自动化 + 20 项人工评估项）
- 评估引擎：[`core/`](core/)（零依赖 Node.js，桌面版与网页版共用）
- 两个版本：**网页版** [`web/`](web/) 与 **桌面版** [`desktop/`](desktop/)，同一引擎、同一标准映射、同一评分模型，结果一致。

---

## 1. 快速开始

### 方式一：一键启动（推荐，Windows 双击即用）

| 启动脚本 | 用途 |
|---|---|
| `启动网页版.bat` | 自动寻找空闲端口 → 启动服务 → 自动打开浏览器。关窗即停 |
| `启动桌面版.bat` | 首次运行自动安装 Electron（需联网），之后直接开窗 |
| `启动桌面版-免Node.bat` | 本机没装 Node.js 也能用（Electron 自带运行时） |
| `打包exe.bat` | 把桌面版打包成独立 exe，产出在 `dist/` 目录 |

### 方式零：已打包的 exe（无需 Node.js，双击即用）

`dist/` 目录已含构建产物，直接双击：

- `dist/网站网络安全评估工具-便携版.exe` —— **单文件便携版**（约 68 MB），拷到任何 Windows 电脑双击即用，不写注册表
- `dist/网站网络安全评估工具-安装版.exe` —— NSIS 安装向导版（可选安装目录、创建开始菜单/桌面快捷方式）
- `dist/win-unpacked/网站网络安全评估工具.exe` —— **绿色版**，免安装、免解包，直接双击内部 exe 即可启动（可整目录拷贝）

> 若 `dist/` 为空，双击 `打包exe.bat` 重新构建。打包逻辑在 `tools/pack-exe.js`：自建应用目录 + 本地离线工具链镜像 + electron-builder，全程约 2–4 分钟；首次需联网安装 Electron（约 100 MB）。

> 启动脚本均为纯 ASCII 批处理 + Node 引导器（`tools/`），避免中文代码页下批处理乱码；端口被占自动顺延（8901→8949）；服务带 30 分钟空闲自动退出，不会残留占端口。

### 方式二：命令行

**网页版**：

```bash
cd web
node server.js                # 默认 http://127.0.0.1:8080
# 可选参数：--port 9000 --host 127.0.0.1 --lib-limit 6 --concurrency 2 --open --idle-exit 30
#   --open       监听就绪后自动打开浏览器（仅对本机地址生效）
#   --idle-exit  空闲 N 分钟自动退出（0 = 禁用，默认 30）
```

浏览器打开 `http://127.0.0.1:8080/`，粘贴目标网址 → 开始评估。

<details>
<summary>运行配置（可选）：<code>SITESEC_*</code> 环境变量，无需改代码</summary>

所有超时、体积上限与并发数集中在 `core/config.js`，可用环境变量覆盖，弱网 / 内网 / 慢站按需调参：

| 变量 | 默认 | 含义 |
|---|---|---|
| `SITESEC_TIMEOUT_PAGE` | 15000 ms | 主页面抓取 |
| `SITESEC_TIMEOUT_REDIRECT` | 6000 ms | HTTP→HTTPS 跳转探测 |
| `SITESEC_TIMEOUT_TLS` | 6000 ms | 单次 TLS 握手 |
| `SITESEC_TIMEOUT_DNS` / `SITESEC_TIMEOUT_DOH` | 5000 / 5000 ms | 系统 DNS / 单个 DoH 端点 |
| `SITESEC_TIMEOUT_EXPOSURE` / `SITESEC_TIMEOUT_LIB` | 6000 / 6000 ms | 暴露面请求 / 外部脚本 |
| `SITESEC_LIMIT_MAXBODY` / `SITESEC_LIMIT_MAXDECOMPRESSED` | 1 MB / 4 MB | 压缩后 / 解压后响应体上限（防压缩炸弹） |
| `SITESEC_LIMIT_MAXREDIRECTS` / `SITESEC_LIMIT_MAXLIBFETCH` | 8 / 6 | 重定向链长度 / 外部脚本抓取数 |
| `SITESEC_LIMIT_QUEUEWAIT` | 120000 ms | 网页版并发排队最长等待（超时返回 503） |
| `SITESEC_CONCURRENCY_TLS` / `_EXPOSURE` / `_LIBS` | 4 / 6 / 3 | 三组探测并发度 |
| `SITESEC_LOG_LEVEL` | `warn` | `silent` / `error` / `warn` / `info` / `debug` |

结构化日志为单行 JSON、写 **stderr**（不污染 NDJSON 进度流与 JSON 报告），并自动剥离 URL 查询串；错误统一走 `core/errors.js` 的错误码模型（`INVALID_URL` / `TIMEOUT` / `BODY_TOO_LARGE` / …）。引擎入口 `core/index.js` 同时导出 `CONFIG`、`logger`、`errors`。

</details>

**桌面版**：

```bash
cd desktop
npm install                   # 安装 Electron（约 100MB+）
npm start                     # 启动桌面窗口（自动带 --disable-gpu，虚拟机/远程桌面也能开）
```

**打包为 exe（推荐一键脚本）**：

```bash
node tools/pack-exe.js               # 便携版 + 安装版，输出到 dist/
node tools/pack-exe.js --portable-only   # 只出便携版
node tools/pack-exe.js --no-mirror       # 不用本地镜像，走 GitHub 在线下载
```

> 为什么不直接 `npx electron-builder --win`：electron-builder 会在打包阶段复制 259 MB 的 Electron 运行时（在受限环境里容易长时间卡死），且需要从 GitHub 下载 NSIS 工具链（内网/受限网络会 `Get ...: EOF` 失败）。`tools/pack-exe.js` 把这两步替换为：
> 1. `tools/make-unpacked.js` —— 同步逐文件自建 `dist/win-unpacked`（实测 ~2 秒）；
> 2. `tools/bins-mirror.js` —— 用本机 electron-builder 缓存里的离线包起一个 127.0.0.1 临时镜像；
> 然后调用 `electron-builder --prepackaged` 只做最后的 exe 封装。镜像不可用时会自动回退到联网下载。

构建产物（`dist/`）：

| 文件 | 说明 |
|---|---|
| `网站网络安全评估工具-便携版.exe` | 单文件便携版（约 68 MB），免安装双击即用，可随意拷贝 |
| `网站网络安全评估工具-安装版.exe` | NSIS 安装向导，可选安装目录、创建开始菜单/桌面快捷方式 |
| `win-unpacked/` | 绿色版目录，免解包直接运行内部 exe |

应用图标由 `tools/make-icon.js` 零依赖生成，v2 造型为**浅粉圆角底 + 深玫瑰「盾牌 + 放大镜」**：盾牌对应安全防护 / 合规基线，放大镜对应检测、审查与发现隐患（而非「已通过」），零渐变、扁平化，16px 任务栏尺寸下仍可辨识。同源几何常量同时输出四份资源：`desktop/build/icon.ico`、`icon.png`、`logo.svg` 与 `ui/logo.svg`。便携版与安装版 exe 均已带此图标；页面顶部 logo 用内联 SVG、favicon 用 `ui/logo.svg`（无外部请求、随主题走）。内层可执行文件出于「不重写 exe 资源」的考虑仍保留 Electron 默认图标，但运行时窗口 / 任务栏图标由 `main.js` 显式指定为同一套图标。

> 打包为**未签名**构建（本地自用场景）。分发给他人时 Windows SmartScreen 会提示「未知发布者」，属正常现象；如需消除提示请自行购买代码签名证书后在 `package.json` 的 `build.win` 中配置 `sign` 或设置 `CSC_LINK` / `CSC_KEY_PASSWORD` 环境变量。

### 直接调用引擎（脚本 / 二次集成）

```js
const { assess, buildMarkdown } = require('./core');

assess('https://www.example.com').then((report) => {
  console.log(report.score, report.level.grade);   // 例如 69.2 'C'（分数随目标实际配置与网络环境变化）
  console.log(buildMarkdown(report));              // Markdown 报告
});
```

---

## 2. 评估模型

| 维度 | 代码 | 权重 | 覆盖内容（节选） |
|---|---|---|---|
| 传输与加密安全 | T | 25% | HTTPS 可用性、HSTS、TLS 版本 / 弱套件、证书有效期与密钥强度、HTTP→HTTPS 跳转 |
| 安全响应头 | H | 20% | CSP、HSTS、X-Frame-Options、X-Content-Type-Options、Referrer-Policy、Permissions-Policy、CORS |
| 内容与代码安全 | D | 15% | 内联脚本 / 事件处理器、混合内容、CSRF 令牌、敏感注释、CMS 与前端组件漏洞 |
| 信息暴露面 | E | 15% | .git/.env/.svn 等敏感路径、security.txt、目录列表、错误页泄露、TRACE/OPTIONS |
| Cookie 与会话 | C | 10% | Secure / HttpOnly / SameSite、会话固定要素 |
| DNS 与邮件安全 | N | 10% | SPF、DMARC、MX、CAA、DNSSEC |
| 隐私与合规 | P | 5% | ICP 备案号、隐私政策链接、表单密码框 autocomplete |

- **单项权重**：高危 3 / 中危 2 / 低危 1；单项得分：通过 1、警告 0.5、不通过 0，不适用与提示不计入。
- **综合等级**：A ≥ 90（优秀）、B 75–89（良好）、C 60–74（合格）、D 40–59（高风险）、E < 40（严重）。

## 3. 标准依据（现行版本，2026-10 核实）

- 国内：《网络安全法》（2025 修正，2026-01-01 施行）、《数据安全法》、《个人信息保护法》、GB/T 22239-2019（等保 2.0）、GB/T 35273-2020、GB/T 43698-2024、GB/T 42460-2023（IPv6 安全，按适用项映射）
- 国际：OWASP Top 10:2021、OWASP ASVS 5.0（2025-05）、ISO/IEC 27001:2022、CIS Controls v8.1、PCI DSS v4.0.1、RFC 9116（security.txt）、RFC 7489（DMARC）等

> 每一项检查的 `cnStandards` / `intlStandards` 字段均带标准映射，报告末尾有汇总，可逐条溯源。

## 4. 合规边界（重要）

工具**只做被动 / 低强度探测**：抓取公开页面、读取响应头、查询公开 DNS、对少量公开路径发 GET/OPTIONS/TRACE。**不注入、不爆破、不深探内网、不下载可执行文件**。

- 仅评估已获授权的目标。
- 网页版默认只监听 `127.0.0.1`。使用 `--host 0.0.0.0` 对外暴露时，服务端会按请求抓取任意 URL（SSRF 风险），必须先自行加访问控制。
- 桌面版通过 IPC 调用本机引擎，无网络暴露面。

## 5. 已知局限

- 协议 / 弱套件探测受**本机 OpenSSL 策略**限制（如 OpenSSL 3.x 默认禁用 TLS 1.0/1.1 探测），受影响项会标记 `limited` 并在报告中说明，不会伪装成"通过"。
- DNS 记录（SPF/DMARC/CAA/DNSSEC）查询以系统解析器为准；系统解析不可用时自动回退 DoH（阿里 / 腾讯 / Google，多端点合并取并集），报告中会注明走了 DoH。**查询失败与"确认无记录"严格区分**：前者相关检查项记为"无法检测"，不会误报为"未配置"。
- DNSSEC 仅依据区顶点 DNSKEY 是否存在判断，**未验证 DS 信任链与 RRSIG**；查到 DNSKEY 也只给 `info` 提示、不计分，无法确认时记为"不适用"。
- **「无法检测 / 不适用」≠「通过」**：页面不可达、响应非 HTML、探测被用户关闭或请求失败时，依赖该数据的检查项统一记为 `na` 并从评分分母中剔除，不会伪装成"通过"。这由 `core/standards.js` 的 `prerequisite()` 前置条件守卫统一兜底。
- 响应体按压缩后 1 MB / 解压后 4 MB 上限截断，正文扫描上限 256 KB、组件特征扫描 64 KB；超限会标记 `scanLimited` 并在报告 6.2 / 6.5 注明，超大页面可能漏检。
- WAF / CDN 会改变响应头与错误页表现，结果反映的是"边缘节点视角"。
- 前端组件漏洞库为高频高危库子集（阈值对照公开 CVE 公告），不等同于完整 SCA。
- 自动化项不能替代人工评估（见标准清单 M1–M20：供应链、备份恢复、应急响应、人员意识等）。

## 6. 目录结构

```
├── docs/          标准清单（V1.0）
├── core/          评估引擎
│   ├── config / errors / logger  集中配置 / 统一错误模型 / 结构化日志（横切基础设施）
│   ├── util / fetcher / tls / dnschk / content / libcheck / exposure   采集模块（内部，勿直接调用）
│   └── standards / engine / report   标准定义 / 编排评分 / 报告渲染（对外入口为 core/index.js）
├── ui/            共享前端（index.html / app.css / app.js / logo.svg），两个版本复用
├── web/           网页版：server.js（零依赖）+ package.json
├── desktop/       桌面版：main.js（Electron 主进程）+ preload.js（contextBridge）+ package.json
├── tools/         启动/打包引导器（launch-web.js / launch-desktop.js / pack-exe.js / make-unpacked.js / make-icon.js / bins-mirror.js）
├── dist/          打包输出（便携版 / 安装版 exe，由 打包exe.bat → tools/pack-exe.js 生成）
│   ├── 网站网络安全评估工具-便携版.exe      单文件便携版（NSIS 自解包，双击即用）
│   ├── 网站网络安全评估工具-安装版.exe      NSIS 安装向导
│   └── win-unpacked/                        绿色版目录（免安装，双击内部 exe 直接跑）
├── 启动网页版.bat / 启动桌面版.bat / 启动桌面版-免Node.bat / 打包exe.bat
└── test/          测试资产：本地靶站（故意作错配置）、单元/回归测试、IPC 冒烟、无头浏览器 UI 检查、验证截图（shots/）
```

测试资产说明：`test/` 下的本地靶站 `local-target.js` 会故意开启目录列表、暴露 .git/.env、返回 TRACE 200 等，**仅供本机验证引擎检出能力，用后请停止，不要常驻**（默认监听 `127.0.0.1:9911`）。

回归测试（均零依赖，直接 `node` 运行）：

| 测试 | 覆盖 |
|---|---|
| `node test/standards-unit-test.js` | 标准映射 / 评分模型 |
| `node test/vulndb-test.js` | 前端组件漏洞库比对 |
| `node test/report-sanitize-test.js` | 报告文本注入 / 转义 |
| `node test/dns-error-path-test.js` | DNS 查询失败与"确认无记录"的区分（零误报） |
| `node test/desktop-ipc-smoke.js` | 桌面版 IPC 参数透传 |
| `node test/fix-regression-test.js` | 早期 bug 回归 |
| `node test/round3-fix-test.js` | 重定向、rawRequest 兜底、TXT 归一化、generator 检测顺序、高级选项透传、TLS 端口取值 |
| `node test/optimization-test.js` | 本轮优化回归（63 项）：URL 边界、字符集 / 压缩炸弹、内容误报漏报、前置条件守卫、暴露面基址、并发容错、错误模型、报告章节 |
| `node test/ui-mock-server.js` | 确定性罐头报告服务（固定数据 + XSS 转义样本），供无头浏览器做结果态回归 |
| `node test/bench-compare.js` | 新旧 core 同目标耗时对比（性能基准） |
| `node test/compare-status.js` | 新旧引擎逐检查项状态 diff（数据兼容性核对） |
| `bash test/ui-browser-check.sh` | 无头浏览器端到端 UI 检查（logo / 统计磁贴筛选 / 证据卡片 / 高级选项生效） |

## 7. 界面与报告

**界面**（`ui/`，两个版本共用，粉色系 + 零渐变，简约布局）：

- **品牌与 logo**：v2 盾牌 + 放大镜造型（见第 1 节），favicon、顶栏、图标四份资源同源；语义是「检测发现隐患」而非「已通过」。
- **信息层级与可读性**：正文基准字号 14.5px，次级文字对比度提升，标题 / 证据 / 说明分层；长中文标签在窄屏不再撑破容器（flex 子项 `min-width:0` + `overflow-x:clip`）。
- **响应式**：1024 / 720 / 480 三档断点，顶栏、统计磁贴、筛选区、证据卡片逐级重排；另支持 `prefers-contrast: more`。
- **统计磁贴**：报告输出后顶部给出「不通过 / 警告 / 通过 / 不适用」四块计数，**点按即筛选**对应发现项，再点取消。
- **步骤导轨**：评估进行时逐段点亮（抓取 → 传输与加密 → 安全响应头 → 内容与代码 → 暴露面 → Cookie → DNS → 隐私合规 → 汇总），进度百分比与导轨同步。
- **技术栈证据卡片**：把 TLS / 证书、CMS / Generator、前端框架、ICP、前端组件漏洞库、SPF / DMARC 等**原始证据**可视化（chip + 组件行 + 可展开明细）；同时显示响应类型、页面编码、`scanLimited` 扫描限制与探测失败清单，与报告第六章一致。
- **无障碍与键盘**：发现项标题为 `<button>`，`Tab` 可聚焦、`Enter` / `Space` 折叠展开；全站 `:focus-visible` 焦点描边 + `skip-link` 跳至主内容 + ARIA 标注 + `<noscript>` 提示；筛选区滚动吸顶。
- 评分数字滚动动画、结果错落入场、toast 提示等动效均尊重 `prefers-reduced-motion`。
- **链接预填安全**：`?url=` 只预填输入框，**必须显式带 `&auto=1` 才会自动发起评估**，避免打开一个链接就在本机触发对任意地址的抓取（SSRF）。

**报告**：Markdown 报告含「**六、技术栈与探测证据**」章节（6.1 TLS 与证书 / 6.2 技术栈与前端组件 / 6.3 DNS 记录 / 6.4 敏感路径暴露面 / **6.5 检测范围与耗时**），原「说明与局限」顺延为「七」。6.5 逐段列出页面抓取、五路并行探测、TLS、暴露面、检查项计算与总耗时，便于判断结论置信度与复现性能。**JSON 导出与 Markdown 报告均含采集到的原始证据字段**，可逐条溯源、复核。

**高级选项**：「检测前端组件漏洞库」「检测敏感路径暴露面」两个开关**现已真正生效**——关闭后对应阶段跳过，并在报告中注明「已按用户设置跳过」，避免把"跳过"误读为"通过"。

**检测范围与前置条件**：报告会列出暴露面实际探测过的路径（`checked`）与失败请求（`failedRequests`）；页面不可达 / 非 HTML / 探测未完成时，相关检查项记为「无法检测 / 不适用」且不计入评分。判定规则集中在 `core/standards.js` 的 `prerequisite()`，覆盖依赖页面、内容与暴露面数据的全部检查项。

## 8. 常见问题

**Q：双击 `ui/index.html` 能直接用吗？**
不能。页面此时是 `file://` 直开模式，评估接口不可用——页面顶部会显示醒目横幅指引。请改用 `启动网页版.bat` 或 `启动桌面版.bat`。

**Q：点"开始评估"提示"无法连接本地评估服务"？**
说明服务没启动。运行 `启动网页版.bat`（或 `node web/server.js`）后刷新页面。浏览器地址应是 `http://127.0.0.1:端口/`，不是 `file:///...`。

**Q：端口被占用？**
启动器会自动顺延（8901→8902→…→8949），无需手动处理。

**Q：桌面版双击 `npm start` 没反应？**
虚拟机 / 远程桌面 / 无 GPU 环境下 Electron 可能被 GPU 进程崩溃直接杀死。本项目已内置 `--disable-gpu`；若仍无窗口，用 `启动桌面版-免Node.bat` 直接拉起 Electron 运行时。

**Q：打包出来的 exe 打开提示「Windows 已保护你的电脑 / 未知发布者」？**
本工具为本地自用场景，产物是**未签名**构建，SmartScreen 拦截属正常现象。点击「更多信息 → 仍要运行」即可。如需彻底消除提示，需购买代码签名证书后配置签名（见上文「打包为 exe」说明）。

**Q：打包卡住 / 报 `Get "https://github.com/...": EOF`？**
别直接用 `npx electron-builder --win`，用 `node tools/pack-exe.js`（或双击 `打包exe.bat`）。它会自建应用目录并启用本地离线工具链镜像，规避 electron-builder「复制 259MB Electron 时卡死」和「GitHub 下载 NSIS 被墙」两个坑。若本机缓存里缺 NSIS 离线包，脚本会自动回退联网下载。

**Q：exe 里面的可执行文件为什么还是 Electron 默认图标？**
打包时关闭了 exe 资源重写（本地自用、不签名，`build.win.signAndEditExecutable=false`），因此内层 `网站网络安全评估工具.exe` 文件图标保持默认；便携版/安装版 exe 图标、以及运行后的窗口/任务栏图标均已替换为本工具图标。

**Q：exe 版和网页版结果一样吗？**
一样。两个版本共用 `core/` 引擎与 `ui/` 前端，同一套标准映射与评分模型。

**Q：服务会一直占着端口吗？**
不会。服务空闲 30 分钟自动退出；关闭启动窗口（或 Ctrl+C）也会连同子服务一起停止。

## 9. 环境要求

- Node.js ≥ 18（开发用 v22 验证）
- 桌面版额外需要 Electron ≥ 31（npm install 自动处理；免 Node 启动方式除外）
