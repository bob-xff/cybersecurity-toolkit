@echo off
rem ============================================
rem  网站网络安全评估工具 - 桌面版（免 Node 便携启动）
rem  适用于本机未安装 Node.js 的环境：
rem  Electron 自带 Node 运行时，无需系统 Node。
rem ============================================
setlocal
cd /d "%~dp0"

if exist "desktop\node_modules\electron\dist\electron.exe" (
  echo Starting desktop app (portable mode, no Node.js required)...
  start "" "desktop\node_modules\electron\dist\electron.exe" desktop --disable-gpu
  echo Done. If no window appears within 10 seconds, use the other
  echo launcher "启动桌面版.bat" instead (requires internet for first run).
) else (
  echo [ERROR] Electron runtime not found: desktop\node_modules\electron\dist\electron.exe
  echo This copy is incomplete. Please use "启动桌面版.bat"
  echo (it downloads Electron on first run, needs internet).
)
echo.
pause
