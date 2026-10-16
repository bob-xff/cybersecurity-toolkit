@echo off
rem ============================================
rem  网站网络安全评估工具 - 网页版启动器
rem  本文件保持纯 ASCII（避免中文 Windows 代码页下批处理解析乱码）
rem  全部引导逻辑在 tools\launch-web.js
rem ============================================
setlocal
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  if exist "C:\Program Files\nodejs\node.exe" set "PATH=C:\Program Files\nodejs;%PATH%"
)
where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js not found.
  echo Please install Node.js 18 or newer: https://nodejs.org/
  echo Then double-click this file again.
  echo.
  pause
  exit /b 1
)

node "tools\launch-web.js"
pause
