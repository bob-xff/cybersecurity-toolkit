@echo off
chcp 437 >nul
rem ============================================================
rem  WebSec Assessment Tool - Desktop EXE packager
rem  Output: dist\*.exe  (portable single-file + NSIS installer)
rem  Logic lives in tools\pack-exe.js (kept in sync with the docs).
rem  NOTE: keep this file ASCII-only (GBK code page garbles CJK).
rem ============================================================
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js not found. Please install Node.js ^(^>=18^) first.
  pause
  exit /b 1
)

echo Packing desktop exe ^(portable + installer^), please wait...
echo This may take a few minutes on the first run.
echo.
call node tools\pack-exe.js
if errorlevel 1 (
  echo.
  echo [ERROR] Build failed. See messages above.
  pause
  exit /b 1
)

echo.
echo ============================================================
echo  DONE. Output folder: %~dp0dist
dir /b "%~dp0dist\*.exe"
echo ============================================================
pause
