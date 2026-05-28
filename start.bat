@echo off
REM One-click launcher for the AI Auditor demo (backend + UI).
REM Opens two console windows: one for the auditor, one for the UI dev server.
REM Close those windows (or run stop.bat) to stop everything.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\start_all.ps1"
if errorlevel 1 (
  echo.
  echo Launcher exited with an error. Press any key to close.
  pause >nul
)
