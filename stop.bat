@echo off
REM Stop the auditor + the UI dev server started by start.bat.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\stop_all.ps1"
