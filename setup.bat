@echo off
REM First-time setup for a fresh clone (Windows). One-shot - runs both bootstrap and init.
REM Idempotent: re-running on an existing checkout reinstalls deps and re-applies migrations.
REM
REM After this finishes successfully, use start.bat to launch the demo every day.
powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%~dp0scripts\windows\bootstrap.ps1'; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & '%~dp0scripts\windows\init.ps1'"
if errorlevel 1 (
  echo.
  echo Setup failed - scroll up for the error. Press any key to close.
  pause >nul
  exit /b 1
)
echo.
echo ================================================================
echo  Setup complete. Run start.bat to launch the demo.
echo ================================================================
echo.
pause
