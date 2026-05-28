@echo off
REM Wipe per-run demo data (flags, incidents, verdicts, events, runs, audit log).
REM Keeps tenants, users, policies, sampler config. Safe to run while the auditor is up.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-Location '%~dp0'; & '.\.venv\Scripts\python.exe' scripts\wipe_run_data.py"
