@echo off
rem Start alatyr in a console window (manual start). Ctrl+C to stop.
cd /d "%~dp0"
alatyr.exe --config config.yaml
if errorlevel 1 pause
