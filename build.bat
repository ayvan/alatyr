@echo off
rem Build alatyr.exe for this Windows machine (needs Go: https://go.dev/dl/)
cd /d "%~dp0"
set CGO_ENABLED=0
go build -trimpath -ldflags "-s -w" -o alatyr.exe .
if errorlevel 1 goto fail
go build -trimpath -ldflags "-s -w" -o awg-tester.exe .\cmd\awg-tester
if errorlevel 1 goto fail
echo Built alatyr.exe and awg-tester.exe
pause
exit /b 0
:fail
echo Build failed
pause
exit /b 1
