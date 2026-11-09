@echo off
rem Allow alatyr.exe through Windows Firewall (inbound, all its ports).
rem Run once. Asks for administrator rights. "firewall-allow.bat remove" deletes the rule.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%1' -Verb RunAs"
  exit /b
)
netsh advfirewall firewall delete rule name="re-vpnator" >nul 2>&1
netsh advfirewall firewall delete rule name="alatyr" >nul 2>&1
if /i "%1"=="remove" (
  echo Firewall rule "alatyr" removed.
  pause
  exit /b 0
)
netsh advfirewall firewall add rule name="alatyr" dir=in action=allow program="%~dp0alatyr.exe" enable=yes profile=any
if errorlevel 1 (
  echo Failed to add firewall rule.
) else (
  echo Firewall rule "alatyr" added for %~dp0alatyr.exe
)
pause
