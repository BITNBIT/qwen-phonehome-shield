@echo off
rem Qwen Phone-Home Shield - guarded AI programs, allowed and blocked sites, log (asks for administrator rights)
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0QwenShield.ps1" -Action Manage
