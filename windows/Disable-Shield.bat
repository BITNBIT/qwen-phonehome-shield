@echo off
rem Qwen Phone-Home Shield - double click to DISABLE the shield (removes everything it added)
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0QwenShield.ps1" -Action Disable
pause
