@echo off
rem Qwen Phone-Home Shield - double click to ENABLE the shield (asks for administrator rights)
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0QwenShield.ps1" -Action Enable
pause
