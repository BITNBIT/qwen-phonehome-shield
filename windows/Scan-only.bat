@echo off
rem Qwen Phone-Home Shield - only checks which Qwen3.8 models are on this PC (changes nothing, no admin needed)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0QwenShield.ps1" -Action Scan
pause
