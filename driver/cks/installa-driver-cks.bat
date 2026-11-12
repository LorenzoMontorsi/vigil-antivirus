@echo off
REM Installa VigilFlt via Custom Kernel Signers (vedi driver\CKS.md). Chiede l'amministratore (UAC).
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%ComSpec%' -ArgumentList '/c \"\"%~f0\" %*\"' -Verb RunAs"
    exit /b
)
set "DIR=%~1"
if "%DIR%"=="" set "DIR=%~dp0."
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installa-driver-cks.ps1" -Dir "%DIR%"
pause
