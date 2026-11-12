@echo off
REM Attiva il test-signing e installa VigilFlt. Chiede da solo l'amministratore (UAC).
REM I file del driver (VigilFlt.sys, VigilKernelSigner.cer) stanno in questa cartella,
REM oppure passa la cartella come primo argomento.
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%ComSpec%' -ArgumentList '/c \"\"%~f0\" %*\"' -Verb RunAs"
    exit /b
)
set "DIR=%~1"
if "%DIR%"=="" set "DIR=%~dp0."
echo [1/2] bcdedit /set testsigning on
bcdedit /set testsigning on
echo [2/2] installo il driver da "%DIR%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installa-driver-testsigning.ps1" -Dir "%DIR%"
echo.
echo Se e' la prima volta, riavvia Windows; poi verifica con: fltmc filters
pause
