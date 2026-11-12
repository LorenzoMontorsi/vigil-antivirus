@echo off
REM ====================================================================
REM  Vigil: installa il servizio VigilRtd (protezione in tempo reale)
REM  e riporta il driver VigilFlt all'altitudine del progetto (328500).
REM  Chiede da solo l'amministratore (UAC).
REM ====================================================================
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%ComSpec%' -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

set "SRC=%~dp0vigil-rtd.exe"
set "BIN=%ProgramFiles%\Vigil"
set "EXE=%BIN%\vigil-rtd.exe"
set "SIGS=%APPDATA%\dev.lorenzo.antivirus\signatures"
set "FEEDS=%APPDATA%\dev.lorenzo.antivirus\feeds"
set "QUAR=%ProgramData%\Vigil\quarantine"
set "SVC=HKLM\SYSTEM\CurrentControlSet\Services\VigilFlt"

if not exist "%SRC%" (
    echo ERRORE: manca "%SRC%"
    pause & exit /b 1
)

echo [1] Fermo VigilRtd (se c'e') e copio vigil-rtd.exe in "%BIN%"...
sc stop VigilRtd >nul 2>&1
ping -n 3 127.0.0.1 >nul
if not exist "%BIN%" mkdir "%BIN%"
copy /y "%SRC%" "%EXE%"
if %errorlevel% neq 0 (
    echo ERRORE: copia non riuscita.
    pause & exit /b 1
)
echo.

echo [2] VigilFlt: gruppo "FSFilter Anti-Virus", altitudine 328500...
sc config VigilFlt group= "FSFilter Anti-Virus"
for %%K in ("%SVC%\Instances" "%SVC%\Parameters\Instances") do (
    reg add %%K /v DefaultInstance /t REG_SZ /d "VigilFlt Instance" /f >nul
    reg add "%%~K\VigilFlt Instance" /v Altitude /t REG_SZ /d 328500 /f >nul
    reg add "%%~K\VigilFlt Instance" /v Flags /t REG_DWORD /d 0 /f >nul
)
echo.

echo [3] Ricarico il driver...
fltmc unload VigilFlt
fltmc load VigilFlt
echo.

echo [4] Installo e avvio il servizio VigilRtd...
if not exist "%QUAR%" mkdir "%QUAR%"
"%EXE%" install --sigs "%FEEDS%" --sigs "%SIGS%" --quarantine "%QUAR%" --auto-quarantine
sc start VigilRtd >nul 2>&1
ping -n 4 127.0.0.1 >nul
echo.

echo [5] Stato:
sc query VigilRtd
fltmc filters
"%EXE%" status
echo.
pause
