@echo off
REM ====================================================================
REM  Vigil: installa e registra il provider AMSI (vigil_amsi.dll)
REM  Chiede da solo l'amministratore (UAC).
REM
REM  Il provider interroga il servizio VigilRtd: prima va installato
REM  con installa-servizio-rtd.bat, altrimenti gli script passano
REM  senza controllo (fail-open).
REM ====================================================================
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%ComSpec%' -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

set "SRC=%~dp0vigil_amsi.dll"
set "BIN=%ProgramFiles%\Vigil"
set "DLL=%BIN%\vigil_amsi.dll"
set "CLSID={2B9E6E0B-5D1A-4C51-9E3B-7A1D2C4F8E61}"

echo === Vigil: installazione provider AMSI ===
echo.
echo Il provider chiede il verdetto al servizio VigilRtd:
echo se non l'hai ancora fatto, lancia prima installa-servizio-rtd.bat.
echo.

if not exist "%SRC%" (
    echo ERRORE: manca "%SRC%"
    echo Metti vigil_amsi.dll nella stessa cartella di questo .bat.
    pause & exit /b 1
)

echo [1] Fermo VigilRtd (se e' in esecuzione) per poter copiare la DLL...
sc query VigilRtd >nul 2>&1
if %errorlevel%==0 (
    sc stop VigilRtd
    ping -n 3 127.0.0.1 >nul
) else (
    echo Servizio VigilRtd non trovato: si prosegue comunque con la DLL.
)
echo.

if not exist "%BIN%" mkdir "%BIN%"

echo [2] Copio vigil_amsi.dll in "%BIN%"...
if exist "%DLL%" (
    del /f /q "%DLL%.old" >nul 2>&1
    ren "%DLL%" "vigil_amsi.dll.old" >nul 2>&1
    if exist "%DLL%" (
        echo ATTENZIONE: la DLL e' in uso, provo a sovrascrivere comunque.
    )
)
copy /y "%SRC%" "%DLL%"
if %errorlevel% neq 0 (
    echo ERRORE: copia non riuscita. Chiudi PowerShell, Office e WScript e riprova.
    pause & exit /b 1
)
echo.

echo [3] Registro il CLSID e il provider AMSI...
reg add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%" /ve /t REG_SZ /d "Vigil AMSI Provider" /f
if %errorlevel% neq 0 (
    echo ERRORE: scrittura registro CLSID non riuscita.
    pause & exit /b 1
)
reg add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%\InprocServer32" /ve /t REG_SZ /d "%DLL%" /f
reg add "HKLM\SOFTWARE\Classes\CLSID\%CLSID%\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both" /f
reg add "HKLM\SOFTWARE\Microsoft\AMSI\Providers\%CLSID%" /ve /t REG_SZ /d "Vigil AMSI Provider" /f
if %errorlevel% neq 0 (
    echo ERRORE: scrittura registro AMSI\Providers non riuscita.
    pause & exit /b 1
)
echo.

echo [4] Riavvio VigilRtd (se il servizio esiste)...
sc query VigilRtd >nul 2>&1
if %errorlevel%==0 (
    sc start VigilRtd
) else (
    echo ATTENZIONE: il servizio VigilRtd non e' installato.
    echo Installa prima il servizio con installa-servizio-rtd.bat:
    echo senza di esso gli script non vengono analizzati.
)
echo.

echo [5] Chiavi del provider:
echo.
reg query "HKLM\SOFTWARE\Classes\CLSID\%CLSID%" /s
echo.
reg query "HKLM\SOFTWARE\Microsoft\AMSI\Providers\%CLSID%"
echo.
echo Nota: solo le nuove finestre di PowerShell (e i nuovi processi)
echo useranno il provider. Chiudi e riapri PowerShell / Office / WScript.
echo Poi riapri Vigil: "Protezione script (AMSI)" dovrebbe risultare attiva
echo se anche VigilRtd e' in esecuzione.
echo.
pause
