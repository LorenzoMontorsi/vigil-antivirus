# Eseguito NELLA VM (amministratore): installa l'app Vigil e la avvia nella sessione
# interattiva dell'utente "vigil", come se l'avesse aperta lui.
$ErrorActionPreference = 'Continue'

# 1. Runtime WebView2 (serve all'interfaccia). Su Windows 10 può mancare.
$wv = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
if (-not (Get-ItemProperty $wv -ErrorAction SilentlyContinue).pv) {
    'WebView2 assente: installazione in corso...'
    $setup = Join-Path $env:TEMP 'MicrosoftEdgeWebview2Setup.exe'
    Invoke-WebRequest -UseBasicParsing 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $setup
    Start-Process $setup -ArgumentList '/silent', '/install' -Wait
}
'WebView2: ' + (Get-ItemProperty $wv -ErrorAction SilentlyContinue).pv

# 2. App
$bin = 'C:\Program Files\Vigil'
New-Item -ItemType Directory -Force $bin | Out-Null
Get-Process Vigil -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 1
Copy-Item C:\Vigil\Vigil.exe "$bin\Vigil.exe" -Force

# 3. Avvio nella sessione interattiva dell'utente (non in quella di SSH, che non ha desktop).
$action = New-ScheduledTaskAction -Execute "$bin\Vigil.exe"
$principal = New-ScheduledTaskPrincipal -UserId 'vigil' -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName VigilApp -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName VigilApp
Start-Sleep 6
'app in esecuzione: ' + [bool](Get-Process Vigil -ErrorAction SilentlyContinue)
