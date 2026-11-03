# Eseguito NELLA VM: installa vigil-rtd come servizio Windows (VigilRtd) e lo avvia.
$ErrorActionPreference = 'Continue'
# Pulizia della vecchia modalità di prova (attività pianificata).
Get-ScheduledTask VigilRtd -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
Stop-Process -Name vigil-rtd -Force -ErrorAction SilentlyContinue

# Il servizio gira da una posizione stabile, non dalla cartella di copia.
$bin = 'C:\Program Files\Vigil'
New-Item -ItemType Directory -Force $bin | Out-Null
if (Get-Service VigilRtd -ErrorAction SilentlyContinue) { Stop-Service VigilRtd -Force -ErrorAction SilentlyContinue; Start-Sleep 2 }
Copy-Item C:\Vigil\vigil-rtd.exe "$bin\vigil-rtd.exe" -Force

& "$bin\vigil-rtd.exe" install --sigs C:\Vigil\sigs --quarantine C:\ProgramData\Vigil\quarantine --auto-quarantine
for ($t = 0; $t -lt 60; $t++) {
    $st = & "$bin\vigil-rtd.exe" status 2>$null | Out-String
    if ($st -match '"driver_connected": true') { break }
    Start-Sleep 1
}
Get-Service VigilRtd, VigilFlt | Format-Table Name, Status, StartType -AutoSize
& "$bin\vigil-rtd.exe" status
