# Eseguito NELLA VM (amministratore): esegue uno script come utente "vigil" NON elevato,
# nella sua sessione interattiva, e ne restituisce l'output. Serve a verificare cosa
# vede un utente normale (permessi, registro HKCU…).
param([Parameter(Mandatory)][string]$Script)
$out = 'C:\Vigil\as-user.txt'
Remove-Item $out -ErrorAction SilentlyContinue
$cmd = "& { $Script } *>&1 | Out-File -FilePath '$out' -Encoding utf8"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $enc"
$principal = New-ScheduledTaskPrincipal -UserId 'vigil' -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName VigilAsUser -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName VigilAsUser
for ($i = 0; $i -lt 30 -and -not (Test-Path $out); $i++) { Start-Sleep -Milliseconds 500 }
Start-Sleep 1
if (Test-Path $out) { Get-Content $out } else { 'nessun output' }
