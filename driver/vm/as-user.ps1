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
# Aspetta che l'attività finisca davvero (non solo che il file compaia).
for ($i = 0; $i -lt 120; $i++) {
    Start-Sleep -Milliseconds 500
    if ((Get-ScheduledTask -TaskName VigilAsUser).State -ne 'Running' -and (Test-Path $out)) { break }
}
if (Test-Path $out) { Get-Content $out } else { 'nessun output' }
