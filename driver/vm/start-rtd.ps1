# Eseguito NELLA VM: avvia vigil-rtd come SYSTEM (attività pianificata).
$ErrorActionPreference = 'Continue'
Remove-Item C:\Vigil\rtd.log -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c C:\Vigil\vigil-rtd.exe C:\Vigil\sigs > C:\Vigil\rtd.log 2>&1'
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries
Register-ScheduledTask -TaskName VigilRtd -Action $action -User 'SYSTEM' -RunLevel Highest -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName VigilRtd
for ($t = 0; $t -lt 90; $t++) {
    if (Select-String -Path C:\Vigil\rtd.log -Pattern 'collegato|errore' -Quiet -ErrorAction SilentlyContinue) { break }
    Start-Sleep 1
}
Get-Content C:\Vigil\rtd.log -ErrorAction SilentlyContinue
$info = Get-ScheduledTaskInfo -TaskName VigilRtd
"attività: stato {0}, ultimo esito 0x{1:X}" -f (Get-ScheduledTask VigilRtd).State, $info.LastTaskResult
"processo vigil-rtd: " + [bool](Get-Process vigil-rtd -ErrorAction SilentlyContinue)
