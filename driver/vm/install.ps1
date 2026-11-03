# Eseguito NELLA VM: installa e carica il driver VigilFlt (test-signed).
$ErrorActionPreference = 'Continue'
Get-ScheduledTask VigilRtd -ErrorAction SilentlyContinue | Stop-ScheduledTask
Stop-Process -Name vigil-rtd -Force -ErrorAction SilentlyContinue
fltmc unload VigilFlt 2>$null | Out-Null

Import-Certificate -FilePath C:\Vigil\VigilTest.cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath C:\Vigil\VigilTest.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
Copy-Item C:\Vigil\VigilFlt.sys C:\Windows\System32\drivers\VigilFlt.sys -Force

# Il servizio va creato come driver di file system (type= filesys): un servizio
# "normale" creato prima resterebbe in cache nel Gestore servizi fino al riavvio.
$existing = Get-CimInstance Win32_SystemDriver -Filter "Name='VigilFlt'" -ErrorAction SilentlyContinue
if (-not $existing) {
    if (Get-Service VigilFlt -ErrorAction SilentlyContinue) { sc.exe delete VigilFlt | Out-Null; Start-Sleep 2 }
    sc.exe create VigilFlt type= filesys start= demand error= normal binPath= "\SystemRoot\System32\drivers\VigilFlt.sys" group= "FSFilter Anti-Virus" depend= FltMgr DisplayName= "VigilFlt"
}
$svc = 'HKLM:\SYSTEM\CurrentControlSet\Services\VigilFlt'
Set-ItemProperty $svc -Name Group -Value 'FSFilter Anti-Virus'
Set-ItemProperty $svc -Name DependOnService -Value @('FltMgr') -Type MultiString
foreach ($base in $svc, "$svc\Parameters") {
    New-Item -Path "$base\Instances\VigilFlt Instance" -Force | Out-Null
    Set-ItemProperty "$base\Instances" -Name DefaultInstance -Value 'VigilFlt Instance'
    Set-ItemProperty "$base\Instances\VigilFlt Instance" -Name Altitude -Value '328500'
    Set-ItemProperty "$base\Instances\VigilFlt Instance" -Name Flags -Value 0 -Type DWord
}

"firma del driver: " + (Get-AuthenticodeSignature C:\Windows\System32\drivers\VigilFlt.sys).Status
fltmc load VigilFlt
"fltmc load: codice $LASTEXITCODE"
fltmc filters
fltmc instances -f VigilFlt
