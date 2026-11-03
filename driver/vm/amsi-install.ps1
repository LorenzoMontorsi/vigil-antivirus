# Eseguito NELLA VM (amministratore): registra il provider AMSI di Vigil.
# Windows caricherà vigil_amsi.dll in ogni processo che usa AMSI (i processi già
# aperti non lo vedono: vale per i nuovi PowerShell, script, ecc.).
param([switch]$Uninstall)
$ErrorActionPreference = 'Continue'
$clsid = '{2B9E6E0B-5D1A-4C51-9E3B-7A1D2C4F8E61}'
$bin = 'C:\Program Files\Vigil'
$dll = Join-Path $bin 'vigil_amsi.dll'
$classKey = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
$providerKey = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\$clsid"

if ($Uninstall) {
    Remove-Item $providerKey -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $classKey -Recurse -Force -ErrorAction SilentlyContinue
    'provider AMSI rimosso (la DLL resta caricata nei processi già aperti)'
    return
}

New-Item -ItemType Directory -Force $bin | Out-Null
# Con l'autodifesa attiva, in Program Files\Vigil scrive solo il servizio: va fermato per aggiornare.
$svc = Get-Service VigilRtd -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') { Stop-Service VigilRtd -Force; Start-Sleep 2 }
# La DLL può essere in uso dai processi aperti: in quel caso si rinomina la vecchia.
if (Test-Path $dll) { Rename-Item $dll "vigil_amsi.$([DateTime]::Now.Ticks).old" -ErrorAction SilentlyContinue }
Copy-Item C:\Vigil\vigil_amsi.dll $dll -Force
'firma della DLL: ' + (Get-AuthenticodeSignature $dll).Status

New-Item -Path "$classKey\InprocServer32" -Force | Out-Null
Set-ItemProperty $classKey -Name '(default)' -Value 'Vigil AMSI Provider'
Set-ItemProperty "$classKey\InprocServer32" -Name '(default)' -Value $dll
Set-ItemProperty "$classKey\InprocServer32" -Name 'ThreadingModel' -Value 'Both'
New-Item -Path $providerKey -Force | Out-Null
Set-ItemProperty $providerKey -Name '(default)' -Value 'Vigil AMSI Provider'
'provider AMSI registrato: ' + $clsid
if ($svc) { Start-Service VigilRtd }
