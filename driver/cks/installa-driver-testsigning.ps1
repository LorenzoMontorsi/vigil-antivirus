<#
  Installa il driver VigilFlt con il test-signing di Windows (niente UEFI, niente SiPolicy, niente SSDE).
  Esegui come AMMINISTRATORE (o con installa-driver-testsigning.bat, che attiva anche il test-signing).
  Il test-signing vale solo dopo un riavvio; sul desktop compare la scritta "Modalita test".

  -Dir deve contenere: VigilFlt.sys e VigilKernelSigner.cer (o il .cer con cui e' firmato il driver).
#>
param([string]$Dir = $PSScriptRoot, [string]$Cer = 'VigilKernelSigner.cer')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_comune.ps1')
Assert-VigilAdmin

$sys = Join-Path $Dir 'VigilFlt.sys'
$cerPath = Join-Path $Dir $Cer
foreach ($f in $sys, $cerPath) { if (-not (Test-Path $f)) { throw "manca $f" } }

Add-VigilTrustedCert $cerPath
Register-VigilFlt $sys 'boot'

# Se il test-signing e' gia' attivo il driver si carica subito, altrimenti dopo il riavvio.
& fltmc.exe load VigilFlt 2>&1 | Out-Host
if ($LASTEXITCODE -eq 0) { Write-Host 'VigilFlt caricato.' }
else { Write-Host 'VigilFlt non caricato ora: riavvia (serve "bcdedit /set testsigning on" attivo).' }
