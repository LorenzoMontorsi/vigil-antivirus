<#
  Installa il driver VigilFlt su Windows 10/11 con Secure Boot ACCESO e SENZA test-signing,
  tramite i Custom Kernel Signers (CKS). Esegui come AMMINISTRATORE (o con installa-driver-cks.bat).

  Prima di questo script, UNA VOLTA SOLA su questo PC, arruola la Platform Key di Vigil nel firmware:
    riavvia in UEFI/BIOS -> Secure Boot -> Key Management -> enroll  VigilPlatformKey.cer  come PK
    (il menu varia per marca). Senza questo passo CKS non puo' fidarsi della policy.
  Procedura completa e avvertenze: driver\CKS.md.

  -Dir deve contenere: VigilFlt.sys, SiPolicy.p7b, VigilKernelSigner.cer
  e una sottocartella  ssde\  con SSDE (https://github.com/valinet/ssde) per Win11,
  oppure gli strumenti HyperSine per Win10 (https://github.com/HyperSine/Windows10-CustomKernelSigners).
  Se non vuoi toccare UEFI usa installa-driver-testsigning.ps1.
#>
param([string]$Dir = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_comune.ps1')
Assert-VigilAdmin

$sys = Join-Path $Dir 'VigilFlt.sys'
$p7b = Join-Path $Dir 'SiPolicy.p7b'
$cer = Join-Path $Dir 'VigilKernelSigner.cer'
foreach ($f in $sys, $p7b, $cer) { if (-not (Test-Path $f)) { throw "manca $f" } }

try {
    if (-not (Confirm-SecureBootUEFI)) {
        Write-Warning 'Secure Boot non attivo: su questo PC basta installa-driver-testsigning.ps1.'
    }
} catch {
    Write-Warning "Confirm-SecureBootUEFI non disponibile: $_"
}

# 1) Rendi fidato il firmatario del driver.
Add-VigilTrustedCert $cer

# 2) Deposita la policy CKS firmata nella partizione EFI.
$efi = 'S:'
if (-not (Test-Path "$efi\")) { mountvol $efi /S }
$dest = "$efi\EFI\Microsoft\Boot"
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item $p7b (Join-Path $dest 'SiPolicy.p7b') -Force
Write-Host "[2] SiPolicy.p7b copiata in $dest."

# 3) Abilita i Custom Kernel Signers (tool esterno).
$ssde = Join-Path $Dir 'ssde\ssde_enable.exe'
if (Test-Path $ssde) { Write-Host '[3] abilito CKS con SSDE...'; & $ssde }
else { Write-Warning "[3] SSDE non presente in $Dir\ssde\ - scaricalo (valinet/ssde) e rilancia, oppure usa HyperSine su Win10." }

# 4) Registra VigilFlt come minifilter boot-start.
Register-VigilFlt $sys 'boot'

Write-Host ''
Write-Host 'Riavvia. Dopo il riavvio: fltmc filters deve elencare VigilFlt, Confirm-SecureBootUEFI = True.'
Write-Host 'Errore 577 del servizio = disattiva HVCI/Integrita memoria. Dettagli: driver\CKS.md.'
