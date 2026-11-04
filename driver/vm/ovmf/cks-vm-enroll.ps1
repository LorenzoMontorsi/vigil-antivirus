<#
.SYNOPSIS
  Dentro la VM CKS (OVMF, Secure Boot acceso, PK di Vigil già nel firmware): rende fidato il
  firmatario del driver, deposita la policy CKS firmata, abilita i Custom Kernel Signers con SSDE
  e registra VigilFlt come servizio boot-start. Da eseguire come amministratore nella VM.

.DESCRIPTION
  Presuppone che l'host abbia copiato in C:\Vigil\ :
    - VigilFlt.sys            (firmato con "Vigil Kernel Signer")
    - SiPolicy.p7b            (policy firmata dalla Platform Key)
    - VigilKernelSigner.cer   (firmatario del driver)
    - ssde\                    (contenuto di https://github.com/valinet/ssde: ssde_enable.exe, ssde.sys, ...)
  La PK NON va arruolata qui: su questa VM è già nel firmware (ovmf-vm.ps1 l'ha pre-provisionata).
  Su hardware fisico, invece, la PK va arruolata a mano nell'UEFI PRIMA di questo passo.

  Dopo l'esecuzione serve UN riavvio perché la policy CKS entri in vigore; poi VigilFlt si carica.
#>
param([string]$Stage = 'C:\Vigil')
$ErrorActionPreference = 'Stop'

function Need($p) { if (-not (Test-Path $p)) { throw "manca $p (copialo dall'host)" } }
$sys  = Join-Path $Stage 'VigilFlt.sys'
$p7b  = Join-Path $Stage 'SiPolicy.p7b'
$cer  = Join-Path $Stage 'VigilKernelSigner.cer'
$ssde = Join-Path $Stage 'ssde\ssde_enable.exe'
Need $sys; Need $p7b; Need $cer

# 0) Secure Boot deve essere acceso (altrimenti CKS non ha senso: sarebbe più semplice il testsigning).
if (-not (Confirm-SecureBootUEFI)) { Write-Warning 'Secure Boot NON attivo: questa VM non sta provando davvero CKS.' }

# 1) Rendi fidato il firmatario del driver (Root + TrustedPublisher).
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root          | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
Write-Host '[1] certificato del driver reso fidato.'

# 2) Deposita la policy firmata nella partizione EFI, dove CKS la cerca.
$efi = 'S:'
if (-not (Test-Path "$efi\")) { mountvol $efi /S }
$dest = "$efi\EFI\Microsoft\Boot"
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item $p7b (Join-Path $dest 'SiPolicy.p7b') -Force
Write-Host "[2] SiPolicy.p7b copiata in $dest."

# 3) Abilita i Custom Kernel Signers con SSDE (Win11) — scarica SSDE separatamente in $Stage\ssde\.
if (Test-Path $ssde) {
    Write-Host '[3] abilito CKS con SSDE...'
    & $ssde
    Write-Host '    (controlla HKLM\SYSTEM\ControlSet001\Control\CI\Protected\Licensed = 1)'
} else {
    Write-Warning "[3] SSDE non trovato in $Stage\ssde\ — scaricalo da https://github.com/valinet/ssde e rilancia."
}

# 4) Registra VigilFlt come minifilter boot-start (il servizio real-time ne dipenderà).
$drvDst = "$env:SystemRoot\System32\drivers\VigilFlt.sys"
Copy-Item $sys $drvDst -Force
sc.exe create VigilFlt type= filesys start= boot binPath= $drvDst group= FSFilter Activity Monitor | Out-Null
# Altitudine (deve combaciare con quella del driver / del servizio real-time).
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\VigilFlt\Instances' /v DefaultInstance /t REG_SZ /d 'VigilFlt Instance' /f | Out-Null
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\VigilFlt\Instances\VigilFlt Instance' /v Altitude /t REG_SZ /d '328010' /f | Out-Null
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\VigilFlt\Instances\VigilFlt Instance' /v Flags /t REG_DWORD /d 0 /f | Out-Null
Write-Host '[4] VigilFlt registrato (boot-start).'

Write-Host ''
Write-Host 'Riavvia la VM. Dopo il riavvio verifica:'
Write-Host '  Confirm-SecureBootUEFI          # deve essere True (Secure Boot acceso)'
Write-Host '  fltmc filters                   # deve elencare VigilFlt'
Write-Host '  reg query "HKLM\SYSTEM\ControlSet001\Control\CI\Protected" /v Licensed   # 1 = CKS attivo'
Write-Host 'Se VigilFlt NON si carica: niente testsigning, quindi il mancato load conferma un problema'
Write-Host 'nella policy/PK (rivedi driver\CKS.md). Errore 577 del servizio = disattiva HVCI/Memory Integrity.'
