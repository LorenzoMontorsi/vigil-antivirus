<#
.SYNOPSIS
  Crea e avvia la VM di collaudo CKS su QEMU + OVMF (firmware UEFI con Secure Boot ACCESO),
  pre-provisionando la Platform Key di Vigil nel firmware. È il banco di prova dove il flusso
  "arruola PK + abilita CKS + carica VigilFlt" gira SENZA gesti manuali sul firmware.

.DESCRIPTION
  Perché OVMF e non VMware: il varstore di OVMF è un file che possiamo RISCRIVERE prima del boot.
  Con virt-fw-vars depositiamo nel firmware:
    - PK  = Vigil Platform Key  (così la policy CKS firmata dalla PK viene accettata)
    - KEK + db = chiavi Microsoft standard (così il bootloader di Windows resta fidato e la VM parte)
  Risultato: Secure Boot acceso, Windows parte, e la nostra PK è già dentro. Nessun passaggio nel
  menù del firmware. Su VMware/hardware fisico questo non è possibile: lì la PK va arruolata a mano.

  Prerequisiti (una volta):
    - QEMU per Windows installato (qemu.weilnetz.de). Porta con sé OVMF (edk2-*-secure-code.fd + vars).
    - Python 3 (per pycdlib e virt-firmware, installati in un venv locale alla VM).
    - I certificati prodotti da ..\..\cks-policy.ps1 in ..\..\build\cks\
      (VigilPlatformKey.cer, VigilKernelSigner.cer, SiPolicy.p7b).

  NOTA: questo script NON è stato eseguito sull'host di sviluppo (Win11 Pro senza QEMU). Va
  collaudato nella VM/host con QEMU installato; i dettagli QEMU/OVMF sono commentati per la messa a punto.

.PARAMETER WindowsIso
  ISO di Windows da installare. Usa la TUA LTSC 2019 legittima
  (es. C:\Users\...\Downloads\it_windows_10_enterprise_ltsc_2019_x64_dvd_2fa02691.iso)
  oppure una eval Enterprise ufficiale. NON ISO crackate.
#>
param(
    [string]$VmDir = 'C:\VM\vigil-ovmf',
    [Parameter(Mandatory)][string]$WindowsIso,
    [string]$CksDir = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'build\cks'),
    [int]$MemoryMB = 6144,
    [int]$Cpus = 4,
    [int]$DiskGB = 64,
    [ValidateSet('whpx','tcg')][string]$Accel = 'whpx',
    [switch]$NoStart
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$repo = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $here))  # ...\<repo>

function Invoke-Native([scriptblock]$cmd) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $cmd 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $prev }
    if ($LASTEXITCODE -ne 0) { throw "comando fallito ($LASTEXITCODE): $cmd" }
}
function Find-First([string[]]$paths) { foreach ($p in $paths) { $g = Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object -First 1; if ($g) { return $g.FullName } } }

if (-not (Test-Path $WindowsIso)) { throw "ISO di Windows non trovata: $WindowsIso" }
foreach ($f in 'VigilPlatformKey.cer','VigilKernelSigner.cer','SiPolicy.p7b') {
    if (-not (Test-Path (Join-Path $CksDir $f))) { throw "manca $f in $CksDir — esegui prima driver\cks-policy.ps1 (nella VM Enterprise)" }
}

# --- QEMU + OVMF ---
$qemu = (Get-Command qemu-system-x86_64.exe -ErrorAction SilentlyContinue).Source
if (-not $qemu) { $qemu = Find-First @('C:\Program Files\qemu\qemu-system-x86_64.exe') }
if (-not $qemu) { throw "QEMU non trovato: installa QEMU per Windows (qemu.weilnetz.de) e riprova." }
$qdir = Split-Path -Parent $qemu
$ovmfCode = Find-First @("$qdir\share\edk2-x86_64-secure-code.fd", "$qdir\share\*OVMF_CODE*secure*.fd", "$qdir\share\*OVMF_CODE*.fd")
$ovmfVars = Find-First @("$qdir\share\edk2-x86_64-vars.fd", "$qdir\share\edk2-i386-vars.fd", "$qdir\share\*OVMF_VARS*.fd")
if (-not $ovmfCode -or -not $ovmfVars) { throw "firmware OVMF non trovato in $qdir\share (serve un edk2 *secure-code* + un *vars* template)." }
Write-Host "QEMU : $qemu"
Write-Host "OVMF code: $ovmfCode"
Write-Host "OVMF vars: $ovmfVars (template)"

New-Item -ItemType Directory -Force $VmDir, "$VmDir\ssh" | Out-Null

# --- venv con pycdlib (ISO) + virt-firmware (varstore) ---
$venv = Join-Path $VmDir '.tool'
if (-not (Test-Path "$venv\Scripts\virt-fw-vars.exe")) {
    if (-not (Test-Path "$venv\Scripts\python.exe")) { Invoke-Native { python -m venv $venv } }
    Invoke-Native { & "$venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check pycdlib cryptography pefile pyyaml requests }
    # virt-firmware dichiara crypt_r (modulo Unix) come dipendenza su Python >=3.13: non compila su
    # Windows e NON serve al varstore. Lo installiamo senza dipendenze (le vere deps sono qui sopra).
    Invoke-Native { & "$venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check --no-deps virt-firmware }
}
$py = "$venv\Scripts\python.exe"
$virtfw = "$venv\Scripts\virt-fw-vars.exe"

# --- chiave SSH dedicata ---
$key = Join-Path $VmDir 'ssh\id_ed25519'
if (-not (Test-Path $key)) {
    $keygen = (Get-Command ssh-keygen -ErrorAction SilentlyContinue).Source
    if (-not $keygen) { $keygen = 'C:\Program Files\Git\usr\bin\ssh-keygen.exe' }
    Invoke-Native { & $keygen -q -t ed25519 -N '""' -C 'vigil-ovmf' -f $key }
}

# --- ISO di installazione automatica (UEFI) ---
$stage = Join-Path $VmDir 'unattend-src'
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item "$here\autounattend-uefi.xml" (Join-Path $stage 'autounattend.xml') -Force
Copy-Item "$here\vigil-firstboot-uefi.ps1" $stage -Force
Copy-Item "$key.pub" (Join-Path $stage 'authorized_key.pub') -Force
$unattendIso = Join-Path $VmDir 'unattend.iso'
Invoke-Native { & $py -I "$repo\scripts\make-unattend-iso.py" $stage $unattendIso }

# --- varstore OVMF pre-provisionato: PK = Vigil, KEK/db = Microsoft ---
function Der2Pem([string]$cer, [string]$pem) {
    $der = [IO.File]::ReadAllBytes($cer)
    $b64 = [Convert]::ToBase64String($der, 'InsertLineBreaks')
    Set-Content -Path $pem -Encoding ascii -Value ("-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----")
}
$pkPem = Join-Path $VmDir 'VigilPlatformKey.pem'
$kmPem = Join-Path $VmDir 'VigilKernelSigner.pem'
Der2Pem (Join-Path $CksDir 'VigilPlatformKey.cer') $pkPem
Der2Pem (Join-Path $CksDir 'VigilKernelSigner.cer') $kmPem
$vars = Join-Path $VmDir 'vigil-vars.fd'
$guid = '11111111-2222-3333-4444-555555555555'   # GUID del proprietario delle chiavi Vigil
# --enroll-microsoft: arruola le chiavi Microsoft (PK/KEK/db: Windows e UEFI CA) -> Windows parte.
# --set-pk          : sovrascrive la PK con la NOSTRA -> la policy CKS firmata dalla PK sarà accettata.
# --add-db          : aggiunge anche il nostro firmatario kernel al db (innocuo; comodità).
# --sb              : abilita Secure Boot in enforcement.
# Verificato: PK=Vigil, KEK=MS 2011/2023, db=Windows/UEFI MS + Vigil, SecureBootEnable=ON.
Invoke-Native { & $virtfw -i $ovmfVars --enroll-microsoft --set-pk $guid $pkPem --add-db $guid $kmPem --sb -o $vars }

# --- disco ---
$disk = Join-Path $VmDir 'disk.qcow2'
$qemuImg = Join-Path $qdir 'qemu-img.exe'
if (-not (Test-Path $disk)) { Invoke-Native { & $qemuImg create -f qcow2 $disk "${DiskGB}G" } }

# --- accelerazione: WHPX (serve la piattaforma Hyper-V) o TCG (lento ma sempre disponibile) ---
# Se QEMU si lamenta di WHPX, rilancia con  -Accel tcg  oppure abilita "Windows Hypervisor Platform".
$accel = if ($Accel -eq 'whpx') { 'whpx,kernel-irqchip=off' } else { 'tcg' }

$serial = Join-Path $VmDir 'serial.log'
$qargs = @(
    '-name','vigil-cks'
    '-machine','q35,smm=on'
    '-accel',$accel
    '-m',"$MemoryMB", '-smp',"$Cpus"
    '-global','driver=cfi.pflash01,property=secure,value=on'
    '-drive',"if=pflash,format=raw,unit=0,file=$ovmfCode,readonly=on"
    '-drive',"if=pflash,format=raw,unit=1,file=$vars"
    '-device','ahci,id=ahci'
    '-drive',"if=none,id=hd0,file=$disk,format=qcow2"
    '-device','ide-hd,drive=hd0,bus=ahci.0'
    '-drive',"if=none,id=cd0,file=$WindowsIso,media=cdrom"
    '-device','ide-cd,drive=cd0,bus=ahci.1'
    '-drive',"if=none,id=cd1,file=$unattendIso,media=cdrom"
    '-device','ide-cd,drive=cd1,bus=ahci.2'
    '-netdev','user,id=net0,hostfwd=tcp::2222-:22'
    '-device','e1000e,netdev=net0'
    '-serial',"file:$serial"
)
Set-Content (Join-Path $VmDir 'qemu-cmd.txt') -Value ("`"$qemu`" " + ($qargs -join ' '))
Set-Content (Join-Path $VmDir 'ip.txt') -Value '127.0.0.1'   # SSH via port forward
Set-Content (Join-Path $VmDir 'ssh-port.txt') -Value '2222'

Write-Host ''
Write-Host "VM pronta in $VmDir. SSH: vigil@127.0.0.1 -p 2222 (chiave ssh\id_ed25519)."
Write-Host 'Al primo avvio, al prompt "Press any key to boot from CD" premi un tasto (è l''unica'
Write-Host 'interazione manuale; l''installazione poi è automatica).'
Write-Host "Comando QEMU salvato in $VmDir\qemu-cmd.txt"
if ($NoStart) { Write-Host 'Avvio saltato (-NoStart).'; return }
Write-Host 'Avvio QEMU...'
& $qemu @qargs
