<#
.SYNOPSIS
  Crea la VM di test di Vigil per VMware Workstation/Player (installazione automatica di Windows 10).
.DESCRIPTION
  - chiave SSH dedicata (ssh\id_ed25519) per comandare la VM dall'host
  - ISO con autounattend.xml + script del primo avvio (testsigning, debug kernel, OpenSSH)
  - disco da 64 GB in formato "monolithicFlat" su file sparse (occupa solo ciò che viene scritto)
  - file .vmx con BIOS, SATA, rete NAT e porta seriale su named pipe per WinDbg
  Poi: vmrun -T player start <vmx> gui   e aspettare che la VM risponda via SSH.
#>
param(
    [string]$VmDir = 'C:\VM\vigil-vmware',
    [Parameter(Mandatory)][string]$WindowsIso,
    [int]$MemoryMB = 6144,
    [int]$Cpus = 4,
    [int]$DiskGB = 64
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$repo = Split-Path -Parent (Split-Path -Parent $here)
if (-not (Test-Path $WindowsIso)) { throw "ISO non trovata: $WindowsIso" }

# Comandi esterni: l'esito lo decide il codice di uscita, non lo stderr
# (in PowerShell 5.1 un avviso su stderr diventerebbe un errore fatale).
function Invoke-Native([scriptblock]$cmd) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $cmd 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $prev }
    if ($LASTEXITCODE -ne 0) { throw "comando fallito ($LASTEXITCODE): $cmd" }
}
New-Item -ItemType Directory -Force $VmDir, "$VmDir\ssh" | Out-Null

# 1. Chiave SSH
$key = Join-Path $VmDir 'ssh\id_ed25519'
if (-not (Test-Path $key)) {
    $keygen = (Get-Command ssh-keygen -ErrorAction SilentlyContinue).Source
    if (-not $keygen) { $keygen = 'C:\Program Files\Git\usr\bin\ssh-keygen.exe' }
    Invoke-Native { & $keygen -q -t ed25519 -N '""' -C 'vigil-host' -f $key }
}

# 2. ISO di installazione automatica
$stage = Join-Path $VmDir 'unattend-src'
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item "$here\unattend\autounattend.xml", "$here\unattend\vigil-firstboot.ps1" $stage -Force
Copy-Item "$key.pub" (Join-Path $stage 'authorized_key.pub') -Force
$venv = Join-Path $VmDir '.isotool'
if (-not (Test-Path "$venv\Scripts\python.exe")) {
    Invoke-Native { python -m venv $venv }
    Invoke-Native { & "$venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check pycdlib }
}
Invoke-Native { & "$venv\Scripts\python.exe" -I "$repo\scripts\make-unattend-iso.py" $stage (Join-Path $VmDir 'unattend.iso') }

# 3. Disco: descrittore + file dati sparse
$flat = Join-Path $VmDir 'win10-flat.vmdk'
if (-not (Test-Path $flat)) {
    New-Item -ItemType File $flat | Out-Null
    fsutil sparse setflag $flat | Out-Null
    $fs = [IO.File]::Open($flat, 'Open', 'ReadWrite'); $fs.SetLength([int64]$DiskGB * 1GB); $fs.Close()
    $sectors = [int64]$DiskGB * 1GB / 512
    $cyl = [math]::Floor($sectors / (255 * 63))
    @"
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicFlat"

# Extent description
RW $sectors FLAT "win10-flat.vmdk" 0

# The Disk Data Base
ddb.adapterType = "lsilogic"
ddb.geometry.cylinders = "$cyl"
ddb.geometry.heads = "255"
ddb.geometry.sectors = "63"
ddb.virtualHWVersion = "21"
"@ | Set-Content -Path (Join-Path $VmDir 'win10.vmdk') -Encoding ascii
}

# 4. Configurazione della VM
@"
.encoding = "windows-1252"
config.version = "8"
virtualHW.version = "21"
displayName = "Vigil-Test"
guestOS = "windows9-64"
firmware = "bios"
memsize = "$MemoryMB"
numvcpus = "$Cpus"
cpuid.coresPerSocket = "$Cpus"
hints.hideAll = "TRUE"
ulm.disableMitigations = "TRUE"

pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"

sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.fileName = "win10.vmdk"
sata0:1.present = "TRUE"
sata0:1.deviceType = "cdrom-image"
sata0:1.fileName = "$WindowsIso"
sata0:1.startConnected = "TRUE"
sata0:2.present = "TRUE"
sata0:2.deviceType = "cdrom-image"
sata0:2.fileName = "unattend.iso"
sata0:2.startConnected = "TRUE"
bios.bootOrder = "hdd,cdrom"

ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "e1000e"
ethernet0.addressType = "generated"

usb.present = "TRUE"
ehci.present = "TRUE"
usb_xhci.present = "TRUE"
svga.present = "TRUE"
svga.autodetect = "TRUE"
mks.enable3d = "FALSE"
sound.present = "FALSE"
floppy0.present = "FALSE"

serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.fileName = "\\.\pipe\vigil-kd"
serial0.pipe.endPoint = "server"
serial0.tryNoRxLoss = "FALSE"
serial0.yieldOnMsrRead = "TRUE"

tools.syncTime = "TRUE"
"@ | Set-Content -Path (Join-Path $VmDir 'Vigil-Test.vmx') -Encoding ascii

Remove-Item (Join-Path $VmDir 'ip.txt') -ErrorAction SilentlyContinue
Write-Host "VM pronta in $VmDir"
Write-Host "Avvio:  & '${env:ProgramFiles(x86)}\VMware\VMware Player\vmrun.exe' -T player start '$VmDir\Vigil-Test.vmx' gui"
