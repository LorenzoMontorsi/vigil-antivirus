<#
.SYNOPSIS
  Installa VigilFlt + vigil-rtd nella VM di test via SSH e prova il blocco in tempo reale.
.DESCRIPTION
  I passaggi veri e propri stanno in driver\vm\*.ps1: vengono copiati nella VM ed
  eseguiti lì (passare script multiriga attraverso ssh rovina virgolette e barre).
.PARAMETER VmDir
  Cartella della VM creata con vm\new-vm.ps1 (contiene ssh\id_ed25519 e ip.txt).
#>
param([string]$VmDir = 'C:\VM\vigil-vmware', [string]$Ip, [switch]$SkipCopy)
if (-not $Ip) { $Ip = Get-Content (Join-Path $VmDir 'ip.txt') -ErrorAction SilentlyContinue }
if (-not $Ip) { throw "IP della VM sconosciuto: manca $VmDir\ip.txt" }
$key = Join-Path $VmDir 'ssh\id_ed25519'
$sshOpts = @('-i', $key, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR')
$root = Split-Path -Parent $PSScriptRoot

function RunInVm([string]$script) {
    Write-Host "== $script" -ForegroundColor Cyan
    & ssh @sshOpts "vigil@$Ip" "powershell -NoProfile -ExecutionPolicy Bypass -File C:\Vigil\$script"
}

if (-not $SkipCopy) {
    $stage = Join-Path $env:TEMP 'vigil-vm-stage'
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force "$stage\sigs" | Out-Null
    $targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { "$root\target" }
    Copy-Item "$root\driver\build\Release\VigilFlt.sys", "$root\driver\build\VigilTest.cer", "$targetDir\release\vigil-rtd.exe" $stage
    Copy-Item "$PSScriptRoot\vm\*.ps1" $stage
    # Regola di prova (sempre) + regole YARA-Forge se l'app le ha già scaricate su questo PC.
    Copy-Item "$PSScriptRoot\vm\prova-vigil.yar" "$stage\sigs"
    Copy-Item "$env:APPDATA\dev.lorenzo.antivirus\feeds\yara-forge.yar" "$stage\sigs" -ErrorAction SilentlyContinue

    Write-Host "== copia nella VM ($Ip)" -ForegroundColor Cyan
    & ssh @sshOpts "vigil@$Ip" "Stop-ScheduledTask VigilRtd -ErrorAction SilentlyContinue; Stop-Process -Name vigil-rtd -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force C:\Vigil | Out-Null"
    foreach ($item in Get-ChildItem $stage) {
        & scp @sshOpts -r $item.FullName "vigil@${Ip}:C:/Vigil/"
        if ($LASTEXITCODE -ne 0) { throw "scp di $($item.Name) fallito" }
    }
}

RunInVm 'install.ps1'
RunInVm 'start-rtd.ps1'
RunInVm 'test-block.ps1'
