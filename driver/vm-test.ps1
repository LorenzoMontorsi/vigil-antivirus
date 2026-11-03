<#
.SYNOPSIS
  Installa VigilFlt + vigil-rtd nella VM di test via SSH e prova il blocco in tempo reale.
.DESCRIPTION
  I passaggi veri e propri stanno in driver\vm\*.ps1: vengono copiati nella VM ed
  eseguiti lì (passare script multiriga attraverso ssh rovina virgolette e barre).
.PARAMETER Ip
  Indirizzo della VM (default: H:\VM\vigil-vmware\ip.txt).
#>
param([string]$Ip = (Get-Content H:\VM\vigil-vmware\ip.txt -ErrorAction SilentlyContinue), [switch]$SkipCopy)
if (-not $Ip) { throw "IP della VM sconosciuto" }
$key = 'H:\VM\vigil-test\ssh\id_ed25519'
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
    Copy-Item "$root\driver\build\Release\VigilFlt.sys", "$root\driver\build\VigilTest.cer", "$root\target\release\vigil-rtd.exe" $stage
    Copy-Item "$PSScriptRoot\vm\*.ps1" $stage
    Copy-Item "$env:APPDATA\dev.lorenzo.antivirus\signatures\*.yar" "$stage\sigs" -ErrorAction SilentlyContinue
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
