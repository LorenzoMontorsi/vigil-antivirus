# Compila vigil-rtd e lo copia in app\src-tauri\payload\ (incluso nell'installer da tauri.conf.json).
# Da lanciare prima di "npm run tauri build".
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    cargo build -p vigil-rtd --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build vigil-rtd fallito ($LASTEXITCODE)" }
    $target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }
    Copy-Item (Join-Path $target 'release\vigil-rtd.exe') (Join-Path $root 'app\src-tauri\payload\vigil-rtd.exe') -Force
    Write-Host 'vigil-rtd.exe copiato in app\src-tauri\payload\'
} finally { Pop-Location }
