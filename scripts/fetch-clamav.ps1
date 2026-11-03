<#
.SYNOPSIS
  Scarica ClamAV per Windows (versione fissata), ne verifica lo SHA-256 e copia
  in vendor\clamav solo i file che servono a Vigil (clamd, freshclam, DLL,
  certificati, licenze).

.NOTES
  L'hash è quello del pacchetto ufficiale verificato con la firma GPG di
  Cisco Talos (chiave 5BAD CA26 65EF 59DC F8A2 3D8B 707F 0DB4 8083 6771).
  Per aggiornare ClamAV: cambia $Version e $Sha256 dopo aver verificato la
  nuova firma (vedi docs.clamav.net, "Verifying signatures").
#>
param(
    # Usa uno zip già scaricato invece di riscaricarlo.
    [string]$ZipPath
)

$ErrorActionPreference = 'Stop'
$Version = '1.5.4'
$Sha256 = '0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395'

$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root 'vendor\clamav'
$name = "clamav-$Version.win.x64"
$work = Join-Path ([IO.Path]::GetTempPath()) "vigil-clamav-$Version"
New-Item -ItemType Directory -Force $work | Out-Null

if (-not $ZipPath) {
    $ZipPath = Join-Path $work "$name.zip"
    if (-not (Test-Path $ZipPath)) {
        $url = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$Version/$name.zip"
        Write-Host "Download $url"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $ZipPath -UseBasicParsing
    }
}

$actual = (Get-FileHash -Algorithm SHA256 $ZipPath).Hash.ToLower()
if ($actual -ne $Sha256) {
    throw "SHA-256 non corrispondente!`n atteso:  $Sha256`n trovato: $actual"
}
Write-Host "SHA-256 verificato."

$extract = Join-Path $work 'x'
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
Expand-Archive -Path $ZipPath -DestinationPath $extract
$src = Join-Path $extract $name

if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
New-Item -ItemType Directory -Force $dest | Out-Null

Copy-Item (Join-Path $src 'clamd.exe'), (Join-Path $src 'freshclam.exe'), (Join-Path $src 'COPYING.txt') $dest
Get-ChildItem $src -Filter *.dll | Where-Object { $_.Name -ne 'pdcurses.dll' } | Copy-Item -Destination $dest
Copy-Item -Recurse (Join-Path $src 'certs') (Join-Path $dest 'certs')
Copy-Item -Recurse (Join-Path $src 'COPYING') (Join-Path $dest 'COPYING')
Set-Content -Path (Join-Path $dest 'VERSION') -Value $Version -Encoding ascii -NoNewline
@"
ClamAV $Version - Copyright (C) Cisco Systems, Inc. e contributori.
Distribuito sotto GNU GPL v2 (vedi COPYING.txt e la cartella COPYING).
Codice sorgente: https://github.com/Cisco-Talos/clamav/releases/tag/clamav-$Version
Vigil usa ClamAV come programma separato (clamd/freshclam), senza modificarlo.
"@ | Set-Content -Path (Join-Path $dest 'LEGGIMI-CLAMAV.txt') -Encoding utf8

$size = (Get-ChildItem -Recurse $dest | Measure-Object -Sum Length).Sum / 1MB
Write-Host ("ClamAV {0} pronto in {1} ({2:N1} MB)" -f $Version, $dest, $size)
