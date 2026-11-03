<#
.SYNOPSIS
  Firma VigilFlt.sys con un certificato di TEST (solo per macchine in testsigning).
.DESCRIPTION
  Al primo uso crea un certificato autofirmato "Vigil Test Signing" nell'archivio
  dell'utente corrente (nessun privilegio richiesto) e lo esporta in
  build\VigilTest.cer, da importare nella VM in Root e TrustedPublisher.
  NON importarlo mai sul PC principale: quel certificato potrebbe firmare qualunque driver.
#>
param([string]$Configuration = 'Release', [string[]]$Files)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$signtool = Join-Path $root 'packages\Microsoft.Windows.SDK.CPP.10.0.26100.6584\c\bin\10.0.26100.0\x64\signtool.exe'
$sys = Join-Path $root "build\$Configuration\VigilFlt.sys"
$cer = Join-Path $root 'build\VigilTest.cer'
$subject = 'CN=Vigil Test Signing'

$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $subject -and $_.NotAfter -gt (Get-Date) } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -KeyAlgorithm RSA -KeyLength 3072 `
        -HashAlgorithm SHA256 -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(3)
    Write-Host "Creato certificato di test $($cert.Thumbprint)"
}
Export-Certificate -Cert $cert -FilePath $cer -Force | Out-Null

if (-not $Files) { $Files = @($sys) }
foreach ($f in $Files) {
    & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /s My $f
    if ($LASTEXITCODE -ne 0) { throw "signtool ha fallito su $f ($LASTEXITCODE)" }
    Write-Host "Firmato: $f"
}
Write-Host "Certificato: $cer"
