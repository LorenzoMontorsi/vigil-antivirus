<#
.SYNOPSIS
  Genera il "set riusabile" per caricare VigilFlt.sys su Windows 10/11 con Secure Boot ACCESO,
  senza test-signing, tramite i Custom Kernel Signers (CKS):
    - una policy di Code Integrity che autorizza nel KERNEL il nostro firmatario;
    - la policy compilata e FIRMATA dalla Platform Key -> SiPolicy.p7b (da copiare in EFI\Microsoft\Boot\);
    - i certificati pubblici da arruolare/fidare sul bersaglio.

.DESCRIPTION
  I Custom Kernel Signers sono una funzione UFFICIALE di Windows (Enterprise/Education, da 1703):
  dici al sistema di fidarsi SOLO del tuo firmatario per i driver kernel, senza test-signing e con
  Secure Boot acceso. Non e' una patch, non tocca ci.dll.

  Riferimenti (leggine le AVVERTENZE):
    - https://github.com/HyperSine/Windows10-CustomKernelSigners           (Win10)
    - https://github.com/valinet/ssde                                      (Win11, tool SSDE)
    - https://github.com/MysticSnows/Custom-Kernel-Signer-Win11-KnowledgeBase (procedura Win11 24H2)

  "UNA volta, per TUTTE le tue macchine": le CHIAVI e la policy firmata si generano una sola volta
  (in questa VM Enterprise) e si riusano su tutte le TUE macchine. Le CHIAVI PRIVATE non lasciano mai
  la macchina di build: sui bersagli arrivano solo il driver gia' firmato, la SiPolicy.p7b e i
  certificati PUBBLICI (PK da arruolare in UEFI, firmatario da rendere fidato). Quello che NON si puo'
  riusare e' l'arruolamento della PK nel firmware: va fatto, a mano, una volta su OGNI PC fisico.

  Ruoli dei due certificati prodotti:
    - "Vigil Kernel Signer"  (km) : firma VigilFlt.sys; la policy lo autorizza nel kernel.
    - "Vigil Platform Key"   (PK) : firma la policy (-> .p7b) e si arruola nell'UEFI del bersaglio.

.NOTES
  ConvertFrom-CIPolicy richiede Windows Enterprise/Education: esegui questo script nella VM Enterprise.
  Le chiavi private restano in Cert:\CurrentUser\My di QUESTA macchina. Esportane un backup .pfx
  (protetto da password) e CUSTODISCILO: ti serve per firmare driver/policy futuri. Non committarlo mai.

  ATTENZIONE: arruolare la PK / cambiare le chiavi di Secure Boot e' un'operazione a livello di
  firmware. Falla solo su una macchina di PROVA dedicata, MAI su un portatile in dual-boot/Boot Camp
  d'uso quotidiano: un errore puo' impedire l'avvio (anche di un altro sistema operativo).
#>
param(
    [string]$Sys = (Join-Path $PSScriptRoot 'build\Release\VigilFlt.sys'),
    [string]$OutDir = (Join-Path $PSScriptRoot 'build\cks'),
    [string]$KmSubject = 'CN=Vigil Kernel Signer',
    [string]$PkSubject = 'CN=Vigil Platform Key'
)
$ErrorActionPreference = 'Stop'

function Resolve-SignTool {
    $c = Get-ChildItem (Join-Path $PSScriptRoot 'packages') -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
         Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
    if ($c) { return $c.FullName }
    $c = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    throw 'signtool.exe non trovato (manca Windows SDK): esegui prima "nuget restore" / build.ps1.'
}

function Get-OrNew-SigningCert([string]$Subject) {
    $c = Get-ChildItem Cert:\CurrentUser\My |
         Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date) } |
         Select-Object -First 1
    if (-not $c) {
        $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject `
             -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
             -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable `
             -NotAfter (Get-Date).AddYears(10)
        Write-Host "  creato $Subject  thumbprint $($c.Thumbprint)"
    } else {
        Write-Host "  riuso   $Subject  thumbprint $($c.Thumbprint)"
    }
    return $c
}

if (-not (Get-Command New-CIPolicy -ErrorAction SilentlyContinue)) { throw 'Modulo ConfigCI assente: serve Windows 10/11.' }
if (-not (Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue)) {
    throw 'ConvertFrom-CIPolicy assente: serve Windows ENTERPRISE/EDUCATION (eseguilo nella VM Enterprise).'
}
if (-not (Test-Path $Sys)) { throw "VigilFlt.sys non trovato: compilalo e firmalo. $Sys" }

$signtool = Resolve-SignTool
New-Item -ItemType Directory -Force $OutDir | Out-Null

$xml = Join-Path $OutDir 'VigilCIPolicy.xml'
$bin = Join-Path $OutDir 'SiPolicy.bin'
$p7b = Join-Path $OutDir 'SiPolicy.p7b'
$kmCer = Join-Path $OutDir 'VigilKernelSigner.cer'
$pkCer = Join-Path $OutDir 'VigilPlatformKey.cer'

Write-Host '== Certificati riusabili (restano in CurrentUser\My di questa macchina) =='
$km = Get-OrNew-SigningCert $KmSubject
$pk = Get-OrNew-SigningCert $PkSubject

# 1) Firma il driver con il certificato km, cosi' la policy che lo autorizza combacia col binario.
Write-Host "== Firmo $Sys con $KmSubject =="
& $signtool sign /fd SHA256 /sha1 $km.Thumbprint /s My $Sys
if ($LASTEXITCODE -ne 0) { throw "signtool (driver) ha fallito ($LASTEXITCODE)" }

# 2) Policy: autorizza nel KERNEL il firmatario del driver. Formato base single-policy (SiPolicy.p7b),
#    compatibile anche con Win10 (niente MultiplePolicyFormat).
Write-Host '== Genero la policy di Code Integrity =='
$rules = New-CIPolicyRule -DriverFilePath $Sys -Level LeafCertificate
New-CIPolicy -FilePath $xml -Rules $rules -UserPEs:$false -ErrorAction Stop

# Opzioni della policy:
#   0  Enabled:UMCI                        -> RIMOSSO (solo kernel)
#   3  Enabled:Audit Mode                  -> RIMOSSO (enforcement)
#   6  Enabled:Unsigned System Integrity   -> RIMOSSO (la policy sara' FIRMATA)
foreach ($opt in 0,3,6) { try { Set-RuleOption -FilePath $xml -Option $opt -Delete } catch {} }

# 3) Compila e firma la policy con la PK -> SiPolicy.p7b
Write-Host '== Compilo e firmo la policy con la Platform Key =='
ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath $bin | Out-Null
# OID 1.3.6.1.4.1.311.79.1 = content type "CI policy"; firma PKCS#7 staccata.
if (Test-Path $p7b) { Remove-Item $p7b -Force }
& $signtool sign /v /fd SHA256 /sha1 $pk.Thumbprint /s My `
    /p7 $OutDir /p7co 1.3.6.1.4.1.311.79.1 /p7ce DetachedSignedData $bin
if ($LASTEXITCODE -ne 0) { throw "signtool (policy) ha fallito ($LASTEXITCODE)" }
# signtool /p7 scrive "<nome>.p7"; rinomino in SiPolicy.p7b
$p7 = "$bin.p7"
if (-not (Test-Path $p7)) { $p7 = (Join-Path $OutDir 'SiPolicy.bin.p7') }
if (-not (Test-Path $p7)) { throw "firma prodotta non trovata accanto a $bin" }
Move-Item $p7 $p7b -Force

# 4) Esporta i certificati PUBBLICI (DER) per bersaglio e UEFI.
[IO.File]::WriteAllBytes($kmCer, $km.Export('Cert'))
[IO.File]::WriteAllBytes($pkCer, $pk.Export('Cert'))

Write-Host ''
Write-Host "Prodotti in $OutDir :"
Write-Host '  SiPolicy.p7b           policy FIRMATA -> copiala in  EFI\Microsoft\Boot\SiPolicy.p7b'
Write-Host '  VigilCIPolicy.xml      policy in chiaro (per revisione)'
Write-Host '  VigilKernelSigner.cer  firmatario del driver -> rendilo FIDATO sul bersaglio (Root+TrustedPublisher)'
Write-Host '  VigilPlatformKey.cer   Platform Key -> ARRUOLALA nell UEFI del bersaglio (una volta per PC)'
Write-Host ''
Write-Host 'Il driver VigilFlt.sys e'' ora firmato col Kernel Signer. Backup consigliato delle chiavi:'
Write-Host "  Export-PfxCertificate -Cert Cert:\CurrentUser\My\$($km.Thumbprint) -FilePath $OutDir\VigilKernelSigner.pfx -Password (Read-Host -AsSecureString)"
Write-Host "  Export-PfxCertificate -Cert Cert:\CurrentUser\My\$($pk.Thumbprint) -FilePath $OutDir\VigilPlatformKey.pfx  -Password (Read-Host -AsSecureString)"
Write-Host '  (custodisci i .pfx: NON committarli. build\ e'' gia'' in .gitignore.)'
Write-Host ''
Write-Host 'Prossimi passi sul bersaglio (Win11 -> SSDE, Win10 -> HyperSine): vedi driver\CKS.md'
