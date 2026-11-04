<#
.SYNOPSIS
  Genera una policy di Code Integrity che fa fidare Windows del firmatario di VigilFlt.sys
  per il kernel, da usare con i Custom Kernel Signers (CKS) su Windows 10/11.

.DESCRIPTION
  I Custom Kernel Signers sono una funzione UFFICIALE di Windows 10 (Enterprise/Education, da 1703):
  permettono di decidere quali certificati sono fidati per i driver kernel, SENZA test-signing e con
  Secure Boot acceso. Non è una patch: è una policy di WDAC/Code Integrity firmata, messa nella
  partizione EFI, abilitata entrando in Setup Mode dell'UEFI (si possiede la Platform Key).

  Questo script produce la parte "lato Vigil": la regola che autorizza il nostro firmatario e la
  policy compilata (.cip) + la sua versione XML. I passaggi di boot/UEFI (possesso della PK,
  deposito della policy in EFI, driver di persistenza) sono descritti dal progetto di riferimento:
  https://github.com/HyperSine/Windows10-CustomKernelSigners  — leggine le AVVERTENZE prima di agire.

  ATTENZIONE: cambiare le chiavi di Secure Boot / la policy di boot è un'operazione a livello di
  firmware. Falla solo su una macchina di PROVA dedicata, MAI su un portatile in dual-boot/Boot Camp
  che usi tutti i giorni: un errore può impedire l'avvio (anche di un altro sistema operativo).

.NOTES
  Testato: la GENERAZIONE dei file (serve il modulo ConfigCI, presente su Win10/11).
  Da collaudare sul bersaglio: l'ACCETTAZIONE della policy da parte di CKS.
#>
param(
    [string]$Sys = (Join-Path $PSScriptRoot 'build\Release\VigilFlt.sys'),
    [string]$OutDir = (Join-Path $PSScriptRoot 'build\cks')
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Sys)) { throw "VigilFlt.sys non trovato: compilalo e firmalo (build.ps1 + sign-test.ps1). $Sys" }
if (-not (Get-Command New-CIPolicyRule -ErrorAction SilentlyContinue)) { throw 'Modulo ConfigCI assente: serve Windows 10/11.' }

New-Item -ItemType Directory -Force $OutDir | Out-Null
$xml = Join-Path $OutDir 'VigilCIPolicy.xml'
$cip = Join-Path $OutDir 'VigilCIPolicy.cip'

# Regola "fidati di questo firmatario" ricavata dalla firma del driver. Il nostro certificato è
# autofirmato (leaf = root), quindi LeafCertificate individua esattamente quel firmatario.
Write-Host "Ricavo il firmatario da $Sys ..."
$rules = New-CIPolicyRule -DriverFilePath $Sys -Level LeafCertificate

# Policy base solo kernel (niente modalità utente), a partire dalla regola del firmatario.
New-CIPolicy -FilePath $xml -Rules $rules -UserPEs:$false -MultiplePolicyFormat -ErrorAction Stop

# Opzioni: niente UMCI (solo kernel); la policy è pensata per essere FIRMATA e consumata da CKS.
try { Set-RuleOption -FilePath $xml -Option 0 -Delete } catch {}   # 0 = Enabled:UMCI -> rimosso
Set-RuleOption -FilePath $xml -Option 3 -Delete 2>$null            # 3 = Audit mode -> in enforcement

ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath $cip | Out-Null

# Esporta anche il certificato pubblico del firmatario, da far fidare sul bersaglio.
$cer = Join-Path $OutDir 'VigilKernelSigner.cer'
$sig = (Get-AuthenticodeSignature $Sys)
if ($sig.SignerCertificate) { [IO.File]::WriteAllBytes($cer, $sig.SignerCertificate.Export('Cert')) }

Write-Host ""
Write-Host "Prodotti in $OutDir :"
Write-Host "  VigilCIPolicy.xml   policy leggibile (per revisione)"
Write-Host "  VigilCIPolicy.cip   policy compilata (da firmare e installare con la procedura CKS)"
Write-Host "  VigilKernelSigner.cer  certificato del firmatario da rendere fidato sul bersaglio"
Write-Host ""
Write-Host "Prossimi passi (macchina di PROVA, Win10 Enterprise/Education): vedi driver\CKS.md"
