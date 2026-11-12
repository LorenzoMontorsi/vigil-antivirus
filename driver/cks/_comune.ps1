# Funzioni comuni agli script di installazione del driver VigilFlt.
# SOLO ASCII e salvato in UTF-8 con BOM: PowerShell 5.1 legge i file senza BOM come ANSI
# e un carattere non ASCII (es. un trattino lungo) puo' spezzare le stringhe.

# Altitudine e gruppo devono combaciare con driver\VigilFlt\VigilFlt.inf.
# (328010 e' di Microsoft Defender / WdFilter: NON usarla.)
$VigilAltitude = '328500'
$VigilGroup    = 'FSFilter Anti-Virus'

# Controllo amministratore tramite SID (S-1-5-32-544): non dipende dalla lingua di Windows
# (in italiano il gruppo si chiama "Administrators"/"Administratori" a seconda della build).
function Test-VigilAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole($admins)
}

function Assert-VigilAdmin {
    if (-not (Test-VigilAdmin)) { throw 'Esegui questo script come Amministratore.' }
    Write-Host ('Admin OK (utente: {0})' -f [Security.Principal.WindowsIdentity]::GetCurrent().Name)
}

# Rende fidato un certificato in Root + TrustedPublisher della macchina.
# certutil invece di Import-Certificate, che su alcuni PC restituisce E_ACCESSDENIED anche da admin.
function Add-VigilTrustedCert([string]$Cer) {
    foreach ($store in 'Root', 'TrustedPublisher') {
        & certutil.exe -f -addstore $store $Cer | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "certutil -addstore $store fallito (codice $LASTEXITCODE)" }
    }
    Write-Host '[1] certificato del driver reso fidato (Root + TrustedPublisher).'
}

# Copia il driver e lo registra come minifilter. Scrive l'istanza sia in Instances
# sia in Parameters\Instances (quest'ultima e' quella che usa l'INF su Windows 10 1903+).
function Register-VigilFlt([string]$Sys, [string]$Start = 'boot') {
    $drvDst = "$env:SystemRoot\System32\drivers\VigilFlt.sys"
    & fltmc.exe unload VigilFlt 2>&1 | Out-Null
    Copy-Item $Sys $drvDst -Force
    & sc.exe query VigilFlt 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        & sc.exe config VigilFlt type= filesys start= $Start binPath= $drvDst group= $VigilGroup depend= FltMgr | Out-Null
    } else {
        & sc.exe create VigilFlt type= filesys start= $Start error= normal binPath= $drvDst group= $VigilGroup depend= FltMgr DisplayName= VigilFlt | Out-Null
    }
    if ($LASTEXITCODE -ne 0) { throw "registrazione del servizio VigilFlt fallita (codice $LASTEXITCODE)" }
    $svc = 'HKLM\SYSTEM\CurrentControlSet\Services\VigilFlt'
    foreach ($base in "$svc\Instances", "$svc\Parameters\Instances") {
        & reg.exe add $base /v DefaultInstance /t REG_SZ /d 'VigilFlt Instance' /f | Out-Null
        & reg.exe add "$base\VigilFlt Instance" /v Altitude /t REG_SZ /d $VigilAltitude /f | Out-Null
        & reg.exe add "$base\VigilFlt Instance" /v Flags /t REG_DWORD /d 0 /f | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "scrittura di $base fallita (codice $LASTEXITCODE)" }
    }
    Write-Host "[4] VigilFlt registrato (avvio: $Start, gruppo '$VigilGroup', altitudine $VigilAltitude)."
}
