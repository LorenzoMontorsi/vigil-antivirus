# Eseguito NELLA VM come utente normale (tramite as-user.ps1): prova il provider AMSI.
# Il marcatore è composto a pezzi: questo file non lo contiene in chiaro. Lo vede
# completo solo il PowerShell figlio, come succede a uno script decodificato al volo.
$m = 'VIGIL-TEST-' + 'QUARANTENA-' + '7f3a'
$casi = [ordered]@{
    'script pulito'        = "Write-Output 'ciao dal PowerShell figlio'"
    'script con marcatore' = "Write-Output '$m'"
}
foreach ($nome in $casi.Keys) {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($casi[$nome]))
    $r = (powershell -NoProfile -EncodedCommand $enc 2>&1 | Out-String).Trim()
    # Il risultato non deve contenere il marcatore: il file di output verrebbe
    # (giustamente) messo in quarantena dalla protezione in tempo reale.
    "$nome -> " + $r.Replace($m, '<marcatore>')
}
