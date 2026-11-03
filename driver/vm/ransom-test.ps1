# Eseguito NELLA VM come utente normale (as-user.ps1): finto ransomware INNOCUO.
# Lavora solo su una cartella di prova creata qui e su copie di testo generate al momento.
$dir = Join-Path $env:USERPROFILE 'Documents\VigilProvaRansomware'
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $dir | Out-Null
1..15 | ForEach-Object { Set-Content -Path "$dir\documento$_.txt" -Value ("testo del documento numero $_ " * 200) }
Start-Sleep 2

function Start-Child([string]$code) {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $p = Start-Process powershell -ArgumentList '-NoProfile', '-EncodedCommand', $enc -PassThru -WindowStyle Hidden
    [void]$p.WaitForExit(60000)
    $p
}

'== 1. riscrittura cifrata di documenti esistenti'
$p = Start-Child @"
`$r = [Random]::new()
foreach (`$f in Get-ChildItem '$dir' -Filter *.txt) {
    `$b = New-Object byte[] 20000; `$r.NextBytes(`$b)
    [IO.File]::WriteAllBytes(`$f.FullName, `$b)
    Start-Sleep -Milliseconds 150
}
"@
$intatti = (Get-ChildItem $dir -Filter *.txt | Where-Object { (Get-Content $_.FullName -TotalCount 1) -like 'testo del documento*' }).Count
"finto ransomware: codice di uscita $($p.ExitCode) (1 = terminato da Vigil); documenti rimasti intatti: $intatti su 15"

'== 2. file esca'
$esca = Join-Path $env:USERPROFILE 'Documents\!Vigil - non modificare.docx'
"file esca presente: $(Test-Path $esca)"
$p = Start-Child "Rename-Item -LiteralPath '$esca' -NewName 'rinominato.docx' -ErrorAction Stop; Start-Sleep 5"
"processo che rinomina l'esca: codice di uscita $($p.ExitCode); esca ancora al suo posto: $(Test-Path $esca)"
