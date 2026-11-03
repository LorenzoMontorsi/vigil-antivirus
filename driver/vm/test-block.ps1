# Eseguito NELLA VM: un eseguibile pulito deve partire, uno marcato deve essere bloccato.
$ErrorActionPreference = 'Continue'
$dir = 'C:\Vigil\prova'
New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item C:\Windows\System32\whoami.exe "$dir\pulito.exe" -Force
Copy-Item C:\Windows\System32\whoami.exe "$dir\marcato.exe" -Force
# Il marcatore in coda (overlay) non impedisce l'esecuzione, ma la regola YARA di prova lo riconosce.
[IO.File]::AppendAllText("$dir\marcato.exe", 'VIGIL-TEST-QUARANTENA-7f3a')
Start-Sleep 2

foreach ($name in 'pulito', 'marcato') {
    $exe = Join-Path $dir "$name.exe"
    try {
        $out = & $exe 2>&1
        "{0}.exe -> PARTITO (output: {1})" -f $name, ($out -join ' ')
    } catch {
        "{0}.exe -> BLOCCATO ({1})" -f $name, $_.Exception.Message
    }
}
Start-Sleep 1
'--- log vigil-rtd (ultime righe):'
Get-Content C:\Vigil\rtd.log -Tail 12
