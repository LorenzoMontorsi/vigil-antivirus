# Eseguito NELLA VM:
#  1. un eseguibile pulito deve partire, uno marcato deve essere bloccato;
#  2. un file marcato appena scritto deve finire in quarantena da solo.
$ErrorActionPreference = 'Continue'
$dir = 'C:\Vigil\prova'
$marker = 'VIGIL-TEST-QUARANTENA-7f3a'
New-Item -ItemType Directory -Force $dir | Out-Null
Remove-Item "$dir\*" -Force -ErrorAction SilentlyContinue

# Gli eseguibili vengono preparati in un'altra cartella e poi spostati:
# copiarli direttamente qui li farebbe già isolare dalla protezione sulla scrittura.
$tmp = Join-Path $env:TEMP 'vigil-prep'
New-Item -ItemType Directory -Force $tmp | Out-Null
Copy-Item C:\Windows\System32\whoami.exe "$dir\pulito.exe" -Force

'== 1. blocco dell''esecuzione'
& "$dir\pulito.exe" | Out-Null
"pulito.exe  -> " + $(if ($?) { 'PARTITO' } else { 'errore' })

# marcato.exe: whoami + marcatore in coda, scritto con un'unica operazione.
$bytes = [IO.File]::ReadAllBytes('C:\Windows\System32\whoami.exe') + [Text.Encoding]::ASCII.GetBytes($marker)
[IO.File]::WriteAllBytes("$dir\marcato.exe", $bytes)
Start-Sleep 3
if (Test-Path "$dir\marcato.exe") {
    try { & "$dir\marcato.exe" | Out-Null; 'marcato.exe -> PARTITO (male!)' }
    catch { 'marcato.exe -> BLOCCATO: ' + $_.Exception.Message }
} else {
    'marcato.exe -> già messo in quarantena alla scrittura (ancora meglio)'
}

'== 2. quarantena automatica alla scrittura'
Set-Content -Path "$dir\scaricato.txt" -Value "documento con marcatore $marker" -Encoding ascii
Start-Sleep 4
'scaricato.txt -> ' + $(if (Test-Path "$dir\scaricato.txt") { 'ANCORA PRESENTE (male!)' } else { 'RIMOSSO e messo in quarantena' })

'== eventi del servizio'
& 'C:\Program Files\Vigil\vigil-rtd.exe' status | Select-String -Pattern '^#|exec_|writes_|quarantined|threats'
