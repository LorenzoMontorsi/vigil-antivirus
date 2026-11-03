# Eseguito NELLA VM come AMMINISTRATORE (via SSH): prova l'autodifesa di Vigil.
# Anche un amministratore non deve poter terminare il servizio o toccare i suoi file;
# fermarlo dal Gestore servizi invece resta possibile (manutenzione).
$ErrorActionPreference = 'Continue'
$p = Get-Process vigil-rtd -ErrorAction SilentlyContinue
"servizio in esecuzione: pid $($p.Id)"

'== 1. terminare il processo del servizio'
try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; 'Stop-Process -> TERMINATO (male!)' } catch { 'Stop-Process -> ' + $_.Exception.Message }
$r = taskkill /F /PID $p.Id 2>&1 | Out-String
'taskkill /F -> ' + $r.Trim()
Start-Sleep 1
'servizio ancora vivo: ' + [bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue)

'== 2. file di Vigil'
$bin = 'C:\Program Files\Vigil'
try { Set-Content "$bin\intruso.txt" 'x' -ErrorAction Stop; 'scrivere in Program Files\Vigil -> RIUSCITO (male!)' } catch { 'scrivere in Program Files\Vigil -> ' + $_.Exception.Message }
try { Remove-Item "$bin\vigil-rtd.exe" -Force -ErrorAction Stop; 'cancellare vigil-rtd.exe -> RIUSCITO (male!)' } catch { 'cancellare vigil-rtd.exe -> ' + $_.Exception.Message }
try { Rename-Item "$bin\vigil-rtd.exe" 'x.exe' -ErrorAction Stop; 'rinominare vigil-rtd.exe -> RIUSCITO (male!)' } catch { 'rinominare vigil-rtd.exe -> ' + $_.Exception.Message }
try { Remove-Item 'C:\ProgramData\Vigil\quarantine\key.bin' -Force -ErrorAction Stop; 'cancellare la chiave della quarantena -> RIUSCITO (male!)' } catch { 'cancellare la chiave della quarantena -> ' + $_.Exception.Message }
'leggere vigil-rtd.exe (deve funzionare): ' + ((Get-Item "$bin\vigil-rtd.exe").Length -gt 0)

'== 3. manutenzione: fermarlo dal Gestore servizi resta possibile'
Stop-Service VigilRtd -Force; Start-Sleep 2
'dopo Stop-Service: ' + (Get-Service VigilRtd).Status
try { Set-Content "$bin\manutenzione.txt" 'ok' -ErrorAction Stop; 'scrivere col servizio fermo -> consentito' ; Remove-Item "$bin\manutenzione.txt" } catch { 'scrivere col servizio fermo -> ' + $_.Exception.Message }
Start-Service VigilRtd; Start-Sleep 4
'riavviato: ' + (Get-Service VigilRtd).Status
