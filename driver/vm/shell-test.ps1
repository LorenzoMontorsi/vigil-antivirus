# Eseguito NELLA VM (amministratore): verifica la voce "Analizza con Vigil" del menu
# del tasto destro e simula ciò che fa Esplora risorse con più elementi selezionati:
# un lancio del comando registrato per ciascun elemento, a pochi millisecondi di distanza.
$ErrorActionPreference = 'Continue'
$check = {
    foreach ($t in '*', 'Directory', 'Drive') {
        $k = "HKCU:\Software\Classes\$t\shell\VigilScan"
        $label = (Get-ItemProperty $k -ErrorAction SilentlyContinue).'(default)'
        $cmd = (Get-ItemProperty "$k\command" -ErrorAction SilentlyContinue).'(default)'
        "[$t] voce: $label | comando: $cmd"
    }
}
$launch = {
    $cmd = (Get-ItemProperty 'HKCU:\Software\Classes\*\shell\VigilScan\command').'(default)'
    $exe = ($cmd -split '"')[1]
    New-Item -ItemType Directory -Force "$env:USERPROFILE\Documents\ProvaMenu" | Out-Null
    'uno' | Set-Content "$env:USERPROFILE\Documents\ProvaMenu\uno.txt"
    'due' | Set-Content "$env:USERPROFILE\Documents\due.txt"
    foreach ($p in "$env:USERPROFILE\Documents\ProvaMenu", "$env:USERPROFILE\Documents\due.txt", 'C:\Windows\notepad.exe') {
        Start-Process $exe -ArgumentList '--scan', "`"$p`""
        Start-Sleep -Milliseconds 150
    }
    'lanciati 3 elementi'
}
& "$PSScriptRoot\as-user.ps1" -Script $check.ToString()
& "$PSScriptRoot\as-user.ps1" -Script $launch.ToString()
Start-Sleep 8
'processi Vigil: ' + @(Get-Process Vigil -ErrorAction SilentlyContinue).Count
& "$PSScriptRoot\screenshot.ps1"
