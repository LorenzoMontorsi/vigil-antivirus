# Primo avvio della VM CKS di Vigil (firmware OVMF/UEFI, Secure Boot ACCESO).
# A differenza della VM BIOS, qui NON attiviamo il test-signing: vogliamo provare
# proprio il caricamento del driver via Custom Kernel Signers. Serve solo SSH per
# pilotare la VM dall'host (port forward 2222->22 di QEMU user-net).
$ErrorActionPreference = 'Continue'
Start-Transcript -Path C:\vigil-firstboot.log

# Debug del kernel su seriale (comodo per diagnosticare un mancato load del driver).
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

# Niente sospensione: la VM deve restare raggiungibile.
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /h off

# Server SSH (Internet disponibile tramite la user-net di QEMU).
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic
Start-Service sshd
New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell `
    -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force

# Accesso solo con la chiave dell'host (utente amministratore).
$auth = 'C:\ProgramData\ssh\administrators_authorized_keys'
Get-Content (Join-Path $PSScriptRoot 'authorized_key.pub') | Set-Content -Path $auth -Encoding ascii
icacls $auth /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F'
if (-not (Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}

Set-Content -Path C:\vigil-setup-done.txt -Value (Get-Date)
Stop-Transcript
Restart-Computer -Force
