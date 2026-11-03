# Primo avvio della VM di test di Vigil: modalità test per i driver,
# debug del kernel su COM1 e server SSH per il controllo dall'host.
$ErrorActionPreference = 'Continue'
Start-Transcript -Path C:\vigil-firstboot.log

# Driver firmati con certificato di test + debugger del kernel su seriale.
bcdedit /set testsigning on
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

# Niente sospensione: la VM deve restare raggiungibile.
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /h off

# Server SSH (richiede Internet, disponibile tramite la NAT di VMware).
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
