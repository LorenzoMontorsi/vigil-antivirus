# Sviluppo di Vigil: come ripartire su un altro PC

## 1. Strumenti

- Windows 10/11 x64, Git, [Rust](https://rustup.rs/) (target `x86_64-pc-windows-msvc`), Node.js 20+
- Visual Studio 2022 Community con il carico di lavoro "Sviluppo di applicazioni desktop con C++"
  (serve anche per compilare il driver: il WDK arriva da NuGet, niente estensione WDK)
- [GitHub CLI](https://cli.github.com/) per il push (`gh auth login`)
- VMware Workstation Player 17 per la VM di test del driver

## 2. Dopo il clone

```powershell
git clone https://github.com/LorenzoMontorsi/vigil-antivirus.git
cd vigil-antivirus
git config user.email "138049722+LorenzoMontorsi@users.noreply.github.com"   # email anonima nei commit

.\scripts\fetch-clamav.ps1                       # ClamAV 1.5.4 in vendor\clamav (SHA-256 verificato)
cd app; npm install; cd ..
cargo test --workspace
```

Driver (WDK via NuGet, ~1,4 GB):

```powershell
cd driver
mkdir tools; curl.exe -L -o tools\nuget.exe https://dist.nuget.org/win-x86-commandline/latest/nuget.exe
.\tools\nuget.exe restore packages.config -PackagesDirectory packages
.\build.ps1
.\sign-test.ps1      # crea un NUOVO certificato di test sul PC (non va mai importato sull'host)
```

## 3. Cose che NON sono nel repository (da ricreare)

| Cosa | Dove stava | Come ricrearla |
|---|---|---|
| Auth-Key MalwareBazaar | impostazioni dell'app (`%APPDATA%\dev.lorenzo.antivirus\settings.json`) | reinserirla in Impostazioni |
| Certificato di test del driver | archivio certificati utente | `driver\sign-test.ps1` ne crea uno nuovo |
| VM di test | `H:\VM\vigil-vmware` (+ chiave SSH in `H:\VM\vigil-test\ssh`) | copiare la cartella, oppure reinstallare con `autounattend.xml` |
| ClamAV, WDK | `vendor\`, `driver\packages\` | script sopra |

### VM di test

```powershell
# Crea la VM (installazione di Windows 10 senza clic, testsigning, debug kernel, SSH con chiave)
.\driver\vm\new-vm.ps1 -WindowsIso C:\percorso\Windows.iso          # default: C:\VM\vigil-vmware
& "${env:ProgramFiles(x86)}\VMware\VMware Player\vmrun.exe" -T player start C:\VM\vigil-vmware\Vigil-Test.vmx gui
# ~30 minuti dopo la VM risponde via SSH: scrivere il suo IP in C:\VM\vigil-vmware\ip.txt
.\driver\vm-test.ps1      # installa driver + servizio VigilRtd e prova blocco e quarantena
```

Usare la ISO **ufficiale** Microsoft di Windows 10 (19041 o successive, italiano: l'`autounattend.xml` usa it-IT).
Se la VM gira su un PC diverso da quello di sviluppo, la scheda di rete va in **bridged**.

### Consiglio: cartella `target` su un disco interno

La compilazione scrive decine di migliaia di file: su un disco esterno exFAT un solo scollegamento
rovina il file system. Meglio:

```powershell
[Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR', 'C:\Dev\vigil-target', 'User')
```

## 4. Stato dei lavori (3 novembre 2026, sera)

Fatto e verificato nella VM:
- motore (YARA-Forge, hash, ZIP, euristica, Authenticode, cache), ClamAV incluso, quarantena, GUI
- minifilter `VigilFlt` + servizio Windows `VigilRtd` (avvio automatico, dipende dal driver):
  - blocco dell'esecuzione delle minacce (con il processo che le ha lanciate)
  - quarantena automatica dei file appena scritti
  - named pipe `\\.\pipe\vigil-rtd` con stato, statistiche ed eventi
- app: modulo e scheda "Attività in tempo reale" in Panoramica, interruttore in Impostazioni (UAC),
  notifiche di Windows. Verificata con dati di esempio (`?rt=on` nel devMock), **non ancora con il
  servizio vero**: l'app andrebbe provata dentro la VM.

Aggiunto e verificato nella VM (sera del 3 novembre):
- icona nell'area di notifica con menu (sospensione 5 min…fino al riavvio), avvisi a popup con azioni
- ClamAV scaricato da solo se manca; certificati radice per freshclam su Windows appena installati
- quarantena del servizio nella pagina Quarantena; avvio con Windows nascosto nella barra
- **protezione script (AMSI)**: `crates/amsi` è un provider COM che inoltra gli script al servizio;
  installazione nella VM con `driver\vm\amsi-install.ps1` (DLL firmata con `sign-test.ps1 -Files`),
  prova con `driver\vm\amsi-test.ps1` eseguito come utente (`as-user.ps1`)

Per le prove nella VM: `npm run tauri build -- --debug --no-bundle` è molto più veloce della release
(ha una console nera: normale per la build di debug).

Da fare:
- la quarantena del servizio sta in `C:\ProgramData\Vigil\quarantine`: va mostrata nella pagina Quarantena
- ClamAV sul percorso in tempo reale, AMSI, ETW, autodifesa, installer unico (app + servizio + driver)
- altitudine ufficiale da Microsoft e firma del driver per poterlo usare fuori dalla VM
