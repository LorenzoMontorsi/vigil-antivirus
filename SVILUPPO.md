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

La VM di test: Windows 10 con `testsigning` e debug kernel attivi, utente `vigil`, SSH con chiave.
Se la VM gira su un PC diverso da quello di sviluppo, la scheda di rete va in **bridged**
(`ethernet0.connectionType = "bridged"` nel `.vmx`) e l'IP va scritto in `ip.txt` accanto al `.vmx`
(lo legge `driver\vm-test.ps1`, modificare il percorso se cambia).

## 4. Stato dei lavori (3 novembre 2026)

Fatto e verificato:
- motore (YARA-Forge, hash, ZIP, euristica, Authenticode, cache), ClamAV incluso, quarantena, GUI
- minifilter `VigilFlt` + `vigil-rtd`: blocco dell'esecuzione verificato nella VM

**In corso (codice scritto, NON ancora compilato/provato del tutto):**
- `crates/rtd`: `vigil-rtd` come servizio Windows `VigilRtd` (moduli `service`, `ipc`, `driver`, `state`),
  pipe `\\.\pipe\vigil-rtd`, coda per i file scritti con quarantena automatica, cache sull'esecuzione.
  I test unitari passavano; manca la prova nella VM (`driver\vm-test.ps1`, che ora installa il servizio).
- `crates/engine/src/rtproto.rs`: protocollo condiviso servizio ↔ app.
- `app/src-tauri/src/rt.rs`: l'app interroga il servizio ogni 2 s, notifiche Windows, interruttore con UAC.
  Il backend compilava; **manca tutta la parte React** (tipi in `api.ts`, hook, scheda in Panoramica,
  sezione in Impostazioni, voci nel `devMock.ts`).

Da fare dopo:
- la quarantena del servizio sta in `C:\ProgramData\Vigil\quarantine`: va mostrata anche nella pagina Quarantena
- cache e ClamAV sul percorso in tempo reale, AMSI, ETW, autodifesa, installer
