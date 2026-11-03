# Vigil

Antivirus open source per Windows, scritto in **Rust** (motore, app, servizio) e **C** (driver kernel), con interfaccia in **Tauri + React**.

> ⚠️ **Progetto sperimentale.** Non sostituisce Microsoft Defender né un antivirus commerciale. La protezione in tempo reale funziona solo su macchine di test con firma dei driver in modalità test.

## Cosa fa

| Funzione | Stato |
|---|---|
| Scansione su richiesta (rapida, completa, personalizzata) | ✅ |
| Firme: hash SHA-256 + regole YARA ([yara-x](https://github.com/VirusTotal/yara-x)) | ✅ |
| Aggiornamento automatico firme: [YARA-Forge](https://github.com/YARAHQ/yara-forge), [MalwareBazaar](https://bazaar.abuse.ch/) (con Auth-Key gratuita) | ✅ |
| Secondo motore [ClamAV](https://www.clamav.net/) incluso (clamd + freshclam) | ✅ |
| Archivi ZIP annidati con protezione anti zip-bomb | ✅ |
| Euristica PE (packer, sezioni W+X, entropia, import sospetti, doppie estensioni, RLO) | ✅ |
| Verifica firme Authenticode (anche da catalogo) e fiducia nei file Microsoft | ✅ |
| Cache delle scansioni | ✅ |
| Quarantena cifrata (ChaCha20-Poly1305) con ripristino, anche automatica | ✅ |
| Esclusioni per percorso ed estensione | ✅ |
| Protezione in tempo reale: minifilter `VigilFlt` + servizio `vigil-rtd` | 🧪 funziona in VM (blocco dell'esecuzione) |
| Protezione script (AMSI), analisi comportamentale (ETW), autodifesa | 🛠️ da fare |

## Struttura

```
crates/engine     motore di scansione (libreria Rust, testata)
crates/rtd        lato utente della protezione in tempo reale
app/              app desktop Tauri (backend Rust in src-tauri, interfaccia React in src)
driver/VigilFlt   minifilter kernel in C
driver/vm         script di installazione e prova nella VM di test
scripts/          utilità (download verificato di ClamAV)
```

## Compilare

Requisiti: Windows 10/11 x64, [Rust](https://rustup.rs/), Node.js, Visual Studio 2022 (carico di lavoro C++).

```powershell
# ClamAV (versione fissata, SHA-256 verificato)
.\scripts\fetch-clamav.ps1

# App
cd app
npm install
npm run tauri dev        # sviluppo
npm run tauri build      # installer

# Test del motore
cargo test -p vigil-engine
```

### Driver (solo per sviluppo, in una VM)

```powershell
cd driver
.\tools\nuget.exe restore packages.config -PackagesDirectory packages   # WDK via NuGet
.\build.ps1          # compila VigilFlt.sys con cl/link
.\sign-test.ps1      # firma con un certificato di TEST
.\vm-test.ps1        # installa nella VM e prova il blocco
```

La VM deve avere `bcdedit /set testsigning on`. **Non** installare il certificato di test sul PC principale.
L'altitudine del minifilter (328500) è provvisoria: per distribuire il driver servono un'altitudine assegnata da Microsoft e la firma tramite il programma hardware di Microsoft.

## Licenza

GPL-3.0-or-later (vedi [LICENSE](LICENSE)).
ClamAV è distribuito separatamente sotto GPL-2.0 da Cisco Talos: Vigil lo usa come programma esterno, senza modificarlo.
Le regole YARA-Forge e i dati di MalwareBazaar hanno le proprie licenze e condizioni d'uso.
