//! Gestione di ClamAV come secondo motore: configurazione, aggiornamento firme
//! (freshclam, il client ufficiale) e demone di scansione (clamd).

use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::Serialize;
use vigil_engine::clamd::ClamdClient;

use crate::util::hide_window;

pub const PORT: u16 = 33100;

/// Versione di ClamAV usata da Vigil: la stessa di scripts/fetch-clamav.ps1.
/// L'hash è quello del pacchetto ufficiale verificato con la firma GPG di Cisco Talos.
pub const CLAMAV_VERSION: &str = "1.5.4";
const CLAMAV_SHA256: &str = "0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395";
const UA: &str = concat!("Vigil/", env!("CARGO_PKG_VERSION"));

/// Scarica ClamAV dalle release ufficiali, ne verifica lo SHA-256 ed estrae in `dest`
/// solo i file che servono (clamd, freshclam, DLL, certificati, licenze).
pub fn download(dest: &Path, mut log: impl FnMut(&str)) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};

    let name = format!("clamav-{CLAMAV_VERSION}.win.x64");
    let url = format!("https://github.com/Cisco-Talos/clamav/releases/download/clamav-{CLAMAV_VERSION}/{name}.zip");
    let parent = dest.parent().ok_or("cartella di destinazione non valida")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let zip_path = parent.join(format!("{name}.zip.part"));

    let resp = ureq::get(&url)
        .set("User-Agent", UA)
        .timeout(Duration::from_secs(1800))
        .call()
        .map_err(|e| format!("download di ClamAV: {e}"))?;
    let total_mb = resp.header("Content-Length").and_then(|v| v.parse::<u64>().ok()).map(|b| b / (1024 * 1024));
    let mut reader = resp.into_reader().take(512 * 1024 * 1024);
    let mut file = fs::File::create(&zip_path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let (mut done, mut next_report) = (0u64, 0u64);
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("download interrotto: {e}"))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        hasher.update(&buf[..n]);
        done += n as u64;
        if done >= next_report {
            let mb = done / (1024 * 1024);
            log(&match total_mb {
                Some(t) => format!("scaricati {mb} di {t} MB"),
                None => format!("scaricati {mb} MB"),
            });
            next_report += 25 * 1024 * 1024;
        }
    }
    drop(file);
    let hash: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if hash != CLAMAV_SHA256 {
        let _ = fs::remove_file(&zip_path);
        return Err(format!("SHA-256 del pacchetto non corrispondente (atteso {CLAMAV_SHA256}, trovato {hash}): scartato"));
    }
    log("SHA-256 verificato, estrazione…");

    let tmp = dest.with_extension("tmp");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(fs::File::open(&zip_path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        // enclosed_name rifiuta i percorsi che uscirebbero dalla cartella ("..", assoluti).
        let Some(rel) = entry.enclosed_name() else { continue };
        let Ok(rel) = rel.strip_prefix(&name) else { continue };
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let top_level_dll = rel_str.ends_with(".dll") && !rel_str.contains('/') && rel_str != "pdcurses.dll";
        let keep = matches!(rel_str.as_str(), "clamd.exe" | "freshclam.exe" | "COPYING.txt")
            || top_level_dll
            || rel_str.starts_with("certs/")
            || rel_str.starts_with("COPYING/");
        if !keep || entry.is_dir() {
            continue;
        }
        let out = tmp.join(rel);
        if let Some(p) = out.parent() {
            fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let mut f = fs::File::create(&out).map_err(|e| e.to_string())?;
        std::io::copy(&mut entry, &mut f).map_err(|e| e.to_string())?;
    }
    fs::write(tmp.join("VERSION"), CLAMAV_VERSION).map_err(|e| e.to_string())?;
    let _ = fs::write(
        tmp.join("LEGGIMI-CLAMAV.txt"),
        format!(
            "ClamAV {CLAMAV_VERSION} - Copyright (C) Cisco Systems, Inc. e contributori.\r\n\
             Distribuito sotto GNU GPL v2 (vedi COPYING.txt e la cartella COPYING).\r\n\
             Codice sorgente: https://github.com/Cisco-Talos/clamav/releases/tag/clamav-{CLAMAV_VERSION}\r\n"
        ),
    );
    if !is_valid_install(&tmp) {
        return Err("pacchetto di ClamAV incompleto".into());
    }
    let _ = fs::remove_dir_all(dest);
    fs::rename(&tmp, dest).map_err(|e| e.to_string())?;
    let _ = fs::remove_file(&zip_path);
    Ok(())
}

/// Su un Windows installato da poco i certificati radice non ci sono tutti:
/// Windows li scarica da Windows Update solo quando serve a un programma che usa
/// il SUO motore TLS (Schannel). freshclam usa OpenSSL, che legge l'archivio di
/// Windows ma non fa scattare quel download, e fallisce con "SSL peer certificate
/// … was not OK" (errore 60). Un collegamento con curl.exe di Windows (Schannel)
/// allo stesso sito fa installare il certificato mancante. Innocuo se c'è già.
fn warm_root_certificates() {
    let system = std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| r"C:\Windows".into());
    let curl = system.join(r"System32\curl.exe");
    if !curl.is_file() {
        return;
    }
    let mut cmd = Command::new(curl);
    cmd.args(["-s", "-o", "NUL", "-I", "--max-time", "20", "https://database.clamav.net/"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    hide_window(&mut cmd);
    let _ = cmd.status();
}

pub fn is_valid_install(dir: &Path) -> bool {
    dir.join("clamd.exe").is_file() && dir.join("freshclam.exe").is_file()
}

#[derive(Debug, Clone, Serialize)]
pub struct ClamStatus {
    pub installed: bool,
    /// Versione di ClamAV inclusa in Vigil.
    pub bundled_version: Option<String>,
    pub database: bool,
    pub running: bool,
    pub starting: bool,
    pub version: Option<String>,
}

pub struct ClamAv {
    home: PathBuf,
    child: Mutex<Option<Child>>,
    starting: std::sync::atomic::AtomicBool,
}

impl ClamAv {
    pub fn new(home: PathBuf) -> Self {
        let _ = fs::create_dir_all(home.join("database"));
        Self { home, child: Mutex::new(None), starting: Default::default() }
    }

    fn db_dir(&self) -> PathBuf {
        self.home.join("database")
    }

    pub fn client(&self) -> ClamdClient {
        ClamdClient::new(([127, 0, 0, 1], PORT).into())
    }

    pub fn has_database(&self) -> bool {
        let db = self.db_dir();
        let any = |base: &str| ["cvd", "cld"].iter().any(|ext| db.join(format!("{base}.{ext}")).is_file());
        any("main") && any("daily")
    }

    pub fn status(&self, install: &Path) -> ClamStatus {
        let client = self.client();
        let running = client.ping();
        ClamStatus {
            installed: is_valid_install(install),
            bundled_version: fs::read_to_string(install.join("VERSION")).ok().map(|v| v.trim().to_owned()),
            database: self.has_database(),
            running,
            starting: !running && self.starting.load(std::sync::atomic::Ordering::Relaxed),
            version: if running { client.version().ok() } else { None },
        }
    }

    fn write_configs(&self, max_file_mb: u64) -> Result<(PathBuf, PathBuf), String> {
        let h = self.home.display();
        let db = self.db_dir();
        let db = db.display();
        let limit = max_file_mb.max(25);
        let freshclam = format!(
            "DatabaseDirectory {db}\r\nDatabaseMirror database.clamav.net\r\nUpdateLogFile {h}\\freshclam.log\r\nLogFileMaxSize 2M\r\n"
        );
        let clamd = format!(
            "TCPSocket {PORT}\r\nTCPAddr 127.0.0.1\r\nDatabaseDirectory {db}\r\nLogFile {h}\\clamd.log\r\nLogFileMaxSize 5M\r\n\
             MaxThreads 8\r\nStreamMaxLength {limit}M\r\nMaxFileSize {limit}M\r\nMaxScanSize {}M\r\nForeground yes\r\n",
            limit * 4
        );
        let f = self.home.join("freshclam.conf");
        let c = self.home.join("clamd.conf");
        fs::write(&f, freshclam).map_err(|e| e.to_string())?;
        fs::write(&c, clamd).map_err(|e| e.to_string())?;
        Ok((f, c))
    }

    /// Aggiorna le firme con freshclam. `on_line` riceve l'output utile.
    pub fn update(&self, install: &Path, max_file_mb: u64, mut on_line: impl FnMut(&str)) -> Result<(), String> {
        if !is_valid_install(install) {
            return Err("ClamAV incluso non trovato: reinstalla Vigil (in sviluppo: esegui scripts/fetch-clamav.ps1)".into());
        }
        let (fconf, _) = self.write_configs(max_file_mb)?;
        warm_root_certificates();
        let mut cmd = Command::new(install.join("freshclam.exe"));
        cmd.arg(format!("--config-file={}", fconf.display()))
            .arg("--stdout")
            .current_dir(install)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        hide_window(&mut cmd);
        let mut child = cmd.spawn().map_err(|e| format!("avvio di freshclam fallito: {e}"))?;
        if let Some(out) = child.stdout.take() {
            // La barra di avanzamento usa '\r': teniamo solo le righe di testo vere.
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                for part in line.split('\r') {
                    let part = part.trim();
                    if !part.is_empty() && !part.starts_with("Time:") {
                        on_line(part);
                    }
                }
            }
        }
        let status = child.wait().map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("freshclam è terminato con codice {:?}", status.code()));
        }
        // Se il demone è attivo, gli facciamo ricaricare le firme nuove.
        let client = self.client();
        if client.ping() {
            let _ = client.reload();
        }
        Ok(())
    }

    /// Avvia clamd (se non è già in ascolto) e attende che abbia caricato le firme.
    pub fn start(&self, install: &Path, max_file_mb: u64) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        let client = self.client();
        if client.ping() {
            return Ok(());
        }
        if !is_valid_install(install) {
            return Err("ClamAV incluso non trovato".into());
        }
        if !self.has_database() {
            return Err("firme di ClamAV assenti: esegui prima l'aggiornamento".into());
        }
        if self.starting.swap(true, Ordering::SeqCst) {
            return Err("ClamAV si sta già avviando".into());
        }
        let result = (|| {
            let (_, cconf) = self.write_configs(max_file_mb)?;
            let mut cmd = Command::new(install.join("clamd.exe"));
            cmd.arg(format!("--config-file={}", cconf.display()))
                .current_dir(install)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            hide_window(&mut cmd);
            let child = cmd.spawn().map_err(|e| format!("avvio di clamd fallito: {e}"))?;
            *self.child.lock().unwrap() = Some(child);

            // Il caricamento di ~3,6 milioni di firme richiede da 10 a 60 secondi.
            let t = Instant::now();
            loop {
                if client.ping() {
                    return Ok(());
                }
                if let Some(c) = self.child.lock().unwrap().as_mut() {
                    if let Ok(Some(code)) = c.try_wait() {
                        return Err(format!("clamd si è chiuso subito (codice {:?}): vedi clamd.log", code.code()));
                    }
                }
                if t.elapsed() > Duration::from_secs(240) {
                    return Err("clamd non risponde dopo 4 minuti".into());
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        })();
        self.starting.store(false, Ordering::SeqCst);
        result
    }

    /// Ferma il demone avviato da Vigil.
    pub fn stop(&self) {
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = self.client().shutdown();
            let t = Instant::now();
            while t.elapsed() < Duration::from_secs(3) {
                if let Ok(Some(_)) = c.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = c.kill();
        }
    }
}
