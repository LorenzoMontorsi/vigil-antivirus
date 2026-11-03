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
