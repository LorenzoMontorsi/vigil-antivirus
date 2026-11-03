//! Analisi comportamentale anti-ransomware.
//!
//! Due segnali, entrambi dal minifilter:
//! 1. **riscrittura cifrata**: un processo che in `WINDOW` riscrive almeno
//!    `THRESHOLD` file GIÀ ESISTENTI nelle cartelle dell'utente con contenuto ad
//!    alta entropia (cioè cifrato). Copiare una cartella crea file nuovi e non
//!    conta: è la differenza tra un ransomware e Esplora risorse o un backup.
//! 2. **file esca**: file nascosti messi da Vigil in Documenti e sul Desktop.
//!    Nessun programma legittimo ha motivo di modificarli, rinominarli o
//!    eliminarli: chi lo fa viene fermato subito.
//!
//! Reazione: il processo viene terminato e, se non è un file di sistema
//! firmato Microsoft, il suo eseguibile finisce in quarantena.

use std::{
    collections::{HashMap, HashSet},
    io::Read,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use vigil_engine::rtproto::RtEventKind;
use windows_sys::Win32::{
    Foundation::CloseHandle,
    Storage::FileSystem::{FILE_ATTRIBUTE_HIDDEN, SetFileAttributesW},
    System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess},
};

use crate::state::Shared;

const WINDOW: Duration = Duration::from_secs(30);
const THRESHOLD: usize = 10;
const HIGH_ENTROPY: f64 = 7.2;
const CANARY_NAME: &str = "!Vigil - non modificare.docx";

/// Programmi che sincronizzano o riscrivono legittimamente molti file dell'utente.
/// Valgono solo per la regola della riscrittura, MAI per i file esca.
const EXEMPT_IMAGES: &[&str] =
    &["onedrive.exe", "dropbox.exe", "googledrivefs.exe", "msmpeng.exe", "searchindexer.exe", "tiworker.exe", "trustedinstaller.exe"];

#[derive(Default)]
struct ProcActivity {
    since: Option<Instant>,
    /// File esistenti riscritti con contenuto cifrato nella finestra corrente.
    encrypted: HashSet<String>,
    stopped: bool,
}

pub struct Behavior {
    procs: Mutex<HashMap<u32, ProcActivity>>,
    canaries: HashSet<String>,
    own_pid: u32,
}

fn key(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

/// Cartelle "dati dell'utente": sotto C:\Users ma fuori da AppData
/// (cache di browser, aggiornamenti e simili sono naturalmente ad alta entropia).
fn is_user_data(path: &Path) -> bool {
    let p = key(path);
    p.starts_with(r"c:\users\") && !p.contains(r"\appdata\")
}

fn entropy_of(path: &Path) -> Option<f64> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = f.read(&mut buf).ok()?;
    if n < 512 {
        return None; // troppo piccolo per dire qualcosa
    }
    let mut counts = [0u64; 256];
    for &b in &buf[..n] {
        counts[b as usize] += 1;
    }
    let len = n as f64;
    Some(counts.iter().filter(|&&c| c > 0).map(|&c| -(c as f64 / len) * (c as f64 / len).log2()).sum())
}

impl Behavior {
    /// Prepara i file esca nelle cartelle Documenti e Desktop di tutti i profili.
    pub fn new() -> Self {
        let mut canaries = HashSet::new();
        if let Ok(entries) = std::fs::read_dir(r"C:\Users") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_lowercase();
                if matches!(name.as_str(), "public" | "default" | "default user" | "all users") || !e.path().is_dir() {
                    continue;
                }
                for sub in ["Documents", "Desktop"] {
                    let dir = e.path().join(sub);
                    if dir.is_dir() {
                        let file = dir.join(CANARY_NAME);
                        if !file.exists() {
                            // Contenuto a bassa entropia, plausibile: un file esca deve sembrare un documento.
                            let text = "Documento di controllo di Vigil. Non modificarlo né spostarlo: \
                                        serve a riconoscere i ransomware.\r\n"
                                .repeat(64);
                            if std::fs::write(&file, text).is_ok() {
                                let wide: Vec<u16> = file.as_os_str().to_string_lossy().encode_utf16().chain(Some(0)).collect();
                                unsafe { SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN) };
                            }
                        }
                        canaries.insert(key(&file));
                    }
                }
            }
        }
        println!("anti-ransomware: {} file esca", canaries.len());
        Self { procs: Mutex::new(HashMap::new()), canaries, own_pid: std::process::id() }
    }

    fn is_canary(&self, path: &Path) -> bool {
        self.canaries.contains(&key(path))
    }

    /// Rinomina o eliminazione: `true` se va bloccata (file esca).
    ///
    /// Solo la decisione: il processo va fermato DOPO aver risposto al driver con
    /// `stop_after_block`. Terminandolo prima, si interromperebbe la sua attesa nel
    /// kernel e il driver (fail-open) lascerebbe passare l'operazione.
    pub fn should_block_rename_or_delete(&self, path: &Path, pid: u32) -> bool {
        pid != self.own_pid && self.is_canary(path)
    }

    pub fn stop_after_block(&self, shared: &Shared, path: &Path, pid: u32) {
        self.stop(shared, pid, format!("ha tentato di rinominare o eliminare il file esca {}", path.display()));
    }

    /// Un file modificato è stato chiuso. `existed`: c'era già (riscritto, non creato).
    pub fn on_modified(&self, shared: &Shared, path: &Path, pid: u32, existed: bool) {
        if pid == self.own_pid || pid <= 4 {
            return;
        }
        if self.is_canary(path) {
            self.stop(shared, pid, format!("ha modificato il file esca {}", path.display()));
            return;
        }
        if !existed || !is_user_data(path) || !entropy_of(path).is_some_and(|e| e >= HIGH_ENTROPY) {
            return;
        }
        let image = crate::driver::process_image(pid).unwrap_or_default();
        let name = image.rsplit('\\').next().unwrap_or("").to_lowercase();
        if EXEMPT_IMAGES.contains(&name.as_str()) {
            return;
        }
        let count = {
            let mut procs = self.procs.lock().unwrap();
            let a = procs.entry(pid).or_default();
            if a.stopped {
                return;
            }
            if a.since.is_none_or(|t| t.elapsed() > WINDOW) {
                a.since = Some(Instant::now());
                a.encrypted.clear();
            }
            a.encrypted.insert(key(path));
            if a.encrypted.len() >= THRESHOLD {
                a.stopped = true;
            }
            a.encrypted.len()
        };
        if count >= THRESHOLD {
            self.stop(shared, pid, format!("ha riscritto con contenuto cifrato {count} file dell'utente in pochi secondi"));
        }
    }

    /// Termina il processo, isola il suo eseguibile e registra l'evento.
    fn stop(&self, shared: &Shared, pid: u32, reason: String) {
        let image = crate::driver::process_image(pid);
        let killed = unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            let ok = !h.is_null() && TerminateProcess(h, 1) != 0;
            if !h.is_null() {
                CloseHandle(h);
            }
            ok
        };
        self.procs.lock().unwrap().entry(pid).or_default().stopped = true;
        shared.stats.lock().unwrap().ransomware_blocked += 1;
        let shown = image.clone().unwrap_or_else(|| format!("processo {pid}"));
        println!("RANSOMWARE {shown}: {reason} — terminato: {killed}");

        // L'eseguibile va in quarantena, salvo che sia un file di Windows firmato Microsoft
        // (per esempio uno script malevolo eseguito da powershell.exe: si ferma il processo,
        // non si toglie PowerShell dal sistema).
        let mut detail = format!("{reason}. Processo {}.", if killed { "terminato" } else { "NON terminato" });
        if let (Some(img), Some(q), true) = (&image, &shared.quarantine, shared.config.auto_quarantine) {
            let img_path = PathBuf::from(img);
            let system = key(&img_path).starts_with(r"c:\windows\");
            let microsoft = vigil_engine::trust::signer(&img_path).is_some_and(|s| vigil_engine::trust::is_microsoft(&s));
            if !system && !microsoft {
                std::thread::sleep(Duration::from_millis(500)); // lascia chiudere il processo
                match q.add(&img_path, "Comportamento da ransomware", "behavior") {
                    Ok(_) => detail.push_str(" Eseguibile messo in quarantena."),
                    Err(e) => detail.push_str(&format!(" Eseguibile non isolato: {e}.")),
                }
            }
        }
        shared.push_event(RtEventKind::RansomwareBlocked, shown, "Comportamento da ransomware".into(), image, Some(detail));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_data_excludes_appdata() {
        assert!(is_user_data(Path::new(r"C:\Users\Lorenzo\Documents\tesi.docx")));
        assert!(!is_user_data(Path::new(r"C:\Users\Lorenzo\AppData\Local\Temp\x.tmp")));
        assert!(!is_user_data(Path::new(r"D:\Foto\a.jpg")));
    }

    #[test]
    fn entropy_distinguishes_text_and_random() {
        let d = tempfile::tempdir().unwrap();
        let text = d.path().join("t.txt");
        std::fs::write(&text, "testo semplice ripetuto ".repeat(200)).unwrap();
        let rnd = d.path().join("r.bin");
        // pseudo-casuale deterministico (xorshift): simula un file cifrato
        let mut x: u64 = 0x9e3779b97f4a7c15;
        let data: Vec<u8> = (0..8192).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x as u8 }).collect();
        std::fs::write(&rnd, data).unwrap();
        assert!(entropy_of(&text).unwrap() < 5.0);
        assert!(entropy_of(&rnd).unwrap() > HIGH_ENTROPY);
    }
}
