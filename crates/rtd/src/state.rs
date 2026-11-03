//! Stato condiviso del servizio: motore, statistiche, eventi recenti.

use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use vigil_engine::{
    Engine, EngineBuilder, Exclusions, ScanCache,
    quarantine::Quarantine,
    rtproto::{PAUSED_UNTIL_RESTART, RtEvent, RtEventKind, RtStats, RtStatus},
};

const MAX_EVENTS: usize = 500;

pub struct Config {
    pub signature_dirs: Vec<PathBuf>,
    pub quarantine_dir: Option<PathBuf>,
    pub auto_quarantine: bool,
    pub threads: usize,
    /// Cartella per log degli eventi e cache (ProgramData\Vigil).
    pub data_dir: PathBuf,
    /// Autodifesa anche della cartella del programma (solo come servizio installato:
    /// in sviluppo bloccherebbe la cartella di compilazione).
    pub protect_install_dir: bool,
}

pub struct Shared {
    pub config: Config,
    engine: RwLock<Arc<Engine>>,
    cache: RwLock<Arc<ScanCache>>,
    pub quarantine: Option<Quarantine>,
    pub stats: Mutex<RtStats>,
    events: Mutex<VecDeque<RtEvent>>,
    next_id: AtomicU64,
    pub driver_connected: AtomicBool,
    started_at: u64,
    /// 0 = attiva; altrimenti istante di ripresa (o PAUSED_UNTIL_RESTART).
    paused_until: AtomicU64,
    exclusions: RwLock<Exclusions>,
    /// Ultimo blocco per percorso: Windows ritenta subito lo stesso caricamento,
    /// e un solo evento basta.
    recent_blocks: Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn build_engine(dirs: &[PathBuf]) -> Engine {
    let mut b = EngineBuilder::new();
    for d in dirs {
        b.load_signature_dir(d);
    }
    b.build()
}

fn cache_for(engine: &Engine, data_dir: &std::path::Path) -> ScanCache {
    let i = engine.info();
    // Generazione legata alle firme: se cambiano, la cache riparte da zero.
    ScanCache::load(data_dir.join("rtd-cache.bin"), format!("rtd|{}|{}|{}", i.version, i.yara_rules, i.hash_signatures))
}

impl Shared {
    pub fn new(config: Config) -> Result<Self, String> {
        let _ = std::fs::create_dir_all(&config.data_dir);
        let engine = build_engine(&config.signature_dirs);
        let cache = cache_for(&engine, &config.data_dir);
        let quarantine = match &config.quarantine_dir {
            Some(d) => Some(Quarantine::open(d).map_err(|e| format!("quarantena {}: {e}", d.display()))?),
            None => None,
        };
        Ok(Self {
            engine: RwLock::new(Arc::new(engine)),
            cache: RwLock::new(Arc::new(cache)),
            quarantine,
            stats: Mutex::new(RtStats::default()),
            events: Mutex::new(VecDeque::new()),
            next_id: AtomicU64::new(1),
            driver_connected: AtomicBool::new(false),
            started_at: now(),
            paused_until: AtomicU64::new(0),
            exclusions: RwLock::new(load_exclusions(&config.data_dir)),
            recent_blocks: Mutex::new(std::collections::HashMap::new()),
            config,
        })
    }

    pub fn engine(&self) -> Arc<Engine> {
        self.engine.read().unwrap().clone()
    }

    pub fn cache(&self) -> Arc<ScanCache> {
        self.cache.read().unwrap().clone()
    }

    pub fn reload(&self) {
        let engine = build_engine(&self.config.signature_dirs);
        let cache = cache_for(&engine, &self.config.data_dir);
        let _ = self.cache().save();
        *self.cache.write().unwrap() = Arc::new(cache);
        *self.engine.write().unwrap() = Arc::new(engine);
    }

    pub fn save_cache(&self) {
        let _ = self.cache().save();
    }

    pub fn push_event(&self, kind: RtEventKind, path: String, threat: String, process: Option<String>, detail: Option<String>) {
        let ev = RtEvent { id: self.next_id.fetch_add(1, Ordering::SeqCst), time: now(), kind, path, threat, process, detail };
        // Registro persistente (una riga JSON per evento).
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(self.config.data_dir.join("rtd-events.jsonl")) {
            if let Ok(line) = serde_json::to_string(&ev) {
                let _ = writeln!(f, "{line}");
            }
        }
        let mut q = self.events.lock().unwrap();
        if q.len() >= MAX_EVENTS {
            q.pop_front();
        }
        q.push_back(ev);
    }

    pub fn events_after(&self, after: u64, limit: usize) -> Vec<RtEvent> {
        let q = self.events.lock().unwrap();
        let mut v: Vec<RtEvent> = q.iter().filter(|e| e.id > after).cloned().collect();
        let limit = limit.clamp(1, MAX_EVENTS);
        if v.len() > limit {
            v.drain(..v.len() - limit);
        }
        v
    }

    /// `true` se per questo percorso va registrato un nuovo evento di blocco
    /// (non ne è stato registrato uno negli ultimi 10 secondi).
    pub fn should_report_block(&self, path: &str) -> bool {
        let mut m = self.recent_blocks.lock().unwrap();
        m.retain(|_, t| t.elapsed() < std::time::Duration::from_secs(10));
        let key = path.to_lowercase();
        if m.contains_key(&key) {
            return false;
        }
        m.insert(key, std::time::Instant::now());
        true
    }

    /// `true` se la protezione è sospesa (riprende da sola alla scadenza).
    pub fn is_paused(&self) -> bool {
        let until = self.paused_until.load(Ordering::SeqCst);
        if until == 0 {
            return false;
        }
        if until != PAUSED_UNTIL_RESTART && now() >= until {
            self.paused_until.store(0, Ordering::SeqCst);
            println!("protezione ripresa automaticamente");
            return false;
        }
        true
    }

    pub fn pause(&self, seconds: Option<u64>) {
        let until = match seconds {
            Some(s) => now().saturating_add(s.clamp(60, 24 * 3600)),
            None => PAUSED_UNTIL_RESTART,
        };
        self.paused_until.store(until, Ordering::SeqCst);
        println!("protezione sospesa ({seconds:?} s)");
    }

    pub fn resume(&self) {
        self.paused_until.store(0, Ordering::SeqCst);
        println!("protezione ripresa");
    }

    pub fn is_excluded(&self, path: &std::path::Path) -> bool {
        self.exclusions.read().unwrap().is_excluded(path, false)
    }

    pub fn add_exclusion(&self, path: String) -> Result<(), String> {
        let mut ex = self.exclusions.write().unwrap();
        if !ex.paths.iter().any(|p| p.eq_ignore_ascii_case(&path)) {
            ex.paths.push(path);
        }
        let json = serde_json::to_string_pretty(&*ex).map_err(|e| e.to_string())?;
        std::fs::write(self.config.data_dir.join("rtd-exclusions.json"), json).map_err(|e| e.to_string())
    }

    pub fn status(&self) -> RtStatus {
        let _ = self.is_paused(); // aggiorna la scadenza
        let info = self.engine().info().clone();
        RtStatus {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            driver_connected: self.driver_connected.load(Ordering::SeqCst),
            started_at: self.started_at,
            auto_quarantine: self.config.auto_quarantine && self.quarantine.is_some(),
            yara_rules: info.yara_rules,
            hash_signatures: info.hash_signatures,
            stats: self.stats.lock().unwrap().clone(),
            last_event_id: self.next_id.load(Ordering::SeqCst) - 1,
            paused_until: self.paused_until.load(Ordering::SeqCst),
            exclusions: self.exclusions.read().unwrap().paths.len(),
            quarantine_dir: self.quarantine.as_ref().map(|q| q.dir().display().to_string()),
        }
    }
}

fn load_exclusions(dir: &std::path::Path) -> Exclusions {
    std::fs::read_to_string(dir.join("rtd-exclusions.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> (tempfile::TempDir, Shared) {
        let d = tempfile::tempdir().unwrap();
        let s = Shared::new(Config {
            signature_dirs: vec![],
            quarantine_dir: Some(d.path().join("q")),
            auto_quarantine: true,
            threads: 1,
            data_dir: d.path().join("data"),
            protect_install_dir: false,
        })
        .unwrap();
        (d, s)
    }

    #[test]
    fn events_are_ordered_limited_and_logged() {
        let (d, s) = shared();
        for i in 0..5 {
            s.push_event(RtEventKind::Blocked, format!("C:\\{i}.exe"), "T".into(), None, None);
        }
        let all = s.events_after(0, 100);
        assert_eq!(all.iter().map(|e| e.id).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5]);
        let tail = s.events_after(0, 2);
        assert_eq!(tail.iter().map(|e| e.id).collect::<Vec<_>>(), vec![4, 5]);
        assert_eq!(s.events_after(3, 100).len(), 2);
        assert_eq!(s.status().last_event_id, 5);
        let log = std::fs::read_to_string(d.path().join("data").join("rtd-events.jsonl")).unwrap();
        assert_eq!(log.lines().count(), 5);
    }

    #[test]
    fn pause_resume_and_exclusions() {
        let (_d, s) = shared();
        assert!(!s.is_paused());
        s.pause(Some(300));
        assert!(s.is_paused());
        assert!(s.status().paused_until > now());
        s.resume();
        assert!(!s.is_paused());
        s.pause(None);
        assert_eq!(s.status().paused_until, PAUSED_UNTIL_RESTART);
        // Scadenza passata: riprende da sola.
        s.paused_until.store(now() - 1, Ordering::SeqCst);
        assert!(!s.is_paused());

        assert!(s.should_report_block(r"C:\a.exe"));
        assert!(!s.should_report_block(r"c:\A.EXE"), "secondo tentativo ravvicinato: niente nuovo evento");
        assert!(s.should_report_block(r"C:\b.exe"));

        s.add_exclusion(r"C:\Strumenti".into()).unwrap();
        assert!(s.is_excluded(std::path::Path::new(r"C:\Strumenti\tool.exe")));
        assert_eq!(load_exclusions(&s.config.data_dir).paths.len(), 1, "salvata su disco");
    }
}
