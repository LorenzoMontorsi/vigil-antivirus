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
    Engine, EngineBuilder, ScanCache,
    quarantine::Quarantine,
    rtproto::{RtEvent, RtEventKind, RtStats, RtStatus},
};

const MAX_EVENTS: usize = 500;

pub struct Config {
    pub signature_dirs: Vec<PathBuf>,
    pub quarantine_dir: Option<PathBuf>,
    pub auto_quarantine: bool,
    pub threads: usize,
    /// Cartella per log degli eventi e cache (ProgramData\Vigil).
    pub data_dir: PathBuf,
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

    pub fn status(&self) -> RtStatus {
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
        }
    }
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
}
