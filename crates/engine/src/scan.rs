use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Instant,
};

use crossbeam_channel::bounded;
use serde::Serialize;
use walkdir::WalkDir;

use crate::{Engine, Exclusions, ScanResult, Verdict};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_file_size: u64,
    pub threads: usize,
    pub exclusions: Exclusions,
    /// Analizza il contenuto degli archivi ZIP.
    pub scan_archives: bool,
    /// Segnala i file sospetti secondo l'euristica statica.
    pub heuristics: bool,
    /// Secondo motore ClamAV (demone clamd), opzionale.
    pub clamd: Option<crate::clamd::ClamdClient>,
    /// Gli eseguibili con firma Microsoft valida saltano ClamAV, euristica e regole deboli.
    pub trust_microsoft: bool,
    /// Salta i file già trovati puliti e non modificati.
    pub cache: Option<std::sync::Arc<crate::ScanCache>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        let cpus = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        Self {
            max_file_size: 64 * 1024 * 1024,
            threads: cpus.clamp(1, 8),
            exclusions: Exclusions::default(),
            scan_archives: true,
            heuristics: true,
            clamd: None,
            trust_microsoft: true,
            cache: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanSummary {
    /// File analizzati (puliti + infetti).
    pub scanned: u64,
    pub infected: u64,
    pub suspicious: u64,
    pub skipped: u64,
    pub errors: u64,
    /// File saltati perché già puliti in cache.
    pub cached: u64,
    /// Eseguibili con firma Microsoft verificata.
    pub trusted: u64,
    pub cancelled: bool,
    pub elapsed_ms: u64,
}

impl Engine {
    /// Scansiona file e cartelle in parallelo.
    ///
    /// `on_result` viene chiamato sul thread chiamante per ogni file, insieme
    /// al riepilogo aggiornato. Impostare `cancel` a `true` interrompe la scansione.
    pub fn scan_paths<F>(
        &self,
        roots: &[PathBuf],
        opts: &ScanOptions,
        cancel: &AtomicBool,
        mut on_result: F,
    ) -> ScanSummary
    where
        F: FnMut(&ScanResult, &ScanSummary),
    {
        let start = Instant::now();
        let mut summary = ScanSummary::default();
        let (path_tx, path_rx) = bounded::<PathBuf>(4096);
        let (res_tx, res_rx) = bounded::<ScanResult>(4096);

        thread::scope(|s| {
            // Enumerazione dei file.
            let walk_tx = res_tx.clone();
            s.spawn(move || {
                for root in roots {
                    let walker = WalkDir::new(root)
                        .follow_links(false)
                        .into_iter()
                        .filter_entry(|e| !opts.exclusions.is_excluded(e.path(), e.file_type().is_dir()));
                    for entry in walker {
                        if cancel.load(Ordering::Relaxed) {
                            return;
                        }
                        match entry {
                            Ok(e) if e.file_type().is_file() => {
                                if path_tx.send(e.into_path()).is_err() {
                                    return;
                                }
                            }
                            Ok(_) => {}
                            Err(err) => {
                                let path = err.path().map(Path::to_path_buf).unwrap_or_default();
                                let r = ScanResult {
                                    path,
                                    size: 0,
                                    sha256: None,
                                    verdict: Verdict::Error { message: err.to_string() },
                                    cached: false,
                                    signer: None,
                                };
                                if walk_tx.send(r).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
            });

            // Worker di scansione: ognuno con il proprio scanner YARA.
            for _ in 0..opts.threads.max(1) {
                let rx = path_rx.clone();
                let tx = res_tx.clone();
                s.spawn(move || {
                    let mut scanner = self.scanner();
                    for path in rx {
                        if cancel.load(Ordering::Relaxed) {
                            break;
                        }
                        if tx.send(scanner.scan_file(&path, opts)).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(path_rx);
            drop(res_tx);

            for r in res_rx {
                if r.cached {
                    summary.cached += 1;
                }
                if r.signer.as_deref().is_some_and(crate::trust::is_microsoft) {
                    summary.trusted += 1;
                }
                match r.verdict {
                    Verdict::Clean => summary.scanned += 1,
                    Verdict::Infected { .. } => {
                        summary.scanned += 1;
                        summary.infected += 1;
                    }
                    Verdict::Suspicious { .. } => {
                        summary.scanned += 1;
                        summary.suspicious += 1;
                    }
                    Verdict::Skipped { .. } => summary.skipped += 1,
                    Verdict::Error { .. } => summary.errors += 1,
                }
                summary.elapsed_ms = start.elapsed().as_millis() as u64;
                on_result(&r, &summary);
            }
        });

        if let Some(cache) = &opts.cache {
            let _ = cache.save();
        }
        summary.cancelled = cancel.load(Ordering::Relaxed);
        summary.elapsed_ms = start.elapsed().as_millis() as u64;
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EngineBuilder;
    use std::fs;

    #[test]
    fn scans_tree_respecting_exclusions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("sub/skipme")).unwrap();
        fs::write(root.join("a.txt"), "pulito").unwrap();
        fs::write(root.join("sub/b.bin"), "contiene VIGIL_MARKER qui").unwrap();
        fs::write(root.join("sub/skipme/c.bin"), "VIGIL_MARKER").unwrap();
        fs::write(root.join("sub/d.iso"), "VIGIL_MARKER").unwrap();

        let mut b = EngineBuilder::new();
        b.add_yara_source("test", "rule Marker { strings: $a = \"VIGIL_MARKER\" condition: $a }").unwrap();
        let engine = b.build();

        let opts = ScanOptions {
            exclusions: Exclusions {
                paths: vec![root.join("sub/skipme").to_string_lossy().into_owned()],
                extensions: vec!["iso".into()],
            },
            ..Default::default()
        };
        let mut threats = Vec::new();
        let summary = engine.scan_paths(&[root.to_path_buf()], &opts, &AtomicBool::new(false), |r, _| {
            if r.is_infected() {
                threats.push(r.path.clone());
            }
        });

        assert_eq!(summary.scanned, 2);
        assert_eq!(summary.infected, 1);
        assert_eq!(threats, vec![root.join("sub").join("b.bin")]);
    }
}
