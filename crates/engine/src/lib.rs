//! Motore di scansione di Vigil.
//!
//! Livelli di rilevamento, in ordine:
//! 1. hash SHA-256 di file noti come malevoli;
//! 2. regole YARA (motore `yara-x`);
//! 3. contenuto degli archivi ZIP (ricorsivo, con limiti anti zip-bomb);
//! 4. ClamAV tramite `clamd`, se configurato (solo sul file di primo livello:
//!    ClamAV apre da sé archivi ed eseguibili compressi);
//! 5. euristica statica (nome del file, struttura PE).
//!
//! Le firme si caricano da cartelle: `*.yar` / `*.yara` per le regole,
//! `*.txt` / `*.sha256` per gli elenchi di hash
//! (una riga per file: `<sha256> [nome minaccia]`, `#` per i commenti).

pub mod cache;
pub mod clamd;
mod exclusions;
mod heuristics;
pub mod quarantine;
mod scan;
mod signatures;
pub mod trust;

use std::{
    collections::HashMap,
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Serialize;
use sha2::{Digest, Sha256};

pub use cache::ScanCache;
pub use exclusions::Exclusions;
pub use scan::{ScanOptions, ScanSummary};

/// Variabili esterne usate da molte regole pubbliche (signature-base, LOKI, THOR).
const YARA_GLOBALS: &[&str] = &["filename", "filepath", "extension", "filetype", "owner"];

const MAX_ARCHIVE_DEPTH: u32 = 3;
const MAX_ARCHIVE_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    Hash,
    Yara,
    Clamav,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Infected {
        threat: String,
        source: DetectionSource,
        /// Descrizione dalla regola YARA, se presente.
        description: Option<String>,
        /// Percorso dentro l'archivio, se la minaccia è in un file compresso.
        location: Option<String>,
    },
    Suspicious {
        score: i32,
        reasons: Vec<String>,
    },
    Skipped {
        reason: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: Option<String>,
    pub verdict: Verdict,
    /// Risultato preso dalla cache: il file non è stato riletto.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub cached: bool,
    /// Firmatario Authenticode valido, se verificato.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

impl ScanResult {
    pub fn is_infected(&self) -> bool {
        matches!(self.verdict, Verdict::Infected { .. })
    }
    /// Infetto o sospetto: da mostrare all'utente.
    pub fn is_detection(&self) -> bool {
        matches!(self.verdict, Verdict::Infected { .. } | Verdict::Suspicious { .. })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineInfo {
    pub version: &'static str,
    pub yara_rules: usize,
    pub hash_signatures: usize,
    /// Problemi non fatali durante il caricamento delle firme.
    pub warnings: Vec<String>,
}

pub struct Engine {
    rules: yara_x::Rules,
    hashes: HashMap<[u8; 32], String>,
    info: EngineInfo,
}

impl Engine {
    /// Motore con le sole regole integrate.
    pub fn builtin() -> Self {
        EngineBuilder::new().build()
    }

    pub fn info(&self) -> &EngineInfo {
        &self.info
    }

    /// Uno scanner per thread: riusarlo tra più file evita di ricrearlo.
    pub fn scanner(&self) -> FileScanner<'_> {
        let mut yara = yara_x::Scanner::new(&self.rules);
        yara.set_timeout(Duration::from_secs(30));
        FileScanner { engine: self, yara }
    }
}

pub struct EngineBuilder {
    compiler: yara_x::Compiler<'static>,
    hashes: HashMap<[u8; 32], String>,
    warnings: Vec<String>,
}

impl Default for EngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineBuilder {
    pub fn new() -> Self {
        let mut compiler = yara_x::Compiler::new();
        // Accetta le espressioni regolari "permissive" della YARA classica.
        compiler.relaxed_re_syntax(true);
        for g in YARA_GLOBALS {
            compiler.define_global(g, "").expect("variabile globale valida");
        }
        compiler.new_namespace("builtin");
        compiler
            .add_source(signatures::BUILTIN_RULES)
            .expect("le regole integrate devono compilare");
        Self { compiler, hashes: HashMap::new(), warnings: Vec::new() }
    }

    pub fn add_yara_source(&mut self, namespace: &str, source: &str) -> Result<(), String> {
        self.compiler.new_namespace(namespace);
        self.compiler.add_source(source).map(|_| ()).map_err(|e| e.to_string())
    }

    pub fn add_hash_list(&mut self, text: &str, origin: &str) {
        let mut bad = 0usize;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (hash, name) = match line.split_once(char::is_whitespace) {
                Some((h, n)) => (h, n.trim()),
                None => (line, ""),
            };
            match parse_sha256(hash) {
                Some(h) => {
                    let name = if name.is_empty() { "Malware.Hash.Generic" } else { name };
                    self.hashes.insert(h, name.to_owned());
                }
                None => bad += 1,
            }
        }
        if bad > 0 {
            self.warnings.push(format!("{origin}: {bad} righe con hash SHA-256 non valido ignorate"));
        }
    }

    /// Carica tutte le firme presenti in `dir` (non ricorsivo). Gli errori
    /// sui singoli file finiscono in `EngineInfo::warnings`.
    pub fn load_signature_dir(&mut self, dir: &Path) {
        let entries = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) => {
                self.warnings.push(format!("{}: {e}", dir.display()));
                return;
            }
        };
        let mut files: Vec<PathBuf> =
            entries.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.is_file()).collect();
        files.sort();

        for path in files {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase());
            let is_yara = match ext.as_deref() {
                Some("yar" | "yara") => true,
                Some("txt" | "sha256") => false,
                _ => continue,
            };
            let text = match fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    self.warnings.push(format!("{name}: {e}"));
                    continue;
                }
            };
            if is_yara {
                let ns = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                if let Err(e) = self.add_yara_source(&ns, &text) {
                    self.warnings.push(format!("{name}: {e}"));
                }
            } else {
                self.add_hash_list(&text, &name);
            }
        }
    }

    pub fn build(self) -> Engine {
        let rules = self.compiler.build();
        let info = EngineInfo {
            version: env!("CARGO_PKG_VERSION"),
            yara_rules: rules.iter().count(),
            hash_signatures: self.hashes.len(),
            warnings: self.warnings,
        };
        Engine { rules, hashes: self.hashes, info }
    }
}

/// Scanner legato a un `Engine`. Non è condivisibile tra thread: creane uno per thread.
pub struct FileScanner<'e> {
    engine: &'e Engine,
    yara: yara_x::Scanner<'e>,
}

impl FileScanner<'_> {
    pub fn scan_file(&mut self, path: &Path, opts: &ScanOptions) -> ScanResult {
        let mut result = ScanResult {
            path: path.to_path_buf(),
            size: 0,
            sha256: None,
            verdict: Verdict::Clean,
            cached: false,
            signer: None,
        };
        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                result.verdict = io_error_verdict(&e);
                return result;
            }
        };
        let size = meta.len();
        result.size = size;
        if let Some(cache) = &opts.cache {
            if cache.is_clean(path, &meta) {
                result.cached = true;
                return result;
            }
        }
        if size > opts.max_file_size {
            result.verdict = Verdict::Skipped {
                reason: format!("file più grande del limite ({} MB)", opts.max_file_size / (1024 * 1024)),
            };
            return result;
        }
        match fs::read(path) {
            Ok(data) => {
                // Gli eseguibili con firma Microsoft valida saltano i controlli
                // costosi o soggetti a falsi positivi (ClamAV, euristica, regole deboli).
                if opts.trust_microsoft && data.starts_with(b"MZ") {
                    result.signer = trust::signer(path);
                }
                let trusted = result.signer.as_deref().is_some_and(trust::is_microsoft);
                let (digest, verdict) = self.detect(&data, &path.to_string_lossy(), opts, 0, trusted);
                result.sha256 = Some(hex::encode(digest));
                result.verdict = verdict;
                if let Some(cache) = &opts.cache {
                    if result.verdict == Verdict::Clean {
                        cache.mark_clean(path, &meta);
                    } else {
                        cache.forget(path);
                    }
                }
            }
            Err(e) => result.verdict = io_error_verdict(&e),
        }
        result
    }

    /// Analizza dati in memoria. `path_hint` è usato per le variabili YARA
    /// (`filename`, `filepath`, `extension`) e per l'euristica sul nome.
    pub fn scan_bytes(&mut self, data: &[u8], path_hint: &str, opts: &ScanOptions) -> (String, Verdict) {
        let (digest, verdict) = self.detect(data, path_hint, opts, 0, false);
        (hex::encode(digest), verdict)
    }

    fn detect(
        &mut self,
        data: &[u8],
        path_hint: &str,
        opts: &ScanOptions,
        depth: u32,
        trusted: bool,
    ) -> ([u8; 32], Verdict) {
        let digest: [u8; 32] = Sha256::digest(data).into();

        // 1. Hash noti.
        if let Some(name) = self.engine.hashes.get(&digest) {
            return (
                digest,
                Verdict::Infected { threat: name.clone(), source: DetectionSource::Hash, description: None, location: None },
            );
        }

        // 2. YARA.
        let file_name = path_hint.rsplit(['\\', '/']).next().unwrap_or(path_hint);
        let extension = file_name.rsplit_once('.').map(|(_, e)| e.to_lowercase()).unwrap_or_default();
        let _ = self.yara.set_global("filename", file_name);
        let _ = self.yara.set_global("filepath", path_hint);
        let _ = self.yara.set_global("extension", format!(".{extension}").as_str());
        // Le regole generate automaticamente (es. Malpedia/yara-signator) da sole
        // producono solo un "sospetto": vedi `is_low_confidence`.
        let mut weak_reasons: Vec<String> = Vec::new();
        match self.yara.scan(data) {
            Ok(res) => {
                for rule in res.matching_rules() {
                    let description = rule.metadata().find_map(|(k, v)| match v {
                        yara_x::MetaValue::String(s) if k == "description" => Some(s.to_owned()),
                        _ => None,
                    });
                    if is_low_confidence(rule.identifier(), description.as_deref()) {
                        if !trusted && weak_reasons.len() < 3 {
                            weak_reasons.push(format!(
                                "Regola YARA generata automaticamente (bassa affidabilità): {}",
                                rule.identifier()
                            ));
                        }
                        continue;
                    }
                    return (
                        digest,
                        Verdict::Infected {
                            threat: rule.identifier().to_owned(),
                            source: DetectionSource::Yara,
                            description,
                            location: None,
                        },
                    );
                }
            }
            Err(yara_x::ScanError::Timeout) => {}
            Err(e) => return (digest, Verdict::Error { message: format!("YARA: {e}") }),
        }

        // 3. Archivi.
        if opts.scan_archives && depth < MAX_ARCHIVE_DEPTH && data.starts_with(b"PK\x03\x04") {
            if let Some(v) = self.scan_zip(data, opts, depth + 1) {
                return (digest, v);
            }
        }

        // 4. ClamAV.
        if depth == 0 && !trusted {
            if let Some(clamd) = &opts.clamd {
                match clamd.scan(data) {
                    Ok(clamd::ClamdVerdict::Found(name)) => {
                        return (
                            digest,
                            Verdict::Infected { threat: name, source: DetectionSource::Clamav, description: None, location: None },
                        );
                    }
                    Ok(clamd::ClamdVerdict::Clean) => {}
                    Err(message) => return (digest, Verdict::Error { message }),
                }
            }
        }

        // 5. Euristica (più gli eventuali indizi deboli raccolti da YARA).
        let mut finding = if opts.heuristics && !trusted { heuristics::analyze(data, file_name) } else { None };
        if !weak_reasons.is_empty() {
            let f = finding.get_or_insert(heuristics::Finding { score: 0, reasons: Vec::new() });
            f.score = f.score.max(heuristics::THRESHOLD);
            weak_reasons.append(&mut f.reasons);
            f.reasons = weak_reasons;
        }
        if let Some(f) = finding {
            return (digest, Verdict::Suspicious { score: f.score, reasons: f.reasons });
        }

        (digest, Verdict::Clean)
    }

    /// Restituisce la prima minaccia trovata nell'archivio.
    fn scan_zip(&mut self, data: &[u8], opts: &ScanOptions, depth: u32) -> Option<Verdict> {
        let mut archive = zip::ZipArchive::new(Cursor::new(data)).ok()?;
        let budget = opts.max_file_size.saturating_mul(4);
        let mut total: u64 = 0;
        for i in 0..archive.len().min(MAX_ARCHIVE_ENTRIES) {
            // Le voci cifrate o con compressione non supportata danno errore: si saltano.
            let Ok(mut entry) = archive.by_index(i) else { continue };
            if entry.is_dir() || entry.size() > opts.max_file_size {
                continue;
            }
            let name = entry.name().to_owned();
            let mut buf = Vec::with_capacity(entry.size().min(opts.max_file_size) as usize);
            // `take` protegge da intestazioni che mentono sulla dimensione.
            if (&mut entry).take(opts.max_file_size + 1).read_to_end(&mut buf).is_err() {
                continue;
            }
            drop(entry);
            total += buf.len() as u64;
            if buf.len() as u64 > opts.max_file_size || total > budget {
                break;
            }
            if let (_, Verdict::Infected { threat, source, description, location }) =
                self.detect(&buf, &name, opts, depth, false)
            {
                let location = Some(match location {
                    Some(inner) => format!("{name} › {inner}"),
                    None => name,
                });
                return Some(Verdict::Infected { threat, source, description, location });
            }
        }
        None
    }
}

/// Regole prodotte da generatori automatici: utili come indizio, troppo
/// soggette a falsi positivi per condannare un file da sole.
fn is_low_confidence(identifier: &str, description: Option<&str>) -> bool {
    identifier.ends_with("_Auto")
        || description.is_some_and(|d| d.to_ascii_lowercase().contains("autogenerated"))
}

fn io_error_verdict(e: &std::io::Error) -> Verdict {
    // 225 = ERROR_VIRUS_INFECTED: un altro antivirus (es. Defender) ha bloccato la lettura.
    let message = match e.raw_os_error() {
        Some(225) => "lettura bloccata da un altro antivirus (probabile minaccia)".to_owned(),
        Some(5) => "accesso negato".to_owned(),
        Some(32) => "file in uso da un altro processo".to_owned(),
        _ => e.to_string(),
    };
    Verdict::Error { message }
}

fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const EICAR: &str =
        concat!("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR", "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    fn opts() -> ScanOptions {
        ScanOptions::default()
    }

    fn threat_of(v: &Verdict) -> Option<&str> {
        match v {
            Verdict::Infected { threat, .. } => Some(threat),
            _ => None,
        }
    }

    #[test]
    fn detects_eicar_in_memory() {
        let engine = Engine::builtin();
        let (_, v) = engine.scanner().scan_bytes(EICAR.as_bytes(), "eicar.com", &opts());
        assert_eq!(threat_of(&v), Some("EICAR_Test_File"));
        assert!(matches!(v, Verdict::Infected { source: DetectionSource::Yara, description: Some(_), .. }));
    }

    #[test]
    fn clean_data_is_clean() {
        let engine = Engine::builtin();
        let (sha, v) = engine.scanner().scan_bytes(b"ciao mondo", "nota.txt", &opts());
        assert_eq!(v, Verdict::Clean);
        assert_eq!(sha.len(), 64);
    }

    #[test]
    fn hash_signature_matches() {
        let data = b"finto malware di prova";
        let sha = hex::encode(Sha256::digest(data));
        let mut b = EngineBuilder::new();
        b.add_hash_list(&format!("# commento\n{sha} Test.Hash.Sample\nnon-un-hash\n"), "test.txt");
        let engine = b.build();
        assert_eq!(engine.info().hash_signatures, 1);
        assert_eq!(engine.info().warnings.len(), 1);
        let (_, v) = engine.scanner().scan_bytes(data, "x.bin", &opts());
        assert_eq!(threat_of(&v), Some("Test.Hash.Sample"));
    }

    #[test]
    fn bad_yara_file_is_a_warning_not_a_crash() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("rotta.yar"), "rule {").unwrap();
        fs::write(dir.path().join("buona.yar"), "rule Marker { strings: $a = \"VIGIL_MARKER\" condition: $a }").unwrap();
        let mut b = EngineBuilder::new();
        b.load_signature_dir(dir.path());
        let engine = b.build();
        assert_eq!(engine.info().warnings.len(), 1);
        assert_eq!(engine.info().yara_rules, 2); // EICAR + Marker
        let (_, v) = engine.scanner().scan_bytes(b"xx VIGIL_MARKER xx", "a.bin", &opts());
        assert_eq!(threat_of(&v), Some("Marker"));
    }

    #[test]
    fn globals_are_available_to_rules() {
        let mut b = EngineBuilder::new();
        b.add_yara_source("t", r#"rule ByName { condition: filename == "evil.exe" and extension == ".exe" }"#).unwrap();
        let engine = b.build();
        let mut s = engine.scanner();
        assert_eq!(threat_of(&s.scan_bytes(b"x", r"C:\tmp\evil.exe", &opts()).1), Some("ByName"));
        assert_eq!(s.scan_bytes(b"x", r"C:\tmp\good.exe", &opts()).1, Verdict::Clean);
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn finds_threat_in_nested_zip() {
        let inner = make_zip(&[("leggimi.txt", b"ciao"), ("payload.com", EICAR.as_bytes())]);
        let outer = make_zip(&[("doc/info.txt", b"niente"), ("doc/allegato.zip", &inner)]);
        let engine = Engine::builtin();
        let (_, v) = engine.scanner().scan_bytes(&outer, "posta.zip", &opts());
        match v {
            Verdict::Infected { threat, location, .. } => {
                assert_eq!(threat, "EICAR_Test_File");
                assert_eq!(location.as_deref(), Some("doc/allegato.zip › payload.com"));
            }
            other => panic!("atteso infetto, ottenuto {other:?}"),
        }
        let no_archives = ScanOptions { scan_archives: false, ..opts() };
        assert_eq!(engine.scanner().scan_bytes(&outer, "posta.zip", &no_archives).1, Verdict::Clean);
    }

    #[test]
    fn autogenerated_rules_only_make_suspects() {
        let mut b = EngineBuilder::new();
        b.add_yara_source(
            "t",
            r#"
            rule Fam_Loader_Auto { meta: description = "autogenerated rule" strings: $a = "AUTOHIT" condition: $a }
            rule Handmade { strings: $a = "REALHIT" condition: $a }
            "#,
        )
        .unwrap();
        let engine = b.build();
        let mut s = engine.scanner();
        assert!(matches!(s.scan_bytes(b"xx AUTOHIT", "a.dll", &opts()).1, Verdict::Suspicious { .. }));
        assert_eq!(threat_of(&s.scan_bytes(b"AUTOHIT REALHIT", "a.dll", &opts()).1), Some("Handmade"));
        let no_heur = ScanOptions { heuristics: false, ..opts() };
        assert!(matches!(s.scan_bytes(b"AUTOHIT", "a.dll", &no_heur).1, Verdict::Suspicious { .. }));
    }

    #[test]
    fn suspicious_name_is_reported() {
        let engine = Engine::builtin();
        let (_, v) = engine.scanner().scan_bytes(b"MZ", r"C:\Users\x\Downloads\fattura.pdf.exe", &opts());
        assert!(matches!(v, Verdict::Suspicious { .. }));
        let no_heur = ScanOptions { heuristics: false, ..opts() };
        assert_eq!(engine.scanner().scan_bytes(b"MZ", "fattura.pdf.exe", &no_heur).1, Verdict::Clean);
    }
}
