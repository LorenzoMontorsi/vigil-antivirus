//! Fonti di firme scaricabili: YARA-Forge e MalwareBazaar.
//!
//! Tutto finisce nella cartella `feeds`, che il motore carica insieme a
//! quella delle firme personali.

use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{settings::RulesPackage, util::write_atomic};

const UA: &str = concat!("Vigil/", env!("CARGO_PKG_VERSION"), " (+antivirus open source personale)");
const MAX_DOWNLOAD: u64 = 200 * 1024 * 1024;

pub const YARA_FORGE_FILE: &str = "yara-forge.yar";
pub const MALWAREBAZAAR_FILE: &str = "malwarebazaar.txt";
const STATE_FILE: &str = "state.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FeedState {
    pub last_update_unix: Option<u64>,
    pub yara_forge_release: Option<String>,
    pub malwarebazaar_hashes: usize,
    pub sources: Vec<SourceStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceStatus {
    pub name: String,
    pub ok: bool,
    pub message: String,
}

impl FeedState {
    pub fn load(dir: &Path) -> Self {
        fs::read_to_string(dir.join(STATE_FILE)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }
    pub fn save(&self, dir: &Path) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = write_atomic(&dir.join(STATE_FILE), json.as_bytes());
        }
    }
}

fn download(url: &str) -> Result<(Vec<u8>, String), String> {
    let resp = ureq::get(url)
        .set("User-Agent", UA)
        .timeout(Duration::from_secs(300))
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(401 | 403, _) => "accesso negato (chiave non valida?)".to_owned(),
            ureq::Error::Status(code, _) => format!("il server ha risposto {code}"),
            other => other.to_string(),
        })?;
    let final_url = resp.get_url().to_owned();
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_DOWNLOAD)
        .read_to_end(&mut buf)
        .map_err(|e| format!("download interrotto: {e}"))?;
    Ok((buf, final_url))
}

/// Primo file nell'archivio ZIP il cui nome soddisfa `pred`.
fn extract_from_zip(data: &[u8], pred: impl Fn(&str) -> bool) -> Result<Vec<u8>, String> {
    let mut ar = zip::ZipArchive::new(Cursor::new(data)).map_err(|e| format!("archivio non valido: {e}"))?;
    for i in 0..ar.len() {
        let mut f = ar.by_index(i).map_err(|e| e.to_string())?;
        if f.is_file() && pred(f.name()) {
            let mut out = Vec::new();
            f.read_to_end(&mut out).map_err(|e| e.to_string())?;
            return Ok(out);
        }
    }
    Err("file non trovato nell'archivio".into())
}

/// Scarica il pacchetto di regole YARA-Forge scelto.
pub fn update_yara_forge(dir: &Path, package: RulesPackage) -> Result<(String, Option<String>), String> {
    let target = dir.join(YARA_FORGE_FILE);
    let name = match package {
        RulesPackage::Core => "core",
        RulesPackage::Extended => "extended",
        RulesPackage::None => {
            let _ = fs::remove_file(&target);
            return Ok(("disattivato".into(), None));
        }
    };
    let url = format!("https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-{name}.zip");
    let (zip, final_url) = download(&url)?;
    let rules = extract_from_zip(&zip, |n| n.ends_with(".yar"))?;
    if !rules.windows(5).any(|w| w == b"rule ") {
        return Err("il pacchetto scaricato non contiene regole".into());
    }
    write_atomic(&target, &rules).map_err(|e| e.to_string())?;
    let _ = final_url;
    let tag = latest_yara_forge_tag();
    let msg = format!("pacchetto {name}{}", tag.as_ref().map(|t| format!(", release {t}")).unwrap_or_default());
    Ok((msg, tag))
}

/// Versione dell'ultima release, dall'API pubblica di GitHub (facoltativa).
fn latest_yara_forge_tag() -> Option<String> {
    let resp = ureq::get("https://api.github.com/repos/YARAHQ/yara-forge/releases/latest")
        .set("User-Agent", UA)
        .set("Accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(20))
        .call()
        .ok()?;
    let json: serde_json::Value = serde_json::from_str(&resp.into_string().ok()?).ok()?;
    json.get("tag_name")?.as_str().map(str::to_owned)
}

/// Scarica gli hash delle ultime 48 ore e li unisce a quelli già noti:
/// l'archivio locale cresce a ogni aggiornamento.
pub fn update_malwarebazaar(dir: &Path, key: &str) -> Result<(String, usize), String> {
    let key = key.trim();
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("chiave non valida".into());
    }
    let (data, _) = download(&format!("https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"))?;
    let data = if data.starts_with(b"PK\x03\x04") { extract_from_zip(&data, |n| n.ends_with(".csv"))? } else { data };
    let text = String::from_utf8_lossy(&data);

    let path = dir.join(MALWAREBAZAAR_FILE);
    let mut known: BTreeMap<String, String> = fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(h, n)| (h.to_owned(), n.to_owned())))
        .collect();
    let before = known.len();
    let fresh = parse_malwarebazaar_csv(&text);
    if fresh.is_empty() {
        return Err("risposta senza hash (formato cambiato o chiave errata?)".into());
    }
    known.extend(fresh);

    let mut out = String::with_capacity(known.len() * 100);
    for (h, n) in &known {
        out.push_str(h);
        out.push(' ');
        out.push_str(n);
        out.push('\n');
    }
    write_atomic(&path, out.as_bytes()).map_err(|e| e.to_string())?;
    Ok((format!("{} nuovi hash, {} in totale", known.len() - before, known.len()), known.len()))
}

/// Colonne: first_seen, sha256, md5, sha1, reporter, file_name, file_type, mime, signature, …
fn parse_malwarebazaar_csv(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let f = split_csv(l);
            let sha = f.get(1)?.to_ascii_lowercase();
            if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            let family = f.get(8).map(|s| s.trim()).filter(|s| !s.is_empty() && *s != "n/a");
            let name = match family {
                Some(fam) => format!(
                    "MalwareBazaar.{}",
                    fam.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect::<String>()
                ),
                None => "MalwareBazaar.Generic".to_owned(),
            };
            Some((sha, name))
        })
        .collect()
}

fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur).trim().to_owned()),
            _ => cur.push(c),
        }
    }
    out.push(cur.trim().to_owned());
    out
}

pub fn feeds_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("feeds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_malwarebazaar_rows() {
        let csv = "################\n# MalwareBazaar recent\n\
\"2026-11-02 10:00:00\", \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\", \"m\", \"s\", \"r\", \"x.exe\", \"exe\", \"application/x-dosexec\", \"AgentTesla\", \"n/a\"\n\
\"2026-11-02 10:00:01\", \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\", \"m\", \"s\", \"r\", \"a, b.doc\", \"doc\", \"x\", \"n/a\", \"n/a\"\n\
\"bad\", \"nothex\"\n";
        let rows = parse_malwarebazaar_csv(csv);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("a".repeat(64), "MalwareBazaar.AgentTesla".into()));
        assert_eq!(rows[1].1, "MalwareBazaar.Generic");
    }
}
