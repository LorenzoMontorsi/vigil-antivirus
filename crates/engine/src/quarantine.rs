//! Quarantena: i file pericolosi vengono cifrati e spostati in un deposito.
//!
//! Cifrare il contenuto (ChaCha20-Poly1305) serve a neutralizzarlo: il file
//! non è eseguibile né riconoscibile dagli altri antivirus, e il tag di
//! autenticazione garantisce che un ripristino restituisca esattamente
//! l'originale. La chiave è per-installazione e sta nel deposito stesso:
//! lo scopo non è la segretezza ma l'isolamento.
//!
//! Struttura del deposito:
//!   key.bin            chiave a 256 bit
//!   <id>.vq            nonce (12 byte) + contenuto cifrato
//!   <id>.json          metadati (percorso originale, minaccia, …)

use std::{
    fs,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Limite di dimensione per la quarantena (il file viene tenuto in memoria).
pub const MAX_QUARANTINE_SIZE: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: PathBuf,
    pub threat: String,
    /// Motore che l'ha rilevato ("yara", "clamav", "hash", "heuristics").
    pub source: String,
    pub sha256: String,
    pub size: u64,
    pub quarantined_at: u64,
}

#[derive(Debug)]
pub enum QuarantineError {
    TooLarge,
    InUse,
    AccessDenied,
    AlreadyExists(PathBuf),
    NotFound,
    Corrupted,
    Io(io::Error),
}

impl std::fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "file troppo grande per la quarantena (oltre 1 GB)"),
            Self::InUse => write!(f, "il file è in uso: chiudi il programma che lo usa e riprova"),
            Self::AccessDenied => {
                write!(f, "accesso negato: il file è protetto (prova ad avviare Vigil come amministratore)")
            }
            Self::AlreadyExists(p) => write!(f, "esiste già un file in {}", p.display()),
            Self::NotFound => write!(f, "elemento non trovato in quarantena"),
            Self::Corrupted => write!(f, "elemento in quarantena danneggiato: impossibile ripristinarlo"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for QuarantineError {}

impl From<io::Error> for QuarantineError {
    fn from(e: io::Error) -> Self {
        match e.raw_os_error() {
            Some(32 | 33) => Self::InUse,
            Some(5) => Self::AccessDenied,
            _ if e.kind() == ErrorKind::PermissionDenied => Self::AccessDenied,
            _ if e.kind() == ErrorKind::NotFound => Self::NotFound,
            _ => Self::Io(e),
        }
    }
}

pub struct Quarantine {
    dir: PathBuf,
    cipher: ChaCha20Poly1305,
}

impl Quarantine {
    /// Apre (o crea) il deposito nella cartella indicata.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let key_path = dir.join("key.bin");
        let key = match fs::read(&key_path) {
            Ok(k) if k.len() == 32 => k,
            Ok(_) => return Err(io::Error::new(ErrorKind::InvalidData, "chiave della quarantena non valida")),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let k = ChaCha20Poly1305::generate_key(&mut OsRng);
                fs::write(&key_path, k.as_slice())?;
                k.to_vec()
            }
            Err(e) => return Err(e),
        };
        let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("chiave di 32 byte");
        Ok(Self { dir, cipher })
    }

    fn blob(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.vq"))
    }

    fn meta(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Isola un file: lo cifra nel deposito e poi elimina l'originale.
    /// Se l'originale non si può eliminare, la quarantena viene annullata.
    pub fn add(&self, path: &Path, threat: &str, source: &str) -> Result<QuarantineItem, QuarantineError> {
        let meta = fs::metadata(path)?;
        if meta.len() > MAX_QUARANTINE_SIZE {
            return Err(QuarantineError::TooLarge);
        }
        let data = fs::read(path)?;

        let id = new_id();
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut blob = nonce.to_vec();
        blob.extend(self.cipher.encrypt(&nonce, data.as_slice()).map_err(|_| QuarantineError::Corrupted)?);

        let item = QuarantineItem {
            id: id.clone(),
            original_path: fs::canonicalize(path).map(strip_verbatim).unwrap_or_else(|_| path.to_path_buf()),
            threat: threat.to_owned(),
            source: source.to_owned(),
            sha256: hex::encode(Sha256::digest(&data)),
            size: data.len() as u64,
            quarantined_at: now(),
        };
        write_atomic(&self.blob(&id), &blob)?;
        write_atomic(&self.meta(&id), serde_json::to_string_pretty(&item).expect("serializzabile").as_bytes())?;

        if let Err(e) = remove_file_forced(path) {
            // Annulla: niente copie in quarantena di file rimasti al loro posto.
            let _ = fs::remove_file(self.blob(&id));
            let _ = fs::remove_file(self.meta(&id));
            return Err(e.into());
        }
        Ok(item)
    }

    pub fn list(&self) -> io::Result<Vec<QuarantineItem>> {
        list_dir(&self.dir)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn get(&self, id: &str) -> Result<QuarantineItem, QuarantineError> {
        if !valid_id(id) {
            return Err(QuarantineError::NotFound);
        }
        let s = fs::read_to_string(self.meta(id))?;
        serde_json::from_str(&s).map_err(|_| QuarantineError::Corrupted)
    }

    /// Ripristina un file. Se `target` è `None` torna nel percorso originale.
    /// Non sovrascrive mai un file esistente.
    pub fn restore(&self, id: &str, target: Option<&Path>) -> Result<PathBuf, QuarantineError> {
        let item = self.get(id)?;
        let dest = target.map(Path::to_path_buf).unwrap_or_else(|| item.original_path.clone());
        if dest.exists() {
            return Err(QuarantineError::AlreadyExists(dest));
        }
        let data = self.decrypt(id)?;
        if hex::encode(Sha256::digest(&data)) != item.sha256 {
            return Err(QuarantineError::Corrupted);
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        // create_new: fallisce se nel frattempo è comparso un file con quel nome.
        use std::io::Write;
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&dest)?;
        f.write_all(&data)?;
        f.sync_all()?;
        drop(f);
        self.delete(id)?;
        Ok(dest)
    }

    /// Elimina definitivamente un elemento.
    pub fn delete(&self, id: &str) -> Result<(), QuarantineError> {
        if !valid_id(id) {
            return Err(QuarantineError::NotFound);
        }
        let had_meta = fs::remove_file(self.meta(id)).is_ok();
        let had_blob = fs::remove_file(self.blob(id)).is_ok();
        if had_meta || had_blob { Ok(()) } else { Err(QuarantineError::NotFound) }
    }

    fn decrypt(&self, id: &str) -> Result<Vec<u8>, QuarantineError> {
        let blob = fs::read(self.blob(id))?;
        if blob.len() < 12 {
            return Err(QuarantineError::Corrupted);
        }
        let (nonce, ct) = blob.split_at(12);
        self.cipher.decrypt(Nonce::from_slice(nonce), ct).map_err(|_| QuarantineError::Corrupted)
    }
}

/// Elenca un deposito senza aprirlo né modificarlo (basta il permesso di lettura):
/// serve all'app per mostrare la quarantena del servizio, che non può scrivere.
pub fn list_dir(dir: &Path) -> io::Result<Vec<QuarantineItem>> {
    let mut items = Vec::new();
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension().is_some_and(|e| e == "json") {
            if let Some(item) = fs::read_to_string(&p).ok().and_then(|s| serde_json::from_str(&s).ok()) {
                items.push(item);
            }
        }
    }
    items.sort_by(|a: &QuarantineItem, b| b.quarantined_at.cmp(&a.quarantined_at).then(b.id.cmp(&a.id)));
    Ok(items)
}

fn new_id() -> String {
    let mut r = [0u8; 6];
    OsRng.fill_bytes(&mut r);
    format!("{}-{}", now(), hex::encode(r))
}

/// Gli id sono generati da noi: rifiutare tutto il resto evita percorsi tipo "..\x".
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)
}

/// Elimina anche i file in sola lettura.
fn remove_file_forced(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            let mut perms = fs::metadata(path)?.permissions();
            if perms.readonly() {
                #[allow(clippy::permissions_set_readonly_false)]
                perms.set_readonly(false);
                fs::set_permissions(path, perms)?;
                fs::remove_file(path)
            } else {
                Err(e)
            }
        }
        other => other,
    }
}

/// `canonicalize` su Windows restituisce `\\?\C:\…`: lo riportiamo a `C:\…`.
fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = b"contenuto malevolo di prova MZ\x00\x01\x02";

    fn setup() -> (tempfile::TempDir, Quarantine, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::open(dir.path().join("vault")).unwrap();
        let f = dir.path().join("sub").join("virus.exe");
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(&f, DATA).unwrap();
        (dir, q, f)
    }

    #[test]
    fn add_then_restore_roundtrip() {
        let (_d, q, f) = setup();
        let item = q.add(&f, "Test.Threat", "yara").unwrap();
        assert!(!f.exists(), "l'originale deve sparire");
        let blob = fs::read(q.blob(&item.id)).unwrap();
        assert!(!blob.windows(DATA.len()).any(|w| w == DATA), "il deposito non deve contenere il file in chiaro");
        assert_eq!(q.list().unwrap(), vec![item.clone()]);

        let restored = q.restore(&item.id, None).unwrap();
        assert_eq!(fs::read(&restored).unwrap(), DATA);
        assert!(q.list().unwrap().is_empty());
    }

    #[test]
    fn restore_never_overwrites() {
        let (_d, q, f) = setup();
        let item = q.add(&f, "T", "hash").unwrap();
        fs::write(&f, b"file nuovo").unwrap();
        assert!(matches!(q.restore(&item.id, None), Err(QuarantineError::AlreadyExists(_))));
        assert_eq!(fs::read(&f).unwrap(), b"file nuovo");
        assert_eq!(q.list().unwrap().len(), 1, "l'elemento resta in quarantena");
    }

    #[test]
    fn tampered_blob_is_rejected() {
        let (_d, q, f) = setup();
        let item = q.add(&f, "T", "yara").unwrap();
        let mut blob = fs::read(q.blob(&item.id)).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        fs::write(q.blob(&item.id), blob).unwrap();
        assert!(matches!(q.restore(&item.id, None), Err(QuarantineError::Corrupted)));
        assert!(!f.exists());
    }

    #[test]
    fn delete_and_bad_ids() {
        let (_d, q, f) = setup();
        let item = q.add(&f, "T", "yara").unwrap();
        assert!(matches!(q.delete(r"..\..\key"), Err(QuarantineError::NotFound)));
        q.delete(&item.id).unwrap();
        assert!(q.list().unwrap().is_empty());
        assert!(matches!(q.delete(&item.id), Err(QuarantineError::NotFound)));
    }

    #[test]
    fn readonly_file_is_quarantined() {
        let (_d, q, f) = setup();
        let mut p = fs::metadata(&f).unwrap().permissions();
        p.set_readonly(true);
        fs::set_permissions(&f, p).unwrap();
        q.add(&f, "T", "yara").unwrap();
        assert!(!f.exists());
    }

    #[cfg(windows)]
    #[test]
    fn locked_file_is_rolled_back() {
        use std::os::windows::fs::OpenOptionsExt;
        let (_d, q, f) = setup();
        // Aperto senza FILE_SHARE_DELETE: non si può eliminare finché resta aperto.
        let _lock = fs::OpenOptions::new().read(true).share_mode(1 /* FILE_SHARE_READ */).open(&f).unwrap();
        let err = q.add(&f, "T", "yara").unwrap_err();
        assert!(matches!(err, QuarantineError::InUse | QuarantineError::AccessDenied), "{err:?}");
        assert!(f.exists());
        assert!(q.list().unwrap().is_empty(), "nessun residuo nel deposito");
    }
}
