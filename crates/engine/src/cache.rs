//! Cache delle scansioni: un file già trovato pulito, non modificato da allora
//! e controllato con le stesse firme, non viene rianalizzato.
//!
//! La "generazione" identifica l'insieme di firme e opzioni: se cambia
//! (aggiornamento firme, opzioni diverse) la cache riparte da zero.
//!
//! Limite noto: si basa su dimensione e data di modifica. Un attaccante che
//! modifica un file mantenendo identiche dimensione e data lo farebbe saltare;
//! la scansione completa con "ignora cache" resta il controllo definitivo.

use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::UNIX_EPOCH,
};

const MAGIC: &[u8; 8] = b"VIGILC01";

#[derive(Clone, Copy, PartialEq, Eq)]
struct Entry {
    size: u64,
    mtime: u64,
}

pub struct ScanCache {
    file: PathBuf,
    generation: String,
    map: Mutex<HashMap<String, Entry>>,
    dirty: AtomicBool,
}

impl std::fmt::Debug for ScanCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanCache").field("generation", &self.generation).field("entries", &self.len()).finish()
    }
}

fn key(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

pub fn mtime_of(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

impl ScanCache {
    /// Carica la cache; se manca, è rovinata o di un'altra generazione, parte vuota.
    pub fn load(file: PathBuf, generation: String) -> Self {
        let map = read_file(&file, &generation).unwrap_or_default();
        Self { file, generation, map: Mutex::new(map), dirty: AtomicBool::new(false) }
    }

    pub fn generation(&self) -> &str {
        &self.generation
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_clean(&self, path: &Path, meta: &fs::Metadata) -> bool {
        let e = Entry { size: meta.len(), mtime: mtime_of(meta) };
        e.mtime != 0 && self.map.lock().unwrap().get(&key(path)) == Some(&e)
    }

    pub fn mark_clean(&self, path: &Path, meta: &fs::Metadata) {
        let e = Entry { size: meta.len(), mtime: mtime_of(meta) };
        if e.mtime != 0 {
            self.map.lock().unwrap().insert(key(path), e);
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    pub fn forget(&self, path: &Path) {
        if self.map.lock().unwrap().remove(&key(path)).is_some() {
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    pub fn clear(&self) -> io::Result<()> {
        self.map.lock().unwrap().clear();
        self.dirty.store(false, Ordering::Relaxed);
        match fs::remove_file(&self.file) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    pub fn save(&self) -> io::Result<()> {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return Ok(());
        }
        let map = self.map.lock().unwrap();
        let mut out = Vec::with_capacity(map.len() * 80 + 64);
        out.extend_from_slice(MAGIC);
        write_str(&mut out, &self.generation);
        out.extend_from_slice(&(map.len() as u64).to_le_bytes());
        for (k, e) in map.iter() {
            write_str(&mut out, k);
            out.extend_from_slice(&e.size.to_le_bytes());
            out.extend_from_slice(&e.mtime.to_le_bytes());
        }
        drop(map);
        if let Some(dir) = self.file.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.file.with_extension("tmp");
        fs::File::create(&tmp)?.write_all(&out)?;
        fs::rename(&tmp, &self.file)
    }
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn read_file(file: &Path, generation: &str) -> Option<HashMap<String, Entry>> {
    let mut data = Vec::new();
    fs::File::open(file).ok()?.read_to_end(&mut data).ok()?;
    let mut r = Reader { data: &data, pos: 0 };
    if r.take(8)? != MAGIC || r.string()? != generation {
        return None;
    }
    let n = r.u64()? as usize;
    let mut map = HashMap::with_capacity(n.min(10_000_000));
    for _ in 0..n {
        let k = r.string()?;
        let size = r.u64()?;
        let mtime = r.u64()?;
        map.insert(k, Entry { size, mtime });
    }
    Some(map)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(s)
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn string(&mut self) -> Option<String> {
        let n = u32::from_le_bytes(self.take(4)?.try_into().ok()?) as usize;
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_generation() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, "ciao").unwrap();
        let meta = fs::metadata(&f).unwrap();
        let cache_file = dir.path().join("cache.bin");

        let c = ScanCache::load(cache_file.clone(), "g1".into());
        assert!(!c.is_clean(&f, &meta));
        c.mark_clean(&f, &meta);
        c.save().unwrap();

        let c = ScanCache::load(cache_file.clone(), "g1".into());
        assert!(c.is_clean(&f, &meta));
        // Firme diverse: si riparte da zero.
        assert!(ScanCache::load(cache_file.clone(), "g2".into()).is_empty());

        // File modificato: non più in cache.
        fs::write(&f, "ciao mondo").unwrap();
        assert!(!c.is_clean(&f, &fs::metadata(&f).unwrap()));
    }
}
