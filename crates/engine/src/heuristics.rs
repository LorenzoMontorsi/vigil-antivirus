//! Euristica statica: indicatori sospetti nel nome del file e negli eseguibili PE.
//!
//! Ogni indicatore ha un peso; sopra `THRESHOLD` il file è "sospetto".
//! I pesi sono volutamente prudenti: un sospetto non è una condanna e non
//! viene mai messo in quarantena automaticamente.

use goblin::pe::PE;

pub const THRESHOLD: i32 = 60;

const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

const EXEC_EXTS: &[&str] = &["exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "hta", "lnk", "msi", "ps1"];
const DECOY_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "avi",
    "zip", "rar",
];
const PACKER_SECTIONS: &[&str] = &[
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".petite", ".MPRESS1", ".MPRESS2", ".nsp0", ".nsp1", "pebundle", ".packed",
    ".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2",
];

#[derive(Debug)]
pub struct Finding {
    pub score: i32,
    pub reasons: Vec<String>,
}

struct Acc {
    score: i32,
    reasons: Vec<String>,
}

impl Acc {
    fn add(&mut self, weight: i32, reason: &str) {
        self.score += weight;
        if weight > 0 {
            self.reasons.push(reason.to_owned());
        }
    }
}

/// `file_name`: solo il nome del file (senza cartella).
pub fn analyze(data: &[u8], file_name: &str) -> Option<Finding> {
    let mut acc = Acc { score: 0, reasons: Vec::new() };
    analyze_name(file_name, &mut acc);
    if data.starts_with(b"MZ") {
        if let Ok(pe) = PE::parse(data) {
            analyze_pe(&pe, data, &mut acc);
        }
    }
    (acc.score >= THRESHOLD).then(|| Finding { score: acc.score, reasons: acc.reasons })
}

fn analyze_name(name: &str, acc: &mut Acc) {
    if name.contains('\u{202E}') {
        acc.add(80, "Il nome contiene un carattere di inversione del testo (RLO) che maschera l'estensione");
    }
    let lower = name.to_lowercase();
    let parts: Vec<&str> = lower.rsplitn(3, '.').collect();
    if parts.len() == 3 && EXEC_EXTS.contains(&parts[0]) && DECOY_EXTS.contains(&parts[1]) {
        acc.add(70, &format!("Doppia estensione ingannevole (.{}.{})", parts[1], parts[0]));
    }
}

fn analyze_pe(pe: &PE, data: &[u8], acc: &mut Acc) {
    let section_name = |s: &goblin::pe::section_table::SectionTable| s.name().unwrap_or("").to_owned();

    // Packer noti.
    if let Some(s) = pe.sections.iter().find(|s| PACKER_SECTIONS.contains(&section_name(s).as_str())) {
        acc.add(25, &format!("Sezione tipica di un packer ({})", section_name(s)));
    }

    // Sezioni scrivibili ed eseguibili insieme (codice che si modifica da solo).
    if pe
        .sections
        .iter()
        .any(|s| s.characteristics & SCN_MEM_EXECUTE != 0 && s.characteristics & SCN_MEM_WRITE != 0)
    {
        acc.add(25, "Sezione contemporaneamente scrivibile ed eseguibile");
    }

    // Entry point in una sezione scrivibile.
    let ep = pe.entry as u32;
    if let Some(s) = pe
        .sections
        .iter()
        .find(|s| ep >= s.virtual_address && ep < s.virtual_address.saturating_add(s.virtual_size.max(s.size_of_raw_data)))
    {
        if s.characteristics & SCN_MEM_WRITE != 0 {
            acc.add(20, "Il punto di ingresso si trova in una sezione scrivibile");
        }
    }

    // Codice ad alta entropia: compresso o cifrato.
    for s in &pe.sections {
        if s.characteristics & SCN_MEM_EXECUTE == 0 || s.size_of_raw_data < 1024 {
            continue;
        }
        let start = s.pointer_to_raw_data as usize;
        let end = start.saturating_add(s.size_of_raw_data as usize).min(data.len());
        if start < end && entropy(&data[start..end]) > 7.2 {
            acc.add(20, "Codice eseguibile con entropia molto alta (compresso o cifrato)");
            break;
        }
    }

    // Import.
    let is_dotnet = pe.imports.iter().any(|i| i.dll.eq_ignore_ascii_case("mscoree.dll"));
    let has = |names: &[&str]| pe.imports.iter().any(|i| names.iter().any(|n| i.name.eq_ignore_ascii_case(n)));
    if !is_dotnet {
        if pe.imports.len() <= 6 && has(&["GetProcAddress"]) && has(&["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"]) {
            acc.add(20, "Pochissimi import, risolti a runtime con LoadLibrary/GetProcAddress");
        }
        if has(&["VirtualAllocEx"]) && has(&["WriteProcessMemory"]) && has(&["CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext"]) {
            acc.add(30, "API per l'iniezione di codice in altri processi");
        }
        if has(&["SetWindowsHookExA", "SetWindowsHookExW"]) && has(&["GetAsyncKeyState", "GetKeyState", "GetKeyboardState"]) {
            acc.add(20, "API per intercettare la tastiera (keylogger)");
        }
    }

    // Firma digitale (presenza, non validità: quella richiede WinVerifyTrust).
    if pe.certificates.is_empty() {
        acc.add(10, "Eseguibile non firmato digitalmente");
    } else {
        acc.add(-40, "");
    }
}

fn entropy(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_extension() {
        let f = analyze(b"MZ", "Fattura_2026.pdf.exe").expect("sospetto");
        assert!(f.reasons[0].contains(".pdf.exe"));
        assert!(analyze(b"", "setup.1.2.exe").is_none());
        assert!(analyze(b"", "archivio.tar.gz").is_none());
    }

    #[test]
    fn rlo_trick() {
        assert!(analyze(b"", "invoice\u{202E}fdp.exe").is_some());
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[0u8; 100]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }
}
