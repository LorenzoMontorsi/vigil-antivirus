//! Analisi degli script ricevuti dal provider AMSI.

use vigil_engine::{ScanOptions, Verdict, rtproto::RtEventKind};

use crate::state::Shared;

/// PowerShell e gli altri host passano spesso il testo in UTF-16LE: molte regole
/// YARA cercano testo ASCII, quindi analizziamo anche la versione convertita.
fn as_utf16_text(data: &[u8]) -> Option<String> {
    if data.len() < 4 || data.len() % 2 != 0 {
        return None;
    }
    // Euristica semplice: molti byte nulli nelle posizioni dispari = UTF-16LE di testo latino.
    let zeros = data.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
    if zeros * 2 < data.len() / 2 {
        return None;
    }
    let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Some(String::from_utf16_lossy(&units))
}

/// AMSI identifica l'host con stringhe come "PowerShell_C:\...\powershell.exe_10.0.19041"
/// o "OFFICE_VBA": ne ricaviamo un nome leggibile.
pub fn host_name(app: &str) -> String {
    let first = app.split('_').next().unwrap_or(app).trim();
    match first.to_ascii_lowercase().as_str() {
        "" => "sconosciuto".into(),
        "powershell" => "PowerShell".into(),
        "jscript" => "JScript".into(),
        "vbscript" => "VBScript".into(),
        "office" => "macro di Office".into(),
        _ => first.to_owned(),
    }
}

/// Restituisce il nome della minaccia se il contenuto va bloccato.
pub fn scan(shared: &Shared, app: &str, name: &str, data: &[u8], client_pid: u32) -> Option<String> {
    if shared.is_paused() {
        return None;
    }
    shared.stats.lock().unwrap().scripts_checked += 1;
    let engine = shared.engine();
    let mut scanner = engine.scanner();
    // Niente euristica sui file né archivi: qui è testo di script.
    let opts = ScanOptions { heuristics: false, scan_archives: false, trust_microsoft: false, ..Default::default() };
    let hint = if name.is_empty() { app } else { name };

    let threat_of = |v: Verdict| match v {
        Verdict::Infected { threat, .. } => Some(threat),
        _ => None,
    };
    let mut threat = threat_of(scanner.scan_bytes(data, hint, &opts).1);
    if threat.is_none() {
        if let Some(text) = as_utf16_text(data) {
            threat = threat_of(scanner.scan_bytes(text.as_bytes(), hint, &opts).1);
        }
    }
    let threat = threat?;

    shared.stats.lock().unwrap().scripts_blocked += 1;
    let host = host_name(app);
    // Il nome del contenuto (spesso il file dello script) se c'è, altrimenti il tipo di script.
    let what = if name.is_empty() { format!("Script {host}") } else { name.to_owned() };
    // Lo stesso script viene spesso riproposto più volte di fila: un solo evento.
    if shared.should_report_block(&format!("amsi|{what}|{threat}")) {
        println!("SCRIPT BLOCCATO  {what}  [{threat}]");
        shared.push_event(
            RtEventKind::ScriptBlocked,
            what,
            threat.clone(),
            crate::driver::process_image(client_pid),
            Some(format!("Bloccato prima dell'esecuzione ({host})")),
        );
    }
    Some(threat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readable_host_names() {
        assert_eq!(host_name(r"PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.19041.4522"), "PowerShell");
        assert_eq!(host_name("OFFICE_VBA"), "macro di Office");
        assert_eq!(host_name(""), "sconosciuto");
    }

    #[test]
    fn detects_utf16_text() {
        let wide: Vec<u8> = "Write-Output 'ciao'".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(as_utf16_text(&wide).as_deref(), Some("Write-Output 'ciao'"));
        assert_eq!(as_utf16_text(b"testo normale ascii"), None);
    }
}
