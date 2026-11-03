//! Protocollo tra il servizio di protezione in tempo reale (vigil-rtd) e l'app.
//!
//! Trasporto: named pipe locale, una richiesta JSON per connessione (una riga),
//! una risposta JSON (una riga). La pipe è leggibile dagli utenti interattivi,
//! ma NON espone comandi per disattivare la protezione: quello richiede
//! l'amministratore (si ferma il servizio).

use serde::{Deserialize, Serialize};

pub const PIPE_NAME: &str = r"\\.\pipe\vigil-rtd";
pub const SERVICE_NAME: &str = "VigilRtd";
pub const DRIVER_SERVICE_NAME: &str = "VigilFlt";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    /// Eventi con id maggiore di `after` (al massimo `limit`, i più recenti).
    Events { after: u64, limit: usize },
    /// Ricarica le firme dal disco (dopo un aggiornamento).
    Reload,
    /// Sospende la protezione per `seconds` secondi, o fino al riavvio del servizio
    /// se `None`. Accettata SOLO da un client con privilegi di amministratore.
    Pause { seconds: Option<u64> },
    /// Riprende la protezione (accettata da chiunque: riattivare è sempre sicuro).
    Resume,
    /// Esclude un file o una cartella dalla protezione. SOLO amministratore.
    AddExclusion { path: String },
}

/// `RtStatus::paused_until` quando la sospensione dura fino al riavvio del servizio.
pub const PAUSED_UNTIL_RESTART: u64 = u64::MAX;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtStats {
    pub exec_checked: u64,
    pub exec_blocked: u64,
    pub exec_cached: u64,
    pub writes_checked: u64,
    pub threats_found: u64,
    pub quarantined: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtStatus {
    pub version: String,
    /// Il servizio è collegato al driver (altrimenti non protegge nulla).
    pub driver_connected: bool,
    pub started_at: u64,
    pub auto_quarantine: bool,
    pub yara_rules: usize,
    pub hash_signatures: usize,
    pub stats: RtStats,
    pub last_event_id: u64,
    /// 0 = protezione attiva; altrimenti istante (unix) di ripresa automatica,
    /// oppure `PAUSED_UNTIL_RESTART`.
    #[serde(default)]
    pub paused_until: u64,
    #[serde(default)]
    pub exclusions: usize,
    /// Deposito della quarantena del servizio (leggibile dagli utenti, modificabile
    /// solo dagli amministratori).
    #[serde(default)]
    pub quarantine_dir: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RtEventKind {
    /// Esecuzione di un programma o di una DLL bloccata.
    Blocked,
    /// File scritto riconosciuto come minaccia e messo in quarantena.
    Quarantined,
    /// File scritto riconosciuto come minaccia (quarantena automatica disattivata).
    Detected,
    /// Minaccia trovata ma impossibile da mettere in quarantena.
    QuarantineFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtEvent {
    pub id: u64,
    pub time: u64,
    pub kind: RtEventKind,
    pub path: String,
    pub threat: String,
    /// Processo che ha causato l'operazione (percorso dell'eseguibile), se noto.
    pub process: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Status(RtStatus),
    Events { events: Vec<RtEvent> },
    Ok,
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_is_stable() {
        assert_eq!(serde_json::to_string(&Request::Status).unwrap(), r#"{"cmd":"status"}"#);
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"cmd":"events","after":7,"limit":20}"#).unwrap(),
            Request::Events { after: 7, limit: 20 }
        );
        assert_eq!(
            serde_json::to_string(&Request::Pause { seconds: Some(300) }).unwrap(),
            r#"{"cmd":"pause","seconds":300}"#
        );
        let r = Response::Error { message: "x".into() };
        let back: Response = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        let s = Response::Status(RtStatus {
            version: "0.1.0".into(),
            driver_connected: true,
            started_at: 1,
            auto_quarantine: true,
            yara_rules: 2,
            hash_signatures: 3,
            stats: RtStats::default(),
            last_event_id: 0,
            paused_until: 0,
            exclusions: 0,
            quarantine_dir: None,
        });
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.starts_with(r#"{"type":"status","version":"0.1.0""#), "{json}");
        assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), s);
    }
}
