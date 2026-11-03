//! Collegamento dell'app al servizio di protezione in tempo reale (VigilRtd).
//!
//! L'app legge stato ed eventi dalla named pipe del servizio e mostra le
//! notifiche. Accendere o spegnere la protezione significa avviare o fermare
//! il servizio: richiede l'amministratore (prompt UAC), mai la pipe.

use std::{
    io::{BufRead, BufReader, Write},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use vigil_engine::rtproto::{PIPE_NAME, Request, Response, RtEvent, RtEventKind, RtStatus, SERVICE_NAME};

const MAX_UI_EVENTS: usize = 100;

#[derive(Debug, Clone, Default, Serialize)]
pub struct RtUiStatus {
    /// Il servizio VigilRtd è registrato in Windows.
    pub installed: bool,
    /// Il servizio è in esecuzione.
    pub running: bool,
    /// Stato riportato dal servizio (se raggiungibile).
    pub status: Option<RtStatus>,
    /// Il provider AMSI di Vigil è registrato in Windows.
    pub amsi_installed: bool,
}

/// CLSID del provider AMSI (vedi crates/amsi).
const AMSI_PROVIDER_KEY: &str = r"SOFTWARE\Microsoft\AMSI\Providers\{2B9E6E0B-5D1A-4C51-9E3B-7A1D2C4F8E61}";

#[cfg(windows)]
fn amsi_installed() -> bool {
    use windows_sys::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW};
    let wide: Vec<u16> = AMSI_PROVIDER_KEY.encode_utf16().chain(Some(0)).collect();
    let mut key: HKEY = std::ptr::null_mut();
    let ok = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide.as_ptr(), 0, KEY_READ, &mut key) } == 0;
    if ok {
        unsafe { RegCloseKey(key) };
    }
    ok
}

#[cfg(not(windows))]
fn amsi_installed() -> bool {
    false
}

#[derive(Default)]
pub struct Realtime {
    ui: Mutex<RtUiStatus>,
    events: Mutex<Vec<RtEvent>>,
    last_seen: AtomicU64,
    primed: AtomicBool,
}

impl Realtime {
    pub fn ui(&self) -> RtUiStatus {
        self.ui.lock().unwrap().clone()
    }
    pub fn events(&self) -> Vec<RtEvent> {
        self.events.lock().unwrap().clone()
    }
}

/// Una richiesta sulla pipe del servizio.
pub fn query(req: &Request) -> Result<Response, String> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_NAME)
        .map_err(|e| format!("servizio non raggiungibile: {e}"))?;
    let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    writeln!(f, "{line}").map_err(|e| e.to_string())?;
    let mut out = String::new();
    BufReader::new(f).read_line(&mut out).map_err(|e| e.to_string())?;
    serde_json::from_str(&out).map_err(|e| format!("risposta non valida: {e}"))
}

#[cfg(windows)]
fn service_state() -> (bool, bool) {
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
        return (false, false);
    };
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(s) => (true, s.query_status().is_ok_and(|st| st.current_state == ServiceState::Running)),
        Err(_) => (false, false),
    }
}

#[cfg(not(windows))]
fn service_state() -> (bool, bool) {
    (false, false)
}

/// Avviso a popup per un evento del servizio, con le azioni possibili.
fn notify(app: &AppHandle, ev: &RtEvent) {
    use crate::toast::{Action::*, Tone, ToastData};
    let (tone, title, actions) = match ev.kind {
        RtEventKind::Blocked => (Tone::Danger, "Minaccia bloccata", vec![Quarantine, Delete, Exclude, Ignore]),
        RtEventKind::Detected => (Tone::Danger, "Minaccia rilevata", vec![Quarantine, Delete, Exclude, Ignore]),
        RtEventKind::Quarantined => (Tone::Ok, "Minaccia messa in quarantena", vec![Open, Close]),
        RtEventKind::QuarantineFailed => (Tone::Warn, "Minaccia non isolata", vec![Delete, Exclude, Ignore]),
        // Uno script vive in memoria: se viene da un file su disco si può isolare quello.
        RtEventKind::ScriptBlocked if std::path::Path::new(&ev.path).is_file() => {
            (Tone::Danger, "Script dannoso bloccato", vec![Quarantine, Delete, Ignore])
        }
        RtEventKind::ScriptBlocked => (Tone::Danger, "Script dannoso bloccato", vec![Close]),
    };
    crate::toast::show(
        app,
        ToastData {
            tone,
            title: title.into(),
            threat: Some(ev.threat.clone()),
            path: Some(ev.path.clone()),
            process: ev.process.clone(),
            message: ev.detail.clone(),
            actions,
            realtime: true,
            source: "realtime".into(),
            ..Default::default()
        },
    );
}

fn notify_pause_change(app: &AppHandle, before: u64, after: u64) {
    use crate::toast::{Tone, ToastData};
    let (tone, title, message) = match (before, after) {
        (0, x) if x > 0 => (
            Tone::Warn,
            "Protezione sospesa",
            if x == vigil_engine::rtproto::PAUSED_UNTIL_RESTART {
                "Fino al riavvio del servizio. Puoi riprenderla dal menu dell'icona.".to_owned()
            } else {
                let min = x.saturating_sub(crate::util::now_unix()).div_ceil(60);
                format!("Riprenderà da sola tra {min} minuti. Puoi riprenderla prima dal menu dell'icona.")
            },
        ),
        (b, 0) if b > 0 => (Tone::Ok, "Protezione ripresa", "Vigil sta di nuovo controllando programmi e file.".to_owned()),
        _ => return,
    };
    crate::toast::show(app, ToastData { tone, title: title.into(), message: Some(message), auto_close_secs: Some(8), ..Default::default() });
}

fn poll_once(app: &AppHandle) {
    let rt = app.state::<Realtime>();
    let (installed, running) = service_state();
    let status = if running {
        match query(&Request::Status) {
            Ok(Response::Status(s)) => Some(s),
            _ => None,
        }
    } else {
        None
    };

    let paused_before = rt.ui.lock().unwrap().status.as_ref().map_or(0, |s| s.paused_until);
    if let Some(s) = &status {
        if rt.primed.load(Ordering::SeqCst) {
            notify_pause_change(app, paused_before, s.paused_until);
        }
        let mut last = rt.last_seen.load(Ordering::SeqCst);
        if s.last_event_id < last {
            // Il servizio è ripartito: gli id ricominciano da capo.
            last = 0;
            rt.events.lock().unwrap().clear();
        }
        if s.last_event_id > last {
            if let Ok(Response::Events { events }) = query(&Request::Events { after: last, limit: 50 }) {
                // Al primo giro carichiamo lo storico senza notificarlo.
                let primed = rt.primed.load(Ordering::SeqCst);
                for ev in &events {
                    if primed {
                        notify(app, ev);
                    }
                    let _ = app.emit("rt://event", ev);
                }
                let mut list = rt.events.lock().unwrap();
                list.extend(events);
                let excess = list.len().saturating_sub(MAX_UI_EVENTS);
                list.drain(..excess);
            }
            rt.last_seen.store(s.last_event_id, Ordering::SeqCst);
        }
    }
    rt.primed.store(true, Ordering::SeqCst);

    let ui = RtUiStatus { installed, running, status, amsi_installed: amsi_installed() };
    crate::tray::update(app, &ui);
    let changed = {
        let mut cur = rt.ui.lock().unwrap();
        let changed = serde_json::to_string(&*cur).ok() != serde_json::to_string(&ui).ok();
        *cur = ui.clone();
        changed
    };
    if changed {
        let _ = app.emit("rt://status", &ui);
    }
}

pub fn spawn_poller(app: AppHandle) {
    std::thread::spawn(move || {
        loop {
            poll_once(&app);
            std::thread::sleep(Duration::from_secs(2));
        }
    });
}

/// Esegue un programma con i privilegi di amministratore (prompt UAC), senza finestra.
#[cfg(windows)]
fn run_as_admin(file: &str, args: &str) -> Result<(), String> {
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_HIDE};
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let r = unsafe {
        ShellExecuteW(std::ptr::null_mut(), wide("runas").as_ptr(), wide(file).as_ptr(), wide(args).as_ptr(), std::ptr::null(), SW_HIDE)
    } as isize;
    // Valori <= 32 sono errori; 5 = accesso negato (UAC annullato).
    match r {
        r if r > 32 => Ok(()),
        5 => Err("Operazione annullata: serve l'autorizzazione di amministratore.".into()),
        r => Err(format!("Impossibile eseguire l'operazione (codice {r}).")),
    }
}

#[cfg(not(windows))]
fn run_as_admin(_file: &str, _args: &str) -> Result<(), String> {
    Err("solo su Windows".into())
}

/// Percorso di vigil-rtd.exe, letto dalla configurazione del servizio.
#[cfg(windows)]
fn service_exe() -> Result<String, String> {
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(|e| e.to_string())?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG)
        .map_err(|_| "La protezione in tempo reale non è installata.".to_string())?;
    let cfg = service.query_config().map_err(|e| e.to_string())?;
    Ok(cfg.executable_path.display().to_string())
}

#[cfg(not(windows))]
fn service_exe() -> Result<String, String> {
    Err("solo su Windows".into())
}

/// Avvia o ferma il servizio (UAC).
pub fn set_enabled(enabled: bool) -> Result<(), String> {
    run_as_admin("sc.exe", &format!("{} {SERVICE_NAME}", if enabled { "start" } else { "stop" }))
}

/// Sospende la protezione per `minutes` minuti, o fino al riavvio se `None` (UAC).
pub fn pause(minutes: Option<u64>) -> Result<(), String> {
    let arg = minutes.map(|m| m.to_string()).unwrap_or_else(|| "riavvio".into());
    run_as_admin(&service_exe()?, &format!("pause {arg}"))
}

/// Riprende la protezione: non servono privilegi.
pub fn resume() -> Result<(), String> {
    match query(&Request::Resume)? {
        Response::Error { message } => Err(message),
        _ => Ok(()),
    }
}

/// File isolati dal servizio (sola lettura: il deposito sta in ProgramData).
pub fn vault_items(ui: &RtUiStatus) -> Vec<vigil_engine::quarantine::QuarantineItem> {
    ui.status
        .as_ref()
        .and_then(|s| s.quarantine_dir.as_ref())
        .and_then(|d| vigil_engine::quarantine::list_dir(std::path::Path::new(d)).ok())
        .unwrap_or_default()
}

fn valid_vault_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Ripristina un file isolato dal servizio, eventualmente escludendolo (UAC).
pub fn vault_restore(id: &str, exclude: bool) -> Result<(), String> {
    if !valid_vault_id(id) {
        return Err("identificativo non valido".into());
    }
    run_as_admin(&service_exe()?, &format!("vault-restore {id}{}", if exclude { " --exclude" } else { "" }))
}

/// Elimina definitivamente file isolati dal servizio (UAC).
pub fn vault_delete(ids: &[String]) -> Result<(), String> {
    if ids.is_empty() || !ids.iter().all(|i| valid_vault_id(i)) {
        return Err("identificativi non validi".into());
    }
    run_as_admin(&service_exe()?, &format!("vault-delete {}", ids.join(" ")))
}

/// Esclude un percorso dalla protezione in tempo reale (UAC).
pub fn exclude(path: &str) -> Result<(), String> {
    if path.contains('"') {
        return Err("percorso non valido".into());
    }
    run_as_admin(&service_exe()?, &format!("exclude \"{path}\""))
}
