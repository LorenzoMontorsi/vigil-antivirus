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
use tauri_plugin_notification::NotificationExt;
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

fn notify(app: &AppHandle, ev: &RtEvent) {
    let file = ev.path.rsplit(['\\', '/']).next().unwrap_or(&ev.path);
    let (title, body) = match ev.kind {
        RtEventKind::Blocked => ("Minaccia bloccata", format!("{file} non è stato eseguito ({})", ev.threat)),
        RtEventKind::Quarantined => ("Minaccia messa in quarantena", format!("{file} ({})", ev.threat)),
        RtEventKind::Detected => ("Minaccia rilevata", format!("{file} ({})", ev.threat)),
        RtEventKind::QuarantineFailed => ("Minaccia non isolata", format!("{file}: {}", ev.detail.as_deref().unwrap_or("errore"))),
    };
    let _ = app.notification().builder().title(title).body(body).show();
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

    if let Some(s) = &status {
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

    let ui = RtUiStatus { installed, running, status };
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

/// Avvia o ferma il servizio con i privilegi di amministratore (chiede conferma UAC).
#[cfg(windows)]
pub fn set_enabled(enabled: bool) -> Result<(), String> {
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_HIDE};
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let args = format!("{} {SERVICE_NAME}", if enabled { "start" } else { "stop" });
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            wide("runas").as_ptr(),
            wide("sc.exe").as_ptr(),
            wide(&args).as_ptr(),
            std::ptr::null(),
            SW_HIDE,
        )
    } as isize;
    // Valori <= 32 sono errori; 5 = accesso negato (UAC annullato).
    match r {
        r if r > 32 => Ok(()),
        5 => Err("Operazione annullata: serve l'autorizzazione di amministratore.".into()),
        r => Err(format!("Impossibile cambiare lo stato del servizio (codice {r}).")),
    }
}

#[cfg(not(windows))]
pub fn set_enabled(_enabled: bool) -> Result<(), String> {
    Err("solo su Windows".into())
}
