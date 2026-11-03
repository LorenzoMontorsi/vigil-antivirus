//! Avvisi a popup in basso a destra (finestre senza bordi, sempre in primo piano),
//! con azioni: quarantena, elimina, escludi, ignora…
//!
//! Ogni avviso è una piccola finestra che carica l'interfaccia con `?toast=<id>`:
//! il contenuto lo legge con `toast_get`, le azioni passano da `toast_action`.

use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, LogicalPosition, Manager, WebviewUrl, WebviewWindowBuilder};

use crate::AppState;

const WIDTH: f64 = 384.0;
const HEIGHT: f64 = 196.0;
const MARGIN: f64 = 12.0;
const MAX_VISIBLE: usize = 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tone {
    Danger,
    Warn,
    Ok,
    #[default]
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Quarantine,
    Delete,
    Exclude,
    Ignore,
    Open,
    Close,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ToastData {
    pub id: u64,
    pub tone: Tone,
    pub title: String,
    pub threat: Option<String>,
    pub path: Option<String>,
    pub process: Option<String>,
    pub message: Option<String>,
    pub actions: Vec<Action>,
    /// L'evento viene dalla protezione in tempo reale (le esclusioni vanno anche al servizio).
    pub realtime: bool,
    /// Motore che l'ha rilevato, per la quarantena.
    pub source: String,
    #[serde(skip)]
    pub auto_close_secs: Option<u64>,
}

#[derive(Default)]
pub struct Toasts {
    items: Mutex<HashMap<u64, ToastData>>,
    /// Ordine di apparizione: il più vecchio in basso.
    order: Mutex<Vec<u64>>,
    next: AtomicU64,
}

fn label(id: u64) -> String {
    format!("toast-{id}")
}

/// Mostra un avviso. Se ce ne sono già troppi, chiude il più vecchio senza azioni pendenti.
pub fn show(app: &AppHandle, mut data: ToastData) {
    let toasts = app.state::<Toasts>();
    // Un avviso identico (stesso titolo e stesso file) è già aperto: non serve ripeterlo.
    if data.path.is_some()
        && toasts.items.lock().unwrap().values().any(|t| t.title == data.title && t.path == data.path)
    {
        return;
    }
    let id = toasts.next.fetch_add(1, Ordering::SeqCst) + 1;
    data.id = id;
    let auto = data.auto_close_secs;
    toasts.items.lock().unwrap().insert(id, data);
    let overflow = {
        let mut order = toasts.order.lock().unwrap();
        order.push(id);
        if order.len() > MAX_VISIBLE { Some(order[0]) } else { None }
    };
    if let Some(old) = overflow {
        close(app, old);
    }

    let app2 = app.clone();
    // Le finestre si creano dal ciclo eventi principale.
    let _ = app.run_on_main_thread(move || {
        let built = WebviewWindowBuilder::new(&app2, label(id), WebviewUrl::App(format!("index.html?toast={id}").into()))
            .title("Vigil")
            .inner_size(WIDTH, HEIGHT)
            .decorations(false)
            .resizable(false)
            .maximizable(false)
            .minimizable(false)
            .always_on_top(true)
            .skip_taskbar(true)
            .focused(false)
            .visible(false)
            .build();
        if built.is_ok() {
            layout(&app2);
        }
    });

    if let Some(secs) = auto {
        let app = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(secs));
            close(&app, id);
        });
    }
}

/// Impila gli avvisi dal basso verso l'alto nell'angolo in basso a destra dell'area di lavoro.
fn layout(app: &AppHandle) {
    let Ok(Some(monitor)) = app.primary_monitor() else { return };
    let scale = monitor.scale_factor();
    let area = monitor.work_area();
    let right = (area.position.x as f64 + area.size.width as f64) / scale;
    let bottom = (area.position.y as f64 + area.size.height as f64) / scale;
    let order = app.state::<Toasts>().order.lock().unwrap().clone();
    for (i, id) in order.iter().enumerate() {
        if let Some(w) = app.get_webview_window(&label(*id)) {
            // Il primo (il più vecchio) in basso, i successivi sopra.
            let y = bottom - (HEIGHT + MARGIN) * (i as f64 + 1.0);
            let _ = w.set_position(LogicalPosition::new(right - WIDTH - MARGIN, y));
            let _ = w.show();
        }
    }
}

pub fn close(app: &AppHandle, id: u64) {
    let toasts = app.state::<Toasts>();
    toasts.items.lock().unwrap().remove(&id);
    toasts.order.lock().unwrap().retain(|x| *x != id);
    let app2 = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(w) = app2.get_webview_window(&label(id)) {
            let _ = w.close();
        }
        layout(&app2);
    });
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn remove_file_forced(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let mut p = std::fs::metadata(path)?.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            p.set_readonly(false);
            std::fs::set_permissions(path, p)?;
            std::fs::remove_file(path)
        }
        other => other,
    }
}

#[tauri::command]
pub fn toast_get(toasts: tauri::State<'_, Toasts>, id: u64) -> Option<ToastData> {
    toasts.items.lock().unwrap().get(&id).cloned()
}

/// Esegue un'azione dell'avviso. Restituisce un messaggio da mostrare; l'avviso si chiude da solo.
#[tauri::command]
pub async fn toast_action(app: AppHandle, id: u64, action: Action) -> Result<String, String> {
    let data = app.state::<Toasts>().items.lock().unwrap().get(&id).cloned().ok_or("avviso scaduto")?;
    let path = data.path.clone().unwrap_or_default();
    let handle = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || -> Result<String, String> {
        let state = handle.state::<AppState>();
        match action {
            Action::Quarantine => {
                let threat = data.threat.as_deref().unwrap_or("Minaccia");
                state.quarantine.add(Path::new(&path), threat, &data.source).map_err(|e| e.to_string())?;
                let _ = handle.emit("quarantine://changed", ());
                Ok("Messo in quarantena".into())
            }
            Action::Delete => {
                remove_file_forced(Path::new(&path)).map_err(|e| format!("Impossibile eliminare: {e}"))?;
                Ok("File eliminato".into())
            }
            Action::Exclude => {
                // Esclusione nelle scansioni dell'app…
                let mut s = state.settings();
                if !s.exclusions.paths.iter().any(|p| p.eq_ignore_ascii_case(&path)) {
                    s.exclusions.paths.push(path.clone());
                    s.save(&state.settings_path)?;
                    *state.settings.lock().unwrap() = s;
                }
                // …e nella protezione in tempo reale (richiede l'amministratore).
                if data.realtime {
                    crate::rt::exclude(&path)?;
                }
                Ok("Aggiunto alle esclusioni".into())
            }
            Action::Open => {
                show_main(&handle);
                let _ = handle.emit("tray://open-page", "quarantine");
                Ok(String::new())
            }
            Action::Ignore | Action::Close => Ok(String::new()),
        }
    })
    .await
    .map_err(|e| e.to_string())?;

    let _ = app.emit("toast://handled", serde_json::json!({ "path": data_path(&app, id), "action": action, "ok": result.is_ok() }));
    if result.is_ok() {
        let app = app.clone();
        // Lascia leggere l'esito per un attimo, poi chiude.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1200));
            close(&app, id);
        });
    }
    result
}

fn data_path(app: &AppHandle, id: u64) -> Option<String> {
    app.state::<Toasts>().items.lock().unwrap().get(&id).and_then(|d| d.path.clone())
}

#[tauri::command]
pub fn toast_close(app: AppHandle, id: u64) {
    close(&app, id);
}
