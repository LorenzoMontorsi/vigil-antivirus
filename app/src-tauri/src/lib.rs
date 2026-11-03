mod clamav;
mod feeds;
mod rt;
mod toast;
mod tray;
mod settings;
mod shell;
mod util;

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use vigil_engine::{
    Engine, EngineBuilder, EngineInfo, ScanCache, ScanOptions, ScanSummary,
    quarantine::{Quarantine, QuarantineItem},
};

use clamav::{ClamAv, ClamStatus};
use feeds::{FeedState, SourceStatus};
use settings::{RulesPackage, Settings};

/// Ogni quanto il pianificatore controlla se è ora di aggiornare.
const UPDATE_CHECK_EVERY: Duration = Duration::from_secs(15 * 60);

/// `true` se l'ultimo aggiornamento è più vecchio dell'intervallo scelto.
fn update_due(feeds_dir: &Path, interval_hours: u64) -> bool {
    FeedState::load(feeds_dir)
        .last_update_unix
        .is_none_or(|t| util::now_unix().saturating_sub(t) >= interval_hours.clamp(1, 168) * 3600)
}

/// Cerca aggiornamenti in autonomia: firme e motore, ogni `update_interval_hours`.
fn spawn_update_scheduler(app: AppHandle) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(UPDATE_CHECK_EVERY);
            let state = app.state::<AppState>();
            let s = state.settings();
            if s.auto_update && update_due(&state.feeds_dir, s.update_interval_hours) {
                // Se è già in corso un aggiornamento (manuale) non succede nulla.
                let _ = run_update_bg(&app);
            }
        }
    });
}

struct AppState {
    engine: RwLock<Arc<Engine>>,
    engine_loading: AtomicBool,
    scan_cancel: Mutex<Option<Arc<AtomicBool>>>,
    updating: AtomicBool,
    settings: Mutex<Settings>,
    settings_path: PathBuf,
    signatures_dir: PathBuf,
    feeds_dir: PathBuf,
    cache_file: PathBuf,
    cache: Mutex<Option<Arc<ScanCache>>>,
    /// Cartella di ClamAV incluso nelle risorse dell'app.
    /// ClamAV in uso: quello incluso nelle risorse dell'app oppure quello scaricato.
    clamav_install: RwLock<PathBuf>,
    /// Dove scaricare ClamAV se quello incluso manca.
    clamav_download_dir: PathBuf,
    clamav: ClamAv,
    quarantine: Quarantine,
    /// Cartella dati di Vigil: sempre esclusa dalle scansioni.
    data_dir: PathBuf,
}

impl AppState {
    fn settings(&self) -> Settings {
        self.settings.lock().unwrap().clone()
    }

    fn clamav_dir(&self) -> PathBuf {
        self.clamav_install.read().unwrap().clone()
    }
}

#[derive(Serialize)]
struct StatusDto {
    #[serde(flatten)]
    engine: EngineInfo,
    engine_loading: bool,
    updating: bool,
    signatures_dir: String,
    feeds: FeedState,
    clamav_enabled: bool,
    clamav: ClamStatus,
    cache_entries: usize,
    quarantine_count: usize,
}

#[derive(Debug, Clone, Copy, serde::Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum ScanKind {
    Quick,
    Full,
    Custom,
}

#[derive(Clone, Serialize)]
struct StartedPayload {
    kind: ScanKind,
    roots: Vec<String>,
    notes: Vec<String>,
}

#[derive(Clone, Serialize)]
struct ProgressPayload<'a> {
    summary: &'a ScanSummary,
    current: String,
}

#[derive(Clone, Serialize)]
struct HandledPayload {
    path: String,
    ok: bool,
    error: Option<String>,
}

#[derive(Clone, Serialize)]
struct UpdateDone {
    ok: bool,
    sources: Vec<SourceStatus>,
}

const SIGNATURES_README: &str = "Cartella firme personali di Vigil\r\n\
=================================\r\n\
\r\n\
*.yar / *.yara   regole YARA\r\n\
*.txt / *.sha256 elenchi di hash, una riga per file:  <sha256> [nome minaccia]\r\n\
                 le righe che iniziano con # sono commenti\r\n\
\r\n\
Le firme scaricate automaticamente stanno nella cartella \"feeds\" accanto a questa.\r\n\
Dopo aver aggiunto o modificato file, premi \"Ricarica\" nell'app.\r\n";

fn notify_status(app: &AppHandle) {
    let _ = app.emit("status://changed", ());
}

fn build_engine(signatures: &Path, feeds: &Path) -> Engine {
    let mut b = EngineBuilder::new();
    b.load_signature_dir(feeds);
    b.load_signature_dir(signatures);
    b.build()
}

/// Ricompila le firme in background; il motore precedente resta in uso fino alla fine.
fn reload_engine_bg(app: &AppHandle) {
    let state = app.state::<AppState>();
    if state.engine_loading.swap(true, Ordering::SeqCst) {
        return;
    }
    notify_status(app);
    let app = app.clone();
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let engine = build_engine(&state.signatures_dir, &state.feeds_dir);
        *state.engine.write().unwrap() = Arc::new(engine);
        state.engine_loading.store(false, Ordering::SeqCst);
        notify_status(&app);
    });
}

fn start_clamav_bg(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let s = state.settings();
        if !s.clamav_enabled {
            return;
        }
        // Lo stato "in avvio" diventa visibile appena start() parte.
        let notifier = {
            let app = app.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                notify_status(&app);
            })
        };
        let res = state.clamav.start(&state.clamav_dir(), s.max_file_size_mb);
        let _ = notifier.join();
        if let Err(e) = res {
            let _ = app.emit("clamav://error", e);
        }
        notify_status(&app);
    });
}

fn run_update_bg(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    if state.updating.swap(true, Ordering::SeqCst) {
        return Err("Aggiornamento già in corso".into());
    }
    notify_status(app);
    let app = app.clone();
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let s = state.settings();
        let log = |msg: &str| {
            let _ = app.emit("update://log", msg.to_owned());
        };
        let mut fs_state = FeedState::load(&state.feeds_dir);
        let mut sources = Vec::new();

        log("YARA-Forge: download del pacchetto di regole…");
        match feeds::update_yara_forge(&state.feeds_dir, s.rules_package) {
            Ok((msg, tag)) => {
                log(&format!("YARA-Forge: {msg}"));
                if tag.is_some() || s.rules_package == RulesPackage::None {
                    fs_state.yara_forge_release = tag;
                }
                sources.push(SourceStatus { name: "YARA-Forge".into(), ok: true, message: msg });
            }
            Err(e) => {
                log(&format!("YARA-Forge: errore: {e}"));
                sources.push(SourceStatus { name: "YARA-Forge".into(), ok: false, message: e });
            }
        }

        if s.malwarebazaar_key.trim().is_empty() {
            sources.push(SourceStatus {
                name: "MalwareBazaar".into(),
                ok: true,
                message: "non configurato (serve una Auth-Key gratuita)".into(),
            });
        } else {
            log("MalwareBazaar: download degli hash delle ultime 48 ore…");
            match feeds::update_malwarebazaar(&state.feeds_dir, &s.malwarebazaar_key) {
                Ok((msg, total)) => {
                    log(&format!("MalwareBazaar: {msg}"));
                    fs_state.malwarebazaar_hashes = total;
                    sources.push(SourceStatus { name: "MalwareBazaar".into(), ok: true, message: msg });
                }
                Err(e) => {
                    log(&format!("MalwareBazaar: errore: {e}"));
                    sources.push(SourceStatus { name: "MalwareBazaar".into(), ok: false, message: e });
                }
            }
        }

        // ClamAV non incluso nel pacchetto: lo scarichiamo (versione fissata, SHA-256 verificato).
        let mut clamav_ready = clamav::is_valid_install(&state.clamav_dir());
        if s.clamav_enabled && !clamav_ready {
            log(&format!("ClamAV: non trovato, download di ClamAV {} dalle release ufficiali (~225 MB)…", clamav::CLAMAV_VERSION));
            match clamav::download(&state.clamav_download_dir, |m| log(&format!("ClamAV: {m}"))) {
                Ok(()) => {
                    *state.clamav_install.write().unwrap() = state.clamav_download_dir.clone();
                    clamav_ready = true;
                    log("ClamAV: installato");
                }
                Err(e) => {
                    log(&format!("ClamAV: errore: {e}"));
                    sources.push(SourceStatus { name: "ClamAV".into(), ok: false, message: e });
                }
            }
        }

        // Motore: nuova versione di ClamAV? Si installa solo con la firma GPG di Talos valida.
        if s.clamav_enabled && clamav_ready && s.auto_engine_update {
            let current = clamav::installed_version(&state.clamav_dir()).unwrap_or_default();
            match clamav::latest_release() {
                Ok(latest) if clamav::parse_version(&latest) > clamav::parse_version(&current) => {
                    log(&format!("ClamAV: nuova versione del motore {latest} (installata {current}), download e verifica della firma…"));
                    let res = clamav::download_version(
                        &state.clamav_download_dir,
                        &latest,
                        || {
                            // clamd tiene aperti i file: va fermato prima di sostituirli.
                            state.clamav.stop();
                            let _ = state.clamav.client().shutdown();
                            std::thread::sleep(Duration::from_secs(2));
                        },
                        |m| log(&format!("ClamAV: {m}")),
                    );
                    match res {
                        Ok(()) => {
                            *state.clamav_install.write().unwrap() = state.clamav_download_dir.clone();
                            log(&format!("ClamAV: motore aggiornato a {latest}"));
                        }
                        Err(e) => log(&format!("ClamAV: aggiornamento del motore non riuscito: {e}")),
                    }
                }
                Ok(_) => log(&format!("ClamAV: il motore è aggiornato (versione {current})")),
                Err(e) => log(&format!("ClamAV: impossibile controllare nuove versioni del motore: {e}")),
            }
        }

        if s.clamav_enabled && clamav_ready {
            log("ClamAV: aggiornamento con freshclam…");
            let mut last = String::new();
            match state.clamav.update(&state.clamav_dir(), s.max_file_size_mb, |line| {
                log(&format!("ClamAV: {line}"));
                last = line.to_owned();
            }) {
                Ok(()) => sources.push(SourceStatus { name: "ClamAV".into(), ok: true, message: last }),
                Err(e) => {
                    log(&format!("ClamAV: errore: {e}"));
                    sources.push(SourceStatus { name: "ClamAV".into(), ok: false, message: e });
                }
            }
        }

        fs_state.last_update_unix = Some(util::now_unix());
        fs_state.sources = sources.clone();
        fs_state.save(&state.feeds_dir);
        state.updating.store(false, Ordering::SeqCst);

        log("Ricompilazione delle firme di Vigil…");
        // Se il servizio di protezione è attivo, ricarica anche lui le firme.
        let _ = rt::query(&vigil_engine::rtproto::Request::Reload);
        reload_engine_bg(&app);
        if s.clamav_enabled && !state.clamav.client().ping() {
            start_clamav_bg(&app);
        }
        let ok = sources.iter().all(|x| x.ok);
        let _ = app.emit("update://done", UpdateDone { ok, sources });
        notify_status(&app);
    });
    Ok(())
}

fn toast_for_detection(app: &AppHandle, r: &vigil_engine::ScanResult) {
    use toast::{Action::*, Tone, ToastData};
    let (tone, title, threat, source, message) = match &r.verdict {
        vigil_engine::Verdict::Infected { threat, source, location, .. } => (
            Tone::Danger,
            "Minaccia rilevata",
            threat.clone(),
            serde_json::to_value(source).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default(),
            location.as_ref().map(|l| format!("dentro l'archivio: {l}")),
        ),
        vigil_engine::Verdict::Suspicious { reasons, .. } => (
            Tone::Warn,
            "File sospetto rilevato",
            "Sospetto (euristica)".to_owned(),
            "heuristics".to_owned(),
            reasons.first().cloned(),
        ),
        _ => return,
    };
    toast::show(
        app,
        ToastData {
            tone,
            title: title.into(),
            threat: Some(threat),
            path: Some(r.path.display().to_string()),
            message,
            actions: vec![Quarantine, Delete, Exclude, Ignore],
            source,
            ..Default::default()
        },
    );
}

fn quick_scan_roots() -> Vec<PathBuf> {
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    let mut roots = Vec::new();
    if let Some(home) = env("USERPROFILE") {
        roots.push(home.join("Desktop"));
        roots.push(home.join("Downloads"));
    }
    if let Some(tmp) = env("TEMP") {
        roots.push(tmp);
    }
    if let Some(appdata) = env("APPDATA") {
        roots.push(appdata.join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    if let Some(pd) = env("ProgramData") {
        roots.push(pd.join(r"Microsoft\Windows\Start Menu\Programs\StartUp"));
    }
    roots.retain(|p| p.exists());
    roots.dedup();
    roots
}

fn full_scan_roots() -> Vec<PathBuf> {
    (b'A'..=b'Z').map(|c| PathBuf::from(format!("{}:\\", c as char))).filter(|p| p.exists()).collect()
}

// ── Comandi ────────────────────────────────────────────────────────────────

#[tauri::command]
fn status(state: State<'_, AppState>, rt: State<'_, rt::Realtime>) -> StatusDto {
    let s = state.settings();
    StatusDto {
        engine: state.engine.read().unwrap().info().clone(),
        engine_loading: state.engine_loading.load(Ordering::SeqCst),
        updating: state.updating.load(Ordering::SeqCst),
        signatures_dir: state.signatures_dir.display().to_string(),
        feeds: FeedState::load(&state.feeds_dir),
        clamav_enabled: s.clamav_enabled,
        clamav: state.clamav.status(&state.clamav_dir()),
        cache_entries: state.cache.lock().unwrap().as_ref().map_or(0, |c| c.len()),
        // Quarantena dell'app + quella del servizio di protezione in tempo reale.
        quarantine_count: state.quarantine.list().map(|l| l.len()).unwrap_or(0) + rt::vault_items(&rt.ui()).len(),
    }
}

// ── Quarantena ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct QuarantineRequest {
    path: String,
    threat: String,
    source: String,
}

#[derive(Serialize)]
struct QuarantineOutcome {
    path: String,
    ok: bool,
    error: Option<String>,
}

#[tauri::command]
async fn quarantine_add(app: AppHandle, items: Vec<QuarantineRequest>) -> Vec<QuarantineOutcome> {
    // Cifrare file grandi richiede tempo: fuori dal thread dell'interfaccia.
    let handle = app.clone();
    let out = tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<AppState>();
        items
            .into_iter()
            .map(|it| match state.quarantine.add(Path::new(&it.path), &it.threat, &it.source) {
                Ok(_) => QuarantineOutcome { path: it.path, ok: true, error: None },
                Err(e) => QuarantineOutcome { path: it.path, ok: false, error: Some(e.to_string()) },
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    let _ = app.emit("quarantine://changed", ());
    out
}

#[tauri::command]
fn quarantine_list(state: State<'_, AppState>) -> Result<Vec<QuarantineItem>, String> {
    state.quarantine.list().map_err(|e| e.to_string())
}

/// Ripristina nel percorso originale; con `exclude` aggiunge il file alle esclusioni.
#[tauri::command]
fn quarantine_restore(app: AppHandle, state: State<'_, AppState>, id: String, exclude: bool) -> Result<String, String> {
    let path = state.quarantine.restore(&id, None).map_err(|e| e.to_string())?;
    let shown = path.display().to_string();
    if exclude {
        let mut s = state.settings();
        if !s.exclusions.paths.iter().any(|p| p.eq_ignore_ascii_case(&shown)) {
            s.exclusions.paths.push(shown.clone());
            s.save(&state.settings_path)?;
            *state.settings.lock().unwrap() = s;
        }
    }
    let _ = app.emit("quarantine://changed", ());
    Ok(shown)
}

#[tauri::command]
fn quarantine_delete(app: AppHandle, state: State<'_, AppState>, ids: Vec<String>) -> Result<(), String> {
    let mut errors = Vec::new();
    for id in &ids {
        if let Err(e) = state.quarantine.delete(id) {
            errors.push(e.to_string());
        }
    }
    let _ = app.emit("quarantine://changed", ());
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

#[tauri::command]
fn rt_status(rt: State<'_, rt::Realtime>) -> rt::RtUiStatus {
    rt.ui()
}

#[tauri::command]
fn rt_events(rt: State<'_, rt::Realtime>) -> Vec<vigil_engine::rtproto::RtEvent> {
    rt.events()
}

#[tauri::command]
fn rt_set_enabled(enabled: bool) -> Result<(), String> {
    rt::set_enabled(enabled)
}

#[tauri::command]
fn rt_pause(minutes: Option<u64>) -> Result<(), String> {
    rt::pause(minutes)
}

#[tauri::command]
fn rt_resume() -> Result<(), String> {
    rt::resume()
}

#[tauri::command]
fn rt_vault_list(rt: State<'_, rt::Realtime>) -> Vec<vigil_engine::quarantine::QuarantineItem> {
    rt::vault_items(&rt.ui())
}

#[tauri::command]
fn rt_vault_restore(id: String, exclude: bool) -> Result<(), String> {
    rt::vault_restore(&id, exclude)
}

#[tauri::command]
fn rt_vault_delete(ids: Vec<String>) -> Result<(), String> {
    rt::vault_delete(&ids)
}

/// Avvio automatico all'accesso (HKCU\...\Run), con l'app nascosta nell'area di notifica.
fn apply_autostart(app: &AppHandle, enabled: bool) {
    use tauri_plugin_autostart::ManagerExt;
    // In sviluppo non registriamo l'eseguibile di debug.
    if cfg!(debug_assertions) {
        return;
    }
    let al = app.autolaunch();
    let _ = if enabled { al.enable() } else { al.disable() };
}

#[tauri::command]
fn clear_cache(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if state.scan_cancel.lock().unwrap().is_some() {
        return Err("Impossibile svuotare la cache durante una scansione".into());
    }
    let cache = state.cache.lock().unwrap().take();
    match cache {
        Some(c) => c.clear(),
        None => fs::remove_file(&state.cache_file).or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) }),
    }
    .map_err(|e| e.to_string())?;
    notify_status(&app);
    Ok(())
}

/// Identifica firme e opzioni in uso: se cambia, la cache non vale più.
fn cache_generation(engine: &Engine, feeds: &FeedState, clamav_version: Option<&str>, s: &Settings) -> String {
    let i = engine.info();
    format!(
        "v{}|y{}|h{}|f{:?}|c{}|h{}a{}t{}m{}",
        i.version,
        i.yara_rules,
        i.hash_signatures,
        feeds.last_update_unix,
        clamav_version.unwrap_or("off"),
        s.heuristics as u8,
        s.scan_archives as u8,
        s.trust_microsoft as u8,
        s.max_file_size_mb,
    )
}

fn cache_for(state: &AppState, generation: String) -> Arc<ScanCache> {
    let mut slot = state.cache.lock().unwrap();
    match slot.as_ref() {
        Some(c) if c.generation() == generation => c.clone(),
        _ => {
            let c = Arc::new(ScanCache::load(state.cache_file.clone(), generation));
            *slot = Some(c.clone());
            c
        }
    }
}

#[tauri::command]
fn reload_signatures(app: AppHandle) {
    reload_engine_bg(&app);
}

#[tauri::command]
fn update_signatures(app: AppHandle) -> Result<(), String> {
    run_update_bg(&app)
}

#[tauri::command]
fn start_clamav(app: AppHandle) {
    start_clamav_bg(&app);
}

#[tauri::command]
fn open_signatures_dir(state: State<'_, AppState>) -> Result<(), String> {
    let mut cmd = std::process::Command::new("explorer");
    cmd.arg(&state.signatures_dir);
    cmd.spawn().map(|_| ()).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_settings(state: State<'_, AppState>) -> Settings {
    state.settings()
}

#[tauri::command]
fn save_settings(app: AppHandle, state: State<'_, AppState>, settings: Settings) -> Result<(), String> {
    settings.save(&state.settings_path)?;
    let old = std::mem::replace(&mut *state.settings.lock().unwrap(), settings.clone());
    if old.start_at_login != settings.start_at_login {
        apply_autostart(&app, settings.start_at_login);
    }
    if old.context_menu != settings.context_menu {
        shell::apply(settings.context_menu);
    }
    let clamav_changed = old.clamav_enabled != settings.clamav_enabled;
    if clamav_changed {
        if settings.clamav_enabled {
            start_clamav_bg(&app);
        } else {
            state.clamav.stop();
        }
    }
    notify_status(&app);
    Ok(())
}

#[tauri::command]
fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    kind: ScanKind,
    paths: Option<Vec<String>>,
    ignore_cache: Option<bool>,
) -> Result<(), String> {
    let mut slot = state.scan_cancel.lock().unwrap();
    if slot.is_some() {
        return Err("Una scansione è già in corso".into());
    }
    let roots = match kind {
        ScanKind::Quick => quick_scan_roots(),
        ScanKind::Full => full_scan_roots(),
        ScanKind::Custom => paths.unwrap_or_default().into_iter().map(PathBuf::from).collect(),
    };
    if roots.is_empty() {
        return Err("Nessun percorso da scansionare".into());
    }

    let settings = state.settings();
    let mut notes = Vec::new();
    if state.engine_loading.load(Ordering::SeqCst) {
        notes.push("Le firme di Vigil si stanno ancora caricando: questa scansione usa quelle precedenti.".to_owned());
    }
    let mut clamav_version = None;
    let clamd = if settings.clamav_enabled {
        let client = state.clamav.client();
        if client.ping() {
            clamav_version = client.version().ok();
            Some(client)
        } else {
            notes.push("ClamAV non è attivo: questa scansione usa solo il motore di Vigil.".to_owned());
            None
        }
    } else {
        None
    };

    let cancel = Arc::new(AtomicBool::new(false));
    *slot = Some(cancel.clone());
    drop(slot);

    let engine = state.engine.read().unwrap().clone();
    let cache = (settings.use_cache && !ignore_cache.unwrap_or(false)).then(|| {
        let feeds = FeedState::load(&state.feeds_dir);
        cache_for(&state, cache_generation(&engine, &feeds, clamav_version.as_deref(), &settings))
    });
    let mut exclusions = settings.exclusions.clone();
    exclusions.paths.push(state.data_dir.display().to_string());
    let opts = ScanOptions {
        max_file_size: settings.max_file_size_mb.max(1) * 1024 * 1024,
        exclusions,
        scan_archives: settings.scan_archives,
        heuristics: settings.heuristics,
        trust_microsoft: settings.trust_microsoft,
        cache,
        clamd,
        ..Default::default()
    };

    let _ = app.emit(
        "scan://started",
        StartedPayload { kind, roots: roots.iter().map(|p| p.display().to_string()).collect(), notes },
    );

    let auto_quarantine = settings.auto_quarantine;
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let mut last_progress: Option<Instant> = None;
        let mut quarantined_any = false;
        let mut toasts_shown = 0usize;
        let mut pending_detections = 0usize;
        let summary = engine.scan_paths(&roots, &opts, &cancel, |r, s| {
            if r.is_detection() {
                let _ = app.emit("scan://threat", r);
            }
            // Quarantena automatica: solo minacce certe, mai i sospetti dell'euristica.
            let mut handled = false;
            if auto_quarantine {
                if let vigil_engine::Verdict::Infected { threat, source, .. } = &r.verdict {
                    let source = serde_json::to_value(source).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
                    let res = state.quarantine.add(&r.path, threat, &source);
                    quarantined_any |= res.is_ok();
                    handled = res.is_ok();
                    let _ = app.emit(
                        "scan://handled",
                        HandledPayload {
                            path: r.path.display().to_string(),
                            ok: res.is_ok(),
                            error: res.err().map(|e| e.to_string()),
                        },
                    );
                }
            }
            // Avviso a popup per ciò che resta da decidere (al massimo 3 per scansione).
            if r.is_detection() && !handled {
                if toasts_shown < 3 {
                    toasts_shown += 1;
                    toast_for_detection(&app, r);
                } else {
                    pending_detections += 1;
                }
            }
            if last_progress.is_none_or(|t| t.elapsed() >= Duration::from_millis(100)) {
                last_progress = Some(Instant::now());
                let _ = app.emit("scan://progress", ProgressPayload { summary: s, current: r.path.display().to_string() });
            }
        });
        state.scan_cancel.lock().unwrap().take();
        if pending_detections > 0 {
            toast::show(
                &app,
                toast::ToastData {
                    tone: toast::Tone::Warn,
                    title: format!("Altri {pending_detections} rilevamenti da controllare"),
                    message: Some("Aprili dalla pagina Scansione per decidere cosa farne.".into()),
                    actions: vec![toast::Action::Open, toast::Action::Close],
                    ..Default::default()
                },
            );
        }
        if quarantined_any {
            let _ = app.emit("quarantine://changed", ());
        }
        let _ = app.emit("scan://finished", &summary);
    });
    Ok(())
}

#[tauri::command]
fn cancel_scan(state: State<'_, AppState>) {
    if let Some(flag) = state.scan_cancel.lock().unwrap().as_ref() {
        flag.store(true, Ordering::Relaxed);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(shell::ShellScan::default())
        // Una sola istanza: rilanciare Vigil riapre la finestra esistente.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // "Analizza con Vigil" con Vigil già aperto: i percorsi arrivano qui.
            let paths = shell::scan_args(&args);
            if paths.is_empty() { toast::show_main(app) } else { shell::queue(app, paths) }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--hidden"]),
        ))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let config_dir = app.path().app_config_dir()?;
            let data_dir = app.path().app_data_dir()?;
            let signatures_dir = data_dir.join("signatures");
            let feeds_dir = feeds::feeds_dir(&data_dir);
            for d in [&config_dir, &signatures_dir, &feeds_dir] {
                fs::create_dir_all(d)?;
            }
            let readme = signatures_dir.join("LEGGIMI.md");
            if !readme.exists() {
                let _ = fs::write(&readme, SIGNATURES_README);
            }

            let settings_path = config_dir.join("settings.json");
            let settings = Settings::load(&settings_path);
            // ClamAV: prima quello incluso nel pacchetto, poi quello eventualmente già scaricato.
            let bundled_clamav = app.path().resource_dir()?.join("clamav");
            let clamav_download_dir = data_dir.join("clamav-bin");
            let clamav_install =
                if clamav::is_valid_install(&bundled_clamav) { bundled_clamav } else { clamav_download_dir.clone() };
            let clamav_missing = settings.clamav_enabled && !clamav::is_valid_install(&clamav_install);

            let needs_update =
                clamav_missing || settings.auto_update && update_due(&feeds_dir, settings.update_interval_hours);

            app.manage(AppState {
                // Si parte con le sole regole integrate: l'interfaccia si apre subito.
                engine: RwLock::new(Arc::new(Engine::builtin())),
                engine_loading: AtomicBool::new(false),
                scan_cancel: Mutex::new(None),
                updating: AtomicBool::new(false),
                settings: Mutex::new(settings),
                settings_path,
                signatures_dir,
                feeds_dir,
                cache_file: data_dir.join("cache").join("scan-cache.bin"),
                cache: Mutex::new(None),
                clamav_install: RwLock::new(clamav_install),
                clamav_download_dir,
                clamav: ClamAv::new(data_dir.join("clamav")),
                quarantine: Quarantine::open(data_dir.join("quarantine"))?,
                data_dir: data_dir.clone(),
            });

            app.manage(rt::Realtime::default());
            app.manage(toast::Toasts::default());
            tray::init(app.handle())?;
            rt::spawn_poller(app.handle().clone());
            spawn_update_scheduler(app.handle().clone());

            apply_autostart(app.handle(), app.state::<AppState>().settings().start_at_login);
            shell::apply(app.state::<AppState>().settings().context_menu);
            // Avviato da "Analizza con Vigil" mentre non era aperto.
            let args: Vec<String> = std::env::args().collect();
            shell::queue(app.handle(), shell::scan_args(&args));

            // Chiudere la finestra la nasconde: Vigil resta attivo nell'area di notifica.
            // All'avvio automatico (--hidden) la finestra non compare affatto.
            if let Some(main) = app.get_webview_window("main") {
                if !std::env::args().any(|a| a == "--hidden") {
                    let _ = main.show();
                }
                let w = main.clone();
                main.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = w.hide();
                    }
                });
            }

            let handle = app.handle();
            if needs_update {
                // L'aggiornamento ricompila e avvia ClamAV da solo alla fine.
                let _ = run_update_bg(handle);
                reload_engine_bg(handle);
            } else {
                reload_engine_bg(handle);
                start_clamav_bg(handle);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            reload_signatures,
            update_signatures,
            start_clamav,
            open_signatures_dir,
            get_settings,
            save_settings,
            start_scan,
            cancel_scan,
            clear_cache,
            quarantine_add,
            quarantine_list,
            quarantine_restore,
            quarantine_delete,
            rt_status,
            rt_events,
            rt_set_enabled,
            rt_pause,
            rt_resume,
            rt_vault_list,
            rt_vault_restore,
            rt_vault_delete,
            toast::toast_get,
            toast::toast_action,
            toast::toast_close,
            shell::take_shell_scan,
        ])
        .build(tauri::generate_context!())
        .expect("errore durante l'avvio di Vigil")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                app.state::<AppState>().clamav.stop();
            }
        });
}
