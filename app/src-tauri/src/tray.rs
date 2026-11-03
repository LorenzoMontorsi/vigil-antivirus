//! Icona nella barra di sistema con menu contestuale: stato della protezione,
//! apertura, scansione rapida, aggiornamento, sospensione per un tempo, uscita.

use std::sync::Mutex;

use tauri::{
    AppHandle, Emitter, Manager,
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem, Submenu},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use vigil_engine::rtproto::PAUSED_UNTIL_RESTART;

use crate::{rt::RtUiStatus, toast};

const TRAY_ID: &str = "vigil";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayState {
    /// Protezione in tempo reale non installata: solo scansioni su richiesta.
    OnDemand,
    Active,
    Paused,
    Stopped,
}

/// Ultimo stato disegnato, per non ricostruire il menu a ogni controllo.
#[derive(Default)]
pub struct TrayCache(Mutex<Option<(TrayState, String)>>);

fn state_of(ui: &RtUiStatus) -> TrayState {
    match (&ui.status, ui.installed, ui.running) {
        (_, false, _) => TrayState::OnDemand,
        (_, true, false) => TrayState::Stopped,
        (Some(s), true, true) if s.paused_until > 0 => TrayState::Paused,
        (Some(s), true, true) if s.driver_connected => TrayState::Active,
        _ => TrayState::Stopped,
    }
}

fn status_text(ui: &RtUiStatus) -> String {
    match state_of(ui) {
        TrayState::OnDemand => "Scansione su richiesta (tempo reale non installato)".into(),
        TrayState::Active => "Protezione attiva".into(),
        TrayState::Stopped => "Protezione disattivata".into(),
        TrayState::Paused => {
            let until = ui.status.as_ref().map_or(0, |s| s.paused_until);
            if until == PAUSED_UNTIL_RESTART {
                "Protezione sospesa fino al riavvio".into()
            } else {
                let min = until.saturating_sub(crate::util::now_unix()).div_ceil(60);
                format!("Protezione sospesa (ancora {min} min)")
            }
        }
    }
}

/// Icona 32×32 disegnata al volo: scudo pieno del colore dello stato.
fn icon(state: TrayState) -> Image<'static> {
    let (r, g, b) = match state {
        TrayState::Active => (0x34, 0xe0, 0xa1),
        TrayState::Paused => (0xfb, 0xbf, 0x24),
        TrayState::Stopped => (0xfb, 0x4b, 0x6e),
        TrayState::OnDemand => (0x8b, 0x5c, 0xf6),
    };
    const N: usize = 32;
    let mut px = vec![0u8; N * N * 4];
    for y in 0..N {
        for x in 0..N {
            let fx = x as f32 + 0.5 - 16.0;
            let fy = y as f32 + 0.5;
            // Scudo: lati dritti in alto, punta arrotondata in basso.
            let half_width = if fy < 4.0 {
                0.0
            } else if fy < 18.0 {
                13.0
            } else {
                13.0 * (1.0 - ((fy - 18.0) / 12.0).powf(1.6)).max(0.0)
            };
            let inside = fy >= 3.0 && fy <= 30.0 && fx.abs() <= half_width;
            if inside {
                let edge = fx.abs() > half_width - 1.6 || fy < 4.6;
                let i = (y * N + x) * 4;
                let k = if edge { 0.72 } else { 1.0 };
                px[i] = (r as f32 * k) as u8;
                px[i + 1] = (g as f32 * k) as u8;
                px[i + 2] = (b as f32 * k) as u8;
                px[i + 3] = 255;
            }
        }
    }
    // Segno di spunta (attiva) o barre di pausa, in scuro.
    let mut dot = |x: usize, y: usize| {
        if x < N && y < N {
            let i = (y * N + x) * 4;
            if px[i + 3] > 0 {
                px[i] = 0x10;
                px[i + 1] = 0x12;
                px[i + 2] = 0x22;
            }
        }
    };
    match state {
        TrayState::Active | TrayState::OnDemand => {
            for t in 0..5 {
                for w in 0..3 {
                    dot(9 + t, 15 + t + w);
                }
            }
            for t in 0..9 {
                for w in 0..3 {
                    dot(13 + t, 19 - t + w);
                }
            }
        }
        TrayState::Paused => {
            for y in 10..22 {
                for w in 0..3 {
                    dot(11 + w, y);
                    dot(18 + w, y);
                }
            }
        }
        TrayState::Stopped => {
            for t in 0..10 {
                for w in 0..3 {
                    dot(11 + t, 10 + t + w);
                    dot(20 - t, 10 + t + w);
                }
            }
        }
    }
    Image::new_owned(px, N as u32, N as u32)
}

fn build_menu(app: &AppHandle, ui: &RtUiStatus) -> tauri::Result<Menu<tauri::Wry>> {
    let state = state_of(ui);
    let header = MenuItem::with_id(app, "status", format!("Vigil — {}", status_text(ui)), false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Apri Vigil", true, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan_quick", "Scansione rapida", true, None::<&str>)?;
    let update = MenuItem::with_id(app, "update", "Aggiorna firme", true, None::<&str>)?;
    let can_pause = state == TrayState::Active;
    let pause = Submenu::with_items(
        app,
        "Sospendi la protezione",
        can_pause,
        &[
            &MenuItem::with_id(app, "pause_5", "5 minuti", true, None::<&str>)?,
            &MenuItem::with_id(app, "pause_15", "15 minuti", true, None::<&str>)?,
            &MenuItem::with_id(app, "pause_30", "30 minuti", true, None::<&str>)?,
            &MenuItem::with_id(app, "pause_60", "1 ora", true, None::<&str>)?,
            &MenuItem::with_id(app, "pause_180", "3 ore", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "pause_restart", "Fino al riavvio", true, None::<&str>)?,
        ],
    )?;
    let resume = MenuItem::with_id(app, "resume", "Riprendi la protezione", state == TrayState::Paused, None::<&str>)?;
    let toggle = match state {
        TrayState::Stopped => MenuItem::with_id(app, "rt_on", "Attiva la protezione in tempo reale", true, None::<&str>)?,
        _ => MenuItem::with_id(app, "rt_off", "Disattiva la protezione in tempo reale", state != TrayState::OnDemand, None::<&str>)?,
    };
    let quit = MenuItem::with_id(app, "quit", "Esci da Vigil", true, None::<&str>)?;
    Menu::with_items(
        app,
        &[
            &header,
            &PredefinedMenuItem::separator(app)?,
            &open,
            &scan,
            &update,
            &PredefinedMenuItem::separator(app)?,
            &pause,
            &resume,
            &toggle,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )
}

fn report(app: &AppHandle, result: Result<(), String>) {
    if let Err(message) = result {
        toast::show(
            app,
            toast::ToastData {
                tone: toast::Tone::Warn,
                title: "Operazione non riuscita".into(),
                message: Some(message),
                auto_close_secs: Some(8),
                ..Default::default()
            },
        );
    }
}

fn on_menu(app: &AppHandle, id: &str) {
    match id {
        "open" => toast::show_main(app),
        "scan_quick" => {
            toast::show_main(app);
            let _ = app.emit("tray://quick-scan", ());
        }
        "update" => report(app, crate::run_update_bg(app)),
        "resume" => report(app, crate::rt::resume()),
        "rt_on" => report(app, crate::rt::set_enabled(true)),
        "rt_off" => report(app, crate::rt::set_enabled(false)),
        "quit" => app.exit(0),
        other => {
            if let Some(arg) = other.strip_prefix("pause_") {
                let minutes = if arg == "restart" { None } else { arg.parse().ok() };
                report(app, crate::rt::pause(minutes));
            }
        }
    }
}

pub fn init(app: &AppHandle) -> tauri::Result<()> {
    let ui = RtUiStatus::default();
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon(state_of(&ui)))
        .tooltip("Vigil")
        .menu(&build_menu(app, &ui)?)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| on_menu(app, ev.id().as_ref()))
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                toast::show_main(tray.app_handle());
            }
        })
        .build(app)?;
    app.manage(TrayCache::default());
    Ok(())
}

/// Aggiorna icona, suggerimento e menu quando cambia lo stato.
pub fn update(app: &AppHandle, ui: &RtUiStatus) {
    let state = state_of(ui);
    let text = status_text(ui);
    let Some(cache) = app.try_state::<TrayCache>() else { return };
    {
        let mut c = cache.0.lock().unwrap();
        if c.as_ref().is_some_and(|(s, t)| *s == state && *t == text) {
            return;
        }
        *c = Some((state, text.clone()));
    }
    let app2 = app.clone();
    let ui = ui.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(tray) = app2.tray_by_id(TRAY_ID) {
            let _ = tray.set_icon(Some(icon(state)));
            let _ = tray.set_tooltip(Some(format!("Vigil — {text}")));
            if let Ok(menu) = build_menu(&app2, &ui) {
                let _ = tray.set_menu(Some(menu));
            }
        }
    });
}
