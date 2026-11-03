//! "Analizza con Vigil" nel menu del tasto destro di Esplora risorse.
//!
//! La voce è registrata per l'utente corrente (HKCU\Software\Classes): niente
//! privilegi. Con più elementi selezionati Esplora risorse avvia Vigil una volta
//! per ciascuno (fino a 15): i lanci ravvicinati arrivano all'istanza già aperta
//! (plugin single-instance) e vengono raccolti in un'unica scansione.
//!
//! Su Windows 11 le voci "classiche" compaiono sotto "Mostra altre opzioni".

use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tauri::{AppHandle, Emitter, Manager};

const VERB: &str = "VigilScan";
const LABEL: &str = "Analizza con Vigil";
/// Esplora risorse avvia un processo per elemento: aspettiamo che arrivino tutti.
const GATHER: Duration = Duration::from_millis(900);

#[derive(Default)]
pub struct ShellScan {
    incoming: Mutex<Vec<String>>,
    ready: Mutex<Vec<String>>,
    gathering: AtomicBool,
}

/// Percorsi passati con `--scan <percorso>` sulla riga di comando.
pub fn scan_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--scan" {
            if let Some(p) = it.next() {
                if !p.trim().is_empty() {
                    out.push(p.clone());
                }
            }
        }
    }
    out
}

/// Accoda i percorsi e, finiti i lanci ravvicinati, avvisa l'interfaccia.
pub fn queue(app: &AppHandle, paths: Vec<String>) {
    if paths.is_empty() {
        return;
    }
    let st = app.state::<ShellScan>();
    st.incoming.lock().unwrap().extend(paths);
    if st.gathering.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(GATHER);
        let st = app.state::<ShellScan>();
        st.gathering.store(false, Ordering::SeqCst);
        let mut batch: Vec<String> = std::mem::take(&mut *st.incoming.lock().unwrap());
        batch.sort_by_key(|p| p.to_lowercase());
        batch.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        st.ready.lock().unwrap().extend(batch);
        crate::toast::show_main(&app);
        let _ = app.emit("shell://scan", ());
    });
}

/// L'interfaccia ritira i percorsi da analizzare (al primo avvio e a ogni "shell://scan").
#[tauri::command]
pub fn take_shell_scan(st: tauri::State<'_, ShellScan>) -> Vec<String> {
    std::mem::take(&mut *st.ready.lock().unwrap())
}

#[cfg(windows)]
mod reg {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW,
        RegSetValueExW,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// Scrive un valore stringa (nome vuoto = valore predefinito della chiave).
    pub fn set(path: &str, name: &str, value: &str) -> bool {
        let mut key: HKEY = std::ptr::null_mut();
        let ok = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                wide(path).as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        } == 0;
        if !ok {
            return false;
        }
        let data = wide(value);
        let name_w = wide(name);
        let r = unsafe {
            RegSetValueExW(
                key,
                if name.is_empty() { std::ptr::null() } else { name_w.as_ptr() },
                0,
                REG_SZ,
                data.as_ptr() as *const u8,
                (data.len() * 2) as u32,
            )
        };
        unsafe { RegCloseKey(key) };
        r == 0
    }

    pub fn delete_tree(path: &str) {
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, wide(path).as_ptr()) };
    }
}

/// Classi di oggetti su cui compare la voce: file, cartelle, unità.
const TARGETS: &[&str] = &["*", "Directory", "Drive"];

/// Registra o rimuove la voce del menu contestuale per l'eseguibile corrente.
#[cfg(windows)]
pub fn apply(enabled: bool) {
    // In sviluppo non registriamo l'eseguibile di debug.
    if cfg!(debug_assertions) {
        return;
    }
    for t in TARGETS {
        let base = format!(r"Software\Classes\{t}\shell\{VERB}");
        if !enabled {
            reg::delete_tree(&base);
            continue;
        }
        let Ok(exe) = std::env::current_exe() else { return };
        let exe = exe.display().to_string();
        reg::set(&base, "", LABEL);
        reg::set(&base, "Icon", &format!("\"{exe}\",0"));
        reg::set(&format!(r"{base}\command"), "", &format!("\"{exe}\" --scan \"%1\""));
    }
}

#[cfg(not(windows))]
pub fn apply(_enabled: bool) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scan_arguments() {
        let args: Vec<String> =
            ["vigil.exe", "--scan", r"C:\Users\x\file.exe", "--hidden", "--scan", r"D:\Cartella"].map(String::from).into();
        assert_eq!(scan_args(&args), vec![r"C:\Users\x\file.exe".to_owned(), r"D:\Cartella".to_owned()]);
        assert!(scan_args(&["vigil.exe".into()]).is_empty());
    }
}
