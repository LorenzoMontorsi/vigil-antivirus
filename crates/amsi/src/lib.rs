//! Provider AMSI di Vigil.
//!
//! Windows chiama `Scan` con il contenuto di uno script già decodificato, subito
//! prima di eseguirlo (PowerShell, VBScript/JScript, macro di Office…). Il provider
//! lo inoltra al servizio VigilRtd sulla named pipe e restituisce il verdetto.
//!
//! Regole:
//! - fail-open: se il servizio non risponde entro `TIMEOUT`, lo script passa;
//! - niente motore qui dentro: questa DLL vive in ogni processo che usa script.
//!
//! Registrazione (amministratore): CLSID in HKLM\SOFTWARE\Classes\CLSID e
//! HKLM\SOFTWARE\Microsoft\AMSI\Providers (vedi driver/vm/amsi-install.ps1).

#![cfg(windows)]

use std::{
    ffi::c_void,
    io::{BufRead, BufReader, Write},
    sync::mpsc,
    time::Duration,
};

use base64::Engine as _;
use windows::{
    Win32::{
        Foundation::{CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_POINTER, S_FALSE},
        System::{
            Antimalware::{
                AMSI_ATTRIBUTE, AMSI_ATTRIBUTE_APP_NAME, AMSI_ATTRIBUTE_CONTENT_ADDRESS, AMSI_ATTRIBUTE_CONTENT_NAME,
                AMSI_ATTRIBUTE_CONTENT_SIZE, AMSI_RESULT, AMSI_RESULT_DETECTED, AMSI_RESULT_NOT_DETECTED, IAmsiStream,
                IAntimalwareProvider, IAntimalwareProvider_Impl,
            },
            Com::{IClassFactory, IClassFactory_Impl},
        },
    },
    core::{BOOL, GUID, HRESULT, IUnknown, Interface, PWSTR, Ref, implement, w},
};

/// {2B9E6E0B-5D1A-4C51-9E3B-7A1D2C4F8E61}
pub const CLSID_VIGIL_AMSI: GUID = GUID::from_u128(0x2b9e6e0b_5d1a_4c51_9e3b_7a1d2c4f8e61);

const PIPE_NAME: &str = r"\\.\pipe\vigil-rtd";
const TIMEOUT: Duration = Duration::from_secs(2);
/// Oltre questa dimensione si analizza solo l'inizio del contenuto.
const MAX_CONTENT: usize = 4 * 1024 * 1024;

#[implement(IAntimalwareProvider)]
struct Provider;

impl IAntimalwareProvider_Impl for Provider_Impl {
    fn Scan(&self, stream: Ref<IAmsiStream>) -> windows::core::Result<AMSI_RESULT> {
        let Ok(stream) = stream.ok() else { return Ok(AMSI_RESULT_NOT_DETECTED) };
        let app = string_attr(stream, AMSI_ATTRIBUTE_APP_NAME);
        let name = string_attr(stream, AMSI_ATTRIBUTE_CONTENT_NAME);
        let data = read_content(stream);
        if data.is_empty() {
            return Ok(AMSI_RESULT_NOT_DETECTED);
        }
        Ok(if ask_service(&app, &name, &data) == Some(true) { AMSI_RESULT_DETECTED } else { AMSI_RESULT_NOT_DETECTED })
    }

    fn CloseSession(&self, _session: u64) {}

    fn DisplayName(&self) -> windows::core::Result<PWSTR> {
        // Stringa statica: AMSI non la libera.
        Ok(PWSTR(w!("Vigil").as_ptr() as *mut u16))
    }
}

/// Legge un attributo del flusso. `None` se assente.
fn raw_attr(stream: &IAmsiStream, attr: AMSI_ATTRIBUTE, buf: &mut [u8]) -> Option<usize> {
    let mut ret = 0u32;
    unsafe { stream.GetAttribute(attr, buf, &mut ret) }.ok()?;
    Some(ret as usize)
}

fn string_attr(stream: &IAmsiStream, attr: AMSI_ATTRIBUTE) -> String {
    let mut buf = vec![0u8; 2048];
    let Some(n) = raw_attr(stream, attr, &mut buf) else { return String::new() };
    let wide: Vec<u16> = buf[..n.min(buf.len())].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

fn read_content(stream: &IAmsiStream) -> Vec<u8> {
    let mut size_buf = [0u8; 8];
    let size = match raw_attr(stream, AMSI_ATTRIBUTE_CONTENT_SIZE, &mut size_buf) {
        Some(8) => u64::from_le_bytes(size_buf) as usize,
        _ => return Vec::new(),
    };
    let size = size.min(MAX_CONTENT);
    if size == 0 {
        return Vec::new();
    }
    // Preferibilmente il contenuto è già in memoria: lo copiamo direttamente.
    let mut addr_buf = [0u8; 8];
    if raw_attr(stream, AMSI_ATTRIBUTE_CONTENT_ADDRESS, &mut addr_buf) == Some(8) {
        let addr = usize::from_le_bytes(addr_buf) as *const u8;
        if !addr.is_null() {
            return unsafe { std::slice::from_raw_parts(addr, size) }.to_vec();
        }
    }
    let mut data = vec![0u8; size];
    let mut read = 0u32;
    match unsafe { stream.Read(0, &mut data, &mut read) } {
        Ok(()) => {
            data.truncate(read as usize);
            data
        }
        Err(_) => Vec::new(),
    }
}

/// `Some(true)` = minaccia. `None` = servizio non raggiungibile o in ritardo (fail-open).
fn ask_service(app: &str, name: &str, data: &[u8]) -> Option<bool> {
    let line = serde_json::json!({
        "cmd": "scan_buffer",
        "app": app,
        "name": name,
        "data": base64::engine::general_purpose::STANDARD.encode(data),
    })
    .to_string();
    let (tx, rx) = mpsc::channel();
    // Un thread a parte: se il servizio si blocca, lo script non resta appeso.
    std::thread::spawn(move || {
        let _ = tx.send(exchange(&line));
    });
    rx.recv_timeout(TIMEOUT).ok().flatten()
}

fn exchange(line: &str) -> Option<bool> {
    let mut pipe = None;
    for _ in 0..3 {
        match std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
            Ok(f) => {
                pipe = Some(f);
                break;
            }
            // Tutte le istanze occupate per un istante: si riprova.
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut f = pipe?;
    writeln!(f, "{line}").ok()?;
    let mut out = String::new();
    BufReader::new(f).read_line(&mut out).ok()?;
    let v: serde_json::Value = serde_json::from_str(&out).ok()?;
    (v.get("type")?.as_str()? == "scan").then(|| v.get("detected").and_then(|d| d.as_bool()).unwrap_or(false))
}

// ── COM: fabbrica di classi ed esportazioni della DLL ──────────────────────

#[implement(IClassFactory)]
struct Factory;

impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<IUnknown>,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> windows::core::Result<()> {
        if ppv.is_null() {
            return Err(E_POINTER.into());
        }
        unsafe { *ppv = std::ptr::null_mut() };
        if outer.as_ref().is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        let provider: IAntimalwareProvider = Provider.into();
        unsafe { provider.query(riid, ppv) }.ok()
    }

    fn LockServer(&self, _lock: BOOL) -> windows::core::Result<()> {
        Ok(())
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn DllGetClassObject(rclsid: *const GUID, riid: *const GUID, ppv: *mut *mut c_void) -> HRESULT {
    unsafe {
        if ppv.is_null() || rclsid.is_null() {
            return E_POINTER;
        }
        *ppv = std::ptr::null_mut();
        if *rclsid != CLSID_VIGIL_AMSI {
            return CLASS_E_CLASSNOTAVAILABLE;
        }
        let factory: IClassFactory = Factory.into();
        factory.query(riid, ppv)
    }
}

/// La DLL resta caricata finché vive il processo: è il comportamento più semplice e sicuro.
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_FALSE
}
