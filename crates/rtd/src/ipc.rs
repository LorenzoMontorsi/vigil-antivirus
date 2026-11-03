//! Named pipe per l'app: una richiesta JSON (una riga) e una risposta per connessione.
//!
//! Permessi: SYSTEM e Amministratori pieno controllo, utenti interattivi
//! lettura/scrittura; client remoti rifiutati. I comandi esposti non permettono
//! di disattivare la protezione (per quello serve fermare il servizio).

use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    os::windows::io::FromRawHandle,
    sync::Arc,
};

use vigil_engine::rtproto::{PIPE_NAME, Request, Response};
use windows_sys::Win32::{
    Foundation::{ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::PIPE_ACCESS_DUPLEX,
    System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    },
};

use crate::state::Shared;

/// SYSTEM e Amministratori: tutto. Utenti interattivi: lettura e scrittura.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
const MAX_REQUEST: u64 = 4096;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub fn handle_request(shared: &Shared, req: Request) -> Response {
    match req {
        Request::Status => Response::Status(shared.status()),
        Request::Events { after, limit } => Response::Events { events: shared.events_after(after, limit) },
        Request::Reload => {
            shared.reload();
            Response::Ok
        }
    }
}

/// Serve la pipe per sempre (un thread per client).
pub fn serve(shared: Arc<Shared>) {
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(PIPE_SDDL).as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut())
    };
    if ok == 0 {
        eprintln!("descrittore di sicurezza della pipe non valido: {}", unsafe { GetLastError() });
        return;
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let name = wide(PIPE_NAME);
    loop {
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &sa,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            eprintln!("CreateNamedPipeW: {}", unsafe { GetLastError() });
            std::thread::sleep(std::time::Duration::from_secs(1));
            continue;
        }
        let connected = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) } != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        let file = unsafe { File::from_raw_handle(h as _) };
        if !connected {
            continue; // il drop chiude l'handle
        }
        let shared = shared.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new((&file).take_limited());
            let mut line = String::new();
            let resp = match reader.read_line(&mut line) {
                Ok(_) => match serde_json::from_str::<Request>(line.trim()) {
                    Ok(req) => handle_request(&shared, req),
                    Err(e) => Response::Error { message: format!("richiesta non valida: {e}") },
                },
                Err(e) => Response::Error { message: e.to_string() },
            };
            if let Ok(mut out) = serde_json::to_string(&resp) {
                out.push('\n');
                let _ = (&file).write_all(out.as_bytes());
                let _ = (&file).flush();
            }
        });
    }
    #[allow(unreachable_code)]
    unsafe {
        LocalFree(sd as _);
    }
}

/// Limita la lettura della richiesta: un client non può farci allocare memoria a piacere.
trait TakeLimited: Sized + std::io::Read {
    fn take_limited(self) -> std::io::Take<Self> {
        self.take(MAX_REQUEST)
    }
}
impl<R: std::io::Read> TakeLimited for R {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Config;

    #[test]
    fn requests_are_answered() {
        let d = tempfile::tempdir().unwrap();
        let shared = Shared::new(Config {
            signature_dirs: vec![],
            quarantine_dir: None,
            auto_quarantine: false,
            threads: 1,
            data_dir: d.path().to_path_buf(),
        })
        .unwrap();
        match handle_request(&shared, Request::Status) {
            Response::Status(s) => {
                assert!(!s.driver_connected);
                assert!(!s.auto_quarantine, "senza cartella di quarantena non può essere attiva");
                assert_eq!(s.yara_rules, 1); // solo EICAR integrata
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(handle_request(&shared, Request::Events { after: 0, limit: 10 }), Response::Events { events: vec![] });
    }
}
