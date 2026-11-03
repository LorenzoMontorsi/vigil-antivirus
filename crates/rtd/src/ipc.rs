//! Named pipe per l'app: una richiesta JSON (una riga) e una risposta per connessione.
//!
//! Permessi: SYSTEM e Amministratori pieno controllo, utenti interattivi
//! lettura/scrittura; client remoti rifiutati. I comandi esposti non permettono
//! di disattivare la protezione (per quello serve fermare il servizio).

use std::{
    ffi::c_void,
    fs::File,
    io::{BufRead, BufReader, Write},
    os::windows::io::{AsRawHandle, FromRawHandle},
    sync::Arc,
};

use vigil_engine::rtproto::{PIPE_NAME, Request, Response};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        GetTokenInformation, PSECURITY_DESCRIPTOR, RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
        TokenElevation,
    },
    System::Threading::{GetCurrentThread, OpenThreadToken},
    Storage::FileSystem::PIPE_ACCESS_DUPLEX,
    System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    },
};

use crate::state::Shared;

/// SYSTEM e Amministratori: tutto. Utenti interattivi: lettura e scrittura.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
/// Le richieste di AMSI portano il contenuto dello script (fino a 4 MB, in base64).
const MAX_REQUEST: u64 = 6 * 1024 * 1024;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// `admin`: il client ha un token di amministratore elevato (verificato impersonandolo).
/// `client_pid`: processo all'altro capo della pipe (per AMSI è chi esegue lo script).
pub fn handle_request(shared: &Shared, req: Request, admin: bool, client_pid: u32) -> Response {
    let denied = || Response::Error {
        message: "operazione riservata agli amministratori: conferma la richiesta di Windows".into(),
    };
    match req {
        Request::Status => Response::Status(shared.status()),
        Request::Events { after, limit } => Response::Events { events: shared.events_after(after, limit) },
        Request::Reload => {
            shared.reload();
            Response::Ok
        }
        Request::Resume => {
            shared.resume();
            Response::Ok
        }
        Request::Pause { seconds } => {
            if !admin {
                return denied();
            }
            shared.pause(seconds);
            Response::Ok
        }
        Request::ScanBuffer { app, name, data } => {
            use base64::Engine as _;
            match base64::engine::general_purpose::STANDARD.decode(data.as_bytes()) {
                Ok(bytes) => {
                    let threat = crate::script::scan(shared, &app, &name, &bytes, client_pid);
                    Response::Scan { detected: threat.is_some(), threat }
                }
                Err(_) => Response::Error { message: "contenuto non valido".into() },
            }
        }
        Request::AddExclusion { path } => {
            if !admin {
                return denied();
            }
            match shared.add_exclusion(path) {
                Ok(()) => Response::Ok,
                Err(message) => Response::Error { message },
            }
        }
    }
}

/// `true` se il client della pipe ha un token elevato. Va chiamata dopo aver letto
/// dalla pipe (requisito di ImpersonateNamedPipeClient).
fn client_is_admin(pipe: HANDLE) -> bool {
    unsafe {
        if ImpersonateNamedPipeClient(pipe) == 0 {
            return false;
        }
        let mut token: HANDLE = std::ptr::null_mut();
        let ok = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token);
        RevertToSelf();
        if ok == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let r = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        r != 0 && elevation.TokenIsElevated != 0
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
                    Ok(req) => {
                        let h = file.as_raw_handle() as HANDLE;
                        let mut pid = 0u32;
                        unsafe { GetNamedPipeClientProcessId(h, &mut pid) };
                        // Il controllo dei privilegi serve solo ai comandi riservati.
                        let admin = matches!(req, Request::Pause { .. } | Request::AddExclusion { .. }) && client_is_admin(h);
                        handle_request(&shared, req, admin, pid)
                    }
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
        match handle_request(&shared, Request::Status, false, 0) {
            Response::Status(s) => {
                assert!(!s.driver_connected);
                assert!(!s.auto_quarantine, "senza cartella di quarantena non può essere attiva");
                assert_eq!(s.yara_rules, 1); // solo EICAR integrata
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(handle_request(&shared, Request::Events { after: 0, limit: 10 }, false, 0), Response::Events { events: vec![] });
        // Sospendere senza privilegi viene rifiutato, riprendere no.
        assert!(matches!(handle_request(&shared, Request::Pause { seconds: Some(600) }, false, 0), Response::Error { .. }));
        assert!(!shared.is_paused());
        assert_eq!(handle_request(&shared, Request::Pause { seconds: Some(600) }, true, 0), Response::Ok);
        assert!(shared.is_paused());
        assert_eq!(handle_request(&shared, Request::Resume, false, 0), Response::Ok);
        assert!(!shared.is_paused());
        assert!(matches!(
            handle_request(&shared, Request::AddExclusion { path: r"C:\x".into() }, false, 0),
            Response::Error { .. }
        ));
    }
}
