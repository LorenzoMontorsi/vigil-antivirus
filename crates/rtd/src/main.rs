//! vigil-rtd: si collega al minifilter VigilFlt e decide in tempo reale.
//!
//! - richiesta "Execute": un exe/dll sta per essere caricato come codice.
//!   Lo analizziamo e rispondiamo "blocca" se è una minaccia certa.
//! - richiesta "ModifiedClose": un file è stato scritto e chiuso.
//!   Lo analizziamo e segnaliamo; il driver non aspetta un verdetto utile.
//!
//! Uso (da amministratore o SYSTEM):
//!   vigil-rtd <cartella-firme> [--threads N]
//!
//! Prima versione da console per i test nella VM; diventerà un servizio di Windows.

#[cfg(not(windows))]
fn main() {
    eprintln!("vigil-rtd funziona solo su Windows");
}

#[cfg(windows)]
fn main() {
    if let Err(e) = imp::run() {
        eprintln!("errore: {e}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod imp {
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
        time::Instant,
    };

    use vigil_engine::{EngineBuilder, ScanOptions, Verdict};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_OPERATION_ABORTED, GetLastError, HANDLE},
        System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED},
        Storage::{
            FileSystem::QueryDosDeviceW,
            InstallableFileSystems::{
                FILTER_MESSAGE_HEADER, FILTER_REPLY_HEADER, FilterConnectCommunicationPort, FilterGetMessage,
                FilterReplyMessage,
            },
        },
    };

    // Deve corrispondere a driver/VigilFlt/vigil_shared.h
    const PORT_NAME: &str = r"\VigilPort";
    const MAX_PATH_CHARS: usize = 1024;
    const KIND_EXECUTE: u32 = 1;
    const KIND_MODIFIED_CLOSE: u32 = 2;
    const VERDICT_ALLOW: u32 = 0;
    const VERDICT_BLOCK: u32 = 1;

    #[repr(C)]
    struct Request {
        kind: u32,
        process_id: u32,
        path_length: u32,
        path: [u16; MAX_PATH_CHARS],
    }

    /// Buffer di un messaggio in attesa. Come nell'esempio "scanner" di Microsoft:
    /// la porta è asincrona, quindi si usa I/O overlapped con una completion port.
    #[repr(C)]
    struct Message {
        header: FILTER_MESSAGE_HEADER,
        request: Request,
        ovlp: OVERLAPPED,
    }

    /// Dimensione passata a FilterGetMessage: intestazione + richiesta, senza OVERLAPPED.
    const MESSAGE_SIZE: u32 = std::mem::offset_of!(Message, ovlp) as u32;
    /// HRESULT_FROM_WIN32(ERROR_IO_PENDING)
    const HR_IO_PENDING: i32 = 0x8007_03E5u32 as i32;

    /// Puntatori passati ai thread: ogni buffer è usato da un solo thread alla volta
    /// (quello che ne ha ricevuto il completamento).
    #[derive(Clone, Copy)]
    struct Raw(usize);
    unsafe impl Send for Raw {}

    /// Accoda (di nuovo) una lettura asincrona sul buffer.
    unsafe fn post_read(port: HANDLE, msg: *mut Message) -> Result<(), i32> {
        unsafe {
            (*msg).ovlp = std::mem::zeroed();
            let hr = FilterGetMessage(port, &mut (*msg).header, MESSAGE_SIZE, &mut (*msg).ovlp);
            if hr == HR_IO_PENDING || hr >= 0 { Ok(()) } else { Err(hr) }
        }
    }

    #[repr(C)]
    struct Reply {
        verdict: u32,
    }

    #[repr(C)]
    struct ReplyMessage {
        header: FILTER_REPLY_HEADER,
        reply: Reply,
    }

    struct Port(HANDLE);
    unsafe impl Send for Port {}
    unsafe impl Sync for Port {}
    impl Drop for Port {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// "\Device\HarddiskVolume3" -> "C:" per tutte le lettere di unità presenti.
    fn device_map() -> Vec<(String, String)> {
        let mut map = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let mut buf = [0u16; 512];
            let n = unsafe { QueryDosDeviceW(wide(&drive).as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n > 0 {
                let end = buf.iter().position(|&c| c == 0).unwrap_or(0);
                map.push((String::from_utf16_lossy(&buf[..end]), drive));
            }
        }
        // Prima i dispositivi con nome più lungo (HarddiskVolume10 prima di HarddiskVolume1).
        map.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        map
    }

    fn to_dos_path(nt: &str, map: &[(String, String)]) -> Option<PathBuf> {
        map.iter().find_map(|(dev, drive)| {
            let rest = nt.strip_prefix(dev.as_str())?;
            rest.starts_with('\\').then(|| PathBuf::from(format!("{drive}{rest}")))
        })
    }

    pub fn run() -> Result<(), String> {
        let mut args = std::env::args().skip(1);
        let sigs = PathBuf::from(args.next().ok_or("uso: vigil-rtd <cartella-firme> [--threads N]")?);
        let mut threads = 4usize;
        while let Some(a) = args.next() {
            if a == "--threads" {
                threads = args.next().and_then(|n| n.parse().ok()).unwrap_or(4).clamp(1, 16);
            }
        }

        let t = Instant::now();
        let mut b = EngineBuilder::new();
        b.load_signature_dir(&sigs);
        let engine = Arc::new(b.build());
        let info = engine.info();
        println!(
            "motore pronto: {} regole YARA, {} hash ({:?}){}",
            info.yara_rules,
            info.hash_signatures,
            t.elapsed(),
            if info.warnings.is_empty() { String::new() } else { format!(", {} avvisi", info.warnings.len()) }
        );

        let mut handle: HANDLE = std::ptr::null_mut();
        let hr = unsafe {
            FilterConnectCommunicationPort(wide(PORT_NAME).as_ptr(), 0, std::ptr::null(), 0, std::ptr::null(), &mut handle)
        };
        if hr < 0 {
            return Err(format!(
                "connessione al driver fallita (HRESULT 0x{hr:08X}): VigilFlt è caricato? (fltmc load VigilFlt) Serve l'amministratore."
            ));
        }
        let port = Arc::new(Port(handle));
        let devices = Arc::new(device_map());

        let iocp = unsafe { CreateIoCompletionPort(port.0, std::ptr::null_mut(), 0, threads as u32) };
        if iocp.is_null() {
            return Err(format!("CreateIoCompletionPort fallita: {}", unsafe { GetLastError() }));
        }
        // Due buffer per thread: mentre uno viene analizzato l'altro è già in attesa.
        for _ in 0..threads * 2 {
            let msg: *mut Message = Box::into_raw(Box::new(unsafe { std::mem::zeroed() }));
            unsafe { post_read(port.0, msg) }.map_err(|hr| format!("FilterGetMessage iniziale: 0x{hr:08X}"))?;
        }
        println!("collegato al driver VigilFlt, {threads} thread in ascolto");

        let mut workers = Vec::new();
        for _ in 0..threads {
            let (port, engine, devices, iocp) = (port.clone(), engine.clone(), devices.clone(), Raw(iocp as usize));
            workers.push(std::thread::spawn(move || worker(&port, iocp, &engine, &devices)));
        }
        for w in workers {
            let _ = w.join();
        }
        Ok(())
    }

    fn worker(port: &Port, iocp: Raw, engine: &vigil_engine::Engine, devices: &[(String, String)]) {
        // Niente ClamAV qui per ora: solo il motore di Vigil, veloce.
        let opts = ScanOptions { scan_archives: true, heuristics: false, trust_microsoft: true, ..Default::default() };
        let mut scanner = engine.scanner();
        loop {
            let mut bytes = 0u32;
            let mut key = 0usize;
            let mut povl: *mut OVERLAPPED = std::ptr::null_mut();
            let ok = unsafe { GetQueuedCompletionStatus(iocp.0 as HANDLE, &mut bytes, &mut key, &mut povl, u32::MAX) };
            if povl.is_null() {
                eprintln!("completion port chiusa ({}), il thread termina", unsafe { GetLastError() });
                return;
            }
            let msg = unsafe { (povl as *mut u8).sub(std::mem::offset_of!(Message, ovlp)) as *mut Message };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err == ERROR_OPERATION_ABORTED {
                    return; // porta chiusa: il driver è stato scaricato
                }
                eprintln!("lettura fallita ({err}), riprovo");
                let _ = unsafe { post_read(port.0, msg) };
                continue;
            }

            let (message_id, kind, pid, nt_path) = unsafe {
                let m = &*msg;
                let len = (m.request.path_length as usize / 2).min(MAX_PATH_CHARS);
                (m.header.MessageId, m.request.kind, m.request.process_id, String::from_utf16_lossy(&m.request.path[..len]))
            };
            let dos = to_dos_path(&nt_path, devices);

            let t = Instant::now();
            let verdict = match &dos {
                Some(p) => scanner.scan_file(p, &opts).verdict,
                None => Verdict::Skipped { reason: "percorso non convertibile".into() },
            };
            let shown = dos.as_deref().map(Path::display).map(|d| d.to_string()).unwrap_or(nt_path.clone());
            let block = kind == KIND_EXECUTE && matches!(verdict, Verdict::Infected { .. });

            match (&verdict, kind) {
                (Verdict::Infected { threat, .. }, KIND_EXECUTE) => {
                    println!("BLOCCATO  esecuzione di {shown}  [{threat}]  pid {pid}")
                }
                (Verdict::Infected { threat, .. }, KIND_MODIFIED_CLOSE) => {
                    println!("MINACCIA  scritta {shown}  [{threat}]  pid {pid}")
                }
                (_, KIND_EXECUTE) => println!("ok        exec  {shown}  ({:?})", t.elapsed()),
                (_, _) => println!("ok        write {shown}  ({:?})", t.elapsed()),
            }

            let mut reply = ReplyMessage {
                header: FILTER_REPLY_HEADER { Status: 0, MessageId: message_id },
                reply: Reply { verdict: if block { VERDICT_BLOCK } else { VERDICT_ALLOW } },
            };
            let hr = unsafe {
                FilterReplyMessage(
                    port.0,
                    &mut reply.header,
                    (size_of::<FILTER_REPLY_HEADER>() + size_of::<Reply>()) as u32,
                )
            };
            if hr < 0 {
                // Tipicamente: il driver ha già superato il timeout e ha lasciato passare.
                eprintln!("FilterReplyMessage: HRESULT 0x{hr:08X}");
            }
            if let Err(hr) = unsafe { post_read(port.0, msg) } {
                eprintln!("FilterGetMessage: HRESULT 0x{hr:08X}");
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn converts_nt_paths() {
            let map = vec![
                (r"\Device\HarddiskVolume10".to_owned(), "D:".to_owned()),
                (r"\Device\HarddiskVolume1".to_owned(), "C:".to_owned()),
            ];
            assert_eq!(to_dos_path(r"\Device\HarddiskVolume1\Windows\a.exe", &map), Some(PathBuf::from(r"C:\Windows\a.exe")));
            assert_eq!(to_dos_path(r"\Device\HarddiskVolume10\x.dll", &map), Some(PathBuf::from(r"D:\x.dll")));
            assert_eq!(to_dos_path(r"\Device\Mup\server\share", &map), None);
        }

        #[test]
        fn layout_matches_driver() {
            // VIGIL_REQUEST: 3 ULONG + 1024 WCHAR
            assert_eq!(size_of::<Request>(), 12 + 2048);
            assert_eq!(size_of::<Reply>(), 4);
            // FILTER_MESSAGE_HEADER (16) + VIGIL_REQUEST, più eventuale riempimento
            // prima di OVERLAPPED (allineato a 8): il buffer non deve essere più piccolo.
            assert!(MESSAGE_SIZE as usize >= 16 + 12 + 2048);
            assert_eq!(std::mem::offset_of!(Message, request), 16);
        }
    }
}
