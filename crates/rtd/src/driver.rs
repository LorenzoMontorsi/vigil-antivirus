//! Collegamento al minifilter VigilFlt: porta di comunicazione, I/O overlapped
//! con completion port (come l'esempio "scanner" di Microsoft) e decisioni.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use crossbeam_channel::{Receiver, Sender};
use vigil_engine::{
    ScanOptions, Verdict,
    quarantine::QuarantineError,
    rtproto::RtEventKind,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_OPERATION_ABORTED, GetLastError, HANDLE},
    Storage::{
        FileSystem::QueryDosDeviceW,
        InstallableFileSystems::{
            FILTER_MESSAGE_HEADER, FILTER_REPLY_HEADER, FilterConnectCommunicationPort, FilterGetMessage,
            FilterReplyMessage, FilterSendMessage,
        },
    },
    System::{
        IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED},
        Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW},
    },
};

use crate::state::Shared;

// Deve corrispondere a driver/VigilFlt/vigil_shared.h
const PORT_NAME: &str = r"\VigilPort";
const MAX_PATH_CHARS: usize = 1024;
const KIND_EXECUTE: u32 = 1;
const KIND_MODIFIED_CLOSE: u32 = 2;
const KIND_RENAME: u32 = 3;
const KIND_DELETE: u32 = 4;
const FLAG_EXISTED: u32 = 0x1;
const VERDICT_ALLOW: u32 = 0;
const VERDICT_BLOCK: u32 = 1;

#[repr(C)]
pub(crate) struct Request {
    kind: u32,
    process_id: u32,
    flags: u32,
    path_length: u32,
    path: [u16; MAX_PATH_CHARS],
}

/// Buffer di un messaggio in attesa: la porta è asincrona, quindi I/O overlapped.
#[repr(C)]
pub(crate) struct Message {
    header: FILTER_MESSAGE_HEADER,
    request: Request,
    ovlp: OVERLAPPED,
}

#[repr(C)]
pub(crate) struct Reply {
    verdict: u32,
}

#[repr(C)]
struct ReplyMessage {
    header: FILTER_REPLY_HEADER,
    reply: Reply,
}

/// Messaggio servizio -> driver: cartelle da proteggere (vigil_shared.h, VIGIL_CONFIG).
const MAX_PROTECTED: usize = 4;
const PROTECTED_CHARS: usize = 300;

#[repr(C)]
struct DriverConfig {
    count: u32,
    paths: [[u16; PROTECTED_CHARS]; MAX_PROTECTED],
}

/// "C:\Program Files\Vigil" -> "\Device\HarddiskVolume3\Program Files\Vigil\"
pub(crate) fn to_nt_dir(dos: &Path, map: &[(String, String)]) -> Option<String> {
    let s = dos.to_string_lossy();
    let (drive, rest) = s.split_at_checked(2)?;
    let dev = map.iter().find(|(_, d)| d.eq_ignore_ascii_case(drive)).map(|(dev, _)| dev)?;
    let rest = rest.trim_end_matches('\\');
    Some(format!("{dev}{rest}\\"))
}

/// Autodifesa: comunica al driver le cartelle in cui solo il servizio può scrivere.
fn send_protected_dirs(port: HANDLE, shared: &Shared, devices: &[(String, String)]) {
    let mut dirs = vec![shared.config.data_dir.clone()];
    if shared.config.protect_install_dir {
        if let Some(d) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
            dirs.push(d);
        }
    }
    let mut cfg: DriverConfig = unsafe { std::mem::zeroed() };
    for d in dirs.iter().take(MAX_PROTECTED) {
        let Some(nt) = to_nt_dir(d, devices) else { continue };
        let w: Vec<u16> = nt.encode_utf16().collect();
        if w.len() >= PROTECTED_CHARS {
            continue;
        }
        cfg.paths[cfg.count as usize][..w.len()].copy_from_slice(&w);
        cfg.count += 1;
        println!("autodifesa: {}", d.display());
    }
    let mut ret = 0u32;
    let hr = unsafe {
        FilterSendMessage(port, &cfg as *const _ as *const _, size_of::<DriverConfig>() as u32, std::ptr::null_mut(), 0, &mut ret)
    };
    if hr < 0 {
        eprintln!("configurazione dell'autodifesa non accettata dal driver: HRESULT 0x{hr:08X}");
    }
}

/// Dimensione passata a FilterGetMessage: intestazione + richiesta, senza OVERLAPPED.
pub(crate) const MESSAGE_SIZE: u32 = std::mem::offset_of!(Message, ovlp) as u32;
/// HRESULT_FROM_WIN32(ERROR_IO_PENDING)
const HR_IO_PENDING: i32 = 0x8007_03E5u32 as i32;

struct Handle(HANDLE);
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Ogni buffer è usato da un solo thread alla volta (quello che ne riceve il completamento).
#[derive(Clone, Copy)]
struct Raw(usize);
unsafe impl Send for Raw {}

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

pub(crate) fn to_dos_path(nt: &str, map: &[(String, String)]) -> Option<PathBuf> {
    map.iter().find_map(|(dev, drive)| {
        let rest = nt.strip_prefix(dev.as_str())?;
        rest.starts_with('\\').then(|| PathBuf::from(format!("{drive}{rest}")))
    })
}

pub(crate) fn process_image(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

unsafe fn post_read(port: HANDLE, msg: *mut Message) -> Result<(), i32> {
    unsafe {
        (*msg).ovlp = std::mem::zeroed();
        let hr = FilterGetMessage(port, &mut (*msg).header, MESSAGE_SIZE, &mut (*msg).ovlp);
        if hr == HR_IO_PENDING || hr >= 0 { Ok(()) } else { Err(hr) }
    }
}

fn reply(port: HANDLE, message_id: u64, block: bool) {
    let mut r = ReplyMessage {
        header: FILTER_REPLY_HEADER { Status: 0, MessageId: message_id },
        reply: Reply { verdict: if block { VERDICT_BLOCK } else { VERDICT_ALLOW } },
    };
    // Un errore qui di solito significa che il driver ha già superato il timeout (e ha lasciato passare).
    let _ = unsafe { FilterReplyMessage(port, &mut r.header, (size_of::<FILTER_REPLY_HEADER>() + size_of::<Reply>()) as u32) };
}

/// Si collega al driver (riprovando finché non è disponibile) e serve le richieste. Non ritorna.
/// Eventi per l'analisi comportamentale: (percorso, pid, il file esisteva già).
type BehaviorEvent = (PathBuf, u32, bool);

pub fn run(shared: Arc<Shared>) {
    let (write_tx, write_rx) = crossbeam_channel::unbounded::<(PathBuf, u32)>();
    {
        let shared = shared.clone();
        std::thread::spawn(move || write_worker(&shared, write_rx));
    }
    let behavior = Arc::new(crate::behavior::Behavior::new());
    let (beh_tx, beh_rx) = crossbeam_channel::unbounded::<BehaviorEvent>();
    {
        let (shared, behavior) = (shared.clone(), behavior.clone());
        std::thread::spawn(move || {
            for (path, pid, existed) in beh_rx {
                if !shared.is_paused() {
                    behavior.on_modified(&shared, &path, pid, existed);
                }
            }
        });
    }
    loop {
        match connect_and_serve(&shared, &write_tx, &beh_tx, &behavior) {
            Ok(()) => eprintln!("connessione con il driver chiusa, riprovo"),
            Err(e) => eprintln!("{e}"),
        }
        shared.driver_connected.store(false, Ordering::SeqCst);
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn connect_and_serve(
    shared: &Arc<Shared>,
    write_tx: &Sender<(PathBuf, u32)>,
    beh_tx: &Sender<BehaviorEvent>,
    behavior: &Arc<crate::behavior::Behavior>,
) -> Result<(), String> {
    let mut h: HANDLE = std::ptr::null_mut();
    let hr = unsafe {
        FilterConnectCommunicationPort(wide(PORT_NAME).as_ptr(), 0, std::ptr::null(), 0, std::ptr::null(), &mut h)
    };
    if hr < 0 {
        return Err(format!("driver VigilFlt non raggiungibile (HRESULT 0x{hr:08X}), riprovo tra poco"));
    }
    let port = Arc::new(Handle(h));
    let threads = shared.config.threads.max(1);
    let iocp = unsafe { CreateIoCompletionPort(port.0, std::ptr::null_mut(), 0, threads as u32) };
    if iocp.is_null() {
        return Err(format!("CreateIoCompletionPort: {}", unsafe { GetLastError() }));
    }
    let iocp = Arc::new(Handle(iocp));
    let mut buffers = Vec::new();
    for _ in 0..threads * 2 {
        let msg: *mut Message = Box::into_raw(Box::new(unsafe { std::mem::zeroed() }));
        buffers.push(Raw(msg as usize));
        unsafe { post_read(port.0, msg) }.map_err(|hr| format!("FilterGetMessage iniziale: 0x{hr:08X}"))?;
    }
    shared.driver_connected.store(true, Ordering::SeqCst);
    println!("collegato al driver VigilFlt, {threads} thread in ascolto");

    let devices = Arc::new(device_map());
    send_protected_dirs(port.0, shared, &devices);
    let workers: Vec<_> = (0..threads)
        .map(|_| {
            let (shared, port, iocp, devices, tx, btx, beh) =
                (shared.clone(), port.clone(), iocp.clone(), devices.clone(), write_tx.clone(), beh_tx.clone(), behavior.clone());
            std::thread::spawn(move || exec_worker(&shared, &port, &iocp, &devices, &tx, &btx, &beh))
        })
        .collect();
    for w in workers {
        let _ = w.join();
    }
    // Tutti i thread sono usciti: nessuno usa più i buffer.
    for b in buffers {
        drop(unsafe { Box::from_raw(b.0 as *mut Message) });
    }
    Ok(())
}

fn exec_worker(
    shared: &Shared,
    port: &Handle,
    iocp: &Handle,
    devices: &[(String, String)],
    write_tx: &Sender<(PathBuf, u32)>,
    beh_tx: &Sender<BehaviorEvent>,
    behavior: &crate::behavior::Behavior,
) {
    loop {
        let mut bytes = 0u32;
        let mut key = 0usize;
        let mut povl: *mut OVERLAPPED = std::ptr::null_mut();
        let ok = unsafe { GetQueuedCompletionStatus(iocp.0, &mut bytes, &mut key, &mut povl, u32::MAX) };
        if povl.is_null() {
            return;
        }
        let msg = unsafe { (povl as *mut u8).sub(std::mem::offset_of!(Message, ovlp)) as *mut Message };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_OPERATION_ABORTED {
                return; // porta chiusa (driver scaricato)
            }
            if unsafe { post_read(port.0, msg) }.is_err() {
                return;
            }
            continue;
        }
        let (message_id, kind, pid, flags, nt_path) = unsafe {
            let m = &*msg;
            let len = (m.request.path_length as usize / 2).min(MAX_PATH_CHARS);
            (
                m.header.MessageId,
                m.request.kind,
                m.request.process_id,
                m.request.flags,
                String::from_utf16_lossy(&m.request.path[..len]),
            )
        };
        let dos = to_dos_path(&nt_path, devices);

        match kind {
            KIND_EXECUTE => {
                let block = dos.as_deref().is_some_and(|p| check_execute(shared, p, pid));
                reply(port.0, message_id, block);
            }
            KIND_MODIFIED_CLOSE => {
                // Risposta immediata: chi scrive non deve aspettare la scansione.
                reply(port.0, message_id, false);
                if let Some(p) = dos {
                    let _ = beh_tx.send((p.clone(), pid, flags & FLAG_EXISTED != 0));
                    let _ = write_tx.send((p, pid));
                }
            }
            KIND_RENAME | KIND_DELETE => {
                let block =
                    !shared.is_paused() && dos.as_deref().is_some_and(|p| behavior.should_block_rename_or_delete(p, pid));
                // Prima la risposta (l'operazione viene negata), poi si ferma il processo.
                reply(port.0, message_id, block);
                if block {
                    if let Some(p) = &dos {
                        behavior.stop_after_block(shared, p, pid);
                    }
                }
            }
            _ => reply(port.0, message_id, false),
        }
        if unsafe { post_read(port.0, msg) }.is_err() {
            return;
        }
    }
}

/// `true` se l'esecuzione va bloccata.
fn check_execute(shared: &Shared, path: &Path, pid: u32) -> bool {
    if shared.is_paused() || shared.is_excluded(path) {
        return false;
    }
    let engine = shared.engine();
    let cache = shared.cache();
    let opts = ScanOptions { heuristics: false, scan_archives: false, trust_microsoft: true, cache: Some(cache), ..Default::default() };
    let r = engine.scanner().scan_file(path, &opts);
    let mut stats = shared.stats.lock().unwrap();
    stats.exec_checked += 1;
    if r.cached {
        stats.exec_cached += 1;
    }
    if let Verdict::Infected { threat, .. } = &r.verdict {
        stats.exec_blocked += 1;
        drop(stats);
        let shown = path.display().to_string();
        // Si blocca sempre; l'evento (e quindi l'avviso) si registra una volta sola.
        if shared.should_report_block(&shown) {
            shared.stats.lock().unwrap().threats_found += 1;
            println!("BLOCCATO  {shown}  [{threat}]");
            shared.push_event(RtEventKind::Blocked, shown, threat.clone(), process_image(pid), None);
        }
        return true;
    }
    false
}

/// Analizza in coda i file appena scritti e, se serve, li mette in quarantena.
fn write_worker(shared: &Shared, rx: Receiver<(PathBuf, u32)>) {
    let opts = ScanOptions { heuristics: false, trust_microsoft: true, ..Default::default() };
    let mut recent: HashMap<PathBuf, Instant> = HashMap::new();
    let mut last_save = Instant::now();
    for (path, pid) in rx {
        // Un download genera molte chiusure dello stesso file: una scansione al secondo basta.
        recent.retain(|_, t| t.elapsed() < Duration::from_secs(5));
        if recent.get(&path).is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
            continue;
        }
        recent.insert(path.clone(), Instant::now());
        if shared.is_paused() || shared.is_excluded(&path) {
            continue;
        }
        // Il file sta finendo di chiudersi: un attimo di pazienza prima di leggerlo.
        std::thread::sleep(Duration::from_millis(300));

        let engine = shared.engine();
        let r = engine.scanner().scan_file(&path, &opts);
        shared.stats.lock().unwrap().writes_checked += 1;
        if let Verdict::Infected { threat, source, .. } = &r.verdict {
            shared.stats.lock().unwrap().threats_found += 1;
            let shown = path.display().to_string();
            let process = process_image(pid);
            match (&shared.quarantine, shared.config.auto_quarantine) {
                (Some(q), true) => {
                    let source = format!("{source:?}").to_lowercase();
                    let mut attempt = 0;
                    let res = loop {
                        match q.add(&path, threat, &source) {
                            Err(QuarantineError::InUse) if attempt < 10 => {
                                attempt += 1;
                                std::thread::sleep(Duration::from_secs(1));
                            }
                            other => break other,
                        }
                    };
                    match res {
                        Ok(_) => {
                            shared.stats.lock().unwrap().quarantined += 1;
                            println!("QUARANTENA {shown}  [{threat}]");
                            shared.push_event(RtEventKind::Quarantined, shown, threat.clone(), process, None);
                        }
                        Err(e) => {
                            println!("MINACCIA   {shown}  [{threat}]  quarantena fallita: {e}");
                            shared.push_event(RtEventKind::QuarantineFailed, shown, threat.clone(), process, Some(e.to_string()));
                        }
                    }
                }
                _ => {
                    println!("MINACCIA   {shown}  [{threat}]");
                    shared.push_event(RtEventKind::Detected, shown, threat.clone(), process, None);
                }
            }
        }
        if last_save.elapsed() > Duration::from_secs(60) {
            shared.save_cache();
            last_save = Instant::now();
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
    fn converts_dos_dirs_to_nt() {
        let map = vec![(r"\Device\HarddiskVolume3".to_owned(), "C:".to_owned())];
        assert_eq!(
            to_nt_dir(Path::new(r"C:\Program Files\Vigil"), &map).as_deref(),
            Some(r"\Device\HarddiskVolume3\Program Files\Vigil\")
        );
        assert_eq!(to_nt_dir(Path::new(r"c:\ProgramData\Vigil\"), &map).as_deref(), Some(r"\Device\HarddiskVolume3\ProgramData\Vigil\"));
        assert_eq!(to_nt_dir(Path::new(r"Z:\x"), &map), None);
        assert_eq!(size_of::<DriverConfig>(), 4 + 4 * 300 * 2);
    }

    #[test]
    fn layout_matches_driver() {
        // VIGIL_REQUEST: 4 ULONG + 1024 WCHAR
        assert_eq!(size_of::<Request>(), 16 + 2048);
        assert_eq!(size_of::<Reply>(), 4);
        assert!(MESSAGE_SIZE as usize >= 16 + 16 + 2048);
        assert_eq!(std::mem::offset_of!(Message, request), 16);
    }
}
