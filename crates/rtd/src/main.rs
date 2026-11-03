//! vigil-rtd: protezione in tempo reale di Vigil.
//!
//! Comandi:
//!   vigil-rtd run [opzioni]        in primo piano, da console (amministratore)
//!   vigil-rtd service [opzioni]    avviato dal Gestore servizi
//!   vigil-rtd install [opzioni]    registra e avvia il servizio VigilRtd (amministratore)
//!   vigil-rtd uninstall            ferma e rimuove il servizio (amministratore)
//!   vigil-rtd status               interroga il servizio tramite la pipe
//!   vigil-rtd pause <minuti|riavvio>  sospende la protezione (amministratore)
//!   vigil-rtd resume               riprende la protezione
//!   vigil-rtd exclude <percorso>   esclude un file/cartella (amministratore)
//!   vigil-rtd vault-restore <id> [--exclude]   ripristina dalla quarantena del servizio (amministratore)
//!   vigil-rtd vault-delete <id>...             elimina dalla quarantena del servizio (amministratore)
//!
//! Opzioni:
//!   --sigs <cartella>       cartella di firme (ripetibile)
//!   --quarantine <cartella> deposito della quarantena
//!   --auto-quarantine       isola i file scritti riconosciuti come minacce
//!   --threads <n>           thread per le richieste del driver (default 4)
//!   --data <cartella>       log ed eventi (default %ProgramData%\Vigil)

#[cfg(windows)]
mod driver;
#[cfg(windows)]
mod ipc;
mod script;
#[cfg(windows)]
mod service;
mod state;

use std::{path::PathBuf, sync::Arc};

use state::{Config, Shared};

pub struct Options(Config);

impl Options {
    pub fn parse(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut c = Config {
            signature_dirs: Vec::new(),
            quarantine_dir: None,
            auto_quarantine: false,
            threads: 4,
            data_dir: std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join("Vigil"),
        };
        let mut args = args.peekable();
        while let Some(a) = args.next() {
            let mut value = |name: &str| args.next().ok_or(format!("manca il valore di {name}"));
            match a.as_str() {
                "--sigs" => c.signature_dirs.push(value("--sigs")?.into()),
                "--quarantine" => c.quarantine_dir = Some(value("--quarantine")?.into()),
                "--auto-quarantine" => c.auto_quarantine = true,
                "--threads" => c.threads = value("--threads")?.parse().map_err(|_| "--threads non valido")?,
                "--data" => c.data_dir = value("--data")?.into(),
                other => return Err(format!("opzione sconosciuta: {other}")),
            }
        }
        c.threads = c.threads.clamp(1, 16);
        Ok(Self(c))
    }
}

/// Carica il motore e avvia i thread di protezione e della pipe.
#[cfg(windows)]
pub fn start_protection(opts: Options) -> Result<Arc<Shared>, String> {
    let shared = Arc::new(Shared::new(opts.0)?);
    let st = shared.status();
    println!(
        "motore pronto: {} regole YARA, {} hash; quarantena automatica {}",
        st.yara_rules,
        st.hash_signatures,
        if st.auto_quarantine { "attiva" } else { "disattivata" }
    );
    {
        let s = shared.clone();
        std::thread::spawn(move || ipc::serve(s));
    }
    {
        let s = shared.clone();
        std::thread::spawn(move || driver::run(s));
    }
    Ok(shared)
}

#[cfg(windows)]
fn ask(req: &vigil_engine::rtproto::Request) -> Result<vigil_engine::rtproto::Response, String> {
    use std::io::{BufRead, BufReader, Write};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(vigil_engine::rtproto::PIPE_NAME)
        .map_err(|e| format!("servizio non raggiungibile: {e}"))?;
    writeln!(f, "{}", serde_json::to_string(req).unwrap()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(f).read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map_err(|e| e.to_string())
}

/// Invia un comando; una risposta di errore diventa un errore (codice di uscita 1).
#[cfg(windows)]
fn command(req: vigil_engine::rtproto::Request) -> Result<(), String> {
    match ask(&req)? {
        vigil_engine::rtproto::Response::Error { message } => Err(message),
        _ => {
            println!("ok");
            Ok(())
        }
    }
}

#[cfg(windows)]
fn client_status() -> Result<(), String> {
    use vigil_engine::rtproto::{Request, Response};
    println!("{}", serde_json::to_string_pretty(&ask(&Request::Status)?).unwrap());
    if let Response::Events { events } = ask(&Request::Events { after: 0, limit: 10 })? {
        for e in events {
            println!("#{} {:?} {} [{}] da {}", e.id, e.kind, e.path, e.threat, e.process.as_deref().unwrap_or("?"));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let rest: Vec<String> = args.collect();
    let result = match cmd.as_str() {
        "run" => Options::parse(rest.into_iter()).and_then(start_protection).map(|_| loop {
            std::thread::park();
        }),
        "service" => service::run_as_service(),
        "install" => Options::parse(rest.clone().into_iter()).and_then(|_| service::install(rest)),
        "uninstall" => service::uninstall(),
        "status" => client_status(),
        "pause" => parse_pause(rest.first().map(String::as_str))
            .and_then(|seconds| command(vigil_engine::rtproto::Request::Pause { seconds })),
        "resume" => command(vigil_engine::rtproto::Request::Resume),
        "vault-restore" => vault_restore(&rest),
        "vault-delete" => vault_delete(&rest),
        "exclude" => match rest.first() {
            Some(p) => command(vigil_engine::rtproto::Request::AddExclusion { path: p.clone() }),
            None => Err("uso: vigil-rtd exclude <percorso>".into()),
        },
        _ => Err("uso: vigil-rtd run|service|install|uninstall|status [opzioni]  (vedi l'intestazione di main.rs)".into()),
    };
    if let Err(e) = result {
        eprintln!("errore: {e}");
        std::process::exit(1);
    }
}

/// Deposito della quarantena del servizio: quello dichiarato dal servizio, altrimenti il predefinito.
#[cfg(windows)]
fn vault() -> Result<vigil_engine::quarantine::Quarantine, String> {
    let dir = match ask(&vigil_engine::rtproto::Request::Status) {
        Ok(vigil_engine::rtproto::Response::Status(s)) => s.quarantine_dir.map(PathBuf::from),
        _ => None,
    }
    .unwrap_or_else(|| Options::parse(std::iter::empty()).map(|o| o.0.data_dir.join("quarantine")).unwrap_or_default());
    vigil_engine::quarantine::Quarantine::open(&dir).map_err(|e| format!("quarantena {}: {e}", dir.display()))
}

#[cfg(windows)]
fn vault_restore(args: &[String]) -> Result<(), String> {
    let id = args.first().ok_or("uso: vigil-rtd vault-restore <id> [--exclude]")?;
    let path = vault()?.restore(id, None).map_err(|e| e.to_string())?;
    println!("ripristinato: {}", path.display());
    if args.iter().any(|a| a == "--exclude") {
        command(vigil_engine::rtproto::Request::AddExclusion { path: path.display().to_string() })?;
    }
    Ok(())
}

#[cfg(windows)]
fn vault_delete(ids: &[String]) -> Result<(), String> {
    if ids.is_empty() {
        return Err("uso: vigil-rtd vault-delete <id>...".into());
    }
    let q = vault()?;
    for id in ids {
        q.delete(id).map_err(|e| format!("{id}: {e}"))?;
    }
    println!("eliminati: {}", ids.len());
    Ok(())
}

/// "15" -> 15 minuti; "riavvio" -> fino al riavvio del servizio.
fn parse_pause(arg: Option<&str>) -> Result<Option<u64>, String> {
    match arg {
        Some("riavvio") | Some("restart") => Ok(None),
        Some(m) => m.parse::<u64>().map(|m| Some(m * 60)).map_err(|_| format!("minuti non validi: {m}")),
        None => Err("uso: vigil-rtd pause <minuti|riavvio>".into()),
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("vigil-rtd funziona solo su Windows");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_options() {
        let o = Options::parse(
            ["--sigs", "A", "--sigs", "B", "--quarantine", "Q", "--auto-quarantine", "--threads", "99"].map(String::from).into_iter(),
        )
        .unwrap()
        .0;
        assert_eq!(o.signature_dirs, vec![PathBuf::from("A"), PathBuf::from("B")]);
        assert_eq!(o.quarantine_dir, Some(PathBuf::from("Q")));
        assert!(o.auto_quarantine);
        assert_eq!(o.threads, 16);
        assert!(Options::parse(["--boh"].map(String::from).into_iter()).is_err());
    }
}
