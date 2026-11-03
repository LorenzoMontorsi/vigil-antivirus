//! vigil-rtd: protezione in tempo reale di Vigil.
//!
//! Comandi:
//!   vigil-rtd run [opzioni]        in primo piano, da console (amministratore)
//!   vigil-rtd service [opzioni]    avviato dal Gestore servizi
//!   vigil-rtd install [opzioni]    registra e avvia il servizio VigilRtd (amministratore)
//!   vigil-rtd uninstall            ferma e rimuove il servizio (amministratore)
//!   vigil-rtd status               interroga il servizio tramite la pipe
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
fn client_status() -> Result<(), String> {
    use std::io::{BufRead, BufReader, Write};
    use vigil_engine::rtproto::{PIPE_NAME, Request, Response};
    let ask = |req: &Request| -> Result<Response, String> {
        let mut f = std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME).map_err(|e| format!("servizio non raggiungibile: {e}"))?;
        writeln!(f, "{}", serde_json::to_string(req).unwrap()).map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(f).read_line(&mut line).map_err(|e| e.to_string())?;
        serde_json::from_str(&line).map_err(|e| e.to_string())
    };
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
        _ => Err("uso: vigil-rtd run|service|install|uninstall|status [opzioni]  (vedi l'intestazione di main.rs)".into()),
    };
    if let Err(e) = result {
        eprintln!("errore: {e}");
        std::process::exit(1);
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
