//! Client minimale per il demone `clamd` di ClamAV (protocollo TCP, comando INSTREAM).
//!
//! Ogni chiamata apre una connessione: clamd gestisce le richieste in parallelo
//! (`MaxThreads`), quindi più worker possono usarlo contemporaneamente.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

const CHUNK: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct ClamdClient {
    addr: SocketAddr,
    timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClamdVerdict {
    Clean,
    Found(String),
}

impl ClamdClient {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr, timeout: Duration::from_secs(120) }
    }

    fn connect(&self) -> std::io::Result<TcpStream> {
        let s = TcpStream::connect_timeout(&self.addr, Duration::from_secs(3))?;
        s.set_read_timeout(Some(self.timeout))?;
        s.set_write_timeout(Some(self.timeout))?;
        Ok(s)
    }

    fn command(&self, cmd: &str) -> std::io::Result<String> {
        let mut s = self.connect()?;
        s.write_all(format!("z{cmd}\0").as_bytes())?;
        read_reply(&mut s)
    }

    /// `true` se il demone risponde (database caricato).
    pub fn ping(&self) -> bool {
        self.command("PING").map(|r| r == "PONG").unwrap_or(false)
    }

    /// Es. "ClamAV 1.4.3/27800/Sun Nov  1 09:00:00 2026".
    pub fn version(&self) -> std::io::Result<String> {
        self.command("VERSION")
    }

    /// Ricarica le firme dal disco (dopo un aggiornamento).
    pub fn reload(&self) -> std::io::Result<String> {
        self.command("RELOAD")
    }

    /// Chiede al demone di terminare.
    pub fn shutdown(&self) -> std::io::Result<()> {
        let mut s = self.connect()?;
        s.write_all(b"zSHUTDOWN\0")
    }

    pub fn scan(&self, data: &[u8]) -> Result<ClamdVerdict, String> {
        let io = |e: std::io::Error| format!("ClamAV: {e}");
        let mut s = self.connect().map_err(io)?;
        s.write_all(b"zINSTREAM\0").map_err(io)?;
        for chunk in data.chunks(CHUNK) {
            s.write_all(&(chunk.len() as u32).to_be_bytes()).map_err(io)?;
            s.write_all(chunk).map_err(io)?;
        }
        s.write_all(&0u32.to_be_bytes()).map_err(io)?;
        let reply = read_reply(&mut s).map_err(io)?;
        parse_reply(&reply)
    }
}

fn read_reply(s: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    while matches!(buf.last(), Some(0 | b'\n')) {
        buf.pop();
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn parse_reply(reply: &str) -> Result<ClamdVerdict, String> {
    let body = reply.strip_prefix("stream: ").unwrap_or(reply);
    if body == "OK" {
        Ok(ClamdVerdict::Clean)
    } else if let Some(name) = body.strip_suffix(" FOUND") {
        Ok(ClamdVerdict::Found(name.to_owned()))
    } else {
        Err(format!("ClamAV: {body}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_replies() {
        assert_eq!(parse_reply("stream: OK"), Ok(ClamdVerdict::Clean));
        assert_eq!(
            parse_reply("stream: Win.Test.EICAR_HDB-1 FOUND"),
            Ok(ClamdVerdict::Found("Win.Test.EICAR_HDB-1".into()))
        );
        assert!(parse_reply("INSTREAM size limit exceeded. ERROR").is_err());
    }
}
