//! Diagnostica: verifica il collegamento a clamd e scansiona un file.
//! Uso: cargo run -p vigil-engine --example clamd_check -- <porta> [file]

use std::time::{Duration, Instant};
use vigil_engine::clamd::ClamdClient;

fn main() {
    let mut args = std::env::args().skip(1);
    let port: u16 = args.next().expect("porta").parse().unwrap();
    let client = ClamdClient::new(([127, 0, 0, 1], port).into());
    let t = Instant::now();
    while !client.ping() {
        if t.elapsed() > Duration::from_secs(180) {
            panic!("clamd non risponde");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("pronto dopo {:?}: {}", t.elapsed(), client.version().unwrap());
    let eicar = concat!("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR", "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    println!("EICAR in memoria: {:?}", client.scan(eicar.as_bytes()));
    if let Some(f) = args.next() {
        let data = std::fs::read(&f).unwrap();
        let t = Instant::now();
        println!("{f}: {:?} in {:?}", client.scan(&data), t.elapsed());
    }
}
