//! Diagnostica: scansiona una cartella con firme da una directory e stampa i rilevamenti.
//! Uso: cargo run --release -p vigil-engine --example scan_dir -- <cartella-firme> <cartella-da-scansionare> [porta-clamd|-] [file-cache]

use std::{path::PathBuf, sync::atomic::AtomicBool, time::Instant};
use std::sync::Arc;
use vigil_engine::{EngineBuilder, ScanCache, ScanOptions, Verdict, clamd::ClamdClient};

fn main() {
    let mut args = std::env::args().skip(1);
    let sigs = PathBuf::from(args.next().expect("cartella firme"));
    let target = PathBuf::from(args.next().expect("cartella da scansionare"));
    let clamd = args.next().filter(|p| p != "-").map(|p| ClamdClient::new(([127, 0, 0, 1], p.parse().unwrap()).into()));
    let cache = args.next().map(|f| Arc::new(ScanCache::load(f.into(), "diagnostica".into())));

    let t = Instant::now();
    let mut b = EngineBuilder::new();
    b.load_signature_dir(&sigs);
    let engine = b.build();
    let info = engine.info();
    println!("motore: {} regole, {} hash, {} avvisi, {:?}", info.yara_rules, info.hash_signatures, info.warnings.len(), t.elapsed());

    let opts = ScanOptions { clamd, cache, ..Default::default() };
    let summary = engine.scan_paths(&[target], &opts, &AtomicBool::new(false), |r, _| match &r.verdict {
        Verdict::Infected { threat, source, location, .. } => {
            println!("INFETTO  [{source:?}] {threat}  {}{}", r.path.display(), location.as_ref().map(|l| format!(" › {l}")).unwrap_or_default())
        }
        Verdict::Suspicious { score, reasons } => println!("SOSPETTO [{score}] {}  {reasons:?}", r.path.display()),
        _ => {}
    });
    println!("{summary:?}");
}
