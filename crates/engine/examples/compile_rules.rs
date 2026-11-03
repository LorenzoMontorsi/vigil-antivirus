//! Diagnostica: compila un file di regole YARA e misura tempi e dimensioni.
//! Uso: cargo run --release -p vigil-engine --example compile_rules -- <file.yar>

use std::time::Instant;

fn main() {
    let path = std::env::args().nth(1).expect("percorso del file .yar");
    let src = std::fs::read_to_string(&path).expect("lettura");
    let t = Instant::now();
    let mut c = yara_x::Compiler::new();
    c.relaxed_re_syntax(true);
    for g in ["filename", "filepath", "extension", "filetype", "owner"] {
        c.define_global(g, "").unwrap();
    }
    match c.add_source(src.as_str()) {
        Ok(_) => {}
        Err(e) => {
            println!("ERRORE di compilazione:\n{e}");
            return;
        }
    }
    let warnings = c.warnings().len();
    let rules = c.build();
    println!("compilate {} regole in {:?} ({} warning)", rules.iter().count(), t.elapsed(), warnings);
    let t = Instant::now();
    let bytes = rules.serialize().unwrap();
    println!("serializzate: {} MB in {:?}", bytes.len() / 1_000_000, t.elapsed());
    let t = Instant::now();
    let r2 = yara_x::Rules::deserialize(&bytes).unwrap();
    println!("deserializzate in {:?}", t.elapsed());
    let mut s = yara_x::Scanner::new(&r2);
    let data = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let t = Instant::now();
    let n = s.scan(&data).unwrap().matching_rules().count();
    println!("scansione di {} KB: {} match in {:?}", data.len() / 1024, n, t.elapsed());
}
