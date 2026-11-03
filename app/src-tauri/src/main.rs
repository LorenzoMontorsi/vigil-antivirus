// Evita la finestra console aggiuntiva su Windows in release, NON RIMUOVERE!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    vigil_lib::run()
}
