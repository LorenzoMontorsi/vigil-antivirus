use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use vigil_engine::Exclusions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RulesPackage {
    /// YARA-Forge "core": alta precisione, pochi falsi positivi.
    Core,
    /// YARA-Forge "extended": più copertura, qualche falso positivo in più.
    Extended,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub exclusions: Exclusions,
    pub max_file_size_mb: u64,
    pub heuristics: bool,
    pub scan_archives: bool,
    /// Gli eseguibili con firma Microsoft valida saltano ClamAV ed euristica.
    pub trust_microsoft: bool,
    /// Non rianalizza i file già trovati puliti e non modificati.
    pub use_cache: bool,
    /// Mette subito in quarantena le minacce certe (mai i sospetti).
    pub auto_quarantine: bool,
    pub rules_package: RulesPackage,
    /// Auth-Key gratuita da https://auth.abuse.ch/ (vuota = MalwareBazaar disattivato).
    pub malwarebazaar_key: String,
    pub auto_update: bool,
    /// Ogni quante ore cercare aggiornamenti (firme e motore) mentre Vigil è aperto.
    pub update_interval_hours: u64,
    /// Aggiorna da solo anche il motore ClamAV (solo pacchetti con firma GPG di Cisco Talos).
    pub auto_engine_update: bool,
    /// Usa il motore ClamAV incluso in Vigil.
    pub clamav_enabled: bool,
    /// Avvia Vigil (nascosto nell'area di notifica) all'accesso a Windows.
    pub start_at_login: bool,
    /// Voce "Analizza con Vigil" nel menu del tasto destro di Esplora risorse.
    pub context_menu: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            exclusions: Exclusions::default(),
            max_file_size_mb: 64,
            heuristics: true,
            scan_archives: true,
            trust_microsoft: true,
            use_cache: true,
            auto_quarantine: true,
            rules_package: RulesPackage::Core,
            malwarebazaar_key: String::new(),
            auto_update: true,
            update_interval_hours: 4,
            auto_engine_update: true,
            clamav_enabled: true,
            start_at_login: true,
            context_menu: true,
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::util::write_atomic(path, json.as_bytes()).map_err(|e| format!("Impossibile salvare le impostazioni: {e}"))
    }
}
