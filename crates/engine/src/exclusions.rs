use std::path::Path;

use serde::{Deserialize, Serialize};

/// Elementi da non scansionare.
///
/// - `paths`: cartelle o file. Una cartella esclude tutto il suo contenuto.
/// - `extensions`: estensioni (con o senza punto), confronto case-insensitive.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Exclusions {
    pub paths: Vec<String>,
    pub extensions: Vec<String>,
}

impl Exclusions {
    pub fn is_excluded(&self, path: &Path, is_dir: bool) -> bool {
        let p = normalize(&path.to_string_lossy());
        let path_hit = self.paths.iter().any(|ex| {
            let ex = normalize(ex);
            !ex.is_empty()
                && (p == ex || (p.starts_with(&ex) && p.as_bytes().get(ex.len()) == Some(&b'\\')))
        });
        if path_hit {
            return true;
        }
        if is_dir {
            return false;
        }
        match path.extension() {
            Some(ext) => {
                let ext = ext.to_string_lossy();
                self.extensions
                    .iter()
                    .any(|e| e.trim().trim_start_matches('.').eq_ignore_ascii_case(&ext))
            }
            None => false,
        }
    }
}

/// Windows: separatori uniformi, niente slash finale, case-insensitive.
fn normalize(s: &str) -> String {
    s.trim().replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_exclusion_matches_children_only() {
        let ex = Exclusions { paths: vec![r"C:\Dev\Build\".into()], extensions: vec![] };
        assert!(ex.is_excluded(Path::new(r"c:\dev\build"), true));
        assert!(ex.is_excluded(Path::new(r"C:\Dev\Build\out\a.exe"), false));
        assert!(!ex.is_excluded(Path::new(r"C:\Dev\BuildTools\a.exe"), false));
    }

    #[test]
    fn extension_exclusion() {
        let ex = Exclusions { paths: vec![], extensions: vec![".ISO".into(), "vhdx".into()] };
        assert!(ex.is_excluded(Path::new(r"D:\img\win.iso"), false));
        assert!(ex.is_excluded(Path::new(r"D:\vm\disk.VHDX"), false));
        assert!(!ex.is_excluded(Path::new(r"D:\folder.iso"), true));
        assert!(!ex.is_excluded(Path::new(r"D:\a.exe"), false));
    }
}
