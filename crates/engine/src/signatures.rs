//! Regole integrate nel motore, sempre presenti anche senza firme esterne.

// La stringa EICAR è spezzata in due letterali così il file sorgente non
// contiene la sequenza intera (alcuni antivirus segnalerebbero il sorgente).
pub const BUILTIN_RULES: &str = concat!(
    r#"
rule EICAR_Test_File {
  meta:
    description = "File di test standard EICAR (innocuo)"
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"#,
    r#"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition:
    $eicar at 0
}
"#
);
