// Regola di prova innocua per i test nella VM: riconosce un marcatore di testo.
// Nessun file reale la contiene; gli script di test la aggiungono apposta.
rule Vigil_Test_Quarantena {
  meta:
    description = "File di prova innocuo per testare blocco e quarantena"
  strings:
    $a = "VIGIL-TEST-QUARANTENA-7f3a"
  condition:
    $a
}
