// Regola di prova innocua per i test nella VM: riconosce il marcatore di testo
// "VIGIL-TEST-QUARANTENA-7f3a", scritto qui in esadecimale perché il file della regola
// non contenga la sequenza in chiaro (altrimenti verrebbe rilevato lui stesso).
// La variante "wide" copre il testo UTF-16 che PowerShell passa ad AMSI.
rule Vigil_Test_Quarantena {
  meta:
    description = "File di prova innocuo per testare blocco e quarantena"
  strings:
    $a = { 56 49 47 49 4C 2D 54 45 53 54 2D 51 55 41 52 41 4E 54 45 4E 41 2D 37 66 33 61 }
    $w = { 56 00 49 00 47 00 49 00 4C 00 2D 00 54 00 45 00 53 00 54 00 2D 00 51 00 55 00 41 00 52 00 41 00 4E 00 54 00 45 00 4E 00 41 00 2D 00 37 00 66 00 33 00 61 00 }
  condition:
    any of them
}
