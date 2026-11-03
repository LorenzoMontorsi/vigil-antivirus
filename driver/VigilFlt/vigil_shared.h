/*
 * Strutture condivise tra il driver VigilFlt e il servizio in user mode.
 * Qualsiasi modifica va replicata nel lato Rust (crates/rtd/src/driver.rs).
 */
#pragma once

#define VIGIL_PORT_NAME L"\\VigilPort"
#define VIGIL_MAX_PATH_CHARS 1024

typedef enum _VIGIL_REQUEST_KIND {
    /* Un'immagine (exe/dll) sta per essere mappata come codice: il servizio decide se bloccarla. */
    VigilRequestExecute = 1,
    /* Un file aperto in scrittura e modificato è stato chiuso: solo notifica. */
    VigilRequestModifiedClose = 2,
    /* Un file sta per essere rinominato (Path = nome attuale): il servizio può bloccarlo. */
    VigilRequestRename = 3,
    /* Un file sta per essere eliminato: il servizio può bloccarlo. */
    VigilRequestDelete = 4,
} VIGIL_REQUEST_KIND;

/* Flags di VIGIL_REQUEST */
#define VIGIL_FLAG_EXISTED 0x1  /* ModifiedClose: il file esisteva già (riscritto, non creato) */

typedef enum _VIGIL_VERDICT {
    VigilVerdictAllow = 0,
    VigilVerdictBlock = 1,
} VIGIL_VERDICT;

typedef struct _VIGIL_REQUEST {
    unsigned long Kind;          /* VIGIL_REQUEST_KIND */
    unsigned long ProcessId;     /* processo che ha causato l'operazione */
    unsigned long Flags;         /* VIGIL_FLAG_* */
    unsigned long PathLength;    /* in byte, senza terminatore */
    wchar_t Path[VIGIL_MAX_PATH_CHARS]; /* percorso NT normalizzato (\Device\HarddiskVolumeN\...) */
} VIGIL_REQUEST;

typedef struct _VIGIL_REPLY {
    unsigned long Verdict;       /* VIGIL_VERDICT */
} VIGIL_REPLY;

/* Messaggio servizio -> driver (FilterSendMessage): cartelle da proteggere
   (autodifesa). Percorsi NT con barra finale, es. \Device\HarddiskVolume3\Program Files\Vigil\ */
#define VIGIL_MAX_PROTECTED 4
#define VIGIL_PROTECTED_CHARS 300

typedef struct _VIGIL_CONFIG {
    unsigned long Count;
    wchar_t Paths[VIGIL_MAX_PROTECTED][VIGIL_PROTECTED_CHARS]; /* terminati da zero */
} VIGIL_CONFIG;
