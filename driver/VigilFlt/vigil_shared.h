/*
 * Strutture condivise tra il driver VigilFlt e il servizio in user mode.
 * Qualsiasi modifica va replicata nel lato Rust (crates/kclient).
 */
#pragma once

#define VIGIL_PORT_NAME L"\\VigilPort"
#define VIGIL_MAX_PATH_CHARS 1024

typedef enum _VIGIL_REQUEST_KIND {
    /* Un'immagine (exe/dll) sta per essere mappata come codice: il servizio decide se bloccarla. */
    VigilRequestExecute = 1,
    /* Un file aperto in scrittura e modificato è stato chiuso: solo notifica. */
    VigilRequestModifiedClose = 2,
} VIGIL_REQUEST_KIND;

typedef enum _VIGIL_VERDICT {
    VigilVerdictAllow = 0,
    VigilVerdictBlock = 1,
} VIGIL_VERDICT;

typedef struct _VIGIL_REQUEST {
    unsigned long Kind;          /* VIGIL_REQUEST_KIND */
    unsigned long ProcessId;     /* processo che ha causato l'operazione */
    unsigned long PathLength;    /* in byte, senza terminatore */
    wchar_t Path[VIGIL_MAX_PATH_CHARS]; /* percorso NT normalizzato (\Device\HarddiskVolumeN\...) */
} VIGIL_REQUEST;

typedef struct _VIGIL_REPLY {
    unsigned long Verdict;       /* VIGIL_VERDICT */
} VIGIL_REPLY;
