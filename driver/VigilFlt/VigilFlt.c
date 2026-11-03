/*
 * VigilFlt - minifilter di protezione in tempo reale di Vigil.
 *
 * - IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION (pre): quando un file sta per
 *   essere mappato come codice eseguibile chiede un verdetto al servizio e,
 *   se è "blocca", nega l'operazione (il processo/DLL non parte).
 * - IRP_MJ_CREATE (post) + IRP_MJ_WRITE (pre) + IRP_MJ_CLEANUP (pre):
 *   i file aperti in scrittura e modificati vengono notificati alla chiusura,
 *   indicando se esistevano già (riscrittura) o sono stati creati.
 * - IRP_MJ_SET_INFORMATION (pre): rinomine ed eliminazioni vengono notificate e
 *   il servizio può bloccarle (file esca dell'anti-ransomware, autodifesa).
 *
 * Principi:
 * - fail-open: se il servizio non è connesso o non risponde in tempo,
 *   l'operazione prosegue. Un problema di Vigil non deve bloccare il sistema.
 * - le operazioni del servizio stesso vengono ignorate (niente deadlock).
 * - la porta è accessibile solo ad Amministratori e SYSTEM.
 */
#include <fltKernel.h>
#include <ntstrsafe.h>
#include "vigil_shared.h"

#define VIGIL_TAG 'lgiV'
#define EXECUTE_TIMEOUT_MS 30000   /* scansione di un eseguibile prima del blocco */
#define CLOSE_TIMEOUT_MS   2000    /* notifica di chiusura: non deve rallentare chi scrive */
#define SETINFO_TIMEOUT_MS 2000    /* rinomina/eliminazione: il servizio risponde subito */

typedef struct _VIGIL_GLOBALS {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;          /* una sola connessione: il servizio */
    HANDLE ServiceProcessId;
} VIGIL_GLOBALS;

static VIGIL_GLOBALS Globals;

typedef struct _VIGIL_HANDLE_CONTEXT {
    BOOLEAN Modified;
    BOOLEAN Existed;   /* il file c'era già all'apertura (non creato da questo handle) */
} VIGIL_HANDLE_CONTEXT, *PVIGIL_HANDLE_CONTEXT;

DRIVER_INITIALIZE DriverEntry;
static NTSTATUS FLTAPI VigilUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
static NTSTATUS FLTAPI VigilInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                                          _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
static FLT_PREOP_CALLBACK_STATUS FLTAPI PreSectionSync(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                       _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
static FLT_POSTOP_CALLBACK_STATUS FLTAPI PostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                    _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);
static FLT_PREOP_CALLBACK_STATUS FLTAPI PreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                 _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
static FLT_PREOP_CALLBACK_STATUS FLTAPI PreCleanup(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                   _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
static FLT_PREOP_CALLBACK_STATUS FLTAPI PreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                          _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, PreSectionSync, NULL },
    { IRP_MJ_CREATE, 0, NULL, PostCreate },
    { IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreWrite, NULL },
    { IRP_MJ_CLEANUP, 0, PreCleanup, NULL },
    { IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreSetInformation, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_CONTEXT_REGISTRATION Contexts[] = {
    { FLT_STREAMHANDLE_CONTEXT, 0, NULL, sizeof(VIGIL_HANDLE_CONTEXT), VIGIL_TAG },
    { FLT_CONTEXT_END }
};

static const FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    Contexts,
    Callbacks,
    VigilUnload,
    VigilInstanceSetup,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/* ── Porta di comunicazione ─────────────────────────────────────────────── */

static NTSTATUS FLTAPI PortConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
                                   _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                                   _In_ ULONG SizeOfContext, _Outptr_result_maybenull_ PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    *ConnectionPortCookie = NULL;
    Globals.ServiceProcessId = PsGetCurrentProcessId();
    Globals.ClientPort = ClientPort;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "VigilFlt: servizio connesso (pid %p)\n", Globals.ServiceProcessId);
    return STATUS_SUCCESS;
}

static VOID FLTAPI PortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(Globals.Filter, &Globals.ClientPort);
    Globals.ServiceProcessId = NULL;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "VigilFlt: servizio disconnesso\n");
}

/* ── Utilità ────────────────────────────────────────────────────────────── */

/* Operazioni da non esaminare: kernel, servizio stesso, nessun servizio connesso.
   CheckMode = FALSE per IRP_MJ_CLEANUP: lo genera il gestore I/O in modalità kernel
   anche quando a chiudere il file è un programma utente. */
static BOOLEAN ShouldSkip(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ BOOLEAN CheckMode)
{
    if (Globals.ClientPort == NULL) return TRUE;
    if (CheckMode && Data->RequestorMode == KernelMode) return TRUE;
    if ((HANDLE)(ULONG_PTR)FltGetRequestorProcessId(Data) == Globals.ServiceProcessId) return TRUE;
    if (FltObjects->FileObject == NULL) return TRUE;
    return FALSE;
}

/* Invia una richiesta al servizio. Restituisce il verdetto; Allow in caso di errori o timeout. */
static VIGIL_VERDICT AskService(_In_ PFLT_CALLBACK_DATA Data, _In_ VIGIL_REQUEST_KIND Kind, _In_ ULONG Flags, _In_ ULONG TimeoutMs)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    VIGIL_REQUEST* req = NULL;
    VIGIL_REPLY reply = { VigilVerdictAllow };
    ULONG replyLen = sizeof(reply);
    LARGE_INTEGER timeout;
    NTSTATUS status;

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) return VigilVerdictAllow;

    req = (VIGIL_REQUEST*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(VIGIL_REQUEST), VIGIL_TAG);
    if (req == NULL) goto done;

    req->Kind = (ULONG)Kind;
    req->ProcessId = FltGetRequestorProcessId(Data);
    req->Flags = Flags;
    req->PathLength = min((ULONG)nameInfo->Name.Length, (ULONG)(sizeof(req->Path) - sizeof(WCHAR)));
    RtlCopyMemory(req->Path, nameInfo->Name.Buffer, req->PathLength);
    req->Path[req->PathLength / sizeof(WCHAR)] = L'\0';

    timeout.QuadPart = -10000LL * TimeoutMs; /* relativo, unità di 100 ns */
    status = FltSendMessage(Globals.Filter, &Globals.ClientPort, req, sizeof(VIGIL_REQUEST),
                            &reply, &replyLen, &timeout);
    if (status != STATUS_SUCCESS) {
        /* STATUS_TIMEOUT o porta chiusa: fail-open */
        reply.Verdict = VigilVerdictAllow;
    }

done:
    if (req) ExFreePoolWithTag(req, VIGIL_TAG);
    FltReleaseFileNameInformation(nameInfo);
    return (VIGIL_VERDICT)reply.Verdict;
}

/* ── Callback ───────────────────────────────────────────────────────────── */

static FLT_PREOP_CALLBACK_STATUS FLTAPI PreSectionSync(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                       _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    ULONG prot;
    *CompletionContext = NULL;

    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    prot = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    if (prot != PAGE_EXECUTE && prot != PAGE_EXECUTE_READ && prot != PAGE_EXECUTE_READWRITE && prot != PAGE_EXECUTE_WRITECOPY)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (ShouldSkip(Data, FltObjects, TRUE))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Il pre-callback arriva prima che il file system acquisisca i lock:
       il servizio può leggere il file senza rischio di deadlock. */
    if (AskService(Data, VigilRequestExecute, 0, EXECUTE_TIMEOUT_MS) == VigilVerdictBlock) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "VigilFlt: esecuzione bloccata\n");
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS FLTAPI PostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                    _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PVIGIL_HANDLE_CONTEXT ctx = NULL;
    ACCESS_MASK access;
    BOOLEAN isDir = FALSE;
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) || !NT_SUCCESS(Data->IoStatus.Status) ||
        Data->IoStatus.Status == STATUS_REPARSE || ShouldSkip(Data, FltObjects, TRUE))
        return FLT_POSTOP_FINISHED_PROCESSING;

    access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (!FlagOn(access, FILE_WRITE_DATA | FILE_APPEND_DATA))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (NT_SUCCESS(FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDir)) && isDir)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (NT_SUCCESS(FltAllocateContext(Globals.Filter, FLT_STREAMHANDLE_CONTEXT, sizeof(VIGIL_HANDLE_CONTEXT),
                                      NonPagedPoolNx, (PFLT_CONTEXT*)&ctx))) {
        ctx->Modified = FALSE;
        /* FILE_CREATED = nuovo; FILE_OPENED/OVERWRITTEN/SUPERSEDED = c'era già. */
        ctx->Existed = Data->IoStatus.Information != FILE_CREATED;
        (VOID)FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
                                        FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, NULL);
        FltReleaseContext(ctx);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI PreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                 _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PVIGIL_HANDLE_CONTEXT ctx = NULL;
    UNREFERENCED_PARAMETER(Data);
    *CompletionContext = NULL;
    if (NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&ctx))) {
        ctx->Modified = TRUE;
        FltReleaseContext(ctx);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI PreCleanup(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                   _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PVIGIL_HANDLE_CONTEXT ctx = NULL;
    BOOLEAN modified = FALSE;
    ULONG flags = 0;
    *CompletionContext = NULL;

    if (NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&ctx))) {
        modified = ctx->Modified;
        if (ctx->Existed) flags |= VIGIL_FLAG_EXISTED;
        FltReleaseContext(ctx);
    }
    /* Il contesto esiste solo per handle aperti in scrittura da un programma utente. */
    if (modified && !ShouldSkip(Data, FltObjects, FALSE)) {
        (VOID)AskService(Data, VigilRequestModifiedClose, flags, CLOSE_TIMEOUT_MS);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI PreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                          _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    PVOID buf = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    VIGIL_REQUEST_KIND kind;
    *CompletionContext = NULL;

    switch (cls) {
    case FileRenameInformation:
    case FileRenameInformationEx:
        kind = VigilRequestRename;
        break;
    case FileDispositionInformation:
        if (buf == NULL || !((PFILE_DISPOSITION_INFORMATION)buf)->DeleteFile) return FLT_PREOP_SUCCESS_NO_CALLBACK;
        kind = VigilRequestDelete;
        break;
    case FileDispositionInformationEx:
        if (buf == NULL || !FlagOn(((PFILE_DISPOSITION_INFORMATION_EX)buf)->Flags, FILE_DISPOSITION_DELETE))
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        kind = VigilRequestDelete;
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (ShouldSkip(Data, FltObjects, TRUE))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (AskService(Data, kind, 0, SETINFO_TIMEOUT_MS) == VigilVerdictBlock) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ── Ciclo di vita ──────────────────────────────────────────────────────── */

static NTSTATUS FLTAPI VigilInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                                          _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    /* Solo volumi disco con file system "veri"; niente rete né pipe per ora. */
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) return STATUS_FLT_DO_NOT_ATTACH;
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS && VolumeFilesystemType != FLT_FSTYPE_REFS &&
        VolumeFilesystemType != FLT_FSTYPE_FAT && VolumeFilesystemType != FLT_FSTYPE_EXFAT)
        return STATUS_FLT_DO_NOT_ATTACH;
    return STATUS_SUCCESS;
}

static NTSTATUS FLTAPI VigilUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (Globals.ServerPort) FltCloseCommunicationPort(Globals.ServerPort);
    FltUnregisterFilter(Globals.Filter);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName = RTL_CONSTANT_STRING(VIGIL_PORT_NAME);
    UNREFERENCED_PARAMETER(RegistryPath);

    /* Pool non eseguibile di default per le allocazioni legacy. */
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    RtlZeroMemory(&Globals, sizeof(Globals));

    status = FltRegisterFilter(DriverObject, &Registration, &Globals.Filter);
    if (!NT_SUCCESS(status)) return status;

    /* Accesso alla porta: solo Amministratori e SYSTEM. */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
        status = FltCreateCommunicationPort(Globals.Filter, &Globals.ServerPort, &oa, NULL,
                                            PortConnect, PortDisconnect, NULL, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(Globals.Filter);
    }
    if (!NT_SUCCESS(status)) {
        if (Globals.ServerPort) FltCloseCommunicationPort(Globals.ServerPort);
        FltUnregisterFilter(Globals.Filter);
    }
    return status;
}
