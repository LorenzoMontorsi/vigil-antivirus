# Usare VigilFlt su Windows 10/11 senza test-signing (Custom Kernel Signers)

Il driver `VigilFlt.sys` è firmato con un **certificato autofirmato** (`driver\sign-test.ps1`). Su Windows a
64 bit, di norma, un driver così si carica solo con il **test-signing** attivo (la scritta "Modalità test" sul
desktop). I **Custom Kernel Signers (CKS)** sono un'alternativa **ufficiale** di Windows: invece di accettare
*qualsiasi* driver di test, dici al sistema di fidarsi **solo** del tuo firmatario per il kernel — **senza**
test-signing e con **Secure Boot acceso**. Non è una patch e non tocca `ci.dll`.

Riferimento con i comandi esatti e gli strumenti di boot:
<https://github.com/HyperSine/Windows10-CustomKernelSigners> — **leggi le sue avvertenze prima di procedere.**

## ⚠️ Avvertenze

- CKS richiede di **ri-provisionare le chiavi di Secure Boot** (entrare in *Setup Mode* dell'UEFI e possedere
  la **Platform Key**) e di depositare una policy firmata nella partizione **EFI**. È un'operazione a livello di
  **firmware**: un errore può impedire l'avvio.
- Fallo **solo su una macchina di PROVA dedicata**. **Mai** su un portatile in dual-boot o **Boot Camp** che usi
  tutti i giorni: toccare le chiavi UEFI può compromettere anche l'avvio di macOS/dell'altro sistema.
- Serve **Windows 10 Enterprise o Education** (la funzione CKS si abilita lì; presente da 1703). Non è su Home/Pro.
- Il servizio di licenze (`sppsvc`) tende a **ridisattivare** CKS dopo ~10 minuti: per questo la procedura di
  riferimento installa un piccolo **driver di persistenza** che mantiene attiva l'impostazione.

Se tutto questo è troppo, su Windows 10/11 resta valido il **test-signing** (semplice, ma con filigrana) oppure —
per un prodotto distribuito a terzi — l'unica via "pulita" è un **certificato EV** con firma per attestazione di
Microsoft (a pagamento). CKS è pensato per chi fa girare un **proprio** driver sulle **proprie** macchine.

## "Una volta sola, per tutte le tue macchine"

Due cose si generano **una volta** (in questa VM Enterprise) e si riusano su **tutte le tue** macchine;
una terza va ripetuta su ogni PC fisico:

| Cosa | Dove vive | Riusabile su tutte? |
|---|---|---|
| Certificati **km** (firma driver) e **PK** (firma policy) — chiavi **private** | solo su questa macchina di build (`Cert:\CurrentUser\My`) | n/a — **non lasciano** mai la build |
| `SiPolicy.p7b` firmata + `VigilFlt.sys` firmato + certificati **pubblici** (`.cer`) | li copi sui bersagli | ✅ **sì**, lo stesso set ovunque |
| **Arruolamento della PK** nel firmware UEFI | NVRAM del singolo PC | ❌ **no** — a mano, una volta per ogni PC |

Sui bersagli non arriva **nessuna chiave privata**: solo il driver già firmato, la policy firmata e i
certificati pubblici. È il motivo per cui questa via è sicura per le *tue* macchine ma **non** per la
distribuzione a terzi (lì serve un **certificato EV** con firma per attestazione Microsoft).

## Parte lato Vigil — nella VM Enterprise, una volta

`ConvertFrom-CIPolicy` gira solo su **Enterprise/Education**: esegui questi passi nella VM Enterprise
(Win11 per bersagli Win11, va bene anche Win10 LTSC per bersagli Win10).

```powershell
cd driver
.\build.ps1                 # compila VigilFlt.sys
.\cks-policy.ps1            # crea i certificati, firma il driver, genera e FIRMA la policy
```

`cks-policy.ps1` crea/riusa due certificati autofirmati (`Vigil Kernel Signer`, `Vigil Platform Key`),
firma `VigilFlt.sys` col primo, e produce in `driver\build\cks\`:

| File | Cos'è |
|---|---|
| `SiPolicy.p7b` | la policy **compilata e firmata dalla PK** — da copiare in `EFI\Microsoft\Boot\SiPolicy.p7b` |
| `VigilCIPolicy.xml` | la policy in chiaro (regola *Signer = Vigil Kernel Signer*, scenario **131 = kernel**), per revisione |
| `VigilKernelSigner.cer` | certificato del **firmatario del driver** → da rendere **fidato** sul bersaglio (Root + TrustedPublisher) |
| `VigilPlatformKey.cer` | certificato della **Platform Key** → da **arruolare nell'UEFI** del bersaglio |

**Backup delle chiavi** (ti serve per firmare driver/policy futuri; NON committarlo — `build\` è in `.gitignore`):

```powershell
Export-PfxCertificate -Cert Cert:\CurrentUser\My\<THUMB_KM> -FilePath build\cks\VigilKernelSigner.pfx -Password (Read-Host -AsSecureString)
Export-PfxCertificate -Cert Cert:\CurrentUser\My\<THUMB_PK> -FilePath build\cks\VigilPlatformKey.pfx  -Password (Read-Host -AsSecureString)
```

## Parte lato sistema — su ogni bersaglio

Prerequisito **una volta per PC fisico**: entra nell'UEFI e **arruola `VigilPlatformKey.cer` come PK**
(firmware in *Setup/Custom Mode* → *Enroll/Add PK*; il menù varia per marca). Questo è il gesto manuale
che **non** si può saltare né fare da Windows.

Poi, da Windows (admin):

1. rendi **fidato** il firmatario del driver:
   `certutil -addstore Root build\cks\VigilKernelSigner.cer` e `certutil -addstore TrustedPublisher build\cks\VigilKernelSigner.cer`
   (il servizio Vigil ha già `--trust-cert <cer>` per farlo senza `certutil`);
2. copia la policy firmata: `copy build\cks\SiPolicy.p7b "%SystemDrive%\EFI\Microsoft\Boot\SiPolicy.p7b"`
   (monta la partizione EFI con `mountvol` se non è visibile);
3. **abilita i Custom Kernel Signers** per questo boot:
   - **Win11 (24H2):** usa **SSDE** (`ssde_enable.exe`) — <https://github.com/valinet/ssde>
   - **Win10:** usa **CKS-HyperSine** (`ckspdrv`) — <https://github.com/HyperSine/Windows10-CustomKernelSigners>
4. installa il **driver di persistenza** del tool (SSDE: `ssde.sys` boot-start) per non far ridisattivare
   CKS da `sppsvc` dopo ~10 minuti; **non riavviare** prima di questo passo o la policy va persa;
5. riavvia: ora `VigilFlt.sys` (firmato *Vigil Kernel Signer*) si carica **senza** test-signing e con
   Secure Boot acceso.

Verifica: `fltmc filters` elenca `VigilFlt`, e il servizio real-time parte con la dipendenza dal driver.
Lo stato della licenza CKS si legge in `HKLM\SYSTEM\ControlSet001\Control\CI\Protected\Licensed` (deve essere `1`).

> **Errore 577** all'avvio del servizio (segnalato con SSDE): è un conflitto con **HVCI/Memory Integrity**.
> Disattiva Memory Integrity (Sicurezza di Windows → Sicurezza dispositivo → Isolamento core) o la relativa
> chiave di registro, poi riavvia.

> Stato: la parte **lato Vigil** (certificati + policy firmata) è scriptata e verificabile nella VM. La parte
> **UEFI/CKS** (arruolamento PK + SSDE/HyperSine + persistenza) va collaudata nella VM Enterprise con la
> Platform Key in proprio possesso, prima di toccare qualsiasi macchina fisica.
