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

## Parte lato Vigil (questa la prepari e la verifichi qui)

```powershell
cd driver
.\build.ps1                 # compila VigilFlt.sys
.\sign-test.ps1            # lo firma col certificato "Vigil Test Signing"
.\cks-policy.ps1          # genera la policy di Code Integrity che autorizza quel firmatario nel kernel
```

Esce in `driver\build\cks\`:

| File | Cos'è |
|---|---|
| `VigilCIPolicy.xml` | la policy in chiaro, per revisionarla (regola *Signer = Vigil Test Signing*, scenario **131 = kernel**) |
| `VigilCIPolicy.cip` | la policy **compilata**, da firmare e installare con la procedura CKS |
| `VigilKernelSigner.cer` | il certificato pubblico del firmatario, da rendere fidato sul bersaglio |

## Parte lato sistema (macchina di prova, seguendo HyperSine)

In sintesi (i comandi esatti sono nel repo di riferimento):

1. genera/possiedi le chiavi di Secure Boot (PK/KEK/db) sulla macchina di prova;
2. **firma** `VigilCIPolicy.cip` con una chiave inclusa nel tuo `db`;
3. deposita la policy firmata nella partizione **EFI** dove CKS la cerca;
4. abilita i **Custom Kernel Signers** (riavvio in *Setup Mode* dell'UEFI);
5. installa il **driver di persistenza** per non far ridisattivare CKS da `sppsvc`;
6. riavvia: ora `VigilFlt.sys` (firmato "Vigil Test Signing") si carica **senza** test-signing.

Verifica finale: `fltmc filters` elenca `VigilFlt`, e il servizio `VigilRtd` parte con la dipendenza dal driver.

> Stato: la parte **lato Vigil** (policy + certificato) è generata e verificata. La parte **UEFI/CKS** va
> collaudata su un Windows 10 Enterprise/Education di prova con la Platform Key in proprio possesso.
