# Banco di prova CKS su QEMU + OVMF

Qui si collauda, **in virtuale e senza rischi**, il flusso completo dei Custom Kernel Signers:
caricare `VigilFlt.sys` **autofirmato** con **Secure Boot acceso** e **senza test-signing**.

Perché OVMF e non VMware: il varstore UEFI di OVMF è un file che possiamo **riscrivere prima del
boot**, quindi depositiamo noi la **Platform Key di Vigil** nel firmware. Su VMware e su hardware
fisico questo non è possibile: lì la PK va arruolata **a mano** nel menù UEFI (una volta per PC).
Vedi `..\..\CKS.md` per la spiegazione e la procedura sul bersaglio reale.

## Prerequisiti (una volta)

- **QEMU per Windows** — <https://qemu.weilnetz.de>. **Installato: QEMU 11.1.0** in `C:\Program Files\qemu`
  (porta con sé OVMF: `edk2-x86_64-secure-code.fd` + `edk2-i386-vars.fd`, usati come coppia).
- **Python 3** nel PATH (presente: 3.14). Lo script crea un venv con `pycdlib` + `virt-firmware`.
  Nota: `virt-firmware` dichiara `crypt_r` (modulo Unix) su Python ≥3.13, che non compila su Windows e
  non serve al varstore: `ovmf-vm.ps1` lo installa **senza dipendenze** dopo aver messo le vere deps.
- **Accelerazione WHPX** (piattaforma "Windows Hypervisor Platform") consigliata; senza, usa
  `ovmf-vm.ps1 -Accel tcg` (molto più lento ma sempre disponibile).
- ISO di Windows **legittima**: la tua **LTSC 2019 Enterprise**, o una eval Enterprise ufficiale. **Mai ISO crackate.**
- Il set CKS già generato (nella VM Enterprise) da `..\..\cks-policy.ps1` → `..\..\build\cks\`
  (`VigilPlatformKey.cer`, `VigilKernelSigner.cer`, `SiPolicy.p7b`).

## Flusso

```powershell
# 1) Sull'host con QEMU: crea e avvia la VM (PK di Vigil pre-provisionata nel firmware).
cd driver\vm\ovmf
.\ovmf-vm.ps1 -WindowsIso C:\percorso\it_windows_10_enterprise_ltsc_2019_x64_dvd_2fa02691.iso
#   -> al prompt "Press any key to boot from CD" premi un tasto (unica interazione manuale).
#   -> l'installazione è automatica; la VM si riavvia e alza SSH su 127.0.0.1:2222.

# 2) Copia nella VM i file e SSDE, poi esegui lo script in-guest:
#    scp -P 2222 -i <VmDir>\ssh\id_ed25519 ..\..\build\cks\VigilFlt.sys ...\SiPolicy.p7b ...\VigilKernelSigner.cer vigil@127.0.0.1:C:/Vigil/
#    (più la cartella ssde\ scaricata da https://github.com/valinet/ssde)
#    ssh -p 2222 -i ... vigil@127.0.0.1 "powershell -ExecutionPolicy Bypass -File C:\Vigil\cks-vm-enroll.ps1"

# 3) Riavvia la VM e verifica: Confirm-SecureBootUEFI = True, fltmc filters elenca VigilFlt,
#    CI\Protected\Licensed = 1. Niente testsigning: se carica, CKS funziona.
```

## File

| File | Dove gira | Cosa fa |
|---|---|---|
| `ovmf-vm.ps1` | host (QEMU) | crea VARS con PK=Vigil + chiavi MS, disco, ISO unattend; avvia QEMU |
| `autounattend-uefi.xml` | setup Windows | installazione automatica **UEFI/GPT** (ESP+MSR+Windows) |
| `vigil-firstboot-uefi.ps1` | primo avvio VM | SSH + niente sospensione; **niente** testsigning (proviamo CKS) |
| `cks-vm-enroll.ps1` | in-guest | fida il cert, deposita `SiPolicy.p7b`, abilita CKS (SSDE), registra VigilFlt |

> **Stato:** la **catena host è validata** su questo PC — QEMU 11.1.0 installato; `ovmf-vm.ps1` crea il
> venv, installa `virt-firmware` (con l'aggiro di `crypt_r`) e **riscrive il varstore OVMF**: verificato
> PK=Vigil, KEK=Microsoft 2011/2023, db=Windows/UEFI MS + Vigil, Secure Boot ON; `qemu-img` crea il disco.
> Restano da collaudare in VM: l'**installazione di Windows** sotto OVMF (prompt "Press any key", controller
> AHCI, accel WHPX vs TCG) e la parte **in-guest** (`cks-vm-enroll.ps1`: SSDE + load del driver). Fallo
> **solo in VM**, mai sul Boot Camp d'uso quotidiano.
