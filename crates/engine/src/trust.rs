//! Verifica delle firme Authenticode tramite le API di Windows.
//!
//! Gestisce sia la firma incorporata nel file sia la firma tramite catalogo
//! (`.cat`), che è il caso della maggior parte dei file di sistema di Windows.
//! Il controllo di revoca usa solo la cache locale: nessuna richiesta di rete.

use std::path::Path;

/// Nome del firmatario se il file ha una firma valida che risale a una CA fidata.
#[cfg(windows)]
pub fn signer(path: &Path) -> Option<String> {
    imp::signer(path)
}

#[cfg(not(windows))]
pub fn signer(_path: &Path) -> Option<String> {
    None
}

/// Firmatari considerati affidabili per saltare i controlli più costosi.
pub fn is_microsoft(signer: &str) -> bool {
    signer.starts_with("Microsoft ")
}

#[cfg(windows)]
mod imp {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, path::Path, ptr};

    use windows_sys::{
        Win32::{
            Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE},
            Security::{
                Cryptography::{
                    CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
                    Catalog::{
                        CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
                        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
                        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
                    },
                },
                WinTrust::{
                    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_FILE_INFO,
                    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
                    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
                    WTHelperProvDataFromStateData, WinVerifyTrust,
                },
            },
            Storage::FileSystem::{CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
        },
        core::GUID,
    };

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    pub fn signer(path: &Path) -> Option<String> {
        let wpath = wide(path.as_os_str());
        // Prima la firma incorporata, poi i cataloghi di sistema.
        verify_embedded(&wpath).or_else(|| verify_catalog(&wpath))
    }

    fn verify_embedded(wpath: &[u16]) -> Option<String> {
        let mut file_info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
        file_info.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = wpath.as_ptr();

        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut file_info;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        run_verify(&mut data)
    }

    fn verify_catalog(wpath: &[u16]) -> Option<String> {
        unsafe {
            let file: HANDLE = CreateFileW(
                wpath.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            );
            if file == INVALID_HANDLE_VALUE {
                return None;
            }
            let mut result = None;
            // I cataloghi moderni usano SHA256, quelli più vecchi SHA1.
            for alg in ["SHA256", "SHA1"] {
                result = verify_catalog_with(file, wpath, alg);
                if result.is_some() {
                    break;
                }
            }
            CloseHandle(file);
            result
        }
    }

    unsafe fn verify_catalog_with(file: HANDLE, wpath: &[u16], alg: &str) -> Option<String> {
        unsafe {
            let walg: Vec<u16> = alg.encode_utf16().chain(Some(0)).collect();
            let mut admin = Default::default();
            if CryptCATAdminAcquireContext2(&mut admin, ptr::null(), walg.as_ptr(), ptr::null(), 0) == 0 {
                return None;
            }
            let mut hash = [0u8; 64];
            let mut hash_len = hash.len() as u32;
            let mut out = None;
            if CryptCATAdminCalcHashFromFileHandle2(admin, file, &mut hash_len, hash.as_mut_ptr(), 0) != 0 {
                let cat = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), hash_len, 0, ptr::null_mut());
                if cat != 0 {
                    let mut info: CATALOG_INFO = std::mem::zeroed();
                    info.cbStruct = size_of::<CATALOG_INFO>() as u32;
                    if CryptCATCatalogInfoFromContext(cat, &mut info, 0) != 0 {
                        let tag: Vec<u16> = hash[..hash_len as usize]
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect::<String>()
                            .encode_utf16()
                            .chain(Some(0))
                            .collect();
                        let mut cat_info: WINTRUST_CATALOG_INFO = std::mem::zeroed();
                        cat_info.cbStruct = size_of::<WINTRUST_CATALOG_INFO>() as u32;
                        cat_info.pcwszCatalogFilePath = info.wszCatalogFile.as_ptr();
                        cat_info.pcwszMemberTag = tag.as_ptr();
                        cat_info.pcwszMemberFilePath = wpath.as_ptr();
                        cat_info.hMemberFile = file;
                        cat_info.pbCalculatedFileHash = hash.as_mut_ptr();
                        cat_info.cbCalculatedFileHash = hash_len;
                        cat_info.hCatAdmin = admin;

                        let mut data: WINTRUST_DATA = std::mem::zeroed();
                        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
                        data.dwUIChoice = WTD_UI_NONE;
                        data.fdwRevocationChecks = WTD_REVOKE_NONE;
                        data.dwUnionChoice = WTD_CHOICE_CATALOG;
                        data.Anonymous.pCatalog = &mut cat_info;
                        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
                        out = run_verify(&mut data);
                    }
                    CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                }
            }
            CryptCATAdminReleaseContext(admin, 0);
            out
        }
    }

    /// Esegue la verifica, legge il nome del firmatario e chiude lo stato.
    fn run_verify(data: &mut WINTRUST_DATA) -> Option<String> {
        let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        unsafe {
            let status = WinVerifyTrust(ptr::null_mut(), &mut action, data as *mut _ as *mut c_void);
            let name = if status == 0 { signer_name(data.hWVTStateData) } else { None };
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(ptr::null_mut(), &mut action, data as *mut _ as *mut c_void);
            if status == 0 { Some(name.unwrap_or_default()) } else { None }
        }
    }

    unsafe fn signer_name(state: HANDLE) -> Option<String> {
        unsafe {
            let prov = WTHelperProvDataFromStateData(state);
            if prov.is_null() {
                return None;
            }
            let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
            if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
                return None;
            }
            let cert = (*(*sgnr).pasCertChain).pCert;
            if cert.is_null() {
                return None;
            }
            let mut buf = [0u16; 256];
            let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, ptr::null(), buf.as_mut_ptr(), buf.len() as u32);
            (n > 1).then(|| String::from_utf16_lossy(&buf[..n as usize - 1]))
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn notepad_is_microsoft_signed() {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
        let s = signer(&Path::new(&windir).join(r"System32\notepad.exe"));
        assert!(s.as_deref().is_some_and(is_microsoft), "firmatario: {s:?}");
    }

    #[test]
    fn catalog_signed_dll_is_microsoft() {
        // kernel32.dll è firmato tramite catalogo, non con firma incorporata.
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
        let s = signer(&Path::new(&windir).join(r"System32\kernel32.dll"));
        assert!(s.as_deref().is_some_and(is_microsoft), "firmatario: {s:?}");
    }

    #[test]
    fn unsigned_file_has_no_signer() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.exe");
        std::fs::write(&p, b"MZ non firmato").unwrap();
        assert_eq!(signer(&p), None);
    }
}
