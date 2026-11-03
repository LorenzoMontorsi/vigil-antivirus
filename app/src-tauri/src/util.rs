use std::{fs, io, path::Path};

/// Scrive su un file temporaneo e poi rinomina: niente file a metà se l'app si chiude.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp-vigil");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(windows)]
pub fn hide_window(cmd: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
pub fn hide_window(_cmd: &mut std::process::Command) {}
