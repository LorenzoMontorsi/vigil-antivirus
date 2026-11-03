# Eseguito NELLA VM come utente "vigil" (tramite as-user.ps1): porta Vigil in primo piano
# e fa clic alle coordinate indicate (pixel dello schermo della VM).
param([int]$X, [int]$Y)
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class VigilMouse {
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, UIntPtr e);
    public static void Click(int x, int y) {
        SetCursorPos(x, y);
        mouse_event(0x0002, 0, 0, 0, UIntPtr.Zero); // sinistro giù
        mouse_event(0x0004, 0, 0, 0, UIntPtr.Zero); // sinistro su
    }
}
'@
# Rilanciare Vigil riporta in primo piano la finestra esistente (istanza singola).
Start-Process 'C:\Program Files\Vigil\Vigil.exe'
Start-Sleep 2
[VigilMouse]::Click($X, $Y)
Start-Sleep 2
'clic eseguito'
