# Eseguito NELLA VM: fotografa lo schermo dell'utente "vigil" in C:\Vigil\screen.png.
# La cattura deve avvenire nella sessione interattiva, quindi passa da un'attività pianificata.
param([switch]$Inner)
$out = 'C:\Vigil\screen.png'
if ($Inner) {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $b = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size)
    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    return
}
Remove-Item $out -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Inner"
$principal = New-ScheduledTaskPrincipal -UserId 'vigil' -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName VigilShot -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName VigilShot
for ($i = 0; $i -lt 20 -and -not (Test-Path $out); $i++) { Start-Sleep -Milliseconds 500 }
if (Test-Path $out) { 'screenshot: ok' } else { 'screenshot: non riuscito' }
