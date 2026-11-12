; Hook NSIS dell'installer di Vigil (bundle.windows.nsis.installerHooks).
; Il servizio VigilRtd gira come LocalSystem: l'eseguibile va in "Program Files" (scrivibile solo
; dagli amministratori), non in $INSTDIR, che con l'installazione per utente e' scrivibile dall'utente.
; Il servizio dipende dal driver VigilFlt: se il driver non e' registrato non si installa nulla
; (resta la scansione su richiesta). Ogni passo da amministratore chiede l'UAC.

!macro VIGIL_RTD_INSTALL
  ReadRegStr $R0 HKLM "SYSTEM\CurrentControlSet\Services\VigilFlt" "ImagePath"
  ${If} $R0 != ""
  ${AndIf} ${FileExists} "$INSTDIR\rt\vigil-rtd.exe"
    ReadEnvStr $R1 "ProgramData"
    ExecShellWait "runas" "$SYSDIR\cmd.exe" '/c sc stop VigilRtd >nul 2>&1 & ping -n 3 127.0.0.1 >nul & mkdir "$PROGRAMFILES64\Vigil" 2>nul & copy /y "$INSTDIR\rt\vigil-rtd.exe" "$PROGRAMFILES64\Vigil\vigil-rtd.exe" && "$PROGRAMFILES64\Vigil\vigil-rtd.exe" install --sigs "$APPDATA\dev.lorenzo.antivirus\feeds" --sigs "$APPDATA\dev.lorenzo.antivirus\signatures" --quarantine "$R1\Vigil\quarantine" --auto-quarantine' SW_HIDE
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro VIGIL_RTD_INSTALL
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ReadRegStr $R0 HKLM "SYSTEM\CurrentControlSet\Services\VigilRtd" "ImagePath"
  ${If} $R0 != ""
  ${AndIf} ${FileExists} "$PROGRAMFILES64\Vigil\vigil-rtd.exe"
    ExecShellWait "runas" "$PROGRAMFILES64\Vigil\vigil-rtd.exe" "uninstall" SW_HIDE
  ${EndIf}
!macroend
