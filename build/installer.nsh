; Levik's own Xray or sing-box left running after a crash keeps their files
; locked, so an update could not replace the core. Only processes next to
; this app's executable are ended; another VPN's xray.exe is left alone.
; Best effort: without administrator rights an elevated core cannot be ended,
; and the app itself stops it before it starts an update.
!macro stopLevikCores
  Push $0
  nsExec::Exec `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Where-Object { ($$_.Name -eq 'xray.exe' -or $$_.Name -eq 'sing-box.exe') -and $$_.ExecutablePath -and (Test-Path -LiteralPath (Join-Path (Split-Path (Split-Path (Split-Path $$_.ExecutablePath))) '${APP_EXECUTABLE_FILENAME}')) } | ForEach-Object { Stop-Process -Id $$_.ProcessId -Force -ErrorAction SilentlyContinue }"`
  Pop $0
  Pop $0
!macroend

!macro customInit
  !insertmacro stopLevikCores
!macroend

!macro customUnInit
  !insertmacro stopLevikCores
!macroend

!macro customInstall
  ${If} ${FileExists} "$INSTDIR\resources\kill-switch\levik-kill-switch.exe"
    ClearErrors
    ExecWait '"$INSTDIR\resources\kill-switch\levik-kill-switch.exe" disable' $R0
    ${If} ${Errors}
      Abort
    ${EndIf}
    ${If} $R0 != 0
      Abort
    ${EndIf}
  ${EndIf}
!macroend

!macro customUnInstall
  ${If} ${FileExists} "$INSTDIR\resources\kill-switch\levik-kill-switch.exe"
    ClearErrors
    ExecWait '"$INSTDIR\resources\kill-switch\levik-kill-switch.exe" disable' $R0
    ${If} ${Errors}
      Abort
    ${EndIf}
    ${If} $R0 != 0
      Abort
    ${EndIf}
  ${EndIf}
!macroend
