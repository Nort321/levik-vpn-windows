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
