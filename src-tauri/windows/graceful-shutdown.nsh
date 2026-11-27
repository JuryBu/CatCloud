!include LogicLib.nsh

!macro CatCloudGracefulShutdownRunning MODE
  !ifdef CATCLOUD_GS_SEQ
    !define /math _CATCLOUD_GS_NEXT ${CATCLOUD_GS_SEQ} + 1
    !undef CATCLOUD_GS_SEQ
    !define CATCLOUD_GS_SEQ ${_CATCLOUD_GS_NEXT}
    !undef _CATCLOUD_GS_NEXT
  !else
    !define CATCLOUD_GS_SEQ 1
  !endif
  !define CATCLOUD_GS_UID "${CATCLOUD_GS_SEQ}_${__LINE__}"

  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5

  ; Step 1: Cross-IL graceful exit signal (EVENT_MODIFY_STATE = 0x0002) for standard installed
  ; CatCloud instances (both Medium IL and UAC-elevated High IL). Never touches portable or
  ; isolated sandbox instances.
  System::Call 'kernel32::OpenEventW(i 0x0002, i 0, w "Local\CatCloud_GracefulExit_Installed_v1") p.r0'
  ${If} $0 != 0
  ${AndIf} $0 != ""
    System::Call 'kernel32::SetEvent(p r0)'
    System::Call 'kernel32::CloseHandle(p r0)'
  ${EndIf}

  ; Step 2: Poll strictly by exclusive file-open lock on `$INSTDIR\${MAINBINARYNAME}.exe`
  ; (up to 30 * 200ms = 6000ms). Never scan processes by image name or window title.
  IfFileExists "$INSTDIR\${MAINBINARYNAME}.exe" 0 catcloud_gs_done_${CATCLOUD_GS_UID}

  StrCpy $2 0
  StrCpy $4 "0"
  catcloud_gs_wait_${CATCLOUD_GS_UID}:
  IfFileExists "$INSTDIR\${MAINBINARYNAME}.exe" 0 catcloud_gs_done_${CATCLOUD_GS_UID}
  ; GENERIC_READ|GENERIC_WRITE=0xC0000000, dwShareMode=0 (exclusive), OPEN_EXISTING=3, FILE_ATTRIBUTE_NORMAL=0x80
  System::Call 'kernel32::CreateFileW(w "$INSTDIR\${MAINBINARYNAME}.exe", i 0xC0000000, i 0, p 0, i 3, i 0x80, p 0) p.r1 ?e'
  Pop $3
  ${If} $1 != -1
  ${AndIf} $1 != 0
  ${AndIf} $1 != ""
    System::Call 'kernel32::CloseHandle(p r1)'
    Goto catcloud_gs_done_${CATCLOUD_GS_UID}
  ${EndIf}
  ; ERROR_FILE_NOT_FOUND (2) / ERROR_PATH_NOT_FOUND (3): target binary already gone -> proceed.
  ${If} $3 == 2
  ${OrIf} $3 == 3
    Goto catcloud_gs_done_${CATCLOUD_GS_UID}
  ${EndIf}
  ; Not ERROR_SHARING_VIOLATION (32) (e.g. read-only attribute causing ERROR_ACCESS_DENIED (5)):
  ; clear read-only attribute once and immediately retry exclusive open to avoid false positives.
  ${If} $3 != 32
  ${AndIf} $4 == "0"
    StrCpy $4 "1"
    SetFileAttributes "$INSTDIR\${MAINBINARYNAME}.exe" NORMAL
    System::Call 'kernel32::CreateFileW(w "$INSTDIR\${MAINBINARYNAME}.exe", i 0xC0000000, i 0, p 0, i 3, i 0x80, p 0) p.r1 ?e'
    Pop $3
    ${If} $1 != -1
    ${AndIf} $1 != 0
    ${AndIf} $1 != ""
      System::Call 'kernel32::CloseHandle(p r1)'
      Goto catcloud_gs_done_${CATCLOUD_GS_UID}
    ${EndIf}
    ${If} $3 == 2
    ${OrIf} $3 == 3
      Goto catcloud_gs_done_${CATCLOUD_GS_UID}
    ${EndIf}
  ${EndIf}
  ${If} $2 >= 30
    Goto catcloud_gs_locked_${CATCLOUD_GS_UID}
  ${EndIf}
  Sleep 200
  IntOp $2 $2 + 1
  Goto catcloud_gs_wait_${CATCLOUD_GS_UID}

  ; Step 3: Still locked after 6000ms -> prompt (unless silent / /P / /UPDATE) and stop safely
  ; so Tauri's CheckIfAppIsRunning never force-kills the process leaving stale proxy/TUN state.
  catcloud_gs_locked_${CATCLOUD_GS_UID}:
  StrCpy $0 "0"
  ${If} ${Silent}
    StrCpy $0 "1"
  ${EndIf}

  ; Pure inline scan of `$CMDLINE` for standalone `/P` or `/UPDATE` switches (zero non-un. Function
  ; calls, 100% valid in both Section Install and Section Uninstall).
  ${If} $0 == "0"
    StrLen $1 $CMDLINE
    StrCpy $2 0
    catcloud_gs_cmd_${CATCLOUD_GS_UID}:
    ${If} $2 >= $1
      Goto catcloud_gs_cmd_done_${CATCLOUD_GS_UID}
    ${EndIf}
    StrCpy $5 "0"
    ${If} $2 == 0
      StrCpy $5 "1"
    ${Else}
      IntOp $4 $2 - 1
      StrCpy $3 $CMDLINE 1 $4
      ${If} $3 == " "
        StrCpy $5 "1"
      ${ElseIf} $3 == "$\t"
        StrCpy $5 "1"
      ${ElseIf} $3 == '"'
        StrCpy $5 "1"
      ${EndIf}
    ${EndIf}
    ${If} $5 == "1"
      StrCpy $3 $CMDLINE 2 $2
      ${If} $3 == "/P"
        IntOp $4 $2 + 2
        ${If} $4 >= $1
          StrCpy $0 "1"
          Goto catcloud_gs_cmd_done_${CATCLOUD_GS_UID}
        ${Else}
          StrCpy $3 $CMDLINE 1 $4
          ${If} $3 == " "
            StrCpy $0 "1"
            Goto catcloud_gs_cmd_done_${CATCLOUD_GS_UID}
          ${ElseIf} $3 == "$\t"
            StrCpy $0 "1"
            Goto catcloud_gs_cmd_done_${CATCLOUD_GS_UID}
          ${ElseIf} $3 == '"'
            StrCpy $0 "1"
            Goto catcloud_gs_cmd_done_${CATCLOUD_GS_UID}
          ${EndIf}
        ${EndIf}
      ${EndIf}
      StrCpy $3 $CMDLINE 7 $2
      ${If} $3 == "/UPDATE"
        IntOp $4 $2 + 7
        ${If} $4 >= $1
          StrCpy $0 "1"
          Goto catcloud_gs_cmd_done_${CATCLOUD_GS_UID}
        ${Else}
          StrCpy $3 $CMDLINE 1 $4
          ${If} $3 == " "
            StrCpy $0 "1"
            Goto catcloud_gs_cmd_done_${CATCLOUD_GS_UID}
          ${ElseIf} $3 == "$\t"
            StrCpy $0 "1"
            Goto catcloud_gs_cmd_done_${CATCLOUD_GS_UID}
          ${ElseIf} $3 == '"'
            StrCpy $0 "1"
            Goto catcloud_gs_cmd_done_${CATCLOUD_GS_UID}
          ${EndIf}
        ${EndIf}
      ${EndIf}
    ${EndIf}
    IntOp $2 $2 + 1
    Goto catcloud_gs_cmd_${CATCLOUD_GS_UID}
    catcloud_gs_cmd_done_${CATCLOUD_GS_UID}:
  ${EndIf}

  ${If} $0 == "0"
    !if "${MODE}" == "UNINSTALL"
      MessageBox MB_ICONEXCLAMATION|MB_OK "检测到旧版 猫猫云梯（CatCloud）仍在运行，且在 6 秒内未能自动退出。$\r$\n$\r$\n为避免系统代理或虚拟网卡异常残留，请先右键系统托盘中的猫猫云梯图标选择「退出」，再重新运行卸载程序。"
    !else
      MessageBox MB_ICONEXCLAMATION|MB_OK "检测到旧版 猫猫云梯（CatCloud）仍在运行，且在 6 秒内未能自动退出。$\r$\n$\r$\n为避免系统代理或虚拟网卡异常残留，请先右键系统托盘中的猫猫云梯图标选择「退出」，再重新运行安装程序。"
    !endif
  ${EndIf}
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
  !if "${MODE}" == "UNINSTALL"
    ; Exit with code 1 (user cancelled) to match Tauri `installer.nsi` PageLeaveReinstall
    ; `${If} $0 = 1 Abort`, preventing a duplicate generic `$(unableToUninstall)` dialog.
    SetErrorLevel 1
    Quit
  !else
    Abort "CatCloud is still running in $INSTDIR; aborted to prevent forced termination."
  !endif

  catcloud_gs_done_${CATCLOUD_GS_UID}:
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
  !undef CATCLOUD_GS_UID
!macroend