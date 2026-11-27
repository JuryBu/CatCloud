!include LogicLib.nsh
!include x64.nsh
!include FileFunc.nsh
!include "${__FILEDIR__}\graceful-shutdown.nsh"

!define MUI_CUSTOMFUNCTION_GUIINIT CatCloudCheckX64GuiInit

Function CatCloudCheckX64GuiInit
  ${If} ${IsNativeARM64}
    Push $0
    Push $1
    StrCpy $1 "0"
    ${If} ${Silent}
      StrCpy $1 "1"
    ${EndIf}
    ${If} $1 == "0"
      ClearErrors
      ${GetOptions} $CMDLINE "/P" $0
      ${IfNot} ${Errors}
        StrCpy $1 "1"
      ${EndIf}
    ${EndIf}
    ${If} $1 == "0"
      ClearErrors
      ${GetOptions} $CMDLINE "/UPDATE" $0
      ${IfNot} ${Errors}
        StrCpy $1 "1"
      ${EndIf}
    ${EndIf}
    ${If} $1 == "0"
      MessageBox MB_ICONQUESTION|MB_YESNO "检测到当前为 Windows ARM64 设备，但你打开的是 x64 安装包（将通过转译运行）。$\r$\n$\r$\n建议改用原生 windows-arm64-setup.exe；是否仍继续安装 x64 版本？" IDYES catcloud_x64_gui_continue
      Pop $1
      Pop $0
      Quit
      catcloud_x64_gui_continue:
    ${EndIf}
    Pop $1
    Pop $0
  ${EndIf}
FunctionEnd

!macro NSIS_HOOK_PREINSTALL
  !insertmacro CatCloudGracefulShutdownRunning "INSTALL"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro CatCloudGracefulShutdownRunning "UNINSTALL"
!macroend