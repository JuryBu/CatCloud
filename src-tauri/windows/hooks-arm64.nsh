!include LogicLib.nsh
!include x64.nsh
!include FileFunc.nsh
!include "${__FILEDIR__}\graceful-shutdown.nsh"

!define MUI_CUSTOMFUNCTION_GUIINIT CatCloudCheckArm64GuiInit

Function CatCloudCheckArm64GuiInit
  ${IfNot} ${IsNativeARM64}
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
      MessageBox MB_ICONSTOP|MB_OK "检测到当前电脑不是 ARM64 架构的 Windows（常见为 Intel / AMD x64 电脑）。$\r$\n$\r$\n你打开的是 ARM64 专用安装包，继续安装后将无法运行。请改用 CatCloud-*-windows-x64-setup.exe 或绿色便携版。"
    ${EndIf}
    Pop $1
    Pop $0
    SetErrorLevel 1
    Quit
  ${EndIf}
FunctionEnd

!macro NSIS_HOOK_PREINSTALL
  ${IfNot} ${IsNativeARM64}
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
      MessageBox MB_ICONSTOP|MB_OK "检测到当前电脑不是 ARM64 架构的 Windows（常见为 Intel / AMD x64 电脑）。$\r$\n$\r$\n请改用 CatCloud-*-windows-x64-setup.exe。"
    ${EndIf}
    Pop $1
    Pop $0
    RMDir "$INSTDIR"
    Abort "Incompatible architecture: ARM64 installer requires Windows on ARM64."
  ${EndIf}
  !insertmacro CatCloudGracefulShutdownRunning "INSTALL"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro CatCloudGracefulShutdownRunning "UNINSTALL"
!macroend