!include LogicLib.nsh
!include x64.nsh

!define MUI_CUSTOMFUNCTION_GUIINIT CatCloudCheckArm64GuiInit

Function CatCloudCheckArm64GuiInit
  ${IfNot} ${IsNativeARM64}
    MessageBox MB_ICONSTOP|MB_OK "检测到当前电脑不是 ARM64 架构的 Windows（常见为 Intel / AMD x64 电脑）。$\r$\n$\r$\n你打开的是 ARM64 专用安装包，继续安装后将无法运行。请改用 CatCloud-*-windows-x64-setup.exe 或绿色便携版。"
    Quit
  ${EndIf}
FunctionEnd

!macro NSIS_HOOK_PREINSTALL
  ${IfNot} ${IsNativeARM64}
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "检测到当前电脑不是 ARM64 架构的 Windows（常见为 Intel / AMD x64 电脑）。$\r$\n$\r$\n请改用 CatCloud-*-windows-x64-setup.exe。"
    ${EndIf}
    RMDir "$INSTDIR"
    Abort "Incompatible architecture: ARM64 installer requires Windows on ARM64."
  ${EndIf}
!macroend
