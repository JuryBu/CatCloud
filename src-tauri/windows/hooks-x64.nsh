!include LogicLib.nsh
!include x64.nsh

!define MUI_CUSTOMFUNCTION_GUIINIT CatCloudCheckX64GuiInit

Function CatCloudCheckX64GuiInit
  ${If} ${IsNativeARM64}
    MessageBox MB_ICONQUESTION|MB_YESNO "检测到当前为 Windows ARM64 设备，但你打开的是 x64 安装包（将通过转译运行）。$\r$\n$\r$\n建议改用原生 windows-arm64-setup.exe；是否仍继续安装 x64 版本？" IDYES catcloud_x64_gui_continue
    Quit
    catcloud_x64_gui_continue:
  ${EndIf}
FunctionEnd

!macro NSIS_HOOK_PREINSTALL
!macroend
