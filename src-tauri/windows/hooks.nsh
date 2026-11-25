!include LogicLib.nsh
!include x64.nsh

!macro NSIS_HOOK_PREINSTALL
  !if "${ARCH}" == "arm64"
    ${IfNot} ${IsNativeARM64}
      ${IfNot} ${Silent}
        MessageBox MB_ICONSTOP|MB_OK "检测到当前电脑不是 ARM64 架构的 Windows（常见为 Intel / AMD x64 电脑）。$\r$\n$\r$\n你正在运行 ARM64 专用安装包，请改用 CatCloud-*-windows-x64-setup.exe 或便携版。"
      ${EndIf}
      RMDir "$INSTDIR"
      Abort "Incompatible architecture: ARM64 installer requires Windows on ARM64."
    ${EndIf}
  !endif
  !if "${ARCH}" == "x64"
    ${If} ${IsNativeARM64}
      ${IfNot} ${Silent}
        MessageBox MB_ICONQUESTION|MB_YESNO "检测到当前为 Windows ARM64 设备，但你打开的是 x64 安装包（将通过转译运行）。$\r$\n$\r$\n建议改用原生 windows-arm64-setup.exe；是否仍继续安装 x64 版本？" IDYES catcloud_x64_continue
        RMDir "$INSTDIR"
        Abort "Cancelled by user on ARM64 host."
        catcloud_x64_continue:
      ${EndIf}
    ${EndIf}
  !endif
!macroend
