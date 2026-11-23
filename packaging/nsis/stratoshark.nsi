;
; stratoshark.nsi
;
; A thin wrapper around the Stratoshark MSI package (packaging/wix). It
; installs the Visual C++ redistributable and the MSI, and removes any
; earlier NSIS-based installation. Everything else, including shortcuts,
; file associations, and the uninstaller, is handled by the MSI.
;

; Our payloads are already compressed.
SetCompress off
;SetCompressor /SOLID lzma
;SetCompressorDictSize 64 ; MB


; ============================================================================
; Name and version information
; ============================================================================

Unicode true
; This improves the installer's appearance considerably here on a display scaled
; to 225%, but checkboxes are comically small. We might be able to fix this
; using the SysCompImg extension:
; http://forums.winamp.com/showthread.php?t=443754
ManifestDPIAware true
; These might be correct in the future, but are currently undocumented:
; http://forums.winamp.com/showthread.php?t=452632
; ManifestDPIAware System
; ManifestDPIAwareness "PerMonitorV2,System"

!ifdef NSIS_INCLUDE_DIR
!addincludedir ${NSIS_INCLUDE_DIR}
!endif

!include "stratoshark-config.nsh"

!define DISPLAY_NAME "${PROGRAM_NAME} ${VERSION} ${WIRESHARK_TARGET_PLATFORM}"
Name "${DISPLAY_NAME}"

VIAddVersionKey "ProductName" "${PROGRAM_NAME}"
VIAddVersionKey "Comments" "My manta ray is all right."
VIAddVersionKey "CompanyName" "${PROGRAM_NAME} development team"
; NSIS handles U+00a9 but not a UTF-8 encoded copyright symbol.
VIAddVersionKey "LegalCopyright" "${U+00a9} Gerald Combs and many others"
VIAddVersionKey "LegalTrademarks" "Stratoshark and the 'fin' logo are trademarks of the Wireshark Foundation"
VIAddVersionKey "FileDescription" "${PROGRAM_NAME} installer for Windows on ${WIRESHARK_TARGET_PLATFORM}"
VIAddVersionKey "Language" "English"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "FileVersion" "${PRODUCT_VERSION}"
VIProductVersion "${PRODUCT_VERSION}"

XPStyle on

!macro IsStratosharkRunning
; See if Stratoshark is running
; https://nsis.sourceforge.io/Check_whether_your_application_is_running
${Do}

  System::Call 'kernel32::OpenMutex(i 0x100000, b 0, t "Global\${PROGRAM_NAME}-is-running-{9CA78EEA-EA4D-4490-9240-FC01FCEF464B}") i .R0'
    IntCmp $R0 0 checkRunningSession
    System::Call 'kernel32::CloseHandle(i $R0)'
    Goto isRunning

checkRunningSession:
  System::Call 'kernel32::OpenMutex(i 0x100000, b 0, t "${PROGRAM_NAME}-is-running-{9CA78EEA-EA4D-4490-9240-FC01FCEF464B}") i .R0'
    IntCmp $R0 0 notRunning
    System::Call 'kernel32::CloseHandle(i $R0)'

isRunning:
  ; You'd better go catch it.
  MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "${PROGRAM_NAME} or one of its associated programs is running.$\r$\nPlease close it first." /SD IDCANCEL IDRETRY continueChecking
  Quit

notRunning:
  ${ExitDo}

continueChecking:
${Loop}
!macroend

!include 'LogicLib.nsh'

; ============================================================================
; Header configuration
; ============================================================================

; The file to write
OutFile "${OUTFILE_DIR}\${PROGRAM_NAME}-${VERSION}-${WIRESHARK_TARGET_PLATFORM}.exe"
; Installer icon
Icon "${TOP_SRC_DIR}\resources\icons\stratoshark.ico"

; ============================================================================
; Modern UI
; ============================================================================

!include "MUI2.nsh"

!define MUI_ICON "${TOP_SRC_DIR}\resources\icons\stratoshark.ico"
BrandingText "Stratoshark${U+00ae} Installer"

!define MUI_COMPONENTSPAGE_SMALLDESC
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of ${PROGRAM_NAME}.$\r$\n$\r$\nBefore starting the installation, make sure ${PROGRAM_NAME} is not running.$\r$\n$\r$\nClick 'Next' to continue."
!define MUI_FINISHPAGE_TITLE_3LINES

; ============================================================================
; MUI Pages
; ============================================================================

!insertmacro MUI_PAGE_WELCOME

!define MUI_LICENSEPAGE_TEXT_TOP "Stratoshark is distributed under the GNU General Public License."
!define MUI_LICENSEPAGE_TEXT_BOTTOM "This is not an end user license agreement (EULA). It is provided here for informational purposes only."
!define MUI_LICENSEPAGE_BUTTON "Noted"
!insertmacro MUI_PAGE_LICENSE "${STAGING_DIR}\COPYING.txt"

!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

; ============================================================================
; Section macros
; ============================================================================
!include "Sections.nsh"

; ============================================================================
; Command Line
; ============================================================================
!include "FileFunc.nsh"
!insertmacro GetParameters
!insertmacro GetOptions

; ============================================================================
; Functions and macros
; ============================================================================

; Earlier versions used an NSIS-based installer.
Var OLD_UNINSTALLER
Var OLD_INSTDIR
Var OLD_DISPLAYNAME
Var TMP_UNINSTALLER

; WiX
Var REGISTRY_BITS
Var TMP_PRODUCT_GUID
Var WIX_DISPLAYNAME
Var WIX_DISPLAYVERSION
Var WIX_UNINSTALLSTRING

; Used when building the msiexec command line.
Var MSI_FEATURES
Var MSI_PROPERTIES

; ============================================================================
; Platform and OS version checks
; ============================================================================
!include x64.nsh
!include WinVer.nsh
!include WinMessages.nsh

Function PlatformCheck
  !if ${WIRESHARK_TARGET_PLATFORM} == "x64"
    ; http://forums.winamp.com/printthread.php?s=16ffcdd04a8c8d52bee90c0cae273ac5&threadid=262873
    ${IfNot} ${RunningX64}
      MessageBox MB_OK "Stratoshark only runs on 64-bit machines." /SD IDOK
      Abort
    ${EndIf}
  !endif

  !if ${WIRESHARK_TARGET_PLATFORM} == "arm64"
    ${IfNot} ${IsNativeARM64}
      MessageBox MB_OK "You're trying to install the Arm64 version of Stratoshark on an x64 system.$\nTry the native x64 installer instead." /SD IDOK
      Abort
    ${EndIf}
  !endif

  ; This should match the following:
  ; - The NTDDI_VERSION and _WIN32_WINNT parts of cmakeconfig.h.in
  ; - The <compatibility><application> section in resources\stratoshark.exe.manifest.in
  ; - The WINDOWSBUILDNUMBER parts of packaging\wix\StratosharkPrerequisites.wxi
  ${If} ${AtMostWin8.1}
  ${OrIf} ${AtMostWin2012R2}
  ${OrIfNot} ${AtLeastBuild} 19044
    MessageBox MB_OK \
      "Windows 10, version 21H2 or Server 2022 and later are required." /SD IDOK
    Quit
  ${EndIf}
FunctionEnd

; ============================================================================
; Installation execution commands
; ============================================================================

; Install the Visual C++ Redistributable. The MSI checks for it and refuses
; to install if it's missing.
Section "-Visual C++ Redistributable"
  InitPluginsDir
  SetOutPath $PLUGINSDIR

  ; vc_redist.x64.exe or vc_redist.arm64.exe - extract and execute the
  ; redistributable installer.
  File "${VCREDIST_DIR}\${VCREDIST_EXE}"

  ; If the user already has the redistributable installed they will see a
  ; Big Ugly Dialog by default, asking if they want to uninstall or repair.
  ; Ideally we should add a checkbox for this somewhere. In the meantime,
  ; just do a "quiet" install.
  ; http://asawicki.info/news_1597_installing_visual_c_redistributable_package_from_command_line.html
  ExecWait '"$PLUGINSDIR\${VCREDIST_EXE}" /install /quiet /norestart' $0
  DetailPrint "${VCREDIST_EXE} returned $0"

  ; https://docs.microsoft.com/en-us/windows/desktop/Msi/error-codes
  !define ERROR_SUCCESS 0
  !define ERROR_SUCCESS_REBOOT_INITIATED 1641
  !define ERROR_PRODUCT_VERSION 1638
  !define ERROR_SUCCESS_REBOOT_REQUIRED 3010

  ${Switch} $0
    ${Case} ${ERROR_SUCCESS}
    ${Case} ${ERROR_PRODUCT_VERSION} ; Newer version already installed.
      ${Break}
    ${Case} ${ERROR_SUCCESS_REBOOT_INITIATED} ; Shouldn't happen.
    ${Case} ${ERROR_SUCCESS_REBOOT_REQUIRED}
      SetRebootFlag true
      ${Break}
    ${Default}
      MessageBox MB_OK "The Visual C++ Redistributable installer failed with error $0.$\nUnable to continue installation." /SD IDOK
      Abort
    ${Break}
  ${EndSwitch}

  Delete "$PLUGINSDIR\${VCREDIST_EXE}"
SectionEnd

; The selectable sections below correspond to features in the MSI. They
; don't install anything themselves. Their selection is turned into the
; ADDLOCAL property for msiexec by "-Stratoshark MSI".
; Keep the feature names in sync with packaging\wix\StratosharkFeatures.wxi.

Section "${PROGRAM_NAME}" SecStratosharkQt
  ; Fe.Stratoshark
SectionEnd

Section "Strato" SecStrato
  ; Fe.Strato
SectionEnd

SectionGroup /e "External capture tools (extcap)" SecExtcapGroup

Section "Falcodump" SecFalcodump
  ; Fe.Extcap.Falcodump
SectionEnd

!ifdef LIBSSH_FOUND
Section "Sshdig" SecSshdig
  ; Fe.Extcap.Sshdig
SectionEnd
!endif

SectionGroupEnd ; "External Capture (extcap)"

!macro AddMsiFeature FEATURE
  ${If} $MSI_FEATURES == ""
    StrCpy $MSI_FEATURES "${FEATURE}"
  ${Else}
    StrCpy $MSI_FEATURES "$MSI_FEATURES,${FEATURE}"
  ${EndIf}
!macroend

Section "-Stratoshark MSI"
  InitPluginsDir
  SetOutPath $PLUGINSDIR
  File "/oname=Stratoshark.msi" "${STRATOSHARK_MSI_FILE}"

  ; Always install the required files.
  !insertmacro AddMsiFeature "Fe.StratosharkRequired"

  ${If} ${SectionIsSelected} ${SecStratosharkQt}
    !insertmacro AddMsiFeature "Fe.Stratoshark"
  ${EndIf}

  ${If} ${SectionIsSelected} ${SecStrato}
    !insertmacro AddMsiFeature "Fe.Strato"
  ${EndIf}

  ; The extcap features are children of Fe.Extcap.
  StrCpy $R0 0
  ${If} ${SectionIsSelected} ${SecFalcodump}
    StrCpy $R0 1
  ${EndIf}
  !ifdef LIBSSH_FOUND
    ${If} ${SectionIsSelected} ${SecSshdig}
      StrCpy $R0 1
    ${EndIf}
  !endif
  ${If} $R0 == 1
    !insertmacro AddMsiFeature "Fe.Extcap"
  ${EndIf}
  ${If} ${SectionIsSelected} ${SecFalcodump}
    !insertmacro AddMsiFeature "Fe.Extcap.Falcodump"
  ${EndIf}
  !ifdef LIBSSH_FOUND
    ${If} ${SectionIsSelected} ${SecSshdig}
      !insertmacro AddMsiFeature "Fe.Extcap.Sshdig"
    ${EndIf}
  !endif

  DetailPrint "Installing ${PROGRAM_NAME} features: $MSI_FEATURES"

  ; Interactive installs show a progress window (/passive). Silent installs
  ; are quiet (/qn).
  ${If} ${Silent}
    StrCpy $R1 "/qn"
  ${Else}
    StrCpy $R1 "/passive"
  ${EndIf}

  ExecWait '"$SYSDIR\msiexec.exe" /i "$PLUGINSDIR\Stratoshark.msi" ADDLOCAL=$MSI_FEATURES $MSI_PROPERTIES $R1 /norestart' $0
  DetailPrint "msiexec returned $0"

  ${Switch} $0
    ${Case} ${ERROR_SUCCESS}
      ${Break}
    ${Case} ${ERROR_SUCCESS_REBOOT_INITIATED}
    ${Case} ${ERROR_SUCCESS_REBOOT_REQUIRED}
      SetRebootFlag true
      ${Break}
    ${Default}
      MessageBox MB_OK "The ${PROGRAM_NAME} installer failed with error $0." /SD IDOK
      Abort
    ${Break}
  ${EndSwitch}

  Delete "$PLUGINSDIR\Stratoshark.msi"
SectionEnd

; Convert /EXTRACOMPONENTS=name,name,... to selected sections, which end up in
; msiexec's ADDLOCAL property. Silent installs only.
Function SelectExtraComponents
  ${GetParameters} $R0
  ${GetOptions} $R0 "/EXTRACOMPONENTS=" $R1
  IfErrors extra_done

  extra_loop:
    StrCmp $R1 "" extra_done

    ; Split at the first comma.
    StrCpy $R2 0
    extra_find_comma:
      StrCpy $R3 $R1 1 $R2
      StrCmp $R3 "" extra_got_word
      StrCmp $R3 "," extra_got_word
      IntOp $R2 $R2 + 1
      Goto extra_find_comma
    extra_got_word:
      StrCpy $R4 $R1 $R2
      IntOp $R2 $R2 + 1
      StrCpy $R1 $R1 "" $R2

    ${If} $R4 == "falcodump"
      !insertmacro SelectSection ${SecFalcodump}
    !ifdef LIBSSH_FOUND
    ${ElseIf} $R4 == "sshdig"
      !insertmacro SelectSection ${SecSshdig}
    !endif
    ${EndIf}
    Goto extra_loop

  extra_done:
FunctionEnd

Function .onInit

  Call PlatformCheck

  !insertmacro IsStratosharkRunning

  ; Pass /desktopicon=yes through to the MSI.
  StrCpy $MSI_PROPERTIES ""
  ${GetParameters} $R0
  ${GetOptions} $R0 "/desktopicon=" $R1
  ${If} $R1 == "yes"
    StrCpy $MSI_PROPERTIES "STRATOSHARK_DESKTOP_ICON=1"
  ${Endif}

  ${If} ${Silent}
    Call SelectExtraComponents
  ${EndIf}

  ; Copied from https://nsis.sourceforge.io/Auto-uninstall_old_before_installing_new
  ReadRegStr $OLD_UNINSTALLER HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" \
    "UninstallString"
  StrCmp $OLD_UNINSTALLER "" check_wix

  ReadRegStr $OLD_INSTDIR HKLM \
    "Software\Microsoft\Windows\CurrentVersion\App Paths\${PROGRAM_NAME}.exe" \
    "Path"
  StrCmp $OLD_INSTDIR "" check_wix

  ReadRegStr $OLD_DISPLAYNAME HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" \
    "DisplayName"
  StrCmp $OLD_DISPLAYNAME "" check_wix

  MessageBox MB_YESNOCANCEL|MB_ICONQUESTION \
    "$OLD_DISPLAYNAME is already installed.\
     $\n$\nWould you like to uninstall it first?" \
      /SD IDYES \
      IDYES prep_nsis_uninstaller \
      IDNO check_wix
  Abort

  ; Run the old uninstaller from a temporary location.
  prep_nsis_uninstaller:
    ClearErrors

    StrCpy $TMP_UNINSTALLER "$TEMP\${PROGRAM_NAME}_uninstaller.exe"

    ; Strip the surrounding quotes from the uninstall string.
    StrCpy $0 $OLD_UNINSTALLER -1 1
    StrCpy $1 "$TEMP\${PROGRAM_NAME}_uninstaller.exe"
    StrCpy $2 1
    System::Call 'kernel32::CopyFile(t r0, t r1, b r2) 1'

    ExecWait "$TMP_UNINSTALLER /S _?=$OLD_INSTDIR"
    Delete "$TMP_UNINSTALLER"

  ; Look for an MSI-installed package. Its DisplayName is exactly
  ; "${PROGRAM_NAME}", unlike the NSIS-based installation.
  check_wix:
    StrCpy $REGISTRY_BITS 64
    SetRegView 64
    check_wix_restart:
      StrCpy $0 0
    wix_reg_enum_loop:
      EnumRegKey $TMP_PRODUCT_GUID HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" $0
      StrCmp $TMP_PRODUCT_GUID "" wix_enum_reg_done
      IntOp $0 $0 + 1
      ReadRegStr $WIX_DISPLAYNAME HKLM \
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$TMP_PRODUCT_GUID" \
        "DisplayName"
      StrCmp $WIX_DISPLAYNAME "${PROGRAM_NAME}" wix_found wix_reg_enum_loop

      wix_found:
        ReadRegStr $WIX_DISPLAYVERSION HKLM \
          "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$TMP_PRODUCT_GUID" \
          "DisplayVersion"
        ; Prefer QuietUninstallString and fall back to UninstallString.
        ReadRegStr $WIX_UNINSTALLSTRING HKLM \
          "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$TMP_PRODUCT_GUID" \
          "QuietUninstallString"
        StrCmp $WIX_UNINSTALLSTRING "" 0 wix_have_uninstallstring
        ReadRegStr $WIX_UNINSTALLSTRING HKLM \
          "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$TMP_PRODUCT_GUID" \
          "UninstallString"

        wix_have_uninstallstring:
        StrCmp $WIX_UNINSTALLSTRING "" done
        MessageBox MB_YESNOCANCEL|MB_ICONQUESTION \
          "$WIX_DISPLAYNAME $WIX_DISPLAYVERSION (msi) is already installed.\
           $\n$\nWould you like to uninstall it first?" \
            /SD IDYES \
            IDYES prep_wix_uninstaller \
            IDNO done
        Abort

        ; Run the WiX-provided QuietUninstallString or UninstallString.
        prep_wix_uninstaller:
          ClearErrors
          ExecWait "$WIX_UNINSTALLSTRING"

        Goto done

    wix_enum_reg_done:
      IntCmp $REGISTRY_BITS 32 done
      StrCpy $REGISTRY_BITS 32
      SetRegView 32
      Goto check_wix_restart

  done:

FunctionEnd

; Sign our installer during compilation.
!ifdef ENABLE_SIGNED_NSIS
!finalize 'sign-stratoshark.bat "%1"' = 0 ; %1 is replaced by the installer exe to be signed.
!endif

; ============================================================================
; PLEASE MAKE SURE, THAT THE DESCRIPTIVE TEXT FITS INTO THE DESCRIPTION FIELD!
; ============================================================================
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStratosharkQt} "The main system call and log analyzer application."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStrato} "Text based system call and log analyzer."

  !insertmacro MUI_DESCRIPTION_TEXT ${SecExtcapGroup} "External Capture Interfaces"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecFalcodump} "Provide capture interfaces from Falco plugins."
  !ifdef LIBSSH_FOUND
  !insertmacro MUI_DESCRIPTION_TEXT ${SecSshdig} "Provide remote capture through SSH. (sysdig)"
  !endif
!insertmacro MUI_FUNCTION_DESCRIPTION_END
