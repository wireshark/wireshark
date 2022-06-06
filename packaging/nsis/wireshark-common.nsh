
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

!include "wireshark-config.nsh"

!if ${WIRESHARK_TARGET_PLATFORM} == "win32"
!define BITS 32
!else
!define BITS 64
!endif

!define DISPLAY_NAME "${PROGRAM_NAME} ${VERSION} ${BITS}-bit"
Name "${DISPLAY_NAME}"

!define PROGRAM_FULL_NAME "The ${PROGRAM_NAME} Network Protocol Analyzer"
!define PROGRAM_NAME_PATH "${PROGRAM_NAME}.exe"

!define UNINSTALLER_NAME "uninstall-wireshark.exe"

VIAddVersionKey "ProductName" "${PROGRAM_NAME}"
VIAddVersionKey "Comments" "It's a great product with a great story to tell. I'm pumped!"
VIAddVersionKey "CompanyName" "${PROGRAM_NAME} development team"
; NSIS handles U+00a9 but not a UTF-8 encoded copyright symbol.
VIAddVersionKey "LegalCopyright" "${U+00a9} Gerald Combs and many others"
VIAddVersionKey "LegalTrademarks" "Wireshark and the 'fin' logo are registered trademarks of the Wireshark Foundation"
VIAddVersionKey "FileDescription" "${PROGRAM_NAME} installer for ${BITS}-bit Windows"
VIAddVersionKey "Language" "English"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "FileVersion" "${PRODUCT_VERSION}"
VIProductVersion "${PRODUCT_VERSION}"

XPStyle on


; ============================================================================
; Functions and macros
; ============================================================================

; Used to refresh the display of file association
!define SHCNE_ASSOCCHANGED 0x08000000
!define SHCNF_IDLIST 0

!macro UpdateIcons
  Push $R0
  Push $R1
  Push $R2

  !define UPDATEICONS_UNIQUE ${__LINE__}

  IfFileExists "$SYSDIR\shell32.dll" UpdateIcons.ok_shell32_${UPDATEICONS_UNIQUE} UpdateIcons.error_shell32_${UPDATEICONS_UNIQUE}
UpdateIcons.ok_shell32_${UPDATEICONS_UNIQUE}:
  System::Call 'shell32.dll::SHChangeNotify(i, i, i, i) v (${SHCNE_ASSOCCHANGED}, ${SHCNF_IDLIST}, 0, 0)'
  Goto UpdateIcons.quit_${UPDATEICONS_UNIQUE}

UpdateIcons.error_shell32_${UPDATEICONS_UNIQUE}:
  MessageBox MB_OK|MB_ICONSTOP  \
    "Can't find 'shell32.dll' library. Impossible to update icons" \
    /SD IDOK
  Goto UpdateIcons.quit_${UPDATEICONS_UNIQUE}

UpdateIcons.quit_${UPDATEICONS_UNIQUE}:
  !undef UPDATEICONS_UNIQUE
  Pop $R2
  Pop $R1
  Pop $R0

; Force the icon cache to refresh
; https://superuser.com/questions/499078/refresh-icon-cache-without-rebooting
IfFileExists "$SYSDIR\ie4uinit.exe" 0 +2
Exec '"$SYSDIR\ie4uinit.exe" -ClearIconCache'

!macroend

; ============================================================================
; Push our known file extensions onto the stack, prepended with a marker
; Note that this is a subset of dump_open_table in wiretap/file_access.c. We
; probably don't want to grab JPEG or MP3 files.
; ============================================================================

; Used to add associations between file extensions and Wireshark
!define WIRESHARK_ASSOC "wireshark-capture-file"

!define FILE_EXTENSION_MARKER "FILE_EXTENSION_MARKER"

!macro PushFileExtensions
  Push "${FILE_EXTENSION_MARKER}"
  Push ".wpz"
  Push ".wpc"
  Push ".vwr"
  Push ".trc"
  Push ".trace"
  Push ".tr1"
  Push ".tpc"
  Push ".syc"
  Push ".snoop"
  Push ".rf5"
  Push ".pkt"
  Push ".pklg"
  Push ".pcapng"
  Push ".pcap"
  Push ".out"
  Push ".ntar"
  Push ".mplog"
  Push ".lcap"
  Push ".ipfix"
  Push ".fdc"
  Push ".erf"
  Push ".enc"
  Push ".cap"
  Push ".bfr"
  Push ".atc"
  Push ".apc"
  Push ".acp"
  Push ".5vw"
!macroend

!macro IsWiresharkRunning
; See if Wireshark is running
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
