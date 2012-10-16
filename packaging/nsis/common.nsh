
; ============================================================================
; Name and version information
; ============================================================================

!if ${WIRESHARK_TARGET_PLATFORM} == "win32"
!define BITS 32
!else
!define BITS 64
!endif

!define DISPLAY_NAME "${PROGRAM_NAME} ${VERSION} (${BITS}-bit)"
Name "${DISPLAY_NAME}"

!define UNINSTALLER_NAME "uninstall.exe"

VIAddVersionKey "ProductName" "${PROGRAM_NAME}"
VIAddVersionKey "Comments" "It's a great product with a great story to tell. I'm pumped!"
VIAddVersionKey "CompanyName" "${PROGRAM_NAME} development team"
; NSIS handles the copyright symbol correctly using CP-1252 but not UTF-8.
VIAddVersionKey "LegalCopyright" "© Gerald Combs and many others"
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
	Push ".trc"
	Push ".trace"
	Push ".tr1"
	Push ".tpc"
	Push ".syc"
	Push ".snoop"
	Push ".rf5"
	Push ".pkt"
	Push ".pcapng"
	Push ".pcap"
	Push ".ntar"
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