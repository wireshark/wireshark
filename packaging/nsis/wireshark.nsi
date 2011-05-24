;
; wireshark.nsi
;
; $Id$


; Set the compression mechanism first.
; As of NSIS 2.07, solid compression which makes installer about 1MB smaller
; is no longer the default, so use the /SOLID switch.
; This unfortunately is unknown to NSIS prior to 2.07 and creates an error.
; So if you get an error here, please update to at least NSIS 2.07!
SetCompressor /SOLID lzma

InstType "un.Default (keep Personal Settings and WinPcap)"
InstType "un.All (remove all)"

; Used to refresh the display of file association
!define SHCNE_ASSOCCHANGED 0x08000000
!define SHCNF_IDLIST 0

; Used to add associations between file extensions and Wireshark
!define WIRESHARK_ASSOC "wireshark-capture-file"

; ============================================================================
; Header configuration
; ============================================================================
; The name of the installer
!define PROGRAM_NAME "Wireshark"
!if ${WIRESHARK_TARGET_PLATFORM} == "win32"
!define BITS 32
!else
!define BITS 64
!endif

Name "${PROGRAM_NAME} ${VERSION} (${BITS}-bit)"

; 
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


; The file to write
OutFile "wireshark-${WIRESHARK_TARGET_PLATFORM}-${VERSION}.exe"

; Icon of installer and uninstaller
Icon "..\..\image\wiresharkinst.ico"
UninstallIcon "..\..\image\wiresharkinst.ico"

; Uninstall stuff (NSIS 2.08: "\r\n" don't work here)
!define MUI_UNCONFIRMPAGE_TEXT_TOP "The following Wireshark installation will be uninstalled. Click 'Next' to continue."
; Uninstall stuff (this text isn't used with the MODERN_UI!)
;UninstallText "This will uninstall Wireshark.\r\nBefore starting the uninstallation, make sure Wireshark is not running.\r\nClick 'Next' to continue."

XPStyle on



; ============================================================================
; Modern UI
; ============================================================================
; The modern user interface will look much better than the common one.
; However, as the development of the modern UI is still going on, and the script
; syntax changes, you will need exactly that NSIS version, which this script is
; made for. This is the current (December 2003) latest version: V2.0b4
; If you are using a different version, it's not predictable what will happen.

!include "MUI.nsh"
;!addplugindir ".\Plugins"

!define MUI_ICON "..\..\image\wiresharkinst.ico"
!define MUI_UNICON "..\..\image\wiresharkinst.ico"

!define MUI_COMPONENTSPAGE_SMALLDESC
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of Wireshark.\r\n\r\nBefore starting the installation, make sure Wireshark is not running.\r\n\r\nClick 'Next' to continue."
;!define MUI_FINISHPAGE_LINK "Install WinPcap to be able to capture packets from a network!"
;!define MUI_FINISHPAGE_LINK_LOCATION "http://www.winpcap.org"

; NSIS shows Readme files by opening the Readme file with the default application for
; the file's extension. "README.win32" won't work in most cases, because extension "win32"
; is usually not associated with an appropriate text editor. We should use extension "txt"
; for a text file or "html" for an html README file.
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\NEWS.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Show News"
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
!define MUI_FINISHPAGE_RUN "$INSTDIR\wireshark.exe"
!define MUI_FINISHPAGE_RUN_NOTCHECKED



!define MUI_PAGE_CUSTOMFUNCTION_SHOW myShowCallback

; ============================================================================
; MUI Pages
; ============================================================================

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\COPYING"
!insertmacro MUI_PAGE_COMPONENTS
Page custom DisplayAdditionalTasksPage
!insertmacro MUI_PAGE_DIRECTORY
Page custom DisplayWinPcapPage
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_COMPONENTS
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; ============================================================================
; MUI Languages
; ============================================================================

!insertmacro MUI_LANGUAGE "English"

; ============================================================================
; Reserve Files
; ============================================================================

  ;Things that need to be extracted on first (keep these lines before any File command!)
  ;Only useful for BZIP2 compression

  ReserveFile "AdditionalTasksPage.ini"
  ReserveFile "WinPcapPage.ini"
  !insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

; ============================================================================
; Section macros
; ============================================================================
!include "Sections.nsh"

; ========= Macro to unselect and disable a section =========

!macro DisableSection SECTION

  Push $0
    SectionGetFlags "${SECTION}" $0
    IntOp $0 $0 & ${SECTION_OFF}
    IntOp $0 $0 | ${SF_RO}
    SectionSetFlags "${SECTION}" $0
  Pop $0

!macroend

; ========= Macro to enable (unreadonly) a section =========
!define SECTION_ENABLE   0xFFFFFFEF
!macro EnableSection SECTION

  Push $0
    SectionGetFlags "${SECTION}" $0
    IntOp $0 $0 & ${SECTION_ENABLE}
    SectionSetFlags "${SECTION}" $0
  Pop $0

!macroend

; ============================================================================
; Command Line
; ============================================================================
!include "FileFunc.nsh"

!insertmacro GetParameters
!insertmacro GetOptions

; ============================================================================
; License page configuration
; ============================================================================
LicenseText "Wireshark is distributed under the GNU General Public License."
LicenseData "..\..\COPYING"

; ============================================================================
; Component page configuration
; ============================================================================
ComponentText "The following components are available for installation."

; Component check boxes
; Commented out for NSIS v 2.0
; EnabledBitmap "..\..\image\nsis-checked.bmp"
; DisabledBitmap "..\..\image\nsis-unchecked.bmp"

; ============================================================================
; Directory selection page configuration
; ============================================================================
; The text to prompt the user to enter a directory
DirText "Choose a directory in which to install Wireshark."

; The default installation directory
!if ${WIRESHARK_TARGET_PLATFORM} == "win64"
  InstallDir $PROGRAMFILES64\Wireshark
!else
  InstallDir $PROGRAMFILES\Wireshark
!endif

; See if this is an upgrade; if so, use the old InstallDir as default
InstallDirRegKey HKEY_LOCAL_MACHINE SOFTWARE\Wireshark "InstallDir"


; ============================================================================
; Install page configuration
; ============================================================================
ShowInstDetails show
ShowUninstDetails show

; ============================================================================
; Functions and macros
; ============================================================================
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

Function Associate
	; $R0 should contain the prefix to associate to Wireshark
	Push $R1

	ReadRegStr $R1 HKCR $R0 ""
	StrCmp $R1 "" Associate.doRegister
	Goto Associate.end
Associate.doRegister:
	;The extension is not associated to any program, we can do the link
	WriteRegStr HKCR $R0 "" ${WIRESHARK_ASSOC}
Associate.end:
	pop $R1
FunctionEnd

Function un.unlink
	; $R0 should contain the prefix to unlink
	Push $R1

	ReadRegStr $R1 HKCR $R0 ""
	StrCmp $R1 ${WIRESHARK_ASSOC} un.unlink.doUnlink
	Goto un.unlink.end
un.unlink.doUnlink:
	; The extension is associated with Wireshark so, we must destroy this!
	DeleteRegKey HKCR $R0
un.unlink.end:
	pop $R1
FunctionEnd

Var OLD_UNINSTALLER
Var OLD_INSTDIR
Var OLD_DISPLAYNAME
Var TMP_UNINSTALLER

; ============================================================================
; 64-bit support
; ============================================================================
!include x64.nsh

Function .onInit
  !if ${WIRESHARK_TARGET_PLATFORM} == "win64"
    ; http://forums.winamp.com/printthread.php?s=16ffcdd04a8c8d52bee90c0cae273ac5&threadid=262873
    ${IfNot} ${RunningX64}
      MessageBox MB_OK "This version of Wireshark only runs on x64 machines.\nTry installing the 32-bit version instead."
      Abort
    ${EndIf}
  !endif

  ; Copied from http://nsis.sourceforge.net/Auto-uninstall_old_before_installing_new
  ReadRegStr $OLD_UNINSTALLER HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" \
    "UninstallString"
  StrCmp $OLD_UNINSTALLER "" done

  ReadRegStr $OLD_INSTDIR HKLM \
    "Software\Microsoft\Windows\CurrentVersion\App Paths\wireshark.exe" \
    "Path"
  StrCmp $OLD_INSTDIR "" done

  ReadRegStr $OLD_DISPLAYNAME HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" \
    "DisplayName"
  StrCmp $OLD_DISPLAYNAME "" done

  MessageBox MB_YESNOCANCEL|MB_ICONQUESTION \
    "$OLD_DISPLAYNAME is already installed.\
    $\n$\nWould you like to uninstall it first?" \
      /SD IDYES \
      IDYES prep_uninstaller \
      IDNO done
  Abort
 
; Copy the uninstaller to $TEMP and run it.
; The uninstaller normally does this by itself, but doesn't wait around
; for the executable to finish, which means ExecWait won't work correctly.
prep_uninstaller:
  ClearErrors
  StrCpy $TMP_UNINSTALLER "$TEMP\wireshark_uninstaller.exe"
  ; ...because we surround UninstallString in quotes.
  StrCpy $0 $OLD_UNINSTALLER -1 1
  StrCpy $1 "$TEMP\wireshark_uninstaller.exe"
  StrCpy $2 1
  System::Call 'kernel32::CopyFile(t r0, t r1, b r2) 1'
  IfSilent silent_uninstall
  ExecWait "$TMP_UNINSTALLER _?=$OLD_INSTDIR"
  Goto cleanup

silent_uninstall:
  ExecWait "$TMP_UNINSTALLER /S _?=$OLD_INSTDIR"

cleanup:
  Delete "$TMP_UNINSTALLER"
  
done:
  ;Extract InstallOptions INI files
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "AdditionalTasksPage.ini"
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "WinpcapPage.ini"
FunctionEnd

Function DisplayAdditionalTasksPage
  !insertmacro MUI_HEADER_TEXT "Select Additional Tasks" "Which additional tasks should be done?"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "AdditionalTasksPage.ini"
FunctionEnd

Function DisplayWinPcapPage
  !insertmacro MUI_HEADER_TEXT "Install WinPcap?" "WinPcap is required to capture live network data. Should WinPcap be installed?"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "WinPcapPage.ini"
FunctionEnd

; ============================================================================
; Installation execution commands
; ============================================================================

Var WINPCAP_UNINSTALL ;declare variable for holding the value of a registry key
;Var WIRESHARK_UNINSTALL ;declare variable for holding the value of a registry key

Section "-Required"
;-------------------------------------------

;
; Install for every user
;
SetShellVarContext all



SetOutPath $INSTDIR
File "..\..\wiretap\wiretap-${WTAP_VERSION}.dll"
!ifdef ENABLE_LIBWIRESHARK
File "..\..\epan\libwireshark.dll"
!endif
File "..\..\wsutil\libwsutil.dll"
File "${GTK_DIR}\bin\libgio-2.0-0.dll"
File "${GTK_DIR}\bin\libglib-2.0-0.dll"
File "${GTK_DIR}\bin\libgobject-2.0-0.dll"
File "${GTK_DIR}\bin\libgmodule-2.0-0.dll"
File "${GTK_DIR}\bin\libgthread-2.0-0.dll"
!ifdef ICONV_DIR
File "${GTK_DIR}\bin\iconv.dll"
!endif
File "${GTK_DIR}\bin\${INTL_DLL}"
!ifdef ZLIB_DIR
File "${ZLIB_DIR}\zlib1.dll"
!endif
!ifdef C_ARES_DIR
File "${C_ARES_DIR}\bin\libcares-2.dll"
!endif
!ifdef ADNS_DIR
File "${ADNS_DIR}\..\${MSVC_VARIANT}\adns\adns_dll.dll"
!endif
!ifdef PCRE_DIR
File "${PCRE_DIR}\bin\pcre3.dll"
File "${PCRE_DIR}\man\cat3\pcrepattern.3.txt"
!endif
!ifdef KFW_DIR
File "${KFW_PATH}\comerr32.dll"
File "${KFW_PATH}\krb5_32.dll"
File "${KFW_PATH}\k5sprt32.dll"
!endif
!ifdef GNUTLS_DIR
File "${GNUTLS_DIR}\bin\libgcrypt-11.dll"
File "${GNUTLS_DIR}\bin\libgnutls-26.dll"
File "${GNUTLS_DIR}\bin\libgnutls-extra-26.dll"
File "${GNUTLS_DIR}\bin\libgnutls-openssl-26.dll"
File "${GNUTLS_DIR}\bin\libgpg-error-0.dll"
File "${GNUTLS_DIR}\bin\libtasn1-3.dll"
StrCmp "${INTL_DLL}" "libintl-8.dll" SkipLibIntl8
File "${GNUTLS_DIR}\bin\libintl-8.dll"
SkipLibIntl8:
!endif
!ifdef LUA_DIR
File "${LUA_DIR}\lua5.1.dll"
File "..\..\epan\wslua\init.lua"
File "..\..\epan\wslua\console.lua"
File "..\..\epan\wslua\dtd_gen.lua"
!endif
!ifdef SMI_DIR
File "${SMI_DIR}\lib\smi.dll"
!endif
File "..\..\wireshark-gtk2\COPYING.txt"
File "..\..\wireshark-gtk2\NEWS.txt"
File "..\..\wireshark-gtk2\README.txt"
File "..\..\wireshark-gtk2\README.windows.txt"
File "..\..\doc\AUTHORS-SHORT"
File "..\..\manuf"
File "..\..\services"
File "..\..\pdml2html.xsl"
File "..\..\doc\ws.css"
File "..\..\doc\wireshark.html"
File "..\..\doc\wireshark-filter.html"
File "..\..\dumpcap.exe"
File "..\..\doc\dumpcap.html"
File "..\..\ipmap.html"

; C-runtime redistributable
!ifdef VCREDIST_EXE
; vcredist_x86.exe (MSVC V8) - copy and execute the redistributable installer
File "${VCREDIST_EXE}"
!if ${WIRESHARK_TARGET_PLATFORM} == "win32"
; If the user already has the redistributable installed they will see a
; Big Ugly Dialog by default, asking if they want to uninstall or repair.
; Ideally we should add a checkbox for this somewhere. In the meantime,
; just do a silent install.
ExecWait '"$INSTDIR\vcredist_x86.exe" /q' $0
!else
ExecWait '"$INSTDIR\vcredist_x64.exe" /q' $0
!endif ; WIRESHARK_TARGET_PLATFORM
DetailPrint "vcredist_x86 returned $0"
!else
!ifdef MSVCR_DLL
; msvcr*.dll (MSVC V7 or V7.1) - simply copy the dll file
!echo "IF YOU GET AN ERROR HERE, check the MSVC_VARIANT setting in config.nmake: MSVC2005 vs. MSVC2005EE!"
File "${MSVCR_DLL}"
!else
!if ${MSVC_VARIANT} != "MSVC6"
!error "C-Runtime redistributable for this package not available / not redistributable!"
!endif
!endif	; MSVCR_DLL
!endif	; VCREDIST_EXE


; global config files - don't overwrite if already existing
;IfFileExists cfilters dont_overwrite_cfilters
File "..\..\cfilters"
;dont_overwrite_cfilters:
;IfFileExists colorfilters dont_overwrite_colorfilters
File "..\..\colorfilters"
;dont_overwrite_colorfilters:
;IfFileExists dfilters dont_overwrite_dfilters
File "..\..\dfilters"
;dont_overwrite_dfilters:
;IfFileExists smi_modules dont_overwrite_smi_modules
File "..\..\smi_modules"
;dont_overwrite_smi_modules:


;
; Install the Diameter DTD and XML files in the "diameter" subdirectory
; of the installation directory.
;
SetOutPath $INSTDIR\diameter
File "..\..\diameter\chargecontrol.xml"
File "..\..\diameter\dictionary.dtd"
File "..\..\diameter\dictionary.xml"
File "..\..\diameter\eap.xml"
File "..\..\diameter\Ericsson.xml"
File "..\..\diameter\etsie2e4.xml"
File "..\..\diameter\gqpolicy.xml"
File "..\..\diameter\imscxdx.xml"
File "..\..\diameter\mobileipv4.xml"
File "..\..\diameter\mobileipv6.xml"
File "..\..\diameter\nasreq.xml"
File "..\..\diameter\sip.xml"
File "..\..\diameter\sunping.xml"
File "..\..\diameter\TGPPGmb.xml"
File "..\..\diameter\TGPPRx.xml"
File "..\..\diameter\TGPPSh.xml"
SetOutPath $INSTDIR



;
; Install the RADIUS directory files in the "radius" subdirectory
; of the installation directory.
;
SetOutPath $INSTDIR\radius
File "..\..\radius\README.radius_dictionary"
File "..\..\radius\dictionary"
File "..\..\radius\dictionary.3com"
File "..\..\radius\dictionary.3gpp"
File "..\..\radius\dictionary.3gpp2"
File "..\..\radius\dictionary.acc"
File "..\..\radius\dictionary.acme"
File "..\..\radius\dictionary.airespace"
File "..\..\radius\dictionary.alcatel"
File "..\..\radius\dictionary.alcatel.esam"
File "..\..\radius\dictionary.alcatel.sr"
File "..\..\radius\dictionary.alteon"
File "..\..\radius\dictionary.altiga"
File "..\..\radius\dictionary.alvarion"
File "..\..\radius\dictionary.apc"
File "..\..\radius\dictionary.aptis"
File "..\..\radius\dictionary.aruba"
File "..\..\radius\dictionary.ascend"
File "..\..\radius\dictionary.asn"
File "..\..\radius\dictionary.audiocodes"
File "..\..\radius\dictionary.avaya"
File "..\..\radius\dictionary.azaire"
File "..\..\radius\dictionary.bay"
File "..\..\radius\dictionary.bintec"
File "..\..\radius\dictionary.bristol"
File "..\..\radius\dictionary.cablelabs"
File "..\..\radius\dictionary.cabletron"
File "..\..\radius\dictionary.chillispot"
File "..\..\radius\dictionary.cisco"
File "..\..\radius\dictionary.cisco.bbsm"
File "..\..\radius\dictionary.cisco.vpn3000"
File "..\..\radius\dictionary.cisco.vpn5000"
File "..\..\radius\dictionary.clavister"
File "..\..\radius\dictionary.colubris"
File "..\..\radius\dictionary.columbia_university"
File "..\..\radius\dictionary.compat"
File "..\..\radius\dictionary.cosine"
File "..\..\radius\dictionary.dhcp"
File "..\..\radius\dictionary.digium"
File "..\..\radius\dictionary.eltex"
File "..\..\radius\dictionary.epygi"
File "..\..\radius\dictionary.ericsson"
File "..\..\radius\dictionary.erx"
File "..\..\radius\dictionary.extreme"
File "..\..\radius\dictionary.fortinet"
File "..\..\radius\dictionary.foundry"
File "..\..\radius\dictionary.freeradius"
File "..\..\radius\dictionary.freeradius.internal"
File "..\..\radius\dictionary.freeswitch"
File "..\..\radius\dictionary.gandalf"
File "..\..\radius\dictionary.garderos"
File "..\..\radius\dictionary.gemtek"
File "..\..\radius\dictionary.h3c"
File "..\..\radius\dictionary.hp"
File "..\..\radius\dictionary.huawei"
File "..\..\radius\dictionary.iea"
File "..\..\radius\dictionary.infonet"
File "..\..\radius\dictionary.ipunplugged"
File "..\..\radius\dictionary.issanni"
File "..\..\radius\dictionary.itk"
File "..\..\radius\dictionary.jradius"
File "..\..\radius\dictionary.juniper"
File "..\..\radius\dictionary.karlnet"
File "..\..\radius\dictionary.lancom"
File "..\..\radius\dictionary.livingston"
File "..\..\radius\dictionary.localweb"
File "..\..\radius\dictionary.lucent"
File "..\..\radius\dictionary.manzara"
File "..\..\radius\dictionary.merit"
File "..\..\radius\dictionary.microsoft"
File "..\..\radius\dictionary.mikrotik"
File "..\..\radius\dictionary.motorola"
File "..\..\radius\dictionary.motorola.wimax"
File "..\..\radius\dictionary.navini"
File "..\..\radius\dictionary.netscreen"
File "..\..\radius\dictionary.networkphysics"
File "..\..\radius\dictionary.nexans"
File "..\..\radius\dictionary.nokia"
File "..\..\radius\dictionary.nokia.conflict"
File "..\..\radius\dictionary.nomadix"
File "..\..\radius\dictionary.nortel"
File "..\..\radius\dictionary.ntua"
File "..\..\radius\dictionary.openser"
File "..\..\radius\dictionary.packeteer"
File "..\..\radius\dictionary.patton"
File "..\..\radius\dictionary.propel"
File "..\..\radius\dictionary.prosoft"
File "..\..\radius\dictionary.quiconnect"
File "..\..\radius\dictionary.quintum"
File "..\..\radius\dictionary.redback"
File "..\..\radius\dictionary.redcreek"
File "..\..\radius\dictionary.rfc2865"
File "..\..\radius\dictionary.rfc2866"
File "..\..\radius\dictionary.rfc2867"
File "..\..\radius\dictionary.rfc2868"
File "..\..\radius\dictionary.rfc2869"
File "..\..\radius\dictionary.rfc3162"
File "..\..\radius\dictionary.rfc3576"
File "..\..\radius\dictionary.rfc3580"
File "..\..\radius\dictionary.rfc4072"
File "..\..\radius\dictionary.rfc4372"
File "..\..\radius\dictionary.rfc4603"
File "..\..\radius\dictionary.rfc4675"
File "..\..\radius\dictionary.rfc4679"
File "..\..\radius\dictionary.rfc4818"
File "..\..\radius\dictionary.rfc4849"
File "..\..\radius\dictionary.rfc5090"
File "..\..\radius\dictionary.rfc5176"
File "..\..\radius\dictionary.rfc5580"
File "..\..\radius\dictionary.rfc5607"
File "..\..\radius\dictionary.rfc5904"
File "..\..\radius\dictionary.riverstone"
File "..\..\radius\dictionary.roaringpenguin"
File "..\..\radius\dictionary.shasta"
File "..\..\radius\dictionary.shiva"
File "..\..\radius\dictionary.slipstream"
File "..\..\radius\dictionary.sofaware"
File "..\..\radius\dictionary.sonicwall"
File "..\..\radius\dictionary.springtide"
File "..\..\radius\dictionary.starent"
File "..\..\radius\dictionary.t_systems_nova"
File "..\..\radius\dictionary.telebit"
File "..\..\radius\dictionary.telkom"
File "..\..\radius\dictionary.trapeze"
File "..\..\radius\dictionary.tropos"
File "..\..\radius\dictionary.unix"
File "..\..\radius\dictionary.usr"
File "..\..\radius\dictionary.utstarcom"
File "..\..\radius\dictionary.valemount"
File "..\..\radius\dictionary.versanet"
File "..\..\radius\dictionary.vqp"
File "..\..\radius\dictionary.walabi"
File "..\..\radius\dictionary.waverider"
File "..\..\radius\dictionary.wichorus"
File "..\..\radius\dictionary.wimax"
File "..\..\radius\dictionary.wimax.wichorus"
File "..\..\radius\dictionary.wispr"
File "..\..\radius\dictionary.xedia"
File "..\..\radius\dictionary.xylan"
File "..\..\radius\dictionary.zyxel"
SetOutPath $INSTDIR

;
; install the dtds in the dtds subdirectory
;
SetOutPath $INSTDIR\dtds
File "..\..\dtds\dc.dtd"
File "..\..\dtds\itunes.dtd"
File "..\..\dtds\mscml.dtd"
File "..\..\dtds\pocsettings.dtd"
File "..\..\dtds\presence.dtd"
File "..\..\dtds\reginfo.dtd"
File "..\..\dtds\rlmi.dtd"
File "..\..\dtds\rss.dtd"
File "..\..\dtds\smil.dtd"
File "..\..\dtds\xcap-caps.dtd"
File "..\..\dtds\xcap-error.dtd"
File "..\..\dtds\watcherinfo.dtd"
SetOutPath $INSTDIR

; Install the TPNCP DAT file in the "tpncp" subdirectory
; of the installation directory.
SetOutPath $INSTDIR\tpncp
File "..\..\tpncp\tpncp.dat"

;
; install the wimaxasncp TLV definitions in the wimaxasncp subdirectory
;
SetOutPath $INSTDIR\wimaxasncp
File "..\..\wimaxasncp\dictionary.xml"
File "..\..\wimaxasncp\dictionary.dtd"
SetOutPath $INSTDIR

SetOutPath $INSTDIR\help
File "..\..\wireshark-gtk2\help\toc"
File "..\..\wireshark-gtk2\help\overview.txt"
File "..\..\wireshark-gtk2\help\getting_started.txt"
File "..\..\wireshark-gtk2\help\capturing.txt"
File "..\..\wireshark-gtk2\help\capture_filters.txt"
File "..\..\wireshark-gtk2\help\display_filters.txt"
File "..\..\wireshark-gtk2\help\faq.txt"

; Write the uninstall keys for Windows
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" "DisplayVersion" "${VERSION}"
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" "DisplayName" "Wireshark ${VERSION}"
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" "UninstallString" '"$INSTDIR\uninstall.exe"'
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" "Publisher" "The Wireshark developer community, http://www.wireshark.org"
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" "HelpLink" "mailto:wireshark-users@wireshark.org"
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" "URLInfoAbout" "http://www.wireshark.org"
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" "URLUpdateInfo" "http://www.wireshark.org/download/win32/"
WriteRegDWORD HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" "NoModify" 1
WriteRegDWORD HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" "NoRepair" 1
WriteUninstaller "uninstall.exe"

; Write an entry for ShellExecute
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\App Paths\wireshark.exe" "" '$INSTDIR\wireshark.exe'
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\App Paths\wireshark.exe" "Path" '$INSTDIR'

; Create start menu entries (depending on additional tasks page)
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "State"
StrCmp $0 "0" SecRequired_skip_StartMenu
SetOutPath $PROFILE
;CreateDirectory "$SMPROGRAMS\Wireshark"
; To qoute "http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dnwue/html/ch11d.asp":
; "Do not include Readme, Help, or Uninstall entries on the Programs menu."
Delete "$SMPROGRAMS\Wireshark\Wireshark Web Site.lnk"
;WriteINIStr "$SMPROGRAMS\Wireshark\Wireshark Web Site.url" "InternetShortcut" "URL" "http://www.wireshark.org/"
CreateShortCut "$SMPROGRAMS\Wireshark.lnk" "$INSTDIR\wireshark.exe" "" "$INSTDIR\wireshark.exe" 0 "" "" "The Wireshark Network Protocol Analyzer"
;CreateShortCut "$SMPROGRAMS\Wireshark\Wireshark Manual.lnk" "$INSTDIR\wireshark.html"
;CreateShortCut "$SMPROGRAMS\Wireshark\Display Filters Manual.lnk" "$INSTDIR\wireshark-filter.html"
;CreateShortCut "$SMPROGRAMS\Wireshark\Wireshark Program Directory.lnk" "$INSTDIR"
;CreateShortCut "$SMPROGRAMS\Wireshark\Uninstall Wireshark.lnk" "$INSTDIR\uninstall.exe"
SecRequired_skip_StartMenu:

; is command line option "/desktopicon" set?
${GetParameters} $R0
${GetOptions} $R0 "/desktopicon=" $R1
StrCmp $R1 "no" SecRequired_skip_DesktopIcon
StrCmp $R1 "yes" SecRequired_install_DesktopIcon

; Create desktop icon (depending on additional tasks page and command line option)
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "State"
StrCmp $0 "0" SecRequired_skip_DesktopIcon
SecRequired_install_DesktopIcon:
CreateShortCut "$DESKTOP\Wireshark.lnk" "$INSTDIR\wireshark.exe" "" "$INSTDIR\wireshark.exe" 0 "" "" "The Wireshark Network Protocol Analyzer"
SecRequired_skip_DesktopIcon:

; is command line option "/quicklaunchicon" set?
${GetParameters} $R0
${GetOptions} $R0 "/quicklaunchicon=" $R1
StrCmp $R1 "no" SecRequired_skip_QuickLaunchIcon
StrCmp $R1 "yes" SecRequired_install_QuickLaunchIcon

; Create quick launch icon (depending on additional tasks page and command line option)
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "State"
StrCmp $0 "0" SecRequired_skip_QuickLaunchIcon
SecRequired_install_QuickLaunchIcon:
CreateShortCut "$QUICKLAUNCH\Wireshark.lnk" "$INSTDIR\wireshark.exe" "" "$INSTDIR\wireshark.exe" 0 "" "" "The Wireshark Network Protocol Analyzer"
SecRequired_skip_QuickLaunchIcon:

; Create File Extensions (depending on additional tasks page)
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State"
StrCmp $0 "0" SecRequired_skip_FileExtensions
WriteRegStr HKCR ${WIRESHARK_ASSOC} "" "Wireshark capture file"
WriteRegStr HKCR "${WIRESHARK_ASSOC}\Shell\open\command" "" '"$INSTDIR\wireshark.exe" "%1"'
WriteRegStr HKCR "${WIRESHARK_ASSOC}\DefaultIcon" "" '"$INSTDIR\wireshark.exe",1'
push $R0
	StrCpy $R0 ".5vw"
  	Call Associate
	StrCpy $R0 ".acp"
  	Call Associate
  	StrCpy $R0 ".apc"
  	Call Associate
  	StrCpy $R0 ".atc"
  	Call Associate
  	StrCpy $R0 ".bfr"
  	Call Associate
	StrCpy $R0 ".cap"
  	Call Associate
	StrCpy $R0 ".enc"
  	Call Associate
  	StrCpy $R0 ".erf"
  	Call Associate
  	StrCpy $R0 ".fdc"
  	Call Associate
  	StrCpy $R0 ".pcap"
  	Call Associate
  	StrCpy $R0 ".pcapng"
  	Call Associate
  	StrCpy $R0 ".pkt"
  	Call Associate
  	StrCpy $R0 ".snoop"
  	Call Associate
	StrCpy $R0 ".syc"
  	Call Associate
  	StrCpy $R0 ".tpc"
  	Call Associate
  	StrCpy $R0 ".tr1"
  	Call Associate
  	StrCpy $R0 ".trace"
  	Call Associate
	StrCpy $R0 ".trc"
  	Call Associate
  	StrCpy $R0 ".wpc"
  	Call Associate
  	StrCpy $R0 ".wpz"
  	Call Associate
  	StrCpy $R0 ".rf5"
  	Call Associate
; if somethings added here, add it also to the uninstall section and the AdditionalTask page
pop $R0
!insertmacro UpdateIcons
SecRequired_skip_FileExtensions:

; if running as a silent installer, don't try to install winpcap
IfSilent SecRequired_skip_Winpcap

; Install WinPcap (depending on winpcap page setting)
ReadINIStr $0 "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "State"
StrCmp $0 "0" SecRequired_skip_Winpcap
; Uinstall old WinPcap first
ReadRegStr $WINPCAP_UNINSTALL HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "UninstallString"
IfErrors lbl_winpcap_notinstalled ;if RegKey is unavailable, WinPcap is not installed
; from released version 3.1, WinPcap will uninstall an old version by itself
;ExecWait '$WINPCAP_UNINSTALL' $0
;DetailPrint "WinPcap uninstaller returned $0"
lbl_winpcap_notinstalled:
SetOutPath $INSTDIR
File "WinPcap_4_1_2.exe"
ExecWait '"$INSTDIR\WinPcap_4_1_2.exe"' $0
DetailPrint "WinPcap installer returned $0"
SecRequired_skip_Winpcap:

; If no user profile exists for Wireshark but for Ethereal, copy it over
SetShellVarContext current
IfFileExists $APPDATA\Wireshark profile_done
IfFileExists $APPDATA\Ethereal 0 profile_done
;MessageBox MB_YESNO "This seems to be the first time you use Wireshark. Copy over the personal settings from Ethereal?" /SD IDYES IDNO profile_done
CreateDirectory $APPDATA\Wireshark
CopyFiles $APPDATA\Ethereal\*.* $APPDATA\Wireshark
profile_done:
SetShellVarContext all

SectionEnd ; "Required"

!ifdef GTK_DIR
Section "Wireshark" SecWireshark
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\wireshark.exe"
File "${GTK_DIR}\bin\libgdk-win32-2.0-0.dll"
File "${GTK_DIR}\bin\libgdk_pixbuf-2.0-0.dll"
File "${GTK_DIR}\bin\libgtk-win32-2.0-0.dll"
File "${GTK_DIR}\bin\libatk-1.0-0.dll"
File "${GTK_DIR}\bin\libpango-1.0-0.dll"
File "${GTK_DIR}\bin\libpangowin32-1.0-0.dll"
!ifdef NEED_CAIRO_DLL
File "${GTK_DIR}\bin\libcairo-2.dll"
File "${GTK_DIR}\bin\libpangocairo-1.0-0.dll"
!endif
!ifdef NEED_LIBPNG_DLL
File "${GTK_DIR}\bin\${PNG_DLL}"
!endif
!ifdef NEED_LIBTIFF_DLL
File "${GTK_DIR}\bin\${TIFF_DLL}"
!endif
!ifdef NEED_LIBJPEG_DLL
File "${GTK_DIR}\bin\${JPEG_DLL}"
!endif
!ifdef NEED_FREETYPE_DLL
File "${GTK_DIR}\bin\libpangoft2-1.0-0.dll"
File "${GTK_DIR}\bin\${FREETYPE_DLL}"
!endif
!ifdef NEED_FONTCONFIG_DLL
File "${GTK_DIR}\bin\${FONTCONFIG_DLL}"
!endif
!ifdef NEED_EXPAT_DLL
File "${GTK_DIR}\bin\${EXPAT_DLL}"
!endif
SetOutPath $INSTDIR\etc\gtk-2.0
File "${GTK_DIR}\etc\gtk-2.0\*.*"

!if ${WIRESHARK_TARGET_PLATFORM} == "win32"
SetOutPath $INSTDIR\etc\pango
File "${GTK_DIR}\etc\pango\pango.*"
; Not needed for GTK+ >= 2.18
;SetOutPath $INSTDIR\lib\gtk-2.0\${GTK_LIB_DIR}\loaders
;File "${GTK_DIR}\lib\gtk-2.0\${GTK_LIB_DIR}\loaders\libpixbufloader-*.dll"
!endif

SetOutPath $INSTDIR\lib\gtk-2.0\${GTK_LIB_DIR}\engines
File "${GTK_DIR}\lib\gtk-2.0\${GTK_LIB_DIR}\engines\libpixmap.dll"
SetOutPath $INSTDIR\lib\gtk-2.0\modules
File "${GTK_DIR}\lib\gtk-2.0\modules\libgail.dll"

; GTK MS-Windows Engine (GTK-Wimp)
SetOutPath $INSTDIR\${GTK_WIMP_DLLDST_DIR}
File "${GTK_WIMP_DLLSRC_DIR}\libwimp.dll"
SetOutPath $INSTDIR\${GTK_WIMP_RCDST_DIR}
File "${GTK_WIMP_RCSRC_DIR}\gtkrc"

SectionEnd ; "Wireshark"
!endif


Section "TShark" SecTShark
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\tshark.exe"
File "..\..\doc\tshark.html"
SectionEnd

SectionGroup "Plugins / Extensions" SecPluginsGroup

Section "Dissector Plugins" SecPlugins
;-------------------------------------------
SetOutPath '$INSTDIR\plugins\${VERSION}'
File "..\..\plugins\asn1\asn1.dll"
File "..\..\plugins\docsis\docsis.dll"
File "..\..\plugins\ethercat\ethercat.dll"
File "..\..\plugins\giop\coseventcomm.dll"
File "..\..\plugins\giop\cosnaming.dll"
File "..\..\plugins\giop\parlay.dll"
File "..\..\plugins\giop\tango.dll"
File "..\..\plugins\gryphon\gryphon.dll"
File "..\..\plugins\interlink\interlink.dll"
File "..\..\plugins\irda\irda.dll"
File "..\..\plugins\m2m\m2m.dll"
File "..\..\plugins\opcua\opcua.dll"
File "..\..\plugins\profinet\profinet.dll"
File "..\..\plugins\sercosiii\sercosiii.dll"
File "..\..\plugins\unistim\unistim.dll"
File "..\..\plugins\wimax\wimax.dll"
File "..\..\plugins\wimaxasncp\wimaxasncp.dll"
!include "custom_plugins.txt"
SectionEnd

Section "Tree Statistics Plugin" SecStatsTree
;-------------------------------------------
SetOutPath '$INSTDIR\plugins\${VERSION}'
File "..\..\plugins\stats_tree\stats_tree.dll"
SectionEnd

Section "Mate - Meta Analysis and Tracing Engine" SecMate
;-------------------------------------------
SetOutPath '$INSTDIR\plugins\${VERSION}'
File "..\..\plugins\mate\mate.dll"
SectionEnd


!ifdef NET_SNMP_DIR
Section "SNMP MIBs" SecMIBs
;-------------------------------------------
SetOutPath $INSTDIR\snmp\mibs
File "${NET_SNMP_DIR}\mibs\*.txt"
SectionEnd
!endif

!ifdef SMI_DIR
Section "SNMP MIBs" SecMIBs
;-------------------------------------------
SetOutPath $INSTDIR\snmp\mibs
File "${SMI_DIR}\mibs\*"
SectionEnd
!endif

SectionGroupEnd	; "Plugins / Extensions"


SectionGroup "Tools" SecToolsGroup

Section "Editcap" SecEditcap
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\editcap.exe"
File "..\..\doc\editcap.html"
SectionEnd

Section "Text2Pcap" SecText2Pcap
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\text2pcap.exe"
File "..\..\doc\text2pcap.html"
SectionEnd

Section "Mergecap" SecMergecap
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\mergecap.exe"
File "..\..\doc\mergecap.html"
SectionEnd

Section "Capinfos" SecCapinfos
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\capinfos.exe"
File "..\..\doc\capinfos.html"
SectionEnd

Section "Rawshark" SecRawshark
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\rawshark.exe"
File "..\..\doc\rawshark.html"
SectionEnd

SectionGroupEnd	; "Tools"

!ifdef HHC_DIR
Section "User's Guide" SecUsersGuide
;-------------------------------------------
SetOutPath $INSTDIR
File "user-guide.chm"
SectionEnd
!endif

Section "Uninstall" un.SecUinstall
;-------------------------------------------

;
; UnInstall for every user
;
SectionIn 1 2
SetShellVarContext all

Delete "$INSTDIR\rawshark.exe"
IfErrors 0 NoRawsharkErrorMsg
	MessageBox MB_OK "Please note: rawshark.exe could not be removed, it's probably in use!" IDOK 0 ;skipped if rawshark.exe removed
	Abort "Please note: rawshark.exe could not be removed, it's probably in use! Abort uninstall process!"
NoRawsharkErrorMsg:

Delete "$INSTDIR\tshark.exe"
IfErrors 0 NoTSharkErrorMsg
	MessageBox MB_OK "Please note: tshark.exe could not be removed, it's probably in use!" IDOK 0 ;skipped if tshark.exe removed
	Abort "Please note: tshark.exe could not be removed, it's probably in use! Abort uninstall process!"
NoTSharkErrorMsg:

Delete "$INSTDIR\wireshark.exe"
IfErrors 0 NoWiresharkErrorMsg
	MessageBox MB_OK "Please note: wireshark.exe could not be removed, it's probably in use!" IDOK 0 ;skipped if wireshark.exe removed
	Abort "Please note: wireshark.exe could not be removed, it's probably in use! Abort uninstall process!"
NoWiresharkErrorMsg:

DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark"
DeleteRegKey HKEY_LOCAL_MACHINE "Software\Wireshark"
DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\App Paths\wireshark.exe"

push $R0
	StrCpy $R0 ".5vw"
  	Call un.unlink
	StrCpy $R0 ".acp"
  	Call un.unlink
  	StrCpy $R0 ".apc"
  	Call un.unlink
  	StrCpy $R0 ".atc"
  	Call un.unlink
  	StrCpy $R0 ".bfr"
  	Call un.unlink
	StrCpy $R0 ".cap"
  	Call un.unlink
	StrCpy $R0 ".enc"
  	Call un.unlink
  	StrCpy $R0 ".erf"
  	Call un.unlink
  	StrCpy $R0 ".fdc"
  	Call un.unlink
  	StrCpy $R0 ".pcap"
  	Call un.unlink
  	StrCpy $R0 ".pkt"
  	Call un.unlink
  	StrCpy $R0 ".snoop"
  	Call un.unlink
	StrCpy $R0 ".syc"
  	Call un.unlink
  	StrCpy $R0 ".tpc"
  	Call un.unlink
  	StrCpy $R0 ".tr1"
  	Call un.unlink
  	StrCpy $R0 ".trace"
  	Call un.unlink
	StrCpy $R0 ".trc"
  	Call un.unlink
  	StrCpy $R0 ".wpc"
  	Call un.unlink
  	StrCpy $R0 ".wpz"
  	Call un.unlink
  	StrCpy $R0 ".rf5"
  	Call un.unlink
pop $R0

DeleteRegKey HKCR ${WIRESHARK_ASSOC}
DeleteRegKey HKCR "${WIRESHARK_ASSOC}\Shell\open\command"
DeleteRegKey HKCR "${WIRESHARK_ASSOC}\DefaultIcon"
!insertmacro UpdateIcons

Delete "$INSTDIR\etc\gtk-2.0\*.*"
Delete "$INSTDIR\etc\pango\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.2.0\engines\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.2.0\loaders\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.2.0\immodules\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.4.0\engines\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.4.0\loaders\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.4.0\immodules\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.10.0\engines\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.10.0\loaders\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\*.*"
Delete "$INSTDIR\lib\gtk-2.0\modules\*.*"
Delete "$INSTDIR\lib\pango\1.2.0\modules\*.*"
Delete "$INSTDIR\lib\pango\1.4.0\modules\*.*"
Delete "$INSTDIR\lib\pango\1.5.0\modules\*.*"
Delete "$INSTDIR\share\themes\Default\gtk-2.0\*.*"
Delete "$INSTDIR\help\*.*"
Delete "$INSTDIR\diameter\*.*"
Delete "$INSTDIR\snmp\mibs\*.*"
Delete "$INSTDIR\snmp\*.*"
Delete "$INSTDIR\tpncp\*.*"
Delete "$INSTDIR\wimaxasncp\*.*"
Delete "$INSTDIR\*.exe"
Delete "$INSTDIR\*.dll"
Delete "$INSTDIR\*.html"
Delete "$INSTDIR\ws.css"
Delete "$INSTDIR\COPYING*"
Delete "$INSTDIR\AUTHORS-SHORT"
; previous versions installed these files
Delete "$INSTDIR\*.manifest"
; previous versions installed this file
Delete "$INSTDIR\AUTHORS-SHORT-FORMAT"
Delete "$INSTDIR\README*"
Delete "$INSTDIR\NEWS.txt"
Delete "$INSTDIR\manuf"
Delete "$INSTDIR\services"
Delete "$INSTDIR\pdml2html.xsl"
Delete "$INSTDIR\pcrepattern.3.txt"
Delete "$INSTDIR\user-guide.chm"
Delete "$INSTDIR\example_snmp_users_file"
Delete "$INSTDIR\ipmap.html"
Delete "$INSTDIR\radius\*.*"
Delete "$INSTDIR\dtds\*.*"
Delete "$SMPROGRAMS\Wireshark\*.*"
Delete "$SMPROGRAMS\Wireshark.lnk"
Delete "$DESKTOP\Wireshark.lnk"
Delete "$QUICKLAUNCH\Wireshark.lnk"

RMDir "$INSTDIR\etc\gtk-2.0"
RMDir "$INSTDIR\etc\pango"
RMDir "$INSTDIR\etc"
RMDir "$INSTDIR\lib\gtk-2.0\2.2.0\engines"
RMDir "$INSTDIR\lib\gtk-2.0\2.2.0\loaders"
RMDir "$INSTDIR\lib\gtk-2.0\2.2.0\immodules"
RMDir "$INSTDIR\lib\gtk-2.0\2.2.0"
RMDir "$INSTDIR\lib\gtk-2.0\2.4.0\engines"
RMDir "$INSTDIR\lib\gtk-2.0\2.4.0\loaders"
RMDir "$INSTDIR\lib\gtk-2.0\2.4.0\immodules"
RMDir "$INSTDIR\lib\gtk-2.0\2.4.0"
RMDir "$INSTDIR\lib\gtk-2.0\2.10.0\engines"
RMDir "$INSTDIR\lib\gtk-2.0\2.10.0\loaders"
RMDir "$INSTDIR\lib\gtk-2.0\2.10.0\immodules"
RMDir "$INSTDIR\lib\gtk-2.0\2.10.0"
RMDir "$INSTDIR\lib\gtk-2.0\modules"
RMDir "$INSTDIR\lib\gtk-2.0"
RMDir "$INSTDIR\lib\pango\1.2.0\modules"
RMDir "$INSTDIR\lib\pango\1.2.0"
RMDir "$INSTDIR\lib\pango\1.4.0\modules"
RMDir "$INSTDIR\lib\pango\1.4.0"
RMDir "$INSTDIR\lib\pango\1.5.0\modules"
RMDir "$INSTDIR\lib\pango\1.5.0"
RMDir "$INSTDIR\lib\pango"
RMDir "$INSTDIR\lib"
RMDir "$INSTDIR\share\themes\Default\gtk-2.0"
RMDir "$INSTDIR\share\themes\Default"
RMDir "$INSTDIR\share\themes"
RMDir "$INSTDIR\share"
RMDir "$SMPROGRAMS\Wireshark"
RMDir "$INSTDIR\help"
RMDir "$INSTDIR\diameter"
RMDir "$INSTDIR\snmp\mibs"
RMDir "$INSTDIR\snmp"
RMDir "$INSTDIR\radius"
RMDir "$INSTDIR\dtds"
RMDir "$INSTDIR\tpncp"
RMDir "$INSTDIR\wimaxasncp"
RMDir "$INSTDIR"

SectionEnd ; "Uinstall"

Section "Un.Plugins" un.SecPlugins
;-------------------------------------------
SectionIn 1 2
;Delete "$INSTDIR\plugins\${VERSION}\*.*"
;Delete "$INSTDIR\plugins\*.*"
;RMDir "$INSTDIR\plugins\${VERSION}"
;RMDir "$INSTDIR\plugins"
RMDir /r "$INSTDIR\plugins"
SectionEnd

Section "Un.Global Settings" un.SecGlobalSettings
;-------------------------------------------
SectionIn 1 2
Delete "$INSTDIR\cfilters"
Delete "$INSTDIR\colorfilters"
Delete "$INSTDIR\dfilters"
Delete "$INSTDIR\init.lua"
Delete "$INSTDIR\console.lua"
Delete "$INSTDIR\dtd_gen.lua"
Delete "$INSTDIR\smi_modules"
RMDir "$INSTDIR"
SectionEnd

Section /o "Un.Personal Settings" un.SecPersonalSettings
;-------------------------------------------
SectionIn 2
SetShellVarContext current
Delete "$APPDATA\Wireshark\*.*"
RMDir "$APPDATA\Wireshark"
SectionEnd

;VAR un.WINPCAP_UNINSTALL

Section /o "Un.WinPcap" un.SecWinPcap
;-------------------------------------------
SectionIn 2
ReadRegStr $1 HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "UninstallString"
;IfErrors un.lbl_winpcap_notinstalled ;if RegKey is unavailable, WinPcap is not installed
;MessageBox MB_OK "WinPcap $1"
ExecWait '$1' $0
DetailPrint "WinPcap uninstaller returned $0"
;SetRebootFlag true
;un.lbl_winpcap_notinstalled:
SectionEnd

Section "-Un.Finally"
;-------------------------------------------
SectionIn 1 2
; this test must be done after all other things uninstalled (e.g. Global Settings)
IfFileExists "$INSTDIR" 0 NoFinalErrorMsg
    MessageBox MB_OK "Please note: The directory $INSTDIR could not be removed!" IDOK 0 ; skipped if dir doesn't exist
NoFinalErrorMsg:
SectionEnd


; ============================================================================
; PLEASE MAKE SURE, THAT THE DESCRIPTIVE TEXT FITS INTO THE DESCRIPTION FIELD!
; ============================================================================
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!ifdef GTK_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecWireshark} "${PROGRAM_NAME} is a GUI network protocol analyzer."
!endif
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTShark} "TShark is a text based network protocol analyzer."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPluginsGroup} "Some plugins and extensions for both Wireshark and TShark."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPlugins} "Plugins with some extended dissections."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStatsTree} "Plugin for some extended statistics."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMate} "Plugin - Meta Analysis and Tracing Engine (Experimental)."
!ifdef NET_SNMP_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMIBs} "SNMP MIBs for better SNMP dissection."
!endif
!ifdef SMI_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMIBs} "SNMP MIBs for better SNMP dissection."
!endif
  !insertmacro MUI_DESCRIPTION_TEXT ${SecToolsGroup} "Additional command line based tools."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecEditCap} "Editcap is a program that reads a capture file and writes some or all of the packets into another capture file."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecText2Pcap} "Text2pcap is a program that reads in an ASCII hex dump and writes the data into a libpcap-style capture file."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMergecap} "Mergecap is a program that combines multiple saved capture files into a single output file"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCapinfos} "Capinfos is a program that provides information on capture files."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecRawshark} "Rawshark is a raw packet filter."
!ifdef HHC_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecUsersGuide} "Install the user's guide, so an internet connection is not required to read the help pages."
!endif
!insertmacro MUI_FUNCTION_DESCRIPTION_END

!insertmacro MUI_UNFUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecUinstall} "Uninstall all Wireshark components."
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecPlugins} "Uninstall all Plugins (even from previous Wireshark versions)."
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecGlobalSettings} "Uninstall global settings like: $INSTDIR\cfilters"
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecPersonalSettings} "Uninstall personal settings like your preferences file from your profile: $PROFILE."
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecWinPcap} "Call WinPcap's uninstall program."
!insertmacro MUI_UNFUNCTION_DESCRIPTION_END

; ============================================================================
; Callback functions
; ============================================================================
!ifdef GTK_DIR
; Disable File extensions if Wireshark isn't selected
Function .onSelChange
	Push $0
	SectionGetFlags ${SecWireshark} $0
	IntOp  $0 $0 & 1
	IntCmp $0 0 onSelChange.unselect
	WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" 1
	WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "Flags" ""
	WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "Flags" ""
	Goto onSelChange.end

onSelChange.unselect:
	WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" 0
	WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "Flags" "DISABLED"
	WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "Flags" "DISABLED"
	Goto onSelChange.end

onSelChange.end:
	Pop $0
FunctionEnd
!endif


!include "GetWindowsVersion.nsh"
!include WinMessages.nsh
!include "VersionCompare.nsh"

Var WINPCAP_NAME ; DisplayName from WinPcap installation
Var WINPCAP_VERSION ; DisplayVersion from WinPcap installation

Function myShowCallback

	; Get the Windows version
	Call GetWindowsVersion
	Pop $R0 ; Windows Version

	; Check if we're able to run with this version
	StrCmp $R0 '95' lbl_winversion_unsupported
	StrCmp $R0 '98' lbl_winversion_unsupported
	StrCmp $R0 'ME' lbl_winversion_unsupported
	StrCmp $R0 'NT 4.0' lbl_winversion_unsupported_nt4
	StrCmp $R0 '2000' lbl_winversion_unsupported_2000
	Goto lbl_winversion_supported
lbl_winversion_unsupported:
	MessageBox MB_OK \
            "Windows $R0 is no longer supported. The last known version working with 98/ME was Ethereal 0.99.0." \
            /SD IDOK
	Quit

lbl_winversion_unsupported_nt4:
	MessageBox MB_OK \
            "Windows $R0 is no longer supported. The last known version working with NT 4.0 was Wireshark 0.99.4." \
            /SD IDOK
	Quit

lbl_winversion_unsupported_2000:
	MessageBox MB_OK \
            "Windows $R0 is no longer supported. Please install Wireshark 1.2 or 1.0." \
            /SD IDOK
	Quit

lbl_winversion_supported:
	; detect if WinPcap should be installed
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "Text" "Install WinPcap 4.1.2"
	ReadRegStr $WINPCAP_NAME HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "DisplayName"
	IfErrors 0 lbl_winpcap_installed ;if RegKey is available, WinPcap is already installed
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 2" "Text" "WinPcap is currently not installed"
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 2" "Flags" "DISABLED"
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 5" "Text" "(Use Add/Remove Programs first to uninstall any undetected old WinPcap versions)"
	Goto lbl_winpcap_done

lbl_winpcap_installed:
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 2" "Text" "$WINPCAP_NAME"
	; Compare the installed build against the one we have.
	ReadRegStr $WINPCAP_VERSION HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "DisplayVersion"
	StrCmp $WINPCAP_VERSION "" lbl_winpcap_do_install ; WinPcap is really old(?) or installed improperly.
	${VersionCompare} $WINPCAP_VERSION "4.1.0.2001" $1 ; WinPcap 4.1.2
	StrCmp $1 "2" lbl_winpcap_do_install

;lbl_winpcap_dont_install:
	; The installed version is >= to what we have, so don't install
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "State" "0"
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 5" "Text" "If selected, the currently installed $WINPCAP_NAME will be uninstalled first."
	Goto lbl_winpcap_done

;lbl_winpcap_dont_upgrade:
	; force the user to upgrade by hand
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "State" "0"
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "Flags" "DISABLED"
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 5" "Text" "If you wish to install WinPcap 4.1.2, please uninstall $WINPCAP_NAME manually first."
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 5" "Flags" "DISABLED"
	Goto lbl_winpcap_done

lbl_winpcap_do_install:
	; seems to be an old version, install newer one
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "State" "1"
	WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 5" "Text" "The currently installed $WINPCAP_NAME will be uninstalled first."

lbl_winpcap_done:

	; if Wireshark was previously installed, unselect previously not installed icons etc.
	; detect if Wireshark is already installed ->
	ReadRegStr $0 HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" "UninstallString"
	IfErrors lbl_wireshark_notinstalled ;if RegKey is unavailable, Wireshark is not installed

	; only select Start Menu Group, if previously installed
	; (we use the "all users" start menu, so select it first)
	SetShellVarContext all
	IfFileExists "$SMPROGRAMS\Wireshark\Wireshark.lnk" lbl_have_startmenu
	IfFileExists "$SMPROGRAMS\Wireshark.lnk" lbl_have_startmenu
	WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "State" "0"
lbl_have_startmenu:

	; only select Desktop Icon, if previously installed
	IfFileExists "$DESKTOP\Wireshark.lnk" lbl_have_desktopicon
	WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "State" "0"
lbl_have_desktopicon:

	; only select Quick Launch Icon, if previously installed
	IfFileExists "$QUICKLAUNCH\Wireshark.lnk" lbl_have_quicklaunchicon
	WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "State" "0"
lbl_have_quicklaunchicon:

lbl_wireshark_notinstalled:


FunctionEnd
