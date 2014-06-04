;
; wireshark.nsi
;

; Set the compression mechanism first.
; As of NSIS 2.07, solid compression which makes installer about 1MB smaller
; is no longer the default, so use the /SOLID switch.
; This unfortunately is unknown to NSIS prior to 2.07 and creates an error.
; So if you get an error here, please update to at least NSIS 2.07!
SetCompressor /SOLID lzma
SetCompressorDictSize 64 ; MB

!include "common.nsh"
!include 'LogicLib.nsh'

; ============================================================================
; Header configuration
; ============================================================================

; The file to write
OutFile "${PROGRAM_NAME}-${WIRESHARK_TARGET_PLATFORM}-${VERSION}.exe"
; Installer icon
Icon "..\..\image\wiresharkinst.ico"

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
BrandingText "Wireshark Installer (tm)"

!define MUI_COMPONENTSPAGE_SMALLDESC
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of ${PROGRAM_NAME}.\r\n\r\nBefore starting the installation, make sure ${PROGRAM_NAME} is not running.\r\n\r\nClick 'Next' to continue."
;!define MUI_FINISHPAGE_LINK "Install WinPcap to be able to capture packets from a network."
;!define MUI_FINISHPAGE_LINK_LOCATION "http://www.winpcap.org"

; NSIS shows Readme files by opening the Readme file with the default application for
; the file's extension. "README.win32" won't work in most cases, because extension "win32"
; is usually not associated with an appropriate text editor. We should use extension "txt"
; for a text file or "html" for an html README file.
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\NEWS.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Show News"
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
!define MUI_FINISHPAGE_RUN "$INSTDIR\${PROGRAM_NAME_PATH_GTK}"
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

; ============================================================================
; Directory selection page configuration
; ============================================================================
; The text to prompt the user to enter a directory
DirText "Choose a directory in which to install ${PROGRAM_NAME}."

; The default installation directory
!if ${WIRESHARK_TARGET_PLATFORM} == "win64"
  InstallDir $PROGRAMFILES64\${PROGRAM_NAME}
!else
  InstallDir $PROGRAMFILES\${PROGRAM_NAME}
!endif

; See if this is an upgrade; if so, use the old InstallDir as default
InstallDirRegKey HKEY_LOCAL_MACHINE SOFTWARE\${PROGRAM_NAME} "InstallDir"


; ============================================================================
; Install page configuration
; ============================================================================
ShowInstDetails show

; ============================================================================
; Functions and macros
; ============================================================================

Var EXTENSION
; http://msdn.microsoft.com/en-us/library/windows/desktop/cc144148.aspx
Function Associate
    Push $R0
!insertmacro PushFileExtensions

    Pop $EXTENSION

    ${DoUntil} $EXTENSION == ${FILE_EXTENSION_MARKER}
        ReadRegStr $R0 HKCR $EXTENSION ""
        StrCmp $R0 "" Associate.doRegister
        Goto Associate.end

Associate.doRegister:
        ;The extension is not associated to any program, we can do the link
        WriteRegStr HKCR $EXTENSION "" ${WIRESHARK_ASSOC}
        DetailPrint "Registered file type: $EXTENSION"

Associate.end:
        Pop $EXTENSION
    ${Loop}

    Pop $R0
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
      MessageBox MB_OK "This version of Wireshark only runs on x64 machines.$\nTry installing the 32-bit version instead." /SD IDOK
      Abort
    ${EndIf}
  !endif

!insertmacro IsWiresharkRunning

  ; Copied from http://nsis.sourceforge.net/Auto-uninstall_old_before_installing_new
  ReadRegStr $OLD_UNINSTALLER HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" \
    "UninstallString"
  StrCmp $OLD_UNINSTALLER "" done

  ReadRegStr $OLD_INSTDIR HKLM \
    "Software\Microsoft\Windows\CurrentVersion\App Paths\${PROGRAM_NAME}.exe" \
    "Path"
  StrCmp $OLD_INSTDIR "" done

  ReadRegStr $OLD_DISPLAYNAME HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}" \
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
  StrCpy $TMP_UNINSTALLER "$TEMP\${PROGRAM_NAME}_uninstaller.exe"
  ; ...because we surround UninstallString in quotes.
  StrCpy $0 $OLD_UNINSTALLER -1 1
  StrCpy $1 "$TEMP\${PROGRAM_NAME}_uninstaller.exe"
  StrCpy $2 1
  System::Call 'kernel32::CopyFile(t r0, t r1, b r2) 1'
  ExecWait "$TMP_UNINSTALLER /S _?=$OLD_INSTDIR"

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

!ifdef VCREDIST_EXE
Var VCREDIST_FLAGS ; silent vs passive, norestart
!endif

Section "-Required"
;-------------------------------------------

;
; Install for every user
;
SetShellVarContext all


SetOutPath $INSTDIR
File "${STAGING_DIR}\${UNINSTALLER_NAME}"
File "${STAGING_DIR}\wiretap-${WTAP_VERSION}.dll"
!ifdef ENABLE_LIBWIRESHARK
File "${STAGING_DIR}\libwireshark.dll"
!endif
File "${STAGING_DIR}\libwsutil.dll"
File "${STAGING_DIR}\libgio-2.0-0.dll"
File "${STAGING_DIR}\libglib-2.0-0.dll"
File "${STAGING_DIR}\libgobject-2.0-0.dll"
File "${STAGING_DIR}\libgmodule-2.0-0.dll"
File "${STAGING_DIR}\libgthread-2.0-0.dll"
!ifdef ICONV_DIR
File "${STAGING_DIR}\iconv.dll"
!endif
File "${STAGING_DIR}\${INTL_DLL}"
!ifdef ZLIB_DIR
File "${STAGING_DIR}\zlib1.dll"
!endif
!ifdef C_ARES_DIR
File "${STAGING_DIR}\libcares-2.dll"
!endif
!ifdef ADNS_DIR
File "${STAGING_DIR}\adns_dll.dll"
!endif
!ifdef KFW_DIR
File "${STAGING_DIR}\comerr32.dll"
File "${STAGING_DIR}\krb5_32.dll"
File "${STAGING_DIR}\k5sprt32.dll"
!endif
!ifdef GNUTLS_DIR
File "${STAGING_DIR}\libffi-6.dll"
File "${STAGING_DIR}\${GCC_DLL}"
File "${STAGING_DIR}\libgcrypt-20.dll"
File "${STAGING_DIR}\libgmp-10.dll"
File "${STAGING_DIR}\libgnutls-28.dll"
File "${STAGING_DIR}\${GPGERROR_DLL}"
File "${STAGING_DIR}\libhogweed-2-4.dll"
File "${STAGING_DIR}\libnettle-4-6.dll"
File "${STAGING_DIR}\libp11-kit-0.dll"
File "${STAGING_DIR}\libtasn1-6.dll"
StrCmp "${INTL_DLL}" "libintl-8.dll" SkipLibIntl8
File "${STAGING_DIR}\libintl-8.dll"
SkipLibIntl8:
!endif
!ifdef LUA_DIR
File "${STAGING_DIR}\lua52.dll"
File "..\..\epan\wslua\init.lua"
File "..\..\epan\wslua\console.lua"
File "..\..\epan\wslua\dtd_gen.lua"
!endif
!ifdef SMI_DIR
File "${STAGING_DIR}\libsmi-2.dll"
!endif
!ifdef GEOIP_DIR
File "${STAGING_DIR}\libGeoIP-1.dll"
!endif
!ifdef WINSPARKLE_DIR
File "${STAGING_DIR}\WinSparkle.dll"
!endif
File "${STAGING_DIR}\COPYING.txt"
File "${STAGING_DIR}\NEWS.txt"
File "${STAGING_DIR}\README.txt"
File "${STAGING_DIR}\README.windows.txt"
File "..\..\doc\AUTHORS-SHORT"
File "..\..\manuf"
File "..\..\services"
File "..\..\pdml2html.xsl"
File "..\..\doc\ws.css"
File "..\..\doc\wireshark.html"
File "..\..\doc\wireshark-filter.html"
File "${STAGING_DIR}\dumpcap.exe"
File "..\..\doc\dumpcap.html"
File "..\..\ipmap.html"

; C-runtime redistributable
!ifdef VCREDIST_EXE
; vcredist_x86.exe (MSVC V8) - copy and execute the redistributable installer
File "${VCREDIST_EXE}"
; If the user already has the redistributable installed they will see a
; Big Ugly Dialog by default, asking if they want to uninstall or repair.
; Ideally we should add a checkbox for this somewhere. In the meantime,
; just do a "passive+norestart" install for MSVC 2010 and later and a
; "silent" install otherwise.

; http://blogs.msdn.com/b/astebner/archive/2010/10/20/10078468.aspx
; "!if ${MSVC_VER_REQUIRED} >= 1600" doesn't work.
!searchparse /noerrors ${MSVC_VER_REQUIRED} "1400" VCREDIST_OLD_FLAGS "1500" VCREDIST_OLD_FLAGS
!ifdef VCREDIST_OLD_FLAGS
StrCpy $VCREDIST_FLAGS "/q"
!else ; VCREDIST_OLD_FLAGS
StrCpy $VCREDIST_FLAGS "/q /norestart"
!endif ; VCREDIST_OLD_FLAGS

ExecWait '"$INSTDIR\vcredist_${TARGET_MACHINE}.exe" $VCREDIST_FLAGS' $0
DetailPrint "vcredist_${TARGET_MACHINE} returned $0"
IntCmp $0 3010 redistReboot redistNoReboot
redistReboot:
SetRebootFlag true
redistNoReboot:
Delete "$INSTDIR\vcredist_${TARGET_MACHINE}.exe"
!else
!ifdef MSVCR_DLL
; msvcr*.dll (MSVC V7 or V7.1) - simply copy the dll file
!echo "IF YOU GET AN ERROR HERE, check the MSVC_VARIANT setting in config.nmake: MSVC2005 vs. MSVC2005EE."
File "${MSVCR_DLL}"
!else
!if ${MSVC_VARIANT} != "MSVC6"
!error "C-Runtime redistributable for this package not available / not redistributable."
!endif
!endif ; MSVCR_DLL
!endif ; VCREDIST_EXE


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
File "..\..\diameter\AlcatelLucent.xml"
File "..\..\diameter\chargecontrol.xml"
File "..\..\diameter\ChinaTelecom.xml"
File "..\..\diameter\Cisco.xml"
File "..\..\diameter\Custom.xml"
File "..\..\diameter\dictionary.dtd"
File "..\..\diameter\dictionary.xml"
File "..\..\diameter\eap.xml"
File "..\..\diameter\Ericsson.xml"
File "..\..\diameter\etsie2e4.xml"
File "..\..\diameter\gqpolicy.xml"
File "..\..\diameter\imscxdx.xml"
File "..\..\diameter\SKT.xml"
File "..\..\diameter\mobileipv4.xml"
File "..\..\diameter\mobileipv6.xml"
File "..\..\diameter\nasreq.xml"
File "..\..\diameter\Nokia.xml"
File "..\..\diameter\NokiaSiemensNetworks.xml"
File "..\..\diameter\sip.xml"
File "..\..\diameter\Starent.xml"
File "..\..\diameter\sunping.xml"
File "..\..\diameter\TGPPGmb.xml"
File "..\..\diameter\TGPPRx.xml"
File "..\..\diameter\TGPPS9.xml"
File "..\..\diameter\TGPPSh.xml"
File "..\..\diameter\VerizonWireless.xml"
File "..\..\diameter\Vodafone.xml"
!include "custom_diameter_xmls.txt"
SetOutPath $INSTDIR

;
; Install the RADIUS directory files in the "radius" subdirectory
; of the installation directory.
;
SetOutPath $INSTDIR\radius
File "..\..\radius\README.radius_dictionary"
File "..\..\radius\custom.includes"
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
File "..\..\radius\dictionary.alcatel-lucent.aaa"
File "..\..\radius\dictionary.alcatel-lucent.xylan"
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
File "..\..\radius\dictionary.rfc5447"
File "..\..\radius\dictionary.rfc5580"
File "..\..\radius\dictionary.rfc5607"
File "..\..\radius\dictionary.rfc5904"
File "..\..\radius\dictionary.rfc6519"
File "..\..\radius\dictionary.rfc6572"
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
File "..\..\radius\dictionary.ukerna"
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
File "..\..\radius\dictionary.zyxel"
!include "custom_radius_dict.txt"
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
File "${STAGING_DIR}\help\toc"
File "${STAGING_DIR}\help\overview.txt"
File "${STAGING_DIR}\help\getting_started.txt"
File "${STAGING_DIR}\help\capturing.txt"
File "${STAGING_DIR}\help\capture_filters.txt"
File "${STAGING_DIR}\help\display_filters.txt"
File "${STAGING_DIR}\help\faq.txt"

; Write the uninstall keys for Windows
; http://nsis.sourceforge.net/Add_uninstall_information_to_Add/Remove_Programs
; http://msdn.microsoft.com/en-us/library/ms954376.aspx
; http://msdn.microsoft.com/en-us/library/windows/desktop/aa372105.aspx
!define UNINSTALL_PATH "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}"

WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "Comments" "${DISPLAY_NAME}"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "DisplayIcon" "$INSTDIR\${PROGRAM_NAME_PATH_GTK},0"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "DisplayName" "${DISPLAY_NAME}"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "DisplayVersion" "${VERSION}"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "HelpLink" "http://ask.wireshark.org/"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "InstallLocation" "$INSTDIR"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "Publisher" "The Wireshark developer community, http://www.wireshark.org"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "URLInfoAbout" "http://www.wireshark.org"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "URLUpdateInfo" "http://www.wireshark.org/download.html"

WriteRegDWORD HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "NoModify" 1
WriteRegDWORD HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "NoRepair" 1
WriteRegDWORD HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "VersionMajor" ${VERSION_MAJOR}
WriteRegDWORD HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "VersionMinor" ${VERSION_MINOR}

WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "UninstallString" '"$INSTDIR\${UNINSTALLER_NAME}"'
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "QuietUninstallString" '"$INSTDIR\${UNINSTALLER_NAME}" /S'

; Write an entry for ShellExecute
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\App Paths\${PROGRAM_NAME_PATH_GTK}" "" '$INSTDIR\${PROGRAM_NAME_PATH_GTK}'
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\App Paths\${PROGRAM_NAME_PATH_GTK}" "Path" '$INSTDIR'
!ifdef QT_DIR
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\App Paths\${PROGRAM_NAME_PATH_QT}" "" '$INSTDIR\${PROGRAM_NAME_PATH_QT}'
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\App Paths\${PROGRAM_NAME_PATH_QT}" "Path" '$INSTDIR'
!endif

; Create start menu entries (depending on additional tasks page)
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "State"
StrCmp $0 "0" SecRequired_skip_StartMenu
SetOutPath $PROFILE
;CreateDirectory "$SMPROGRAMS\${PROGRAM_NAME}"
; To quote "http://download.microsoft.com/download/0/4/6/046bbd36-0812-4c22-a870-41911c6487a6/WindowsUserExperience.pdf"
; "Do not include Readme, Help, or Uninstall entries on the Programs menu."
Delete "$SMPROGRAMS\${PROGRAM_NAME}\Wireshark Web Site.lnk"
;WriteINIStr "$SMPROGRAMS\${PROGRAM_NAME}\Wireshark Web Site.url" "InternetShortcut" "URL" "http://www.wireshark.org/"
CreateShortCut "$SMPROGRAMS\${PROGRAM_NAME_GTK}.lnk" "$INSTDIR\${PROGRAM_NAME_PATH_GTK}" "" "$INSTDIR\${PROGRAM_NAME_PATH_GTK}" 0 "" "" "${PROGRAM_FULL_NAME_GTK}"
;CreateShortCut "$SMPROGRAMS\${PROGRAM_NAME}\Wireshark Manual.lnk" "$INSTDIR\wireshark.html"
;CreateShortCut "$SMPROGRAMS\${PROGRAM_NAME}\Display Filters Manual.lnk" "$INSTDIR\wireshark-filter.html"
;CreateShortCut "$SMPROGRAMS\${PROGRAM_NAME}\Wireshark Program Directory.lnk" "$INSTDIR"
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
CreateShortCut "$DESKTOP\${PROGRAM_NAME_GTK}.lnk" "$INSTDIR\${PROGRAM_NAME_PATH_GTK}" "" "$INSTDIR\${PROGRAM_NAME_PATH_GTK}" 0 "" "" "${PROGRAM_FULL_NAME_GTK}"
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
CreateShortCut "$QUICKLAUNCH\${PROGRAM_NAME_GTK}.lnk" "$INSTDIR\${PROGRAM_NAME_PATH_GTK}" "" "$INSTDIR\${PROGRAM_NAME_PATH_GTK}" 0 "" "" "${PROGRAM_FULL_NAME_GTK}"
SecRequired_skip_QuickLaunchIcon:

; Create File Extensions (depending on additional tasks page)
; None Associate
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 11" "State"
StrCmp $0 "1" SecRequired_skip_FileExtensions
; GTK+ Associate
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 9" "State"
StrCmp $0 "1" SecRequired_GTK_FileExtensions
; Qt Associate
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 10" "State"
StrCmp $0 "1" SecRequired_QT_FileExtensions

SecRequired_GTK_FileExtensions:
WriteRegStr HKCR ${WIRESHARK_ASSOC} "" "Wireshark capture file"
WriteRegStr HKCR "${WIRESHARK_ASSOC}\Shell\open\command" "" '"$INSTDIR\${PROGRAM_NAME_PATH_GTK}" "%1"'
WriteRegStr HKCR "${WIRESHARK_ASSOC}\DefaultIcon" "" '"$INSTDIR\${PROGRAM_NAME_PATH_GTK}",1'
Goto SecRequired_Associate_FileExtensions

SecRequired_QT_FileExtensions:
WriteRegStr HKCR ${WIRESHARK_ASSOC} "" "Wireshark capture file"
WriteRegStr HKCR "${WIRESHARK_ASSOC}\Shell\open\command" "" '"$INSTDIR\${PROGRAM_NAME_PATH_QT}" "%1"'
WriteRegStr HKCR "${WIRESHARK_ASSOC}\DefaultIcon" "" '"$INSTDIR\${PROGRAM_NAME_PATH_QT}",1'
Goto SecRequired_Associate_FileExtensions


SecRequired_Associate_FileExtensions:
; We refresh the icon cache down in -Finally.
Call Associate
; if somethings added here, add it also to the uninstall section and the AdditionalTask page

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
File "${WIRESHARK_LIB_DIR}\WinPcap_${WINPCAP_VERSION}.exe"
ExecWait '"$INSTDIR\WinPcap_${WINPCAP_VERSION}.exe"' $0
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
Section "${PROGRAM_NAME}" SecWiresharkGtk
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\${PROGRAM_NAME_PATH_GTK}"
File "${STAGING_DIR}\${GDK_DLL}"
File "${STAGING_DIR}\libgdk_pixbuf-2.0-0.dll"
File "${STAGING_DIR}\${GTK_DLL}"
File "${STAGING_DIR}\libatk-1.0-0.dll"
File "${STAGING_DIR}\libpango-1.0-0.dll"
File "${STAGING_DIR}\libpangowin32-1.0-0.dll"
!ifdef NEED_CAIRO_GOBJECT_DLL
File "${STAGING_DIR}\libcairo-gobject-2.dll"
!endif
!ifdef NEED_CAIRO_DLL
File "${STAGING_DIR}\libcairo-2.dll"
File "${STAGING_DIR}\libpangocairo-1.0-0.dll"
!endif
!ifdef NEED_EXPAT_DLL
File "${STAGING_DIR}\${EXPAT_DLL}"
!endif
!ifdef NEED_FFI_DLL
File "${STAGING_DIR}\${FFI_DLL}"
!endif
!ifdef NEED_FONTCONFIG_DLL
File "${STAGING_DIR}\${FONTCONFIG_DLL}"
!endif
!ifdef NEED_FREETYPE_DLL
File "${STAGING_DIR}\libpangoft2-1.0-0.dll"
File "${STAGING_DIR}\${FREETYPE_DLL}"
!endif
!ifdef NEED_HARFBUZZ_DLL
File "${STAGING_DIR}\${HARFBUZZ_DLL}"
!endif
!ifdef NEED_JASPER_DLL
File "${STAGING_DIR}\${JASPER_DLL}"
!endif
!ifdef NEED_JPEG_DLL
File "${STAGING_DIR}\${JPEG_DLL}"
!endif
!ifdef NEED_LZMA_DLL
File "${STAGING_DIR}\${LZMA_DLL}"
!endif
!ifdef NEED_PIXMAN_DLL
File "${STAGING_DIR}\${PIXMAN_DLL}"
!endif
!ifdef NEED_PNG_DLL
File "${STAGING_DIR}\${PNG_DLL}"
!endif
!ifdef NEED_SEH_DLL
File "${STAGING_DIR}\${SEH_DLL}"
!endif
!ifdef NEED_SJLJ_DLL
File "${STAGING_DIR}\${SJLJ_DLL}"
!endif
!ifdef NEED_TIFF_DLL
File "${STAGING_DIR}\${TIFF_DLL}"
!endif
!ifdef NEED_XML_DLL
File "${STAGING_DIR}\${XML_DLL}"
!endif

SetOutPath $INSTDIR\${GTK_ETC_DIR}
File "${GTK_DIR}\${GTK_ETC_DIR}\*.*"

!ifdef GTK_ENGINES_DIR
SetOutPath $INSTDIR\${GTK_ENGINES_DIR}
File "${STAGING_DIR}\${GTK_ENGINES_DIR}\libpixmap.dll"
File "${STAGING_DIR}\${GTK_ENGINES_DIR}\libwimp.dll"
!endif

!ifdef GTK_MODULES_DIR
SetOutPath $INSTDIR\${GTK_MODULES_DIR}
File "${STAGING_DIR}\${GTK_MODULES_DIR}\libgail.dll"
!endif

!ifdef GTK_SCHEMAS_DIR
SetOutPath $INSTDIR\${GTK_SCHEMAS_DIR}
File "${STAGING_DIR}\${GTK_SCHEMAS_DIR}\*.*"
!endif

SectionEnd ; "Wireshark"
!endif


Section "TShark" SecTShark
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\tshark.exe"
File "..\..\doc\tshark.html"
SectionEnd

!ifdef QT_DIR
Section "${PROGRAM_NAME} 2 Preview" SecWiresharkQt
;-------------------------------------------
; by default, QtShark is installed but file is always associate with Wireshark GTK+
SetOutPath $INSTDIR
File "${QT_DIR}\${PROGRAM_NAME_PATH_QT}"
!ifdef NEED_QT4_DLL
File "${QT_DIR}\QtCore4.dll"
File "${QT_DIR}\QtGui4.dll"
!endif
!ifdef NEED_QT5_DLL
File "${QT_DIR}\Qt5Core.dll"
File "${QT_DIR}\Qt5Gui.dll"
File "${QT_DIR}\Qt5Widgets.dll"
File "${QT_DIR}\Qt5PrintSupport.dll"
SetOutPath $INSTDIR\platforms
File "${QT_DIR}\platforms\qwindows.dll"
!endif

Push $0
;SectionGetFlags ${SecWiresharkQt} $0
;IntOp  $0 $0 & 1
;CreateShortCut "$SMPROGRAMS\${PROGRAM_NAME_QT}.lnk" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" "" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" 0 "" "" "${PROGRAM_FULL_NAME_QT}"

; Create start menu entries (depending on additional tasks page)
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "State"
StrCmp $0 "0" SecRequired_skip_StartMenuQt
CreateShortCut "$SMPROGRAMS\${PROGRAM_NAME_QT}.lnk" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" "" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" 0 "" "" "${PROGRAM_FULL_NAME_QT}"
SecRequired_skip_StartMenuQt:


; is command line option "/desktopicon" set?
${GetParameters} $R0
${GetOptions} $R0 "/desktopicon=" $R1
StrCmp $R1 "no" SecRequired_skip_DesktopIconQt
StrCmp $R1 "yes" SecRequired_install_DesktopIconQt

; Create desktop icon (depending on additional tasks page and command line option)
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State"
StrCmp $0 "0" SecRequired_skip_DesktopIconQt
SecRequired_install_DesktopIconQt:
CreateShortCut "$DESKTOP\${PROGRAM_NAME_QT}.lnk" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" "" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" 0 "" "" "${PROGRAM_FULL_NAME_QT}"
SecRequired_skip_DesktopIconQt:

; is command line option "/quicklaunchicon" set?
${GetParameters} $R0
${GetOptions} $R0 "/quicklaunchicon=" $R1
StrCmp $R1 "no" SecRequired_skip_QuickLaunchIconQt
StrCmp $R1 "yes" SecRequired_install_QuickLaunchIconQt

; Create quick launch icon (depending on additional tasks page and command line option)
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "State"
StrCmp $0 "0" SecRequired_skip_QuickLaunchIconQt
SecRequired_install_QuickLaunchIconQt:
CreateShortCut "$QUICKLAUNCH\${PROGRAM_NAME_QT}.lnk" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" "" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" 0 "" "" "${PROGRAM_FULL_NAME_QT}"
SecRequired_skip_QuickLaunchIconQt:

Pop $0
SectionEnd
!endif

SectionGroup "Plugins / Extensions" SecPluginsGroup

Section "Dissector Plugins" SecPlugins
;-------------------------------------------
SetOutPath '$INSTDIR\plugins\${VERSION}'
File "${STAGING_DIR}\plugins\${VERSION}\docsis.dll"
File "${STAGING_DIR}\plugins\${VERSION}\ethercat.dll"
File "${STAGING_DIR}\plugins\${VERSION}\gryphon.dll"
File "${STAGING_DIR}\plugins\${VERSION}\irda.dll"
File "${STAGING_DIR}\plugins\${VERSION}\m2m.dll"
File "${STAGING_DIR}\plugins\${VERSION}\opcua.dll"
File "${STAGING_DIR}\plugins\${VERSION}\profinet.dll"
File "${STAGING_DIR}\plugins\${VERSION}\unistim.dll"
File "${STAGING_DIR}\plugins\${VERSION}\wimax.dll"
File "${STAGING_DIR}\plugins\${VERSION}\wimaxasncp.dll"
File "${STAGING_DIR}\plugins\${VERSION}\wimaxmacphy.dll"
!include "custom_plugins.txt"
SectionEnd

Section "Tree Statistics Plugin" SecStatsTree
;-------------------------------------------
SetOutPath '$INSTDIR\plugins\${VERSION}'
File "${STAGING_DIR}\plugins\${VERSION}\stats_tree.dll"
SectionEnd

Section "Mate - Meta Analysis and Tracing Engine" SecMate
;-------------------------------------------
SetOutPath '$INSTDIR\plugins\${VERSION}'
File "${STAGING_DIR}\plugins\${VERSION}\mate.dll"
SectionEnd

Section "Configuration Profiles" SecProfiles
;-------------------------------------------
; This should be a function or macro
SetOutPath '$INSTDIR\profiles\Bluetooth'
File "${STAGING_DIR}\profiles\Bluetooth\colorfilters"
SetOutPath '$INSTDIR\profiles\Classic'
File "${STAGING_DIR}\profiles\Classic\colorfilters"
SectionEnd

!ifdef SMI_DIR
Section "SNMP MIBs" SecMIBs
;-------------------------------------------
SetOutPath $INSTDIR\snmp\mibs
File "${SMI_DIR}\share\mibs\iana\*"
File "${SMI_DIR}\share\mibs\ietf\*"
File "${SMI_DIR}\share\mibs\irtf\*"
File "${SMI_DIR}\share\mibs\tubs\*"
File "${SMI_DIR}\share\pibs\*"
File "${SMI_DIR}\share\yang\*.yang"
!include "custom_mibs.txt"
SectionEnd
!endif

SectionGroupEnd ; "Plugins / Extensions"


SectionGroup "Tools" SecToolsGroup

Section "Editcap" SecEditcap
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\editcap.exe"
File "..\..\doc\editcap.html"
SectionEnd

Section "Text2Pcap" SecText2Pcap
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\text2pcap.exe"
File "..\..\doc\text2pcap.html"
SectionEnd

Section "Mergecap" SecMergecap
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\mergecap.exe"
File "..\..\doc\mergecap.html"
SectionEnd

Section "Reordercap" SecReordercap
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\reordercap.exe"
SectionEnd

Section "Capinfos" SecCapinfos
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\capinfos.exe"
File "..\..\doc\capinfos.html"
SectionEnd

Section "Rawshark" SecRawshark
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\rawshark.exe"
File "..\..\doc\rawshark.html"
SectionEnd

SectionGroupEnd ; "Tools"

!ifdef HHC_DIR
Section "User's Guide" SecUsersGuide
;-------------------------------------------
SetOutPath $INSTDIR
File "user-guide.chm"
SectionEnd
!endif

Section "-Finally"

!insertmacro UpdateIcons

; Compute and write the installation directory size
${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
IntFmt $0 "0x%08X" $0
WriteRegDWORD HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "EstimatedSize" "$0"

SectionEnd


; ============================================================================
; PLEASE MAKE SURE, THAT THE DESCRIPTIVE TEXT FITS INTO THE DESCRIPTION FIELD!
; ============================================================================
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!ifdef GTK_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecWiresharkGtk} "The main network protocol analyzer application."
!endif
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTShark} "Text based network protocol analyzer."
!ifdef QT_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecWiresharkQt} "Preview of the next major release."
!endif

  !insertmacro MUI_DESCRIPTION_TEXT ${SecPluginsGroup} "Plugins and extensions for both ${PROGRAM_NAME} and TShark."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPlugins} "Additional protocol dissectors."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStatsTree} "Extended statistics."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMate} "Plugin - Meta Analysis and Tracing Engine (Experimental)."

  !insertmacro MUI_DESCRIPTION_TEXT ${SecProfiles} "Configuration profiles"

!ifdef SMI_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMIBs} "SNMP MIBs for better SNMP dissection."
!endif

  !insertmacro MUI_DESCRIPTION_TEXT ${SecToolsGroup} "Additional command line based tools."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecEditCap} "Copy packets to a new file, optionally trimmming packets, omitting them, or saving to a different format."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecText2Pcap} "Read an ASCII hex dump and write the data into a libpcap-style capture file."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMergecap} "Combine multiple saved capture files into a single output file"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecReordercap} "Copy packets to a new file, sorted by time."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCapinfos} "Pring information about capture files."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecRawshark} "Raw packet filter."

!ifdef HHC_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecUsersGuide} "Install an offline copy of the User's Guide."
!endif
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ============================================================================
; Callback functions
; ============================================================================
!ifdef GTK_DIR
; Disable File extensions and icon if Wireshark (GTK+ / QT ) isn't selected
Function .onSelChange
    Push $0
    Goto onSelChange.checkgtk

;Check Wireshark GTK+ and after check Qt
onSelChange.checkgtk:
    SectionGetFlags ${SecWiresharkGtk} $0
    IntOp  $0 $0 & 1
    IntCmp $0 0 onSelChange.unselectgtk
    IntCmp $0 1 onSelChange.selectgtk
    Goto onSelChange.checkqt

onSelChange.unselectgtk:
    ;GTK Icon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "State" 0
    ;GTK Association
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 9" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 9" "Flags" "DISABLED"
    ; Select "None Association"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 11" "State" 1
    Goto onSelChange.checkqt

onSelChange.selectgtk:
    ;GTK Icon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "State" 1
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "State" 1
    ;GTK Association
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 9" "State" 1
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 9" "Flags" ""
    ; Force None and Qt Association to no selected
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 11" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 10" "State" 0
    Goto onSelChange.checkqt

;Check Wireshark Qt+
onSelChange.checkqt:
!ifdef QT_DIR
    SectionGetFlags ${SecWiresharkQt} $0
    IntOp  $0 $0 & 1
    IntCmp $0 0 onSelChange.unselectqt
    IntCmp $0 1 onSelChange.selectqt
!endif
    Goto onSelChange.end

!ifdef QT_DIR
onSelChange.unselectqt:
    ;Qt Icon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "State" 0
    ;Qt Association
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 10" "Flags" "DISABLED"
    Goto onSelChange.end

onSelChange.selectqt:
    ;Qt Icon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "State" 1
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "State" 1
    ;Qt Association
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 10" "Flags" ""
    Goto onSelChange.end
!endif

onSelChange.end:
    Pop $0
FunctionEnd
!endif


!include "GetWindowsVersion.nsh"
!include WinMessages.nsh
!include "VersionCompare.nsh"

Var WINPCAP_NAME ; DisplayName from WinPcap installation
Var WINWINPCAP_VERSION ; DisplayVersion from WinPcap installation

Function myShowCallback

!ifdef QT_DIR
    ; if Qt is available enable icon and associate from additional tasks
    ;Qt Icon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "State" 1
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "State" 1
    ;Qt Association
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 10" "Flags" ""
!endif

    ; Get the Windows version
    Call GetWindowsVersion
    Pop $R0 ; Windows Version

    ; Check if we're able to run with this version
    StrCmp $R0 '95' lbl_winversion_unsupported
    StrCmp $R0 '98' lbl_winversion_unsupported
    StrCmp $R0 'ME' lbl_winversion_unsupported
    StrCmp $R0 'NT 4.0' lbl_winversion_unsupported_nt4
    StrCmp $R0 '2000' lbl_winversion_unsupported_2000
    StrCmp $R0 'XP' lbl_winversion_warn_xp
    Goto lbl_winversion_supported

lbl_winversion_unsupported:
    MessageBox MB_OK \
        "Windows $R0 is no longer supported.$\nPlease install Ethereal 0.99.0 instead." \
        /SD IDOK
    Quit

lbl_winversion_unsupported_nt4:
    MessageBox MB_OK \
            "Windows $R0 is no longer supported.$\nPlease install Wireshark 0.99.4 instead." \
            /SD IDOK
    Quit

lbl_winversion_unsupported_2000:
    MessageBox MB_OK \
        "Windows $R0 is no longer supported.$\nPlease install Wireshark 1.2 or 1.0 instead." \
        /SD IDOK
    Quit

lbl_winversion_warn_xp:
    MessageBox MB_OK \
        "This version of ${PROGRAM_NAME} may not work on Windows $R0.$\nWe recommend Wireshark 1.10 instead." \
        /SD IDOK
    ; Don't quit.

lbl_winversion_supported:
    ; detect if WinPcap should be installed
    WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "Text" "Install WinPcap ${PCAP_DISPLAY_VERSION}"
    ReadRegStr $WINPCAP_NAME HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "DisplayName"
    IfErrors 0 lbl_winpcap_installed ;if RegKey is available, WinPcap is already installed
    WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 2" "Text" "WinPcap is currently not installed"
    WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 2" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 5" "Text" "(Use Add/Remove Programs first to uninstall any undetected old WinPcap versions)"
    Goto lbl_winpcap_done

lbl_winpcap_installed:
    WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 2" "Text" "$WINPCAP_NAME"
    ; Compare the installed build against the one we have.
    ReadRegStr $WINWINPCAP_VERSION HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "DisplayVersion"
    StrCmp $WINWINPCAP_VERSION "" lbl_winpcap_do_install ; WinPcap is really old(?) or installed improperly.
    ${VersionCompare} $WINWINPCAP_VERSION "4.1.0.2980" $1 ; WinPcap 4.1.3
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
    WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 5" "Text" "If you wish to install WinPcap ${PCAP_DISPLAY_VERSION}, please uninstall $WINPCAP_NAME manually first."
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

    ;Set State=1 to Desktop icon (no enable by default)
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "State" "1"
!ifdef QT_DIR
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" "1"
!endif
    IfFileExists "$SMPROGRAMS\${PROGRAM_NAME}\${PROGRAM_NAME}.lnk" lbl_have_gtk_startmenu
    IfFileExists "$SMPROGRAMS\${PROGRAM_NAME}.lnk" lbl_have_gtk_startmenu
    IfFileExists "$SMPROGRAMS\${PROGRAM_NAME_GTK}.lnk" lbl_have_gtk_startmenu
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "State" "0"
lbl_have_gtk_startmenu:

    ; only select Desktop Icon, if previously installed
    IfFileExists "$DESKTOP\${PROGRAM_NAME}.lnk" lbl_have_gtk_desktopicon
    IfFileExists "$DESKTOP\${PROGRAM_NAME_GTK}.lnk" lbl_have_gtk_desktopicon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "State" "0"
lbl_have_gtk_desktopicon:

    ; only select Quick Launch Icon, if previously installed
    IfFileExists "$QUICKLAUNCH\${PROGRAM_NAME}.lnk" lbl_have_gtk_quicklaunchicon
    IfFileExists "$QUICKLAUNCH\${PROGRAM_NAME_GTK}.lnk" lbl_have_gtk_quicklaunchicon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "State" "0"
lbl_have_gtk_quicklaunchicon:

!ifdef QT_DIR
    IfFileExists "$SMPROGRAMS\${PROGRAM_NAME_QT}.lnk" lbl_have_qt_startmenu
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "State" "0"
lbl_have_qt_startmenu:

    ; only select Desktop Icon, if previously installed
    IfFileExists "$DESKTOP\${PROGRAM_NAME_QT}.lnk" lbl_have_qt_desktopicon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" "0"
lbl_have_qt_desktopicon:

    ; only select Quick Launch Icon, if previously installed
    IfFileExists "$QUICKLAUNCH\${PROGRAM_NAME_QT}.lnk" lbl_have_qt_quicklaunchicon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "State" "0"
lbl_have_qt_quicklaunchicon:
!endif

lbl_wireshark_notinstalled:

FunctionEnd

;
; Editor modelines  -  http://www.wireshark.org/tools/modelines.html
;
; Local variables:
; c-basic-offset: 4
; tab-width: 8
; indent-tabs-mode: nil
; End:
;
; vi: set shiftwidth=4 tabstop=8 expandtab:
; :indentSize=4:tabSize=8:noTabs=true:
;
