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
!include "StrFunc.nsh"
${StrRep}

; See http://nsis.sourceforge.net/Check_if_a_file_exists_at_compile_time for documentation
!macro !defineifexist _VAR_NAME _FILE_NAME
  !tempfile _TEMPFILE
  !ifdef NSIS_WIN32_MAKENSIS
    ; Windows - cmd.exe
    !system 'if exist "${_FILE_NAME}" echo !define ${_VAR_NAME} > "${_TEMPFILE}"'
  !else
    ; Posix - sh
    !system 'if [ -e "${_FILE_NAME}" ]; then echo "!define ${_VAR_NAME}" > "${_TEMPFILE}"; fi'
  !endif
  !include '${_TEMPFILE}'
  !delfile '${_TEMPFILE}'
  !undef _TEMPFILE
!macroend
!define !defineifexist "!insertmacro !defineifexist"

; ============================================================================
; Header configuration
; ============================================================================

; The file to write
OutFile "${PROGRAM_NAME}-${WIRESHARK_TARGET_PLATFORM}-${VERSION}.exe"
; Installer icon
Icon "${TOP_SRC_DIR}\image\wiresharkinst.ico"

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

!define MUI_ICON "${TOP_SRC_DIR}\image\wiresharkinst.ico"
BrandingText "Wireshark Installer (tm)"

!define MUI_COMPONENTSPAGE_SMALLDESC
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of ${PROGRAM_NAME}.\r\n\r\nBefore starting the installation, make sure ${PROGRAM_NAME} is not running.\r\n\r\nClick 'Next' to continue."
;!define MUI_FINISHPAGE_LINK "Install WinPcap to be able to capture packets from a network."
;!define MUI_FINISHPAGE_LINK_LOCATION "https://www.winpcap.org"

; NSIS shows Readme files by opening the Readme file with the default application for
; the file's extension. "README.win32" won't work in most cases, because extension "win32"
; is usually not associated with an appropriate text editor. We should use extension "txt"
; for a text file or "html" for an html README file.
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\NEWS.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Show News"
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
!define MUI_FINISHPAGE_RUN "$INSTDIR\${PROGRAM_NAME_PATH_QT}"
!define MUI_FINISHPAGE_RUN_NOTCHECKED

!define MUI_PAGE_CUSTOMFUNCTION_SHOW myShowCallback

; ============================================================================
; MUI Pages
; ============================================================================

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${STAGING_DIR}\COPYING.txt"
!insertmacro MUI_PAGE_COMPONENTS
Page custom DisplayAdditionalTasksPage
!insertmacro MUI_PAGE_DIRECTORY
Page custom DisplayWinPcapPage
Page custom DisplayUSBPcapPage
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
  ReserveFile "USBPcapPage.ini"
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
LicenseData "${STAGING_DIR}\COPYING.txt"

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
; https://msdn.microsoft.com/en-us/library/windows/desktop/cc144148.aspx
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

!include "GetWindowsVersion.nsh"
!include WinMessages.nsh

Function .onInit
  !if ${WIRESHARK_TARGET_PLATFORM} == "win64"
    ; http://forums.winamp.com/printthread.php?s=16ffcdd04a8c8d52bee90c0cae273ac5&threadid=262873
    ${IfNot} ${RunningX64}
      MessageBox MB_OK "This version of Wireshark only runs on x64 machines.$\nTry installing the 32-bit version instead." /SD IDOK
      Abort
    ${EndIf}
  !endif

    ; Get the Windows version
    ${GetWindowsVersion} $R0

    ; Uncomment to test.
    ; MessageBox MB_OK "You're running Windows $R0."

    ; Check if we're able to run with this version
    StrCmp $R0 '95' lbl_winversion_unsupported
    StrCmp $R0 '98' lbl_winversion_unsupported
    StrCmp $R0 'ME' lbl_winversion_unsupported
    StrCmp $R0 'NT 4.0' lbl_winversion_unsupported_nt4
    StrCmp $R0 '2000' lbl_winversion_unsupported_2000
    StrCmp $R0 'XP' lbl_winversion_unsupported_xp_2003
    StrCmp $R0 '2003' lbl_winversion_unsupported_xp_2003
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

lbl_winversion_unsupported_xp_2003:
    MessageBox MB_OK \
        "Windows $R0 is no longer supported.$\nPlease install ${PROGRAM_NAME} 1.12 or 1.10 instead." \
        /SD IDOK
    Quit

lbl_winversion_supported:
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
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "USBPcapPage.ini"
FunctionEnd

Function DisplayAdditionalTasksPage
  !insertmacro MUI_HEADER_TEXT "Select Additional Tasks" "Which additional tasks should be done?"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "AdditionalTasksPage.ini"
FunctionEnd

Function DisplayWinPcapPage
  !insertmacro MUI_HEADER_TEXT "Install WinPcap?" "WinPcap is required to capture live network data. Should WinPcap be installed?"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "WinPcapPage.ini"
FunctionEnd

Function DisplayUSBPcapPage
  !insertmacro MUI_HEADER_TEXT "Install USBPcap?" "USBPcap is required to capture USB traffic. Should USBPcap be installed (experimental)?"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "USBPcapPage.ini"
FunctionEnd

; ============================================================================
; Installation execution commands
; ============================================================================

Var WINPCAP_UNINSTALL ;declare variable for holding the value of a registry key
Var USBPCAP_UNINSTALL ;declare variable for holding the value of a registry key
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
File "${STAGING_DIR}\libwiretap.dll"
!ifdef ENABLE_LIBWIRESHARK
File "${STAGING_DIR}\libwireshark.dll"
!endif
File "${STAGING_DIR}\libwscodecs.dll"
File "${STAGING_DIR}\libwsutil.dll"

!include all-manifest.nsh

File "${STAGING_DIR}\COPYING.txt"
File "${STAGING_DIR}\NEWS.txt"
File "${STAGING_DIR}\README.txt"
File "${STAGING_DIR}\README.windows.txt"
File "${STAGING_DIR}\AUTHORS-SHORT"
File "${STAGING_DIR}\manuf"
File "${STAGING_DIR}\services"
File "${STAGING_DIR}\pdml2html.xsl"
File "${STAGING_DIR}\ws.css"
File "${STAGING_DIR}\wireshark.html"
File "${STAGING_DIR}\wireshark-filter.html"
File "${STAGING_DIR}\dumpcap.exe"
File "${STAGING_DIR}\dumpcap.html"
File "${STAGING_DIR}\extcap.html"
File "${STAGING_DIR}\ipmap.html"

; C-runtime redistributable
!ifdef VCREDIST_EXE
; vcredist_x64.exe - copy and execute the redistributable installer
File "${VCREDIST_EXE}"
; If the user already has the redistributable installed they will see a
; Big Ugly Dialog by default, asking if they want to uninstall or repair.
; Ideally we should add a checkbox for this somewhere. In the meantime,
; just do a "passive+norestart" install for MSVC 2010 and later and a
; "silent" install otherwise.

; http://blogs.msdn.com/b/astebner/archive/2010/10/20/10078468.aspx
; http://allthingsconfigmgr.wordpress.com/2013/12/17/visual-c-redistributables-made-simple/
; "!if ${MSVC_VER_REQUIRED} >= 1600" doesn't work.
!searchparse /noerrors ${MSVC_VER_REQUIRED} "1600" VCREDIST_FLAGS_Q_NORESTART
!ifdef VCREDIST_FLAGS_Q_NORESTART
StrCpy $VCREDIST_FLAGS "/q /norestart"
!else ; VCREDIST_FLAGS_Q_NORESTART
StrCpy $VCREDIST_FLAGS "/install /quiet /norestart"
!endif ; VCREDIST_FLAGS_Q_NORESTART

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
!echo "IF YOU GET AN ERROR HERE, check the CMAKE_GENERATOR setting"
File "${MSVCR_DLL}"
!endif ; MSVCR_DLL
!endif ; VCREDIST_EXE


; global config files - don't overwrite if already existing
;IfFileExists cfilters dont_overwrite_cfilters
File "${STAGING_DIR}\cfilters"
;dont_overwrite_cfilters:
;IfFileExists colorfilters dont_overwrite_colorfilters
File "${STAGING_DIR}\colorfilters"
;dont_overwrite_colorfilters:
;IfFileExists dfilters dont_overwrite_dfilters
File "${STAGING_DIR}\dfilters"
;dont_overwrite_dfilters:
;IfFileExists smi_modules dont_overwrite_smi_modules
File "${STAGING_DIR}\smi_modules"
;dont_overwrite_smi_modules:


;
; Install the Diameter DTD and XML files in the "diameter" subdirectory
; of the installation directory.
;
SetOutPath $INSTDIR\diameter
File "${STAGING_DIR}\diameter\AlcatelLucent.xml"
File "${STAGING_DIR}\diameter\chargecontrol.xml"
File "${STAGING_DIR}\diameter\Cisco.xml"
File "${STAGING_DIR}\diameter\CiscoSystems.xml"
File "${STAGING_DIR}\diameter\Custom.xml"
File "${STAGING_DIR}\diameter\dictionary.dtd"
File "${STAGING_DIR}\diameter\dictionary.xml"
File "${STAGING_DIR}\diameter\eap.xml"
File "${STAGING_DIR}\diameter\Ericsson.xml"
File "${STAGING_DIR}\diameter\etsie2e4.xml"
File "${STAGING_DIR}\diameter\HP.xml"
File "${STAGING_DIR}\diameter\mobileipv4.xml"
File "${STAGING_DIR}\diameter\mobileipv6.xml"
File "${STAGING_DIR}\diameter\nasreq.xml"
File "${STAGING_DIR}\diameter\Nokia.xml"
File "${STAGING_DIR}\diameter\NokiaSolutionsAndNetworks.xml"
File "${STAGING_DIR}\diameter\Oracle.xml"
File "${STAGING_DIR}\diameter\sip.xml"
File "${STAGING_DIR}\diameter\Starent.xml"
File "${STAGING_DIR}\diameter\sunping.xml"
File "${STAGING_DIR}\diameter\TGPP.xml"
File "${STAGING_DIR}\diameter\TGPP2.xml"
File "${STAGING_DIR}\diameter\Vodafone.xml"
!include "custom_diameter_xmls.txt"
SetOutPath $INSTDIR

;
; Install the RADIUS directory files in the "radius" subdirectory
; of the installation directory.
;
SetOutPath $INSTDIR\radius
File "${STAGING_DIR}\radius\README.radius_dictionary"
File "${STAGING_DIR}\radius\custom.includes"
File "${STAGING_DIR}\radius\dictionary"
File "${STAGING_DIR}\radius\dictionary.3com"
File "${STAGING_DIR}\radius\dictionary.3gpp"
File "${STAGING_DIR}\radius\dictionary.3gpp2"
File "${STAGING_DIR}\radius\dictionary.acc"
File "${STAGING_DIR}\radius\dictionary.acme"
File "${STAGING_DIR}\radius\dictionary.airespace"
File "${STAGING_DIR}\radius\dictionary.actelis"
File "${STAGING_DIR}\radius\dictionary.aerohive"
File "${STAGING_DIR}\radius\dictionary.alcatel"
File "${STAGING_DIR}\radius\dictionary.alcatel.esam"
File "${STAGING_DIR}\radius\dictionary.alcatel.sr"
File "${STAGING_DIR}\radius\dictionary.alcatel-lucent.aaa"
File "${STAGING_DIR}\radius\dictionary.alteon"
File "${STAGING_DIR}\radius\dictionary.altiga"
File "${STAGING_DIR}\radius\dictionary.alvarion"
File "${STAGING_DIR}\radius\dictionary.alvarion.wimax.v2_2"
File "${STAGING_DIR}\radius\dictionary.apc"
File "${STAGING_DIR}\radius\dictionary.aptis"
File "${STAGING_DIR}\radius\dictionary.aruba"
File "${STAGING_DIR}\radius\dictionary.arbor"
File "${STAGING_DIR}\radius\dictionary.ascend"
File "${STAGING_DIR}\radius\dictionary.asn"
File "${STAGING_DIR}\radius\dictionary.audiocodes"
File "${STAGING_DIR}\radius\dictionary.avaya"
File "${STAGING_DIR}\radius\dictionary.azaire"
File "${STAGING_DIR}\radius\dictionary.bay"
File "${STAGING_DIR}\radius\dictionary.bluecoat"
File "${STAGING_DIR}\radius\dictionary.bintec"
File "${STAGING_DIR}\radius\dictionary.broadsoft"
File "${STAGING_DIR}\radius\dictionary.brocade"
File "${STAGING_DIR}\radius\dictionary.bskyb"
File "${STAGING_DIR}\radius\dictionary.bristol"
File "${STAGING_DIR}\radius\dictionary.bt"
File "${STAGING_DIR}\radius\dictionary.camiant"
File "${STAGING_DIR}\radius\dictionary.cablelabs"
File "${STAGING_DIR}\radius\dictionary.cabletron"
File "${STAGING_DIR}\radius\dictionary.chillispot"
File "${STAGING_DIR}\radius\dictionary.cisco"
File "${STAGING_DIR}\radius\dictionary.cisco.asa"
File "${STAGING_DIR}\radius\dictionary.cisco.bbsm"
File "${STAGING_DIR}\radius\dictionary.cisco.vpn3000"
File "${STAGING_DIR}\radius\dictionary.cisco.vpn5000"
File "${STAGING_DIR}\radius\dictionary.citrix"
File "${STAGING_DIR}\radius\dictionary.clavister"
File "${STAGING_DIR}\radius\dictionary.colubris"
File "${STAGING_DIR}\radius\dictionary.columbia_university"
File "${STAGING_DIR}\radius\dictionary.compatible"
File "${STAGING_DIR}\radius\dictionary.compat"
File "${STAGING_DIR}\radius\dictionary.cosine"
File "${STAGING_DIR}\radius\dictionary.dante"
File "${STAGING_DIR}\radius\dictionary.dhcp"
File "${STAGING_DIR}\radius\dictionary.dlink"
File "${STAGING_DIR}\radius\dictionary.digium"
File "${STAGING_DIR}\radius\dictionary.dragonwave"
File "${STAGING_DIR}\radius\dictionary.efficientip"
File "${STAGING_DIR}\radius\dictionary.eltex"
File "${STAGING_DIR}\radius\dictionary.epygi"
File "${STAGING_DIR}\radius\dictionary.equallogic"
File "${STAGING_DIR}\radius\dictionary.ericsson"
File "${STAGING_DIR}\radius\dictionary.ericsson.ab"
File "${STAGING_DIR}\radius\dictionary.ericsson.packet.core.networks"
File "${STAGING_DIR}\radius\dictionary.erx"
File "${STAGING_DIR}\radius\dictionary.extreme"
File "${STAGING_DIR}\radius\dictionary.f5"
File "${STAGING_DIR}\radius\dictionary.fdxtended"
File "${STAGING_DIR}\radius\dictionary.fortinet"
File "${STAGING_DIR}\radius\dictionary.foundry"
File "${STAGING_DIR}\radius\dictionary.freedhcp"
File "${STAGING_DIR}\radius\dictionary.freeradius"
File "${STAGING_DIR}\radius\dictionary.freeradius.internal"
File "${STAGING_DIR}\radius\dictionary.freeswitch"
File "${STAGING_DIR}\radius\dictionary.gandalf"
File "${STAGING_DIR}\radius\dictionary.garderos"
File "${STAGING_DIR}\radius\dictionary.gemtek"
File "${STAGING_DIR}\radius\dictionary.h3c"
File "${STAGING_DIR}\radius\dictionary.hp"
File "${STAGING_DIR}\radius\dictionary.huawei"
File "${STAGING_DIR}\radius\dictionary.iana"
File "${STAGING_DIR}\radius\dictionary.iea"
File "${STAGING_DIR}\radius\dictionary.infoblox"
File "${STAGING_DIR}\radius\dictionary.infonet"
File "${STAGING_DIR}\radius\dictionary.ipunplugged"
File "${STAGING_DIR}\radius\dictionary.issanni"
File "${STAGING_DIR}\radius\dictionary.itk"
File "${STAGING_DIR}\radius\dictionary.jradius"
File "${STAGING_DIR}\radius\dictionary.juniper"
File "${STAGING_DIR}\radius\dictionary.kineto"
File "${STAGING_DIR}\radius\dictionary.karlnet"
File "${STAGING_DIR}\radius\dictionary.lancom"
File "${STAGING_DIR}\radius\dictionary.livingston"
File "${STAGING_DIR}\radius\dictionary.localweb"
File "${STAGING_DIR}\radius\dictionary.lucent"
File "${STAGING_DIR}\radius\dictionary.manzara"
File "${STAGING_DIR}\radius\dictionary.meinberg"
File "${STAGING_DIR}\radius\dictionary.merit"
File "${STAGING_DIR}\radius\dictionary.meru"
File "${STAGING_DIR}\radius\dictionary.microsoft"
File "${STAGING_DIR}\radius\dictionary.mikrotik"
File "${STAGING_DIR}\radius\dictionary.motorola"
File "${STAGING_DIR}\radius\dictionary.motorola.wimax"
File "${STAGING_DIR}\radius\dictionary.navini"
File "${STAGING_DIR}\radius\dictionary.netscreen"
File "${STAGING_DIR}\radius\dictionary.networkphysics"
File "${STAGING_DIR}\radius\dictionary.nexans"
File "${STAGING_DIR}\radius\dictionary.nokia"
File "${STAGING_DIR}\radius\dictionary.nokia.conflict"
File "${STAGING_DIR}\radius\dictionary.nomadix"
File "${STAGING_DIR}\radius\dictionary.nortel"
File "${STAGING_DIR}\radius\dictionary.ntua"
File "${STAGING_DIR}\radius\dictionary.openser"
File "${STAGING_DIR}\radius\dictionary.packeteer"
File "${STAGING_DIR}\radius\dictionary.paloalto"
File "${STAGING_DIR}\radius\dictionary.patton"
File "${STAGING_DIR}\radius\dictionary.perle"
File "${STAGING_DIR}\radius\dictionary.propel"
File "${STAGING_DIR}\radius\dictionary.prosoft"
File "${STAGING_DIR}\radius\dictionary.proxim"
File "${STAGING_DIR}\radius\dictionary.purewave"
File "${STAGING_DIR}\radius\dictionary.quiconnect"
File "${STAGING_DIR}\radius\dictionary.quintum"
File "${STAGING_DIR}\radius\dictionary.redcreek"
File "${STAGING_DIR}\radius\dictionary.rfc2865"
File "${STAGING_DIR}\radius\dictionary.rfc2866"
File "${STAGING_DIR}\radius\dictionary.rfc2867"
File "${STAGING_DIR}\radius\dictionary.rfc2868"
File "${STAGING_DIR}\radius\dictionary.rfc2869"
File "${STAGING_DIR}\radius\dictionary.rfc3162"
File "${STAGING_DIR}\radius\dictionary.rfc3576"
File "${STAGING_DIR}\radius\dictionary.rfc3580"
File "${STAGING_DIR}\radius\dictionary.rfc4072"
File "${STAGING_DIR}\radius\dictionary.rfc4372"
File "${STAGING_DIR}\radius\dictionary.rfc4603"
File "${STAGING_DIR}\radius\dictionary.rfc4675"
File "${STAGING_DIR}\radius\dictionary.rfc4679"
File "${STAGING_DIR}\radius\dictionary.rfc4818"
File "${STAGING_DIR}\radius\dictionary.rfc4849"
File "${STAGING_DIR}\radius\dictionary.rfc5090"
File "${STAGING_DIR}\radius\dictionary.rfc5176"
File "${STAGING_DIR}\radius\dictionary.rfc5447"
File "${STAGING_DIR}\radius\dictionary.rfc5580"
File "${STAGING_DIR}\radius\dictionary.rfc5607"
File "${STAGING_DIR}\radius\dictionary.rfc5904"
File "${STAGING_DIR}\radius\dictionary.rfc6519"
File "${STAGING_DIR}\radius\dictionary.rfc6572"
File "${STAGING_DIR}\radius\dictionary.rfc6677"
File "${STAGING_DIR}\radius\dictionary.rfc6911"
File "${STAGING_DIR}\radius\dictionary.rfc6929"
File "${STAGING_DIR}\radius\dictionary.rfc6930"
File "${STAGING_DIR}\radius\dictionary.rfc7055"
File "${STAGING_DIR}\radius\dictionary.rfc7155"
File "${STAGING_DIR}\radius\dictionary.rfc7268"
File "${STAGING_DIR}\radius\dictionary.rfc7499"
File "${STAGING_DIR}\radius\dictionary.riverbed"
File "${STAGING_DIR}\radius\dictionary.riverstone"
File "${STAGING_DIR}\radius\dictionary.roaringpenguin"
File "${STAGING_DIR}\radius\dictionary.ruckus"
File "${STAGING_DIR}\radius\dictionary.ruggedcom"
File "${STAGING_DIR}\radius\dictionary.sangoma"
File "${STAGING_DIR}\radius\dictionary.sg"
File "${STAGING_DIR}\radius\dictionary.shasta"
File "${STAGING_DIR}\radius\dictionary.shiva"
File "${STAGING_DIR}\radius\dictionary.siemens"
File "${STAGING_DIR}\radius\dictionary.slipstream"
File "${STAGING_DIR}\radius\dictionary.sofaware"
File "${STAGING_DIR}\radius\dictionary.sonicwall"
File "${STAGING_DIR}\radius\dictionary.springtide"
File "${STAGING_DIR}\radius\dictionary.starent"
File "${STAGING_DIR}\radius\dictionary.starent.vsa1"
File "${STAGING_DIR}\radius\dictionary.surfnet"
File "${STAGING_DIR}\radius\dictionary.symbol"
File "${STAGING_DIR}\radius\dictionary.t_systems_nova"
File "${STAGING_DIR}\radius\dictionary.telebit"
File "${STAGING_DIR}\radius\dictionary.telkom"
File "${STAGING_DIR}\radius\dictionary.terena"
File "${STAGING_DIR}\radius\dictionary.trapeze"
File "${STAGING_DIR}\radius\dictionary.travelping"
File "${STAGING_DIR}\radius\dictionary.tropos"
File "${STAGING_DIR}\radius\dictionary.ukerna"
File "${STAGING_DIR}\radius\dictionary.unix"
File "${STAGING_DIR}\radius\dictionary.usr"
File "${STAGING_DIR}\radius\dictionary.utstarcom"
File "${STAGING_DIR}\radius\dictionary.valemount"
File "${STAGING_DIR}\radius\dictionary.versanet"
File "${STAGING_DIR}\radius\dictionary.vqp"
File "${STAGING_DIR}\radius\dictionary.walabi"
File "${STAGING_DIR}\radius\dictionary.waverider"
File "${STAGING_DIR}\radius\dictionary.wichorus"
File "${STAGING_DIR}\radius\dictionary.wimax"
File "${STAGING_DIR}\radius\dictionary.wimax.alvarion"
File "${STAGING_DIR}\radius\dictionary.wimax.wichorus"
File "${STAGING_DIR}\radius\dictionary.wispr"
File "${STAGING_DIR}\radius\dictionary.xedia"
File "${STAGING_DIR}\radius\dictionary.xylan"
File "${STAGING_DIR}\radius\dictionary.yubico"
File "${STAGING_DIR}\radius\dictionary.zeus"
File "${STAGING_DIR}\radius\dictionary.zte"
File "${STAGING_DIR}\radius\dictionary.zyxel"
!include "custom_radius_dict.txt"
SetOutPath $INSTDIR

;
; install the dtds in the dtds subdirectory
;
SetOutPath $INSTDIR\dtds
File "${STAGING_DIR}\dtds\dc.dtd"
File "${STAGING_DIR}\dtds\itunes.dtd"
File "${STAGING_DIR}\dtds\mscml.dtd"
File "${STAGING_DIR}\dtds\pocsettings.dtd"
File "${STAGING_DIR}\dtds\presence.dtd"
File "${STAGING_DIR}\dtds\reginfo.dtd"
File "${STAGING_DIR}\dtds\rlmi.dtd"
File "${STAGING_DIR}\dtds\rss.dtd"
File "${STAGING_DIR}\dtds\smil.dtd"
File "${STAGING_DIR}\dtds\xcap-caps.dtd"
File "${STAGING_DIR}\dtds\xcap-error.dtd"
File "${STAGING_DIR}\dtds\watcherinfo.dtd"
SetOutPath $INSTDIR

; Install the TPNCP DAT file in the "tpncp" subdirectory
; of the installation directory.
SetOutPath $INSTDIR\tpncp
File "${STAGING_DIR}\tpncp\tpncp.dat"

;
; install the wimaxasncp TLV definitions in the wimaxasncp subdirectory
;
SetOutPath $INSTDIR\wimaxasncp
File "${STAGING_DIR}\wimaxasncp\dictionary.xml"
File "${STAGING_DIR}\wimaxasncp\dictionary.dtd"
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
; https://msdn.microsoft.com/en-us/library/ms954376.aspx
; https://msdn.microsoft.com/en-us/library/windows/desktop/aa372105.aspx
!define UNINSTALL_PATH "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}"

WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "Comments" "${DISPLAY_NAME}"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "DisplayIcon" "$INSTDIR\${PROGRAM_NAME_PATH_GTK},0"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "DisplayName" "${DISPLAY_NAME}"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "DisplayVersion" "${VERSION}"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "HelpLink" "https://ask.wireshark.org/"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "InstallLocation" "$INSTDIR"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "Publisher" "The Wireshark developer community, https://www.wireshark.org"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "URLInfoAbout" "https://www.wireshark.org"
WriteRegStr HKEY_LOCAL_MACHINE "${UNINSTALL_PATH}" "URLUpdateInfo" "https://www.wireshark.org/download.html"

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
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "State"
StrCmp $0 "0" SecRequired_skip_StartMenu
SetOutPath $PROFILE
;CreateDirectory "$SMPROGRAMS\${PROGRAM_NAME}"
; To quote "http://download.microsoft.com/download/0/4/6/046bbd36-0812-4c22-a870-41911c6487a6/WindowsUserExperience.pdf"
; "Do not include Readme, Help, or Uninstall entries on the Programs menu."
Delete "$SMPROGRAMS\${PROGRAM_NAME}\Wireshark Web Site.lnk"
;WriteINIStr "$SMPROGRAMS\${PROGRAM_NAME}\Wireshark Web Site.url" "InternetShortcut" "URL" "https://www.wireshark.org/"
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
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State"
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
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "State"
StrCmp $0 "0" SecRequired_skip_QuickLaunchIcon
SecRequired_install_QuickLaunchIcon:
CreateShortCut "$QUICKLAUNCH\${PROGRAM_NAME_GTK}.lnk" "$INSTDIR\${PROGRAM_NAME_PATH_GTK}" "" "$INSTDIR\${PROGRAM_NAME_PATH_GTK}" 0 "" "" "${PROGRAM_FULL_NAME_GTK}"
SecRequired_skip_QuickLaunchIcon:

; Create File Extensions (depending on additional tasks page)
; None Associate
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 11" "State"
StrCmp $0 "1" SecRequired_skip_FileExtensions
; GTK+ Associate
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 10" "State"
StrCmp $0 "1" SecRequired_GTK_FileExtensions
; Qt Associate
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 9" "State"
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
; Uninstall old WinPcap first
ReadRegStr $WINPCAP_UNINSTALL HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "UninstallString"
IfErrors lbl_winpcap_notinstalled ;if RegKey is unavailable, WinPcap is not installed
; from released version 3.1, WinPcap will uninstall an old version by itself
;ExecWait '$WINPCAP_UNINSTALL' $0
;DetailPrint "WinPcap uninstaller returned $0"
lbl_winpcap_notinstalled:
SetOutPath $INSTDIR
File "${WIRESHARK_LIB_DIR}\WinPcap_${WINPCAP_PACKAGE_VERSION}.exe"
ExecWait '"$INSTDIR\WinPcap_${WINPCAP_PACKAGE_VERSION}.exe"' $0
DetailPrint "WinPcap installer returned $0"
SecRequired_skip_Winpcap:

; If running as a silent installer, don't try to install USBPcap
IfSilent SecRequired_skip_USBPcap

ReadINIStr $0 "$PLUGINSDIR\USBPcapPage.ini" "Field 4" "State"
StrCmp $0 "0" SecRequired_skip_USBPcap
SetOutPath $INSTDIR
File "${WIRESHARK_LIB_DIR}\USBPcapSetup-${USBPCAP_DISPLAY_VERSION}.exe"
ExecWait '"$INSTDIR\USBPcapSetup-${USBPCAP_DISPLAY_VERSION}.exe"' $0
DetailPrint "USBPcap installer returned $0"
${If} $0 == "0"
    ${If} ${RunningX64}
        ${DisableX64FSRedirection}
        SetRegView 64
    ${EndIf}
    ReadRegStr $USBPCAP_UNINSTALL HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\USBPcap" "UninstallString"
    ${If} ${RunningX64}
        ${EnableX64FSRedirection}
        SetRegView 32
    ${EndIf}
    CreateDirectory $INSTDIR\extcap
    ${StrRep} $0 '$USBPCAP_UNINSTALL' 'Uninstall.exe' 'USBPcapCMD.exe'
    ${StrRep} $1 '$0' '"' ''
    CopyFiles  /SILENT $1 $INSTDIR\extcap
    SetRebootFlag true
${EndIf}
SecRequired_skip_USBPcap:

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

!ifdef QT_DIR
Section "${PROGRAM_NAME}" SecWiresharkQt
;-------------------------------------------
; by default, Wireshark is installed but file is always associate with Wireshark GTK+
SetOutPath $INSTDIR
File "${QT_DIR}\${PROGRAM_NAME_PATH_QT}"
!include qt-dll-manifest.nsh
${!defineifexist} TRANSLATIONS_FOLDER "${QT_DIR}\translations"
!ifdef TRANSLATIONS_FOLDER
  ; Starting from Qt 5.5, *.qm files are put in a translations subfolder
  File /r "${QT_DIR}\translations"
!else
  File "${QT_DIR}\*.qm"
!endif

Push $0
;SectionGetFlags ${SecWiresharkQt} $0
;IntOp  $0 $0 & 1
;CreateShortCut "$SMPROGRAMS\${PROGRAM_NAME_QT}.lnk" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" "" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" 0 "" "" "${PROGRAM_FULL_NAME_QT}"

; Create start menu entries (depending on additional tasks page)
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "State"
StrCmp $0 "0" SecRequired_skip_StartMenuQt
CreateShortCut "$SMPROGRAMS\${PROGRAM_NAME_QT}.lnk" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" "" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" 0 "" "" "${PROGRAM_FULL_NAME_QT}"
SecRequired_skip_StartMenuQt:

; is command line option "/desktopicon" set?
${GetParameters} $R0
${GetOptions} $R0 "/desktopicon=" $R1
StrCmp $R1 "no" SecRequired_skip_DesktopIconQt
StrCmp $R1 "yes" SecRequired_install_DesktopIconQt

; Create desktop icon (depending on additional tasks page and command line option)
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "State"
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
ReadINIStr $0 "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "State"
StrCmp $0 "0" SecRequired_skip_QuickLaunchIconQt
SecRequired_install_QuickLaunchIconQt:
CreateShortCut "$QUICKLAUNCH\${PROGRAM_NAME_QT}.lnk" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" "" "$INSTDIR\${PROGRAM_NAME_PATH_QT}" 0 "" "" "${PROGRAM_FULL_NAME_QT}"
SecRequired_skip_QuickLaunchIconQt:

Pop $0
SectionEnd ; "SecWiresharkQt"
!endif


Section "TShark" SecTShark
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\tshark.exe"
File "${STAGING_DIR}\tshark.html"
SectionEnd


!ifdef GTK_DIR
Section "${PROGRAM_NAME} 1" SecWiresharkGtk
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\${PROGRAM_NAME_PATH_GTK}"

!include gtk-dll-manifest.nsh

SectionEnd ; "SecWiresharkGtk"
!endif


SectionGroup "Plugins & Extensions" SecPluginsGroup

Section "Dissector Plugins" SecPlugins
;-------------------------------------------
SetOutPath '$INSTDIR\plugins\${VERSION}'
File "${STAGING_DIR}\plugins\docsis.dll"
File "${STAGING_DIR}\plugins\ethercat.dll"
File "${STAGING_DIR}\plugins\gryphon.dll"
File "${STAGING_DIR}\plugins\irda.dll"
File "${STAGING_DIR}\plugins\m2m.dll"
File "${STAGING_DIR}\plugins\opcua.dll"
File "${STAGING_DIR}\plugins\profinet.dll"
File "${STAGING_DIR}\plugins\unistim.dll"
File "${STAGING_DIR}\plugins\wimax.dll"
File "${STAGING_DIR}\plugins\wimaxasncp.dll"
File "${STAGING_DIR}\plugins\wimaxmacphy.dll"
!include "custom_plugins.txt"
SectionEnd

Section "Tree Statistics Plugin" SecStatsTree
;-------------------------------------------
SetOutPath '$INSTDIR\plugins\${VERSION}'
File "${STAGING_DIR}\plugins\stats_tree.dll"
SectionEnd

Section "Mate - Meta Analysis and Tracing Engine" SecMate
;-------------------------------------------
SetOutPath '$INSTDIR\plugins\${VERSION}'
File "${STAGING_DIR}\plugins\mate.dll"
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
SetOutPath '$INSTDIR\snmp\mibs'
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
File "${STAGING_DIR}\editcap.html"
SectionEnd

Section "Text2Pcap" SecText2Pcap
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\text2pcap.exe"
File "${STAGING_DIR}\text2pcap.html"
SectionEnd

Section "Mergecap" SecMergecap
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\mergecap.exe"
File "${STAGING_DIR}\mergecap.html"
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
File "${STAGING_DIR}\capinfos.html"
SectionEnd

Section "Rawshark" SecRawshark
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\rawshark.exe"
File "${STAGING_DIR}\rawshark.html"
SectionEnd

Section /o "Androiddump" SecAndroiddumpinfos
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\androiddump.html"
SetOutPath $INSTDIR\extcap
File "${STAGING_DIR}\extcap\androiddump.exe"
SectionEnd

Section /o "SSHdump" SecSSHdumpinfos
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\sshdump.html"
File "${STAGING_DIR}\ciscodump.html"
SetOutPath $INSTDIR\extcap
File "${STAGING_DIR}\extcap\sshdump.exe"
File "${STAGING_DIR}\extcap\ciscodump.exe"
SectionEnd

Section /o "Randpktdump" SecRandpktdumpinfos
;-------------------------------------------
SetOutPath $INSTDIR
File "${STAGING_DIR}\randpktdump.html"
SetOutPath $INSTDIR\extcap
File "${STAGING_DIR}\extcap\randpktdump.exe"
SectionEnd

SectionGroupEnd ; "Tools"

!ifdef USER_GUIDE_DIR
Section "User's Guide" SecUsersGuide
;-------------------------------------------
SetOutPath $INSTDIR
File "${USER_GUIDE_DIR}\user-guide.chm"
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
!ifdef QT_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecWiresharkQt} "The main network protocol analyzer application."
!endif
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTShark} "Text based network protocol analyzer."
!ifdef GTK_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecWiresharkGtk} "The classic user interface."
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
  !insertmacro MUI_DESCRIPTION_TEXT ${SecAndroiddumpinfos} "Provide capture interfaces from Android devices"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecSSHdumpinfos} "Provide remote capture through SSH"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecRandpktdumpinfos} "Provide random packet generator"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecEditCap} "Copy packets to a new file, optionally trimmming packets, omitting them, or saving to a different format."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecText2Pcap} "Read an ASCII hex dump and write the data into a libpcap-style capture file."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMergecap} "Combine multiple saved capture files into a single output file"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecReordercap} "Copy packets to a new file, sorted by time."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCapinfos} "Pring information about capture files."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecRawshark} "Raw packet filter."

!ifdef USER_GUIDE_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecUsersGuide} "Install an offline copy of the User's Guide."
!endif
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ============================================================================
; Callback functions
; ============================================================================
!ifdef QT_DIR
; Disable File extensions and icon if Wireshark (Qt / GTK+) isn't selected
Function .onSelChange
    Push $0
    Goto onSelChange.checkqt

;Check Wireshark Qt and after check GTK+
onSelChange.checkqt:
    SectionGetFlags ${SecWiresharkQt} $0
    IntOp  $0 $0 & ${SF_SELECTED}
    IntCmp $0 0 onSelChange.unselectqt
    IntCmp $0 ${SF_SELECTED} onSelChange.selectqt
    Goto onSelChange.checkqt

onSelChange.unselectqt:
    ; Qt Icon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "State" 0
    ; Qt Association
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 9" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 9" "Flags" "DISABLED"
    ; Select "None Association"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 11" "State" 1
    Goto onSelChange.checkgtk

onSelChange.selectqt:
    ; Qt Icon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "State" 1
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "State" 1
    ;Qt Association
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 9" "State" 1
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 9" "Flags" ""
    ; Force None and GTK+ Association to no selected
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 11" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 10" "State" 0
    Goto onSelChange.checkgtk

;Check Wireshark GTK+
onSelChange.checkgtk:
!ifdef GTK_DIR
    SectionGetFlags ${SecWiresharkGtk} $0
    IntOp  $0 $0 & ${SF_SELECTED}
    IntCmp $0 0 onSelChange.unselectgtk
    IntCmp $0 ${SF_SELECTED} onSelChange.selectgtk
!endif
    Goto onSelChange.end

!ifdef GTK_DIR
onSelChange.unselectgtk:
    ;GTK+ Icon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "State" 0
    ;GTK+ Association
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 10" "Flags" "DISABLED"
    Goto onSelChange.end

onSelChange.selectgtk:
    ;GTK+ Icon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "State" 1
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "State" 1
    ;GTK+ Association
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 10" "Flags" ""
    Goto onSelChange.end
!endif

onSelChange.end:
    Pop $0
FunctionEnd
!endif


!include "VersionCompare.nsh"

Var WINPCAP_NAME ; DisplayName from WinPcap installation
Var WINWINPCAP_VERSION ; DisplayVersion from WinPcap installation
Var NPCAP_NAME ; DisplayName from Npcap installation
Var USBPCAP_NAME ; DisplayName from USBPcap installation

Function myShowCallback

!ifdef GTK_DIR
    ; If GTK+ is available enable icon and associate from additional tasks
    ; GTK+ Icon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "State" 1
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" 0
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "Flags" ""
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "State" 1
    ;Qt Association
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 10" "Flags" ""
!endif

    ClearErrors
    ; detect if WinPcap should be installed
    WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "Text" "Install WinPcap ${PCAP_DISPLAY_VERSION}"
    ReadRegStr $WINPCAP_NAME HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "DisplayName"
    IfErrors 0 lbl_winpcap_installed ;if RegKey is available, WinPcap is already installed
    ; check also if Npcap is installed
    ReadRegStr $NPCAP_NAME HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "DisplayName"
    IfErrors 0 lbl_npcap_installed
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

lbl_npcap_installed:
    ReadRegDWORD $0 HKEY_LOCAL_MACHINE "SOFTWARE\Npcap" "WinPcapCompatible"
    WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 1" "Text" "Currently installed Npcap version"
    ${If} $0 == "0"
        ; Npcap is installed without WinPcap API-compatible mode; WinPcap can be installed
        WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 2" "Text" "$NPCAP_NAME is currently installed without WinPcap API-compatible mode"
        WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "State" "0"
        WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 5" "Text" "If you still wish to install WinPcap ${PCAP_DISPLAY_VERSION}, please check this option."
    ${Else}
        ; Npcap is installed with WinPcap API-compatible mode; WinPcap must not be installed
        WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 2" "Text" "$NPCAP_NAME"
        WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "State" "0"
        WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "Flags" "DISABLED"
        WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 5" "Text" "If you wish to install WinPcap ${PCAP_DISPLAY_VERSION}, please uninstall $NPCAP_NAME manually first."
        WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 5" "Flags" "DISABLED"
    ${EndIf}
    Goto lbl_winpcap_done

lbl_winpcap_do_install:
    ; seems to be an old version, install newer one
    WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 4" "State" "1"
    WriteINIStr "$PLUGINSDIR\WinPcapPage.ini" "Field 5" "Text" "The currently installed $WINPCAP_NAME will be uninstalled first."

lbl_winpcap_done:

    ; detect if USBPcap should be installed
    WriteINIStr "$PLUGINSDIR\USBPcapPage.ini" "Field 4" "Text" "Install USBPcap ${USBPCAP_DISPLAY_VERSION}"
    ${If} ${RunningX64}
        ${DisableX64FSRedirection}
        SetRegView 64
    ${EndIf}
    ReadRegStr $USBPCAP_NAME HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\USBPcap" "DisplayName"
    ${If} ${RunningX64}
        ${EnableX64FSRedirection}
        SetRegView 32
    ${EndIf}
    IfErrors 0 lbl_usbpcap_installed ;if RegKey is available, USBPcap is already installed
    WriteINIStr "$PLUGINSDIR\USBPcapPage.ini" "Field 2" "Text" "USBPcap is currently not installed"
    WriteINIStr "$PLUGINSDIR\USBPcapPage.ini" "Field 2" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\USBPcapPage.ini" "Field 5" "Text" "(Use Add/Remove Programs first to uninstall any undetected old USBPcap versions)"
    Goto lbl_usbpcap_done

lbl_usbpcap_installed:
    WriteINIStr "$PLUGINSDIR\USBPcapPage.ini" "Field 2" "Text" "$USBPCAP_NAME"
    WriteINIStr "$PLUGINSDIR\USBPcapPage.ini" "Field 4" "State" "0"
    WriteINIStr "$PLUGINSDIR\USBPcapPage.ini" "Field 4" "Flags" "DISABLED"
    WriteINIStr "$PLUGINSDIR\USBPcapPage.ini" "Field 5" "Text" "If you wish to install USBPcap ${USBPCAP_DISPLAY_VERSION}, please uninstall $USBPCAP_NAME manually first."
    WriteINIStr "$PLUGINSDIR\USBPcapPage.ini" "Field 5" "Flags" "DISABLED"
    Goto lbl_usbpcap_done

lbl_usbpcap_done:

    ; if Wireshark was previously installed, unselect previously not installed icons etc.
    ; detect if Wireshark is already installed ->
    ReadRegStr $0 HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark" "UninstallString"
    IfErrors lbl_wireshark_notinstalled ;if RegKey is unavailable, Wireshark is not installed

    ; only select Start Menu Group, if previously installed
    ; (we use the "all users" start menu, so select it first)
    SetShellVarContext all

    ;Set State=1 to Desktop icon (no enable by default)
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" "1"
!ifdef QT_DIR
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "State" "1"
!endif
    IfFileExists "$SMPROGRAMS\${PROGRAM_NAME}\${PROGRAM_NAME}.lnk" lbl_have_gtk_startmenu
    IfFileExists "$SMPROGRAMS\${PROGRAM_NAME}.lnk" lbl_have_gtk_startmenu
    IfFileExists "$SMPROGRAMS\${PROGRAM_NAME_GTK}.lnk" lbl_have_gtk_startmenu
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 5" "State" "0"
lbl_have_gtk_startmenu:

    ; only select Desktop Icon, if previously installed
    IfFileExists "$DESKTOP\${PROGRAM_NAME}.lnk" lbl_have_gtk_desktopicon
    IfFileExists "$DESKTOP\${PROGRAM_NAME_GTK}.lnk" lbl_have_gtk_desktopicon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 6" "State" "0"
lbl_have_gtk_desktopicon:

    ; only select Quick Launch Icon, if previously installed
    IfFileExists "$QUICKLAUNCH\${PROGRAM_NAME}.lnk" lbl_have_gtk_quicklaunchicon
    IfFileExists "$QUICKLAUNCH\${PROGRAM_NAME_GTK}.lnk" lbl_have_gtk_quicklaunchicon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 7" "State" "0"
lbl_have_gtk_quicklaunchicon:

!ifdef QT_DIR
    IfFileExists "$SMPROGRAMS\${PROGRAM_NAME_QT}.lnk" lbl_have_qt_startmenu
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 2" "State" "0"
lbl_have_qt_startmenu:

    ; only select Desktop Icon, if previously installed
    IfFileExists "$DESKTOP\${PROGRAM_NAME_QT}.lnk" lbl_have_qt_desktopicon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 3" "State" "0"
lbl_have_qt_desktopicon:

    ; only select Quick Launch Icon, if previously installed
    IfFileExists "$QUICKLAUNCH\${PROGRAM_NAME_QT}.lnk" lbl_have_qt_quicklaunchicon
    WriteINIStr "$PLUGINSDIR\AdditionalTasksPage.ini" "Field 4" "State" "0"
lbl_have_qt_quicklaunchicon:
!endif

lbl_wireshark_notinstalled:

FunctionEnd

;
; Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
