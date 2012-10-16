;
; uninstall.nsi
;
; $Id$

; Create an installer that only writes an uninstaller.
; http://nsis.sourceforge.net/Signing_an_Uninstaller

!include "common.nsh"
!include 'LogicLib.nsh'

SetCompress off
OutFile "${STAGING_DIR}\uninstall_installer.exe"
RequestExecutionLevel user

InstType "un.Default (keep Personal Settings and WinPcap)"
InstType "un.All (remove all)"

; Uninstaller icon
UninstallIcon "..\..\image\wiresharkinst.ico"

!include "MUI.nsh"

!define MUI_UNICON "..\..\image\wiresharkinst.ico"

; Uninstall stuff (NSIS 2.08: "\r\n" don't work here)
!define MUI_UNCONFIRMPAGE_TEXT_TOP "The following ${PROGRAM_NAME} installation will be removed. Click 'Next' to continue."
; Uninstall stuff (this text isn't used with the MODERN_UI!)
;UninstallText "This will uninstall ${PROGRAM_NAME}.\r\nBefore starting the uninstallation, make sure ${PROGRAM_NAME} is not running.\r\nClick 'Next' to continue."

!define MUI_UNFINISHPAGE_NOAUTOCLOSE

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_COMPONENTS
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

; ============================================================================
; Section macros
; ============================================================================
!include "Sections.nsh"

; ============================================================================
; Uninstall page configuration
; ============================================================================
ShowUninstDetails show

; ============================================================================
; Functions and macros
; ============================================================================

Function .onInit
  ; MUST be the absolute path to our staging directory.
  WriteUninstaller "${MAKEDIR}\${STAGING_DIR}\${UNINSTALLER_NAME}"
  SetErrorLevel 0
  Quit
FunctionEnd

Var EXTENSION
Function un.Disassociate
	Push $R0
!insertmacro PushFileExtensions

	Pop $EXTENSION
	${DoUntil} $EXTENSION == ${FILE_EXTENSION_MARKER}
		ReadRegStr $R0 HKCR $EXTENSION ""
		StrCmp $R0 ${WIRESHARK_ASSOC} un.Disassociate.doDeregister
		Goto un.Disassociate.end
un.Disassociate.doDeregister:
		; The extension is associated with Wireshark so, we must destroy this!
		DeleteRegKey HKCR $EXTENSION
		DetailPrint "Deregistered file type: $EXTENSION"
un.Disassociate.end:
		Pop $EXTENSION
	${Loop}

	Pop $R0
FunctionEnd

Section "-Required"
SectionEnd

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

Delete "$INSTDIR\Qtshark.exe"
IfErrors 0 NoQtSharkErrorMsg
	MessageBox MB_OK "Please note: qtshark.exe could not be removed, it's probably in use!" IDOK 0 ;skipped if qtshark.exe removed
	Abort "Please note: qtshark.exe could not be removed, it's probably in use! Abort uninstall process!"
NoQtSharkErrorMsg:

Delete "$INSTDIR\${PROGRAM_NAME}.exe"
IfErrors 0 NoWiresharkErrorMsg
	MessageBox MB_OK "Please note: ${PROGRAM_NAME}.exe could not be removed, it's probably in use!" IDOK 0 ;skipped if ${PROGRAM_NAME}.exe removed
	Abort "Please note: ${PROGRAM_NAME}.exe could not be removed, it's probably in use! Abort uninstall process!"
NoWiresharkErrorMsg:

DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}"
DeleteRegKey HKEY_LOCAL_MACHINE "Software\${PROGRAM_NAME}"
DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\App Paths\${PROGRAM_NAME}.exe"

Call un.Disassociate

DeleteRegKey HKCR ${WIRESHARK_ASSOC}
DeleteRegKey HKCR "${WIRESHARK_ASSOC}\Shell\open\command"
DeleteRegKey HKCR "${WIRESHARK_ASSOC}\DefaultIcon"
!insertmacro UpdateIcons

Delete "$INSTDIR\etc\gtk-2.0\*.*"
Delete "$INSTDIR\etc\gtk-3.0\*.*"
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
Delete "$INSTDIR\share\glib-2.0\schemas\*.*"
Delete "$INSTDIR\help\*.*"
Delete "$INSTDIR\diameter\*.*"
Delete "$INSTDIR\snmp\mibs\*.*"
Delete "$INSTDIR\snmp\*.*"
Delete "$INSTDIR\tpncp\*.*"
Delete "$INSTDIR\ui\*.*"
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
Delete "$SMPROGRAMS\${PROGRAM_NAME}\*.*"
Delete "$SMPROGRAMS\${PROGRAM_NAME}.lnk"
Delete "$SMPROGRAMS\Qtshark.lnk"
Delete "$DESKTOP\${PROGRAM_NAME}.lnk"
Delete "$QUICKLAUNCH\${PROGRAM_NAME}.lnk"

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
RMDir "$SMPROGRAMS\${PROGRAM_NAME}"
RMDir "$INSTDIR\help"
RMDir "$INSTDIR\diameter"
RMDir "$INSTDIR\snmp\mibs"
RMDir "$INSTDIR\snmp"
RMDir "$INSTDIR\radius"
RMDir "$INSTDIR\dtds"
RMDir "$INSTDIR\tpncp"
RMDir "$INSTDIR\ui"
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
Delete "$APPDATA\${PROGRAM_NAME}\*.*"
RMDir "$APPDATA\${PROGRAM_NAME}"
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

!insertmacro MUI_UNFUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecUinstall} "Uninstall all ${PROGRAM_NAME} components."
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecPlugins} "Uninstall all Plugins (even from previous ${PROGRAM_NAME} versions)."
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecGlobalSettings} "Uninstall global settings like: $INSTDIR\cfilters"
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecPersonalSettings} "Uninstall personal settings like your preferences file from your profile: $PROFILE."
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecWinPcap} "Call WinPcap's uninstall program."
!insertmacro MUI_UNFUNCTION_DESCRIPTION_END
