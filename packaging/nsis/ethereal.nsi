;
; ethereal.nsi
;
; $Id$

 
!ifdef MAKENSIS_MODERN_UI
; Set the compression mechanism first
SetCompressor lzma
!endif

InstType "Ethereal (EXPERIMENTAL native Windows user interface)"
!ifdef GTK1_DIR & GTK2_DIR
InstType "Ethereal (GTK2 user interface)"
InstType "Ethereal (legacy GTK1 user interface)"
!endif

; Used to refresh the display of file association
!define SHCNE_ASSOCCHANGED 0x08000000
!define SHCNF_IDLIST 0

; Used to add associations between file extensions and Ethereal
!define ETHEREAL_ASSOC "ethereal-file"


; ============================================================================
; Header configuration
; ============================================================================
; The name of the installer
!define PROGRAM_NAME "Ethereal"

Name "${PROGRAM_NAME} ${VERSION}"

; The file to write
OutFile "${DEST}-setup-${VERSION}.exe"

; Icon of installer and uninstaller
Icon "..\..\image\ethereal.ico"
UninstallIcon "..\..\image\ethereal.ico"

; Uninstall stuff (this text isn't used with the MODERN_UI!)
UninstallText "This will uninstall Ethereal.\r\nBefore starting the uninstallation, make sure Ethereal is not running.\r\nClick 'Next' to continue."

XPStyle on


!ifdef MAKENSIS_MODERN_UI

; ============================================================================
; Modern UI
; ============================================================================
; The modern user interface will look much better than the common one.
; However, as the development of the modern UI is still going on, and the script
; syntax changes, you will need exactly that NSIS version, which this script is
; made for. This is the current (December 2003) latest version: V2.0b4
; If you are using a different version, it's not predictable what will happen.

!include "MUI.nsh"

!define MUI_ICON "..\..\image\ethereal.ico"
!define MUI_UNICON "..\..\image\ethereal.ico"

!define MUI_COMPONENTSPAGE_SMALLDESC
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of Ethereal.\r\n\r\nBefore starting the installation, make sure Ethereal is not running.\r\n\r\nClick 'Next' to continue."
!define MUI_FINISHPAGE_LINK "Install WinPcap to be able to capture packets from a network!"
!define MUI_FINISHPAGE_LINK_LOCATION "http://winpcap.polito.it"

; NSIS shows Readme files by opening the Readme file with the default application for
; the file's extension. "README.win32" won't work in most cases, because extension "win32" 
; is usually not associated with an appropriate text editor. We should use extension "txt" 
; for a text file or "html" for an html README file.  
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\NEWS.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Show News"
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED

; ============================================================================
; MUI Pages
; ============================================================================

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\COPYING"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
 
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; ============================================================================
; MUI Languages
; ============================================================================
 
!insertmacro MUI_LANGUAGE "English"

!endif ; MAKENSIS_MODERN_UI

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
; License page configuration
; ============================================================================
LicenseText "Ethereal is distributed under the GNU General Public License."
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
DirText "Choose a directory in which to install Ethereal."

; The default installation directory
InstallDir $PROGRAMFILES\Ethereal\

; See if this is an upgrade; if so, use the old InstallDir as default
InstallDirRegKey HKEY_LOCAL_MACHINE SOFTWARE\Ethereal "InstallDir"


; ============================================================================
; Install page configuration
; ============================================================================
ShowInstDetails show

; ============================================================================
; Functions and macros
; ============================================================================
!macro UpdateIcons
	Push $R0
  	Push $R1
  	Push $R2

	!define UPDATEICONS_UNIQUE ${__LINE__}

	IfFileExists "$SYSDIR\shell32.dll" UpdateIcons.next1_${UPDATEICONS_UNIQUE} UpdateIcons.error1_${UPDATEICONS_UNIQUE} 
UpdateIcons.next1_${UPDATEICONS_UNIQUE}:	
	GetDllVersion "$SYSDIR\shell32.dll" $R0 $R1
	IntOp $R2 $R0 / 0x00010000
	IntCmp $R2 4 UpdateIcons.next2_${UPDATEICONS_UNIQUE} UpdateIcons.error2_${UPDATEICONS_UNIQUE}
UpdateIcons.next2_${UPDATEICONS_UNIQUE}:	
	System::Call 'shell32.dll::SHChangeNotify(i, i, i, i) v (${SHCNE_ASSOCCHANGED}, ${SHCNF_IDLIST}, 0, 0)' 
	Goto UpdateIcons.quit_${UPDATEICONS_UNIQUE}	
	
UpdateIcons.error1_${UPDATEICONS_UNIQUE}: 
	MessageBox MB_OK|MB_ICONSTOP  "Can't find 'shell32.dll' library. Impossible to update icons" 
	Goto UpdateIcons.quit_${UPDATEICONS_UNIQUE}
UpdateIcons.error2_${UPDATEICONS_UNIQUE}: 	
	MessageBox MB_OK|MB_ICONINFORMATION "You should install the free 'Microsoft Layer for Unicode' to update Ethereal capture file icons" 
	Goto UpdateIcons.quit_${UPDATEICONS_UNIQUE}
UpdateIcons.quit_${UPDATEICONS_UNIQUE}:	
	!undef UPDATEICONS_UNIQUE
	Pop $R2
	Pop $R1
  	Pop $R0

!macroend

Function Associate
	; $R0 should contain the prefix to associate to Ethereal
	Push $R1
	
	ReadRegStr $R1 HKCR $R0 ""
	StrCmp $R1 "" Associate.doRegister
	Goto Associate.end
Associate.doRegister:
	;The extension is not associated to any program, we can do the link
	WriteRegStr HKCR $R0 "" ${ETHEREAL_ASSOC}
Associate.end:
	pop $R1
FunctionEnd

Function un.unlink
	; $R0 should contain the prefix to unlink
	Push $R1
	
	ReadRegStr $R1 HKCR $R0 ""
	StrCmp $R1 ${ETHEREAL_ASSOC} un.unlink.doUnlink
	Goto un.unlink.end
un.unlink.doUnlink:
	; The extension is associated with Ethereal so, we must destroy this!
	DeleteRegKey HKCR $R0	
un.unlink.end:	
	pop $R1
FunctionEnd

; ============================================================================
; Installation execution commands
; ============================================================================

Section "-Required"
;-------------------------------------------

;
; Install for every user
;
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 1 2 3 RO
!endif
SetShellVarContext all

SetOutPath $INSTDIR
File "..\..\wiretap\wiretap-${WTAP_VERSION}.dll"
!ifdef ENABLE_LIBETHEREAL
File "..\..\epan\libethereal.dll"
!endif
File "${GLIB_DIR}\bin\libglib-2.0-0.dll"
File "${GLIB_DIR}\bin\libgmodule-2.0-0.dll"
File "${GLIB_DIR}\bin\libgobject-2.0-0.dll"
File "${ICONV_DIR}\bin\iconv.dll"
File "${GETTEXT_DIR}\bin\intl.dll"
!ifdef ZLIB_DIR
File "${ZLIB_DIR}\zlib1.dll"
!endif
!ifdef ADNS_DIR
File "${ADNS_DIR}\adns_win32\LIB\adns_dll.dll"
!endif
!ifdef PCRE_DIR
File "${PCRE_DIR}\bin\pcre.dll"
File "${PCRE_DIR}\man\cat3\pcrepattern.3.txt"
!endif
File "..\..\FAQ"
File "..\..\README"
File "..\..\README.win32"
File "..\..\AUTHORS-SHORT"
File "..\..\AUTHORS-SHORT-FORMAT"
File "..\..\COPYING"
File "NEWS.txt"
File "..\..\manuf"
File "..\..\doc\ethereal.html"
File "..\..\doc\ethereal-filter.html"

;
; Install the Diameter DTD and XML files in the "diameter" subdirectory
; of the installation directory.
; 
SetOutPath $INSTDIR\diameter
File "..\..\dictionary.dtd"
File "..\..\dictionary.xml"
File "..\..\imscxdx.xml"
File "..\..\mobileipv4.xml"
File "..\..\nasreq.xml"
File "..\..\sunping.xml"
SetOutPath $INSTDIR

SetOutPath $INSTDIR\help
File "..\..\help\toc"
File "..\..\help\overview.txt"
File "..\..\help\getting_started.txt"
File "..\..\help\capturing.txt"
File "..\..\help\capture_filters.txt"
File "..\..\help\display_filters.txt"
File "..\..\help\faq.txt"

; Write the uninstall keys for Windows
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal" "DisplayVersion" "${VERSION}"
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal" "DisplayName" "Ethereal ${VERSION}"
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal" "UninstallString" '"$INSTDIR\uninstall.exe"'
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal" "Publisher" "The Ethereal developer community, http://www.ethereal.com"
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal" "HelpLink" "mailto:ethereal-users@ethereal.com"
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal" "URLInfoAbout" "http://www.ethereal.com"
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal" "URLUpdateInfo" "http://www.ethereal.com/distribution/win32/"
WriteRegDWORD HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal" "NoModify" 1
WriteRegDWORD HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal" "NoRepair" 1
WriteUninstaller "uninstall.exe"
SectionEnd

!ifdef GTK1_DIR
Section "Ethereal GTK1" SecEtherealGTK1
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 3 RO
!endif
SetOutPath $INSTDIR
File "..\..\ethereal.exe"
File "${GTK1_DIR}\lib\libgtk-0.dll"
File "${GTK1_DIR}\lib\libgdk-0.dll"
SectionEnd
!endif

!ifdef GTK2_DIR
Section "Ethereal GTK2" SecEtherealGTK2
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 2 RO
!endif
SetOutPath $INSTDIR
File /oname=ethereal.exe "..\..\ethereal-gtk2.exe"
File "${GTK2_DIR}\bin\libgdk-win32-2.0-0.dll"
File "${GTK2_DIR}\bin\libgdk_pixbuf-2.0-0.dll"
File "${GTK2_DIR}\bin\libgtk-win32-2.0-0.dll"
File "${GTK2_DIR}\bin\libatk-1.0-0.dll"
File "${GTK2_DIR}\bin\libpango-1.0-0.dll"
File "${GTK2_DIR}\bin\libpangowin32-1.0-0.dll"
SetOutPath $INSTDIR\etc\gtk-2.0
File "${GTK2_DIR}\etc\gtk-2.0\*.*"
SetOutPath $INSTDIR\etc\pango
File "${GTK2_DIR}\etc\pango\pango.*"
SetOutPath $INSTDIR\lib\gtk-2.0\${GTK2_INST_VERSION}.0\loaders
File "${GTK2_DIR}\lib\gtk-2.0\${GTK2_INST_VERSION}.0\loaders\libpixbufloader-*.dll"
SetOutPath $INSTDIR\lib\gtk-2.0\${GTK2_INST_VERSION}.0\immodules
File "${GTK2_DIR}\lib\gtk-2.0\${GTK2_INST_VERSION}.0\immodules\im-*.dll"
SetOutPath $INSTDIR\lib\pango\${PANGO_INST_VERSION}.0\modules
File "${GTK2_DIR}\lib\pango\${PANGO_INST_VERSION}.0\modules\pango-*.dll"
SectionEnd
 
!ifdef GTK_WIMP_DIR
Section "GTK-Wimp" SecGTKWimp
;-------------------------------------------
SetOutPath $INSTDIR\lib\gtk-2.0\${GTK2_INST_VERSION}.0\engines
File "${GTK_WIMP_DIR}\libwimp.dll"
SetOutPath $INSTDIR\share\themes\Default\gtk-2.0
File "${GTK_WIMP_DIR}\Theme\gtk-2.0\gtkrc"
SectionEnd
!endif
!endif

Section "Ethereal Native Win32" SecEtherealNativeWin32
;-------------------------------------------
!ifdef GTK1_DIR | GTK2_DIR
SectionIn 1 RO
!endif
SetOutPath $INSTDIR
File /oname=ethereal.exe "..\..\wethereal.exe"
SectionEnd

Section "Tethereal" SecTethereal
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 1 2 3
!endif
SetOutPath $INSTDIR
File "..\..\tethereal.exe"
File "..\..\doc\tethereal.html"
SectionEnd

Section "Editcap" SecEditcap
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 1 2 3
!endif
SetOutPath $INSTDIR
File "..\..\editcap.exe"
File "..\..\doc\editcap.html"
SectionEnd

Section "Text2Pcap" SecText2Pcap
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 1 2 3
!endif
SetOutPath $INSTDIR
File "..\..\text2pcap.exe"
File "..\..\doc\text2pcap.html"
SectionEnd

Section "Mergecap" SecMergecap
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 1 2 3
!endif
SetOutPath $INSTDIR
File "..\..\mergecap.exe"
File "..\..\doc\mergecap.html"
SectionEnd

Section "Capinfo" SecCapinfo
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 1 2 3
!endif
SetOutPath $INSTDIR
File "..\..\capinfo.exe"
File "..\..\doc\capinfo.html"
SectionEnd


Section "Plugins" SecPlugins
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 1 2 3
!endif
SetOutPath $INSTDIR\plugins\${VERSION}
File "..\..\plugins\acn\acn.dll"
File "..\..\plugins\artnet\artnet.dll"
File "..\..\plugins\asn1\asn1.dll"
File "..\..\plugins\ciscosm\ciscosm.dll"
File "..\..\plugins\docsis\docsis.dll"
File "..\..\plugins\enttec\enttec.dll"
File "..\..\plugins\giop\coseventcomm.dll"
File "..\..\plugins\giop\cosnaming.dll"
File "..\..\plugins\gryphon\gryphon.dll"
File "..\..\plugins\irda\irda.dll"
File "..\..\plugins\lwres\lwres.dll"
File "..\..\plugins\megaco\megaco.dll"
File "..\..\plugins\mgcp\mgcp.dll"
File "..\..\plugins\opsi\opsi.dll"
File "..\..\plugins\pcli\pcli.dll"
File "..\..\plugins\rdm\rdm.dll"
File "..\..\plugins\rlm\rlm.dll"
File "..\..\plugins\rtnet\rtnet.dll"
File "..\..\plugins\rudp\rudp.dll"
File "..\..\plugins\v5ua\v5ua.dll"
SectionEnd

Section "SNMP MIBs" SecMIBs
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 1 2 3
!endif
SetOutPath $INSTDIR\snmp\mibs
File "${NET_SNMP_DIR}\mibs\*.txt"
SectionEnd

; SectionDivider
;-------------------------------------------

Section "Start Menu Shortcuts" SecShortcuts
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 1 2 3
!endif
SetOutPath $PROFILE
CreateDirectory "$SMPROGRAMS\Ethereal"

Delete "$SMPROGRAMS\Ethereal\Ethereal Web Site.lnk"
WriteINIStr "$SMPROGRAMS\Ethereal\Ethereal Web Site.url" \
          "InternetShortcut" "URL" "http://www.ethereal.com/"
CreateShortCut "$SMPROGRAMS\Ethereal\Ethereal.lnk" "$INSTDIR\ethereal.exe"
CreateShortCut "$SMPROGRAMS\Ethereal\Ethereal Manual.lnk" "$INSTDIR\ethereal.html"
CreateShortCut "$SMPROGRAMS\Ethereal\Display Filters Manual.lnk" "$INSTDIR\ethereal-filter.html"
CreateShortCut "$SMPROGRAMS\Ethereal\Ethereal Program Directory.lnk" \
          "$INSTDIR"
CreateShortCut "$SMPROGRAMS\Ethereal\Uninstall Ethereal.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Desktop Icon" SecDesktopIcon
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 1 2 3
!endif
CreateShortCut "$DESKTOP\Ethereal.lnk" "$INSTDIR\ethereal.exe"
SectionEnd

Section "Associate file extensions to Ethereal" SecFileExtensions
;-------------------------------------------
!ifdef GTK1_DIR & GTK2_DIR
SectionIn 1 2 3
!endif
WriteRegStr HKCR ${ETHEREAL_ASSOC} "" "Ethereal file"
WriteRegStr HKCR "${ETHEREAL_ASSOC}\Shell\open\command" "" '"$INSTDIR\ethereal.exe" "%1"'
WriteRegStr HKCR "${ETHEREAL_ASSOC}\DefaultIcon" "" '"$INSTDIR\ethereal.exe",0'
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
pop $R0
!insertmacro UpdateIcons
SectionEnd

Section "Uninstall"
;-------------------------------------------

;
; UnInstall for every user
;
SetShellVarContext all

Delete "$INSTDIR\tethereal.exe"
IfErrors 0 NoTetherealErrorMsg
	MessageBox MB_OK "Please note: tethereal.exe could not be removed, it's probably in use!" IDOK 0 ;skipped if tethereal.exe removed
	Abort "Please note: tethereal.exe could not be removed, it's probably in use! Abort uninstall process!"
NoTetherealErrorMsg:

Delete "$INSTDIR\ethereal.exe"
IfErrors 0 NoEtherealErrorMsg
	MessageBox MB_OK "Please note: ethereal.exe could not be removed, it's probably in use!" IDOK 0 ;skipped if ethereal.exe removed
	Abort "Please note: ethereal.exe could not be removed, it's probably in use! Abort uninstall process!"
NoEtherealErrorMsg:

DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal"
DeleteRegKey HKEY_LOCAL_MACHINE SOFTWARE\Ethereal

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
pop $R0

DeleteRegKey HKCR ${ETHEREAL_ASSOC} 
DeleteRegKey HKCR "${ETHEREAL_ASSOC}\Shell\open\command"
DeleteRegKey HKCR "${ETHEREAL_ASSOC}\DefaultIcon"
!insertmacro UpdateIcons

; regardless if we currently installed GTK1 or 2, try to uninstall GTK2 files too
Delete "$INSTDIR\etc\gtk-2.0\*.*"
Delete "$INSTDIR\etc\pango\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.2.0\engines\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.2.0\loaders\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.2.0\immodules\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.4.0\engines\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.4.0\loaders\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.4.0\immodules\*.*"
Delete "$INSTDIR\lib\pango\1.2.0\modules\*.*"
Delete "$INSTDIR\lib\pango\1.4.0\modules\*.*"
Delete "$INSTDIR\share\themes\Default\gtk-2.0\*.*"
Delete "$INSTDIR\help\*.*"
Delete "$INSTDIR\plugins\${VERSION}\*.*"
Delete "$INSTDIR\plugins\*.*"
Delete "$INSTDIR\diameter\*.*"
Delete "$INSTDIR\snmp\mibs\*.*"
Delete "$INSTDIR\snmp\*.*"
Delete "$INSTDIR\*.exe"
Delete "$INSTDIR\*.dll"
Delete "$INSTDIR\*.html"
Delete "$INSTDIR\COPYING"
Delete "$INSTDIR\AUTHORS-SHORT"
Delete "$INSTDIR\AUTHORS-SHORT-FORMAT"
Delete "$INSTDIR\README*"
Delete "$INSTDIR\FAQ"
Delete "$INSTDIR\NEWS.txt"
Delete "$INSTDIR\manuf"
Delete "$INSTDIR\pcrepattern.3.txt"
Delete "$SMPROGRAMS\Ethereal\*.*"
Delete "$DESKTOP\Ethereal.lnk"

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
RMDir "$INSTDIR\lib\gtk-2.0"
RMDir "$INSTDIR\lib\pango\1.2.0\modules"
RMDir "$INSTDIR\lib\pango\1.2.0"
RMDir "$INSTDIR\lib\pango\1.4.0\modules"
RMDir "$INSTDIR\lib\pango\1.4.0"
RMDir "$INSTDIR\lib\pango"
RMDir "$INSTDIR\lib"
RMDir "$INSTDIR\share\themes\Default\gtk-2.0"
RMDir "$INSTDIR\share\themes\Default"
RMDir "$INSTDIR\share\themes"
RMDir "$INSTDIR\share"
RMDir "$SMPROGRAMS\Ethereal"
RMDir "$INSTDIR\help"
RMDir "$INSTDIR\plugins\${VERSION}"
RMDir "$INSTDIR\plugins"
RMDir "$INSTDIR\diameter"
RMDir "$INSTDIR\snmp\mibs"
RMDir "$INSTDIR\snmp"
RMDir "$INSTDIR"

IfFileExists "$INSTDIR" 0 NoFinalErrorMsg
    MessageBox MB_OK "Please note: The directory $INSTDIR could not be removed!" IDOK 0 ; skipped if file doesn't exist
NoFinalErrorMsg: 

SectionEnd

!ifdef MAKENSIS_MODERN_UI
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!ifdef GTK1_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecEtherealGTK1} "${PROGRAM_NAME} is a GUI network protocol analyzer."
!endif  
!ifdef GTK2_DIR  
  !insertmacro MUI_DESCRIPTION_TEXT ${SecEtherealGTK2} "${PROGRAM_NAME} is a GUI network protocol analyzer (using the modern GTK2 GUI toolkit)."
!ifdef GTK_WIMP_DIR
  !insertmacro MUI_DESCRIPTION_TEXT ${SecGTKWimp} "GTKWimp is the GTK2 windows impersonator (native Win32 look and feel)."
!endif  
!endif
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTethereal} "Tethereal is a network protocol analyzer."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecEditCap} "Editcap is a program that reads a capture file and writes some or all of the packets into another capture file."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecText2Pcap} "Text2pcap is a program that reads in an ASCII hex dump and writes the data into a libpcap-style capture file."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMergecap} "Mergecap is a program that combines multiple saved capture files into a single output file."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCapinfo} "Capinfo is a program that provides information on capture files."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPlugins} "Plugins with some extended dissections."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMIBs} "SNMP MIBs for better SNMP dissection."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcuts} "Start menu shortcuts."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktopIcon} "Ethereal desktop icon."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecFileExtensions} "Associate standard network trace files to ${PROGRAM_NAME}"  
!insertmacro MUI_FUNCTION_DESCRIPTION_END
!endif ; MAKENSIS_MODERN_UI

; ============================================================================
; Callback functions
; ============================================================================
!ifdef GTK1_DIR & GTK2_DIR
;Disable GTK-Wimp for GTK1
Function .onSelChange
	Push $0
	SectionGetFlags ${SecEtherealGTK1} $0
	IntOp  $0 $0 & 1
	IntCmp $0 1 onSelChange.disableGTK2Sections
	;enable GTK2Sections
	!insertmacro EnableSection ${SecGTKWimp}
	Goto onSelChange.end
onSelChange.disableGTK2Sections:
	!insertmacro DisableSection ${SecGTKWimp}
	Goto onSelChange.end
onSelChange.end:
	Pop $0
FunctionEnd	

!else
!ifdef GTK1_DIR | GTK2_DIR
; Disable FileExtension if Ethereal isn't selected
Function .onSelChange
	Push $0
!ifdef GTK1_DIR
	SectionGetFlags ${SecEtherealGTK1} $0
	IntOp  $0 $0 & 1
	IntCmp $0 0 onSelChange.unselect
	SectionGetFlags ${SecFileExtensions} $0
	IntOp  $0 $0 & 16
	IntCmp $0 16 onSelChange.unreadonly
	Goto onSelChange.end
!else
	SectionGetFlags ${SecEtherealGTK2} $0
	IntOp  $0 $0 & 1
	IntCmp $0 0 onSelChange.unselect
	SectionGetFlags ${SecFileExtensions} $0
	IntOp  $0 $0 & 16
	IntCmp $0 16 onSelChange.unreadonly
	Goto onSelChange.end	
!endif
onSelChange.unselect:	
	SectionGetFlags ${SecFileExtensions} $0
	IntOp $0 $0 & 0xFFFFFFFE
	IntOp $0 $0 | 0x10
	SectionSetFlags ${SecFileExtensions} $0
	Goto onSelChange.end
onSelChange.unreadonly:
	SectionGetFlags ${SecFileExtensions} $0
	IntOp $0 $0 & 0xFFFFFFEF
	SectionSetFlags ${SecFileExtensions} $0
	Goto onSelChange.end
onSelChange.end:
	Pop $0
FunctionEnd
!endif
!endif
