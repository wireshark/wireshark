;
; ethereal.nsi
;
; $Id: ethereal.nsi,v 1.40 2004/01/26 21:12:41 ulfl Exp $

; ============================================================================
; Header configuration
; ============================================================================
; The name of the installer
Name "Ethereal"

; The file to write
OutFile "${DEST}-setup-${VERSION}.exe"

; Icon of installer and uninstaller
Icon "..\..\image\ethereal.ico"
UninstallIcon "..\..\image\ethereal.ico"

; Uninstall stuff
UninstallText "This will uninstall Ethereal. Hit 'Next' to continue."

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
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of Ethereal.\r\n\r\nBefore starting the installation, make sure Ethereal is not running.\r\n\r\nClick next to continue."
!define MUI_FINISHPAGE_LINK "Install WinPcap to be able to capture packets from a network!"
!define MUI_FINISHPAGE_LINK_LOCATION "http://winpcap.polito.it"
; show readme doesn't seem to work with NSIS 2.0b4
;!define MUI_FINISHPAGE_SHOWREADME "..\..\README.win32"
;!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED

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
; Installation execution commands
; ============================================================================

Section "-Required"
;-------------------------------------------

;
; Install for every user
;
SetShellVarContext all

SetOutPath $INSTDIR
File "..\..\wiretap\wiretap-${WTAP_VERSION}.dll"
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
File "..\..\manuf"

;
; Install the Diameter DTD and XML files in the "diameter" subdirectory
; of the installation directory.
; 
SetOutPath $INSTDIR\diameter
File "..\..\dictionary.dtd"
File "..\..\dictionary.xml"
File "..\..\mobileipv4.xml"
File "..\..\nasreq.xml"
File "..\..\sunping.xml"
SetOutPath $INSTDIR

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

Section "Ethereal" SecEthereal
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\${DEST}.exe"
File "..\..\doc\ethereal.html"
File "..\..\doc\ethereal-filter.html"
!ifndef GTK2
File "${GTK_DIR}\lib\libgtk-0.dll"
File "${GTK_DIR}\lib\libgdk-0.dll"
!else
File "${GTK_DIR}\bin\libgdk-win32-2.0-0.dll"
File "${GTK_DIR}\bin\libgdk_pixbuf-2.0-0.dll"
File "${GTK_DIR}\bin\libgtk-win32-2.0-0.dll"
File "${GTK_DIR}\bin\libatk-1.0-0.dll"
File "${GTK_DIR}\bin\libpango-1.0-0.dll"
File "${GTK_DIR}\bin\libpangowin32-1.0-0.dll"
SetOutPath $INSTDIR\etc\gtk-2.0
File "${GTK_DIR}\etc\gtk-2.0\gdk-pixbuf.loaders"
File "${GTK_DIR}\etc\gtk-2.0\gtk.immodules"
SetOutPath $INSTDIR\etc\pango
File "${GTK_DIR}\etc\pango\pango.modules"
SetOutPath $INSTDIR\lib\gtk-2.0\2.2.0\loaders
File "${GTK_DIR}\lib\gtk-2.0\2.2.0\loaders\libpixbufloader-*.dll"
SetOutPath $INSTDIR\lib\gtk-2.0\2.2.0\immodules
File "${GTK_DIR}\lib\gtk-2.0\2.2.0\immodules\im-*.dll"
SetOutPath $INSTDIR\lib\pango\1.2.0\modules
File "${GTK_DIR}\lib\pango\1.2.0\modules\pango-*.dll"
!endif
SetOutPath $INSTDIR\help
File "..\..\help\toc"
File "..\..\help\overview.txt"
File "..\..\help\capture_filters.txt"
File "..\..\help\display_filters.txt"
File "..\..\help\well_known.txt"
File "..\..\help\faq.txt"
SectionEnd

Section "Tethereal" SecTethereal
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\tethereal.exe"
File "..\..\doc\tethereal.html"
SectionEnd

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


Section "Plugins" SecPlugins
;-------------------------------------------
SetOutPath $INSTDIR\plugins\${VERSION}
File "..\..\plugins\acn\acn.dll"
File "..\..\plugins\artnet\artnet.dll"
File "..\..\plugins\asn1\asn1.dll"
File "..\..\plugins\docsis\docsis.dll"
File "..\..\plugins\enttec\enttec.dll"
File "..\..\plugins\giop\coseventcomm.dll"
File "..\..\plugins\giop\cosnaming.dll"
File "..\..\plugins\gryphon\gryphon.dll"
File "..\..\plugins\irda\irda.dll"
File "..\..\plugins\lwres\lwres.dll"
File "..\..\plugins\megaco\megaco.dll"
File "..\..\plugins\mgcp\mgcp.dll"
File "..\..\plugins\pcli\pcli.dll"
File "..\..\plugins\rdm\rdm.dll"
File "..\..\plugins\rtnet\rtnet.dll"
File "..\..\plugins\v5ua\v5ua.dll"
SectionEnd

Section "SNMP MIBs" SecMIBs
;-------------------------------------------
SetOutPath $INSTDIR\snmp\mibs
File "${NET_SNMP_DIR}\mibs\*.txt"
SectionEnd

; SectionDivider
;-------------------------------------------

Section "Start Menu Shortcuts" SecShortcuts
;-------------------------------------------
CreateDirectory "$SMPROGRAMS\Ethereal"

Delete "$SMPROGRAMS\Ethereal\Ethereal Web Site.lnk"
WriteINIStr "$SMPROGRAMS\Ethereal\Ethereal Web Site.url" \
          "InternetShortcut" "URL" "http://www.ethereal.com/"
CreateShortCut "$SMPROGRAMS\Ethereal\Ethereal.lnk" "$INSTDIR\ethereal.exe"
CreateShortCut "$SMPROGRAMS\Ethereal\Ethereal Manual.lnk" "$INSTDIR\ethereal.html"
CreateShortCut "$SMPROGRAMS\Ethereal\Display Filters Manual.lnk" "$INSTDIR\ethereal-filter.html"
CreateShortCut "$SMPROGRAMS\Ethereal\Uninstall.lnk" "$INSTDIR\uninstall.exe"
CreateShortCut "$SMPROGRAMS\Ethereal\Ethereal Program Directory.lnk" \
          "$INSTDIR"
SectionEnd

Section "Desktop Icon" SecDesktopIcon
;-------------------------------------------
CreateShortCut "$DESKTOP\Ethereal.lnk" "$INSTDIR\Ethereal.exe"
SectionEnd

Section "Uninstall"
;-------------------------------------------

DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal"
DeleteRegKey HKEY_LOCAL_MACHINE SOFTWARE\Ethereal

;
; UnInstall for every user
;
SetShellVarContext all

!ifdef GTK2
Delete "$INSTDIR\etc\gtk-2.0\*.*"
Delete "$INSTDIR\etc\pango\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.2.0\loaders\*.*"
Delete "$INSTDIR\lib\gtk-2.0\2.2.0\immodules\*.*"
Delete "$INSTDIR\lib\pango\1.2.0\modules\*.*"
!endif
Delete "$INSTDIR\help\*.*"
Delete "$INSTDIR\plugins\${VERSION}\*.*"
Delete "$INSTDIR\plugins\*.*"
Delete "$INSTDIR\diameter\*.*"
Delete "$INSTDIR\snmp\mibs\*.*"
Delete "$INSTDIR\snmp\*.*"
Delete "$INSTDIR\*.*"
Delete "$SMPROGRAMS\Ethereal\*.*"
Delete "$DESKTOP\Ethereal.lnk"

!ifdef GTK2
RMDir "$INSTDIR\etc\gtk-2.0"
RMDir "$INSTDIR\etc\pango"
RMDir "$INSTDIR\etc"
RMDir "$INSTDIR\lib\gtk-2.0\2.2.0\loaders"
RMDir "$INSTDIR\lib\gtk-2.0\2.2.0\immodules"
RMDir "$INSTDIR\lib\gtk-2.0\2.2.0"
RMDir "$INSTDIR\lib\gtk-2.0"
RMDir "$INSTDIR\lib\pango\1.2.0\modules"
RMDir "$INSTDIR\lib\pango\1.2.0"
RMDir "$INSTDIR\lib\pango"
RMDir "$INSTDIR\lib"
!endif
RMDir "$SMPROGRAMS\Ethereal"
RMDir "$INSTDIR\help"
RMDir "$INSTDIR\plugins\${VERSION}"
RMDir "$INSTDIR\plugins"
RMDir "$INSTDIR\diameter"
RMDir "$INSTDIR\snmp\mibs"
RMDir "$INSTDIR\snmp"
RMDir "$INSTDIR"

SectionEnd


!ifdef MAKENSIS_MODERN_UI
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecEthereal} "Ethereal is a GUI network protocol analyzer."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTethereal} "Tethereal is a network protocol analyzer."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecEditCap} "Editcap is a program that reads a capture file and writes some or all of the packets into another capture file."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecText2Pcap} "Text2pcap is a program that reads in an ASCII hex dump and writes the data into a libpcap-style capture file."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMergecap} "Mergecap is a program that combines multiple saved capture files into a single output file."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPlugins} "Plugins with some extended dissections."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMIBs} "SNMP MIBs for better SNMP dissection."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcuts} "Start menu shortcuts."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktopIcon} "Ethereal desktop icon."
!insertmacro MUI_FUNCTION_DESCRIPTION_END
!endif ; MAKENSIS_MODERN_UI

