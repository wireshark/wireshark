;
; ethereal.nsi
;
; $Id: ethereal.nsi,v 1.26 2003/12/08 20:43:59 guy Exp $

; ============================================================================
; Header configuration
; ============================================================================
; The name of the installer
Name "Ethereal"

; The file to write
OutFile "ethereal-setup-${VERSION}.exe"

; Icon of installer and uninstaller
Icon "..\..\image\ethereal.ico"
UninstallIcon "..\..\image\ethereal.ico"

; Uninstall stuff
UninstallText "This will uninstall Ethereal. Hit 'Next' to continue."

XPStyle on

; ============================================================================
; License page configuration
; ============================================================================
LicenseText "Ethereal is distributed under the GNU General Public License."
LicenseData "GPL.txt"

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
!ifndef GLIB2
File "${COMMON_FILES_GNU}\iconv-1.3.dll"
File "${COMMON_FILES_GNU}\glib-1.3.dll"
File "${COMMON_FILES_GNU}\gmodule-1.3.dll"
File "${COMMON_FILES_GNU}\gnu-intl.dll"
!else
File "${COMMON_FILES_GNU}\iconv.dll"
File "${COMMON_FILES_GNU}\libglib-2.0-0.dll"
File "${COMMON_FILES_GNU}\libgmodule-2.0-0.dll"
File "${COMMON_FILES_GNU}\libgobject-2.0-0.dll"
File "${COMMON_FILES_GNU}\libintl-1.dll"
!endif
File "${COMMON_FILES_GNU}\zlib1.dll"
File "${COMMON_FILES_GNU}\adns_dll.dll"
File "${COMMON_FILES_GNU}\pcre.dll"
File "..\..\FAQ"
File "..\..\README"
File "..\..\README.win32"
File "..\..\manuf"
File "${PCRE_DIR}\man\cat3\pcrepattern.3.txt"

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
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal" "DisplayName" "Ethereal ${VERSION}"
WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ethereal" "UninstallString" '"$INSTDIR\uninstall.exe"'
WriteUninstaller "uninstall.exe"
SectionEnd

Section "Ethereal"
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\ethereal.exe"
File "..\..\doc\ethereal.html"
File "..\..\doc\ethereal-filter.html"
!ifndef GTK2
!ifndef GLIB2
File "${COMMON_FILES_GNU}\gtk-1.3.dll"
File "${COMMON_FILES_GNU}\gdk-1.3.dll"
!else
File "${COMMON_FILES_GNU}\libgtk-0.dll"
File "${COMMON_FILES_GNU}\libgdk-0.dll"
!endif
!else
File "${COMMON_FILES_GNU}\libgdk-win32-2.0-0.dll"
File "${COMMON_FILES_GNU}\libgdk_pixbuf-2.0-0.dll"
File "${COMMON_FILES_GNU}\libgtk-win32-2.0-0.dll"
File "${COMMON_FILES_GNU}\libatk-1.0-0.dll"
File "${COMMON_FILES_GNU}\libpango-1.0-0.dll"
File "${COMMON_FILES_GNU}\libpangowin32-1.0-0.dll"
SetOutPath $INSTDIR\etc\gtk-2.0
File "${COMMON_FILES_GNU}\etc\gtk-2.0\gdk-pixbuf.loaders"
File "${COMMON_FILES_GNU}\etc\gtk-2.0\gtk.immodules"
SetOutPath $INSTDIR\etc\pango
File "${COMMON_FILES_GNU}\etc\pango\pango.modules"
SetOutPath $INSTDIR\lib\gtk-2.0\2.2.0\loaders
File "${COMMON_FILES_GNU}\lib\gtk-2.0\2.2.0\loaders\libpixbufloader-*.dll"
SetOutPath $INSTDIR\lib\gtk-2.0\2.2.0\immodules
File "${COMMON_FILES_GNU}\lib\gtk-2.0\2.2.0\immodules\im-*.dll"
SetOutPath $INSTDIR\lib\pango\1.2.0\modules
File "${COMMON_FILES_GNU}\lib\pango\1.2.0\modules\pango-*.dll"
!endif
SectionEnd

Section "Tethereal"
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\tethereal.exe"
File "..\..\doc\tethereal.html"
SectionEnd

Section "Editcap"
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\editcap.exe"
File "..\..\doc\editcap.html"
SectionEnd

Section "Text2Pcap"
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\text2pcap.exe"
File "..\..\doc\text2pcap.html"
SectionEnd

Section "Mergecap"
;-------------------------------------------
SetOutPath $INSTDIR
File "..\..\mergecap.exe"
File "..\..\doc\mergecap.html"
SectionEnd


Section "Plugins"
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
File "..\..\plugins\lwres\lwres.dll"
File "..\..\plugins\megaco\megaco.dll"
File "..\..\plugins\mgcp\mgcp.dll"
File "..\..\plugins\pcli\pcli.dll"
File "..\..\plugins\rdm\rdm.dll"
File "..\..\plugins\rtnet\rtnet.dll"
SectionEnd

Section "SNMP MIBs"
;-------------------------------------------
SetOutPath $INSTDIR\snmp\mibs
File "${NET_SNMP_DIR}\mibs\*.txt"
SectionEnd

; SectionDivider
;-------------------------------------------

Section "Start Menu Shortcuts"
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

Section "Desktop Icon"
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
RMDir "$INSTDIR\plugins\${VERSION}"
RMDir "$INSTDIR\plugins"
RMDir "$INSTDIR\diameter"
RMDir "$INSTDIR\snmp\mibs"
RMDir "$INSTDIR\snmp"
RMDir "$INSTDIR"

SectionEnd
