
; Installer.nsi - installs Wireshark Portable onto a PortableApps enabled device

; $Id$

;Copyright 2007 John T. Haller

;Website: http://www.wireshark.org/

;This software is OSI Certified Open Source Software.
;OSI Certified is a certification mark of the Open Source Initiative.

;This program is free software; you can redistribute it and/or
;modify it under the terms of the GNU General Public License
;as published by the Free Software Foundation; either version 2
;of the License, or (at your option) any later version.

;This program is distributed in the hope that it will be useful,
;but WITHOUT ANY WARRANTY; without even the implied warranty of
;MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;GNU General Public License for more details.

;You should have received a copy of the GNU General Public License
;along with this program; if not, write to the Free Software
;Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

;EXCEPTION: Can be used with non-GPLed open source apps distributed by PortableApps.com

!define APP "Wireshark"
!define NAME "Wireshark Portable"
!define SHORTNAME "WiresharkPortable"
!define FILENAME "WiresharkPortable"
!define CHECKRUNNING "WiresharkPortable.exe"
!define CLOSENAME "Wireshark Portable"
!define ADDONSDIRECTORYPRESERVE "NONE"

!addplugindir "${EXTRA_PLUGINS}"

;=== Program Details
Name "${NAME}"
OutFile "${FILENAME}-${WSVERSION}.paf.exe"
InstallDir "\${SHORTNAME}"
Caption "${NAME} | PortableApps.com Installer"
VIProductVersion "${VERSION}"
VIAddVersionKey ProductName "${NAME}"
VIAddVersionKey Comments "For additional details, visit PortableApps.com"
VIAddVersionKey CompanyName "PortableApps.com"
VIAddVersionKey LegalCopyright "PortableApps.com and contributors"
VIAddVersionKey FileDescription "${NAME}"
VIAddVersionKey FileVersion "${VERSION}"
VIAddVersionKey ProductVersion "${VERSION}"
VIAddVersionKey InternalName "${NAME}"
VIAddVersionKey LegalTrademarks "PortableApps.com is a Trademark of Rare Ideas, LLC."
VIAddVersionKey OriginalFilename "${FILENAME}.paf.exe"
;VIAddVersionKey PrivateBuild ""
;VIAddVersionKey SpecialBuild ""

;=== Runtime Switches
;SetDatablockOptimize on
;SetCompress off
SetCompressor /SOLID lzma
SetCompressorDictSize 64 ; MB
CRCCheck on
AutoCloseWindow True
RequestExecutionLevel user

;=== Include
!include MUI.nsh
!include FileFunc.nsh
!include LogicLib.nsh
!insertmacro DriveSpace
!insertmacro GetOptions
!insertmacro GetDrives
!insertmacro GetRoot
!insertmacro GetSize

;=== Program Icon
Icon "Files\App\AppInfo\appicon.ico"

;=== Icon & Stye ===
!define MUI_ICON "..\..\..\image\wiresharkinst.ico"
BrandingText "PortableApps.com - Your Digital Life, Anywhere™"

;=== Pages
;!define MUI_WELCOMEFINISHPAGE_BITMAP wizard.bmp
!define MUI_WELCOMEPAGE_TITLE "${NAME}"
!define MUI_WELCOMEPAGE_TEXT "$(welcome)"
!insertmacro MUI_PAGE_WELCOME
;!define MUI_LICENSEPAGE_RADIOBUTTONS
;!insertmacro MUI_PAGE_LICENSE "EULA.txt"
!define MUI_DIRECTORYPAGE_VERIFYONLEAVE
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE LeaveDirectory
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TEXT "$(finish)"
!insertmacro MUI_PAGE_FINISH

;=== Languages
!insertmacro MUI_LANGUAGE "English"

LangString welcome ${LANG_ENGLISH} "This wizard will guide you through the installation of ${NAME}.\r\n\r\nIf you are upgrading an existing installation of ${NAME}, please close it before proceeding.\r\n\r\nClick Next to continue."
LangString finish ${LANG_ENGLISH} "${NAME} has been installed on your device.\r\n\r\nClick Finish to close this wizard."
LangString runwarning ${LANG_ENGLISH} "Please close all instances of ${CLOSENAME} and then click OK.  The portable app can not be upgraded while it is running."
LangString invaliddirectory ${LANG_ENGLISH} "The destination folder you selected is invalid.  Please choose a valid folder."
LangString notenoughspace ${LANG_ENGLISH} "The device you have selected to install to does not have enough free space for this app."

;=== Variables
Var FOUNDPORTABLEAPPSPATH

Function .onInit
	;StrCpy $FOUNDPORTABLEAPPSPATH ''

	${GetOptions} "$CMDLINE" "/DESTINATION=" $R0

	IfErrors CheckLegacyDestination
		StrCpy $INSTDIR "$R0${SHORTNAME}"
		Goto InitDone

	CheckLegacyDestination:
		ClearErrors
		${GetOptions} "$CMDLINE" "-o" $R0
		IfErrors NoDestination
			StrCpy $INSTDIR "$R0${SHORTNAME}"
			Goto InitDone

	NoDestination:
		ClearErrors
		${GetDrives} "HDD+FDD" GetDrivesCallBack
		StrCmp $FOUNDPORTABLEAPPSPATH "" DefaultDestination
			StrCpy $INSTDIR "$FOUNDPORTABLEAPPSPATH\${SHORTNAME}"
			Goto InitDone
		
	DefaultDestination:
		StrCpy $INSTDIR "\${SHORTNAME}"

	InitDone:
FunctionEnd

Function GetDrivesCallBack
	;=== Skip usual floppy letters
	StrCmp $8 "FDD" "" CheckForPortableAppsPath
	StrCmp $9 "A:\" End
	StrCmp $9 "B:\" End
	
	CheckForPortableAppsPath:
		IfFileExists "$9PortableApps" "" End
			StrCpy $FOUNDPORTABLEAPPSPATH "$9PortableApps"

	End:
		Push $0
FunctionEnd

Function LeaveDirectory
	GetInstDirError $0
  
	;=== Does it already exist? (upgrade)
	IfFileExists "$INSTDIR" "" CheckInstallerError
		;=== Check if app is running?
		StrCmp ${CHECKRUNNING} "NONE" CheckInstallerError
			FindProcDLL::FindProc "${CHECKRUNNING}"
			StrCmp $R0 "1" "" CheckInstallerError
				MessageBox MB_OK|MB_ICONINFORMATION `$(runwarning)`
				Abort
  
	CheckInstallerError:
		${Switch} $0
		    ${Case} 0 ;=== Valid directory and enough free space
				${Break}
		    ${Case} 1
				MessageBox MB_OK `$(invaliddirectory)`
				Abort
				${Break}
		    ${Case} 2
				IfFileExists `$INSTDIR` "" NotEnoughSpaceNoUpgrade ;=== Is upgrade
					SectionGetSize ${SectionMain} $1 ;=== Space Required for App
					${GetRoot} `$INSTDIR` $2
					${DriveSpace} `$2\` "/D=F /S=K" $3 ;=== Space Free on Device
					${GetSize} `$INSTDIR` "/M=*.* /S=0K /G=1" $4 $5 $6 ;=== Current installation size
					IntOp $7 $3 + $4 ;=== Space Free + Current Install Size
					IfFileExists `$INSTDIR\Data` "" CheckPluginsDirectory
						${GetSize} `$INSTDIR\Data` "/M=*.* /S=0K /G=1" $4 $5 $6 ;=== Size of Data directory
						IntOp $7 $7 - $4 ;=== Remove the data directory from the free space calculation

				CheckPluginsDirectory:
					StrCmp `${ADDONSDIRECTORYPRESERVE}` "NONE" CalculateSpaceLeft
						IfFileExists `$INSTDIR\${ADDONSDIRECTORYPRESERVE}` "" CalculateSpaceLeft
							${GetSize} `$INSTDIR\${ADDONSDIRECTORYPRESERVE}` "/M=*.* /S=0K /G=1" $4 $5 $6 ;=== Size of Data directory
							IntOp $7 $7 - $4 ;=== Remove the plugins directory from the free space calculation

				CalculateSpaceLeft:
					IntCmp $7 $1 NotEnoughSpaceNoUpgrade NotEnoughSpaceNoUpgrade
					Goto EndNotEnoughSpace

				NotEnoughSpaceNoUpgrade:
					MessageBox MB_OK `$(notenoughspace)`
					Abort

				EndNotEnoughSpace:
				${Break}
		${EndSwitch}
FunctionEnd

Section "!App Portable (required)"
	SetOutPath $INSTDIR
	File /r "Files\*.*"
SectionEnd
