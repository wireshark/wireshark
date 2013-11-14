
; WiresharkPortable.nsi - runs Wireshark Portable from a PortableApps enabled device

; $Id$

;Copyright (C) 2004-2007 John T. Haller of PortableApps.com

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

!define NAME "WiresharkPortable"
!define FULLNAME "Wireshark Portable"
!define APP "Wireshark"
!define WEBSITE "www.wireshark.org"
!define DEFAULTEXE "wireshark.exe"
!define DEFAULTAPPDIR "Wireshark"

!addplugindir "${EXTRA_PLUGINS}"

;=== Program Details
Name "${FULLNAME}"
OutFile "Files\${NAME}.exe"
Caption "${FULLNAME} | PortableApps.com"
VIProductVersion "${VERSION}"
VIAddVersionKey ProductName "${FULLNAME}"
VIAddVersionKey Comments "Allows ${APP} to be run from a removable drive.  For additional details, visit ${WEBSITE}"
VIAddVersionKey CompanyName "Wireshark.org"
VIAddVersionKey LegalCopyright "Gerald Combs"
VIAddVersionKey FileDescription "${FULLNAME}"
VIAddVersionKey FileVersion "${VERSION}"
VIAddVersionKey ProductVersion "${VERSION}"
VIAddVersionKey InternalName "${FULLNAME}"
VIAddVersionKey LegalTrademarks "Wireshark and the fin logo are registered trademarks of Gerald C. Combs"
VIAddVersionKey OriginalFilename "${NAME}.exe"
;VIAddVersionKey PrivateBuild ""
;VIAddVersionKey SpecialBuild ""

;=== Runtime Switches
CRCCheck On
WindowIcon Off
SilentInstall Silent
AutoCloseWindow True
RequestExecutionLevel user
XPStyle on

;=== Include
!include "FileFunc.nsh"
!insertmacro GetParameters

;=== Program Icon
Icon "Files\App\AppInfo\appicon.ico"

;=== Variables
Var PROGRAMDIRECTORY
Var ADDITIONALPARAMETERS
Var EXECSTRING
Var PROGRAMEXECUTABLE
Var INIPATH
Var DISABLEWINPCAPINSTALL
Var WINPCAPINSTALLER
Var WINPCAP_UNINSTALL ;declare variable for holding the value of a registry key
Var MSVCREDIST
Var MSVCREDIST_UNINSTALL ;declare variable for holding the value of a registry key
Var PDRIVE

Section "Main"
	;=== Check if another WiresharkPortable already running
	;System::Call 'kernel32::CreateMutexA(i 0, i 0, t "${NAME}") i .r1 ?e'
	;Pop $0
	;StrCmp $0 0 CheckINI
	;	Goto WarnAnotherInstance

	CheckINI:
		;=== Find the INI file, if there is one
		IfFileExists "$EXEDIR\${NAME}.ini" "" CheckSubINI
			StrCpy "$INIPATH" "$EXEDIR"
			Goto ReadINI

	CheckSubINI:
		IfFileExists "$EXEDIR\${NAME}\${NAME}.ini" "" NoINI
			StrCpy "$INIPATH" "$EXEDIR\${NAME}"
			Goto ReadINI

	ReadINI:
		;=== Read the parameters from the INI file
		ReadINIStr $0 "$INIPATH\${NAME}.ini" "${NAME}" "${APP}Directory"
		StrCpy "$PROGRAMDIRECTORY" "$EXEDIR\$0"
	
		;=== Check that the above required parameters are present
		IfErrors NoINI

		ReadINIStr $PROGRAMEXECUTABLE "$INIPATH\${NAME}.ini" "${NAME}" "${APP}Executable"		
		ReadINIStr $ADDITIONALPARAMETERS "$INIPATH\${NAME}.ini" "${NAME}" "AdditionalParameters"

		ReadINIStr $DISABLEWINPCAPINSTALL "$INIPATH\${NAME}.ini" "${NAME}" "DisableWinPcapInstall"
		ReadINIStr $WINPCAPINSTALLER "$INIPATH\${NAME}.ini" "${NAME}" "WinPcapInstaller"
		ReadINIStr $MSVCREDIST "$INIPATH\${NAME}.ini" "${NAME}" "MSVCRedist"

	;CleanUpAnyErrors:
		;=== Any missing unrequired INI entries will be an empty string, ignore associated errors
		ClearErrors

		;=== Correct PROGRAMEXECUTABLE if blank
		StrCmp $PROGRAMEXECUTABLE "" "" EndINI
			StrCpy "$PROGRAMEXECUTABLE" "${DEFAULTEXE}"
			Goto EndINI

		;=== Correct WINPCAPINSTALLER if blank
		StrCmp $WINPCAPINSTALLER "" "" EndINI
			StrCpy "$WINPCAPINSTALLER" "${DEFAULTWINPCAP}"
			Goto EndINI

	NoINI:
		;=== No INI file, so we'll use the defaults
		StrCpy "$ADDITIONALPARAMETERS" ""
		StrCpy "$PROGRAMEXECUTABLE" "${DEFAULTEXE}"
		StrCpy "$WINPCAPINSTALLER" "${DEFAULTWINPCAP}"
		StrCpy "$MSVCREDIST" "${DEFAULTMSVCREDIST}"		

		IfFileExists "$EXEDIR\App\${DEFAULTAPPDIR}\${DEFAULTEXE}" "" CheckPortableProgramDIR
			StrCpy "$PROGRAMDIRECTORY" "$EXEDIR\App\${DEFAULTAPPDIR}"
			GoTo EndINI

		CheckPortableProgramDIR:
			IfFileExists "$EXEDIR\${NAME}\App\${DEFAULTAPPDIR}\${DEFAULTEXE}" "" NoProgramEXE
			StrCpy "$PROGRAMDIRECTORY" "$EXEDIR\${NAME}\App\${DEFAULTAPPDIR}"
			GoTo EndINI

	EndINI:
		IfFileExists "$PROGRAMDIRECTORY\$PROGRAMEXECUTABLE" GetPassedParameters

	NoProgramEXE:
		;=== Program executable not where expected
		MessageBox MB_OK|MB_ICONEXCLAMATION `$PROGRAMEXECUTABLE was not found.  Please check your configuration`
		Abort
		
	FoundProgramEXE:
		;=== Check if Wireshark running from somwehere else (e.g. U3 device)
		; if the following step fails, you'll need the FindProcDLL plug-in from:
		; http://nsis.sourceforge.net/Find_Process_By_Name 
		;FindProcDLL::FindProc "${PROGRAMEXECUTABLE}"
		;StrCmp $R0 "1" WarnAnotherInstance GetPassedParameters

	;WarnAnotherInstance:
	;	MessageBox MB_OK|MB_ICONINFORMATION `Another instance of ${APP} is already running. Please close other instances of ${APP} before launching ${FULLNAME}.`
	;	Abort
	
	GetPassedParameters:
		;=== Get any passed parameters
		${GetParameters} $0
		StrCmp "'$0'" "''" "" LaunchProgramParameters

		;=== No parameters
		StrCpy $EXECSTRING `"$PROGRAMDIRECTORY\$PROGRAMEXECUTABLE"`
		Goto AdditionalParameters

	LaunchProgramParameters:
		StrCpy $EXECSTRING `"$PROGRAMDIRECTORY\$PROGRAMEXECUTABLE" $0`

	AdditionalParameters:
		StrCmp $ADDITIONALPARAMETERS "" CheckWinPcap

		;=== Additional Parameters
		StrCpy $EXECSTRING `$EXECSTRING $ADDITIONALPARAMETERS`

	CheckWinPcap: 
		StrCmp $DISABLEWINPCAPINSTALL "true" EnvironmentVariables

		ReadRegStr $WINPCAP_UNINSTALL HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "UninstallString"
		IfErrors InstallWinPcap

		StrCpy	$WINPCAP_UNINSTALL ""

		goto CheckRedist

	InstallWinPcap: 
		MessageBox MB_YESNO "If you want to capture packets from the network you will need to install WinPcap.\nIt will be uninstalled when you exit Wireshark.\n\nDo you want to install WinPcap?" /SD IDYES IDNO CheckRedist
		ExecWait `"$PROGRAMDIRECTORY\$WINPCAPINSTALLER"`
		;=== remember the uninstall string for when we are done		
		ReadRegStr $WINPCAP_UNINSTALL HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst" "UninstallString"

	CheckRedist: 

		ReadRegStr $MSVCREDIST_UNINSTALL HKLM "SOFTWARE\Microsoft\CurrentVersion\Uninstall\{A49F249F-0C91-497F-86DF-B2585E8E76B7}" "UninstallString"
		IfErrors InstallRedist

		StrCpy	$MSVCREDIST_UNINSTALL ""

		goto EnvironmentVariables

	InstallRedist:
		ExecWait `"$PROGRAMDIRECTORY\$MSVCREDIST" /q`
		;=== remember the uninstall string for when we are done		

		ReadRegStr $MSVCREDIST_UNINSTALL HKLM "SOFTWARE\Microsoft\CurrentVersion\Uninstall\{A49F249F-0C91-497F-86DF-B2585E8E76B7}" "UninstallString"

	EnvironmentVariables:
		; set the U3 environment variables
		StrCpy $PDRIVE $EXEDIR 2
		System::Call 'Kernel32::SetEnvironmentVariableA(t,t) i("U3_DEVICE_SERIAL", "0000060414068917").r0'
		System::Call 'Kernel32::SetEnvironmentVariableA(t,t) i("U3_DEVICE_PATH", "$PDRIVE").r0'
		System::Call 'Kernel32::SetEnvironmentVariableA(t,t) i("U3_DOCUMENT_PATH", "$PDRIVE\Documents").r0'	
		System::Call 'Kernel32::SetEnvironmentVariableA(t,t) i("U3_DEVICE_VENDOR", "Wireshark Developers").r0'
		System::Call 'Kernel32::SetEnvironmentVariableA(t,t) i("U3_DEVICE_PRODUCT", "PortableApps").r0'
		System::Call 'Kernel32::SetEnvironmentVariableA(t,t) i("U3_DEVICE_VENDOR_ID", "0000").r0'
		System::Call 'Kernel32::SetEnvironmentVariableA(t,t) i("U3_APP_DATA_PATH", "$EXEDIR\Data").r0'
		System::Call 'Kernel32::SetEnvironmentVariableA(t,t) i("U3_HOST_EXEC_PATH", "$EXEDIR\App\Wireshark").r0'
		System::Call 'Kernel32::SetEnvironmentVariableA(t,t) i("U3_DEVICE_EXEC_PATH", "$EXEDIR\App\Wireshark").r0'
		System::Call 'Kernel32::SetEnvironmentVariableA(t,t) i("U3_ENV_VERSION", "1.0").r0'
		System::Call 'Kernel32::SetEnvironmentVariableA(t,t) i("U3_ENV_LANGUAGE", "1033").r0'
		StrCmp $SECONDARYLAUNCH "true" LaunchAndExit

		ExecWait $EXECSTRING
		
	CheckRunning:
		Sleep 1000
		FindProcDLL::FindProc "${DEFAULTEXE}"                  
		StrCmp $R0 "1" CheckRunning

		StrCmp $WINPCAP_UNINSTALL "" UninstallRedist ;=== if we installed it, uninstall it
		ExecWait $WINPCAP_UNINSTALL	

	UninstallRedist:

		StrCmp $MSVCREDIST_UNINSTALL "" TheEnd ;=== if we installed it, uninstall it

		ExecWait $MSVCREDIST_UNINSTALL

	Goto TheEnd
	
	LaunchAndExit:
		Exec $EXECSTRING

	TheEnd:
SectionEnd
