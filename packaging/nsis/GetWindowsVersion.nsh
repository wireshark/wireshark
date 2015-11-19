; GetWindowsVersion 4.1.1 (2015-06-22) - alternate script with server versions
;
; http://nsis.sourceforge.net/Get_Windows_version
;
; Based on Yazno's function, http://yazno.tripod.com/powerpimpit/
; Update by Joost Verburg
; Update (Macro, Define, Windows 7 detection) - John T. Haller of PortableApps.com - 2008-01-07
; Update (Windows 8 detection) - Marek Mizanin (Zanir) - 2013-02-07
; Update (Windows 8.1 detection) - John T. Haller of PortableApps.com - 2014-04-04
; Update (Windows 2008, 2008R2, 2012 and 2012R2 detection) - Francisco Simoões Filho franksimoes@gmail.com - 2014-08-25
; Update (Windows 10 TP detection) - John T. Haller of PortableApps.com - 2014-10-01
; Update (Windows 10 TP4 and 2016 detection, and added include guards) - Kairu - 2015-06-22
;
; Usage: ${GetWindowsVersion} $R0
;
; $R0 contains: 95, 98, ME, NT x.x, 2000, XP, 2003, Vista, 2008, 7, 2008R2,
;                8, 2012, 8.1, 2012R2, 10.0, 2016 or '' (for unknown)

!ifndef __GET_WINDOWS_VERSION_NSH
!define __GET_WINDOWS_VERSION_NSH

Function GetWindowsVersion

  Push $R0
  Push $R1
  Push $R2

  ClearErrors

  ; check if Windows NT family
  ReadRegStr $R0 HKLM \
  "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion

  IfErrors 0 lbl_winnt

  ; we are not NT
  ReadRegStr $R0 HKLM \
  "SOFTWARE\Microsoft\Windows\CurrentVersion" VersionNumber

  StrCpy $R1 $R0 1
  StrCmp $R1 '4' 0 lbl_error

  StrCpy $R1 $R0 3

  StrCmp $R1 '4.0' lbl_win32_95
  StrCmp $R1 '4.9' lbl_win32_ME lbl_win32_98

  lbl_win32_95:
    StrCpy $R0 '95'
  Goto lbl_done

  lbl_win32_98:
    StrCpy $R0 '98'
  Goto lbl_done

  lbl_win32_ME:
    StrCpy $R0 'ME'
  Goto lbl_done

  lbl_winnt:

  ; check if Windows is Client or Server.
  ReadRegStr $R2 HKLM \
  "SOFTWARE\Microsoft\Windows NT\CurrentVersion" InstallationType

  StrCpy $R1 $R0 1

  StrCmp $R1 '3' lbl_winnt_x
  StrCmp $R1 '4' lbl_winnt_x

  StrCpy $R1 $R0 3

  StrCmp $R1 '5.0' lbl_winnt_2000
  StrCmp $R1 '5.1' lbl_winnt_XP
  StrCmp $R1 '5.2' lbl_winnt_2003
  StrCmp $R1 '6.0' lbl_winnt_vista_2008
  StrCmp $R1 '6.1' lbl_winnt_7_2008R2
  StrCmp $R1 '6.2' lbl_winnt_8_2012
  StrCmp $R1 '6.3' lbl_winnt_81_2012R2
  StrCmp $R1 '6.4' lbl_winnt_10_2016 ; the early Windows 10 tech previews used version 6.4

  StrCpy $R1 $R0 4

  StrCmp $R1 '10.0' lbl_winnt_10_2016
  Goto lbl_error

  lbl_winnt_x:
    StrCpy $R0 "NT $R0" 6
  Goto lbl_done

  lbl_winnt_2000:
    Strcpy $R0 '2000'
  Goto lbl_done

  lbl_winnt_XP:
    Strcpy $R0 'XP'
  Goto lbl_done

  lbl_winnt_2003:
    Strcpy $R0 '2003'
  Goto lbl_done

  ;----------------- Family - Vista / 2008 -------------
  lbl_winnt_vista_2008:
    StrCmp $R2 'Client' go_vista
    StrCmp $R2 'Server' go_2008

    go_vista:
      Strcpy $R0 'Vista'
      Goto lbl_done

    go_2008:
      Strcpy $R0 '2008'
      Goto lbl_done
  ;-----------------------------------------------------

  ;----------------- Family - 7 / 2008R2 -------------
  lbl_winnt_7_2008R2:
    StrCmp $R2 'Client' go_7
    StrCmp $R2 'Server' go_2008R2

    go_7:
      Strcpy $R0 '7'
      Goto lbl_done

    go_2008R2:
      Strcpy $R0 '2008R2'
      Goto lbl_done
  ;-----------------------------------------------------

  ;----------------- Family - 8 / 2012 -------------
  lbl_winnt_8_2012:
    StrCmp $R2 'Client' go_8
    StrCmp $R2 'Server' go_2012

    go_8:
      Strcpy $R0 '8'
      Goto lbl_done

    go_2012:
      Strcpy $R0 '2012'
      Goto lbl_done
  ;-----------------------------------------------------

  ;----------------- Family - 8.1 / 2012R2 -------------
  lbl_winnt_81_2012R2:
    StrCmp $R2 'Client' go_81
    StrCmp $R2 'Server' go_2012R2

    go_81:
      Strcpy $R0 '8.1'
      Goto lbl_done

    go_2012R2:
      Strcpy $R0 '2012R2'
      Goto lbl_done
  ;-----------------------------------------------------

  ;----------------- Family - 10 / 2016 -------------
  lbl_winnt_10_2016:
    StrCmp $R2 'Client' go_10
    StrCmp $R2 'Server' go_2016

    go_10:
      Strcpy $R0 '10.0'
      Goto lbl_done

    go_2016:
      Strcpy $R0 '2016'
      Goto lbl_done
  ;-----------------------------------------------------

  lbl_error:
    Strcpy $R0 ''
  lbl_done:

  Pop $R2
  Pop $R1
  Exch $R0

FunctionEnd

!macro GetWindowsVersion OUTPUT_VALUE
	Call GetWindowsVersion
	Pop `${OUTPUT_VALUE}`
!macroend

!define GetWindowsVersion '!insertmacro "GetWindowsVersion"'

!endif
