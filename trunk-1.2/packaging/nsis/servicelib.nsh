; from http://nsis.sourceforge.net/wiki/NSIS_Service_Lib
; un. functions disabled to prevent a NSIS warning
;
; NSIS SERVICE LIBRARY - servicelib.nsh
; Version 1.2 - 02/29/2004
; Questions/Comments - dselkirk@hotmail.com
;
; Description:
;   Provides an interface to window services
;
; Inputs:
;   action	- systemlib action ie. create, delete, start, stop, pause,
;		continue, installed, running, status
;   name	- name of service to manipulate
;   param	- action parameters; usage: var1=value1;var2=value2;...etc.
;
; Actions:
;   create	- creates a new windows service
;		Parameters:
;		  path	- path to service executable
;		  autostart	- automatically start with system ie. 1|0
;		  interact	- interact with the desktop ie. 1|0
;		  machine	- machine name where to install service
;		  user		- user that runs the service
;		  password	- password of the above user
;
;   delete	- deletes a windows service
;   start	- start a stopped windows service
;   stop	- stops a running windows service
;   pause	- pauses a running windows service
;   continue	- continues a paused windows service
;   installed	- is the provided service installed
;		Parameters:
;		  action	- if true then invokes the specified action
;   running	- is the provided service running
;		Parameters:
;		  action	- if true then invokes the specified action
;   status	- check the status of the provided service
;
; If run from uninstall define "UN" as "un." gefore running.
;
; Usage:
;   Method 1:
;     Push "action"
;     Push "name"
;     Push "param"
;     Call Service
;     Pop $0 ;response
;
;   Method 2:
;     !insertmacro SERVICE "action" "name" "param"
;
; History:
;		1.0 - 09/15/2003 - Initial release
;		1.1 - 09/16/2003 - Changed &l to i, thx brainsucker
;		1.2 - 02/29/2004 - Fixed documentation.
 
!ifndef SERVICELIB
  !define SERVICELIB
 
  !define SC_MANAGER_ALL_ACCESS 0x3F
  !define SERVICE_ALL_ACCESS 0xF01FF
 
  !define SERVICE_CONTROL_STOP  1
  !define SERVICE_CONTROL_PAUSE  2
  !define SERVICE_CONTROL_CONTINUE  3
 
  !define SERVICE_STOPPED 0x1
  !define SERVICE_START_PENDING 0x2
  !define SERVICE_STOP_PENDING 0x3
  !define SERVICE_RUNNING 0x4
  !define SERVICE_CONTINUE_PENDING 0x5
  !define SERVICE_PAUSE_PENDING 0x6
  !define SERVICE_PAUSED 0x7
 
  !ifndef UN
    !define UN ""
  !endif
 
  !macro SERVICE ACTION NAME PARAM
    Push '${ACTION}'
    Push '${NAME}'
    Push '${PARAM}'
    Call ${UN}Service
  !macroend
 
  !macro FUNC_GETPARAM
    Push $0
    Push $1
    Push $2
    Push $3
    Push $4
    Push $5
    Push $6
    Push $7
    Exch 8
    Pop $1 ;name
    Exch 8
    Pop $2 ;source
    StrCpy $0 ""
    StrLen $7 $2
    StrCpy $3 0
    lbl_loop:
      IntCmp $3 $7 0 0 lbl_done
      StrLen $4 "$1="
      StrCpy $5 $2 $4 $3
      StrCmp $5 "$1=" 0 lbl_next
      IntOp $5 $3 + $4
      StrCpy $3 $5
      lbl_loop2:
        IntCmp $3 $7 0 0 lbl_done
        StrCpy $6 $2 1 $3
        StrCmp $6 ";" 0 lbl_next2
        IntOp $6 $3 - $5
        StrCpy $0 $2 $6 $5
        Goto lbl_done
        lbl_next2:
        IntOp $3 $3 + 1
        Goto lbl_loop2
      lbl_next:
      IntOp $3 $3 + 1
      Goto lbl_loop
    lbl_done:
    Pop $5
    Pop $4
    Pop $3
    Pop $2
    Pop $1
    Exch 2
    Pop $6
    Pop $7
    Exch $0
  !macroend
 
  !macro CALL_GETPARAM VAR NAME DEFAULT LABEL
    Push $1
    Push ${NAME}
    Call ${UN}GETPARAM
    Pop $6
    StrCpy ${VAR} "${DEFAULT}"
    StrCmp $6 "" "${LABEL}" 0
    StrCpy ${VAR} $6
  !macroend
 
  !macro FUNC_SERVICE UN
    Push $0
    Push $1
    Push $2
    Push $3
    Push $4
    Push $5
    Push $6
    Push $7
    Exch 8
    Pop $1 ;param
    Exch 8
    Pop $2 ;name
    Exch 8
    Pop $3 ;action
    ;$0 return
    ;$4 OpenSCManager
    ;$5 OpenService
 
 
    StrCpy $0 "false"
    System::Call 'advapi32::OpenSCManagerA(n, n, i ${SC_MANAGER_ALL_ACCESS}) i.r4'
    IntCmp $4 0 lbl_done
    StrCmp $3 "create" lbl_create
    System::Call 'advapi32::OpenServiceA(i r4, t r2, i ${SERVICE_ALL_ACCESS}) i.r5'
    IntCmp $5 0 lbl_done
 
    lbl_select:
    StrCmp $3 "delete" lbl_delete
    StrCmp $3 "start" lbl_start
    StrCmp $3 "stop" lbl_stop
    StrCmp $3 "pause" lbl_pause
    StrCmp $3 "continue" lbl_continue
    StrCmp $3 "installed" lbl_installed
    StrCmp $3 "running" lbl_running
    StrCmp $3 "status" lbl_status
    Goto lbl_done
 
    ; create service
    lbl_create:
      Push $R1 ;machine
      Push $R2 ;user
      Push $R3 ;password
      Push $R4 ;interact
      Push $R5 ;autostart
      Push $R6 ;path
 
      !insertmacro CALL_GETPARAM $R1 "machine" "n" "lbl_machine"
      lbl_machine:
 
      !insertmacro CALL_GETPARAM $R2 "user" "n" "lbl_user"
      lbl_user:
 
      !insertmacro CALL_GETPARAM $R3 "password" "n" "lbl_password"
      lbl_password:
 
      !insertmacro CALL_GETPARAM $R4 "interact" "0x10" "lbl_interact"
        StrCpy $6 0x10
        IntCmp $R4 0 +2
        IntOp $R4 $6 | 0x100
        StrCpy $R4 $6
      lbl_interact:
 
      !insertmacro CALL_GETPARAM $R5 "autostart" "0x3" "lbl_autostart"
        StrCpy $6 0x3
        IntCmp $R5 0 +2
        StrCpy $6 0x2
        StrCpy $R5 $6
      lbl_autostart:
 
      !insertmacro CALL_GETPARAM $R6 "path" "n" "lbl_path"
      lbl_path:
 
      System::Call 'advapi32::CreateServiceA(i r4, t r2, t r2, i ${SERVICE_ALL_ACCESS}, i R4, i R5, i 0, t R6, n, n, R1, R2, R3) i.r6'
      Pop $R6
      Pop $R5
      Pop $R4
      Pop $R3
      Pop $R2
      Pop $R1
      StrCmp $6 0 lbl_done lbl_good
 
    ; delete service
    lbl_delete:
      System::Call 'advapi32::DeleteService(i r5) i.r6'
      StrCmp $6 0 lbl_done lbl_good
 
    ; start service
    lbl_start:
      System::Call 'advapi32::StartServiceA(i r5, i 0, i 0) i.r6'
      StrCmp $6 0 lbl_done lbl_good
 
    ; stop service
    lbl_stop:
      Push $R1
      System::Call '*(i,i,i,i,i,i,i) i.R1'
      System::Call 'advapi32::ControlService(i r5, i ${SERVICE_CONTROL_STOP}, i $R1) i'
      System::Free $R1
      Pop $R1
      StrCmp $6 0 lbl_done lbl_good
 
    ; pause service
    lbl_pause:
      Push $R1
      System::Call '*(i,i,i,i,i,i,i) i.R1'
      System::Call 'advapi32::ControlService(i r5, i ${SERVICE_CONTROL_PAUSE}, i $R1) i'
      System::Free $R1
      Pop $R1
      StrCmp $6 0 lbl_done lbl_good
 
    ; continue service
    lbl_continue:
      Push $R1
      System::Call '*(i,i,i,i,i,i,i) i.R1'
      System::Call 'advapi32::ControlService(i r5, i ${SERVICE_CONTROL_CONTINUE}, i $R1) i'
      System::Free $R1
      Pop $R1
      StrCmp $6 0 lbl_done lbl_good
 
    ; is installed
    lbl_installed:
      !insertmacro CALL_GETPARAM $7 "action" "" "lbl_good"
        StrCpy $3 $7
        Goto lbl_select
 
    ; is service running
    lbl_running:
      Push $R1
      System::Call '*(i,i,i,i,i,i,i) i.R1'
      System::Call 'advapi32::QueryServiceStatus(i r5, i $R1) i'
      System::Call '*$R1(i, i.r6)'
      System::Free $R1
      Pop $R1
      IntFmt $6 "0x%X" $6
      StrCmp $6 ${SERVICE_RUNNING} 0 lbl_done
      !insertmacro CALL_GETPARAM $7 "action" "" "lbl_good"
        StrCpy $3 $7
        Goto lbl_select
 
    lbl_status:
      Push $R1
      System::Call '*(i,i,i,i,i,i,i) i.R1'
      System::Call 'advapi32::QueryServiceStatus(i r5, i $R1) i'
      System::Call '*$R1(i, i .r6)'
      System::Free $R1
      Pop $R1
      IntFmt $6 "0x%X" $6
      StrCpy $0 "running"
      IntCmp $6 ${SERVICE_RUNNING} lbl_done
      StrCpy $0 "stopped"
      IntCmp $6 ${SERVICE_STOPPED} lbl_done
      StrCpy $0 "start_pending"
      IntCmp $6 ${SERVICE_START_PENDING} lbl_done
      StrCpy $0 "stop_pending"
      IntCmp $6 ${SERVICE_STOP_PENDING} lbl_done
      StrCpy $0 "running"
      IntCmp $6 ${SERVICE_RUNNING} lbl_done
      StrCpy $0 "continue_pending"
      IntCmp $6 ${SERVICE_CONTINUE_PENDING} lbl_done
      StrCpy $0 "pause_pending"
      IntCmp $6 ${SERVICE_PAUSE_PENDING} lbl_done
      StrCpy $0 "paused"
      IntCmp $6 ${SERVICE_PAUSED} lbl_done
      StrCpy $0 "unknown"
 
    lbl_good:
    StrCpy $0 "true"
    lbl_done:
    IntCmp $5 0 +2
    System::Call 'advapi32::CloseServiceHandle(i r5) n'
    IntCmp $4 0 +2
    System::Call 'advapi32::CloseServiceHandle(i r4) n'
    Pop $4
    Pop $3
    Pop $2
    Pop $1
    Exch 3
    Pop $5
    Pop $6
    Pop $7
    Exch $0
  !macroend
 
  Function Service
    !insertmacro FUNC_SERVICE ""
  FunctionEnd
 
;  Function un.Service
;    !insertmacro FUNC_SERVICE "un."
;  FunctionEnd
 
  Function GetParam
    !insertmacro FUNC_GETPARAM
  FunctionEnd
 
;  Function un.GetParam
;    !insertmacro FUNC_GETPARAM
;  FunctionEnd
 
!endif
