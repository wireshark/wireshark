/* u3util.c
 * Utility routines for U3 device support
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Adapted from Microsoft Knowledge Base Article 178893 
 * 
 * http://support.microsoft.com/?kbid=178893
 *
 * and the U3 Answer 106 
 *
 * https://u3.custhelp.com/cgi-bin/u3/php/enduser/std_adp.php?p_faqid=106
 *
 * Indentation logic: 2-space
 */

#include <windows.h>

#define TA_FAILED 0
#define TA_SUCCESS_CLEAN 1
#define TA_SUCCESS_KILL 2
#define TA_SUCCESS_16 3

DWORD TerminateApp( DWORD dwPID, DWORD dwTimeout ) ;
DWORD Terminate16App( DWORD dwPID, DWORD dwThread, WORD w16Task, DWORD dwTimeout );

#include <vdmdbg.h>

typedef struct
{
  DWORD   dwID ;
  DWORD   dwThread ;
} TERMINFO ;

/* Declare Callback Enum Functions. */
BOOL CALLBACK TerminateAppEnum( HWND hwnd, LPARAM lParam ) ;
BOOL CALLBACK Terminate16AppEnum( HWND hwnd, LPARAM lParam ) ;

/*----------------------------------------------------------------
  DWORD TerminateApp( DWORD dwPID, DWORD dwTimeout )

  Purpose:
      Shut down a 32-Bit Process (or 16-bit process under Windows 95)

  Parameters:
      dwPID
         Process ID of the process to shut down.

      dwTimeout
         Wait time in milliseconds before shutting down the process.

   Return Value:
      TA_FAILED - If the shutdown failed.
      TA_SUCCESS_CLEAN - If the process was shutdown using WM_CLOSE.
      TA_SUCCESS_KILL - if the process was shut down with
         TerminateProcess().
      NOTE:  See header for these defines.
   ----------------------------------------------------------------*/ 

DWORD TerminateApp( DWORD dwPID, DWORD dwTimeout )
{
  HANDLE   hProc ;
  DWORD   dwRet ;

  // If we can't open the process with PROCESS_TERMINATE rights,
  // then we give up immediately.
  hProc = OpenProcess(SYNCHRONIZE|PROCESS_TERMINATE, FALSE, dwPID);

  if(hProc == NULL){
    return TA_FAILED;
  }

  if(dwTimeout) {
    /* we are prepared to wait */

    /* TerminateAppEnum() posts WM_CLOSE to all windows whose PID */
    /* matches your process's. */
    EnumWindows((WNDENUMPROC)TerminateAppEnum, (LPARAM) dwPID) ;

    /* Wait on the handle. If it signals, great. If it times out, */
    /* then you kill it. */
    if(WaitForSingleObject(hProc, dwTimeout)!=WAIT_OBJECT_0)
      dwRet=(TerminateProcess(hProc,0)?TA_SUCCESS_KILL:TA_FAILED);
    else
      dwRet = TA_SUCCESS_CLEAN ;
  } else {
    /* we immediately kill the proces */
    dwRet=(TerminateProcess(hProc,0)?TA_SUCCESS_KILL:TA_FAILED);
  }

  CloseHandle(hProc) ;

  return dwRet ;
}

/*----------------------------------------------------------------
  DWORD Terminate16App( DWORD dwPID, DWORD dwThread,
                        WORD w16Task, DWORD dwTimeout )

   Purpose:
      Shut down a Win16 APP.

   Parameters:
      dwPID
         Process ID of the NTVDM in which the 16-bit application is
         running.

      dwThread
         Thread ID of the thread of execution for the 16-bit
         application.

      w16Task
         16-bit task handle for the application.

      dwTimeout
         Wait time in milliseconds before shutting down the task.

   Return Value:
      If successful, returns TA_SUCCESS_16
      If unsuccessful, returns TA_FAILED.
      NOTE:  These values are defined in the header for this
      function.

   NOTE:
      You can get the Win16 task and thread ID through the
      VDMEnumTaskWOW() or the VDMEnumTaskWOWEx() functions.
   ----------------------------------------------------------------*/ 

DWORD Terminate16App( DWORD dwPID, DWORD dwThread, WORD w16Task, DWORD dwTimeout )
{
  HINSTANCE      hInstLib ;
  TERMINFO      info ;

  /* You will be calling the functions through explicit linking */
  /* so that this code will be binary compatible across */
  /* Win32 platforms. */
  BOOL (WINAPI *lpfVDMTerminateTaskWOW)(DWORD dwProcessId, WORD htask) ;

  hInstLib = LoadLibraryA( "VDMDBG.DLL" ) ;
  if( hInstLib == NULL )
    return TA_FAILED ;

  // Get procedure addresses.
  lpfVDMTerminateTaskWOW = (BOOL (WINAPI *)(DWORD, WORD ))
    GetProcAddress( hInstLib, "VDMTerminateTaskWOW" ) ;

  if( lpfVDMTerminateTaskWOW == NULL )
    {
      FreeLibrary( hInstLib ) ;
      return TA_FAILED ;
    }

  /* Post a WM_CLOSE to all windows that match the ID and the */
  /* thread. */
  info.dwID = dwPID ;
  info.dwThread = dwThread ;
  EnumWindows((WNDENUMPROC)Terminate16AppEnum, (LPARAM) &info) ;

  /* Wait. */
  Sleep( dwTimeout ) ;

  /* Then terminate. */
  lpfVDMTerminateTaskWOW(dwPID, w16Task) ;

  FreeLibrary( hInstLib ) ;
  return TA_SUCCESS_16 ;
}

BOOL CALLBACK TerminateAppEnum( HWND hwnd, LPARAM lParam )
{
  DWORD dwID ;

  GetWindowThreadProcessId(hwnd, &dwID) ;

  if(dwID == (DWORD)lParam)
    {
      PostMessage(hwnd, WM_CLOSE, 0, 0) ;
    }

  return TRUE ;
}

BOOL CALLBACK Terminate16AppEnum( HWND hwnd, LPARAM lParam )
{
  DWORD      dwID ;
  DWORD      dwThread ;
  TERMINFO   *termInfo ;

  termInfo = (TERMINFO *)lParam ;

  dwThread = GetWindowThreadProcessId(hwnd, &dwID) ;

  if(dwID == termInfo->dwID && termInfo->dwThread == dwThread )
    {
      PostMessage(hwnd, WM_CLOSE, 0, 0) ;
    }

  return TRUE ;
}

/* This is the new function */

void app_stop(DWORD timeOut)
{
  DWORD  pid = 0;
  HANDLE hFind = INVALID_HANDLE_VALUE;
  WIN32_FIND_DATA find_file_data;
  DWORD dwError;
  char *u3_host_exec_path;
  char dir_spec[MAX_PATH+1];
  char file_name[MAX_PATH+1];

  u3_host_exec_path = getenv("U3_HOST_EXEC_PATH");

  strncpy(dir_spec, u3_host_exec_path, strlen(u3_host_exec_path) + 1);
  strncat(dir_spec, "\\*.pid", 7);

  hFind = FindFirstFile(dir_spec, &find_file_data);

  if(hFind != INVALID_HANDLE_VALUE) {

    do {

      pid = (DWORD)atoi(find_file_data.cFileName);

      if(pid)
	TerminateApp(pid, timeOut);

      strncpy(file_name, u3_host_exec_path, strlen(u3_host_exec_path) + 1);
      strncat(file_name, "\\", 2);
      strncat(file_name, find_file_data.cFileName, strlen(find_file_data.cFileName) + 1);
      
      DeleteFile(TEXT(file_name));

    } while(FindNextFile(hFind, &find_file_data) != 0);

    FindClose(hFind);

  }

}

void host_clean_up(void)
{
  /* the device has been removed - 
     just close the application as quickly as possible */

  app_stop(0);
}

main(int argc, char *argv[])
{
  DWORD time_out = 0;
  char *u3_is_device_available;

  u3_is_device_available = getenv("U3_IS_DEVICE_AVAILABLE");

  if(u3_is_device_available && !strncmp(u3_is_device_available, "true", 5))
    /* the device is available - wait 5 seconds for user to respond to
       any dialogs */
    time_out = 5000; /* 5 seconds */

  if(argc > 1) {
  
    if(!strncmp(argv[1], "appStop", 8))
      app_stop(time_out);
    else if(!strncmp(argv[1], "hostCleanUp", 11))
      host_clean_up();
    
  }

  exit(0);
}
