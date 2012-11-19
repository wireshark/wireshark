/* capture_win_ifnames.c
* Routines supporting the use of Windows friendly interface names within Wireshark
* Copyright 2011-2012, Mike Garratt <wireshark@evn.co.nz>
*
* $Id$
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "config.h"

#ifdef _WIN32

#include <windows.h>
#include <objbase.h> /* for CLSIDFromString() to convert guid text to a GUID */
#include <tchar.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

#include <wtap.h>
#include <libpcap.h>
#include <glib.h>

#include <ntddndis.h>

#include "log.h"

#include "capture_ifinfo.h"
#include "capture_win_ifnames.h"
#include "wsutil/file_util.h"

/* Link with ole32.lib - provides CLSIDFromString() to convert guid text to a GUID */
#pragma comment(lib, "ole32.lib")

/**********************************************************************************/
gboolean IsWindowsVistaOrLater()
{
    OSVERSIONINFO osvi;

    SecureZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    if(GetVersionEx(&osvi)){
        return osvi.dwMajorVersion >= 6;
    }
    return FALSE;
}
/**********************************************************************************/
/* The wireshark gui doesn't appear at this stage to support having logging messages
* returned using g_log() before the interface list.
* Below is a generic logging function that can be easily ripped out or configured to
* redirect to g_log() if the behaviour changes in the future.
*/
static void ifnames_log(const gchar *log_domain, GLogLevelFlags log_level, const gchar *format, ...)
{
    char buf[16384];
    va_list args;

    if(log_level!=G_LOG_LEVEL_ERROR){
        return;
    }

    va_start(args, format);
    vsnprintf(buf, 16383, format, args);
    va_end(args);

    fprintf(stderr,"%s\r\n",buf);

}

#define g_log ifnames_log
/**********************************************************************************/
/* Get the Connection Name for the given GUID */
static int GetInterfaceFriendlyNameFromDeviceGuid(__in GUID *guid, __out char **Name)
{
    HMODULE hIPHlpApi;
    HRESULT status;
    WCHAR wName[NDIS_IF_MAX_STRING_SIZE + 1];
    HRESULT hr;
    gboolean fallbackToUnpublishedApi=TRUE;
    gboolean haveInterfaceFriendlyName=FALSE;

    /* check we have a parameter */
    if(Name==NULL){
        return -1;
    }

    /* Load the ip helper api DLL */
    hIPHlpApi = LoadLibrary(TEXT("iphlpapi.dll"));
    if (hIPHlpApi == NULL) {
        /* Load failed - DLL should always be available in XP+*/
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_ERROR,
            "Failed to load iphlpapi.dll library for interface name lookups, errorcode=0x%08x\n", GetLastError());
        return -1;
    }

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Loaded iphlpapi.dll library for interface friendly name lookups");

    /* Need to convert an Interface GUID to the interface friendly name (e.g. "Local Area Connection")
    * The functions required to do this all reside within iphlpapi.dll
    * - The preferred approach is to use published API functions (Available since Windows Vista)
    * - We do however fallback to trying undocumented API if the published API is not available (Windows XP/2k3 scenario)
    */

    if(IsWindowsVistaOrLater()){
        /* Published API function prototypes (for Windows Vista/Windows Server 2008+) */
        typedef NETIO_STATUS (WINAPI *ProcAddr_CIG2L) (__in CONST GUID *InterfaceGuid, __out PNET_LUID InterfaceLuid);
        typedef NETIO_STATUS (WINAPI *ProcAddr_CIL2A) ( __in CONST NET_LUID *InterfaceLuid,__out_ecount(Length) PWSTR InterfaceAlias, __in SIZE_T Length);

        /* Attempt to do the conversion using Published API functions */
        ProcAddr_CIG2L proc_ConvertInterfaceGuidToLuid=(ProcAddr_CIG2L) GetProcAddress(hIPHlpApi, "ConvertInterfaceGuidToLuid");
        if(proc_ConvertInterfaceGuidToLuid!=NULL){
            ProcAddr_CIL2A Proc_ConvertInterfaceLuidToAlias=(ProcAddr_CIL2A) GetProcAddress(hIPHlpApi, "ConvertInterfaceLuidToAlias");
            if(Proc_ConvertInterfaceLuidToAlias!=NULL){
                /* we have our functions ready to go, attempt to convert interface guid->luid->friendlyname */
                NET_LUID InterfaceLuid;
                hr = proc_ConvertInterfaceGuidToLuid(guid, &InterfaceLuid);
                if(hr==NO_ERROR){
                    /* guid->luid success */
                    hr = Proc_ConvertInterfaceLuidToAlias(&InterfaceLuid, wName, NDIS_IF_MAX_STRING_SIZE+1);

                    if(hr==NO_ERROR){
                        /* luid->friendly name success */
                        haveInterfaceFriendlyName=TRUE; /* success */
                        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                            "converted interface guid to friendly name.");
                    }else{
                        /* luid->friendly name failed */
                        fallbackToUnpublishedApi=FALSE;
                        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE,
                            "ConvertInterfaceLuidToAlias failed to convert interface luid to a friendly name, LastErrorCode=0x%08x.", GetLastError());
                    }
                }else{
                    fallbackToUnpublishedApi=FALSE;
                    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE,
                        "ConvertInterfaceGuidToLuid failed to convert interface guid to a luid, LastErrorCode=0x%08x.", GetLastError());
                }

            }else{
                g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_ERROR,
                    "Failed to find address of ConvertInterfaceLuidToAlias in iphlpapi.dll, LastErrorCode=0x%08x.", GetLastError());
            }
        }else{
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_ERROR,
                "Failed to find address of ConvertInterfaceGuidToLuid in iphlpapi.dll, LastErrorCode=0x%08x.", GetLastError());
        }
    }


    if(fallbackToUnpublishedApi && !haveInterfaceFriendlyName){
        /* Didn't manage to get the friendly name using published api functions
        * (most likely cause wireshark is running on Windows XP/Server 2003)
        * Retry using nhGetInterfaceNameFromGuid (an older unpublished API function) */
        typedef HRESULT (WINAPI *ProcAddr_nhGINFG) (__in GUID *InterfaceGuid, __out PCWSTR InterfaceAlias, __inout DWORD *LengthAddress, wchar_t *a4, wchar_t *a5);

        ProcAddr_nhGINFG Proc_nhGetInterfaceNameFromGuid = NULL;
        Proc_nhGetInterfaceNameFromGuid = (ProcAddr_nhGINFG) GetProcAddress(hIPHlpApi, "NhGetInterfaceNameFromGuid");
        if (Proc_nhGetInterfaceNameFromGuid!= NULL) {
            wchar_t *p4=NULL, *p5=NULL;
            DWORD NameSize;

            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                "Unpublished NhGetInterfaceNameFromGuid function located in iphlpapi.dll, looking up friendly name from guid");

            /* testing of nhGetInterfaceNameFromGuid indicates the unpublished API function expects the 3rd parameter
            * to be the available space in bytes (as compared to wchar's) available in the second parameter buffer
            * to receive the friendly name (in unicode format) including the space for the nul termination.*/
            NameSize = sizeof(wName);

            /* do the guid->friendlyname lookup */
            status = Proc_nhGetInterfaceNameFromGuid(guid, wName, &NameSize, p4, p5);

            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                "nhGetInterfaceNameFromGuidProc status =%d, p4=%d, p5=%d, namesize=%d\n", status, (int)p4, (int)p5, NameSize);
            if(status==0){
                haveInterfaceFriendlyName=TRUE; /* success */
                g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG,
                    "Converted interface guid to friendly name.");
            }

        }else{
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_ERROR,
                "Failed to locate unpublished NhGetInterfaceNameFromGuid function located in iphlpapi.dll, "
                "for looking up interface friendly name, LastErrorCode=0x%08x.", GetLastError());
        }

    }

    /* we have finished with iphlpapi.dll - release it */
    FreeLibrary(hIPHlpApi);

    if(!haveInterfaceFriendlyName){
        /* failed to get the friendly name, nothing further to do */
        return -1;
    }

    /* Get the required buffer size, and then convert the string */
    {
        int size = WideCharToMultiByte(CP_UTF8, 0, wName, -1, NULL, 0, NULL, NULL);
        char *name = (char *) g_malloc(size);
        if (name == NULL){
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_ERROR,
                "Failed to allocate memory to convert format of interface friendly name, LastErrorCode=0x%08x.", GetLastError());
            return -1;
        }
        size=WideCharToMultiByte(CP_UTF8, 0, wName, -1, name, size, NULL, NULL);
        if(size==0){
            /* bytes written == 0, indicating some form of error*/
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_ERROR,
                "Error converting format of interface friendly name, LastErrorCode=0x%08x.", GetLastError());
            g_free(name);
            return -1;
        }
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Friendly name is '%s'", name);

        *Name = name;
    }
    return 0;
}


/**********************************************************************************/
/* returns the interface friendly name for a device name, if it is unable to
* resolve the name, "" is returned */
void get_windows_interface_friendlyname(/* IN */ char *interface_devicename, /* OUT */char **interface_friendlyname)
{
    const char* guid_text;
    GUID guid;

    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "test, 1,2,3");

    /* ensure we can return a result */
    if(interface_friendlyname==NULL){
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "open_raw_pipe sdfsd");
        fflush(stderr);
        fflush(stdout);
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_ERROR,
            "invalid interface_friendlyname parameter to get_windows_interface_friendlyname() function.");
        return;
    }
    /* start on the basis we know nothing */
    *interface_friendlyname=NULL;

    /* Extract the guid text from the interface device name */
    if(strncmp("\\Device\\NPF_", interface_devicename, 12)==0){
        guid_text=interface_devicename+12; /* skip over the '\Device\NPF_' prefix, assume the rest is the guid text */
    }else{
        guid_text=interface_devicename;
    }

    /*** Convert the guid text the GUID structure */
    {
        /* Part 1: guid_text to unicode, dynamically allocating sufficent memory for conversion*/
        WCHAR wGuidText[39];
        HRESULT hr;
        int size=39; /* a guid should always been 38 unicode characters in length (+1 for null termination) */
        size=MultiByteToWideChar(CP_ACP, 0, guid_text, -1, wGuidText, size);
        if(size!=39){
            /* guid text to unicode conversion failed */
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_ERROR,
                "Failed the extract guid from interface devicename, unicode convert result=%d, guid input ='%s', LastErrorCode=0x%08x.",
                size, guid_text, GetLastError());
            return;
        }
        /* Part 2: unicode guid text to GUID structure */
        hr = CLSIDFromString(wGuidText, (LPCLSID)&guid);
        if (hr != S_OK){
            /* guid text to unicode conversion failed */
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_ERROR,
                "Failed to convert interface devicename guid to GUID structure, convert result=0x%08x, guid input ='%s', LastErrorCode=0x%08x.",
                hr, guid_text, GetLastError());
            return;
        }
    }

    /* guid okay, get the interface friendly name associated with the guid */
    {
        int r=GetInterfaceFriendlyNameFromDeviceGuid(&guid, interface_friendlyname);
        if(r!=NO_ERROR){
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_ERROR,
                "Failed to retrieve interface friendly name associated with interface '%s', LastErrorCode=0x%08x.",
                interface_devicename, GetLastError());
            *interface_friendlyname=NULL; /* failed to get friendly name, ensure the ultimate result is NULL */
            return;
        }
    }

    /* success */
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE,
        "\nInterface %s => '%s'\n\n\n", interface_devicename, *interface_friendlyname);

    return;
}

#undef g_log

/**************************************************************************************/
#endif

