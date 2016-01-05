/* capture_win_ifnames.c
* Routines supporting the use of Windows friendly interface names within Wireshark
* Copyright 2011-2012, Mike Garratt <wireshark@evn.co.nz>
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

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#include <ntddndis.h>

#ifndef NDIS_IF_MAX_STRING_SIZE
#define NDIS_IF_MAX_STRING_SIZE IF_MAX_STRING_SIZE   /* =256 in <ifdef.h> */
#endif

#ifndef NETIO_STATUS
#define NETIO_STATUS DWORD
#endif

#include "log.h"

#include "caputils/capture_ifinfo.h"
#include "caputils/capture_win_ifnames.h"

#include <wsutil/file_util.h>

static int gethexdigit(const char *p)
{
    if(*p >= '0' && *p <= '9'){
        return *p - '0';
    }else if(*p >= 'A' && *p <= 'F'){
        return *p - 'A' + 0xA;
    }else if(*p >= 'a' && *p <= 'f'){
        return *p - 'a' + 0xa;
    }else{
        return -1; /* Not a hex digit */
    }
}

static gboolean get8hexdigits(const char *p, DWORD *d)
{
    int digit;
    DWORD val;
    int i;

    val = 0;
    for(i = 0; i < 8; i++){
        digit = gethexdigit(p++);
        if(digit == -1){
            return FALSE; /* Not a hex digit */
        }
        val = (val << 4) | digit;
    }
    *d = val;
    return TRUE;
}

static gboolean get4hexdigits(const char *p, WORD *w)
{
    int digit;
    WORD val;
    int i;

    val = 0;
    for(i = 0; i < 4; i++){
        digit = gethexdigit(p++);
        if(digit == -1){
            return FALSE; /* Not a hex digit */
        }
        val = (val << 4) | digit;
    }
    *w = val;
    return TRUE;
}

/*
 * If a string is a GUID in {}, fill in a GUID structure with the GUID
 * value and return TRUE; otherwise, if the string is not a valid GUID
 * in {}, return FALSE.
 */
gboolean
parse_as_guid(const char *guid_text, GUID *guid)
{
    int i;
    int digit1, digit2;

    if(*guid_text != '{'){
        return FALSE; /* Nope, not enclosed in {} */
    }
    guid_text++;
    /* There must be 8 hex digits; if so, they go into guid->Data1 */
    if(!get8hexdigits(guid_text, &guid->Data1)){
        return FALSE; /* nope, not 8 hex digits */
    }
    guid_text += 8;
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /* There must be 4 hex digits; if so, they go into guid->Data2 */
    if(!get4hexdigits(guid_text, &guid->Data2)){
        return FALSE; /* nope, not 4 hex digits */
    }
    guid_text += 4;
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /* There must be 4 hex digits; if so, they go into guid->Data3 */
    if(!get4hexdigits(guid_text, &guid->Data3)){
        return FALSE; /* nope, not 4 hex digits */
    }
    guid_text += 4;
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /*
     * There must be 4 hex digits; if so, they go into the first 2 bytes
     * of guid->Data4.
     */
    for(i = 0; i < 2; i++){
        digit1 = gethexdigit(guid_text);
        if(digit1 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        digit2 = gethexdigit(guid_text);
        if(digit2 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        guid->Data4[i] = (digit1 << 4)|(digit2);
    }
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /*
     * There must be 12 hex digits; if so,t hey go into the next 6 bytes
     * of guid->Data4.
     */
    for(i = 0; i < 6; i++){
        digit1 = gethexdigit(guid_text);
        if(digit1 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        digit2 = gethexdigit(guid_text);
        if(digit2 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        guid->Data4[i+2] = (digit1 << 4)|(digit2);
    }
    /* Now there must be a closing } */
    if(*guid_text != '}'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /* And that must be the end of the string */
    if(*guid_text != '\0'){
        return FALSE; /* Nope */
    }
    return TRUE;
}

/**********************************************************************************/
gboolean IsWindowsVistaOrLater()
{
#if (_MSC_VER >= 1800)
    /*
     * On VS2103, GetVersionEx is deprecated. Microsoft recommend to
     * use VerifyVersionInfo instead
     */
    OSVERSIONINFOEX osvi;
    DWORDLONG dwlConditionMask = 0;
    int op = VER_GREATER_EQUAL;

    SecureZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    osvi.dwMajorVersion = 6;
    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, op);
    return VerifyVersionInfo(&osvi, VER_MAJORVERSION, dwlConditionMask);
#else
    OSVERSIONINFO osvi;

    SecureZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    if(GetVersionEx(&osvi)){
        return osvi.dwMajorVersion >= 6;
    }
    return FALSE;
#endif
}

/**********************************************************************************/
/* Get the friendly name for the given GUID */
char *
get_interface_friendly_name_from_device_guid(__in GUID *guid)
{
    HMODULE hIPHlpApi;
    HRESULT status;
    WCHAR wName[NDIS_IF_MAX_STRING_SIZE + 1];
    HRESULT hr;
    gboolean fallbackToUnpublishedApi=TRUE;
    gboolean haveInterfaceFriendlyName=FALSE;
    int size;
    char *name;

    /* Load the ip helper api DLL */
    hIPHlpApi = LoadLibrary(TEXT("iphlpapi.dll"));
    if (hIPHlpApi == NULL) {
        /* Load failed - DLL should always be available in XP+*/
        return NULL;
    }

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
                    }else{
                        /* luid->friendly name failed */
                        fallbackToUnpublishedApi=FALSE;
                    }
                }else{
                    fallbackToUnpublishedApi=FALSE;
                }

            }
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

            /* testing of nhGetInterfaceNameFromGuid indicates the unpublished API function expects the 3rd parameter
            * to be the available space in bytes (as compared to wchar's) available in the second parameter buffer
            * to receive the friendly name (in unicode format) including the space for the nul termination.*/
            NameSize = sizeof(wName);

            /* do the guid->friendlyname lookup */
            status = Proc_nhGetInterfaceNameFromGuid(guid, wName, &NameSize, p4, p5);

            if(status==0){
                haveInterfaceFriendlyName=TRUE; /* success */
            }
        }
    }

    /* we have finished with iphlpapi.dll - release it */
    FreeLibrary(hIPHlpApi);

    if(!haveInterfaceFriendlyName){
        /* failed to get the friendly name, nothing further to do */
        return NULL;
    }

    /* Get the required buffer size, and then convert the string
    * from UTF-16 to UTF-8. */
    size=WideCharToMultiByte(CP_UTF8, 0, wName, -1, NULL, 0, NULL, NULL);
    name=(char *) g_malloc(size);
    if (name == NULL){
        return NULL;
    }
    size=WideCharToMultiByte(CP_UTF8, 0, wName, -1, name, size, NULL, NULL);
    if(size==0){
        /* bytes written == 0, indicating some form of error*/
        g_free(name);
        return NULL;
    }
    return name;
}

/*
 * Given an interface name, try to extract the GUID from it and parse it.
 * If that fails, return NULL; if that succeeds, attempt to get the
 * friendly name for the interface in question.  If that fails, return
 * NULL, otherwise return the friendly name, allocated with g_malloc()
 * (so that it must be freed with g_free()).
 */
char *
get_windows_interface_friendly_name(const char *interface_devicename)
{
    const char* guid_text;
    GUID guid;

    /* Extract the guid text from the interface device name */
    if(strncmp("\\Device\\NPF_", interface_devicename, 12)==0){
        guid_text=interface_devicename+12; /* skip over the '\Device\NPF_' prefix, assume the rest is the guid text */
    }else{
        guid_text=interface_devicename;
    }

    if (!parse_as_guid(guid_text, &guid)){
        return NULL; /* not a GUID, so no friendly name */
    }

    /* guid okay, get the interface friendly name associated with the guid */
    return get_interface_friendly_name_from_device_guid(&guid);
}

/**************************************************************************************/
#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
