/* etl.h
*
 * Copyright 2020, Odysseus Yang
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_ETW_MESSAGE_H__
#define __W_ETW_MESSAGE_H__

#include <glib.h>
#include "config.h"

#include <windows.h>
#include <SDKDDKVer.h>
#include <strsafe.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdlib.h>

#define MAX_SMALL_BUFFER 4
#define MAX_LOG_LINE_LENGTH 1024
#define MAX_KEY_LENGTH 64

typedef struct Property_Key_Value
{
    WCHAR key[MAX_KEY_LENGTH];
    WCHAR value[MAX_LOG_LINE_LENGTH];
} PROPERTY_KEY_VALUE;

typedef struct in6_addr {
    union {
        UCHAR       Byte[16];
        USHORT      Word[8];
    } u;
} IN6_ADDR, * PIN6_ADDR, FAR* LPIN6_ADDR;

VOID format_message(WCHAR* lpszMessage, PROPERTY_KEY_VALUE* propArray, DWORD dwPropertyCount, WCHAR* lpszOutBuffer, DWORD dwOutBufferCount);
BOOL get_event_information(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO* pInfo);
PBYTE extract_properties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData, PROPERTY_KEY_VALUE* pExtract);

#endif


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
