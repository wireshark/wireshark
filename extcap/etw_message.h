/** @file
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

#include <windows.h>
#include <SDKDDKVer.h>
#include <strsafe.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdlib.h>
#include <ws2def.h>
#include <ws2ipdef.h>


#define MAX_LOG_LINE_LENGTH 1024
#define MAX_KEY_LENGTH 64

typedef struct Property_Key_Value
{
    USHORT key_length;
    USHORT value_length;
    WCHAR key[MAX_KEY_LENGTH];
    WCHAR value[MAX_LOG_LINE_LENGTH];
} PROPERTY_KEY_VALUE;

/**
 * @brief Formats a message using property key-value pairs.
 *
 * @param lpszMessage The input message string containing format specifiers.
 * @param propArray Array of property key-value pairs to replace format specifiers.
 * @param dwPropertyCount Number of elements in the property array.
 * @param lpszOutBuffer Buffer to store the formatted message.
 * @param dwOutBufferCount Size of the output buffer.
 */
VOID format_message(WCHAR* lpszMessage, PROPERTY_KEY_VALUE* propArray, DWORD dwPropertyCount, WCHAR* lpszOutBuffer, DWORD dwOutBufferCount);

/**
 * @brief Retrieves information about an event.
 *
 * This function retrieves metadata for a given event record using TdhGetEventInformation.
 * If the initial call indicates insufficient buffer size, it allocates memory and retries.
 *
 * @param pEvent Pointer to the EVENT_RECORD structure containing the event data.
 * @param pInfo Pointer to a pointer that receives the TRACE_EVENT_INFO structure containing the event metadata.
 * @return TRUE if successful, FALSE otherwise.
 */
BOOL get_event_information(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO* pInfo);

/**
 * @brief Extract a propertiy from an event record.
 *
 * @param pEvent Pointer to the EVENT_RECORD structure.
 * @param pInfo Pointer to the TRACE_EVENT_INFO structure.
 * @param PointerSize Size of a pointer in bytes.
 * @param i Index of the property to extract.
 * @param pUserData Pointer to user data buffer.
 * @param pEndOfUserData Pointer to the end of the user data buffer.
 * @param pExtract Pointer to the PROPERTY_KEY_VALUE structure where the extracted property will be stored.
 * @return PBYTE Pointer to the next byte in the user data buffer, or NULL if an error occurred.
 */
PBYTE extract_property(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData, PROPERTY_KEY_VALUE* pExtract);

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
