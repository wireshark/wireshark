/* etw_message.h
 *
 * Copyright 2020, Odysseus Yang
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#define WS_LOG_DOMAIN "etwdump"

#include "etw_message.h"
#include <wsutil/wslog.h>
ULONGLONG g_num_events;

VOID format_message(WCHAR* lpszMessage, PROPERTY_KEY_VALUE* propArray, DWORD dwPropertyCount, WCHAR* lpszOutBuffer, DWORD dwOutBufferCount)
{
    DWORD startLoc = 0;
    int percent_loc = 0;

    for (int i = 0; lpszMessage[i] != L'\0';)
    {
        if (lpszMessage[i] != L'%')
        {
            i++;
            continue;
        }
        if (lpszMessage[i + 1] == '%')
        {
            i += 2;
            continue;
        }

        percent_loc = i;
        i++;

        if (iswdigit(lpszMessage[i]))
        {
            DWORD dwDigitalCount = 0;
            WCHAR smallBuffer[MAX_SMALL_BUFFER] = { 0 };
            while (iswdigit(lpszMessage[i]))
            {
                if (dwDigitalCount < (MAX_SMALL_BUFFER - 1))
                {
                    smallBuffer[dwDigitalCount] = lpszMessage[i];
                }
                dwDigitalCount++;
                i++;
            }

            /* We are not parsing this */
            if (dwDigitalCount >= (MAX_SMALL_BUFFER - 1))
            {
                continue;
            }
            DWORD num = _wtoi(smallBuffer);
            /* We are not parsing this */
            if (num == 0 || num > dwPropertyCount || propArray[num - 1].value[0] == L'\0')
            {
                continue;
            }

            if (lpszMessage[i] == L'!' && lpszMessage[i + 1] == L'S' && lpszMessage[i + 2] == L'!')
            {
                i += 3;
            }

            /* We have everything */
            lpszMessage[percent_loc] = L'\0';
            StringCbCat(lpszOutBuffer, dwOutBufferCount, lpszMessage + startLoc);
            StringCbCat(lpszOutBuffer, dwOutBufferCount, propArray[num - 1].value);
            startLoc = i;
            continue; // for
        }
    }
    StringCbCat(lpszOutBuffer, dwOutBufferCount, lpszMessage + startLoc);
}

/*
* Get the length of the property data. For MOF-based events, the size is inferred from the data type
* of the property. For manifest-based events, the property can specify the size of the property value
* using the length attribute. The length attribue can specify the size directly or specify the name
* of another property in the event data that contains the size. If the property does not include the
* length attribute, the size is inferred from the data type. The length will be zero for variable
* length, null-terminated strings and structures.
*/
DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength)
{
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor = { 0 };
    DWORD PropertySize = 0;

    /*
    * If the property is a binary blob and is defined in a manifest, the property can
    * specify the blob's size or it can point to another property that defines the
    * blob's size. The PropertyParamLength flag tells you where the blob's size is defined.
    */
    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
    {
        DWORD Length = 0;  // Expects the length to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].lengthPropertyIndex;
        DataDescriptor.PropertyName = ((ULONGLONG)(pInfo)+(ULONGLONG)pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Length);
        *PropertyLength = (USHORT)Length;
    }
    else
    {
        if (pInfo->EventPropertyInfoArray[i].length > 0)
        {
            *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
        }
        else
        {
            /*
            * If the property is a binary blob and is defined in a MOF class, the extension
            * qualifier is used to determine the size of the blob. However, if the extension
            * is IPAddrV6, you must set the PropertyLength variable yourself because the
            * EVENT_PROPERTY_INFO.length field will be zero.
            */
            if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
                TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
            {
                *PropertyLength = (USHORT)sizeof(IN6_ADDR);
            }
            else if (TDH_INTYPE_UNICODESTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
                TDH_INTYPE_ANSISTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
                (pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
            {
                *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
            }
            else
            {
                ws_debug("Event %d Unexpected length of 0 for intype %d and outtype %d", g_num_events,
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType);

                status = ERROR_EVT_INVALID_EVENT_DATA;
                goto cleanup;
            }
        }
    }
cleanup:
    return status;
}

DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor = { 0 };
    DWORD PropertySize = 0;

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
    {
        /* Expects the count to be defined by a UINT16 or UINT32 */
        DWORD Count = 0;
        DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
        DataDescriptor.PropertyName = ((ULONGLONG)(pInfo)+(ULONGLONG)(pInfo->EventPropertyInfoArray[j].NameOffset));
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
        *ArraySize = (USHORT)Count;
    }
    else
    {
        *ArraySize = pInfo->EventPropertyInfoArray[i].count;
    }
    return status;
}

DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, PEVENT_MAP_INFO* pMapInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD MapSize = 0;

    /* Retrieve the required buffer size for the map info. */
    status = TdhGetEventMapInformation(pEvent, pMapName, *pMapInfo, &MapSize);
    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        *pMapInfo = (PEVENT_MAP_INFO)g_malloc(MapSize);
        if (*pMapInfo == NULL)
        {
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }
        /* Retrieve the map info. */
        status = TdhGetEventMapInformation(pEvent, pMapName, *pMapInfo, &MapSize);
    }

    if (ERROR_NOT_FOUND == status)
    {
        /* This case is okay. */
        status = ERROR_SUCCESS; 
    }

cleanup:

    return status;
}


PBYTE extract_properties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData, PROPERTY_KEY_VALUE* pExtract)
{
    TDHSTATUS status = ERROR_SUCCESS;
    USHORT PropertyLength = 0;
    USHORT UserDataConsumed = 0;
    /* Last member of a structure */
    DWORD LastMember = 0;
    USHORT ArraySize = 0;
    PEVENT_MAP_INFO pMapInfo = NULL;
    WCHAR formatted_data[MAX_LOG_LINE_LENGTH];
    DWORD formatted_data_size = sizeof(formatted_data);
    LPWSTR oversize_formatted_data = NULL;

    do
    {
        StringCbCopy(pExtract->key, sizeof(pExtract->key), (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
        /* Get the length of the property. */
        status = GetPropertyLength(pEvent, pInfo, i, &PropertyLength);
        if (ERROR_SUCCESS != status)
        {
            StringCbPrintf(pExtract->value, sizeof(pExtract->value), L"%s: GetPropertyLength failed 0x%x", pExtract->key, status);
            break;
        }

        /* Get the size of the array if the property is an array. */
        status = GetArraySize(pEvent, pInfo, i, &ArraySize);
        if (ERROR_SUCCESS != status)
        {
            StringCbPrintf(pExtract->value, sizeof(pExtract->value), L"%s: GetArraySize failed 0x%x", pExtract->key, status);
            break;
        }

        /* Add [] for an array property */
        if (ArraySize > 1)
        {
            StringCbCat(pExtract->value, sizeof(pExtract->value), L"[");
        }

        for (USHORT k = 0; k < ArraySize; k++)
        {
            /* Add array item separator "," */
            if (k > 0)
            {
                StringCbCat(pExtract->value, sizeof(pExtract->value), L",");
            }
            /* If the property is a structure, print the members of the structure. */
            if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
            {
                /* Add {} for an array property */
                StringCbCat(pExtract->value, sizeof(pExtract->value), L"{");
                /* Add struct member separator ";" */
                if (k > 0)
                {
                    StringCbCat(pExtract->value, sizeof(pExtract->value), L";");
                }
                LastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex +
                    pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

                for (USHORT j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < LastMember; j++)
                {
                    pUserData = extract_properties(pEvent, pInfo, PointerSize, j, pUserData, pEndOfUserData, pExtract);
                    if (NULL == pUserData)
                    {
                        StringCbPrintf(pExtract->value, sizeof(pExtract->value), L"%s: extract_properties of member %d failed 0x%x", pExtract->key, j, status);
                        break;
                    }
                }
                StringCbCat(pExtract->value, sizeof(pExtract->value), L"}");
            }
            else
            {
                /* Get the name/value mapping only at the first time if the property specifies a value map. */
                if (pMapInfo == NULL)
                {
                    status = GetMapInfo(pEvent,
                        (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
                        &pMapInfo);

                    if (ERROR_SUCCESS != status)
                    {
                        StringCbPrintf(pExtract->value, sizeof(pExtract->value), L"%s: GetMapInfo failed 0x%x", pExtract->key, status);
                        break;
                    }
                }

                /* Get the size of the buffer required for the formatted data. */

                status = TdhFormatProperty(
                    pInfo,
                    pMapInfo,
                    PointerSize,
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
                    PropertyLength,
                    (USHORT)(pEndOfUserData - pUserData),
                    pUserData,
                    &formatted_data_size,
                    formatted_data,
                    &UserDataConsumed);

                if (ERROR_INSUFFICIENT_BUFFER == status)
                {
                    if (oversize_formatted_data)
                    {
                        g_free(oversize_formatted_data);
                        oversize_formatted_data = NULL;
                    }

                    oversize_formatted_data = (LPWSTR)g_malloc(formatted_data_size);
                    if (oversize_formatted_data == NULL)
                    {
                        status = ERROR_OUTOFMEMORY;
                        StringCbPrintf(pExtract->value, sizeof(pExtract->value), L"%s: Allocate FormattedData memory (size %d) for array item %d failed 0x%x", pExtract->key, formatted_data_size, k, status);
                        break;
                    }

                    /* Retrieve the formatted data. */
                    status = TdhFormatProperty(
                        pInfo,
                        pMapInfo,
                        PointerSize,
                        pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                        pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
                        PropertyLength,
                        (USHORT)(pEndOfUserData - pUserData),
                        pUserData,
                        &formatted_data_size,
                        oversize_formatted_data,
                        &UserDataConsumed);
                }

                if (ERROR_SUCCESS == status)
                {
                    if (formatted_data_size > sizeof(formatted_data) && oversize_formatted_data != NULL)
                    {
                        /* Any oversize FormattedData will be truncated */
                        StringCbCat(pExtract->value, sizeof(pExtract->value), oversize_formatted_data);
                    }
                    else
                    {
                        StringCbCat(pExtract->value, sizeof(pExtract->value), formatted_data);
                    }
                    pUserData += UserDataConsumed;
                }
                else
                {
                    StringCbPrintf(pExtract->value, sizeof(pExtract->value), L"%s: TdhFormatProperty for array item %d failed 0x%x", pExtract->key, k, status);
                    break;
                }
            }
        }
        /* Add [] for an array property */
        if (ArraySize > 1)
        {
            StringCbCat(pExtract->value, sizeof(pExtract->value), L"]");
        }
    } while (false);

    if (oversize_formatted_data)
    {
        g_free(oversize_formatted_data);
        oversize_formatted_data = NULL;
    }
    if (pMapInfo)
    {
        g_free(pMapInfo);
        pMapInfo = NULL;
    }

    return (ERROR_SUCCESS == status) ? pUserData : NULL;
}


BOOL get_event_information(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO* pInfo)
{
    BOOL bReturn = false;
    DWORD status;
    DWORD BufferSize = 0;

    /* Retrieve the required buffer size for the event metadata. */
    status = TdhGetEventInformation(pEvent, 0, NULL, *pInfo, &BufferSize);
    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        *pInfo = (TRACE_EVENT_INFO*)g_malloc(BufferSize);
        if (*pInfo == NULL)
        {
            ws_debug("Event %d GetEventInformation Failed to allocate memory for event info (size=%lu).", g_num_events, BufferSize);
            goto Exit;
        }
        /* Retrieve the event metadata. */
        status = TdhGetEventInformation(pEvent, 0, NULL, *pInfo, &BufferSize);
    }

    if (ERROR_SUCCESS != status)
    {
        goto Exit;
    }
    bReturn = true;
Exit:

    return bReturn;
}

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
