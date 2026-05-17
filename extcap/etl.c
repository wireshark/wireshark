/* etl.c
 *
 * Copyright 2020, Odysseus Yang
 *           2026, Gabriel Potter
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Reads an ETL file and writes out a pcapng file with LINKTYPE_ETW.
 *
 * https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
 */

#include "config.h"
#define WS_LOG_DOMAIN "etwdump"

#include "etl.h"
#include "wsutil/ws_getopt.h"
#include "wsutil/strtoi.h"
#include "wsutil/epochs.h"
#include "wsutil/nstime.h"
#include "etw_message.h"
#include "etw_ndiscap.h"

#include <winternl.h>
#include <ip2string.h>
#include <rpc.h>
#include <winevt.h>

#pragma comment(lib, "ntdll.lib")

#define MAX_PACKET_SIZE 0xFFFF
#define ADD_OFFSET_TO_POINTER(buffer, offset) (((PBYTE)buffer) + offset)
#define ROUND_UP_COUNT(Count,Pow2) \
        ( ((Count)+(Pow2)-1) & (~(((int)(Pow2))-1)) )

extern int g_include_undecidable_event;
extern BOOL g_event_enable_sid;
extern BOOL g_event_enable_tsid;
extern BOOL g_event_enable_event_key;
extern BOOL g_event_enable_property_pstartkey;
extern BOOL g_event_enable_stack_trace;
extern BOOL g_event_enable_silos;
extern BOOL g_event_property_source_container_tracking;
extern BOOL g_debug_parsers;

//Microsoft-Windows-Wmbclass-Opn
const GUID mbb_provider = { 0xA42FE227, 0xA7BF, 0x4483, {0xA5, 0x02, 0x6B, 0xCD, 0xA4, 0x28, 0xCD, 0x96} };
// Microsoft-Windows-NDIS-PacketCapture
const GUID ndis_capture_provider = { 0x2ed6006e, 0x4729, 0x4609, {0xb4, 0x23, 0x3e, 0xe7, 0xbc, 0xd6, 0x78, 0xef} };
// Microsoft-Windows-Ras-NdisWanPacketCapture
const GUID ndiswan_capture_provider = { 0xD84521F7, 0x2235, 0x4237, {0xa7, 0xc0, 0x14, 0xe3, 0xa9, 0x67, 0x62, 0x86} };
// Microsoft-Windows-SMBClient
const GUID smbclient_provider = { 0x988C59C5, 0x0A1C, 0x45B6, {0xA5, 0x55, 0x0C, 0x62, 0x27, 0x6E, 0x32, 0x7D} };
// Microsoft-Windows-SMBServer
const GUID smbserver_provider = { 0xD48CE617, 0x33A2, 0x4BC3, {0xA5, 0xC7, 0x11, 0xAA, 0x4F, 0x29, 0x61, 0x9E} };
// Microsoft-Windows-WinINet-Capture
const GUID wininet_capture_provider = { 0xa70ff94f, 0x570b, 0x4979, { 0xba, 0x5c, 0xe5, 0x9c, 0x9f, 0xea, 0xb6, 0x1b } };
// Microsoft-Windows-WebIO
const GUID webio_provider = { 0x50B3E73C, 0x9370, 0x461D, { 0xBB, 0x9F, 0x26, 0xF3, 0x2D, 0x68, 0x88, 0x7D} };
// Microsoft-Windows-LDAP-Client
const GUID ldap_client_provider = { 0x099614A5, 0x5DD7, 0x4788, { 0x8B, 0xC9, 0xE2, 0x9F, 0x43, 0xDB, 0x28, 0xFC } };


EXTERN_C const GUID DECLSPEC_SELECTANY EventTraceGuid = { 0x68fdd900, 0x4a3e, 0x11d1, {0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3} };
EXTERN_C const GUID DECLSPEC_SELECTANY ImageIdGuid = { 0xb3e675d7, 0x2554, 0x4f18, { 0x83, 0xb, 0x27, 0x62, 0x73, 0x25, 0x60, 0xde } };
EXTERN_C const GUID DECLSPEC_SELECTANY SystemConfigExGuid = { 0x9b79ee91, 0xb5fd, 0x41c0, { 0xa2, 0x43, 0x42, 0x48, 0xe2, 0x66, 0xe9, 0xd0 } };
EXTERN_C const GUID DECLSPEC_SELECTANY EventMetadataGuid = { 0xbbccf6c1, 0x6cd1, 0x48c4, {0x80, 0xff, 0x83, 0x94, 0x82, 0xe3, 0x76, 0x71 } };
EXTERN_C const GUID DECLSPEC_SELECTANY ZeroGuid = { 0 };

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        EVENT_HEADER                           |
 * .                             ...                               .
 * .                                                               .
 * |                                                               |
 * +---------------------------------------------------------------+
 * |                     ETW_BUFFER_CONTEXT                        |
 * +-------------------------------+-------------------------------+
 * |      ExtendedDataCount        |           TlvCount            |
 * +-------------------------------+-------------------------------+
 * |                       PropertiesCount                         |
 * +---------------------------------------------------------------+
 * |                   Extended Data Headers                       |
 * .      EVENT_HEADER_EXTENDED_DATA_ITEM[ExtendedDataCount]       .
 * .                                                               .
 * |                                                               |
 * +---------------------------------------------------------------+
 * |                         TLV Headers                           |
 * .                   WTAP_ETL_TLV[TlvCount]                      .
 * .                                                               .
 * |                                                               |
 * +---------------------------------------------------------------+
 * |                       Property Headers                        |
 * .                   ETW_PROPERTY[PropertiesCount]               .
 * .                                                               .
 * |                                                               |
 * +---------------------------------------------------------------+
 * |                             DATA                              |
 * .                              ..                               .
 * .                              ..                               .
 * |                                                               |
 * +---------------------------------------------------------------+
 *                     ETL->Wireshark encapsulation
 */

enum ETL_TLV_TYPE {
    TLV_USER_DATA = 0,
    TLV_MESSAGE,
    TLV_PROVIDER_NAME,
    TLV_SRC_ADDR,
    TLV_DST_ADDR,
    TLV_SESSION_ID,
};

#pragma pack(push, 1)
typedef struct _WTAP_ETL_TLV {
    enum ETL_TLV_TYPE Type;
    DWORD             Offset;
    DWORD             Length;
} WTAP_ETL_TLV;

typedef struct _WTAP_ETL_RECORD {
    EVENT_HEADER                    EventHeader;            // Event header
    ETW_BUFFER_CONTEXT              BufferContext;          // Buffer context
    USHORT                          ExtendedDataCount;
    USHORT                          TlvCount;
    DWORD                           PropertiesCount;
} WTAP_ETL_RECORD;

typedef struct _WTAP_ETW_PROPERTY
{
    DWORD Offset;
    USHORT KeyLength;
    USHORT ValueLength;
} ETW_PROPERTY;
#pragma pack(pop)

typedef struct _WTAP_ETL_RECORD_CONTEXT_ITEM {
    enum ETL_TLV_TYPE Type;
    DWORD Length;
    void* Data;
} WTAP_ETL_RECORD_CONTEXT_ITEM;


typedef struct _WTAP_ETL_RECORD_CONTEXT {
    USHORT tlv_count;
    GArray* tlvs;

    DWORD properties_count;
    PROPERTY_KEY_VALUE* properties;
} WTAP_ETL_RECORD_CONTEXT, * PWTAP_ETL_RECORD_CONTEXT;

enum {
    OPT_PROVIDER,
    OPT_KEYWORD,
    OPT_LEVEL,
};

static const struct ws_option longopts[] = {
    { "p", ws_required_argument, NULL, OPT_PROVIDER},
    { "k", ws_required_argument, NULL, OPT_KEYWORD},
    { "l", ws_required_argument, NULL, OPT_LEVEL},
    { 0, 0, 0, 0 }
};

// We reimplement the scenarios from the defunct MessageAnalyzer :)
const struct _SCENARIO g_scenarios[] = {
    { SCENARIO_KEY L"PacketCapture", { { 0xA42FE227, 0xA7BF, 0x4483, { 0xA5, 0x02, 0x6B, 0xCD, 0xA4, 0x28, 0xCD, 0x96 } }, 0xffffffffffffffff, 5 } },
    { SCENARIO_KEY L"NdisWanPacketCapture", { { 0xD84521F7, 0x2235, 0x4237, {0xA7, 0xC0, 0x14, 0xE3, 0xA9, 0x67, 0x62, 0x86 } }, 0xffffffffffffffff, 5 } },
    { SCENARIO_KEY L"Wbmclass-Opn", { { 0x2ed6006e, 0x4729, 0x4609, { 0xb4, 0x23, 0x3e, 0xe7, 0xbc, 0xd6, 0x78, 0xef } }, 0xffffffffffffffff, 5 } },
    { SCENARIO_KEY L"WinINet-Capture", { { 0xa70ff94f, 0x570b, 0x4979, { 0xba, 0x5c, 0xe5, 0x9c, 0x9f, 0xea, 0xb6, 0x1b } }, 0xffffffffffffffff, 5 } },
    { SCENARIO_KEY L"WebIO-Capture", { { 0x50B3E73C, 0x9370, 0x461D, { 0xBB, 0x9F, 0x26, 0xF3, 0x2D, 0x68, 0x88, 0x7D} }, 0x0000020400000000, 5 } },
    { SCENARIO_KEY L"SASL-LDAP-Capture", { { 0x099614a5, 0x5dd7, 0x4788, { 0x8b, 0xc9, 0xe2, 0x9f, 0x43, 0xdb, 0x28, 0xfc } }, 0x0000000002010800, 5 } },
    { SCENARIO_KEY L"SMBClient-Capture", { { 0x988c59c5, 0x0a1c, 0x45b6, { 0xa5, 0x55, 0x0c, 0x62, 0x27, 0x6e, 0x32, 0x7d } }, 0x0800C40300000000, 5 } },
    { SCENARIO_KEY L"SMBServer-Capture", { { 0xd48ce617, 0x33a2, 0x4bc3, { 0xa5, 0xc7, 0x11, 0xaa, 0x4f, 0x29, 0x61, 0x9e } }, 0x0800040300000000, 5 } },
    { 0, 0 }
};

char g_err_info[FILENAME_MAX];
int g_err = ERROR_SUCCESS;
static wtap_dumper* g_pdh;
extern ULONGLONG g_num_events;
static PROVIDER_FILTER g_provider_filters[32];
static BOOL g_is_live_session;

static GHashTable* g_etw_frags;
typedef struct _etw_frag {
    CHAR PeerAddressFmt[64];  // 46 max for IPv6 address, 1 for ':' and 5 for the port
    PWTAP_ETL_RECORD_CONTEXT ctx;
    GByteArray* buf;
} etw_frag;
static void etw_frag_free(etw_frag* frag);
static etw_frag* etw_frag_new();
static etw_frag* etw_frag_get(PEVENT_RECORD ev, bool begin);
static void etw_frag_remove(PEVENT_RECORD ev);

static void WINAPI event_callback(PEVENT_RECORD ev);
static void etw_dump_write_opn_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
static void etw_dump_write_smb_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
static void etw_dump_write_general_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
static void etw_dump_write_wininet_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
static void etw_dump_write_webio_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
static void etw_dump_write_ldap_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
static wtap_dumper* etw_dump_open(const char* pcapng_filename, int* err, char** err_info);

static DWORD GetPropertyValue(WCHAR* ProviderId, EVT_PUBLISHER_METADATA_PROPERTY_ID PropertyId, PEVT_VARIANT* Value)
{
    BOOL bRet;
    DWORD err = ERROR_SUCCESS;
    PEVT_VARIANT value = NULL;
    DWORD bufSize = 0;
    DWORD bufUsedOrReqd = 0;

    EVT_HANDLE pubHandle = EvtOpenPublisherMetadata(NULL, ProviderId, NULL, GetThreadLocale(), 0);
    if (pubHandle == NULL)
    {
        return GetLastError();
    }

    /*
     * Get required size for property
     */
    bRet = EvtGetPublisherMetadataProperty(
        pubHandle,
        PropertyId,
        0,
        bufSize,
        value,
        &bufUsedOrReqd);

    if (!bRet && ((err = GetLastError()) != ERROR_INSUFFICIENT_BUFFER))
    {
        return err;
    }
    else if (bRet) /* Didn't expect this to succeed */
    {
        return ERROR_INVALID_STATE;
    }

    value = (PEVT_VARIANT)g_malloc(bufUsedOrReqd);
    if (!value)
    {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    bufSize = bufUsedOrReqd;

    /*
     * Get the property value
     */
    bRet = EvtGetPublisherMetadataProperty(
        pubHandle,
        PropertyId,
        0,
        bufSize,
        value,
        &bufUsedOrReqd);
    if (!bRet)
    {
        g_free(value);
        return GetLastError();
    }

    *Value = value;
    return ERROR_SUCCESS;
}

wtap_open_return_val etw_dump(const char* etl_filename, const char* pcapng_filename, const char* params, int* err, char** err_info)
{
    EVENT_TRACE_LOGFILE log_file = { 0 };
    WCHAR w_etl_filename[FILENAME_MAX] = { 0 };
    wtap_open_return_val returnVal = WTAP_OPEN_MINE;

    SUPER_EVENT_TRACE_PROPERTIES super_trace_properties = { 0 };
    super_trace_properties.prop.Wnode.BufferSize = sizeof(SUPER_EVENT_TRACE_PROPERTIES);
    super_trace_properties.prop.Wnode.ClientContext = 2; // "System" Clock Type
    super_trace_properties.prop.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    super_trace_properties.prop.BufferSize = 200;  // 200KB (like traceview)
    super_trace_properties.prop.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    super_trace_properties.prop.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    TRACEHANDLE traceControllerHandle = (TRACEHANDLE)INVALID_HANDLE_VALUE;
    TRACEHANDLE trace_handle = INVALID_PROCESSTRACE_HANDLE;

    ENABLE_TRACE_PARAMETERS trace_params;
    trace_params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    trace_params.EnableProperty = 0;
    trace_params.ControlFlags = 0;
    trace_params.EnableFilterDesc = NULL;
    trace_params.FilterDescCount = 0;
    if (g_event_enable_sid)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_SID;
    }
    if (g_event_enable_property_pstartkey)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_PROCESS_START_KEY;
    }
    if (g_event_enable_event_key)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_EVENT_KEY;
    }
    if (g_event_enable_tsid)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_TS_ID;
    }
    if (g_event_enable_stack_trace)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_STACK_TRACE;
    }
    if (g_event_enable_silos)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_ENABLE_SILOS;
    }
    if (g_event_property_source_container_tracking)
    {
        trace_params.EnableProperty |= EVENT_ENABLE_PROPERTY_SOURCE_CONTAINER_TRACKING;
    }

    SecureZeroMemory(g_provider_filters, sizeof(g_provider_filters));
    SecureZeroMemory(g_err_info, FILENAME_MAX);
    g_err = ERROR_SUCCESS;
    g_num_events = 0;
    g_is_live_session = false;
    g_etw_frags = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    if (params)
    {
        int opt_result = 0;
        int option_idx = 0;
        int provider_idx = 0;
        char** params_array = NULL;
        int params_array_num = 0;
        char* endptr = NULL;
        char* endptr_exp = NULL;
        WCHAR provider_id[FILENAME_MAX] = { 0 };
        ULONG convert_level = 0;
        ULONG64 keyword = 0;

        params_array = g_strsplit(params, " ", -1);
        while (params_array[params_array_num])
        {
            params_array_num++;
        }

        ws_optind = 0;
        while ((opt_result = ws_getopt_long(params_array_num, params_array, ":", longopts, &option_idx)) != -1) {
            switch (opt_result) {
            case OPT_PROVIDER:
                mbstowcs(provider_id, ws_optarg, FILENAME_MAX);

                if (wcsncmp(provider_id, SCENARIO_KEY, sizeof(SCENARIO_KEY) / sizeof(WCHAR) - 1) == 0)
                {
                    // Provider is a "scenario" which includes keywords + level
                    SCENARIO* scenario = (SCENARIO*) & g_scenarios;
                    bool found = false;
                    while (scenario->name)
                    {
                        if (wcscmp(scenario->name, provider_id) == 0)
                        {
                            found = true;
                            g_provider_filters[provider_idx] = scenario->ProviderFilter;
                            break;
                        }
                        scenario += 1;
                    }

                    if (!found)
                    {
                        *err_info = ws_strdup_printf("Unknown scenario: %s", provider_id);
                        return WTAP_OPEN_ERROR;
                    }
                }
                else if (UuidFromString(provider_id, &g_provider_filters[provider_idx].ProviderId) == RPC_S_INVALID_STRING_UUID)                {
                    PEVT_VARIANT value = NULL;

                    *err = GetPropertyValue(
                        provider_id,
                        EvtPublisherMetadataPublisherGuid,
                        &value);

                    /*
                     * Copy returned GUID locally
                     */
                    if (*err == ERROR_SUCCESS)
                    {
                        if (value->Type == EvtVarTypeGuid && value->GuidVal)
                        {
                            g_provider_filters[provider_idx].ProviderId = *(value->GuidVal);
                            /*
                             * Set default logging values (same as traceview.exe)
                             */
                            g_provider_filters[provider_idx].Keyword = 0xffffffffffffffffL;  // ANY
                            g_provider_filters[provider_idx].Level = 5;  // ALL
                        }
                        else
                        {
                            *err = ERROR_INVALID_DATA;
                        }
                    }
                    else
                    {
                        *err_info = ws_strdup_printf("Cannot convert provider %s to a GUID, err is 0x%x", ws_optarg, *err);
                        return WTAP_OPEN_ERROR;
                    }

                    g_free(value);
                }

                if (IsEqualGUID(&g_provider_filters[0].ProviderId, &ZeroGuid))
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("Provider %s is zero, err is 0x%x", ws_optarg, *err);
                    return WTAP_OPEN_ERROR;
                }
                provider_idx++;
                break;
            case OPT_KEYWORD:
                endptr = ws_optarg + strlen(ws_optarg);
                endptr_exp = endptr;
                if (provider_idx == 0)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("-k parameter must follow -p, err is 0x%x", *err);
                    return WTAP_OPEN_ERROR;
                }

                keyword = _strtoui64(ws_optarg, &endptr, 0);
                if (endptr != endptr_exp)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("Keyword %s cannot be converted, err is 0x%x", ws_optarg, *err);
                    return WTAP_OPEN_ERROR;
                }

                g_provider_filters[provider_idx - 1].Keyword = keyword;
                break;
            case OPT_LEVEL:
                endptr = ws_optarg + strlen(ws_optarg);
                endptr_exp = endptr;
                if (provider_idx == 0)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("-l parameter must follow -p, err is 0x%x", *err);
                    return WTAP_OPEN_ERROR;
                }

                convert_level = strtoul(ws_optarg, &endptr, 0);
                if (convert_level > UCHAR_MAX)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("Level %s is bigger than 0xff, err is 0x%x", ws_optarg, *err);
                    return WTAP_OPEN_ERROR;
                }
                if (endptr != endptr_exp)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("Level %s cannot be converted, err is 0x%x", ws_optarg, *err);
                    return WTAP_OPEN_ERROR;
                }

                g_provider_filters[provider_idx - 1].Level = (UCHAR)convert_level;
                break;
            }
        }
        g_strfreev(params_array);
    }

    /* do/while(false) is used to jump out of loop so no complex nested if/else is needed */
    do
    {
        /* Read ETW from an etl file */
        if (etl_filename)
        {
            mbstowcs(w_etl_filename, etl_filename, FILENAME_MAX);

            log_file.LogFileName = w_etl_filename;
            log_file.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
            log_file.EventRecordCallback = event_callback;
            log_file.Context = NULL;
        }
        else
        {
            /*
             * Try the best to stop the leftover session since extcap has no way to cleanup when stop capturing. See issue
             * https://gitlab.com/wireshark/wireshark/-/issues/17131
             */
            ControlTrace((TRACEHANDLE)NULL, LOGGER_NAME, &super_trace_properties.prop, EVENT_TRACE_CONTROL_STOP);

            g_is_live_session = true;

            log_file.LoggerName = LOGGER_NAME;
            log_file.LogFileName = NULL;
            log_file.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            log_file.EventRecordCallback = event_callback;
            log_file.BufferCallback = NULL;
            log_file.Context = NULL;

            *err = StartTrace(
                &traceControllerHandle,
                log_file.LoggerName,
                &super_trace_properties.prop);
            if (*err != ERROR_SUCCESS)
            {
                *err_info = ws_strdup_printf("StartTrace failed with 0x%x", *err);
                returnVal = WTAP_OPEN_ERROR;
                break;
            }

            for (int i = 0; i < ARRAYSIZE(g_provider_filters); i++)
            {
                if (IsEqualGUID(&g_provider_filters[i].ProviderId, &ZeroGuid))
                {
                    break;
                }
                *err = EnableTraceEx2(
                    traceControllerHandle,
                    &g_provider_filters[i].ProviderId,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    g_provider_filters[i].Level,
                    g_provider_filters[i].Keyword,
                    0,
                    0,
                    &trace_params);
                if (*err != ERROR_SUCCESS)
                {
                    *err_info = ws_strdup_printf("EnableTraceEx failed with 0x%x", *err);
                    returnVal = WTAP_OPEN_ERROR;
                    break;
                }
            }
        }

        trace_handle = OpenTrace(&log_file);
        if (trace_handle == INVALID_PROCESSTRACE_HANDLE) {
            *err = GetLastError();
            *err_info = ws_strdup_printf("OpenTrace failed with 0x%x", *err);
            returnVal = WTAP_OPEN_NOT_MINE;
            break;
        }

        g_pdh = etw_dump_open(pcapng_filename, err, err_info);
        if (g_pdh == NULL)
        {
            returnVal = WTAP_OPEN_ERROR;
            break;
        }

        *err = ProcessTrace(&trace_handle, 1, 0, 0);
        if (*err != ERROR_SUCCESS) {
            returnVal = WTAP_OPEN_ERROR;
            *err_info = ws_strdup_printf("ProcessTrace failed with 0x%x", *err);
            break;
        }

        if (g_err != ERROR_SUCCESS)
        {
            *err = g_err;
            *err_info = g_strdup(g_err_info);
            returnVal = WTAP_OPEN_ERROR;
            break;
        }

        if (!g_num_events) {
            *err = ERROR_NO_DATA;
            *err_info = ws_strdup_printf("Didn't find any etw event");
            returnVal = WTAP_OPEN_NOT_MINE;
            break;
        }
    } while (false);

    if (trace_handle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(trace_handle);
    }
    if (g_pdh != NULL)
    {
        if (*err == ERROR_SUCCESS)
        {
            if (!wtap_dump_close(g_pdh, NULL, err, err_info))
            {
                returnVal = WTAP_OPEN_ERROR;
            }
        }
        else
        {
            int err_ignore;
            char* err_info_ignore = NULL;
            if (!wtap_dump_close(g_pdh, NULL, &err_ignore, &err_info_ignore))
            {
                returnVal = WTAP_OPEN_ERROR;
                g_free(err_info_ignore);
            }
        }
    }
    if (g_etw_frags)
    {
        g_hash_table_foreach(g_etw_frags, etw_frag_free, NULL);
        g_hash_table_destroy(g_etw_frags);
    }
    return returnVal;
}

static BOOL is_event_filtered_out(PEVENT_RECORD ev)
{
    if (g_is_live_session)
    {
        return false;
    }

    if (IsEqualGUID(&g_provider_filters[0].ProviderId, &ZeroGuid))
    {
        return false;
    }

    for (int i = 0; i < ARRAYSIZE(g_provider_filters); i++)
    {
        if (IsEqualGUID(&g_provider_filters[i].ProviderId, &ev->EventHeader.ProviderId))
        {
            return false;
        }
        if (IsEqualGUID(&g_provider_filters[i].ProviderId, &ZeroGuid))
        {
            break;
        }
    }

    return true;
}

static void WINAPI event_callback(PEVENT_RECORD ev)
{
    ULARGE_INTEGER timestamp;
    g_num_events++;

    if (is_event_filtered_out(ev))
    {
        return;
    }

    /*
    * 100ns since 1/1/1601 -> usec since 1/1/1970.
    * EPOCH_DELTA_1601_01_01_00_00_00_UTC is the offset in seconds, so
    * we multiply it by 10^6 to convert it to usec.
    *
    * XXX - should we write this out as a 100-nanosecond-resolution pcapng,
    * so we don't lose resolution?
    */
    timestamp.QuadPart = (ev->EventHeader.TimeStamp.QuadPart / 10) - (1000000*EPOCH_DELTA_1601_01_01_00_00_00_UTC);

    if (g_debug_parsers)
    {
        /* Debug: skip all parsers. */
        etw_dump_write_general_event(ev, timestamp);
    }
    else if (IsEqualGUID(&ev->EventHeader.ProviderId, &mbb_provider))
    {
        etw_dump_write_opn_event(ev, timestamp);
    }
    else if (IsEqualGUID(&ev->EventHeader.ProviderId, &ndis_capture_provider))
    {
        etw_dump_write_ndiscap_event(ev, timestamp);
    }
    else if ((IsEqualGUID(&ev->EventHeader.ProviderId, &smbclient_provider) ||
        IsEqualGUID(&ev->EventHeader.ProviderId, &smbserver_provider)) &&
        ev->EventHeader.EventDescriptor.Id == 40000 ||
        ev->EventHeader.EventDescriptor.Id == 2000)
    {
        etw_dump_write_smb_event(ev, timestamp);
    }
    else if (IsEqualGUID(&ev->EventHeader.ProviderId, &wininet_capture_provider) && (
        ev->EventHeader.EventDescriptor.Id == 2001 ||
        ev->EventHeader.EventDescriptor.Id == 2002 ||
        ev->EventHeader.EventDescriptor.Id == 2003 ||
        ev->EventHeader.EventDescriptor.Id == 2004))
    {
        etw_dump_write_wininet_event(ev, timestamp);
    }
    else if (IsEqualGUID(&ev->EventHeader.ProviderId, &webio_provider) && (
        ev->EventHeader.EventDescriptor.Id == 100 ||
        ev->EventHeader.EventDescriptor.Id == 101 ||
        ev->EventHeader.EventDescriptor.Id == 111 ||
        ev->EventHeader.EventDescriptor.Id == 129))
    {
        etw_dump_write_webio_event(ev, timestamp);
    }
    else if (IsEqualGUID(&ev->EventHeader.ProviderId, &ldap_client_provider) && (
        ev->EventHeader.EventDescriptor.Id == 12 ||
        ev->EventHeader.EventDescriptor.Id == 17))
    {
        etw_dump_write_ldap_event(ev, timestamp);
    }
    /* Write any event form other providers other than above */
    else
    {
        etw_dump_write_general_event(ev, timestamp);
    }
}

static wtap_dumper* etw_dump_open(const char* pcapng_filename, int* err, char** err_info)
{
    wtap_dump_params params = { 0 };
    GArray* shb_hdrs = NULL;
    wtap_block_t shb_hdr;
    wtapng_iface_descriptions_t* idb_info;
    GArray* idb_datas;
    wtap_block_t idb_data;
    wtapng_if_descr_mandatory_t* descr_mand;

    wtap_dumper* pdh = NULL;

    shb_hdrs = g_array_new(false, false, sizeof(wtap_block_t));
    shb_hdr = wtap_block_create(WTAP_BLOCK_SECTION);
    g_array_append_val(shb_hdrs, shb_hdr);

    /* In the future, may create multiple WTAP_BLOCK_IF_ID_AND_INFO separately for IP packet */
    idb_info = g_new(wtapng_iface_descriptions_t, 1);
    if (idb_info == NULL)
        return NULL;
    idb_datas = g_array_new(false, false, sizeof(wtap_block_t));
    idb_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
    descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb_data);
    descr_mand->tsprecision = WTAP_TSPREC_USEC;
    descr_mand->wtap_encap = WTAP_ENCAP_ETW;
    /* Timestamp for each pcapng packet is usec units, so time_units_per_second need be set to 10^6 */
    descr_mand->time_units_per_second = WS_USECS_PER_SEC;
    g_array_append_val(idb_datas, idb_data);
    idb_info->interface_data = idb_datas;

    params.encap = WTAP_ENCAP_ETW;
    params.snaplen = 0;
    params.tsprec = WTAP_TSPREC_USEC;
    params.shb_hdrs = shb_hdrs;
    params.idb_inf = idb_info;

    pdh = wtap_dump_open(pcapng_filename, wtap_pcapng_file_type_subtype(), WS_FILE_UNCOMPRESSED, &params, err, err_info);

    if (shb_hdrs)
    {
        wtap_block_array_free(shb_hdrs);
    }
    if (params.idb_inf)
    {
        if (params.idb_inf->interface_data)
        {
            wtap_block_array_free(params.idb_inf->interface_data);
        }
        g_free(params.idb_inf);
        params.idb_inf = NULL;
    }

    return pdh;
}

/// <summary>
/// Add a TLV
/// </summary>
/// <param name="ctx"></param>
/// <param name="message"></param>
static void ctx_add_tlv(PWTAP_ETL_RECORD_CONTEXT ctx, enum ETL_TLV_TYPE Type, void* Data, DWORD Length)
{
    WTAP_ETL_RECORD_CONTEXT_ITEM tlv_ctx;

    tlv_ctx.Type = Type;
    tlv_ctx.Data = Data;
    tlv_ctx.Length = Length;

    g_array_append_val(ctx->tlvs, tlv_ctx);
    ctx->tlv_count++;
}

/// <summary>
/// Function that adds UserData to the context
/// </summary>
static void ctx_add_tlv_user_data(PWTAP_ETL_RECORD_CONTEXT ctx,
    void* custom_user_data,
    DWORD custom_user_data_length)
{
    if (custom_user_data_length > MAX_PACKET_SIZE)
    {
        custom_user_data_length = MAX_PACKET_SIZE;
    }
    ctx_add_tlv(ctx, TLV_USER_DATA, custom_user_data, custom_user_data_length);
}

static void ctx_add_tlv_user_data_ev(PWTAP_ETL_RECORD_CONTEXT ctx, PEVENT_RECORD ev)
{
    ctx_add_tlv_user_data(ctx, ev->UserData, ev->UserDataLength);
}

/// <summary>
/// Add a string tlv
/// </summary>
static void ctx_add_tlv_wchar(PWTAP_ETL_RECORD_CONTEXT ctx, enum ETL_TLV_TYPE Type, wchar_t* data)
{
    ULONG data_length = (ULONG)((wcslen(data) + 1) * sizeof(WCHAR));
    ctx_add_tlv(ctx, Type, data, data_length);
}


/// <summary>
/// Initialize context
/// </summary>
static PWTAP_ETL_RECORD_CONTEXT ctx_init()
{
    PWTAP_ETL_RECORD_CONTEXT ctx = g_malloc(sizeof(WTAP_ETL_RECORD_CONTEXT));
    ctx->tlv_count = 0;
    ctx->tlvs = g_array_new(false, true, sizeof(WTAP_ETL_RECORD_CONTEXT_ITEM));
    ctx->properties_count = 0;
    ctx->properties = NULL;
    return ctx;
}

/// <summary>
/// Free context
/// </summary>
static void ctx_free(PWTAP_ETL_RECORD_CONTEXT ctx)
{
    g_array_free(ctx->tlvs, true);
    g_free(ctx);
}

/// <summary>
/// Build the record from the context
/// </summary>
/// <returns>The size of the total record</returns>
static ULONG wtap_etl_rec_build(
    WTAP_ETL_RECORD** out_etl_record,
    PEVENT_RECORD ev,
    PWTAP_ETL_RECORD_CONTEXT ctx)
{
    // See the top of this file for the file format

    // We use TLVs so that this format can be extended without breaking backwards compatibility
    WTAP_ETL_TLV* tlvs = NULL;
    if (ctx->tlv_count != 0)
    {
        tlvs = g_malloc(sizeof(WTAP_ETL_TLV) * ctx->tlv_count);
        SecureZeroMemory(tlvs, sizeof(tlvs));
    }

    // Used while building
    ULONG hdr_offset = sizeof(WTAP_ETL_RECORD);
    ULONG data_offset = (
        sizeof(WTAP_ETL_RECORD) +
        sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM) * ev->ExtendedDataCount +
        sizeof(WTAP_ETL_TLV) * ctx->tlv_count +
        sizeof(ETW_PROPERTY) * ctx->properties_count);

    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG extended_data_offset = 0;
    ULONG properties_offset = 0;
    ULONG tlvs_offset = 0;
    char** extended_data_ptrs = NULL;
    ULONG* properties_offsets = NULL;
    ETW_PROPERTY prop = { 0, 0 };

    // Extended Data
    if (ev->ExtendedDataCount != 0)
    {
        extended_data_offset = hdr_offset;
        extended_data_ptrs = g_malloc(sizeof(char*) * ev->ExtendedDataCount);
        USHORT extended_data_length = 0;
        for (USHORT i = 0; i < ev->ExtendedDataCount; i++)
        {
            // It doesn't make sense to send the pointer, so we swap it for
            // the offset to display to the client.
            extended_data_ptrs[i] = ((char*)ev->ExtendedData[i].DataPtr);
            ev->ExtendedData[i].DataPtr = data_offset + extended_data_length;
            extended_data_length += ev->ExtendedData[i].DataSize;
        }
        data_offset += ROUND_UP_COUNT(extended_data_length, sizeof(LONG));
        hdr_offset += sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM) * ev->ExtendedDataCount;
    }

    // TLVs
    tlvs_offset = hdr_offset;
    for (USHORT tlv_index = 0; tlv_index < ctx->tlv_count; tlv_index++)
    {
        tlvs[tlv_index].Type = g_array_index(ctx->tlvs, WTAP_ETL_RECORD_CONTEXT_ITEM, tlv_index).Type;
        tlvs[tlv_index].Offset = data_offset;
        tlvs[tlv_index].Length = g_array_index(ctx->tlvs, WTAP_ETL_RECORD_CONTEXT_ITEM, tlv_index).Length;
        data_offset += ROUND_UP_COUNT(tlvs[tlv_index].Length, sizeof(LONG));
    }
    hdr_offset += sizeof(WTAP_ETL_TLV) * ctx->tlv_count;

    // Properties
    if (ctx->properties_count != 0)
    {
        properties_offset = hdr_offset;
        properties_offsets = g_malloc(sizeof(ULONG) * ctx->properties_count);
        ULONG properties_length = 0;
        for (DWORD i = 0; i < ctx->properties_count; i++)
        {
            properties_offsets[i] = data_offset + properties_length;
            properties_length += ctx->properties[i].key_length + ctx->properties[i].value_length;
        }
        data_offset += ROUND_UP_COUNT(properties_length, sizeof(LONG));
        hdr_offset += sizeof(ETW_PROPERTY) * ctx->properties_count;
    }

    (void)hdr_offset;

    // Start building the actual payload
    etl_record = g_malloc(data_offset);
    SecureZeroMemory(etl_record, data_offset);
    etl_record->EventHeader = ev->EventHeader;
    etl_record->BufferContext = ev->BufferContext;
    etl_record->ExtendedDataCount = ev->ExtendedDataCount;
    etl_record->PropertiesCount = ctx->properties_count;
    etl_record->TlvCount = ctx->tlv_count;

    if (extended_data_ptrs != NULL)
    {
        for (USHORT i = 0; i < ev->ExtendedDataCount; i++)
        {
            // Copy eData header
            memcpy(
                ADD_OFFSET_TO_POINTER(etl_record, extended_data_offset + sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM) * i),
                (void*) &ev->ExtendedData[i],
                sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM));
            // Copy eData data
            memcpy(
                ADD_OFFSET_TO_POINTER(etl_record, ev->ExtendedData[i].DataPtr),
                extended_data_ptrs[i],
                ev->ExtendedData[i].DataSize);
        }

        g_free(extended_data_ptrs);
    }

    for (USHORT i = 0; i < etl_record->TlvCount; i++)
    {
        WTAP_ETL_TLV* tlv = &tlvs[i];

        // Copy TLV header
        memcpy(ADD_OFFSET_TO_POINTER(etl_record, tlvs_offset + sizeof(WTAP_ETL_TLV) * i),
               tlv,
               sizeof(WTAP_ETL_TLV));

        // Copy TLV data
        memcpy(ADD_OFFSET_TO_POINTER(etl_record, tlv->Offset),
            g_array_index(ctx->tlvs, WTAP_ETL_RECORD_CONTEXT_ITEM, i).Data,
            tlv->Length);
    }

    if (ctx->properties_count != 0)
    {
        for (USHORT i = 0; i < ctx->properties_count; i++)
        {
            prop.KeyLength = ctx->properties[i].key_length;
            prop.ValueLength = ctx->properties[i].value_length;
            prop.Offset = properties_offsets[i];
            // Copy property header
            memcpy(
                ADD_OFFSET_TO_POINTER(etl_record, properties_offset + sizeof(ETW_PROPERTY) * i),
                (void*)&prop,
                sizeof(ETW_PROPERTY));
            // Copy property key and value data
            memcpy(
                ADD_OFFSET_TO_POINTER(etl_record, properties_offsets[i]),
                ctx->properties[i].key,
                ctx->properties[i].key_length);
            memcpy(
                ADD_OFFSET_TO_POINTER(etl_record, properties_offsets[i] + ctx->properties[i].key_length),
                ctx->properties[i].value,
                ctx->properties[i].value_length);
        }

        g_free(properties_offsets);
    }

    if (ctx->tlv_count != 0)
    {
        g_free(tlvs);
    }

    *out_etl_record = etl_record;
    return data_offset;
}

void wtap_etl_add_interface(int pkt_encap, const char* interface_name, unsigned short interface_name_length, const char* interface_desc, unsigned short interface_desc_length)
{
    wtap_block_t idb_data;
    wtapng_if_descr_mandatory_t* descr_mand;
    char* err_info;
    int err;

    idb_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
    descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb_data);
    descr_mand->wtap_encap = pkt_encap;
    descr_mand->tsprecision = WTAP_TSPREC_USEC;
    /* Timestamp for each pcapng packet is usec units, so time_units_per_second need be set to 10^6 */
    descr_mand->time_units_per_second = WS_USECS_PER_SEC;
    if (interface_name_length) {
        wtap_block_add_string_option(idb_data, OPT_IDB_NAME, interface_name, interface_name_length);
    }
    if (interface_desc_length) {
        wtap_block_add_string_option(idb_data, OPT_IDB_DESCRIPTION, interface_desc, interface_desc_length);
    }
    if(!wtap_dump_add_idb(g_pdh, idb_data, &err, &err_info)) {
        g_err = err;
        sprintf_s(g_err_info, sizeof(g_err_info), "wtap_dump failed, %s", err_info);
        g_free(err_info);
    }
}

void wtap_etl_rec_dump(char* etl_record, ULONG total_packet_length, ULONG original_packet_length, unsigned int interface_id, BOOLEAN is_inbound, ULARGE_INTEGER timestamp, int pkt_encap, char* comment, unsigned short comment_length)
{
    char* err_info;
    int err;
    wtap_rec rec = { 0 };

    wtap_rec_init(&rec, 2048); // Appropriate size?
    wtap_setup_packet_rec(&rec, pkt_encap);
    rec.rec_header.packet_header.caplen = total_packet_length;
    rec.rec_header.packet_header.len = original_packet_length;
    rec.rec_header.packet_header.interface_id = interface_id;
    rec.presence_flags = WTAP_HAS_INTERFACE_ID;
    rec.block = wtap_block_create(WTAP_BLOCK_PACKET);
    wtap_block_add_uint32_option(rec.block, OPT_PKT_FLAGS, is_inbound ? PACK_FLAGS_DIRECTION_INBOUND : PACK_FLAGS_DIRECTION_OUTBOUND);
    if (comment_length) {
        wtap_block_add_string_option(rec.block, OPT_COMMENT, comment, comment_length);
    }
    /* Convert usec of the timestamp into nstime_t */
    rec.ts.secs = (time_t)(timestamp.QuadPart / WS_USECS_PER_SEC);
    rec.ts.nsecs = (int)(((timestamp.QuadPart % WS_USECS_PER_SEC) * WS_NSECS_PER_SEC) / WS_USECS_PER_SEC);

    /* and save the packet */
    ws_buffer_append(&rec.data, (uint8_t*)etl_record, total_packet_length);

    if (!wtap_dump(g_pdh, &rec, &err, &err_info)) {
        g_err = err;
        sprintf_s(g_err_info, sizeof(g_err_info), "wtap_dump failed, %s", err_info);
        g_free(err_info);
    }

    /* Only flush when live session */
    if (g_is_live_session && !wtap_dump_flush(g_pdh, &err)) {
        g_err = err;
        sprintf_s(g_err_info, sizeof(g_err_info), "wtap_dump failed, 0x%x", err);
    }
    wtap_rec_cleanup(&rec);
}

/* Context-related functions */

static etw_frag* etw_frag_new()
{
    etw_frag* frag = g_malloc(sizeof(etw_frag));
    frag->buf = g_byte_array_new();
    frag->ctx = ctx_init();
    return frag;
}

static void etw_frag_free(etw_frag* frag)
{
    g_byte_array_free(frag->buf, true);
    ctx_free(frag->ctx);
    g_free(frag);
}

static etw_frag* etw_frag_get(PEVENT_RECORD ev, bool begin)
{
    etw_frag* frag;
    if (begin)
    {
        /* We need a new buffer */

        if (g_hash_table_contains(g_etw_frags, GINT_TO_POINTER(ev->EventHeader.ThreadId)))
        {
            /* Already exists : remove */
            frag = g_hash_table_lookup(g_etw_frags, GINT_TO_POINTER(ev->EventHeader.ThreadId));
            etw_frag_free(frag);
            etw_frag_remove(ev);
        }

        /* New buffer */
        frag = etw_frag_new();
        g_hash_table_insert(g_etw_frags, GINT_TO_POINTER(ev->EventHeader.ThreadId), frag);
    }
    else
    {
        /* We get an existing buffer */
        frag = g_hash_table_lookup(g_etw_frags, GINT_TO_POINTER(ev->EventHeader.ThreadId));
    }
    return frag;
}

static void etw_frag_remove(PEVENT_RECORD ev)
{
    g_hash_table_remove(g_etw_frags, GINT_TO_POINTER(ev->EventHeader.ThreadId));
}

/* Protocol specific functions */

static void etw_dump_write_opn_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG total_packet_length = 0;
    BOOLEAN is_inbound = false;
    PWTAP_ETL_RECORD_CONTEXT ctx;

    /* 0x80000000 mask the function to host message */
    is_inbound = ((*(INT32*)(ev->UserData)) & 0x80000000) ? true : false;

    // Build packet
    ctx = ctx_init();
    ctx_add_tlv_user_data_ev(ctx, ev);

    // Dump
    total_packet_length = wtap_etl_rec_build(&etl_record, ev, ctx);
    wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, is_inbound, timestamp, WTAP_ENCAP_ETW, NULL, 0);

    g_free(etl_record);
    ctx_free(ctx);
}

static void etw_dump_write_smb_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG total_packet_length = 0;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor = { 0 };
    DWORD PropertySize = 0, Length = 0;
    ULONG status;
    BYTE* Buffer = NULL;

    if (ev->EventHeader.EventDescriptor.Id == 2000)
    {
        // Event 2000 = Fragment; We need to reassemble it

        etw_frag* frag;

        // Get "FragmentData" property
        DataDescriptor.PropertyName = (ULONGLONG)&L"FragmentData";
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(ev, 0, NULL, 1, &DataDescriptor, &Length);
        if (status != NO_ERROR) goto end;
        Buffer = g_malloc(Length);
        status = TdhGetProperty(ev, 0, NULL, 1, &DataDescriptor, Length, Buffer);
        if (status != NO_ERROR) goto end;

        if (ev->EventHeader.EventDescriptor.Keyword & 0x40000000) /* PacketStart */
        {
            // Beggining of the buffer
            frag = etw_frag_get(ev, true);
            if (frag == NULL) goto end;

            // Extract "PeerAddress" from blob
            SOCKADDR_STORAGE* pPeerAddress = (SOCKADDR_STORAGE*)ADD_OFFSET_TO_POINTER(Buffer, 8);

            // Format PeerAddress
            if (pPeerAddress->ss_family == AF_INET || pPeerAddress->ss_family == AF_INET6)
            {
                Length = sizeof(frag->PeerAddressFmt);

                if (pPeerAddress->ss_family == AF_INET)
                    RtlIpv4AddressToStringExA(
                        &((struct sockaddr_in*)pPeerAddress)->sin_addr,
                        ((struct sockaddr_in*)pPeerAddress)->sin_port,
                        (PSTR)&frag->PeerAddressFmt,
                        &Length);
                else
                    RtlIpv6AddressToStringExA(
                        &((struct sockaddr_in6*)pPeerAddress)->sin6_addr,
                        ((struct sockaddr_in6*)pPeerAddress)->sin6_scope_id,
                        ((struct sockaddr_in6*)pPeerAddress)->sin6_port,
                        (PSTR)&frag->PeerAddressFmt,
                        &Length);

                if (ev->EventHeader.EventDescriptor.Keyword & 0x100000000)
                {
                    ctx_add_tlv(frag->ctx, TLV_DST_ADDR, &frag->PeerAddressFmt, Length);
                }
                else
                {
                    ctx_add_tlv(frag->ctx, TLV_SRC_ADDR, &frag->PeerAddressFmt, Length);
                }
            }

            // Reserve 4 octets for the Netbios Header
            uint32_t reserved = 0;
            g_byte_array_append(frag->buf, &reserved, sizeof(reserved));
        }
        else
        {
            // Middle / End of the buffer

            frag = etw_frag_get(ev, false);
            if (frag == NULL) goto end;

            // Append data
            g_byte_array_append(frag->buf, Buffer, Length);
        }

        if (ev->EventHeader.EventDescriptor.Keyword & 0x80000000)  /* PacketEnd */
        {
            // End of the buffer

            if (frag->buf->len > 4)
            {
                // Set the netbios header
                PropertySize = frag->buf->len - 4;
                frag->buf->data[0] = 0;
                frag->buf->data[1] = (PropertySize >> 0x10) & 0xFF;
                frag->buf->data[2] = (PropertySize >> 0x08) & 0xFF;
                frag->buf->data[3] = PropertySize & 0xFF;

                ctx_add_tlv_user_data(frag->ctx, frag->buf->data, frag->buf->len);

                // Dump
                total_packet_length = wtap_etl_rec_build(&etl_record, ev, frag->ctx);
                wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, true, timestamp, WTAP_ENCAP_ETW, NULL, 0);
                g_free(etl_record);
            }

            etw_frag_free(frag);
            etw_frag_remove(ev);
        }
    }
    else
    {
        // Event 40000 = Full I/O.

        SOCKADDR_STORAGE PeerAddress;
        PWTAP_ETL_RECORD_CONTEXT ctx = ctx_init();
        CHAR PeerAddressFmt[64] = { 0 };  // 46 max for IPv6 address, 1 for ':' and 5 for the port

        // Get "PeerAddress" property
        DataDescriptor.PropertyName = (ULONGLONG)&L"PeerAddress";
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetProperty(ev, 0, NULL, 1, &DataDescriptor, sizeof(PeerAddress), (PBYTE)&PeerAddress);
        if (status != NO_ERROR) goto nfend;

        // Format PeerAddress
        if (PeerAddress.ss_family == AF_INET || PeerAddress.ss_family == AF_INET6)
        {
            Length = sizeof(PeerAddressFmt);

            if (PeerAddress.ss_family == AF_INET)
                RtlIpv4AddressToStringExA(
                    &((struct sockaddr_in*)&PeerAddress)->sin_addr,
                    ((struct sockaddr_in*)&PeerAddress)->sin_port,
                    (PSTR)&PeerAddressFmt,
                    &Length);
            else
                RtlIpv6AddressToStringExA(
                    &((struct sockaddr_in6*)&PeerAddress)->sin6_addr,
                    ((struct sockaddr_in6*)&PeerAddress)->sin6_scope_id,
                    ((struct sockaddr_in6*)&PeerAddress)->sin6_port,
                    (PSTR)&PeerAddressFmt,
                    &Length);

            if (ev->EventHeader.EventDescriptor.Keyword & 0x100000000)
            {
                ctx_add_tlv(ctx, TLV_DST_ADDR, &PeerAddressFmt, Length);
            }
            else
            {
                ctx_add_tlv(ctx, TLV_SRC_ADDR, &PeerAddressFmt, Length);
            }
        }

        // Get "PacketData" property
        DataDescriptor.PropertyName = (ULONGLONG)&L"PacketData";
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(ev, 0, NULL, 1, &DataDescriptor, &PropertySize);
        if (status != NO_ERROR) goto nfend;
        if (PropertySize > 0xFFFFFF)
            // Size cannot be longer than 3 octets
            return;
        Length = PropertySize + 4;  // Make room for the Netbios header
        Buffer = g_malloc(Length);
        status = TdhGetProperty(ev, 0, NULL, 1, &DataDescriptor, PropertySize, ADD_OFFSET_TO_POINTER(Buffer, 4));
        if (status != NO_ERROR) goto nfend;

        // Netbios header
        Buffer[0] = 0;
        Buffer[1] = (PropertySize >> 0x10) & 0xFF;
        Buffer[2] = (PropertySize >> 0x08) & 0xFF;
        Buffer[3] = PropertySize & 0xFF;

        ctx_add_tlv_user_data(ctx, Buffer, Length);

        // Dump
        total_packet_length = wtap_etl_rec_build(&etl_record, ev, ctx);
        wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, true, timestamp, WTAP_ENCAP_ETW, NULL, 0);

        g_free(etl_record);

    nfend:
        if (ctx)
            ctx_free(ctx);
    }

end:

    if (Buffer)
        g_free(Buffer);
}

static void etw_dump_write_wininet_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG total_packet_length = 0;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor = { 0 };
    DWORD Length = 0;
    ULONG status;
    ULONGLONG SessionId = 0;
    BYTE* Buffer = NULL;
    PWTAP_ETL_RECORD_CONTEXT ctx = ctx_init();

    // Get "SessionId" property (same for request / response)
    DataDescriptor.PropertyName = (ULONGLONG)&L"SessionId";
    DataDescriptor.ArrayIndex = ULONG_MAX;
    status = TdhGetProperty(ev, 0, NULL, 1, &DataDescriptor, sizeof(SessionId), (PBYTE) &SessionId);
    if (status != NO_ERROR) goto end;
    ctx_add_tlv(ctx, TLV_SESSION_ID, &SessionId, sizeof(SessionId));

    // Get "Payload" property
    DataDescriptor.PropertyName = (ULONGLONG)&L"Payload";
    DataDescriptor.ArrayIndex = ULONG_MAX;
    status = TdhGetPropertySize(ev, 0, NULL, 1, &DataDescriptor, &Length);
    if (status != NO_ERROR) goto end;
    Buffer = g_malloc(Length);
    status = TdhGetProperty(ev, 0, NULL, 1, &DataDescriptor, Length, Buffer);
    if (status != NO_ERROR) goto end;

    ctx_add_tlv_user_data(ctx, Buffer, Length);

    // Dump
    total_packet_length = wtap_etl_rec_build(&etl_record, ev, ctx);
    wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, true, timestamp, WTAP_ENCAP_ETW, NULL, 0);

    g_free(etl_record);

end:
    ctx_free(ctx);

    if (Buffer)
        g_free(Buffer);
}

static void etw_dump_write_webio_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG total_packet_length = 0;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor = { 0 };
    DWORD Length = 0;
    ULONG status;
    ULONGLONG SessionId = 0;
    BYTE* Buffer = NULL;
    PWTAP_ETL_RECORD_CONTEXT ctx = ctx_init();

    // "SessionId" equivalent (same for request / response)
    DataDescriptor.PropertyName = (ULONGLONG)&L"Request";
    DataDescriptor.ArrayIndex = ULONG_MAX;
    status = TdhGetProperty(ev, 0, NULL, 1, &DataDescriptor, sizeof(SessionId), (PBYTE)&SessionId);
    if (status != NO_ERROR) goto end;
    ctx_add_tlv(ctx, TLV_SESSION_ID, &SessionId, sizeof(SessionId));

    // Get "Length" property
    DataDescriptor.PropertyName = (ULONGLONG)&L"Length";
    DataDescriptor.ArrayIndex = ULONG_MAX;
    status = TdhGetProperty(ev, 0, NULL, 1, &DataDescriptor, sizeof(DWORD), &Length);
    if (status != NO_ERROR) goto end;
    Buffer = g_malloc(Length);

    if (ev->EventHeader.EventDescriptor.Id == 100 || ev->EventHeader.EventDescriptor.Id == 101)
    {
        // Get "Headers" property
        DataDescriptor.PropertyName = (ULONGLONG)&L"Headers";
    }
    else
    {
        // Get "Data" property
        DataDescriptor.PropertyName = (ULONGLONG)&L"Data";
    }
    DataDescriptor.ArrayIndex = ULONG_MAX;
    status = TdhGetProperty(ev, 0, NULL, 1, &DataDescriptor, Length, Buffer);
    if (status != NO_ERROR) goto end;

    ctx_add_tlv_user_data(ctx, Buffer, Length);

    // Dump
    total_packet_length = wtap_etl_rec_build(&etl_record, ev, ctx);
    wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, true, timestamp, WTAP_ENCAP_ETW, NULL, 0);

    g_free(etl_record);

end:
    ctx_free(ctx);

    if (Buffer)
        g_free(Buffer);
}

static void etw_dump_write_ldap_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG total_packet_length = 0;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor = { 0 };
    DWORD Length = 0;
    ULONG status;
    BYTE* Message = NULL;
    etw_frag* frag;

    // Get "Message" property
    DataDescriptor.PropertyName = (ULONGLONG)&L"Message";
    DataDescriptor.ArrayIndex = ULONG_MAX;
    status = TdhGetPropertySize(ev, 0, NULL, 1, &DataDescriptor, &Length);
    if (status != NO_ERROR) goto end;
    Message = g_malloc(Length);
    status = TdhGetProperty(ev, 0, NULL, 1, &DataDescriptor, Length, Message);
    if (status != NO_ERROR) goto end;

    // "Message" contains text and a hexdump of the data. We need to parse it
    // and reassemble it. Let's use the ThreadId as the identifying key.

    if (strncmp(Message, "Data", 4) == 0 || strncmp(Message, "Unencrypted", 11) == 0)
    {
        // Beggining of the buffer

        frag = etw_frag_get(ev, true);
    }
    else if (strncmp(Message, "End", 3) == 0)
    {
        // End of the buffer

        frag = etw_frag_get(ev, false);
        if (frag == NULL) goto end;

        ctx_add_tlv_user_data(frag->ctx, frag->buf->data, frag->buf->len);

        // Dump
        total_packet_length = wtap_etl_rec_build(&etl_record, ev, frag->ctx);
        wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, true, timestamp, WTAP_ENCAP_ETW, NULL, 0);

        etw_frag_free(frag);
        etw_frag_remove(ev);
        g_free(etl_record);
    }
    else
    {
        // Data (in hexdump format)

        frag = etw_frag_get(ev, false);
        if (frag == NULL) goto end;

        // Replace "Message" in place
        int i = 0;
        while (i < 16)
        {
            if (Message[i * 3] == 0x20)
                break;
            if (sscanf(&Message[i * 3], "%2hhx", &Message[i]) != 1)
                goto end;
            i++;
        }

        g_byte_array_append(frag->buf, Message, i);
    }

end:
    if (Message)
        g_free(Message);
}

static void etw_dump_write_general_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    PTRACE_EVENT_INFO pInfo = NULL;
    PBYTE pUserData = NULL;
    PBYTE pEndOfUserData = NULL;
    DWORD PointerSize = 0;
    PROPERTY_KEY_VALUE* prop_arr = NULL;
    DWORD dwTopLevelPropertyCount = 0;
    DWORD dwSizeofArray = 0;
    WCHAR* wszProviderName = NULL;
    WCHAR* wszMessage = NULL;
    bool include_user_data = false;
    PWTAP_ETL_RECORD_CONTEXT ctx;

    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG total_packet_length = 0;

    /* Skip EventTrace events */
    if (ev->EventHeader.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER &&
        IsEqualGUID(&ev->EventHeader.ProviderId, &EventTraceGuid))
    {
        /*
        * The first event in every ETL file contains the data from the file header.
        * This is the same data as was returned in the EVENT_TRACE_LOGFILEW by
        * OpenTrace. Since we've already seen this information, we'll skip this
        * event.
        */
        goto end;
    }

    /* Skip events injected by the XPerf tracemerger - they will never be decodable */
    if (IsEqualGUID(&ev->EventHeader.ProviderId, &ImageIdGuid) ||
        IsEqualGUID(&ev->EventHeader.ProviderId, &SystemConfigExGuid) ||
        IsEqualGUID(&ev->EventHeader.ProviderId, &EventMetadataGuid))
    {
        goto end;
    }

    if (!get_event_information(ev, &pInfo))
    {
        goto end;
    }

    if (pInfo->ProviderNameOffset > 0)
    {
        wszProviderName = (WCHAR*)ADD_OFFSET_TO_POINTER(pInfo, pInfo->ProviderNameOffset);
    }

    if (EVENT_HEADER_FLAG_32_BIT_HEADER == (ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
    {
        PointerSize = 4;
    }
    else
    {
        PointerSize = 8;
    }

    pUserData = (PBYTE)ev->UserData;
    pEndOfUserData = (PBYTE)ev->UserData + ev->UserDataLength;

    dwTopLevelPropertyCount = pInfo->TopLevelPropertyCount;
    if (dwTopLevelPropertyCount > 0)
    {
        prop_arr = g_malloc(sizeof(PROPERTY_KEY_VALUE) * dwTopLevelPropertyCount);
        dwSizeofArray = dwTopLevelPropertyCount * sizeof(PROPERTY_KEY_VALUE);
        SecureZeroMemory(prop_arr, dwSizeofArray);
    }

    // Events we don't have a manifest for will have an empty format message
    if (pInfo->EventMessageOffset > 0)
    {
        wszMessage = (LPWSTR)ADD_OFFSET_TO_POINTER(pInfo, pInfo->EventMessageOffset);
    }

    for (USHORT i = 0; i < dwTopLevelPropertyCount; i++)
    {
        pUserData = extract_property(ev, pInfo, PointerSize, i, pUserData, pEndOfUserData, &prop_arr[i]);
        if (NULL == pUserData)
        {
            /* Extraction of a property failed */
            if (g_include_undecidable_event)
            {
                /* In that case, always include Raw User Data */
                include_user_data = true;
            }

            if (ev->EventHeader.Flags & EVENT_HEADER_FLAG_TRACE_MESSAGE)
            {
                /* WPP: we cannot actually read ANY property */
                dwTopLevelPropertyCount = 0;
                break;
            }
        }
    }

    if (dwTopLevelPropertyCount == 0 && wszMessage == NULL)
    {
        // We didn't have the manifest / tmh, and we have nothing interesting to show.
        // Skip if "undecidable" isn't checked
        if (!g_include_undecidable_event)
        {
            goto end;
        }

        // If we're asked to include "undecidable", the only thing we can provide is the
        // raw user data.
        include_user_data = true;
    }

    // Build packet
    ctx = ctx_init();
    if (include_user_data)
        ctx_add_tlv_user_data_ev(ctx, ev);
    if (wszProviderName != NULL)
        ctx_add_tlv_wchar(ctx, TLV_PROVIDER_NAME, wszProviderName);
    if (wszMessage != NULL)
        ctx_add_tlv_wchar(ctx, TLV_MESSAGE, wszMessage);
    ctx->properties = prop_arr;
    ctx->properties_count = dwTopLevelPropertyCount;

    // Dump
    total_packet_length = wtap_etl_rec_build(&etl_record, ev, ctx);
    wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, false, timestamp, WTAP_ENCAP_ETW, NULL, 0);

    g_free(etl_record);
    ctx_free(ctx);

end:
    if (NULL != prop_arr)
    {
        g_free(prop_arr);
        prop_arr = NULL;
    }
    if (NULL != pInfo)
    {
        g_free(pInfo);
        pInfo = NULL;
    }
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
