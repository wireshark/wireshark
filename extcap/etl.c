/* etl.c
 *
 * Copyright 2020, Odysseus Yang
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Reads an ETL file and writes out a pcap file with LINKTYPE_ETW.
 *
 * https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
 */

#include "config.h"
#define WS_LOG_DOMAIN "etwdump"

#include "etl.h"
#include "wsutil/ws_getopt.h"
#include "wsutil/strtoi.h"
#include "etw_message.h"

#include <rpc.h>
#include <winevt.h>

#define MAX_PACKET_SIZE 0xFFFF
#define G_NSEC_PER_SEC 1000000000
#define ADD_OFFSET_TO_POINTER(buffer, offset) (((PBYTE)buffer) + offset)
#define ROUND_UP_COUNT(Count,Pow2) \
        ( ((Count)+(Pow2)-1) & (~(((int)(Pow2))-1)) )

extern int g_include_undecidable_event;

//Microsoft-Windows-Wmbclass-Opn
const GUID mbb_provider = { 0xA42FE227, 0xA7BF, 0x4483, {0xA5, 0x02, 0x6B, 0xCD, 0xA4, 0x28, 0xCD, 0x96} };
// Microsoft-Windows-NDIS-PacketCapture
const GUID ndis_capture_provider = { 0x2ed6006e, 0x4729, 0x4609, 0xb4, 0x23, 0x3e, 0xe7, 0xbc, 0xd6, 0x78, 0xef };

EXTERN_C const GUID DECLSPEC_SELECTANY EventTraceGuid = { 0x68fdd900, 0x4a3e, 0x11d1, {0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3} };
EXTERN_C const GUID DECLSPEC_SELECTANY ImageIdGuid = { 0xb3e675d7, 0x2554, 0x4f18, { 0x83, 0xb, 0x27, 0x62, 0x73, 0x25, 0x60, 0xde } };
EXTERN_C const GUID DECLSPEC_SELECTANY SystemConfigExGuid = { 0x9b79ee91, 0xb5fd, 0x41c0, { 0xa2, 0x43, 0x42, 0x48, 0xe2, 0x66, 0xe9, 0xd0 } };
EXTERN_C const GUID DECLSPEC_SELECTANY EventMetadataGuid = { 0xbbccf6c1, 0x6cd1, 0x48c4, {0x80, 0xff, 0x83, 0x94, 0x82, 0xe3, 0x76, 0x71 } };
EXTERN_C const GUID DECLSPEC_SELECTANY ZeroGuid = { 0 };

typedef struct _WTAP_ETL_RECORD {
    EVENT_HEADER        EventHeader;            // Event header
    ETW_BUFFER_CONTEXT  BufferContext;          // Buffer context
    ULONG               UserDataLength;
    ULONG               MessageLength;
    ULONG               ProviderLength;
} WTAP_ETL_RECORD;

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

typedef struct _PROVIDER_FILTER {
    GUID ProviderId;
    ULONG64 Keyword;
    UCHAR Level;
} PROVIDER_FILTER;

char g_err_info[FILENAME_MAX];
int g_err = ERROR_SUCCESS;
static wtap_dumper* g_pdh;
extern ULONGLONG g_num_events;
static PROVIDER_FILTER g_provider_filters[32];
static BOOL g_is_live_session;

static void WINAPI event_callback(PEVENT_RECORD ev);
void etw_dump_write_opn_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
void etw_dump_write_ndiscap_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
void etw_dump_write_general_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
void etw_dump_write_event_head_only(PEVENT_RECORD ev, ULARGE_INTEGER timestamp);
void wtap_etl_rec_dump(char* etl_record, ULONG total_packet_length, ULONG original_packet_length, unsigned int interface_id, BOOLEAN is_inbound, ULARGE_INTEGER timestamp, int pkt_encap, char* comment, unsigned short comment_length);
wtap_dumper* etw_dump_open(const char* pcapng_filename, int* err, char** err_info);

DWORD GetPropertyValue(WCHAR* ProviderId, EVT_PUBLISHER_METADATA_PROPERTY_ID PropertyId, PEVT_VARIANT* Value)
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
    super_trace_properties.prop.Wnode.ClientContext = 2;
    super_trace_properties.prop.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    super_trace_properties.prop.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    super_trace_properties.prop.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    TRACEHANDLE traceControllerHandle = (TRACEHANDLE)INVALID_HANDLE_VALUE;
    TRACEHANDLE trace_handle = INVALID_PROCESSTRACE_HANDLE;

    SecureZeroMemory(g_provider_filters, sizeof(g_provider_filters));
    SecureZeroMemory(g_err_info, FILENAME_MAX);
    g_err = ERROR_SUCCESS;
    g_num_events = 0;
    g_is_live_session = false;

    if (params)
    {
        int opt_result = 0;
        int option_idx = 0;
        int provider_idx = 0;
        char** params_array = NULL;
        int params_array_num = 0;
        WCHAR provider_id[FILENAME_MAX] = { 0 };
        ULONG convert_level = 0;

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
                if (UuidFromString(provider_id, &g_provider_filters[provider_idx].ProviderId) == RPC_S_INVALID_STRING_UUID)
                {
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
                if (provider_idx == 0)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("-k parameter must follow -p, err is 0x%x", *err);
                    return WTAP_OPEN_ERROR;
                }

                g_provider_filters[provider_idx - 1].Keyword = _strtoui64(ws_optarg, NULL, 0);
                if (!g_provider_filters[provider_idx - 1].Keyword)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("Keyword %s cannot be converted, err is 0x%x", ws_optarg, *err);
                    return WTAP_OPEN_ERROR;
                }
                break;
            case OPT_LEVEL:
                if (provider_idx == 0)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("-l parameter must follow -p, err is 0x%x", *err);
                    return WTAP_OPEN_ERROR;
                }

                convert_level = strtoul(ws_optarg, NULL, 0);
                if (convert_level > UCHAR_MAX)
                {
                    *err = ERROR_INVALID_PARAMETER;
                    *err_info = ws_strdup_printf("Level %s is bigger than 0xff, err is 0x%x", ws_optarg, *err);
                    return WTAP_OPEN_ERROR;
                }
                if (!convert_level)
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
                *err = EnableTraceEx(
                    &g_provider_filters[i].ProviderId,
                    NULL,
                    traceControllerHandle,
                    true,
                    g_provider_filters[i].Level,
                    g_provider_filters[i].Keyword,
                    0,
                    0,
                    NULL);
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
    return returnVal;
}

BOOL is_event_filtered_out(PEVENT_RECORD ev)
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
    * The offset of 11644473600 seconds can be calculated with a couple of calls to SystemTimeToFileTime.
    */
    timestamp.QuadPart = (ev->EventHeader.TimeStamp.QuadPart / 10) - 11644473600000000ll;

    /* Write OPN events that needs mbim sub dissector */
    if (IsEqualGUID(&ev->EventHeader.ProviderId, &mbb_provider))
    {
        etw_dump_write_opn_event(ev, timestamp);
    }
    else if (IsEqualGUID(&ev->EventHeader.ProviderId, &ndis_capture_provider))
    {
        etw_dump_write_ndiscap_event(ev, timestamp);
    }
    /* Write any event form other providers other than above */
    else
    {
        etw_dump_write_general_event(ev, timestamp);
    }
}

wtap_dumper* etw_dump_open(const char* pcapng_filename, int* err, char** err_info)
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
    idb_datas = g_array_new(false, false, sizeof(wtap_block_t));
    idb_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
    descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb_data);
    descr_mand->tsprecision = WTAP_TSPREC_USEC;
    descr_mand->wtap_encap = WTAP_ENCAP_ETW;
    /* Timestamp for each pcapng packet is usec units, so time_units_per_second need be set to 10^6 */
    descr_mand->time_units_per_second = G_USEC_PER_SEC;
    g_array_append_val(idb_datas, idb_data);
    idb_info->interface_data = idb_datas;

    params.encap = WTAP_ENCAP_ETW;
    params.snaplen = 0;
    params.tsprec = WTAP_TSPREC_USEC;
    params.shb_hdrs = shb_hdrs;
    params.idb_inf = idb_info;

    pdh = wtap_dump_open(pcapng_filename, wtap_pcapng_file_type_subtype(), WTAP_UNCOMPRESSED, &params, err, err_info);

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

ULONG wtap_etl_record_buffer_init(WTAP_ETL_RECORD** out_etl_record, PEVENT_RECORD ev, BOOLEAN include_user_data, WCHAR* message, WCHAR* provider_name)
{
    ULONG total_packet_length = sizeof(WTAP_ETL_RECORD);
    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG user_data_length = 0;
    ULONG user_data_offset = 0;
    ULONG message_offset = 0;
    ULONG provider_name_offset = 0;
    ULONG message_length = 0;
    ULONG provider_name_length = 0;

    if (include_user_data)
    {
        if (ev->UserDataLength < MAX_PACKET_SIZE)
        {
            user_data_length = ev->UserDataLength;
        }
        else
        {
            user_data_length = MAX_PACKET_SIZE;
        }
        user_data_offset = sizeof(WTAP_ETL_RECORD);
        total_packet_length += ROUND_UP_COUNT(user_data_length, sizeof(LONG));
    }
    if (message && message[0] != L'\0')
    {
        message_offset = total_packet_length;
        message_length = (ULONG)((wcslen(message) + 1) * sizeof(WCHAR));
        total_packet_length += ROUND_UP_COUNT(message_length, sizeof(LONG));
    }
    if (provider_name && provider_name[0] != L'\0')
    {
        provider_name_offset = total_packet_length;
        provider_name_length = (ULONG)((wcslen(provider_name) + 1) * sizeof(WCHAR));
        total_packet_length += ROUND_UP_COUNT(provider_name_length, sizeof(LONG));
    }

    etl_record = g_malloc(total_packet_length);
    SecureZeroMemory(etl_record, total_packet_length);
    etl_record->EventHeader = ev->EventHeader;
    etl_record->BufferContext = ev->BufferContext;
    etl_record->UserDataLength = user_data_length;
    etl_record->MessageLength = message_length;
    etl_record->ProviderLength = provider_name_length;

    if (user_data_offset)
    {
        memcpy(ADD_OFFSET_TO_POINTER(etl_record, user_data_offset), ev->UserData, user_data_length);
    }
    if (message_offset)
    {
        memcpy(ADD_OFFSET_TO_POINTER(etl_record, message_offset), message, message_length);
    }
    if (provider_name_offset)
    {
        memcpy(ADD_OFFSET_TO_POINTER(etl_record, provider_name_offset), provider_name, provider_name_length);
    }

    *out_etl_record = etl_record;
    return total_packet_length;
}

void wtap_etl_add_interface(int pkt_encap, char* interface_name, unsigned short interface_name_length, char* interface_desc, unsigned short interface_desc_length)
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
    descr_mand->time_units_per_second = G_USEC_PER_SEC;
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

    wtap_rec_init(&rec);
    rec.rec_header.packet_header.caplen = total_packet_length;
    rec.rec_header.packet_header.len = original_packet_length;
    rec.rec_header.packet_header.pkt_encap = pkt_encap;
    rec.rec_header.packet_header.interface_id = interface_id;
    rec.presence_flags = WTAP_HAS_INTERFACE_ID;
    rec.block = wtap_block_create(WTAP_BLOCK_PACKET);
    wtap_block_add_uint32_option(rec.block, OPT_PKT_FLAGS, is_inbound ? PACK_FLAGS_DIRECTION_INBOUND : PACK_FLAGS_DIRECTION_OUTBOUND);
    if (comment_length) {
        wtap_block_add_string_option(rec.block, OPT_COMMENT, comment, comment_length);
    }
    /* Convert usec of the timestamp into nstime_t */
    rec.ts.secs = (time_t)(timestamp.QuadPart / G_USEC_PER_SEC);
    rec.ts.nsecs = (int)(((timestamp.QuadPart % G_USEC_PER_SEC) * G_NSEC_PER_SEC) / G_USEC_PER_SEC);

    /* and save the packet */
    if (!wtap_dump(g_pdh, &rec, (uint8_t*)etl_record, &err, &err_info)) {
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

void etw_dump_write_opn_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG total_packet_length = 0;
    BOOLEAN is_inbound = false;
    /* 0x80000000 mask the function to host message */
    is_inbound = ((*(INT32*)(ev->UserData)) & 0x80000000) ? true : false;
    total_packet_length = wtap_etl_record_buffer_init(&etl_record, ev, true, NULL, NULL);
    wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, is_inbound, timestamp, WTAP_ENCAP_ETW, NULL, 0);
    g_free(etl_record);
}

void etw_dump_write_event_head_only(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG total_packet_length = 0;
    total_packet_length = wtap_etl_record_buffer_init(&etl_record, ev, false, NULL, NULL);
    wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, false, timestamp, WTAP_ENCAP_ETW, NULL, 0);
    g_free(etl_record);
}

void etw_dump_write_general_event(PEVENT_RECORD ev, ULARGE_INTEGER timestamp)
{
    PTRACE_EVENT_INFO pInfo = NULL;
    PBYTE pUserData = NULL;
    PBYTE pEndOfUserData = NULL;
    DWORD PointerSize = 0;
    PROPERTY_KEY_VALUE* prop_arr = NULL;
    DWORD dwTopLevelPropertyCount = 0;
    DWORD dwSizeofArray = 0;
    WCHAR wszMessageBuffer[MAX_LOG_LINE_LENGTH] = { 0 };
    WCHAR formatMessage[MAX_LOG_LINE_LENGTH] = { 0 };

    WTAP_ETL_RECORD* etl_record = NULL;
    ULONG total_packet_length = 0;
    BOOLEAN is_message_dumped = false;

    do
    {
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
            break;
        }

        /* Skip events injected by the XPerf tracemerger - they will never be decodable */
        if (IsEqualGUID(&ev->EventHeader.ProviderId, &ImageIdGuid) ||
            IsEqualGUID(&ev->EventHeader.ProviderId, &SystemConfigExGuid) ||
            IsEqualGUID(&ev->EventHeader.ProviderId, &EventMetadataGuid))
        {
            break;
        }

        if (!get_event_information(ev, &pInfo))
        {
            break;
        }

        /* Skip those events without format message since most of them need special logic to decode like NDIS-PackCapture */
        if (pInfo->EventMessageOffset <= 0)
        {
            break;
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

        StringCbCopy(formatMessage, MAX_LOG_LINE_LENGTH, (LPWSTR)ADD_OFFSET_TO_POINTER(pInfo, pInfo->EventMessageOffset));

        for (USHORT i = 0; i < dwTopLevelPropertyCount; i++)
        {
            pUserData = extract_properties(ev, pInfo, PointerSize, i, pUserData, pEndOfUserData, &prop_arr[i]);
            if (NULL == pUserData)
            {
                break;
            }
        }

        format_message(formatMessage, prop_arr, dwTopLevelPropertyCount, wszMessageBuffer, sizeof(wszMessageBuffer));

        total_packet_length = wtap_etl_record_buffer_init(&etl_record, ev, false, wszMessageBuffer, (WCHAR*)ADD_OFFSET_TO_POINTER(pInfo, pInfo->ProviderNameOffset));
        wtap_etl_rec_dump((char*)etl_record, total_packet_length, total_packet_length, 0, false, timestamp, WTAP_ENCAP_ETW, NULL, 0);
        g_free(etl_record);

        is_message_dumped = true;
    } while (false);

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

    if (!is_message_dumped && g_include_undecidable_event)
    {
        etw_dump_write_event_head_only(ev, timestamp);
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
