/* packet-etw.c
 * Routines for ETW Dissection
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

/* Dissector based on ETW Trace
* https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
*/

#include "config.h"

#include <epan/conversation.h>
#include <epan/packet.h>
#include <wiretap/wtap.h>

#include "packet-windows-common.h"
#include "packet-tcp.h"

#define MAX_SMALL_BUFFER 4

void proto_register_etw(void);
void proto_reg_handoff_etw(void);

static dissector_handle_t etw_handle;

// ETW fields
static int proto_etw;
static int hf_etw_size;
static int hf_etw_header_type;
static int hf_etw_header_flag_extended_info;
static int hf_etw_header_flag_private_session;
static int hf_etw_header_flag_string_only;
static int hf_etw_header_flag_trace_message;
static int hf_etw_header_flag_no_cputime;
static int hf_etw_header_flag_32_bit_header;
static int hf_etw_header_flag_64_bit_header;
static int hf_etw_header_flag_decode_guid;
static int hf_etw_header_flag_classic_header;
static int hf_etw_header_flag_processor_index;
static int hf_etw_flags;
static int hf_etw_event_property;
static int hf_etw_event_property_xml;
static int hf_etw_event_property_forwarded_xml;
static int hf_etw_event_property_legacy_eventlog;
static int hf_etw_event_property_legacy_reloggable;
static int hf_etw_thread_id;
static int hf_etw_process_id;
static int hf_etw_time_stamp;
static int hf_etw_provider_id;
static int hf_etw_buffer_context_processor_number;
static int hf_etw_buffer_context_alignment;
static int hf_etw_buffer_context_logger_id;
static int hf_etw_src;
static int hf_etw_dst;
static int hf_etw_sessid;
static int hf_etw_properties_count;
static int hf_etw_provider_name;
static int hf_etw_message;
static int hf_etw_extended_data_count;
static int hf_etw_extended_data;
static int hf_etw_edata;
static int hf_etw_edata_reserved1;
static int hf_etw_edata_exttype;
static int hf_etw_edata_linkage;
static int hf_etw_edata_datasize;
static int hf_etw_edata_dataptr;
static int hf_etw_edata_data;
static int hf_etw_edata_stacktrace_matchid;
static int hf_etw_edata_stacktrace_address;
static int hf_etw_edata_schematl_size;
static int hf_etw_edata_schematl_reserved1;
static int hf_etw_edata_schematl_name;
static int hf_etw_edata_schematl_field;
static int hf_etw_edata_schematl_field_key;
static int hf_etw_edata_schematl_field_flags;
static int hf_etw_edata_schematl_field_type;
static int hf_etw_edata_schematl_field_ccount;
static int hf_etw_edata_schematl_field_vcount;
static int hf_etw_edata_schematl_field_chain;
static int hf_etw_edata_traits_traitssize;
static int hf_etw_edata_traits_providername;
static int hf_etw_property;
static int hf_etw_property_offset;
static int hf_etw_property_keylen;
static int hf_etw_property_valuelen;
static int hf_etw_property_key;
static int hf_etw_property_value;
static int hf_etw_tlv_count;
static int hf_etw_tlv_length;
static int hf_etw_tlv_offset;
static int hf_etw_tlv_type;
static int hf_etw_user_data;
static int hf_etw_descriptor_id;
static int hf_etw_descriptor_version;
static int hf_etw_descriptor_channel;
static int hf_etw_descriptor_level;
static int hf_etw_descriptor_opcode;
static int hf_etw_descriptor_task;
static int hf_etw_descriptor_keywords;
static int hf_etw_processor_time;
static int hf_etw_activity_id;

// Generated fields
static int hf_etw_type;
static int hf_etw_message_formatted;

static int ett_etw_header;
static int ett_etw_data;
static int ett_etw_descriptor;
static int ett_etw_buffer_context;
static int ett_etw_extended_data;
static int ett_etw_property;
static int ett_etw_edata;
static int ett_etw_edata_data;
static int ett_etw_edata_schematl_schema;
static int ett_etw_schematl_flags;
static int ett_etw_header_flags;
static int ett_etw_event_property_types;
static int ett_etw_tlvs;
static int ett_etw_tlv;

static dissector_handle_t mbim_dissector;
static e_guid_t mbim_net_providerid = { 0xA42FE227, 0xA7BF, 0x4483, {0xA5, 0x02, 0x6B, 0xCD, 0xA4, 0x28, 0xCD, 0x96} };

static dissector_handle_t nbss_dissector;
static e_guid_t smbclient_providerid = { 0x988C59C5, 0x0A1C, 0x45B6, {0xA5, 0x55, 0x0C, 0x62, 0x27, 0x6E, 0x32, 0x7D} };
static e_guid_t smbserver_providerid = { 0xD48CE617, 0x33A2, 0x4BC3, {0xA5, 0xC7, 0x11, 0xAA, 0x4F, 0x29, 0x61, 0x9E} };

static dissector_handle_t http_dissector;
static e_guid_t wininet_providerid = { 0xA70FF94F, 0x570B, 0x4979, { 0xBA, 0x5C, 0xE5, 0x9C, 0x9F, 0xEA, 0xB6, 0x1B} };
static e_guid_t webio_providerid = { 0x50B3E73C, 0x9370, 0x461D, { 0xBB, 0x9F, 0x26, 0xF3, 0x2D, 0x68, 0x88, 0x7D} };

static dissector_handle_t ldap_dissector;
static e_guid_t ldapclient_providerid = { 0x099614A5, 0x5DD7, 0x4788, { 0x8B, 0xC9, 0xE2, 0x9F, 0x43, 0xDB, 0x28, 0xFC } };

static const value_string etw_edata_types[] = {
    { 0x0001, "RELATED_ACTIVITYID" },
    { 0x0002, "SID" },
    { 0x0003, "TS_ID" },
    { 0x0004, "INSTANCE_INFO" },
    { 0x0005, "STACK_TRACE32" },
    { 0x0006, "STACK_TRACE64" },
    { 0x0007, "PEBS_INDEX" },
    { 0x0008, "PMC_COUNTERS" },
    { 0x0009, "PSM_KEY" },
    { 0x000A, "EVENT_KEY" },
    { 0x000B, "EVENT_SCHEMA_TL" },
    { 0x000C, "PROV_TRAITS" },
    { 0x000D, "PROCESS_START_KEY" },
    { 0x000E, "CONTROL_GUID" },
    { 0x000F, "QPC_DELTA" },
    { 0x0010, "CONTAINER_ID" },
    { 0x0011, "STACK_KEY32" },
    { 0x0012, "STACK_KEY64" },
    { 0, NULL }
};

static const value_string etw_tlv_types[] = {
    { 0x0000, "USER_DATA" },
    { 0x0001, "MESSAGE" },
    { 0x0002, "PROVIDER_NAME" },
    { 0x0003, "SRC_ADDR" },
    { 0x0004, "DST_ADDR" },
    { 0x0005, "SESSION_ID" },
    { 0, NULL }
};

static const value_string etw_schematl_types[] = {
    { 0x01, "UNICODESTRING" },
    { 0x02, "ANSISTRING" },
    { 0x03, "INT8" },
    { 0x04, "UINT8" },
    { 0x05, "INT16" },
    { 0x06, "UINT16" },
    { 0x07, "INT32" },
    { 0x08, "UINT32" },
    { 0x09, "INT64" },
    { 0x0A, "UINT64" },
    { 0x0B, "FLOAT" },
    { 0x0C, "DOUBLE" },
    { 0x0D, "BOOL32" },
    { 0x0E, "BINARY" },
    { 0x0F, "GUID" },
    { 0x11, "FILETIME" },
    { 0x12, "SYSTEMTIME" },
    { 0x13, "SID" },
    { 0x14, "HEXINT32" },
    { 0x15, "HEXINT64" },
    { 0x16, "COUNTEDSTRING" },
    { 0x17, "COUNTEDANSISTRING" },
    { 0x18, "STRUCT" },
    { 0x19, "COUNTEDBINARY" },
    { 0, NULL }
};

static int* const etw_schematl_flags[] = {
    &hf_etw_edata_schematl_field_type,
    &hf_etw_edata_schematl_field_ccount,
    &hf_etw_edata_schematl_field_vcount,
    &hf_etw_edata_schematl_field_chain,
    NULL
};

#define ETW_HEADER_SIZE 0x5C

static int etw_counter;

typedef struct Property_Key_Value
{
    const unsigned char *key;
    const unsigned char *value;
} PROPERTY_KEY_VALUE;


/// <summary>
/// Function to format the properties into the eventlog message
/// </summary>
/// <param name="lpszMessage"></param>
/// <param name="propArray"></param>
/// <param name="dwPropertyCount"></param>
/// <param name="lpszOutBuffer"></param>
/// <param name="dwOutBufferCount"></param>
static int
format_message(char* lpszMessage, wmem_array_t* propArray, wmem_allocator_t* allocator, wmem_strbuf_t** out_buffer)
{
    uint16_t startLoc = 0;
    int percent_loc = 0;
    PROPERTY_KEY_VALUE key_value;
    *out_buffer = wmem_strbuf_new(allocator, NULL);

    for (int i = 0; lpszMessage[i] != '\0';)
    {
        if (lpszMessage[i] != '%')
        {
            i++;
            continue;
        }

        percent_loc = i;
        i++;

        if (g_ascii_isdigit(lpszMessage[i]))
        {
            uint16_t dwDigitalCount = 0;
            char smallBuffer[MAX_SMALL_BUFFER] = { 0 };
            while (g_ascii_isdigit(lpszMessage[i]))
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

            gint64 num = g_ascii_strtoll(smallBuffer, NULL, 10);
            /* We are not parsing this */
            if (num <= 0 || num >= G_MAXUSHORT || wmem_array_try_index(propArray, (unsigned int) num - 1, &key_value) != 0 || key_value.value == NULL)
            {
                continue;
            }

            if (lpszMessage[i] == '!' && lpszMessage[i + 1] == 'S' && lpszMessage[i + 2] == '!')
            {
                i += 3;
            }

            /* We have everything */
            lpszMessage[percent_loc] = '\0';
            wmem_strbuf_append(*out_buffer, lpszMessage + startLoc);
            wmem_strbuf_append(*out_buffer, (char*) key_value.value);
            startLoc = i;
            continue; // for
        }
    }
    wmem_strbuf_append(*out_buffer, lpszMessage + startLoc);

    return 0;
}

static int
dissect_properties(tvbuff_t* tvb, packet_info* pinfo, proto_tree* edata_tree, uint32_t offset, uint32_t count, wmem_allocator_t* allocator, wmem_array_t** propArray)
{
    uint32_t i;
    proto_item* ti;
    proto_tree* prop_tree;
    uint32_t item_offset = offset;
    uint16_t item_key_length = 0, item_value_length = 0;

    PROPERTY_KEY_VALUE prop;
    *propArray = wmem_array_new(allocator, sizeof(PROPERTY_KEY_VALUE));

    for (i = 0; i < count; i++)
    {
        ti = proto_tree_add_item(edata_tree, hf_etw_property, tvb, offset, 8, ENC_NA);
        prop_tree = proto_item_add_subtree(ti, ett_etw_property);

        proto_tree_add_item_ret_uint32(prop_tree, hf_etw_property_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &item_offset);
        offset += 4;
        proto_tree_add_item_ret_uint16(prop_tree, hf_etw_property_keylen, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_key_length);
        offset += 2;
        proto_tree_add_item_ret_uint16(prop_tree, hf_etw_property_valuelen, tvb, offset, 2, ENC_LITTLE_ENDIAN, &item_value_length);
        offset += 2;

        proto_tree_add_item_ret_string(prop_tree, hf_etw_property_key, tvb, item_offset, item_key_length, ENC_LITTLE_ENDIAN | ENC_UTF_16, pinfo->pool, &prop.key);
        proto_tree_add_item_ret_string(prop_tree, hf_etw_property_value, tvb, item_offset + item_key_length, item_value_length, ENC_LITTLE_ENDIAN | ENC_UTF_16, pinfo->pool, &prop.value);

        proto_item_set_text(prop_tree, "%s=%s", prop.key, prop.value);
        wmem_array_append(*propArray, &prop, 1);
    }
    offset = item_offset + item_key_length + item_value_length;

    return offset;
}

/// <summary>
/// Dissect the "Extended Data" blobs
/// </summary>
static int
dissect_edata_tlvs(tvbuff_t* tvb, packet_info* pinfo, proto_tree* edata_tree, uint32_t offset, uint16_t extended_data_count, bool* is_tl)
{
    uint16_t i;
    proto_item* ti;
    proto_tree* edata_item_tree, *edata_item_data_tree, *edata_schematl_schema;
    uint64_t edata_off64;
    uint32_t edata_off = offset, edata_off_int;
    uint16_t edata_sz = 0, edata_type = 0;

    for (i = 0; i < extended_data_count; i++)
    {
        ti = proto_tree_add_item(edata_tree, hf_etw_edata, tvb, offset, 16, ENC_NA);
        edata_item_tree = proto_item_add_subtree(ti, ett_etw_edata);

        proto_tree_add_item(edata_item_tree, hf_etw_edata_reserved1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item_ret_uint16(edata_item_tree, hf_etw_edata_exttype, tvb, offset, 2, ENC_LITTLE_ENDIAN, &edata_type);
        offset += 2;
        proto_tree_add_item(edata_item_tree, hf_etw_edata_linkage, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item_ret_uint16(edata_item_tree, hf_etw_edata_datasize, tvb, offset, 2, ENC_LITTLE_ENDIAN, &edata_sz);
        offset += 2;
        proto_tree_add_item_ret_uint64(edata_item_tree, hf_etw_edata_dataptr, tvb, offset, 8, ENC_LITTLE_ENDIAN, &edata_off64);
        offset += 8;

        if (edata_off64 > UINT32_MAX)
            continue; // should never happen, but to be safe

        edata_off = (uint32_t) edata_off64;

        ti = proto_tree_add_item(edata_item_tree, hf_etw_edata_data, tvb, edata_off, edata_sz, ENC_NA);
        edata_item_data_tree = proto_item_add_subtree(ti, ett_etw_edata_data);

        edata_off_int = edata_off;
        switch (edata_type)
        {
        case 0x0002:  // SID
            proto_item_set_text(ti, "Data (SID)");
            dissect_nt_sid(tvb, pinfo, edata_off_int, edata_item_data_tree, "SID", NULL, -1);

            break;
        case 0x0006:  // EVENT_STACK_TRACE64
            proto_item_set_text(ti, "Data (EVENT_STACK_TRACE64)");

            proto_tree_add_item(edata_item_data_tree, hf_etw_edata_stacktrace_matchid, tvb, edata_off_int, 8, ENC_LITTLE_ENDIAN);
            edata_off_int += 8;

            while (edata_off_int < edata_off + edata_sz)
            {
                proto_tree_add_item(edata_item_data_tree, hf_etw_edata_stacktrace_address, tvb, edata_off_int, 8, ENC_LITTLE_ENDIAN);
                edata_off_int += 8;
            }
            break;

        case 0x000B:  // EVENT_SCHEMA_TL
        {
            uint8_t schema_size = 0;
            int item_size = 0;

            *is_tl = true;
            proto_item_set_text(ti, "Data (EVENT_SCHEMA_TL)");

            proto_tree_add_item_ret_uint8(edata_item_data_tree, hf_etw_edata_schematl_size, tvb, edata_off_int, 1, ENC_LITTLE_ENDIAN, &schema_size);
            edata_off_int += 1;
            proto_tree_add_item(edata_item_data_tree, hf_etw_edata_schematl_reserved1, tvb, edata_off_int, 2, ENC_LITTLE_ENDIAN);
            edata_off_int += 2;
            proto_tree_add_item_ret_length(edata_item_data_tree, hf_etw_edata_schematl_name, tvb, edata_off_int, -1, ENC_LITTLE_ENDIAN, &item_size);
            edata_off_int += item_size;

            while (edata_off_int < edata_off + schema_size)
            {
                ti = proto_tree_add_item(edata_item_data_tree, hf_etw_edata_schematl_field, tvb, edata_off_int, 0, ENC_NA);
                edata_schematl_schema = proto_item_add_subtree(ti, ett_etw_edata_schematl_schema);

                proto_tree_add_item_ret_length(edata_schematl_schema, hf_etw_edata_schematl_field_key, tvb, edata_off_int, -1, ENC_LITTLE_ENDIAN, &item_size);
                edata_off_int += item_size;
                proto_tree_add_bitmask(edata_schematl_schema, tvb, edata_off_int, hf_etw_edata_schematl_field_flags,
                    ett_etw_schematl_flags, etw_schematl_flags, ENC_LITTLE_ENDIAN);
                edata_off_int += 1;
            }
            break;
        }
        case 0x000C:  // PROV_TRAITS
        {
            // https://learn.microsoft.com/en-us/windows/win32/etw/provider-traits
            uint16_t traits_size = 0;

            proto_item_set_text(ti, "Data (PROV_TRAITS)");

            proto_tree_add_item_ret_uint16(edata_item_data_tree, hf_etw_edata_traits_traitssize, tvb, edata_off_int, 2, ENC_LITTLE_ENDIAN, &traits_size);
            edata_off_int += 2;
            proto_tree_add_item(edata_item_data_tree, hf_etw_edata_traits_providername, tvb, edata_off_int, traits_size - 2, ENC_NA | ENC_UTF_8);
            /* edata_off_int += traits_size; */
            break;
        }

        default:
            break;
        }


    }

    return offset;
}

static int
dissect_etw(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    // We parse an "ETL->Wireshark encapsulation" format, which is defined in etl.c. This format
    // includes the actual ETW header, in addition to formatted structures which we added during
    // the dump process.

    proto_tree* etw_header, * etw_descriptor, * etw_buffer_context, * edata_tree, * etw_data, * etw_tlvs;
    proto_item* ti;
    tvbuff_t* subproto_tvb;
    char* provider_name;
    uint32_t message_offset = 0, message_length = 0, provider_name_offset = 0, provider_name_length = 0, user_data_offset = 0, user_data_length = 0;
    uint32_t properties_offset, properties_count;
    uint16_t extended_data_count, tlv_count;
    uint64_t flags;
    wmem_array_t* propArray = NULL;
    bool is_tl = false;
    e_guid_t provider_id;
    uint16_t event_id;
    nstime_t timestamp;
    uint64_t ts;
    unsigned offset = 0;
    static int* const etw_header_flags[] = {
        &hf_etw_header_flag_extended_info,
        &hf_etw_header_flag_private_session,
        &hf_etw_header_flag_string_only,
        &hf_etw_header_flag_trace_message,
        &hf_etw_header_flag_no_cputime,
        &hf_etw_header_flag_32_bit_header,
        &hf_etw_header_flag_64_bit_header,
        &hf_etw_header_flag_decode_guid,
        &hf_etw_header_flag_classic_header,
        &hf_etw_header_flag_processor_index,
        NULL
    };

    static int* const etw_event_property_opt[] = {
        &hf_etw_event_property_xml,
        &hf_etw_event_property_forwarded_xml,
        &hf_etw_event_property_legacy_eventlog,
        &hf_etw_event_property_legacy_reloggable,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_DEF_SRC, "windows");
    col_set_str(pinfo->cinfo, COL_DEF_DST, "windows");

    // Header

    etw_header = proto_tree_add_subtree(tree, tvb, 0, ETW_HEADER_SIZE, ett_etw_header, NULL, "ETW Header");
    proto_tree_add_item(etw_header, hf_etw_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(etw_header, hf_etw_header_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask_ret_uint64(etw_header, tvb, offset, hf_etw_flags,
        ett_etw_header_flags, etw_header_flags, ENC_LITTLE_ENDIAN, &flags);
    offset += 2;
    proto_tree_add_bitmask(etw_header, tvb, offset, hf_etw_event_property,
        ett_etw_event_property_types, etw_event_property_opt, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(etw_header, hf_etw_thread_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(etw_header, hf_etw_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    ts = tvb_get_letoh64(tvb, offset) - INT64_C(0x019DB1DED53E8000);
    timestamp.secs = (unsigned)(ts / 10000000);
    timestamp.nsecs = (unsigned)((ts % 10000000) * 100);
    proto_tree_add_time(etw_header, hf_etw_time_stamp, tvb, offset, 8, &timestamp);
    offset += 8;
    tvb_get_letohguid(tvb, offset, &provider_id);
    proto_tree_add_item(etw_header, hf_etw_provider_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
    offset += 16;

    etw_descriptor = proto_tree_add_subtree(etw_header, tvb, 40, 16, ett_etw_descriptor, NULL, "Descriptor");
    proto_tree_add_item_ret_uint16(etw_descriptor, hf_etw_descriptor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &event_id);
    offset += 2;
    proto_tree_add_item(etw_descriptor, hf_etw_descriptor_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(etw_descriptor, hf_etw_descriptor_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(etw_descriptor, hf_etw_descriptor_level, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(etw_descriptor, hf_etw_descriptor_opcode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(etw_descriptor, hf_etw_descriptor_task, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(etw_descriptor, hf_etw_descriptor_keywords, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(etw_header, hf_etw_processor_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(etw_header, hf_etw_activity_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
    offset += 16;

    etw_buffer_context = proto_tree_add_subtree(etw_header, tvb, 80, 4, ett_etw_descriptor, NULL, "Buffer Context");
    proto_tree_add_item(etw_buffer_context, hf_etw_buffer_context_processor_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(etw_buffer_context, hf_etw_buffer_context_alignment, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(etw_buffer_context, hf_etw_buffer_context_logger_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint16(etw_header, hf_etw_extended_data_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &extended_data_count);
    offset += 2;
    proto_tree_add_item_ret_uint16(etw_header, hf_etw_tlv_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &tlv_count);
    offset += 2;
    proto_tree_add_item_ret_uint(etw_header, hf_etw_properties_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &properties_count);
    offset += 4;

    // Extended data

    ti = proto_tree_add_item(etw_header, hf_etw_extended_data, tvb, offset, extended_data_count * 16, ENC_NA);  // sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM) = 16
    edata_tree = proto_item_add_subtree(ti, ett_etw_extended_data);
    offset = dissect_edata_tlvs(tvb, pinfo, edata_tree, offset, extended_data_count, &is_tl);

    // Expert info

    if (flags & 0x0008)  // EVENT_HEADER_FLAG_TRACE_MESSAGE
    {
        // WPP
        ti = proto_tree_add_string(etw_header, hf_etw_type, tvb, 0, -1, "WPP");
    }
    else if (flags & 0x0100)  // EVENT_HEADER_FLAG_CLASSIC_HEADER
    {
        // MOF (CLASSIC)
        ti = proto_tree_add_string(etw_header, hf_etw_type, tvb, 0, -1, "MOF (classic)");
    }
    else if (is_tl)
    {
        // TRACELOGGING
        ti = proto_tree_add_string(etw_header, hf_etw_type, tvb, 0, -1, "TraceLogging");
    }
    else
    {
        // MANIFEST
        ti = proto_tree_add_string(etw_header, hf_etw_type, tvb, 0, -1, "Manifest-based");
    }
    proto_item_set_generated(ti);

    // Now is the bunch of TLVs that include formatted stuff
    if (tlv_count > 0)
    {
        etw_tlvs = proto_tree_add_subtree(etw_header, tvb, offset, tlv_count * 12, ett_etw_tlvs, NULL, "Extra Information");

        for (uint16_t i = 0; i < tlv_count; i++)
        {
            uint32_t tlv_type, tlv_offset, tlv_length;

            proto_tree* etw_tlv = proto_tree_add_subtree(etw_tlvs, tvb, offset, 12, ett_etw_tlv, NULL, "Extra Information Item");

            proto_tree_add_item_ret_uint(etw_tlv, hf_etw_tlv_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, &tlv_type);
            offset += 4;
            proto_tree_add_item_ret_uint(etw_tlv, hf_etw_tlv_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &tlv_offset);
            offset += 4;
            proto_tree_add_item_ret_uint(etw_tlv, hf_etw_tlv_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &tlv_length);
            offset += 4;

            if (tlv_type == 0)
            {
                // TLV_USER_DATA
                proto_item_set_text(etw_tlv, "Extra Information Item (USER_DATA)");
                user_data_offset = tlv_offset;
                user_data_length = tlv_length;
            }
            else if (tlv_type == 1)
            {
                // TLV_MESSAGE
                proto_item_set_text(etw_tlv, "Extra Information Item (MESSAGE)");
                message_offset = tlv_offset;
                message_length = tlv_length;
            }
            else if (tlv_type == 2)
            {
                // TLV_PROVIDER_NAME
                proto_item_set_text(etw_tlv, "Extra Information Item (PROVIDER_NAME)");
                provider_name_offset = tlv_offset;
                provider_name_length = tlv_length;
            }
            else if (tlv_type == 3)
            {
                // TLV_SRC_ADDR
                char* src_addr;
                proto_item_set_text(etw_tlv, "Extra Information Item (SRC_ADDR)");
                proto_tree_add_item_ret_string(etw_tlv, hf_etw_src, tvb, tlv_offset, tlv_length, ENC_NA | ENC_ASCII, pinfo->pool, (const uint8_t**)&src_addr);
                col_set_str(pinfo->cinfo, COL_DEF_SRC, src_addr);
            }
            else if (tlv_type == 4)
            {
                // TLV_DST_ADDR
                char* dst_addr;
                proto_item_set_text(etw_tlv, "Extra Information Item (DST_ADDR)");
                proto_tree_add_item_ret_string(etw_tlv, hf_etw_dst, tvb, tlv_offset, tlv_length, ENC_NA | ENC_ASCII, pinfo->pool, (const uint8_t**)&dst_addr);
                col_set_str(pinfo->cinfo, COL_DEF_DST, dst_addr);
            }
            else if (tlv_type == 5)
            {
                // TLV_SESSION_ID
                uint64_t session_id;
                proto_item_set_text(etw_tlv, "Extra Information Item (SESSION_ID)");
                proto_tree_add_item_ret_uint64(etw_tlv, hf_etw_sessid, tvb, tlv_offset, tlv_length, ENC_LITTLE_ENDIAN, &session_id);

                pinfo->use_conv_addr_port_endpoints = false;
                conversation_set_elements_by_id(pinfo, CONVERSATION_TCP, session_id & 0xFFFFFFFF);
            }
        }
    }

    // Now it's the properties (we parse them later)

    properties_offset = offset;

    // We're done with the header. Starting adding "Data" elements.

    if (provider_name_length) {
        // Specifically for the provider name, we keep it in the "Data" header to handle the MBIM case
        proto_tree_add_item_ret_string(etw_header, hf_etw_provider_name, tvb, provider_name_offset, provider_name_length, ENC_LITTLE_ENDIAN | ENC_UTF_16, pinfo->pool, (const uint8_t**)&provider_name);
    }

    // Depending on the provider ID, we might have special dissections available

    if (user_data_length && memcmp(&mbim_net_providerid, &provider_id, sizeof(e_guid_t)) == 0)
    {
        // MBIM

        uint32_t pack_flags;

        if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_uint32_option_value(pinfo->rec->block, OPT_PKT_FLAGS, &pack_flags)) {
            switch (PACK_FLAGS_DIRECTION(pack_flags)) {
                case PACK_FLAGS_DIRECTION_INBOUND:
                    col_set_str(pinfo->cinfo, COL_DEF_SRC, "device");
                    col_set_str(pinfo->cinfo, COL_DEF_DST, "host");
                    break;
                case PACK_FLAGS_DIRECTION_OUTBOUND:
                    col_set_str(pinfo->cinfo, COL_DEF_SRC, "host");
                    col_set_str(pinfo->cinfo, COL_DEF_DST, "device");
                    break;
            }
        }
        subproto_tvb = tvb_new_subset_length(tvb, user_data_offset, user_data_length);
        call_dissector_only(mbim_dissector, subproto_tvb, pinfo, tree, data);
    }
    else if (user_data_length &&
        (memcmp(&smbclient_providerid, &provider_id, sizeof(e_guid_t)) == 0 ||
            memcmp(&smbserver_providerid, &provider_id, sizeof(e_guid_t)) == 0) &&
        (event_id == 40000 || event_id == 2000))
    {
        // SMB "Packet" event

        subproto_tvb = tvb_new_subset_length(tvb, user_data_offset, user_data_length);
        call_dissector_only(nbss_dissector, subproto_tvb, pinfo, tree, data);
    }
    else if (user_data_length &&
        memcmp(&wininet_providerid, &provider_id, sizeof(e_guid_t)) == 0 &&
        (event_id == 2001 || event_id == 2002 || event_id == 2003 || event_id == 2004))
    {
        // WinInet "HTTP" event

        // Emulate direction
        if (event_id == 2001 || event_id == 2002)
        {
            pinfo->srcport = 50000;
            pinfo->destport = 80;
        }
        else
        {
            pinfo->srcport = 80;
            pinfo->destport = 50000;
        }

        // TODO: figure out how to make reassembly work :(
        subproto_tvb = tvb_new_subset_length(tvb, user_data_offset, user_data_length);
        call_dissector_only(http_dissector, subproto_tvb, pinfo, tree, NULL);
    }
    else if (user_data_length &&
        memcmp(&webio_providerid, &provider_id, sizeof(e_guid_t)) == 0 &&
        (event_id == 100 || event_id == 101 || event_id == 111 || event_id == 129))
    {
        // WebIO (WinHTTP) "HTTP" event

        // TODO: figure out how to make reassembly work :(
        subproto_tvb = tvb_new_subset_length(tvb, user_data_offset, user_data_length);
        call_dissector_only(http_dissector, subproto_tvb, pinfo, tree, NULL);
    }
    else if (user_data_length &&
        memcmp(&ldapclient_providerid, &provider_id, sizeof(e_guid_t)) == 0 &&
        (event_id == 12 || event_id == 17))
    {
        // LDAP events

        // TODO: figure out how to make reassembly work :(
        subproto_tvb = tvb_new_subset_length(tvb, user_data_offset, user_data_length);
        call_dissector_only(ldap_dissector, subproto_tvb, pinfo, tree, NULL);
    }
    else
    {
        // Other provider: add "Data" header

        etw_data = proto_tree_add_subtree(tree, tvb, offset, 0, ett_etw_data, NULL, "ETW Data");
        if (properties_count) {
            /* offset =*/ dissect_properties(tvb, pinfo, etw_data, properties_offset, properties_count, pinfo->pool, &propArray);
        }
        if (user_data_length) {
            proto_tree_add_item(etw_data, hf_etw_user_data, tvb, user_data_offset, user_data_length, ENC_NA);
        }

        if (provider_name_length) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, provider_name);
        }

        if (message_length) {
            char* message;

            proto_tree_add_item_ret_string(etw_data, hf_etw_message, tvb, message_offset, message_length, ENC_LITTLE_ENDIAN | ENC_UTF_16, pinfo->pool, (const uint8_t**)& message);
            if (propArray != NULL)
            {
                wmem_strbuf_t* out_buffer;
                format_message(message, propArray, pinfo->pool, &out_buffer);
                message = out_buffer->str;
                ti = proto_tree_add_string(etw_data, hf_etw_message_formatted, tvb, 0, -1, message);
                proto_item_set_generated(ti);
            }
            col_set_str(pinfo->cinfo, COL_INFO, message);
        }
        else
        {
            col_set_str(pinfo->cinfo, COL_INFO, guids_resolve_guid_to_str(&provider_id, pinfo->pool));
        }
    }

    etw_counter += 1;
    return tvb_captured_length(tvb);
}

void
proto_register_etw(void)
{
    static hf_register_info hf[] = {
        { &hf_etw_size,
            { "Size", "etw.size",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_header_type,
            { "Header Type", "etw.header_type",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_flags,
            { "Flags", "etw.flags",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_header_flag_extended_info,
            { "Extended Info", "etw.header.flag.extended_info",
               FT_UINT32, BASE_DEC, NULL, 0x0001,
               NULL, HFILL }
        },
        { &hf_etw_header_flag_private_session,
            { "Private Session", "etw.header.flag.private_session",
               FT_UINT32, BASE_DEC, NULL, 0x0002,
               NULL, HFILL }
        },
        { &hf_etw_header_flag_string_only,
            { "String Only", "etw.header.flag.string_only",
               FT_UINT32, BASE_DEC, NULL, 0x0004,
               NULL, HFILL }
        },
        { &hf_etw_header_flag_trace_message,
            { "Trace Message", "etw.header.flag.trace_message",
               FT_UINT32, BASE_DEC, NULL, 0x0008,
               NULL, HFILL }
        },
        { &hf_etw_header_flag_no_cputime,
            { "No CPU time", "etw.header.flag.no_cputime",
               FT_UINT32, BASE_DEC, NULL, 0x0010,
               NULL, HFILL }
        },
        { &hf_etw_header_flag_32_bit_header,
            { "32-bit Header", "etw.header.flag.32_bit_header",
               FT_UINT32, BASE_DEC, NULL, 0x0020,
               NULL, HFILL }
        },
        { &hf_etw_header_flag_64_bit_header,
            { "64-bit Header", "etw.header.flag.64_bit_header",
               FT_UINT32, BASE_DEC, NULL, 0x0040,
               NULL, HFILL }
        },
        { &hf_etw_header_flag_decode_guid,
            { "Decode GUID", "etw.header.flag.decode_guid",
               FT_UINT32, BASE_DEC, NULL, 0x0080,
               NULL, HFILL }
        },
        { &hf_etw_header_flag_classic_header,
            { "Classic Header", "etw.header.flag.classic_header",
               FT_UINT32, BASE_DEC, NULL, 0x0100,
               NULL, HFILL }
        },
        { &hf_etw_header_flag_processor_index,
            { "Processor Index", "etw.header.flag.processor_index",
               FT_UINT32, BASE_DEC, NULL, 0x0200,
               NULL, HFILL }
        },
        { &hf_etw_event_property,
            { "Event Property", "etw.event_property",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_event_property_xml,
            { "XML", "etw.property.xml",
               FT_UINT32, BASE_DEC, NULL, 0x0001,
               NULL, HFILL }
        },
        { &hf_etw_event_property_forwarded_xml,
            { "Forwarded XML", "etw.property.forwarded_xml",
               FT_UINT32, BASE_DEC, NULL, 0x0002,
               NULL, HFILL }
        },
        { &hf_etw_event_property_legacy_eventlog,
            { "Legacy Event Log", "etw.property.legacy_event",
               FT_UINT32, BASE_DEC, NULL, 0x0004,
               NULL, HFILL }
        },
        { &hf_etw_event_property_legacy_reloggable,
            { "Legacy Reloggable", "etw.property.legacy_reloggable",
               FT_UINT32, BASE_DEC, NULL, 0x0008,
               NULL, HFILL }
        },
        { &hf_etw_thread_id,
            { "Thread ID", "etw.thread_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_process_id,
            { "Process ID", "etw.process_id",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_time_stamp,
            { "Time Stamp", "etw.time_stamp",
               FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_provider_id,
            { "Provider ID", "etw.provider_id",
               FT_GUID, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_buffer_context_processor_number,
            { "Processor Number", "etw.buffer_context.processor_number",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_buffer_context_alignment,
            { "Alignment", "etw.buffer_context.alignment",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_buffer_context_logger_id,
            { "ID", "etw.buffer_context.logger_id",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_tlv_count,
            { "Extra Information Count", "etw.tlv_count",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_tlv_offset,
            { "Offset", "etw.tlv.offset",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_tlv_length,
            { "Length", "etw.tlv.length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_tlv_type,
            { "Type", "etw.tlv.type",
               FT_UINT32, BASE_DEC, VALS(etw_tlv_types), 0,
              NULL, HFILL }
        },
        { &hf_etw_src,
            { "Source Address", "etw.src",
               FT_STRINGZ, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_dst,
            { "Destination Address", "etw.dst",
               FT_STRINGZ, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_sessid,
            { "Session Id", "etw.sessid",
               FT_UINT64, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_properties_count,
            { "Properties count", "etw.props_count",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_provider_name,
            { "Provider Name", "etw.provider_name",
               FT_STRINGZ, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_message,
            { "Event Message", "etw.message",
               FT_STRINGZ, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_extended_data_count,
            { "Extended Data Count", "etw.extended_data_count",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_extended_data,
            { "Extended Data", "etw.extended_data",
               FT_NONE, BASE_NONE, NULL, 0,
               NULL, HFILL }
        },
        { &hf_etw_edata,
            { "Extended Data Item", "etw.edata",
               FT_NONE, BASE_NONE, NULL, 0,
               NULL, HFILL }
        },
        { &hf_etw_edata_reserved1,
            { "Reserved1", "etw.edata.reserved1",
                FT_UINT16, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_exttype,
            { "ExtType", "etw.edata.exttype",
                FT_UINT16, BASE_DEC, VALS(etw_edata_types), 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_linkage,
            { "Linkage", "etw.edata.linkage",
                FT_UINT16, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_datasize,
            { "DataSize", "etw.edata.datasize",
                FT_UINT16, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_dataptr,
            { "DataPtr", "etw.edata.dataptr",
                FT_UINT64, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_data,
            { "Data", "etw.edata.data",
               FT_NONE, BASE_NONE, NULL, 0,
               NULL, HFILL }
        },
        { &hf_etw_edata_stacktrace_matchid,
            { "MatchId", "etw.edata.stacktrace.matchid",
                FT_UINT64, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_stacktrace_address,
            { "Address", "etw.edata.stacktrace.address",
                FT_UINT64, BASE_HEX, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_schematl_size,
            { "Size", "etw.edata.schematl.size",
                FT_UINT8, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_schematl_reserved1,
            { "Unknown", "etw.edata.schematl.reserved1",
                FT_UINT8, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_schematl_name,
            { "Event Name", "etw.edata.schematl.name",
                FT_STRINGZ, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_schematl_field,
            { "Schema Field", "etw.edata.schematl.field",
                FT_NONE, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_schematl_field_key,
            { "Key", "etw.edata.schematl.field.key",
                FT_STRINGZ, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_schematl_field_flags,
            { "Flags", "etw.edata.schematl.field.flags",
                FT_UINT8, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_schematl_field_type,
            { "Type", "etw.edata.schematl.field.type",
                FT_UINT8, BASE_DEC, VALS(etw_schematl_types), 0x1F,
                NULL, HFILL }
        },
        { &hf_etw_edata_schematl_field_ccount,
            { "Constant array count", "etw.edata.schematl.field.ccount",
                FT_UINT8, BASE_DEC, NULL, 0x20,
                NULL, HFILL }
        },
        { &hf_etw_edata_schematl_field_vcount,
            { "Variable array count", "etw.edata.schematl.field.vcount",
                FT_UINT8, BASE_DEC, NULL, 0x40,
                NULL, HFILL }
        },
        { &hf_etw_edata_schematl_field_chain,
            { "Chain", "etw.edata.schematl.field.chain",
                FT_UINT8, BASE_DEC, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_etw_edata_traits_traitssize,
            { "Trait size", "etw.edata.traits.traitssize",
                FT_UINT16, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_edata_traits_providername,
            { "Trait provider name", "etw.edata.traits.providername",
                FT_STRINGZ, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_property,
            { "Property", "etw.prop",
                FT_NONE, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_property_offset,
            { "Offset", "etw.prop.offset",
                FT_UINT32, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_property_keylen,
            { "Key Length", "etw.prop.keylen",
                FT_UINT16, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_property_valuelen,
            { "Value Length", "etw.prop.valuelen",
                FT_UINT16, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_property_key,
            { "Key", "etw.prop.key",
                FT_STRINGZ, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_property_value,
            { "Value", "etw.prop.value",
                FT_STRINGZ, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_etw_user_data,
            { "Raw User Data", "etw.user_data",
               FT_NONE, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_descriptor_id,
            { "ID", "etw.descriptor.id",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_descriptor_version,
            { "Version", "etw.descriptor.version",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_descriptor_channel,
            { "Channel", "etw.descriptor.channel",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_descriptor_level,
            { "Level", "etw.descriptor.level",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_descriptor_opcode,
            { "Opcode", "etw.descriptor.opcode",
               FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_descriptor_task,
            { "Task", "etw.descriptor.task",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_descriptor_keywords,
            { "Keywords", "etw.descriptor.keywords",
               FT_UINT64, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_processor_time,
            { "Processor Time", "etw.processor_time",
               FT_UINT64, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_activity_id,
            { "Activity ID", "etw.activity_id",
               FT_GUID, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        // Generated fields
        { &hf_etw_type,
            { "Event Type", "etw.type",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_message_formatted,
            { "Message (formatted)", "etw.message_formatted",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_etw_header,
        &ett_etw_data,
        &ett_etw_descriptor,
        &ett_etw_buffer_context,
        &ett_etw_extended_data,
        &ett_etw_property,
        &ett_etw_edata,
        &ett_etw_edata_data,
        &ett_etw_edata_schematl_schema,
        &ett_etw_schematl_flags,
        &ett_etw_header_flags,
        &ett_etw_event_property_types,
        &ett_etw_tlvs,
        &ett_etw_tlv,
    };

    proto_etw = proto_register_protocol("Event Tracing for Windows", "ETW", "etw");
    proto_register_field_array(proto_etw, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    etw_handle = register_dissector("etw", dissect_etw, proto_etw);
}

void
proto_reg_handoff_etw(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_ETW, etw_handle);

    mbim_dissector = find_dissector("mbim.control");
    nbss_dissector = find_dissector("nbss");
    http_dissector = find_dissector("http-over-tcp");
    ldap_dissector = find_dissector("ldap");
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
