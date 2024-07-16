/* packet-etw.c
 * Routines for ETW Dissection
 *
 * Copyright 2020, Odysseus Yang
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

#include <epan/packet.h>
#include <wiretap/wtap.h>

void proto_register_etw(void);
void proto_reg_handoff_etw(void);

static dissector_handle_t etw_handle;

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
static int hf_etw_message_length;
static int hf_etw_provider_name_length;
static int hf_etw_provider_name;
static int hf_etw_message;
static int hf_etw_user_data_length;
static int hf_etw_descriptor_id;
static int hf_etw_descriptor_version;
static int hf_etw_descriptor_channel;
static int hf_etw_descriptor_level;
static int hf_etw_descriptor_opcode;
static int hf_etw_descriptor_task;
static int hf_etw_descriptor_keywords;
static int hf_etw_processor_time;
static int hf_etw_activity_id;

static int ett_etw_header;
static int ett_etw_descriptor;
static int ett_etw_buffer_context;
static int ett_etw_header_flags;
static int ett_etw_event_property_types;

static dissector_handle_t mbim_dissector;

static e_guid_t mbim_net_providerid = { 0xA42FE227, 0xA7BF, 0x4483, {0xA5, 0x02, 0x6B, 0xCD, 0xA4, 0x28, 0xCD, 0x96} };

#define ROUND_UP_COUNT(Count,Pow2) \
        ( ((Count)+(Pow2)-1) & (~(((int)(Pow2))-1)) )
#define ETW_HEADER_SIZE 0x60

static int etw_counter;

static int
dissect_etw(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    proto_tree* etw_header, * etw_descriptor, * etw_buffer_context;
    tvbuff_t* mbim_tvb;
    uint32_t message_offset, message_length, provider_name_offset, provider_name_length, user_data_offset, user_data_length;
    e_guid_t provider_id;
    int offset = 0;
    static int * const etw_header_flags[] = {
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

    static int * const etw_event_property_opt[] = {
        &hf_etw_event_property_xml,
        &hf_etw_event_property_forwarded_xml,
        &hf_etw_event_property_legacy_eventlog,
        &hf_etw_event_property_legacy_reloggable,
        NULL
    };

    etw_header = proto_tree_add_subtree(tree, tvb, 0, ETW_HEADER_SIZE, ett_etw_header, NULL, "ETW Header");
    proto_tree_add_item(etw_header, hf_etw_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(etw_header, hf_etw_header_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(etw_header, tvb, offset, hf_etw_flags,
			ett_etw_header_flags, etw_header_flags, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(etw_header, tvb, offset, hf_etw_event_property,
            ett_etw_event_property_types, etw_event_property_opt, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(etw_header, hf_etw_thread_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(etw_header, hf_etw_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(etw_header, hf_etw_time_stamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    tvb_get_letohguid(tvb, offset, &provider_id);
    proto_tree_add_item(etw_header, hf_etw_provider_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
    offset += 16;

    etw_descriptor = proto_tree_add_subtree(etw_header, tvb, 40, 16, ett_etw_descriptor, NULL, "Descriptor");
    proto_tree_add_item(etw_descriptor, hf_etw_descriptor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item_ret_uint(etw_header, hf_etw_user_data_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &user_data_length);
    offset += 4;
    proto_tree_add_item_ret_uint(etw_header, hf_etw_message_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &message_length);
    offset += 4;
    proto_tree_add_item_ret_uint(etw_header, hf_etw_provider_name_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &provider_name_length);
    offset += 4;
    user_data_offset = offset;
    message_offset = user_data_offset + ROUND_UP_COUNT(user_data_length, sizeof(int32_t));
    if (message_length) {
        proto_tree_add_item(etw_header, hf_etw_message, tvb, message_offset, message_length, ENC_LITTLE_ENDIAN | ENC_UTF_16);
    }
    provider_name_offset = message_offset + ROUND_UP_COUNT(message_length, sizeof(int32_t));
    if (provider_name_length) {
        proto_tree_add_item(etw_header, hf_etw_provider_name, tvb, provider_name_offset, provider_name_length, ENC_LITTLE_ENDIAN | ENC_UTF_16);
    }

    col_set_str(pinfo->cinfo, COL_DEF_SRC, "windows");
    col_set_str(pinfo->cinfo, COL_DEF_DST, "windows");
    if (memcmp(&mbim_net_providerid, &provider_id, sizeof(e_guid_t)) == 0) {
        uint32_t pack_flags;

        if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_uint32_option_value(pinfo->rec->block, OPT_PKT_FLAGS, &pack_flags)) {
            switch(PACK_FLAGS_DIRECTION(pack_flags)) {
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
        mbim_tvb = tvb_new_subset_remaining(tvb, user_data_offset);
        call_dissector_only(mbim_dissector, mbim_tvb, pinfo, tree, data);
    }
    else if (message_length){
        char* message = (char*)tvb_get_string_enc(pinfo->pool, tvb, message_offset, message_length, ENC_LITTLE_ENDIAN | ENC_UTF_16);
        col_set_str(pinfo->cinfo, COL_INFO, message);
        if (provider_name_offset) {
            char* provider_name = (char*)tvb_get_string_enc(pinfo->pool, tvb, provider_name_offset, provider_name_length, ENC_LITTLE_ENDIAN | ENC_UTF_16);
            col_set_str(pinfo->cinfo, COL_PROTOCOL, provider_name);
        }
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, guids_resolve_guid_to_str(&provider_id, pinfo->pool));
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
               FT_UINT64, BASE_DEC, NULL, 0,
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
        { &hf_etw_message_length,
            { "Message Length", "etw.message_length",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_etw_provider_name_length,
            { "Provider Name Length", "etw.provider_name_length",
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
        { &hf_etw_user_data_length,
            { "User Data Length", "etw.user_data_length",
               FT_UINT32, BASE_DEC, NULL, 0,
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
               FT_UINT64, BASE_DEC, NULL, 0,
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
        }
    };

    static int *ett[] = {
        &ett_etw_header,
        &ett_etw_descriptor,
        &ett_etw_buffer_context,
        &ett_etw_header_flags,
        &ett_etw_event_property_types
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
