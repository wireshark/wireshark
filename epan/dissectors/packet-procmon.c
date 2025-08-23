/* packet-procmon.c
 * Routines for MS Procmon dissection
 *
 * Used a lot of information from https://github.com/eronnen/procmon-parser
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include <wiretap/wtap.h>
#include "packet-ipv6.h"

#define PNAME  "MS Procmon Event"
#define PSNAME "MS Procmon"
#define PFNAME "procmon"

void proto_reg_handoff_procmon(void);
void proto_register_procmon(void);

/* Initialize the protocol and registered fields */
static int proto_procmon;

static int hf_procmon_process_index;
static int hf_procmon_thread_id;
static int hf_procmon_event_class;
static int hf_procmon_operation_type;
static int hf_procmon_duration;
static int hf_procmon_timestamp;
static int hf_procmon_event_result;
static int hf_procmon_stack_trace_depth;
static int hf_procmon_details_size;
static int hf_procmon_extra_details_offset;
static int hf_procmon_stack_trace_address;
static int hf_procmon_detail_data;
static int hf_procmon_extra_detail_data;
static int hf_procmon_process_operation;
static int hf_procmon_process_pid;
static int hf_procmon_process_path;
static int hf_procmon_process_path_size;
static int hf_procmon_process_path_is_ascii;
static int hf_procmon_process_path_char_count;
static int hf_procmon_process_commandline;
static int hf_procmon_process_commandline_size;
static int hf_procmon_process_commandline_is_ascii;
static int hf_procmon_process_commandline_char_count;
static int hf_procmon_process_thread_id;
static int hf_procmon_process_exit_status;
static int hf_procmon_process_kernel_time;
static int hf_procmon_process_user_time;
static int hf_procmon_process_working_set;
static int hf_procmon_process_peak_working_set;
static int hf_procmon_process_private_bytes;
static int hf_procmon_process_peak_private_bytes;
static int hf_procmon_process_image_base;
static int hf_procmon_process_image_size;
static int hf_procmon_process_parent_pid;
static int hf_procmon_process_curdir;
static int hf_procmon_process_curdir_size;
static int hf_procmon_process_curdir_is_ascii;
static int hf_procmon_process_curdir_char_count;
static int hf_procmon_process_environment;
static int hf_procmon_process_environment_char_count;
static int hf_procmon_registry_operation;
static int hf_procmon_registry_desired_access;
static int hf_procmon_registry_granted_access;
static int hf_procmon_registry_disposition;
static int hf_procmon_registry_key;
static int hf_procmon_registry_key_size;
static int hf_procmon_registry_key_is_ascii;
static int hf_procmon_registry_key_char_count;
static int hf_procmon_registry_new_key;
static int hf_procmon_registry_new_key_size;
static int hf_procmon_registry_new_key_is_ascii;
static int hf_procmon_registry_new_key_char_count;
static int hf_procmon_registry_value;
static int hf_procmon_registry_value_size;
static int hf_procmon_registry_value_is_ascii;
static int hf_procmon_registry_value_char_count;
static int hf_procmon_registry_length;
static int hf_procmon_registry_key_information_class;
static int hf_procmon_registry_value_information_class;
static int hf_procmon_registry_key_set_information_class;
static int hf_procmon_registry_index;
static int hf_procmon_registry_type;
static int hf_procmon_registry_data_length;
static int hf_procmon_registry_key_name_size;
static int hf_procmon_registry_key_name;
static int hf_procmon_registry_key_handle_tags;
static int hf_procmon_registry_key_flags;
static int hf_procmon_registry_key_last_write_time;
static int hf_procmon_registry_key_title_index;
static int hf_procmon_registry_key_subkeys;
static int hf_procmon_registry_key_max_name_len;
static int hf_procmon_registry_key_values;
static int hf_procmon_registry_key_max_value_name_len;
static int hf_procmon_registry_key_max_value_data_len;
static int hf_procmon_registry_key_class_offset;
static int hf_procmon_registry_key_class_length;
static int hf_procmon_registry_key_max_class_len;
static int hf_procmon_registry_value_reg_type;
static int hf_procmon_registry_value_offset_to_data;
static int hf_procmon_registry_value_length;
static int hf_procmon_registry_value_name_size;
static int hf_procmon_registry_value_name;
static int hf_procmon_registry_value_dword;
static int hf_procmon_registry_value_qword;
static int hf_procmon_registry_value_sz;
static int hf_procmon_registry_value_binary;
static int hf_procmon_registry_value_multi_sz;
static int hf_procmon_registry_key_set_information_write_time;
static int hf_procmon_registry_key_set_information_wow64_flags;
static int hf_procmon_registry_key_set_information_handle_tags;
static int hf_procmon_filesystem_operation;
static int hf_procmon_filesystem_suboperation;
static int hf_procmon_filesystem_padding;
static int hf_procmon_filesystem_details;
static int hf_procmon_filesystem_path;
static int hf_procmon_filesystem_path_size;
static int hf_procmon_filesystem_path_is_ascii;
static int hf_procmon_filesystem_path_char_count;
static int hf_procmon_filesystem_create_file_access_mask;
static int hf_procmon_filesystem_create_file_impersonating_sid_length;
static int hf_procmon_filesystem_create_file_impersonating;
static int hf_procmon_filesystem_create_file_disposition;
static int hf_procmon_filesystem_create_file_options;
static int hf_procmon_filesystem_create_file_attributes;
static int hf_procmon_filesystem_create_file_share_mode;
static int hf_procmon_filesystem_create_file_allocation;
static int hf_procmon_filesystem_create_file_sid_revision;
static int hf_procmon_filesystem_create_file_sid_count;
static int hf_procmon_filesystem_create_file_sid_authority;
static int hf_procmon_filesystem_create_file_sid_value;
static int hf_procmon_filesystem_create_file_open_result;
static int hf_procmon_filesystem_readwrite_file_io_flags;
static int hf_procmon_filesystem_readwrite_file_priority;
static int hf_procmon_filesystem_readwrite_file_length;
static int hf_procmon_filesystem_readwrite_file_offset;
static int hf_procmon_filesystem_readwrite_file_result_length;
static int hf_procmon_filesystem_ioctl_write_length;
static int hf_procmon_filesystem_ioctl_read_length;
static int hf_procmon_filesystem_ioctl_ioctl;
static int hf_procmon_filesystem_ioctl_offset;
static int hf_procmon_filesystem_ioctl_length;
static int hf_procmon_filesystem_create_file_mapping_sync_type;
static int hf_procmon_filesystem_create_file_mapping_page_protection;
static int hf_procmon_filesystem_directory;
static int hf_procmon_filesystem_directory_size;
static int hf_procmon_filesystem_directory_is_ascii;
static int hf_procmon_filesystem_directory_char_count;
static int hf_procmon_filesystem_directory_control_file_information_class;
static int hf_procmon_filesystem_directory_control_notify_change_flags;
static int hf_procmon_filesystem_set_info_file_disposition_delete;
static int hf_procmon_filesystem_directory_control_query_next_entry_offset;
static int hf_procmon_filesystem_directory_control_query_file_index;
static int hf_procmon_filesystem_directory_control_query_name_length;
static int hf_procmon_filesystem_directory_control_query_name;
static int hf_procmon_filesystem_directory_control_query_creation_time;
static int hf_procmon_filesystem_directory_control_query_last_access_time;
static int hf_procmon_filesystem_directory_control_query_last_write_time;
static int hf_procmon_filesystem_directory_control_query_change_time;
static int hf_procmon_filesystem_directory_control_query_end_of_file;
static int hf_procmon_filesystem_directory_control_query_allocation_size;
static int hf_procmon_filesystem_directory_control_query_file_attributes;
static int hf_procmon_filesystem_directory_control_query_file_ea_size;
static int hf_procmon_filesystem_directory_control_query_file_id;
static int hf_procmon_filesystem_directory_control_query_short_name_length;
static int hf_procmon_filesystem_directory_control_query_short_name;
static int hf_procmon_profiling_operation;
static int hf_procmon_network_operation;
static int hf_procmon_network_flags;
static int hf_procmon_network_flags_is_src_ipv4;
static int hf_procmon_network_flags_is_dst_ipv4;
static int hf_procmon_network_flags_tcp_udp;
static int hf_procmon_network_length;
static int hf_procmon_network_src_ipv4;
static int hf_procmon_network_src_ipv6;
static int hf_procmon_network_dest_ipv4;
static int hf_procmon_network_dest_ipv6;
static int hf_procmon_network_src_port;
static int hf_procmon_network_dest_port;
static int hf_procmon_network_padding;
static int hf_procmon_network_details;


/* Initialize the subtree pointers */
static int ett_procmon;
static int ett_procmon_header;
static int ett_procmon_stack_trace;
static int ett_procmon_process_event;
static int ett_procmon_process_path;
static int ett_procmon_process_commandline;
static int ett_procmon_process_curdir;
static int ett_procmon_registry_event;
static int ett_procmon_registry_key;
static int ett_procmon_registry_value;
static int ett_procmon_registry_new_key;
static int ett_procmon_filesystem_event;
static int ett_procmon_filesystem_path;
static int ett_procmon_filesystem_create_file_impersonating;
static int ett_procmon_filesystem_directory;
static int ett_procmon_filesystem_information;
static int ett_procmon_profiling_event;
static int ett_procmon_network_event;
static int ett_procmon_network_flags;


static expert_field ei_procmon_unknown_event_class;
static expert_field ei_procmon_unknown_operation;

static dissector_handle_t procmon_handle;

#define PROCMON_EVENT_CLASS_TYPE_PROCESS     1
#define PROCMON_EVENT_CLASS_TYPE_REGISTRY    2
#define PROCMON_EVENT_CLASS_TYPE_FILE_SYSTEM 3
#define PROCMON_EVENT_CLASS_TYPE_PROFILING   4
#define PROCMON_EVENT_CLASS_TYPE_NETWORK     5

#define STRING_IS_ASCII_MASK   0x8000
#define STRING_CHAR_COUNT_MASK 0x7FFF

static void dissect_procmon_detail_string_info(tvbuff_t* tvb, proto_tree* tree, int offset,
                                            int hf_detail, int hf_detail_ascii, int hf_detail_char_count, int ett_detail, bool* is_ascii, uint16_t* char_count)
{
    proto_tree* detail_tree;
    proto_item* detail_item;
    uint32_t char_value;

    detail_item = proto_tree_add_item(tree, hf_detail, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    detail_tree = proto_item_add_subtree(detail_item, ett_detail);

    proto_tree_add_item_ret_boolean(detail_tree, hf_detail_ascii, tvb, offset, 2, ENC_LITTLE_ENDIAN, is_ascii);
    proto_tree_add_item_ret_uint(detail_tree, hf_detail_char_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &char_value);
    *char_count = (uint16_t)(char_value & STRING_CHAR_COUNT_MASK);
}

static int dissect_procmon_detail_string(tvbuff_t* tvb, proto_tree* tree, int offset, bool is_ascii, uint16_t char_count, int hf_detail_string)
{
        int char_size = is_ascii ? 1 : 2;
        int path_size = char_size * char_count;
        proto_tree_add_item(tree, hf_detail_string, tvb, offset, path_size, is_ascii ? ENC_ASCII : ENC_UTF_16|ENC_LITTLE_ENDIAN);
        return offset + path_size;
}

static void dissect_procmon_access_mask(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, int hf_access_mask, int length, uint32_t* mapping, const value_string* vs_mask_values)
{
    int i = 0;
    bool first = true;
    proto_item* ti;
    uint32_t access_mask;
    wmem_strbuf_t* access_details = wmem_strbuf_new(pinfo->pool, "(");

    ti = proto_tree_add_item_ret_uint(tree, hf_access_mask, tvb, offset, length, ENC_LITTLE_ENDIAN, &access_mask);
    if (mapping != NULL)
    {
        if (access_mask & 0x80000000)
            access_mask |= mapping[0];
        if (access_mask & 0x40000000)
            access_mask |= mapping[1];
        if (access_mask & 0x20000000)
            access_mask |= mapping[2];
        if (access_mask & 0x10000000)
            access_mask |= mapping[3];
    }

    while (vs_mask_values[i].strptr) {
        if ((vs_mask_values[i].value & access_mask) == vs_mask_values[i].value)
        {
            if (first)
                first = false;
            else
                wmem_strbuf_append(access_details, ", ");
            wmem_strbuf_append(access_details, vs_mask_values[i].strptr);
        }

        i++;
    }

    wmem_strbuf_append_c(access_details, ')');
    proto_item_append_text(ti, " %s", wmem_strbuf_get_str(access_details));
}

static const value_string event_class_vals[] = {
        { PROCMON_EVENT_CLASS_TYPE_PROCESS, "Process" },
        { PROCMON_EVENT_CLASS_TYPE_REGISTRY, "Registry" },
        { PROCMON_EVENT_CLASS_TYPE_FILE_SYSTEM, "File System" },
        { PROCMON_EVENT_CLASS_TYPE_PROFILING, "Profiling" },
        { PROCMON_EVENT_CLASS_TYPE_NETWORK, "Network" },
        { 0, NULL }
};

#define PROCMON_PROCESS_OPERATION_DEFINED           0x0000
#define PROCMON_PROCESS_OPERATION_CREATE            0x0001
#define PROCMON_PROCESS_OPERATION_EXIT              0x0002
#define PROCMON_PROCESS_OPERATION_THREAD_CREATE     0x0003
#define PROCMON_PROCESS_OPERATION_THREAD_EXIT       0x0004
#define PROCMON_PROCESS_OPERATION_LOAD_IMAGE        0x0005
#define PROCMON_PROCESS_OPERATION_THREAD_PROFILE    0x0006
#define PROCMON_PROCESS_OPERATION_PROCESS_START     0x0007
#define PROCMON_PROCESS_OPERATION_PROCESS_STATISTICS 0x0008
#define PROCMON_PROCESS_OPERATION_SYSTEM_STATISTICS 0x0009

static const value_string process_operation_vals[] = {
        { PROCMON_PROCESS_OPERATION_DEFINED,           "Process Defined" },
        { PROCMON_PROCESS_OPERATION_CREATE,            "Process Create" },
        { PROCMON_PROCESS_OPERATION_EXIT,              "Process Exit" },
        { PROCMON_PROCESS_OPERATION_THREAD_CREATE,     "Thread Create" },
        { PROCMON_PROCESS_OPERATION_THREAD_EXIT,       "Thread Exit" },
        { PROCMON_PROCESS_OPERATION_LOAD_IMAGE,        "Load Image" },
        { PROCMON_PROCESS_OPERATION_THREAD_PROFILE,    "Thread Profile" },
        { PROCMON_PROCESS_OPERATION_PROCESS_START,     "Process Start" },
        { PROCMON_PROCESS_OPERATION_PROCESS_STATISTICS, "Process Statistics" },
        { PROCMON_PROCESS_OPERATION_SYSTEM_STATISTICS, "System Statistics" },
        { 0, NULL }
};


static bool dissect_procmon_process_event(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, uint32_t operation, tvbuff_t* extra_details_tvb _U_)
{
    proto_tree* process_tree;
    int offset = 0;
    bool handle_extra_details = false;

    process_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_procmon_process_event, NULL, "Process Data");

    switch(operation) {
        case PROCMON_PROCESS_OPERATION_DEFINED:
        case PROCMON_PROCESS_OPERATION_CREATE:
        {
            bool is_path_ascii, is_commandline_ascii;
            uint16_t path_char_count, commandline_char_count;

            //Unknown fields
            offset += 4;
            proto_tree_add_item(process_tree, hf_procmon_process_pid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            //Unknown fields
            offset += 36;
            uint8_t unknown_size1 = tvb_get_uint8(tvb, offset);
            offset += 1;
            uint8_t unknown_size2 = tvb_get_uint8(tvb, offset);
            offset += 1;
            dissect_procmon_detail_string_info(tvb, process_tree, offset,
                hf_procmon_process_path_size, hf_procmon_process_path_is_ascii, hf_procmon_process_path_char_count, ett_procmon_process_path,
                &is_path_ascii, &path_char_count);
            offset += 2;
            dissect_procmon_detail_string_info(tvb, process_tree, offset,
                hf_procmon_process_commandline_size, hf_procmon_process_commandline_is_ascii, hf_procmon_process_commandline_char_count, ett_procmon_process_commandline,
                &is_commandline_ascii, &commandline_char_count);
            offset += 2;
            //Unknown fields
            offset += 2;
            offset += unknown_size1;
            offset += unknown_size2;
            offset = dissect_procmon_detail_string(tvb, process_tree, offset, is_path_ascii, path_char_count, hf_procmon_process_path);
            offset = dissect_procmon_detail_string(tvb, process_tree, offset, is_commandline_ascii, commandline_char_count, hf_procmon_process_commandline);

            break;
        }
        case PROCMON_PROCESS_OPERATION_EXIT:
        {
            proto_tree_add_item(process_tree, hf_procmon_process_exit_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(process_tree, hf_procmon_process_kernel_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_user_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_working_set, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_peak_working_set, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_private_bytes, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_peak_private_bytes, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        }
        case PROCMON_PROCESS_OPERATION_THREAD_CREATE:
        {
            proto_tree_add_item(process_tree, hf_procmon_process_thread_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        }
        case PROCMON_PROCESS_OPERATION_THREAD_EXIT:
        case PROCMON_PROCESS_OPERATION_PROCESS_STATISTICS:
        {
            //Unknown fields
            offset += 4;
            proto_tree_add_item(process_tree, hf_procmon_process_kernel_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_user_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        }
        case PROCMON_PROCESS_OPERATION_LOAD_IMAGE:
        {
            bool is_path_ascii;
            uint16_t path_char_count;

            if (pinfo->pseudo_header->procmon.system_bitness)
            {
                proto_tree_add_item(process_tree, hf_procmon_process_image_base, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;
            }
            else
            {
                proto_tree_add_item(process_tree, hf_procmon_process_image_base, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }

            proto_tree_add_item(process_tree, hf_procmon_process_image_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            dissect_procmon_detail_string_info(tvb, process_tree, offset,
                hf_procmon_process_path_size, hf_procmon_process_path_is_ascii, hf_procmon_process_path_char_count, ett_procmon_process_path,
                &is_path_ascii, &path_char_count);
            offset += 2;
            //Unknown fields
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, process_tree, offset, is_path_ascii, path_char_count, hf_procmon_process_path);
            break;
        }
        case PROCMON_PROCESS_OPERATION_THREAD_PROFILE:
            //Unknown
            break;
        case PROCMON_PROCESS_OPERATION_PROCESS_START:
        {
            bool is_commandline_ascii, is_curdir_ascii;
            uint16_t commandline_char_count, curdir_char_count;
            uint32_t environment_char_count;

            proto_tree_add_item(process_tree, hf_procmon_process_parent_pid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            dissect_procmon_detail_string_info(tvb, process_tree, offset,
                hf_procmon_process_commandline_size, hf_procmon_process_commandline_is_ascii, hf_procmon_process_commandline_char_count, ett_procmon_process_commandline,
                &is_commandline_ascii, &commandline_char_count);
            offset += 2;
            dissect_procmon_detail_string_info(tvb, process_tree, offset,
                hf_procmon_process_curdir_size, hf_procmon_process_curdir_is_ascii, hf_procmon_process_curdir_char_count, ett_procmon_process_curdir,
                &is_curdir_ascii, &curdir_char_count);
            offset += 2;
            proto_tree_add_item_ret_uint(process_tree, hf_procmon_process_environment_char_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &environment_char_count);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, process_tree, offset, is_commandline_ascii, commandline_char_count, hf_procmon_process_commandline);
            offset = dissect_procmon_detail_string(tvb, process_tree, offset, is_curdir_ascii, curdir_char_count, hf_procmon_process_curdir);
            proto_tree_add_item(process_tree, hf_procmon_process_environment, tvb, offset, environment_char_count*2, ENC_UTF_16|ENC_LITTLE_ENDIAN);
            break;
        }
        case PROCMON_PROCESS_OPERATION_SYSTEM_STATISTICS:
            //Unknown
            break;
    }
    return handle_extra_details;
}

#define PROCMON_REGISTRY_OPERATION_OPEN_KEY               0x0000
#define PROCMON_REGISTRY_OPERATION_CREATE_KEY             0x0001
#define PROCMON_REGISTRY_OPERATION_CLOSE_KEY              0x0002
#define PROCMON_REGISTRY_OPERATION_QUERY_KEY              0x0003
#define PROCMON_REGISTRY_OPERATION_SET_VALUE              0x0004
#define PROCMON_REGISTRY_OPERATION_QUERY_VALUE            0x0005
#define PROCMON_REGISTRY_OPERATION_ENUM_VALUE             0x0006
#define PROCMON_REGISTRY_OPERATION_ENUM_KEY               0x0007
#define PROCMON_REGISTRY_OPERATION_SET_INFO_KEY           0x0008
#define PROCMON_REGISTRY_OPERATION_DELETE_KEY             0x0009
#define PROCMON_REGISTRY_OPERATION_DELETE_VALUE           0x000A
#define PROCMON_REGISTRY_OPERATION_FLUSH_KEY              0x000B
#define PROCMON_REGISTRY_OPERATION_LOAD_KEY               0x000C
#define PROCMON_REGISTRY_OPERATION_UNLOAD_KEY             0x000D
#define PROCMON_REGISTRY_OPERATION_RENAME_KEY             0x000E
#define PROCMON_REGISTRY_OPERATION_QUERY_MULTIPLE_VALUE   0x000F
#define PROCMON_REGISTRY_OPERATION_SET_KEY_SECURITY       0x0010
#define PROCMON_REGISTRY_OPERATION_QUERY_KEY_SECURITY     0x0011

static const value_string registry_operation_vals[] = {
        { PROCMON_REGISTRY_OPERATION_OPEN_KEY,             "Open Key" },
        { PROCMON_REGISTRY_OPERATION_CREATE_KEY,           "Create Key" },
        { PROCMON_REGISTRY_OPERATION_CLOSE_KEY,            "Close Key" },
        { PROCMON_REGISTRY_OPERATION_QUERY_KEY,            "Query Key" },
        { PROCMON_REGISTRY_OPERATION_SET_VALUE,            "Set Value" },
        { PROCMON_REGISTRY_OPERATION_QUERY_VALUE,          "Query Value" },
        { PROCMON_REGISTRY_OPERATION_ENUM_VALUE,           "Enum Value" },
        { PROCMON_REGISTRY_OPERATION_ENUM_KEY,             "Enum Key" },
        { PROCMON_REGISTRY_OPERATION_SET_INFO_KEY,         "Set Info Key" },
        { PROCMON_REGISTRY_OPERATION_DELETE_KEY,           "Delete Key" },
        { PROCMON_REGISTRY_OPERATION_DELETE_VALUE,         "Delete Value" },
        { PROCMON_REGISTRY_OPERATION_FLUSH_KEY,            "Flush Key" },
        { PROCMON_REGISTRY_OPERATION_LOAD_KEY,             "Load Key" },
        { PROCMON_REGISTRY_OPERATION_UNLOAD_KEY,           "Unload Key" },
        { PROCMON_REGISTRY_OPERATION_RENAME_KEY,           "Rename Key" },
        { PROCMON_REGISTRY_OPERATION_QUERY_MULTIPLE_VALUE, "Query Multiple Value" },
        { PROCMON_REGISTRY_OPERATION_SET_KEY_SECURITY,     "Set Key Security" },
        { PROCMON_REGISTRY_OPERATION_QUERY_KEY_SECURITY,   "Query Key Security" },
        { 0, NULL }
};

#define PROCMON_REGISTRY_KEY_INFORMATION_CLASS_BASIC         0
#define PROCMON_REGISTRY_KEY_INFORMATION_CLASS_NODE          1
#define PROCMON_REGISTRY_KEY_INFORMATION_CLASS_FULL          2
#define PROCMON_REGISTRY_KEY_INFORMATION_CLASS_NAME          3
#define PROCMON_REGISTRY_KEY_INFORMATION_CLASS_CACHED        4
#define PROCMON_REGISTRY_KEY_INFORMATION_CLASS_FLAGS         5
#define PROCMON_REGISTRY_KEY_INFORMATION_CLASS_VIRTUALIZATION 6
#define PROCMON_REGISTRY_KEY_INFORMATION_CLASS_HANDLE_TAGS   7
#define PROCMON_REGISTRY_KEY_INFORMATION_CLASS_TRUST         8
#define PROCMON_REGISTRY_KEY_INFORMATION_CLASS_LAYER         9

static const value_string registry_key_information_class_vals[] = {
        { PROCMON_REGISTRY_KEY_INFORMATION_CLASS_BASIC,         "Basic" },
        { PROCMON_REGISTRY_KEY_INFORMATION_CLASS_NODE,          "Node" },
        { PROCMON_REGISTRY_KEY_INFORMATION_CLASS_FULL,          "Full" },
        { PROCMON_REGISTRY_KEY_INFORMATION_CLASS_NAME,          "Name" },
        { PROCMON_REGISTRY_KEY_INFORMATION_CLASS_CACHED,        "Cached" },
        { PROCMON_REGISTRY_KEY_INFORMATION_CLASS_FLAGS,         "Flags" },
        { PROCMON_REGISTRY_KEY_INFORMATION_CLASS_VIRTUALIZATION, "Virtualization" },
        { PROCMON_REGISTRY_KEY_INFORMATION_CLASS_HANDLE_TAGS,   "Handle Tags" },
        { PROCMON_REGISTRY_KEY_INFORMATION_CLASS_TRUST,         "Trust" },
        { PROCMON_REGISTRY_KEY_INFORMATION_CLASS_LAYER,         "Layer" },
        { 0, NULL }
};

#define PROCMON_REGISTRY_KEY_SET_INFORMATION_WRITE_TIME_INFO       0
#define PROCMON_REGISTRY_KEY_SET_INFORMATION_WOW64_FLAGS_INFO      1
#define PROCMON_REGISTRY_KEY_SET_INFORMATION_HANDLE_TAGS_INFO      2

static const value_string registry_value_set_information_class_vals[] = {
        { PROCMON_REGISTRY_KEY_SET_INFORMATION_WRITE_TIME_INFO,        "Write Time" },
        { PROCMON_REGISTRY_KEY_SET_INFORMATION_WOW64_FLAGS_INFO,       "WOW64 Flags" },
        { PROCMON_REGISTRY_KEY_SET_INFORMATION_HANDLE_TAGS_INFO,       "Set Handle Tags" },
        { 0, NULL }
};



#define PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_BASIC        0
#define PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_FULL         1
#define PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_PARTIAL      2
#define PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_FULL_ALIGN64 3
#define PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_PARTIAL_ALIGN64 4
#define PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_LAYER        5

static const value_string registry_value_information_class_vals[] = {
        { PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_BASIC,        "Basic" },
        { PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_FULL,         "Full" },
        { PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_PARTIAL,      "Partial" },
        { PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_FULL_ALIGN64, "Full Align64" },
        { PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_PARTIAL_ALIGN64, "Partial Align64" },
        { PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_LAYER,        "Layer" },
        { 0, NULL }
};

#define PROCMON_REGISTRY_DISPOSITION_CREATED_NEW_KEY            1
#define PROCMON_REGISTRY_DISPOSITION_OPENED_EXISTING_KEY        2

static const value_string registry_disposition_vals[] = {
        { PROCMON_REGISTRY_DISPOSITION_CREATED_NEW_KEY,     "Created Key" },
        { PROCMON_REGISTRY_DISPOSITION_OPENED_EXISTING_KEY, "Open Existing" },
        { 0, NULL }
};

static int procmon_registry_query_or_enum_key_extra_details(proto_tree* tree, tvbuff_t* tvb, uint32_t information_class)
{
    uint32_t name_size;
    nstime_t timestamp;
    int offset = 0;

    switch (information_class)
    {
    case PROCMON_REGISTRY_KEY_INFORMATION_CLASS_NAME:
        proto_tree_add_item_ret_uint(tree, hf_procmon_registry_key_name_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &name_size);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_name, tvb, offset, name_size, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
        offset += name_size;
        break;

    case PROCMON_REGISTRY_KEY_INFORMATION_CLASS_HANDLE_TAGS:
        proto_tree_add_item(tree, hf_procmon_registry_key_handle_tags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;

    case PROCMON_REGISTRY_KEY_INFORMATION_CLASS_FLAGS:
        proto_tree_add_item(tree, hf_procmon_registry_key_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;

    case PROCMON_REGISTRY_KEY_INFORMATION_CLASS_CACHED:
        filetime_to_nstime(&timestamp, tvb_get_letoh64(tvb, offset));
        proto_tree_add_time(tree, hf_procmon_registry_key_last_write_time, tvb, offset, 8, &timestamp);
        offset += 8;
        proto_tree_add_item(tree, hf_procmon_registry_key_title_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_subkeys, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_max_name_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_values, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_max_value_name_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_max_value_data_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;

    case PROCMON_REGISTRY_KEY_INFORMATION_CLASS_BASIC:
        filetime_to_nstime(&timestamp, tvb_get_letoh64(tvb, offset));
        proto_tree_add_time(tree, hf_procmon_registry_key_last_write_time, tvb, offset, 8, &timestamp);
        offset += 8;
        proto_tree_add_item(tree, hf_procmon_registry_key_title_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item_ret_uint(tree, hf_procmon_registry_key_name_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &name_size);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_name, tvb, offset, name_size, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
        offset += name_size;
        break;

    case PROCMON_REGISTRY_KEY_INFORMATION_CLASS_FULL:
        filetime_to_nstime(&timestamp, tvb_get_letoh64(tvb, offset));
        proto_tree_add_time(tree, hf_procmon_registry_key_last_write_time, tvb, offset, 8, &timestamp);
        offset += 8;
        proto_tree_add_item(tree, hf_procmon_registry_key_title_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_class_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_class_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_subkeys, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_max_name_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_max_class_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_values, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_max_value_name_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_max_value_data_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;

    case PROCMON_REGISTRY_KEY_INFORMATION_CLASS_NODE:
        filetime_to_nstime(&timestamp, tvb_get_letoh64(tvb, offset));
        proto_tree_add_time(tree, hf_procmon_registry_key_last_write_time, tvb, offset, 8, &timestamp);
        offset += 8;
        proto_tree_add_item(tree, hf_procmon_registry_key_title_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_class_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_class_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item_ret_uint(tree, hf_procmon_registry_key_name_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &name_size);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_key_name, tvb, offset, name_size, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
        offset += name_size;
        break;

    case PROCMON_REGISTRY_KEY_INFORMATION_CLASS_VIRTUALIZATION:
    case PROCMON_REGISTRY_KEY_INFORMATION_CLASS_TRUST:
    case PROCMON_REGISTRY_KEY_INFORMATION_CLASS_LAYER:
        //No extra data (or unknown)
        break;
    }

    return offset;
}

#define PROCMON_REGISTRY_VALUE_REG_TYPE_NONE              0
#define PROCMON_REGISTRY_VALUE_REG_TYPE_SZ                1
#define PROCMON_REGISTRY_VALUE_REG_TYPE_EXPAND_SZ         2
#define PROCMON_REGISTRY_VALUE_REG_TYPE_BINARY            3
#define PROCMON_REGISTRY_VALUE_REG_TYPE_DWORD             4
#define PROCMON_REGISTRY_VALUE_REG_TYPE_DWORD_BIG_ENDIAN  5
#define PROCMON_REGISTRY_VALUE_REG_TYPE_LINK              6
#define PROCMON_REGISTRY_VALUE_REG_TYPE_MULTI_SZ          7
#define PROCMON_REGISTRY_VALUE_REG_TYPE_RESOURCE_LIST     8
#define PROCMON_REGISTRY_VALUE_REG_TYPE_FULL_RESOURCE_DESCRIPTOR 9
#define PROCMON_REGISTRY_VALUE_REG_TYPE_RESOURCE_REQUIREMENTS_LIST 10
#define PROCMON_REGISTRY_VALUE_REG_TYPE_QWORD             11
#define PROCMON_REGISTRY_VALUE_REG_TYPE_QWORD_BIG_ENDIAN  12

static const value_string registry_value_reg_type_vals[] = {
        { PROCMON_REGISTRY_VALUE_REG_TYPE_NONE, "REG_NONE" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_SZ, "REG_SZ" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_EXPAND_SZ, "REG_EXPAND_SZ" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_BINARY, "REG_BINARY" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_DWORD, "REG_DWORD" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_DWORD_BIG_ENDIAN, "REG_DWORD_BIG_ENDIAN" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_LINK, "REG_LINK" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_MULTI_SZ, "REG_MULTI_SZ" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_RESOURCE_LIST, "REG_RESOURCE_LIST" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_FULL_RESOURCE_DESCRIPTOR, "REG_FULL_RESOURCE_DESCRIPTOR" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_RESOURCE_REQUIREMENTS_LIST, "REG_RESOURCE_REQUIREMENTS_LIST" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_QWORD, "REG_QWORD" },
        { PROCMON_REGISTRY_VALUE_REG_TYPE_QWORD_BIG_ENDIAN, "REG_QWORD_BIG_ENDIAN" },
        { 0, NULL }
};

static int procmon_read_registry_data(proto_tree* tree, packet_info* pinfo, tvbuff_t* tvb, int offset, uint32_t type, uint32_t length)
{
    switch (type)
    {
    case PROCMON_REGISTRY_VALUE_REG_TYPE_DWORD:
        proto_tree_add_item(tree, hf_procmon_registry_value_dword, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;
    case PROCMON_REGISTRY_VALUE_REG_TYPE_QWORD:
        proto_tree_add_item(tree, hf_procmon_registry_value_qword, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
        break;
    case PROCMON_REGISTRY_VALUE_REG_TYPE_SZ:
    case PROCMON_REGISTRY_VALUE_REG_TYPE_EXPAND_SZ:
        proto_tree_add_item(tree, hf_procmon_registry_value_sz, tvb, offset, -1, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
        offset += tvb_reported_length(tvb);
        break;
    case PROCMON_REGISTRY_VALUE_REG_TYPE_BINARY:
        proto_tree_add_item(tree, hf_procmon_registry_value_binary, tvb, offset, -1, ENC_NA);
        offset += tvb_reported_length(tvb);
        break;
    case PROCMON_REGISTRY_VALUE_REG_TYPE_MULTI_SZ:
    {
        int str_length;
        int start_offset = offset;
        uint8_t* substring;
        wmem_strbuf_t* full_string = wmem_strbuf_new(pinfo->pool, "");

        while (((substring = tvb_get_stringz_enc(pinfo->pool, tvb, offset, &str_length, ENC_UTF_16 | ENC_LITTLE_ENDIAN)) != NULL) && (strlen(substring) > 0))
        {
            wmem_strbuf_append_printf(full_string, " %s", substring);
            offset += str_length;
        }
        //Include the NULL string at the end of the list
        offset += 2;

        proto_tree_add_string(tree, hf_procmon_registry_value_multi_sz, tvb, start_offset, offset - start_offset, wmem_strbuf_get_str(full_string));
        offset += length;
        break;
    }
    }

    return offset;
}

static int procmon_registry_query_or_enum_value_extra_details(proto_tree* tree, packet_info* pinfo, tvbuff_t* tvb, uint32_t information_class)
{
    int offset = 0;
    uint32_t length = 0, type, name_size;

    //Unknown fields
    offset += 4;

    proto_tree_add_item_ret_uint(tree, hf_procmon_registry_value_reg_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, &type);
    offset += 4;

    switch (information_class)
    {
    case PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_FULL:
        proto_tree_add_item(tree, hf_procmon_registry_value_offset_to_data, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item_ret_uint(tree, hf_procmon_registry_value_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
        offset += 4;
        proto_tree_add_item_ret_uint(tree, hf_procmon_registry_value_name_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &name_size);
        offset += 4;
        proto_tree_add_item(tree, hf_procmon_registry_value_name, tvb, offset, name_size, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
        offset += name_size;
        break;
    case PROCMON_REGISTRY_VALUE_INFORMATION_CLASS_PARTIAL:
        proto_tree_add_item_ret_uint(tree, hf_procmon_registry_value_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
        offset += 4;
        break;
    }

    if (length > 0)
        offset += procmon_read_registry_data(tree, pinfo, tvb, offset, type, length);

    return offset;
}

static bool dissect_procmon_registry_event(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, uint32_t operation, tvbuff_t* extra_details_tvb)
{
    proto_tree* registry_tree;
    int offset = 0, extra_offset = 0;
    bool is_value_ascii, is_new_value_ascii;
    uint32_t information_class, type;
    uint16_t value_char_count, new_value_char_count;
    uint32_t registry_access_mask_mapping[4] = { 0x20019, 0x20006, 0x20019, 0xf003f };

    registry_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_procmon_registry_event, NULL, "Registry Data");

    switch(operation) {
        case PROCMON_REGISTRY_OPERATION_OPEN_KEY:
        case PROCMON_REGISTRY_OPERATION_CREATE_KEY:
        {
            static const value_string desired_access_vals[] = {
                {0xf003f, "All Access"},
                {0x2001f, "Read/Write"},
                {0x20019, "Read"},
                {0x20006, "Write"},
                {0x1, "Query Value"},
                {0x2, "Set Value"},
                {0x4, "Create Sub Key"},
                {0x8, "Enumerate Sub Keys"},
                {0x10, "Notify"},
                {0x20, "Create Link"},
                {0x300, "WOW64_Res"},
                {0x200, "WOW64_32Key"},
                {0x100, "WOW64_64Key"},
                {0x10000, "Delete"},
                {0x20000, "Read Control"},
                {0x40000, "Write DAC"},
                {0x80000, "Write Owner"},
                {0x100000, "Synchronize"},
                {0x1000000, "Access System Security"},
                {0x2000000, "Maximum Allowed"},
                { 0, NULL }
            };
            uint32_t desired_access;

            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            desired_access = tvb_get_letohl(tvb, offset);
            dissect_procmon_access_mask(tvb, pinfo, registry_tree, offset, hf_procmon_registry_desired_access, 4, registry_access_mask_mapping, desired_access_vals);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);

            if (tvb_reported_length(extra_details_tvb) > 0)
            {
                if (desired_access & 0x2000000)
                    dissect_procmon_access_mask(extra_details_tvb, pinfo, registry_tree, extra_offset, hf_procmon_registry_granted_access, 4, registry_access_mask_mapping, desired_access_vals);

                extra_offset += 4;
                proto_tree_add_item(registry_tree, hf_procmon_registry_disposition, extra_details_tvb, extra_offset, 4, ENC_LITTLE_ENDIAN);
                extra_offset += 4;
            }
            break;
        }
        case PROCMON_REGISTRY_OPERATION_CLOSE_KEY:
        case PROCMON_REGISTRY_OPERATION_FLUSH_KEY:
        case PROCMON_REGISTRY_OPERATION_UNLOAD_KEY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            break;

        case PROCMON_REGISTRY_OPERATION_QUERY_KEY:
        {
            proto_item* info_item;
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            info_item = proto_tree_add_item_ret_uint(registry_tree, hf_procmon_registry_key_information_class, tvb, offset, 4, ENC_LITTLE_ENDIAN, &information_class);
            if (try_val_to_str(information_class, registry_key_information_class_vals) == NULL)
                expert_add_info_format(pinfo, info_item, &ei_procmon_unknown_operation, "Unknown Registry Key Information Class: %u", information_class);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            if (tvb_reported_length(extra_details_tvb) > 0)
                extra_offset += procmon_registry_query_or_enum_key_extra_details(registry_tree, extra_details_tvb, information_class);
            break;
        }
        case PROCMON_REGISTRY_OPERATION_QUERY_VALUE:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_value_size, hf_procmon_registry_value_is_ascii, hf_procmon_registry_value_char_count, ett_procmon_registry_value,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item_ret_uint(registry_tree, hf_procmon_registry_value_information_class, tvb, offset, 4, ENC_LITTLE_ENDIAN, &information_class);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_value);
            if (tvb_reported_length(extra_details_tvb) > 0)
                extra_offset += procmon_registry_query_or_enum_value_extra_details(registry_tree, pinfo, extra_details_tvb, information_class);
            break;

        case PROCMON_REGISTRY_OPERATION_ENUM_KEY:
        {
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item_ret_uint(registry_tree, hf_procmon_registry_key_information_class, tvb, offset, 4, ENC_LITTLE_ENDIAN, &information_class);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            if (tvb_reported_length(extra_details_tvb) > 0)
                extra_offset += procmon_registry_query_or_enum_key_extra_details(registry_tree, extra_details_tvb, information_class);
            break;
        }
        case PROCMON_REGISTRY_OPERATION_ENUM_VALUE:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_value_size, hf_procmon_registry_value_is_ascii, hf_procmon_registry_value_char_count, ett_procmon_registry_value,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item_ret_uint(registry_tree, hf_procmon_registry_value_information_class, tvb, offset, 4, ENC_LITTLE_ENDIAN, &information_class);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_value);
            if (tvb_reported_length(extra_details_tvb) > 0)
                extra_offset += procmon_registry_query_or_enum_value_extra_details(registry_tree, pinfo, extra_details_tvb, information_class);
            break;

        case PROCMON_REGISTRY_OPERATION_SET_VALUE:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_value_size, hf_procmon_registry_value_is_ascii, hf_procmon_registry_value_char_count, ett_procmon_registry_value,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item_ret_uint(registry_tree, hf_procmon_registry_type, tvb, offset, 4, ENC_LITTLE_ENDIAN, &type);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_data_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_value);
            if (tvb_reported_length(extra_details_tvb) > 0)
                extra_offset += procmon_read_registry_data(registry_tree, pinfo, extra_details_tvb, extra_offset, type, tvb_reported_length(extra_details_tvb));
            break;
        case PROCMON_REGISTRY_OPERATION_SET_INFO_KEY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item_ret_uint(registry_tree, hf_procmon_registry_key_set_information_class, tvb, offset, 4, ENC_LITTLE_ENDIAN, &information_class);
            offset += 4;

            //Unknown fields
            offset += 4;

            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            //Unknown fields
            offset += 2;

            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);

            if (tvb_reported_length(extra_details_tvb) > 0)
            {
                switch (information_class)
                {
                case PROCMON_REGISTRY_KEY_SET_INFORMATION_WRITE_TIME_INFO:
                {
                    nstime_t timestamp;
                    filetime_to_nstime(&timestamp, tvb_get_letoh64(extra_details_tvb, offset));
                    proto_tree_add_time(registry_tree, hf_procmon_registry_key_set_information_write_time, extra_details_tvb, extra_offset, 8, &timestamp);
                    extra_offset += 8;
                    break;
                }
                case PROCMON_REGISTRY_KEY_SET_INFORMATION_WOW64_FLAGS_INFO:
                    proto_tree_add_item(registry_tree, hf_procmon_registry_key_set_information_wow64_flags, extra_details_tvb, extra_offset, 4, ENC_LITTLE_ENDIAN);
                    extra_offset += 4;
                    break;
                case PROCMON_REGISTRY_KEY_SET_INFORMATION_HANDLE_TAGS_INFO:
                    proto_tree_add_item(registry_tree, hf_procmon_registry_key_set_information_handle_tags, extra_details_tvb, extra_offset, 4, ENC_LITTLE_ENDIAN);
                    extra_offset += 4;
                    break;
                }
            }
            break;

        case PROCMON_REGISTRY_OPERATION_DELETE_KEY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            break;

        case PROCMON_REGISTRY_OPERATION_DELETE_VALUE:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_value_size, hf_procmon_registry_value_is_ascii, hf_procmon_registry_value_char_count, ett_procmon_registry_value,
                &is_value_ascii, &value_char_count);
            offset += 2;

            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_value);
            break;

        case PROCMON_REGISTRY_OPERATION_LOAD_KEY:
        case PROCMON_REGISTRY_OPERATION_RENAME_KEY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_new_key_size, hf_procmon_registry_new_key_is_ascii, hf_procmon_registry_new_key_char_count, ett_procmon_registry_new_key,
                &is_new_value_ascii, &new_value_char_count);
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            extra_offset += dissect_procmon_detail_string(extra_details_tvb, registry_tree, extra_offset, is_new_value_ascii, new_value_char_count, hf_procmon_registry_new_key);
            break;

        case PROCMON_REGISTRY_OPERATION_QUERY_MULTIPLE_VALUE:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_value_size, hf_procmon_registry_value_is_ascii, hf_procmon_registry_value_char_count, ett_procmon_registry_value,
                &is_value_ascii, &value_char_count);
            offset += 2;

            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_value);
            break;

        case PROCMON_REGISTRY_OPERATION_SET_KEY_SECURITY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            break;

        case PROCMON_REGISTRY_OPERATION_QUERY_KEY_SECURITY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            break;
    }

    return (extra_offset != 0);
}

#define PROCMON_FILESYSTEM_OPERATION_VOLUME_DISMOUNT             0
#define PROCMON_FILESYSTEM_OPERATION_VOLUME_MOUNT                1
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_MDL_WRITE_COMPLETE   2
#define PROCMON_FILESYSTEM_OPERATION_WRITE_FILE2                 3
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_MDL_READ_COMPLETE    4
#define PROCMON_FILESYSTEM_OPERATION_READ_FILE2                  5
#define PROCMON_FILESYSTEM_OPERATION_QUERY_OPEN                  6
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_CHECK_IF_POSSIBLE    7
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_12                   8
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_11                   9
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_10                   10
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_9                    11
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_8                    12
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_NOTIFY_STREAM_FO_CREATION 13
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_CC_FLUSH      14
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_ACQUIRE_FOR_CC_FLUSH      15
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_MOD_WRITE    16
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_ACQUIRE_FOR_MOD_WRITE    17
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION 18
#define PROCMON_FILESYSTEM_OPERATION_CREATE_FILE_MAPPING                 19
#define PROCMON_FILESYSTEM_OPERATION_CREATE_FILE                         20
#define PROCMON_FILESYSTEM_OPERATION_CREATE_PIPE                         21
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_CLOSE                        22
#define PROCMON_FILESYSTEM_OPERATION_READ_FILE                         23
#define PROCMON_FILESYSTEM_OPERATION_WRITE_FILE                        24
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE           25
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE             26
#define PROCMON_FILESYSTEM_OPERATION_QUERY_EA_FILE                    27
#define PROCMON_FILESYSTEM_OPERATION_SET_EA_FILE                      28
#define PROCMON_FILESYSTEM_OPERATION_FLUSH_BUFFERS_FILE              29
#define PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION        30
#define PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION          31
#define PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL              32
#define PROCMON_FILESYSTEM_OPERATION_FILE_SYSTEM_CONTROL           33
#define PROCMON_FILESYSTEM_OPERATION_DEVICE_IO_CONTROL         34
#define PROCMON_FILESYSTEM_OPERATION_INTERNAL_DEVICE_IO_CONTROL 35
#define PROCMON_FILESYSTEM_OPERATION_SHUTDOWN                   36
#define PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE           37
#define PROCMON_FILESYSTEM_OPERATION_CLOSE_FILE                38
#define PROCMON_FILESYSTEM_OPERATION_CREATE_MAIL_SLOT          39
#define PROCMON_FILESYSTEM_OPERATION_QUERY_SECURITY_FILE       40
#define PROCMON_FILESYSTEM_OPERATION_SET_SECURITY_FILE         41
#define PROCMON_FILESYSTEM_OPERATION_POWER                     42
#define PROCMON_FILESYSTEM_OPERATION_SYSTEM_CONTROL            43
#define PROCMON_FILESYSTEM_OPERATION_DEVICE_CHANGE             44
#define PROCMON_FILESYSTEM_OPERATION_QUERY_FILE_QUOTA          45
#define PROCMON_FILESYSTEM_OPERATION_SET_FILE_QUOTA            46
#define PROCMON_FILESYSTEM_OPERATION_PLUG_AND_PLAY             47

static const value_string filesystem_operation_vals[] = {
        { PROCMON_FILESYSTEM_OPERATION_VOLUME_DISMOUNT,             "Volume Dismount" },
        { PROCMON_FILESYSTEM_OPERATION_VOLUME_MOUNT,                "Volume Mount" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_MDL_WRITE_COMPLETE,   "Fast I/O MDL Write Complete" },
        { PROCMON_FILESYSTEM_OPERATION_WRITE_FILE2,                 "Write File 2" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_MDL_READ_COMPLETE,    "Fast I/O MDL Read Complete" },
        { PROCMON_FILESYSTEM_OPERATION_READ_FILE2,                  "Read File 2" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_OPEN,                  "Query Open" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_CHECK_IF_POSSIBLE,    "Fast I/O Check If Possible" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_12,                   "IRP_MJ_CLEANUP" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_11,                   "IRP_MJ_SET_INFORMATION" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_10,                   "IRP_MJ_QUERY_INFORMATION" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_9,                    "IRP_MJ_FLUSH_BUFFERS" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_8,                    "IRP_MJ_DIRECTORY_CONTROL" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_NOTIFY_STREAM_FO_CREATION, "Fast I/O Notify Stream File Object Creation" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_CC_FLUSH,      "Fast I/O Release For Cache Manager Flush" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_ACQUIRE_FOR_CC_FLUSH,      "Fast I/O Acquire For Cache Manager Flush" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_MOD_WRITE,    "Fast I/O Release For Modified Write" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_ACQUIRE_FOR_MOD_WRITE,    "Fast I/O Acquire For Modified Write" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION, "Fast I/O Release For Section Synchronization" },
        { PROCMON_FILESYSTEM_OPERATION_CREATE_FILE_MAPPING,                 "Create File Mapping" },
        { PROCMON_FILESYSTEM_OPERATION_CREATE_FILE,                         "Create File" },
        { PROCMON_FILESYSTEM_OPERATION_CREATE_PIPE,                         "Create Pipe" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_CLOSE,                        "IRP_MJ_CLOSE" },
        { PROCMON_FILESYSTEM_OPERATION_READ_FILE,                         "Read File" },
        { PROCMON_FILESYSTEM_OPERATION_WRITE_FILE,                        "Write File" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE,           "Query Information File" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE,             "Set Information File" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_EA_FILE,                    "Query EA File" },
        { PROCMON_FILESYSTEM_OPERATION_SET_EA_FILE,                      "Set EA File" },
        { PROCMON_FILESYSTEM_OPERATION_FLUSH_BUFFERS_FILE,              "Flush Buffers File" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION,        "Query Volume Information" },
        { PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION,          "Set Volume Information" },
        { PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL,              "Directory Control" },
        { PROCMON_FILESYSTEM_OPERATION_FILE_SYSTEM_CONTROL,           "File System Control" },
        { PROCMON_FILESYSTEM_OPERATION_DEVICE_IO_CONTROL,         "Device I/O Control" },
        { PROCMON_FILESYSTEM_OPERATION_INTERNAL_DEVICE_IO_CONTROL, "Internal Device I/O Control" },
        { PROCMON_FILESYSTEM_OPERATION_SHUTDOWN,                   "Shutdown" },
        { PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE,           "Lock/Unlock File" },
        { PROCMON_FILESYSTEM_OPERATION_CLOSE_FILE,                "Close File" },
        { PROCMON_FILESYSTEM_OPERATION_CREATE_MAIL_SLOT,          "Create Mail Slot" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_SECURITY_FILE,       "Query Security File" },
        { PROCMON_FILESYSTEM_OPERATION_SET_SECURITY_FILE,         "Set Security File" },
        { PROCMON_FILESYSTEM_OPERATION_POWER,                     "Power" },
        { PROCMON_FILESYSTEM_OPERATION_SYSTEM_CONTROL,            "System Control" },
        { PROCMON_FILESYSTEM_OPERATION_DEVICE_CHANGE,             "Device Change" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_FILE_QUOTA,          "Query File Quota" },
        { PROCMON_FILESYSTEM_OPERATION_SET_FILE_QUOTA,            "Set File Quota" },
        { PROCMON_FILESYSTEM_OPERATION_PLUG_AND_PLAY,             "Plug and Play" },
        { 0, NULL }
};

#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_BASIC       0x04
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_STANDARD    0x05
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_INTERNAL  0x06
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_EA        0x07
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NAME      0x09
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_POSITION  0x0E
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ALL       0x12
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_END_OF_FILE 0x14
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_STREAM    0x16
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_COMPRESSION 0x1C
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID        0x1D
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_MOVE_CLUSTER 0x1F
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NETWORK_OPEN 0x22
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ATTRIBUTE_TAG 0x23
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID_BOTH_DIRECTORY 0x25
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_VALID_DATA_LENGTH 0x27
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_SHORT_NAME 0x28
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_IO_PRIORITY_HINT 0x2B
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_LINKS     0x2E
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NAMES  0x2F
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NORMALIZED_NAME 0x30
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NETWORK_PHYSICAL_NAME 0x31
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID_GLOBAL_TX_DIRECTORY 0x32
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_IS_REMOTE_DEVICE 0x33
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ATTRIBUTE_CACHE 0x34
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NUMA_NODE 0x35
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_STANDARD_LINK 0x36
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_REMOTE_PROTOCOL 0x37
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_RENAME_BYPASS_ACCESS 0x38
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_LINK_BYPASS_ACCESS 0x39
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_VOLUME_NAME 0x3A
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID_INFO 0x3B
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID_EXTD_DIRECTORY 0x3C
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_HARD_LINK_FULL_ID 0x3E
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID_EXTD_BOTH_DIRECTORY 0x3F
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_DESIRED_STORAGE_CLASS 0x43
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_STAT 0x44
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_MEMORY_PARTITION 0x45
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_SAT_LX 0x46
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_CASE_SENSITIVE 0x47
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_LINK_EX 0x48
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_STORAGE_RESERVED_ID 0x4A
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_CASE_SENSITIVE_FORCE_ACCESS 0x4B

static const value_string filesystem_operation_query_info_vals[] = {
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_BASIC,             "Basic"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_STANDARD,          "Standard"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_INTERNAL,          "Internal"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_EA,                "EA"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NAME,              "Name"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_POSITION,          "Position"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ALL,               "All"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_END_OF_FILE,       "End of File"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_STREAM,            "Stream"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_COMPRESSION,       "Compression"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID,                "ID"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_MOVE_CLUSTER,      "Move Cluster"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NETWORK_OPEN,      "Network Open"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ATTRIBUTE_TAG,     "Attribute Tag"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID_BOTH_DIRECTORY,"ID Both Directory"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_VALID_DATA_LENGTH,"Valid Data Length"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_SHORT_NAME,        "Short Name"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_IO_PRIORITY_HINT,  "I/O Priority Hint"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_LINKS,             "Links"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NAMES,             "Names"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NORMALIZED_NAME,   "Normalized Name"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NETWORK_PHYSICAL_NAME,"Network Physical Name"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID_GLOBAL_TX_DIRECTORY,"ID Global TX Directory"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_IS_REMOTE_DEVICE,  "Is Remote Device"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ATTRIBUTE_CACHE,   "Attribute Cache"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_NUMA_NODE,         "NUMA Node"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_STANDARD_LINK,     "Standard Link"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_REMOTE_PROTOCOL,    "Remote Protocol"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_RENAME_BYPASS_ACCESS, "Rename Bypass Access"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_LINK_BYPASS_ACCESS,   "Link Bypass Access"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_VOLUME_NAME,       "Volume Name"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID_INFO,           "ID Info"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID_EXTD_DIRECTORY, "ID Extended Directory"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_HARD_LINK_FULL_ID, "Hard Link Full ID"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_ID_EXTD_BOTH_DIRECTORY, "ID Extended Both Directory"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_DESIRED_STORAGE_CLASS, "Desired Storage Class"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_STAT,              "Stat"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_MEMORY_PARTITION,  "Memory Partition"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_SAT_LX,           "SAT LX"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_CASE_SENSITIVE,    "Case Sensitive"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_LINK_EX,           "Link Ex"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_STORAGE_RESERVED_ID,"Storage Reserved ID"},
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE_CASE_SENSITIVE_FORCE_ACCESS,"Case Sensitive Force Access"},
        { 0, NULL }
};


#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_BASIC       0x04
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_RENAME      0x0A
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_LINK        0x0B
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_DISPOSITION 0x0D
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_POSITION    0x0E
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_ALLOCATION  0x13
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_END_OF_FILE 0x14
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_STREAM      0x16
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_PIPE        0x17
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_VALID_DATA_LENGTH   0x27
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_SHORT_NAME  0x28
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_REPLACE_COMPLETION  0x3D
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_DISPOSITION_EX 0x40
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_RENAME_EX   0x41
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_RENAME_EX_BYPASS_ACCESS 0x42
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_STORAGE_RESERVE_ID  0x4A

static const value_string filesystem_operation_set_info_vals[] = {
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_BASIC,             "Basic" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_RENAME,            "Rename" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_LINK,              "Link" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_DISPOSITION,       "Disposition" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_POSITION,          "Position" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_ALLOCATION,        "Allocation" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_END_OF_FILE,       "End of File" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_STREAM,            "Stream" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_PIPE,              "Pipe" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_VALID_DATA_LENGTH, "Valid Data Length" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_SHORT_NAME,        "Short name" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_REPLACE_COMPLETION,"Replace Completion" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_DISPOSITION_EX,    "DispositionEx" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_RENAME_EX,         "RenameEx" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_RENAME_EX_BYPASS_ACCESS, "RenameEx Bypass Access" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_STORAGE_RESERVE_ID,"Storage Reserve ID" },
        { 0, NULL }
};

#define PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_INFORMATION 0x1
#define PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_LABEL       0x2
#define PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_SIZE        0x3
#define PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_DEVICE      0x4
#define PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_ATTRIBUTE   0x5
#define PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_CONTROL     0x6
#define PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_FULL_SIZE   0x7
#define PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_OBJECT_ID   0x8

static const value_string filesystem_operation_query_volume_info_vals[] = {
        { PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_INFORMATION, "Query Information" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_LABEL,       "Query Label" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_SIZE,        "Query Size" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_DEVICE,      "Query Device" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_ATTRIBUTE,   "Query Attribute" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_CONTROL,     "Query Control" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_FULL_SIZE,   "Query Full Size" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION_QUERY_OBJECT_ID,   "Query Object ID" },
        { 0, NULL }
};

#define PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION_CONTROL     0x01
#define PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION_LABEL       0x02
#define PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION_OBJECT_ID   0x08

static const value_string filesystem_operation_set_volume_info_vals[] = {
        { PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION_CONTROL,     "Control" },
        { PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION_LABEL,       "Label" },
        { PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION_OBJECT_ID,   "Object ID" },
        { 0, NULL }
};

#define PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL_QUERY             0x01
#define PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL_NOTIFY_CHANGE     0x02

static const value_string filesystem_operation_directory_control_vals[] = {
        { PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL_QUERY,             "Query" },
        { PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL_NOTIFY_CHANGE,     "Notify Change" },
        { 0, NULL }
};

#define PROCMON_FILESYSTEM_OPERATION_PNP_START_DEVICE    0x00
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_REMOVE_DEVICE 0x01
#define PROCMON_FILESYSTEM_OPERATION_PNP_REMOVE_DEVICE   0x02
#define PROCMON_FILESYSTEM_OPERATION_PNP_CANCEL_REMOVE_DEVICE 0x03
#define PROCMON_FILESYSTEM_OPERATION_PNP_STOP_DEVICE     0x04
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_STOP_DEVICE 0x05
#define PROCMON_FILESYSTEM_OPERATION_PNP_CANCEL_STOP_DEVICE 0x06
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_DEVICE_RELATIONS 0x07
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_INTERFACE 0x08
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_CAPABILITIES 0x09
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_RESOURCES 0x0A
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_RESOURCE_REQUIREMENTS 0x0B
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_DEVICE_TEXT 0x0C
#define PROCMON_FILESYSTEM_OPERATION_PNP_FILTER_RESOURCE_REQUIREMENTS 0x0D
#define PROCMON_FILESYSTEM_OPERATION_PNP_READ_CONFIG 0x0F
#define PROCMON_FILESYSTEM_OPERATION_PNP_WRITE_CONFIG 0x10
#define PROCMON_FILESYSTEM_OPERATION_PNP_EJECT 0x11
#define PROCMON_FILESYSTEM_OPERATION_PNP_SET_LOCK 0x12
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_ID2 0x13
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_PNP_DEVICE_STATE 0x14
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_BUS_INFORMATION 0x15
#define PROCMON_FILESYSTEM_OPERATION_PNP_DEVICE_USAGE_NOTIFICATION 0x16
#define PROCMON_FILESYSTEM_OPERATION_PNP_SURPRISE_REMOVAL 0x17
#define PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_LEGACY_BUS_INFORMATION 0x18

static const value_string filesystem_operation_pnp_vals[] = {
        { PROCMON_FILESYSTEM_OPERATION_PNP_START_DEVICE,                "Start Device" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_REMOVE_DEVICE,         "Query Remove Device" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_REMOVE_DEVICE,               "Remove Device" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_CANCEL_REMOVE_DEVICE,        "Cancel Remove Device" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_STOP_DEVICE,                 "Stop Device" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_STOP_DEVICE,           "Query Stop Device" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_CANCEL_STOP_DEVICE,          "Cancel Stop Device" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_DEVICE_RELATIONS,      "Query Device Relations" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_INTERFACE,             "Query Interface" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_CAPABILITIES,          "Query Capabilities" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_RESOURCES,             "Query Resources" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_RESOURCE_REQUIREMENTS, "Query Resource Requirements" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_DEVICE_TEXT,           "Query Device Text" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_FILTER_RESOURCE_REQUIREMENTS,"Filter Resource Requirements" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_READ_CONFIG,                 "Read Config" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_WRITE_CONFIG,                "Write Config" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_EJECT,                       "Eject" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_SET_LOCK,                    "Set Lock" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_ID2,                   "Query ID2" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_PNP_DEVICE_STATE,      "Query PnP Device State" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_BUS_INFORMATION,       "Query Bus Information" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_DEVICE_USAGE_NOTIFICATION,   "Device Usage Notification" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_SURPRISE_REMOVAL,            "Surprise Removal" },
        { PROCMON_FILESYSTEM_OPERATION_PNP_QUERY_LEGACY_BUS_INFORMATION,   "Query Legacy Bus Information" },
        { 0, NULL }
};

#define PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE_LOCK   0x01
#define PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE_UNLOCK_SINGLE 0x02
#define PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE_UNLOCK_ALL 0x03
#define PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE_UNLOCK_BY_KEY 0x04

static const value_string filesystem_operation_lock_unlock_file_vals[] = {
        { PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE_LOCK,            "Lock" },
        { PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE_UNLOCK_SINGLE,    "Unlock Single" },
        { PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE_UNLOCK_ALL,       "Unlock All" },
        { PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE_UNLOCK_BY_KEY,    "Unlock By Key" },
        { 0, NULL }
};

#define PROCMON_FILESYSTEM_DISPOSITION_SUPERSEDE    0x00
#define PROCMON_FILESYSTEM_DISPOSITION_OPEN         0x01
#define PROCMON_FILESYSTEM_DISPOSITION_CREATE       0x02
#define PROCMON_FILESYSTEM_DISPOSITION_OPEN_IF      0x03
#define PROCMON_FILESYSTEM_DISPOSITION_OVERWRITE    0x04
#define PROCMON_FILESYSTEM_DISPOSITION_OVERWRITE_IF 0x05

static const value_string filesystem_disposition_vals[] = {
        { PROCMON_FILESYSTEM_DISPOSITION_SUPERSEDE,    "Supersede" },
        { PROCMON_FILESYSTEM_DISPOSITION_OPEN,         "Open" },
        { PROCMON_FILESYSTEM_DISPOSITION_CREATE,       "Create" },
        { PROCMON_FILESYSTEM_DISPOSITION_OPEN_IF,      "Open If" },
        { PROCMON_FILESYSTEM_DISPOSITION_OVERWRITE,    "Overwrite" },
        { PROCMON_FILESYSTEM_DISPOSITION_OVERWRITE_IF, "Overwrite If" },
        { 0, NULL }
};

static const value_string filesystem_open_result_vals[] = {
        { 0, "Superseded" },
        { 1, "Opened" },
        { 2, "Created" },
        { 3, "Overwritten" },
        { 4, "Exists" },
        { 5, "Does Not Exists" },
        { 0, NULL }
};

static const value_string filesystem_readwrite_priority_vals[] = {
        { 0, "" },
        { 1, "Very Low" },
        { 2, "Low" },
        { 3, "Normal" },
        { 4, "High" },
        { 5, "Critical" },
        { 0, NULL }
};

static const value_string ioctl_code_vals[] = {
    {0x24058, "IOCTL_CDROM_GET_CONFIGURATION"},
    {0x24800, "IOCTL_CDROM_CHECK_VERIFY"},
    {0x24804, "IOCTL_CDROM_MEDIA_REMOVAL"},
    {0x24808, "IOCTL_CDROM_EJECT_MEDIA"},
    {0x2480c, "IOCTL_CDROM_LOAD_MEDIA"},
    {0x41018, "IOCTL_SCSI_GET_ADDRESS"},
    {0x41020, "IOCTL_SCSI_GET_DUMP_POINTERS"},
    {0x41024, "IOCTL_SCSI_FREE_DUMP_POINTERS"},
    {0x4d004, "IOCTL_SCSI_PASS_THROUGH"},
    {0x4d014, "IOCTL_SCSI_PASS_THROUGH_DIRECT"},
    {0x60190, "FSCTL_DFS_TRANSLATE_PATH"},
    {0x60194, "FSCTL_DFS_GET_REFERRALS"},
    {0x60198, "FSCTL_DFS_REPORT_INCONSISTENCY"},
    {0x6019c, "FSCTL_DFS_IS_SHARE_IN_DFS"},
    {0x601a0, "FSCTL_DFS_IS_ROOT"},
    {0x601a4, "FSCTL_DFS_GET_VERSION"},
    {0x70000, "IOCTL_DISK_GET_DRIVE_GEOMETRY"},
    {0x70014, "IOCTL_DISK_VERIFY"},
    {0x70020, "IOCTL_DISK_PERFORMANCE"},
    {0x70024, "IOCTL_DISK_IS_WRITABLE"},
    {0x70028, "IOCTL_DISK_LOGGING"},
    {0x70030, "IOCTL_DISK_HISTOGRAM_STRUCTURE"},
    {0x70034, "IOCTL_DISK_HISTOGRAM_DATA"},
    {0x70038, "IOCTL_DISK_HISTOGRAM_RESET"},
    {0x7003c, "IOCTL_DISK_REQUEST_STRUCTURE"},
    {0x70040, "IOCTL_DISK_REQUEST_DATA"},
    {0x70048, "IOCTL_DISK_GET_PARTITION_INFO_EX"},
    {0x70050, "IOCTL_DISK_GET_DRIVE_LAYOUT_EX"},
    {0x70060, "IOCTL_DISK_PERFORMANCE_OFF"},
    {0x700a0, "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX"},
    {0x700f0, "IOCTL_DISK_GET_DISK_ATTRIBUTES"},
    {0x70140, "IOCTL_DISK_UPDATE_PROPERTIES"},
    {0x70214, "IOCTL_DISK_GET_CLUSTER_INFO"},
    {0x70c00, "IOCTL_DISK_GET_MEDIA_TYPES"},
    {0x74004, "IOCTL_DISK_GET_PARTITION_INFO"},
    {0x7400c, "IOCTL_DISK_GET_DRIVE_LAYOUT"},
    {0x7405c, "IOCTL_DISK_GET_LENGTH_INFO"},
    {0x74080, "SMART_GET_VERSION"},
    {0x740d4, "IOCTL_DISK_GET_CACHE_INFORMATION"},
    {0x74800, "IOCTL_DISK_CHECK_VERIFY"},
    {0x74804, "IOCTL_DISK_MEDIA_REMOVAL"},
    {0x74808, "IOCTL_DISK_EJECT_MEDIA"},
    {0x7480c, "IOCTL_DISK_LOAD_MEDIA"},
    {0x74810, "IOCTL_DISK_RESERVE"},
    {0x74814, "IOCTL_DISK_RELEASE"},
    {0x74818, "IOCTL_DISK_FIND_NEW_DEVICES"},
    {0x7c008, "IOCTL_DISK_SET_PARTITION_INFO"},
    {0x7c010, "IOCTL_DISK_SET_DRIVE_LAYOUT"},
    {0x7c018, "IOCTL_DISK_FORMAT_TRACKS"},
    {0x7c01c, "IOCTL_DISK_REASSIGN_BLOCKS"},
    {0x7c02c, "IOCTL_DISK_FORMAT_TRACKS_EX"},
    {0x7c04c, "IOCTL_DISK_SET_PARTITION_INFO_EX"},
    {0x7c054, "IOCTL_DISK_SET_DRIVE_LAYOUT_EX"},
    {0x7c058, "IOCTL_DISK_CREATE_DISK"},
    {0x7c084, "SMART_SEND_DRIVE_COMMAND"},
    {0x7c088, "SMART_RCV_DRIVE_DATA"},
    {0x7c0a4, "IOCTL_DISK_REASSIGN_BLOCKS_EX"},
    {0x7c0c8, "IOCTL_DISK_UPDATE_DRIVE_SIZE"},
    {0x7c0d0, "IOCTL_DISK_GROW_PARTITION"},
    {0x7c0d8, "IOCTL_DISK_SET_CACHE_INFORMATION"},
    {0x7c0f4, "IOCTL_DISK_SET_DISK_ATTRIBUTES"},
    {0x7c218, "IOCTL_DISK_SET_CLUSTER_INFO"},
    {0x90000, "FSCTL_REQUEST_OPLOCK_LEVEL_1"},
    {0x90004, "FSCTL_REQUEST_OPLOCK_LEVEL_2"},
    {0x90008, "FSCTL_REQUEST_BATCH_OPLOCK"},
    {0x9000c, "FSCTL_OPLOCK_BREAK_ACKNOWLEDGE"},
    {0x90010, "FSCTL_OPBATCH_ACK_CLOSE_PENDING"},
    {0x90014, "FSCTL_OPLOCK_BREAK_NOTIFY"},
    {0x90018, "FSCTL_LOCK_VOLUME"},
    {0x9001c, "FSCTL_UNLOCK_VOLUME"},
    {0x90020, "FSCTL_DISMOUNT_VOLUME"},
    {0x90028, "FSCTL_IS_VOLUME_MOUNTED"},
    {0x9002c, "FSCTL_IS_PATHNAME_VALID"},
    {0x90030, "FSCTL_MARK_VOLUME_DIRTY"},
    {0x9003b, "FSCTL_QUERY_RETRIEVAL_POINTERS"},
    {0x9003c, "FSCTL_GET_COMPRESSION"},
    {0x90050, "FSCTL_OPLOCK_BREAK_ACK_NO_2"},
    {0x90058, "FSCTL_QUERY_FAT_BPB"},
    {0x9005c, "FSCTL_REQUEST_FILTER_OPLOCK"},
    {0x90060, "FSCTL_FILESYSTEM_GET_STATISTICS"},
    {0x90064, "FSCTL_GET_NTFS_VOLUME_DATA"},
    {0x90068, "FSCTL_GET_NTFS_FILE_RECORD"},
    {0x9006f, "FSCTL_GET_VOLUME_BITMAP"},
    {0x90073, "FSCTL_GET_RETRIEVAL_POINTERS"},
    {0x90074, "FSCTL_MOVE_FILE"},
    {0x90078, "FSCTL_IS_VOLUME_DIRTY"},
    {0x90083, "FSCTL_ALLOW_EXTENDED_DASD_IO"},
    {0x90087, "FSCTL_READ_PROPERTY_DATA"},
    {0x9008b, "FSCTL_WRITE_PROPERTY_DATA"},
    {0x9008f, "FSCTL_FIND_FILES_BY_SID"},
    {0x90097, "FSCTL_DUMP_PROPERTY_DATA"},
    {0x90098, "FSCTL_SET_OBJECT_ID"},
    {0x9009c, "FSCTL_GET_OBJECT_ID"},
    {0x900a0, "FSCTL_DELETE_OBJECT_ID"},
    {0x900a4, "FSCTL_SET_REPARSE_POINT"},
    {0x900a8, "FSCTL_GET_REPARSE_POINT"},
    {0x900ac, "FSCTL_DELETE_REPARSE_POINT"},
    {0x900b3, "FSCTL_ENUM_USN_DATA"},
    {0x900bb, "FSCTL_READ_USN_JOURNAL"},
    {0x900bc, "FSCTL_SET_OBJECT_ID_EXTENDED"},
    {0x900c0, "FSCTL_CREATE_OR_GET_OBJECT_ID"},
    {0x900c4, "FSCTL_SET_SPARSE"},
    {0x900d7, "FSCTL_SET_ENCRYPTION"},
    {0x900db, "FSCTL_ENCRYPTION_FSCTL_IO"},
    {0x900df, "FSCTL_WRITE_RAW_ENCRYPTED" },
    {0x900e3, "FSCTL_READ_RAW_ENCRYPTED" },
    {0x900e7, "FSCTL_CREATE_USN_JOURNAL" },
    {0x900eb, "FSCTL_READ_FILE_USN_DATA" },
    {0x900ef, "FSCTL_WRITE_USN_CLOSE_RECORD" },
    {0x900f0, "FSCTL_EXTEND_VOLUME" },
    {0x900f4, "FSCTL_QUERY_USN_JOURNAL" },
    {0x900f8, "FSCTL_DELETE_USN_JOURNAL" },
    {0x900fc, "FSCTL_MARK_HANDLE" },
    {0x90100, "FSCTL_SIS_COPYFILE" },
    {0x90120, "FSCTL_FILE_PREFETCH" },
    {0x901af, "CSC_FSCTL_OPERATION_QUERY_HANDLE" },
    {0x901f0, "FSCTL_QUERY_DEPENDENT_VOLUME" },
    {0x90230, "FSCTL_GET_BOOT_AREA_INFO" },
    {0x90240, "FSCTL_REQUEST_OPLOCK" },
    {0x90244, "FSCTL_CSV_TUNNEL_REQUEST" },
    {0x9024c, "FSCTL_QUERY_FILE_SYSTEM_RECOGNITION" },
    {0x90254, "FSCTL_CSV_GET_VOLUME_NAME_FOR_VOLUME_MOUNT_POINT" },
    {0x90258, "FSCTL_CSV_GET_VOLUME_PATH_NAMES_FOR_VOLUME_NAME" },
    {0x9025c, "FSCTL_IS_FILE_ON_CSV_VOLUME" },
    {0x90260, "FSCTL_CORRUPTION_HANDLING" },
    {0x90270, "FSCTL_SET_PURGE_FAILURE_MODE" },
    {0x90277, "FSCTL_QUERY_FILE_LAYOUT" },
    {0x90278, "FSCTL_IS_VOLUME_OWNED_BYCSVFS" },
    {0x9027c, "FSCTL_GET_INTEGRITY_INFORMATION" },
    {0x90284, "FSCTL_QUERY_FILE_REGIONS" },
    {0x902b0, "FSCTL_SCRUB_DATA" },
    {0x902b8, "FSCTL_DISABLE_LOCAL_BUFFERING" },
    {0x9030c, "FSCTL_SET_EXTERNAL_BACKING" },
    {0x90310, "FSCTL_GET_EXTERNAL_BACKING" },
    {0x940b7, "FSCTL_SECURITY_ID_CHECK" },
    {0x940cf, "FSCTL_QUERY_ALLOCATED_RANGES" },
    {0x941e4, "FSCTL_TXFS_LIST_TRANSACTIONS" },
    {0x94264, "FSCTL_OFFLOAD_READ" },
    {0x980c8, "FSCTL_SET_ZERO_DATA" },
    {0x980d0, "FSCTL_ENABLE_UPGRADE" },
    {0x98208, "FSCTL_FILE_LEVEL_TRIM" },
    {0x98268, "FSCTL_OFFLOAD_WRITE" },
    {0x9c040, "FSCTL_SET_COMPRESSION" },
    {0x9c104, "FSCTL_SIS_LINK_FILES" },
    {0x9c108, "FSCTL_HSM_MSG" },
    {0x9c2b4, "FSCTL_REPAIR_COPIES" },
    {0xc4003, "FSCTL_MAILSLOT_PEEK" },
    {0x110000, "FSCTL_PIPE_ASSIGN_EVENT" },
    {0x110004, "FSCTL_PIPE_DISCONNECT" },
    {0x110008, "FSCTL_PIPE_LISTEN" },
    {0x110010, "FSCTL_PIPE_QUERY_EVENT" },
    {0x110018, "FSCTL_PIPE_WAIT" },
    {0x11001c, "FSCTL_PIPE_IMPERSONATE" },
    {0x110020, "FSCTL_PIPE_SET_CLIENT_PROCESS" },
    {0x110024, "FSCTL_QUERY_CLIENT_PROCESS" },
    {0x11400c, "FSCTL_PIPE_PEEK" },
    {0x116000, "FSCTL_PIPE_INTERNAL_READ" },
    {0x119ff8, "FSCTL_PIPE_INTERNAL_WRITE" },
    {0x11c017, "FSCTL_PIPE_TRANSCEIVE" },
    {0x11dfff, "FSCTL_PIPE_INTERNAL_TRANSCEIVE" },
    {0x140191, "FSCTL_LMR_START" },
    {0x140193, "IOCTL_SMBMRX_START" },
    {0x140194, "FSCTL_LMR_STOP" },
    {0x140197, "IOCTL_SMBMRX_STOP" },
    {0x140198, "IOCTL_SMBMRX_GETSTATE" },
    {0x140199, "FSCTL_NETWORK_SET_CONFIGURATION_INFO" },
    {0x14019e, "FSCTL_NETWORK_GET_CONFIGURATION_INFO" },
    {0x1401a3, "FSCTL_NETWORK_GET_CONNECTION_INFO" },
    {0x1401a7, "FSCTL_NETWORK_ENUMERATE_CONNECTIONS" },
    {0x1401ab, "FSCTL_LMR_FORCE_DISCONNECT" },
    {0x1401ac, "FSCTL_NETWORK_DELETE_CONNECTION" },
    {0x1401b0, "FSCTL_LMR_BIND_TO_TRANSPORT" },
    {0x1401b4, "FSCTL_LMR_UNBIND_FROM_TRANSPORT" },
    {0x1401bb, "FSCTL_LMR_ENUMERATE_TRANSPORTS" },
    {0x1401c4, "FSCTL_LMR_GET_HINT_SIZE" },
    {0x1401c8, "FSCTL_LMR_TRANSACT" },
    {0x1401cc, "FSCTL_LMR_ENUMERATE_PRINT_INFO" },
    {0x1401d0, "FSCTL_NETWORK_GET_STATISTICS" },
    {0x1401d4, "FSCTL_LMR_START_SMBTRACE" },
    {0x1401d8, "FSCTL_LMR_END_SMBTRACE" },
    {0x1401dc, "FSCTL_LMR_START_RBR" },
    {0x1401e0, "FSCTL_NETWORK_SET_DOMAIN_NAME" },
    {0x1401e4, "FSCTL_LMR_SET_SERVER_GUID" },
    {0x1401e8, "FSCTL_LMR_QUERY_TARGET_INFO" },
    {0x1401ec, "FSCTL_LMR_QUERY_DEBUG_INFO" },
    {0x1401f4, "IOCTL_SMBMRX_ADDCONN" },
    {0x1401f8, "IOCTL_SMBMRX_DELCONN" },
    {0x140378, "IOCTL_UMRX_RELEASE_THREADS" },
    {0x14037e, "IOCTL_UMRX_GET_REQUEST" },
    {0x140382, "IOCTL_UMRX_RESPONSE_AND_REQUEST" },
    {0x140386, "IOCTL_UMRX_RESPONSE" },
    {0x140388, "IOCTL_UMRX_GET_LOCK_OWNER" },
    {0x14038c, "IOCTL_LMR_QUERY_REMOTE_SERVER_NAME" },
    {0x140390, "IOCTL_LMR_DISABLE_LOCAL_BUFFERING" },
    {0x140394, "IOCTL_UMRX_PREPARE_QUEUE" },
    {0x140397, "IOCTL_LMR_LWIO_POSTIO" },
    {0x14039b, "IOCTL_LMR_LWIO_PREIO" },
    {0x1403e8, "FSCTL_NETWORK_REMOTE_BOOT_INIT_SCRT" },
    {0x140fdb, "IOCTL_SHADOW_END_REINT" },
    {0x140fff, "IOCTL_GETSHADOW" },
    {0x2d0800, "IOCTL_STORAGE_CHECK_VERIFY2" },
    {0x2d080c, "IOCTL_STORAGE_LOAD_MEDIA2" },
    {0x2d0940, "IOCTL_STORAGE_EJECTION_CONTROL" },
    {0x2d0944, "IOCTL_STORAGE_MCN_CONTROL" },
    {0x2d0c00, "IOCTL_STORAGE_GET_MEDIA_TYPES" },
    {0x2d0c04, "IOCTL_STORAGE_GET_MEDIA_TYPES_EX" },
    {0x2d0c10, "IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER" },
    {0x2d0c14, "IOCTL_STORAGE_GET_HOTPLUG_INFO" },
    {0x2d1080, "IOCTL_STORAGE_GET_DEVICE_NUMBER" },
    {0x2d1100, "IOCTL_STORAGE_PREDICT_FAILURE" },
    {0x2d1400, "IOCTL_STORAGE_QUERY_PROPERTY" },
    {0x2d4800, "IOCTL_STORAGE_CHECK_VERIFY" },
    {0x2d4804, "IOCTL_STORAGE_MEDIA_REMOVAL" },
    {0x2d4808, "IOCTL_STORAGE_EJECT_MEDIA" },
    {0x2d480c, "IOCTL_STORAGE_LOAD_MEDIA" },
    {0x2d4810, "IOCTL_STORAGE_RESERVE" },
    {0x2d4814, "IOCTL_STORAGE_RELEASE" },
    {0x2d4818, "IOCTL_STORAGE_FIND_NEW_DEVICES" },
    {0x2d5000, "IOCTL_STORAGE_RESET_BUS" },
    {0x2d5004, "IOCTL_STORAGE_RESET_DEVICE" },
    {0x2d5014, "IOCTL_STORAGE_BREAK_RESERVATION" },
    {0x2d5018, "IOCTL_STORAGE_PERSISTENT_RESERVE_IN" },
    {0x2d5140, "IOCTL_STORAGE_READ_CAPACITY" },
    {0x2d518c, "IOCTL_STORAGE_QUERY_DEPENDENT_DISK" },
    {0x2dcc18, "IOCTL_STORAGE_SET_HOTPLUG_INFO" },
    {0x2dd01c, "IOCTL_STORAGE_PERSISTENT_RESERVE_OUT" },
    {0x38a813, "IOCTL_CHANNEL_GET_SNDCHANNEL" },
    {0x4d0000, "IOCTL_MOUNTDEV_QUERY_UNIQUE_ID" },
    {0x4d0004, "IOCTL_MOUNTDEV_UNIQUE_ID_CHANGE_NOTIFY" },
    {0x4d0008, "IOCTL_MOUNTDEV_QUERY_DEVICE_NAME" },
    {0x4d000c, "IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME" },
    {0x4d0010, "IOCTL_MOUNTDEV_LINK_CREATED" },
    {0x4d0014, "IOCTL_MOUNTDEV_LINK_DELETED" },
    {0x530018, "IOCTL_VOLSNAP_QUERY_NAMES_OF_SNAPSHOTS" },
    {0x530024, "IOCTL_VOLSNAP_QUERY_DIFF_AREA" },
    {0x53002c, "IOCTL_VOLSNAP_QUERY_DIFF_AREA_SIZES" },
    {0x530034, "IOCTL_VOLSNAP_AUTO_CLEANUP" },
    {0x53003c, "IOCTL_VOLSNAP_QUERY_REVERT" },
    {0x530040, "IOCTL_VOLSNAP_REVERT_CLEANUP" },
    {0x530048, "IOCTL_VOLSNAP_QUERY_REVERT_PROGRESS" },
    {0x53004c, "IOCTL_VOLSNAP_CANCEL_REVERT" },
    {0x530050, "IOCTL_VOLSNAP_QUERY_EPIC" },
    {0x53005e, "IOCTL_VOLSNAP_QUERY_COPY_FREE_BITMAP" },
    {0x530190, "IOCTL_VOLSNAP_QUERY_ORIGINAL_VOLUME_NAME" },
    {0x53019c, "IOCTL_VOLSNAP_QUERY_CONFIG_INFO" },
    {0x5301a0, "IOCTL_VOLSNAP_HAS_CHANGED" },
    {0x5301a4, "IOCTL_VOLSNAP_SET_SNAPSHOT_PRIORITY" },
    {0x5301a8, "IOCTL_VOLSNAP_QUERY_SNAPSHOT_PRIORITY" },
    {0x5301ae, "IOCTL_VOLSNAP_QUERY_DELTA_BITMAP" },
    {0x5301b2, "IOCTL_VOLSNAP_QUERY_SNAPSHOT_SUPPLEMENTAL" },
    {0x5301b6, "IOCTL_VOLSNAP_QUERY_COPIED_BITMAP" },
    {0x5301b8, "IOCTL_VOLSNAP_QUERY_MOVE_LIST" },
    {0x5301be, "IOCTL_VOLSNAP_QUERY_PRE_COPIED_BITMAP" },
    {0x5301c2, "IOCTL_VOLSNAP_QUERY_USED_PRE_COPIED_BITMAP" },
    {0x5301c6, "IOCTL_VOLSNAP_QUERY_DEFRAG_PRE_COPIED_BITMAP" },
    {0x5301ca, "IOCTL_VOLSNAP_QUERY_FREESPACE_PRE_COPIED_BITMAP" },
    {0x5301ce, "IOCTL_VOLSNAP_QUERY_HOTBLOCKS_PRE_COPIED_BITMAP" },
    {0x5301d0, "IOCTL_VOLSNAP_QUERY_DIFF_AREA_FILE_SIZES" },
    {0x534054, "IOCTL_VOLSNAP_QUERY_OFFLINE" },
    {0x534058, "IOCTL_VOLSNAP_QUERY_DIFF_AREA_MINIMUM_SIZE" },
    {0x534064, "IOCTL_VOLSNAP_BLOCK_DELETE_IN_THE_MIDDLE" },
    {0x534070, "IOCTL_VOLSNAP_QUERY_APPLICATION_FLAGS" },
    {0x534080, "IOCTL_VOLSNAP_QUERY_PERFORMANCE_COUNTERS" },
    {0x534088, "IOCTL_VOLSNAP_QUERY_PRE_COPY_AMOUNTS" },
    {0x53408c, "IOCTL_VOLSNAP_QUERY_DEFAULT_PRE_COPY_AMOUNTS" },
    {0x53c000, "IOCTL_VOLSNAP_FLUSH_AND_HOLD_WRITES" },
    {0x53c004, "IOCTL_VOLSNAP_RELEASE_WRITES" },
    {0x53c008, "IOCTL_VOLSNAP_PREPARE_FOR_SNAPSHOT" },
    {0x53c00c, "IOCTL_VOLSNAP_ABORT_PREPARED_SNAPSHOT" },
    {0x53c010, "IOCTL_VOLSNAP_COMMIT_SNAPSHOT" },
    {0x53c014, "IOCTL_VOLSNAP_END_COMMIT_SNAPSHOT" },
    {0x53c01c, "IOCTL_VOLSNAP_CLEAR_DIFF_AREA" },
    {0x53c020, "IOCTL_VOLSNAP_ADD_VOLUME_TO_DIFF_AREA" },
    {0x53c028, "IOCTL_VOLSNAP_SET_MAX_DIFF_AREA_SIZE" },
    {0x53c030, "IOCTL_VOLSNAP_DELETE_OLDEST_SNAPSHOT" },
    {0x53c038, "IOCTL_VOLSNAP_DELETE_SNAPSHOT" },
    {0x53c044, "IOCTL_VOLSNAP_REVERT" },
    {0x53c068, "IOCTL_VOLSNAP_SET_MAX_DIFF_AREA_SIZE_TEMP" },
    {0x53c06c, "IOCTL_VOLSNAP_SET_APPLICATION_FLAGS" },
    {0x53c07c, "IOCTL_VOLSNAP_SET_BC_FAILURE_MODE" },
    {0x53c084, "IOCTL_VOLSNAP_SET_PRE_COPY_AMOUNTS" },
    {0x53c090, "IOCTL_VOLSNAP_PRE_EXPOSE_DEVICES" },
    {0x53c198, "IOCTL_VOLSNAP_SET_APPLICATION_INFO" },
    {0x560000, "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS" },
    {0x560038, "IOCTL_VOLUME_GET_GPT_ATTRIBUTES" },
    {0x700010, "IOCTL_DISK_QUERY_DEVICE_STATE" },
    {0x704008, "IOCTL_DISK_QUERY_DISK_SIGNATURE" },
    { 0, NULL }
};
static value_string_ext ioctl_code_vals_ext = VALUE_STRING_EXT_INIT(ioctl_code_vals);


static const value_string sync_type_vals[] = {
        { 0x0, "Other" },
        { 0x1, "Create Section" },
        { 0, NULL }
};

static const value_string page_protection_vals[] = {
        { 0x0, "None" },
        { 0x01, "No Access" },
        { 0x02, "Read Only" },
        { 0x04, "Read/Write" },
        { 0x08, "Write Copy" },
        { 0x10, "Execute" },
        { 0x20, "Execute Read" },
        { 0x40, "Execute Read/Write" },
        { 0x200, "No Cache" },
        { 0, NULL }
};

static const value_string file_information_class_vals[] = {
        {0, "Unknown"},
        {1, "File Directory Information"},
        {2, "File Full Directory Information"},
        {3, "File Both Directory Information"},
        {4, "File Basic Information"},
        {5, "File Standard Information"},
        {6, "File Internal Information"},
        {7, "File Ea Information"},
        {8, "File Access Information"},
        {9, "File Name Information"},
        {10, "File Rename Information"},
        {11, "File Link Information"},
        {12, "File Names Information"},
        {13, "File Disposition Information"},
        {14, "File Position Information"},
        {15, "File Full Ea Information"},
        {16, "File Mode Information"},
        {17, "File Alignment Information"},
        {18, "File All Information"},
        {19, "File Allocation Information"},
        {20, "File End Of File Information"},
        {21, "File Alternate Name Information"},
        {22, "File Stream Information"},
        {23, "File Pipe Information"},
        {24, "File Pipe Local Information"},
        {25, "File Pipe Remote Information"},
        {26, "File Mailslot Query Information"},
        {27, "File Mailslot Set Information"},
        {28, "File Compression Information"},
        {29, "File ObjectId Information"},
        {30, "File Completion Information"},
        {31, "File Move Cluster Information"},
        {32, "File Quota Information"},
        {33, "File Reparse Point Information"},
        {34, "File Network Open Information"},
        {35, "File Attribute Tag Information"},
        {36, "File Tracking Information"},
        {37, "File Id Both Directory Information"},
        {38, "File Id Full Directory Information"},
        {39, "File Valid Data Length Information"},
        {40, "File Short Name Information"},
        {41, "File Io Completion Notification Information"},
        {42, "File Io Status Block Range Information"},
        {43, "File Io Priority Hint Information"},
        {44, "File Sfio Reserve Information"},
        {45, "File Sfio Volume Information"},
        {46, "File Hard Link Information"},
        {47, "File Process Ids Using File Information"},
        {48, "File Normalized Name Information"},
        {49, "File Network Physical Name Information"},
        {50, "File Id Global Tx Directory Information"},
        {51, "File Is Remote Device Information"},
        {52, "File Unused Information"},
        {53, "File Numa Node Information"},
        {54, "File Standard Link Information"},
        {55, "File Remote Protocol Information"},
        {56, "File Rename Information Bypass Access Check"},
        {57, "File Link Information Bypass Access Check"},
        {58, "File Volume Name Information"},
        {59, "File Id Information"},
        {60, "File Id Extended Directory Information"},
        {61, "File Replace Completion Information"},
        {62, "File Hard Link Full Id Information"},
        {63, "File Id Extended Both Directory Information"},
        {64, "File Disposition Information Ex"},
        {65, "File Rename Information Ex"},
        {66, "File Rename Information Ex Bypass Access Check"},
        {67, "File Desired Storage Class Information"},
        {68, "File Stat Information"},
        {69, "File Memory Partition Information"},
        {70, "File Maximum Information"},
        {71, "SeShutdownPrivilege"},
        {72, "SeChangeNotifyPrivilege"},
        {73, "SeUndockPrivilege"},
        {74, "SeIncreaseWorkingSetPrivilege"},
        {75, "SeTimeZonePrivilege"},
        { 0, NULL }
};

static bool dissect_procmon_filesystem_event(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, uint32_t operation, tvbuff_t* extra_details_tvb)
{
    proto_tree* filesystem_tree;
    int offset = 0, extra_offset = 0;
    uint32_t sub_operation, ioctl_value = 0, file_information_class = 0;
    int size_of_pointer;
    bool is_path_ascii;
    uint16_t path_char_count;
    const value_string* sub_op_vals = NULL;
    uint32_t file_system_access_mask_mapping[4] = {0x120089, 0x120116, 0x1200a0, 0x1f01ff};
    static const value_string file_system_access_mask_vals[] = {
        {0x1f01ff, "All Access"},
        {0x1201bf, "Generic Read/Write/Execute"},
        {0x12019f, "Generic Read/Write"},
        {0x1200a9, "Generic Read/Execute"},
        {0x1201b6, "Generic Write/Execute"},
        {0x120089, "Generic Read"},
        {0x120116, "Generic Write"},
        {0x1200a0, "Generic Execute"},
        {0x1, "Read Data/List Directory"},
        {0x2, "Write Data/Add File"},
        {0x4, "Append Data/Add Subdirectory/Create Pipe Instance"},
        {0x8, "Read EA"},
        {0x10, "Write EA"},
        {0x20, "Execute/Traverse"},
        {0x40, "Delete Child"},
        {0x80, "Read Attributes"},
        {0x100, "Write Attributes"},
        {0x10000, "Delete"},
        {0x20000, "Read Control"},
        {0x40000, "Write DAC"},
        {0x80000, "Write Owner"},
        {0x100000, "Synchronize"},
        {0x1000000, "Access System Security"},
        {0x2000000, "Maximum Allowed"},
        { 0, NULL }
    };
    static const value_string file_system_io_flags_vals[] = {
        {0x10, "Buffered"},
        {0x1, "Non-cached"},
        {0x2, "Paging I/O"},
        {0x4, "Synchronous"},
        {0x40, "Synchronous Paging I/O"},
        {0x400000, "Write Through"},
        { 0, NULL }
    };

    if (pinfo->pseudo_header->procmon.system_bitness)
    {
        size_of_pointer = 8;
    }
    else
    {
        size_of_pointer = 4;
    }

    filesystem_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_procmon_filesystem_event, NULL, "File System Data");

    /* Handle the cases where the Sub operation value string is based on the operation */
    sub_operation = tvb_get_uint8(tvb, offset);
    switch(operation)
    {
    case PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE:
        sub_op_vals = filesystem_operation_query_info_vals;
        break;
    case PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE:
        sub_op_vals = filesystem_operation_set_info_vals;
        break;
    case PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION:
        sub_op_vals = filesystem_operation_query_volume_info_vals;
        break;
    case PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION:
        sub_op_vals = filesystem_operation_set_volume_info_vals;
        break;
    case PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL:
        sub_op_vals = filesystem_operation_directory_control_vals;
        break;
    case PROCMON_FILESYSTEM_OPERATION_PLUG_AND_PLAY:
        sub_op_vals = filesystem_operation_pnp_vals;
        break;
    case PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE:
        sub_op_vals = filesystem_operation_lock_unlock_file_vals;
        break;
    }
    if (sub_op_vals != NULL)
    {
        proto_tree_add_uint_format_value(filesystem_tree, hf_procmon_filesystem_suboperation, tvb, offset, 1, sub_operation, "%s (%u)",
            val_to_str_const(sub_operation, sub_op_vals, "Unknown"), sub_operation);
    }
    else
    {
        proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_suboperation, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }
    offset += 1;
    proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_padding, tvb, offset, 3, ENC_NA);
    offset += 3;

    switch(operation)
    {
        case PROCMON_FILESYSTEM_OPERATION_CREATE_FILE:
        {
            static const value_string file_system_create_file_options_vals[] = {
                {0x1, "Directory"},
                {0x2, "Write Through"},
                {0x4, "Sequential Access"},
                {0x8, "No Buffering"},
                {0x10, "Synchronous IO Alert"},
                {0x20, "Synchronous IO Non-Alert"},
                {0x40, "Non-Directory File"},
                {0x80, "Create Tree Connection"},
                {0x100, "Complete If Oplocked"},
                {0x200, "No EA Knowledge"},
                {0x400, "Open for Recovery"},
                {0x800, "Random Access"},
                {0x1000, "Delete On Close"},
                {0x2000, "Open By ID"},
                {0x4000, "Open For Backup"},
                {0x8000, "No Compression"},
                {0x100000, "Reserve OpFilter"},
                {0x200000, "Open Reparse Point"},
                {0x400000, "Open No Recall"},
                {0x800000, "Open For Free Space Query"},
                {0x10000, "Open Requiring Oplock"},
                {0x20000, "Disallow Exclusive"},
                { 0, NULL }
            };

            static const value_string file_system_create_file_attribute_vals[] = {
                {0x1, "R"},
                {0x2, "H"},
                {0x4, "S"},
                {0x10, "D"},
                {0x20, "A"},
                {0x40, "D"},
                {0x80, "N"},
                {0x100, "T"},
                {0x200, "SF"},
                {0x400, "RP"},
                {0x800, "C"},
                {0x1000, "O"},
                {0x2000, "NCI"},
                {0x4000, "E"},
                {0x10000, "V"},
                { 0, NULL }
            };

            static const value_string file_system_create_file_shared_mode_vals[] = {
                {0x1, "Read"},
                {0x2, "Write"},
                {0x4, "Delete"},
                { 0, NULL }
            };

            int create_file_offset;
            if (size_of_pointer == 4)
            {
                create_file_offset = offset+16;
            }
            else
            {
                create_file_offset = offset+20; //Padding for 64-bit
            }

            proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_create_file_disposition, tvb, create_file_offset, 1, ENC_LITTLE_ENDIAN);
            create_file_offset += 1;
            dissect_procmon_access_mask(tvb, pinfo, filesystem_tree, create_file_offset, hf_procmon_filesystem_create_file_options, 3, NULL, file_system_create_file_options_vals);
            create_file_offset += 3;

            if (size_of_pointer == 8)
                create_file_offset += 4; //Padding for 64-bit

            uint16_t attributes = tvb_get_letohs(tvb, create_file_offset);
            if (attributes == 0)
            {
                proto_tree_add_uint_format_value(filesystem_tree, hf_procmon_filesystem_create_file_attributes, tvb, create_file_offset, 2, attributes, "N/A");
            }
            else
            {
                dissect_procmon_access_mask(tvb, pinfo, filesystem_tree, create_file_offset, hf_procmon_filesystem_create_file_attributes, 3, NULL, file_system_create_file_attribute_vals);
            }
            create_file_offset += 2;
            dissect_procmon_access_mask(tvb, pinfo, filesystem_tree, create_file_offset, hf_procmon_filesystem_create_file_share_mode, 2, NULL, file_system_create_file_shared_mode_vals);
            create_file_offset += 2;

            //Unknown fields
            create_file_offset += (4 + size_of_pointer*2);

            proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_create_file_allocation, tvb, create_file_offset, 4, ENC_LITTLE_ENDIAN);
            create_file_offset += 4;

            if (tvb_reported_length(extra_details_tvb) > 0)
            {
                proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_create_file_open_result, extra_details_tvb, extra_offset, 4, ENC_LITTLE_ENDIAN);
                extra_offset += 4;
            }

            break;
        }
        case PROCMON_FILESYSTEM_OPERATION_READ_FILE:
        case PROCMON_FILESYSTEM_OPERATION_WRITE_FILE:
        {
            int file_offset = offset;
            //Unknown fields
            file_offset += 4;

            dissect_procmon_access_mask(tvb, pinfo, filesystem_tree, file_offset, hf_procmon_filesystem_readwrite_file_io_flags, 4, NULL, file_system_io_flags_vals);
            proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_readwrite_file_priority, tvb, file_offset, 4, ENC_LITTLE_ENDIAN);
            file_offset += 4;

            //Unknown fields
            file_offset += 4;

            proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_readwrite_file_length, tvb, file_offset, 4, ENC_LITTLE_ENDIAN);
            file_offset += 4;
            if (size_of_pointer == 8)
                file_offset += 4; //Padding for 64-bit

            //Unknown fields
            file_offset += 4;
            if (size_of_pointer == 8)
                file_offset += 4; //Padding for 64-bit

            proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_readwrite_file_offset, tvb, file_offset, 8, ENC_LITTLE_ENDIAN);
            if (tvb_reported_length(extra_details_tvb) > 0)
            {
                proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_readwrite_file_result_length, extra_details_tvb, extra_offset, 4, ENC_LITTLE_ENDIAN);
                extra_offset += 4;
            }

            break;
        }
        case PROCMON_FILESYSTEM_OPERATION_FILE_SYSTEM_CONTROL:
        case PROCMON_FILESYSTEM_OPERATION_DEVICE_IO_CONTROL:
        {
            int control_offset = offset;
            //Unknown fields
            control_offset += 8;

            proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_ioctl_write_length, tvb, control_offset, 4, ENC_LITTLE_ENDIAN);
            control_offset += 4;
            proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_ioctl_read_length, tvb, control_offset, 4, ENC_LITTLE_ENDIAN);
            control_offset += 4;

            if (size_of_pointer == 8)
                control_offset += 4; //Padding for 64-bit

            //Unknown fields
            control_offset += 4;
            if (size_of_pointer == 8)
                control_offset += 4; //Padding for 64-bit

            ioctl_value = tvb_get_letohl(tvb, control_offset);
            if (try_val_to_str_ext(ioctl_value, &ioctl_code_vals_ext) == NULL)
            {
                proto_tree_add_uint_format_value(filesystem_tree, hf_procmon_filesystem_ioctl_ioctl, tvb, control_offset, 4, ioctl_value,
                                "0x%08x (Device:0x%08x Function:%d Method: %d)", ioctl_value, ioctl_value >> 16, (ioctl_value >> 2) & 0xfff, ioctl_value & 3);
            }
            else
            {
                proto_tree_add_uint(filesystem_tree, hf_procmon_filesystem_ioctl_ioctl, tvb, control_offset, 4, ioctl_value);
            }
            control_offset += 4;

            break;
        }
        case PROCMON_FILESYSTEM_OPERATION_CREATE_FILE_MAPPING:
        {
            int mapping_offset = offset;
            //Unknown fields
            mapping_offset += 12;
            proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_create_file_mapping_sync_type, tvb, mapping_offset, 4, ENC_LITTLE_ENDIAN);
            mapping_offset += 4;
            proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_create_file_mapping_page_protection, tvb, mapping_offset, 4, ENC_LITTLE_ENDIAN);
            break;
        }
        case PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL:
        {
            int control_offset = offset;
            switch(sub_operation)
            {
            case PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL_QUERY:
                //Unknown fields
                control_offset += 16;
                if (size_of_pointer == 8)
                    control_offset += 4; //Padding for 64-bit
                //Unknown fields
                control_offset += 4;
                if (size_of_pointer == 8)
                    control_offset += 4; //Padding for 64-bit

                proto_tree_add_item_ret_uint(filesystem_tree, hf_procmon_filesystem_directory_control_file_information_class, tvb, control_offset, 4, ENC_LITTLE_ENDIAN, &file_information_class);
                if (tvb_reported_length(extra_details_tvb) > 0)
                {
                    nstime_t timestamp;
                    uint32_t name_length, next_entry_offset;
                    switch (file_information_class)
                    {
                    case 1: // File Directory Information
                    case 2: // File Full Directory Information
                    case 3: // File Both Directory Information
                    case 12: // File Names Information
                    case 37: // File Id Both Directory Information
                    case 38: // File Id Full Directory Information
                        do
                        {
                            int start_extra_offset = extra_offset;
                            proto_item* information_item;
                            proto_tree* information_tree = proto_tree_add_subtree(filesystem_tree, extra_details_tvb, extra_offset, 0, ett_procmon_filesystem_information, &information_item, "Information");

                            proto_tree_add_item_ret_uint(information_tree, hf_procmon_filesystem_directory_control_query_next_entry_offset, extra_details_tvb, extra_offset, 4, ENC_LITTLE_ENDIAN, &next_entry_offset);
                            extra_offset += 4;
                            proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_file_index, extra_details_tvb, extra_offset, 4, ENC_LITTLE_ENDIAN);
                            extra_offset += 4;
                            if (file_information_class == 12)
                            {
                                // File Names Information
                                proto_tree_add_item_ret_uint(information_tree, hf_procmon_filesystem_directory_control_query_name_length, extra_details_tvb, extra_offset, 4, ENC_LITTLE_ENDIAN, &name_length);
                                extra_offset += 4;
                                proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_name, extra_details_tvb, extra_offset, name_length, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                                extra_offset += name_length;
                                proto_item_set_len(information_item, extra_offset-start_extra_offset);
                                continue;
                            }

                            filetime_to_nstime(&timestamp, tvb_get_letoh64(extra_details_tvb, extra_offset));
                            proto_tree_add_time(information_tree, hf_procmon_filesystem_directory_control_query_creation_time, extra_details_tvb, extra_offset, 8, &timestamp);
                            extra_offset += 8;
                            filetime_to_nstime(&timestamp, tvb_get_letoh64(extra_details_tvb, extra_offset));
                            proto_tree_add_time(information_tree, hf_procmon_filesystem_directory_control_query_last_access_time, extra_details_tvb, extra_offset, 8, &timestamp);
                            extra_offset += 8;
                            filetime_to_nstime(&timestamp, tvb_get_letoh64(extra_details_tvb, extra_offset));
                            proto_tree_add_time(information_tree, hf_procmon_filesystem_directory_control_query_last_write_time, extra_details_tvb, extra_offset, 8, &timestamp);
                            extra_offset += 8;
                            filetime_to_nstime(&timestamp, tvb_get_letoh64(extra_details_tvb, extra_offset));
                            proto_tree_add_time(information_tree, hf_procmon_filesystem_directory_control_query_change_time, extra_details_tvb, extra_offset, 8, &timestamp);
                            extra_offset += 8;
                            proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_end_of_file, extra_details_tvb, extra_offset, 8, ENC_LITTLE_ENDIAN);
                            extra_offset += 8;
                            proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_allocation_size, extra_details_tvb, extra_offset, 8, ENC_LITTLE_ENDIAN);
                            extra_offset += 8;
                            proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_file_attributes, extra_details_tvb, extra_offset, 4, ENC_LITTLE_ENDIAN);
                            extra_offset += 4;
                            proto_tree_add_item_ret_uint(information_tree, hf_procmon_filesystem_directory_control_query_name_length, extra_details_tvb, extra_offset, 4, ENC_LITTLE_ENDIAN, &name_length);
                            extra_offset += 4;
                            if (file_information_class == 1)
                            {
                                proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_name, extra_details_tvb, extra_offset, name_length, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                                extra_offset += name_length;
                                proto_item_set_len(information_item, extra_offset - start_extra_offset);
                                continue;
                            }
                            proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_file_ea_size, extra_details_tvb, extra_offset, 4, ENC_LITTLE_ENDIAN);
                            extra_offset += 4;
                            if (file_information_class == 2)
                            {
                                proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_name, extra_details_tvb, extra_offset, name_length, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                                extra_offset += name_length;
                                proto_item_set_len(information_item, extra_offset - start_extra_offset);
                                continue;
                            }
                            if (file_information_class == 38)
                            {
                                proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_file_id, extra_details_tvb, extra_offset, 8, ENC_LITTLE_ENDIAN);
                                extra_offset += 8;
                                proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_name, extra_details_tvb, extra_offset, name_length, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                                extra_offset += name_length;
                                proto_item_set_len(information_item, extra_offset - start_extra_offset);
                                continue;
                            }
                            proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_short_name_length, extra_details_tvb, extra_offset, 1, ENC_LITTLE_ENDIAN);
                            extra_offset += 1;
                            proto_tree_add_item(information_tree, hf_procmon_filesystem_padding, extra_details_tvb, extra_offset, 1, ENC_NA);
                            extra_offset += 1;
                            proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_short_name, extra_details_tvb, extra_offset, 24, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                            extra_offset += 24;
                            if (file_information_class == 3)
                            {
                                proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_name, extra_details_tvb, extra_offset, name_length, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                                extra_offset += name_length;
                                proto_item_set_len(information_item, extra_offset - start_extra_offset);
                                continue;
                            }
                            proto_tree_add_item(information_tree, hf_procmon_filesystem_padding, extra_details_tvb, extra_offset, 2, ENC_NA);
                            extra_offset += 2;
                            proto_tree_add_item(information_tree, hf_procmon_filesystem_directory_control_query_name, extra_details_tvb, extra_offset, name_length, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                            extra_offset += name_length;
                            proto_item_set_len(information_item, extra_offset - start_extra_offset);
                        }
                        while ((tvb_reported_length_remaining(extra_details_tvb, extra_offset) > 0) && (next_entry_offset != 0));
                        break;
                    }
                }
                break;
            case PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL_NOTIFY_CHANGE:
            {
                static const value_string file_system_create_notify_change_flags_vals[] = {
                    {0x1, "FILE_NOTIFY_CHANGE_FILE_NAME"},
                    {0x2, "FILE_NOTIFY_CHANGE_DIR_NAME"},
                    {0x3, "FILE_NOTIFY_CHANGE_NAME"},
                    {0x4, "FILE_NOTIFY_CHANGE_ATTRIBUTES"},
                    {0x8, "FILE_NOTIFY_CHANGE_SIZE"},
                    {0x10, "FILE_NOTIFY_CHANGE_LAST_WRITE"},
                    {0x20, "FILE_NOTIFY_CHANGE_LAST_ACCESS"},
                    {0x40, "FILE_NOTIFY_CHANGE_CREATION"},
                    {0x80, "FILE_NOTIFY_CHANGE_EA"},
                    {0x100, "FILE_NOTIFY_CHANGE_SECURITY"},
                    {0x200, "FILE_NOTIFY_CHANGE_STREAM_NAME"},
                    {0x400, "FILE_NOTIFY_CHANGE_STREAM_SIZE"},
                    {0x800, "FILE_NOTIFY_CHANGE_STREAM_WRITE"},
                    { 0, NULL }
                };

                //Unknown fields
                control_offset += 16;
                if (size_of_pointer == 8)
                    control_offset += 4; //Padding for 64-bit

                dissect_procmon_access_mask(tvb, pinfo, filesystem_tree, control_offset, hf_procmon_filesystem_directory_control_notify_change_flags, 4, NULL, file_system_create_notify_change_flags_vals);
                break;
            }
            default:
                proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_details, tvb, offset, 5 * size_of_pointer + 20, ENC_NA);
                break;
            }
            break;
        }
        default:
            proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_details, tvb, offset, 5 * size_of_pointer + 20, ENC_NA);
            break;
    }
    offset += (5 * size_of_pointer + 20);

    dissect_procmon_detail_string_info(tvb, filesystem_tree, offset,
        hf_procmon_filesystem_path_size, hf_procmon_filesystem_path_is_ascii, hf_procmon_filesystem_path_char_count, ett_procmon_filesystem_path,
        &is_path_ascii, &path_char_count);
    offset += 2;
    proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_padding, tvb, offset, 2, ENC_NA);
    offset += 2;
    offset = dissect_procmon_detail_string(tvb, filesystem_tree, offset, is_path_ascii, path_char_count, hf_procmon_filesystem_path);

    switch(operation)
    {
        case PROCMON_FILESYSTEM_OPERATION_CREATE_FILE:
        {
            uint32_t sid_length;
            dissect_procmon_access_mask(tvb, pinfo, filesystem_tree, offset, hf_procmon_filesystem_create_file_access_mask, 4, file_system_access_mask_mapping, file_system_access_mask_vals);
            offset += 4;
            proto_tree_add_item_ret_uint(filesystem_tree, hf_procmon_filesystem_create_file_impersonating_sid_length, tvb, offset, 1, ENC_LITTLE_ENDIAN, &sid_length);
            offset += 1;
            proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_padding, tvb, offset, 3, ENC_NA);
            offset += 3;
            if (sid_length > 0)
            {
                uint32_t revision, count, value;
                uint64_t identifier_authority;
                int sid_offset = offset;
                proto_item* sid_item;
                wmem_strbuf_t* impersonating_strbuf = wmem_strbuf_new(pinfo->pool, "S-");
                proto_tree* impersonating_tree = proto_tree_add_subtree(filesystem_tree, tvb, sid_offset, sid_length, ett_procmon_filesystem_create_file_impersonating, &sid_item, "Impersonating SID");
                proto_tree_add_item_ret_uint(impersonating_tree, hf_procmon_filesystem_create_file_sid_revision, tvb, sid_offset, 1, ENC_LITTLE_ENDIAN, &revision);
                sid_offset += 1;
                proto_tree_add_item_ret_uint(impersonating_tree, hf_procmon_filesystem_create_file_sid_count, tvb, sid_offset, 1, ENC_LITTLE_ENDIAN, &count);
                sid_offset += 1;
                proto_tree_add_item_ret_uint64(impersonating_tree, hf_procmon_filesystem_create_file_sid_authority, tvb, sid_offset, 6, ENC_BIG_ENDIAN, &identifier_authority);
                sid_offset += 6;
                wmem_strbuf_append_printf(impersonating_strbuf, "%u-%012" PRIx64, revision, identifier_authority);
                for (uint32_t i = 0; i < count; i++)
                {
                    proto_tree_add_item_ret_uint(impersonating_tree, hf_procmon_filesystem_create_file_sid_value, tvb, sid_offset, 4, ENC_LITTLE_ENDIAN, &value);
                    wmem_strbuf_append_printf(impersonating_strbuf, "-%08x", value);
                    sid_offset += 4;
                }
                proto_item* sid_string_item = proto_tree_add_string(impersonating_tree, hf_procmon_filesystem_create_file_impersonating, tvb, offset, sid_offset - offset, wmem_strbuf_get_str(impersonating_strbuf));
                PROTO_ITEM_SET_GENERATED(sid_string_item);
                proto_item_append_text(sid_item, " (%s)", wmem_strbuf_get_str(impersonating_strbuf));
            }
            break;
        }
        case PROCMON_FILESYSTEM_OPERATION_FILE_SYSTEM_CONTROL:
        case PROCMON_FILESYSTEM_OPERATION_DEVICE_IO_CONTROL:
            switch (ioctl_value)
            {
            case 0x94264:   // FSCTL_OFFLOAD_READ
                offset += 8;
                proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_ioctl_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;
                proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_ioctl_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;
                break;
            case 0x98268:   // FSCTL_OFFLOAD_WRITE
                proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_ioctl_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;
                proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_ioctl_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;
                break;
            }
            break;

        case PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL:
            dissect_procmon_detail_string_info(tvb, filesystem_tree, offset,
                hf_procmon_filesystem_directory_size, hf_procmon_filesystem_directory_is_ascii, hf_procmon_filesystem_directory_char_count, ett_procmon_filesystem_directory,
                &is_path_ascii, &path_char_count);
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, filesystem_tree, offset, is_path_ascii, path_char_count, hf_procmon_filesystem_directory);
            break;

        case PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE:
            switch (sub_operation)
            {
            case PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE_DISPOSITION:
                proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_set_info_file_disposition_delete, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
                proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_padding, tvb, offset, 3, ENC_NA);
                offset += 3;
                break;
            }
            break;

        default:
            break;
    }

    return (extra_offset > 0);
}

#define PROCMON_PROFILING_OPERATION_THREAD       0x0000
#define PROCMON_PROFILING_OPERATION_PROCESS      0x0001
#define PROCMON_PROFILING_OPERATION_DEBUG_OUTPUT 0x0002

static const value_string profiling_operation_vals[] = {
        { PROCMON_PROFILING_OPERATION_THREAD,       "Thread" },
        { PROCMON_PROFILING_OPERATION_PROCESS,      "Process" },
        { PROCMON_PROFILING_OPERATION_DEBUG_OUTPUT, "Debug Output" },
        { 0, NULL }
};

static bool dissect_procmon_profiling_event(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, uint32_t operation, tvbuff_t* extra_details_tvb _U_)
{
    int offset = 0;

    proto_tree_add_subtree(tree, tvb, offset, -1, ett_procmon_profiling_event, NULL, "Profiling Data");

    switch(operation)
    {
        case PROCMON_PROFILING_OPERATION_THREAD:
        case PROCMON_PROFILING_OPERATION_PROCESS:
        case PROCMON_PROFILING_OPERATION_DEBUG_OUTPUT:
            //Unknown
            break;
        default:
            break;
    }

    return false;
}

#define PROCMON_NETWORK_OPERATION_UNKNOWN       0x0000
#define PROCMON_NETWORK_OPERATION_OTHER         0x0001
#define PROCMON_NETWORK_OPERATION_SEND          0x0002
#define PROCMON_NETWORK_OPERATION_RECEIVE       0x0003
#define PROCMON_NETWORK_OPERATION_ACCEPT        0x0004
#define PROCMON_NETWORK_OPERATION_CONNECT       0x0005
#define PROCMON_NETWORK_OPERATION_DISCONNECT    0x0006
#define PROCMON_NETWORK_OPERATION_RECONNECT     0x0007
#define PROCMON_NETWORK_OPERATION_RETRANSMIT    0x0008
#define PROCMON_NETWORK_OPERATION_TCP_COPY      0x0009

static const value_string network_operation_vals[] = {
        { PROCMON_NETWORK_OPERATION_UNKNOWN,    "Unknown" },
        { PROCMON_NETWORK_OPERATION_OTHER,      "Other" },
        { PROCMON_NETWORK_OPERATION_SEND,       "Send" },
        { PROCMON_NETWORK_OPERATION_RECEIVE,    "Receive" },
        { PROCMON_NETWORK_OPERATION_ACCEPT,     "Accept" },
        { PROCMON_NETWORK_OPERATION_CONNECT,    "Connect" },
        { PROCMON_NETWORK_OPERATION_DISCONNECT, "Disconnect" },
        { PROCMON_NETWORK_OPERATION_RECONNECT,  "Reconnect" },
        { PROCMON_NETWORK_OPERATION_RETRANSMIT, "Retransmit" },
        { PROCMON_NETWORK_OPERATION_TCP_COPY,   "TCP Copy" },
        { 0, NULL }
};

static const true_false_string tfs_tcp_udp = { "TCP", "UDP" };

#define NETWORK_FLAG_IS_SRC_IPv4_MASK   0x0001
#define NETWORK_FLAG_IS_DEST_IPv4_MASK  0x0002
#define NETWORK_FLAG_IS_TCP_MASK        0x0004

static bool dissect_procmon_network_event(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, uint32_t operation _U_, tvbuff_t* extra_details_tvb _U_)
{
    proto_tree* network_event_tree;
    int offset = 0;
    uint16_t flags;
    int detail_length, detail_offset;
    uint8_t* detail_substring;
    wmem_strbuf_t* details = wmem_strbuf_new(pinfo->pool, "");
    static int* const network_flags_vals[] = {
            &hf_procmon_network_flags_is_src_ipv4,
            &hf_procmon_network_flags_is_dst_ipv4,
            &hf_procmon_network_flags_tcp_udp,
            NULL
    };

    network_event_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_procmon_network_event, NULL, "Network Data");

    proto_tree_add_bitmask_with_flags(network_event_tree, tvb, offset, hf_procmon_network_flags, ett_procmon_network_flags, network_flags_vals, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
    flags = tvb_get_letohs(tvb, offset);
    offset += 2;

    //Unknown fields
    offset += 2;

    proto_tree_add_item(network_event_tree, hf_procmon_network_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (flags & NETWORK_FLAG_IS_SRC_IPv4_MASK)
    {
        proto_tree_add_item(network_event_tree, hf_procmon_network_src_ipv4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(network_event_tree, hf_procmon_network_padding, tvb, offset, 12, ENC_NA);
        offset += 12;
    }
    else
    {
        proto_tree_add_item(network_event_tree, hf_procmon_network_src_ipv6, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
        offset += IPv6_ADDR_SIZE;
    }
    if (flags & NETWORK_FLAG_IS_DEST_IPv4_MASK)
    {
        proto_tree_add_item(network_event_tree, hf_procmon_network_dest_ipv4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(network_event_tree, hf_procmon_network_padding, tvb, offset, 12, ENC_NA);
        offset += 12;
    }
    else
    {
        proto_tree_add_item(network_event_tree, hf_procmon_network_dest_ipv6, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
        offset += IPv6_ADDR_SIZE;
    }
    proto_tree_add_item(network_event_tree, hf_procmon_network_src_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(network_event_tree, hf_procmon_network_dest_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    detail_offset = offset;
    while (((detail_substring = tvb_get_stringz_enc(pinfo->pool, tvb, offset, &detail_length, ENC_UTF_16 | ENC_LITTLE_ENDIAN)) != NULL) && (strlen(detail_substring) > 0))
    {
        wmem_strbuf_append_printf(details, " %s", detail_substring);
        offset += detail_length;
    }
    //Include the NULL string at the end of the list
    offset += 2;
    proto_tree_add_string(network_event_tree, hf_procmon_network_details, tvb, detail_offset, offset-detail_offset, wmem_strbuf_get_str(details));

    return false;
}

static int
dissect_procmon_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *ti_event, *ti_operation;
    proto_tree *procmon_tree, *header_tree, *stack_trace_tree;
    int         offset = 0;
    int         size_of_pointer;
    uint32_t event_class, operation;
    uint32_t stack_trace_size, details_size, extra_details_offset;
    nstime_t timestamp;
    uint16_t extra_details_size = 0;
    int hf_operation;
    const value_string* operation_vs = NULL;
    bool handle_extra_details = false;
    tvbuff_t *details_tvb, *extra_details_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, "MS Procmon Event");

    ti = proto_tree_add_item(tree, proto_procmon, tvb, 0, -1, ENC_NA);
    procmon_tree = proto_item_add_subtree(ti, ett_procmon);

    header_tree = proto_tree_add_subtree(procmon_tree, tvb, offset, 52, ett_procmon_header, NULL, "Event Header");

    proto_tree_add_item(header_tree, hf_procmon_process_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(header_tree, hf_procmon_thread_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    ti_event = proto_tree_add_item_ret_uint(header_tree, hf_procmon_event_class, tvb, offset, 4, ENC_LITTLE_ENDIAN, &event_class);
    offset += 4;

    switch (event_class)
    {
    case PROCMON_EVENT_CLASS_TYPE_PROCESS:
        operation_vs = process_operation_vals;
        hf_operation = hf_procmon_process_operation;
        break;
    case PROCMON_EVENT_CLASS_TYPE_REGISTRY:
        operation_vs = registry_operation_vals;
        hf_operation = hf_procmon_registry_operation;
        break;
    case PROCMON_EVENT_CLASS_TYPE_FILE_SYSTEM:
        operation_vs = filesystem_operation_vals;
        hf_operation = hf_procmon_filesystem_operation;
        break;
    case PROCMON_EVENT_CLASS_TYPE_PROFILING:
        operation_vs = profiling_operation_vals;
        hf_operation = hf_procmon_profiling_operation;
        break;
    case PROCMON_EVENT_CLASS_TYPE_NETWORK:
        operation_vs = network_operation_vals;
        hf_operation = hf_procmon_network_operation;
        break;
    default:
        hf_operation = hf_procmon_operation_type;
        break;
    }
    ti_operation = proto_tree_add_item_ret_uint(header_tree, hf_operation, tvb, offset, 2, ENC_LITTLE_ENDIAN, &operation);
    offset += 2;

    if (operation_vs != NULL)
    {
        const char* event_class_str = val_to_str_const(event_class, event_class_vals, "Unknown");
        const char* operation_str = try_val_to_str(operation, operation_vs);
        if (operation_str == NULL)
        {
            expert_add_info_format(pinfo, ti_operation, &ei_procmon_unknown_operation, "Unknown %s operation: 0x%04x", event_class_str, operation);
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s Operation: Unknown (0x%04x)", event_class_str, operation);
        }
        else
        {
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s Operation: %s", event_class_str, operation_str);
        }
    }

    //Next 6 bytes are unknown
    offset += 6;
    proto_tree_add_item(header_tree, hf_procmon_duration, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    filetime_to_nstime(&timestamp, tvb_get_letoh64(tvb, offset));
    proto_tree_add_time(header_tree, hf_procmon_timestamp, tvb, offset, 8, &timestamp);
    offset += 8;
    proto_tree_add_item(header_tree, hf_procmon_event_result, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(header_tree, hf_procmon_stack_trace_depth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    //Next 2 bytes are unknown
    offset += 2;
    proto_tree_add_item_ret_uint(header_tree, hf_procmon_details_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &details_size);
    offset += 4;
    proto_tree_add_item_ret_uint(header_tree, hf_procmon_extra_details_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &extra_details_offset);
    offset += 4;

    //Stack trace size part of the record
    stack_trace_size = tvb_get_letohl(tvb, offset);
    offset += 4;
    if (stack_trace_size > 0)
    {
        stack_trace_tree = proto_tree_add_subtree(procmon_tree, tvb, offset, stack_trace_size, ett_procmon_stack_trace, NULL, "Stack Trace");
        if (pinfo->pseudo_header->procmon.system_bitness)
        {
            size_of_pointer = 8;
        }
        else
        {
            size_of_pointer = 4;
        }
        for (uint32_t i = 0; i < stack_trace_size; i += size_of_pointer)
        {
            proto_tree_add_item(stack_trace_tree, hf_procmon_stack_trace_address, tvb, offset, size_of_pointer, ENC_LITTLE_ENDIAN);
            offset += size_of_pointer;
        }
    }


    details_tvb = tvb_new_subset_length(tvb, offset, details_size);
    offset += details_size;
    if (extra_details_offset > 0)
    {
        extra_details_size = tvb_get_letohs(tvb, offset);
        offset += 2;
    }

    extra_details_tvb = tvb_new_subset_length(tvb, offset, extra_details_size);
    switch(event_class)
    {
        case PROCMON_EVENT_CLASS_TYPE_PROCESS:
            handle_extra_details = dissect_procmon_process_event(details_tvb, pinfo, procmon_tree, operation, extra_details_tvb);
            break;
        case PROCMON_EVENT_CLASS_TYPE_REGISTRY:
            handle_extra_details = dissect_procmon_registry_event(details_tvb, pinfo, procmon_tree, operation, extra_details_tvb);
            break;
        case PROCMON_EVENT_CLASS_TYPE_FILE_SYSTEM:
            handle_extra_details = dissect_procmon_filesystem_event(details_tvb, pinfo, procmon_tree, operation, extra_details_tvb);
            break;
        case PROCMON_EVENT_CLASS_TYPE_PROFILING:
            handle_extra_details = dissect_procmon_profiling_event(details_tvb, pinfo, procmon_tree, operation, extra_details_tvb);
            break;
        case PROCMON_EVENT_CLASS_TYPE_NETWORK:
            handle_extra_details = dissect_procmon_network_event(details_tvb, pinfo, procmon_tree, operation, extra_details_tvb);
            break;
        default:
            expert_add_info(pinfo, ti_event, &ei_procmon_unknown_event_class);
            proto_tree_add_item(procmon_tree, hf_procmon_detail_data, details_tvb, 0, details_size, ENC_NA);
            break;
    }

    if ((extra_details_size > 0) && (!handle_extra_details))
    {
        proto_tree_add_item(procmon_tree, hf_procmon_extra_detail_data, tvb, offset, extra_details_size, ENC_NA);
        offset += extra_details_size;
    }

    return offset;
}

/*
 * Register the protocol with Wireshark.
 */
void
proto_register_procmon(void)
{
    static hf_register_info hf[] = {
        { &hf_procmon_process_index,
          { "Process Index", "procmon.process_index",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_thread_id,
          { "Thread ID", "procmon.thread_id",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_event_class,
          { "Event Class", "procmon.event_class",
            FT_UINT32, BASE_DEC, VALS(event_class_vals), 0, NULL, HFILL}
        },
        { &hf_procmon_operation_type,
          { "Operation Type", "procmon.operation_type",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_duration,
          { "Duration", "procmon.duration",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_timestamp,
          { "Timestamp", "procmon.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_event_result,
          { "Event Result", "procmon.event_result",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_stack_trace_depth,
          { "Stack Trace Depth", "procmon.stack_trace_depth",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_details_size,
          { "Details Size", "procmon.details_size",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_extra_details_offset,
          { "Extra Details Offset", "procmon.extra_details_offset",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_stack_trace_address,
          { "Stack trace address", "procmon.stack_trace_address",
            FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_detail_data,
          { "Detail Data", "procmon.detail_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_extra_detail_data,
          { "Extra detail data", "procmon.extra_detail_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_operation,
          { "Operation Type", "procmon.process.operation_type",
            FT_UINT16, BASE_DEC, VALS(process_operation_vals), 0, NULL, HFILL}
        },
        { &hf_procmon_process_pid,
          { "PID", "procmon.process.pid",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_path,
          { "Path", "procmon.process.path",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_path_size,
          { "Path Size", "procmon.process.path.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_path_is_ascii,
          { "Is ASCII", "procmon.process.path.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_path_char_count,
          { "Char Count", "procmon.process.path.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_commandline,
          { "Commandline", "procmon.process.commandline",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_commandline_size,
          { "Commandline Size", "procmon.process.commandline.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_commandline_is_ascii,
          { "Is ASCII", "procmon.process.commandline.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_commandline_char_count,
          { "Char Count", "procmon.process.commandline.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_exit_status,
          { "Exit Status", "procmon.process.exit_status",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_kernel_time,
          { "Kernel time", "procmon.process.kernel_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_user_time,
          { "User time", "procmon.process.user_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_working_set,
          { "Working Set", "procmon.process.working_set",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_peak_working_set,
          { "Peak Working Set", "procmon.process.peak_working_set",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_private_bytes,
          { "Private Bytes", "procmon.process.private_bytes",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_peak_private_bytes,
          { "Peak Private Bytes", "procmon.process.peak_private_bytes",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_thread_id,
          { "Thread ID", "procmon.process.thread_id",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_image_base,
          { "Image Base", "procmon.process.image_base",
            FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_image_size,
          { "Image Size", "procmon.process.image_size",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_parent_pid,
          { "Parent PID", "procmon.process.parent_pid",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_curdir,
          { "Current Directory", "procmon.process.curdir",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_curdir_size,
          { "Current Directory Size", "procmon.process.curdir.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_curdir_is_ascii,
          { "Is ASCII", "procmon.process.curdir.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_curdir_char_count,
          { "Char Count", "procmon.process.curdir.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_environment_char_count,
          { "Environment Size", "procmon.process.environment.char_count",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_environment,
          { "Environment", "procmon.process.environment",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_operation,
          { "Operation Type", "procmon.registry.operation_type",
            FT_UINT16, BASE_DEC, VALS(registry_operation_vals), 0, NULL, HFILL }
        },
        { &hf_procmon_registry_desired_access,
          { "Desired Access", "procmon.registry.desired_access",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_granted_access,
          { "Granted Access", "procmon.registry.granted_access",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_disposition,
          { "Disposition", "procmon.registry.disposition",
            FT_UINT32, BASE_DEC, VALS(registry_disposition_vals), 0, NULL, HFILL}
        },
        { &hf_procmon_registry_key,
          { "Key", "procmon.registry.key",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_size,
          { "Key Size", "procmon.registry.key.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_is_ascii,
          { "Is ASCII", "procmon.registry.key.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_key_char_count,
          { "Char Count", "procmon.registry.key.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_new_key,
          { "New Key", "procmon.registry.new_key",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_new_key_size,
          { "New Key Size", "procmon.registry.new_key.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_new_key_is_ascii,
          { "Is ASCII", "procmon.registry.new_key.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_new_key_char_count,
          { "Char Count", "procmon.registry.new_key.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_value,
          { "Value", "procmon.registry.value",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_size,
          { "Value Size", "procmon.registry.value.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_is_ascii,
          { "Is ASCII", "procmon.registry.value.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_value_char_count,
          { "Char Count", "procmon.registry.value.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_length,
          { "Length", "procmon.registry.length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_information_class,
          { "Information Class", "procmon.registry.key.information_class",
            FT_UINT32, BASE_DEC, VALS(registry_key_information_class_vals), 0, NULL, HFILL}
        },
        { &hf_procmon_registry_key_set_information_class,
          { "Information Class", "procmon.registry.key.set_information_class",
            FT_UINT32, BASE_DEC, VALS(registry_value_set_information_class_vals), 0, NULL, HFILL}
        },
        { &hf_procmon_registry_value_information_class,
          { "Information Class", "procmon.registry.value.information_class",
            FT_UINT32, BASE_DEC, VALS(registry_value_information_class_vals), 0, NULL, HFILL}
        },
        { &hf_procmon_registry_index,
          { "Index", "procmon.registry.index",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_type,
          { "Type", "procmon.registry.type",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_data_length,
          { "Data Length", "procmon.registry.data_length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_name_size,
          { "Name Size", "procmon.registry.key.name_size",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_name,
          { "Name", "procmon.registry.key.name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_handle_tags,
          { "Handle Tags", "procmon.registry.key.handle_tags",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_flags,
          { "Flags", "procmon.registry.key.flags",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_last_write_time,
          { "Last Write Time", "procmon.registry.key.last_write_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_title_index,
          { "Title Index", "procmon.registry.key.title_index",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_subkeys,
          { "Subkeys", "procmon.registry.key.subkeys",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_max_name_len,
          { "Max Name Length", "procmon.registry.key.max_name_len",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_values,
          { "Values", "procmon.registry.key.values",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_max_value_name_len,
          { "Max Value Name Length", "procmon.registry.key.max_value_name_len",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_max_value_data_len,
          { "Max Value Data Length", "procmon.registry.key.max_value_data_len",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_class_offset,
          { "Class Offset", "procmon.registry.key.class_offset",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_class_length,
          { "Class Length", "procmon.registry.key.class_length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_max_class_len,
          { "Max Class Length", "procmon.registry.key.max_class_len",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_reg_type,
          { "Registry Type", "procmon.registry.value.reg_type",
            FT_UINT32, BASE_DEC, VALS(registry_value_reg_type_vals), 0, NULL, HFILL}
        },
        { &hf_procmon_registry_value_offset_to_data,
          { "Offset to Data", "procmon.registry.value.offset_to_data",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_length,
          { "Length", "procmon.registry.value.length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_name_size,
          { "Name Size", "procmon.registry.value.name_size",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_name,
          { "Name", "procmon.registry.value.name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_dword,
          { "DWORD", "procmon.registry.value.dword",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_qword,
          { "QWORD", "procmon.registry.value.qword",
            FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_sz,
          { "SZ", "procmon.registry.value.sz",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_binary,
          { "Binary", "procmon.registry.value.binary",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_multi_sz,
          { "MultiSZ", "procmon.registry.value.multi_sz",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_set_information_write_time,
          { "Last Write Time", "procmon.registry.key.set_information.write_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_set_information_wow64_flags,
          { "WOW64 Flags", "procmon.registry.key.set_information.wow64_flags",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_set_information_handle_tags,
          { "Handle Tags", "procmon.registry.key.set_information.handle_tags",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_operation,
          { "Operation Type", "procmon.filesystem.operation_type",
            FT_UINT16, BASE_DEC, VALS(filesystem_operation_vals), 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_suboperation,
          { "Suboperation", "procmon.filesystem.suboperation",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_padding,
          { "Padding", "procmon.filesystem.padding",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_details,
          { "Details", "procmon.filesystem.details",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_path,
          { "Path", "procmon.filesystem.path",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_path_size,
          { "Path Size", "procmon.filesystem.path.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_path_is_ascii,
          { "Is ASCII", "procmon.filesystem.path.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_filesystem_path_char_count,
          { "Char Count", "procmon.filesystem.path.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_access_mask,
          { "File Access Mask", "procmon.filesystem.create_file.access_mask",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_impersonating_sid_length,
          { "Impersonating SID Length", "procmon.filesystem.create_file.impersonating_sid_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_impersonating,
          { "Impersonating", "procmon.filesystem.create_file.impersonating",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_disposition,
          { "Disposition", "procmon.filesystem.create_file.disposition",
            FT_UINT8, BASE_DEC, VALS(filesystem_disposition_vals), 0, NULL, HFILL}
        },
        { &hf_procmon_filesystem_create_file_options,
          { "Options", "procmon.filesystem.create_file.options",
            FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_attributes,
          { "Attributes", "procmon.filesystem.create_file.attributes",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_share_mode,
          { "Share Mode", "procmon.filesystem.create_file.share_mode",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_allocation,
          { "Allocation", "procmon.filesystem.create_file.allocation",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_sid_revision,
          { "Revision", "procmon.filesystem.create_file.sid.revision",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_sid_count,
          { "Count", "procmon.filesystem.create_file.sid.count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_sid_authority,
          { "Authority", "procmon.filesystem.create_file.sid.authority",
            FT_UINT48, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_sid_value,
          { "Value", "procmon.filesystem.create_file.sid.value",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_open_result,
          { "Open Result", "procmon.filesystem.create_file.open_result",
            FT_UINT32, BASE_DEC, VALS(filesystem_open_result_vals), 0, NULL, HFILL}
        },
        { &hf_procmon_filesystem_readwrite_file_io_flags,
          { "IO Flags", "procmon.filesystem.readwrite_file.length",
            FT_UINT32, BASE_HEX, NULL, 0x00EFFFFF, NULL, HFILL }
        },
        { &hf_procmon_filesystem_readwrite_file_priority,
          { "Priority", "procmon.filesystem.readwrite_file.length",
            FT_UINT32, BASE_HEX, VALS(filesystem_readwrite_priority_vals), 0x00E00000, NULL, HFILL}
        },
        { &hf_procmon_filesystem_readwrite_file_length,
          { "Length", "procmon.filesystem.readwrite_file.length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_readwrite_file_offset,
          { "Offset", "procmon.filesystem.readwrite_file.file_offset",
            FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_readwrite_file_result_length,
          { "Result Length", "procmon.filesystem.readwrite_file.result_length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_ioctl_write_length,
          { "Write Length", "procmon.filesystem.ioctl.write_length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_ioctl_read_length,
          { "Read Length", "procmon.filesystem.ioctl.read_length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_ioctl_ioctl,
          { "ioctl", "procmon.filesystem.ioctl.ioctl",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ioctl_code_vals_ext, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_ioctl_offset,
          { "Offset", "procmon.filesystem.ioctl.offset",
            FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_ioctl_length,
          { "Length", "procmon.filesystem.ioctl.length",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_mapping_sync_type,
          { "Sync Type", "procmon.filesystem.create_file_mapping.sync_type",
            FT_UINT32, BASE_HEX, VALS(sync_type_vals), 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_create_file_mapping_page_protection,
          { "Page Protection", "procmon.filesystem.create_file_mapping.page_protection",
            FT_UINT32, BASE_HEX, VALS(page_protection_vals), 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory,
          { "Directory", "procmon.filesystem.directory",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_size,
          { "Directory Size", "procmon.filesystem.directory.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_is_ascii,
          { "Is ASCII", "procmon.filesystem.directory.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_char_count,
          { "Char Count", "procmon.filesystem.directory.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_file_information_class,
          { "File Information Class", "procmon.filesystem.directory_control.file_information_class",
            FT_UINT32, BASE_DEC, VALS(file_information_class_vals), 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_notify_change_flags,
          { "Notify Change Flags", "procmon.filesystem.directory_control.notify_change_flags",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_set_info_file_disposition_delete,
          { "Disposition Delete", "procmon.filesystem.set_info_file.disposition.delete",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_next_entry_offset,
          { "Next Entry Offset", "procmon.filesystem.directory_control.query.next_entry_offset",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_file_index,
          { "File Index", "procmon.filesystem.directory_control.query.file_index",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_name_length,
          { "Name Length", "procmon.filesystem.directory_control.query.name_length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_name,
          { "Name", "procmon.filesystem.directory_control.query.name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_creation_time,
          { "Creation Time", "procmon.filesystem.directory_control.query.creation_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_last_access_time,
          { "Last Access Time", "procmon.filesystem.directory_control.query.last_access_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_last_write_time,
          { "Last Write Time", "procmon.filesystem.directory_control.query.last_write_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_change_time,
          { "Change Time", "procmon.filesystem.directory_control.query.change_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_end_of_file,
          { "End of File", "procmon.filesystem.directory_control.query.end_of_file",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_allocation_size,
          { "Allocation Size", "procmon.filesystem.directory_control.query.allocation_size",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_file_attributes,
          { "File Attributes", "procmon.filesystem.directory_control.query.file_attributes",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_file_ea_size,
          { "EA Size", "procmon.filesystem.directory_control.query.ea_size",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_file_id,
          { "File ID", "procmon.filesystem.directory_control.query.file_id",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_short_name_length,
          { "Name Length", "procmon.filesystem.directory_control.query.short_name_length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_directory_control_query_short_name,
          { "Name", "procmon.filesystem.directory_control.short_name",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_profiling_operation,
          { "Operation Type", "procmon.profiling.operation_type",
            FT_UINT16, BASE_DEC, VALS(profiling_operation_vals), 0, NULL, HFILL }
        },
        { &hf_procmon_network_operation,
          { "Operation Type", "procmon.network.operation_type",
            FT_UINT16, BASE_DEC, VALS(network_operation_vals), 0, NULL, HFILL }
        },
        { &hf_procmon_network_flags,
          { "Flags", "procmon.network.flags",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_flags_is_src_ipv4,
          { "Is Src IPv4", "procmon.network.flags.is_src_ipv4",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }
        },
        { &hf_procmon_network_flags_is_dst_ipv4,
          { "Is Dest IPv4", "procmon.network.flags.is_dst_ipv4",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }
        },
        { &hf_procmon_network_flags_tcp_udp,
          { "TCP/UDP", "procmon.network.flags.tcp_udp",
            FT_BOOLEAN, 16, TFS(&tfs_tcp_udp), 0x0004, NULL, HFILL}
        },
        { &hf_procmon_network_length,
          { "Length", "procmon.network.length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_src_ipv4,
          { "Src IP", "procmon.network.src_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_src_ipv6,
          { "Src IP", "procmon.network.src_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_dest_ipv4,
          { "Dest IP", "procmon.network.dest_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_dest_ipv6,
          { "Dest IP", "procmon.network.dest_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_src_port,
          { "Src Port", "procmon.network.src_port",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_dest_port,
          { "Dest Port", "procmon.network.dest_port",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_padding,
          { "Padding", "procmon.network.padding",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_details,
          { "Details", "procmon.network.details",
            FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }
        },

    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_procmon,
        &ett_procmon_header,
        &ett_procmon_stack_trace,
        &ett_procmon_process_event,
        &ett_procmon_process_path,
        &ett_procmon_process_commandline,
        &ett_procmon_process_curdir,
        &ett_procmon_registry_event,
        &ett_procmon_registry_key,
        &ett_procmon_registry_new_key,
        &ett_procmon_registry_value,
        &ett_procmon_filesystem_event,
        &ett_procmon_filesystem_path,
        &ett_procmon_filesystem_create_file_impersonating,
        &ett_procmon_filesystem_directory,
        &ett_procmon_filesystem_information,
        &ett_procmon_profiling_event,
        &ett_procmon_network_event,
        &ett_procmon_network_flags,
    };

    static ei_register_info ei[] = {
            { &ei_procmon_unknown_event_class, { "procmon.event_class.unknown", PI_UNDECODED, PI_WARN, "Unknown event class", EXPFILL }},
            { &ei_procmon_unknown_operation, { "procmon.operation_type.unknown", PI_UNDECODED, PI_WARN, "Unknown event class", EXPFILL }},
    };

    expert_module_t* expert_procmon;

    /* Register the protocol name and description */
    proto_procmon = proto_register_protocol(PNAME, PSNAME, PFNAME);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_procmon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_procmon = expert_register_protocol(proto_procmon);
    expert_register_field_array(expert_procmon, ei, array_length(ei));

    procmon_handle = register_dissector("procmon", dissect_procmon_event, proto_procmon);
}

void
proto_reg_handoff_procmon(void)
{
    int file_type_subtype_procmon;

    file_type_subtype_procmon = wtap_name_to_file_type_subtype("procmon");
    if (file_type_subtype_procmon != -1)
        dissector_add_uint("wtap_fts_rec", file_type_subtype_procmon, procmon_handle);
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
