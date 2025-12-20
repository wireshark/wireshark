/* packet-xgt.c
 * Routines for XGT (LS ELECTRIC PLC) protocol packet disassembly
 *
 * Copyright 2025, Gihyeon Ryu and the SLiMe team (BoB 14th)
 *
 * XGT is a proprietary protocol used by LS ELECTRIC (formerly LS Industrial Systems)
 * for communication with their XGT series PLCs over Ethernet.
 *
 * Protocol specifications based on:
 * "XGT FEnet I/F Module Protocol Specification" (2005.03.30)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <stdbool.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/wmem_scopes.h>
#include <epan/tfs.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include "packet-tcp.h"
#include <ws_version.h>

/* XGT Protocol Ports */
#define XGT_TCP_PORT 2004
#define XGT_UDP_PORT 2005

/* Company ID */
#define XGT_COMPANY_ID "LSIS-XGT"
#define XGT_COMPANY_ID_LEN 8

/* Header sizes */
#define XGT_HEADER_LEN 20

/* Source of Frame values */
#define XGT_SOURCE_CLIENT 0x33
#define XGT_SOURCE_SERVER 0x11

/* CPU Info */
#define XGT_CPU_INFO_XGK 0xA0
#define XGT_CPU_INFO_XGI 0xA4
#define XGT_CPU_INFO_XGR 0xA8

/* Command codes */
#define XGT_CMD_READ_REQUEST    0x0054
#define XGT_CMD_READ_RESPONSE   0x0055
#define XGT_CMD_WRITE_REQUEST   0x0058
#define XGT_CMD_WRITE_RESPONSE  0x0059
#define XGT_CMD_STATUS_REQUEST  0x00B0
#define XGT_CMD_STATUS_RESPONSE 0x00B1

/* Data types */
#define XGT_DTYPE_BIT    0x00
#define XGT_DTYPE_BYTE   0x01
#define XGT_DTYPE_WORD   0x02
#define XGT_DTYPE_DWORD  0x03
#define XGT_DTYPE_LWORD  0x04
#define XGT_DTYPE_CONTINUOUS 0x14

/* Error status */
#define XGT_ERROR_NONE   0x0000
#define XGT_ERROR_EXISTS 0xFFFF

/* CPU Types */
#define XGT_CPU_TYPE_XGK_CPUH 0x01
#define XGT_CPU_TYPE_XGK_CPUS 0x02
#define XGT_CPU_TYPE_XGI_CPUU 0x05

/* System States */
#define XGT_SYS_STATE_RUN   0x01
#define XGT_SYS_STATE_STOP  0x02
#define XGT_SYS_STATE_ERROR 0x04
#define XGT_SYS_STATE_DEBUG 0x08

void proto_register_xgt(void);
void proto_reg_handoff_xgt(void);

/* Protocol handles */
static int proto_xgt;

/* Conversation data structure for request-response matching */
typedef struct _xgt_conv_info_t {
    wmem_map_t *invoke_id_map;  /* Map: invoke_id -> variable_name */
} xgt_conv_info_t;

/* Header fields */
static int hf_xgt_company_id;
static int hf_xgt_reserved1;
static int hf_xgt_plc_info;
static int hf_xgt_plc_info_cpu_type;
static int hf_xgt_plc_info_redundancy;
static int hf_xgt_plc_info_cpu_error;
static int hf_xgt_plc_info_sys_state;
static int hf_xgt_cpu_info;
static int hf_xgt_source;
static int hf_xgt_invoke_id;
static int hf_xgt_length;
static int hf_xgt_fenet_position;
static int hf_xgt_fenet_slot;
static int hf_xgt_fenet_base;
static int hf_xgt_reserved2;

/* Instruction fields */
static int hf_xgt_command;
static int hf_xgt_data_type;
static int hf_xgt_reserved_area;
static int hf_xgt_error_status;
static int hf_xgt_error_code;
static int hf_xgt_block_count;
static int hf_xgt_variable_count;
static int hf_xgt_variable_length;
static int hf_xgt_variable_name;
static int hf_xgt_data_length;
static int hf_xgt_data;
static int hf_xgt_data_value_uint8;
static int hf_xgt_data_value_uint16;
static int hf_xgt_data_value_uint32;
static int hf_xgt_data_value_uint64;
static int hf_xgt_byte_count;
static int hf_xgt_word;

/* Status fields */
static int hf_xgt_status_data;
static int hf_xgt_slot_info;
static int hf_xgt_cpu_type;
static int hf_xgt_ver_num;
static int hf_xgt_sys_state;
static int hf_xgt_padt_cnf;
static int hf_xgt_cnf_er;
static int hf_xgt_cnf_war;

/* Subtree indices */
static int ett_xgt;
static int ett_xgt_header;
static int ett_xgt_instruction;
static int ett_xgt_plc_info;
static int ett_xgt_fenet_position;
static int ett_xgt_block;
static int ett_xgt_status;

/* Expert info fields */
static expert_field ei_xgt_invalid_length = EI_INIT;
static expert_field ei_xgt_error_response = EI_INIT;
static expert_field ei_xgt_truncated_data = EI_INIT;
static expert_field ei_xgt_invalid_command = EI_INIT;
static expert_field ei_xgt_cpu_error = EI_INIT;
static expert_field ei_xgt_suspicious_count = EI_INIT;

/* Value strings */
static const value_string xgt_command_vals[] = {
    { XGT_CMD_READ_REQUEST,    "Read Request" },
    { XGT_CMD_READ_RESPONSE,   "Read Response" },
    { XGT_CMD_WRITE_REQUEST,   "Write Request" },
    { XGT_CMD_WRITE_RESPONSE,  "Write Response" },
    { XGT_CMD_STATUS_REQUEST,  "Status Request" },
    { XGT_CMD_STATUS_RESPONSE, "Status Response" },
    { 0, NULL }
};

static const value_string xgt_data_type_vals[] = {
    { XGT_DTYPE_BIT,    "BIT" },
    { XGT_DTYPE_BYTE,   "BYTE" },
    { XGT_DTYPE_WORD,   "WORD" },
    { XGT_DTYPE_DWORD,  "DWORD" },
    { XGT_DTYPE_LWORD,  "LWORD" },
    { XGT_DTYPE_CONTINUOUS, "Continuous Block" },
    { 0, NULL }
};

static const value_string xgt_source_vals[] = {
    { XGT_SOURCE_CLIENT, "Client (HMI -> PLC)" },
    { XGT_SOURCE_SERVER, "Server (PLC -> HMI)" },
    { 0, NULL }
};

static const value_string xgt_cpu_info_vals[] = {
    { XGT_CPU_INFO_XGK, "XGK CPU" },
    { XGT_CPU_INFO_XGI, "XGI CPU" },
    { XGT_CPU_INFO_XGR, "XGR CPU" },
    { 0, NULL }
};

static const value_string xgt_cpu_type_vals[] = {
    { XGT_CPU_TYPE_XGK_CPUH, "XGK-CPUH" },
    { XGT_CPU_TYPE_XGK_CPUS, "XGK-CPUS" },
    { XGT_CPU_TYPE_XGI_CPUU, "XGI-CPUU" },
    { 0, NULL }
};

static const value_string xgt_sys_state_vals[] = {
    { XGT_SYS_STATE_RUN,   "RUN" },
    { XGT_SYS_STATE_STOP,  "STOP" },
    { XGT_SYS_STATE_ERROR, "ERROR" },
    { XGT_SYS_STATE_DEBUG, "DEBUG" },
    { 0, NULL }
};

static const value_string xgt_error_status_vals[] = {
    { XGT_ERROR_NONE,   "Success" },
    { XGT_ERROR_EXISTS, "Error" },
    { 0, NULL }
};

/* XGT Error codes (common error codes from protocol spec) */
static const value_string xgt_error_code_vals[] = {
    { 0x0000, "No Error" },
    { 0x1101, "There is no XGT instruction" },
    { 0x1102, "There is no XGT device" },
    { 0x1104, "Invalid data size" },
    { 0x1105, "Invalid data range" },
    { 0x1106, "Data is protected" },
    { 0x1107, "Invalid block number" },
    { 0x1108, "Variable name error" },
    { 0x1109, "Duplicated variable" },
    { 0x110A, "Read not allowed" },
    { 0x110B, "Write not allowed" },
    { 0x1201, "CPU is in STOP mode" },
    { 0x1202, "CPU is in RUN mode" },
    { 0x1203, "CPU module error" },
    { 0x1301, "Password error" },
    { 0x1302, "Mode change not allowed" },
    { 0x1303, "Communication timeout" },
    { 0, NULL }
};

/* True/False strings */
static const true_false_string tfs_slave_master = {
    "Slave",
    "Master"
};

static const true_false_string tfs_error_normal = {
    "Error",
    "Normal"
};

/* Dissect XGT Application Header */
static int
dissect_xgt_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *ti, *plc_info_item;
    proto_tree *header_tree, *plc_info_tree, *fenet_tree;
    unsigned source;
    unsigned fenet_pos;
    unsigned plc_info, data_length;

    /* Bounds check - ensure we have enough data for the header */
    if (tvb_reported_length_remaining(tvb, offset) < XGT_HEADER_LEN) {
        expert_add_info(pinfo, tree, &ei_xgt_truncated_data);
        return tvb_captured_length(tvb);
    }

    ti = proto_tree_add_item(tree, proto_xgt, tvb, offset, XGT_HEADER_LEN, ENC_NA);
    header_tree = proto_item_add_subtree(ti, ett_xgt_header);

    /* Company ID */
    proto_tree_add_item(header_tree, hf_xgt_company_id, tvb, offset, 8, ENC_ASCII);
    offset += 8;

    /* Reserved */
    proto_tree_add_item(header_tree, hf_xgt_reserved1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* PLC Info */
    plc_info_item = proto_tree_add_item_ret_uint(header_tree, hf_xgt_plc_info, tvb, offset, 2, ENC_LITTLE_ENDIAN, &plc_info);
    plc_info_tree = proto_item_add_subtree(plc_info_item, ett_xgt_plc_info);

    proto_tree_add_item(plc_info_tree, hf_xgt_plc_info_cpu_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(plc_info_tree, hf_xgt_plc_info_redundancy, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(plc_info_tree, hf_xgt_plc_info_cpu_error, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(plc_info_tree, hf_xgt_plc_info_sys_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);

    /* Check for CPU error and add expert info */
    if (plc_info & 0x0080) {
        expert_add_info(pinfo, plc_info_item, &ei_xgt_cpu_error);
    }
    offset += 2;

    /* CPU Info */
    proto_tree_add_item(header_tree, hf_xgt_cpu_info, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* Source of Frame */
    proto_tree_add_item_ret_uint(header_tree, hf_xgt_source, tvb, offset, 1, ENC_LITTLE_ENDIAN, &source);
    offset += 1;

    /* Update info column based on source */
    if (source == XGT_SOURCE_CLIENT) {
        col_set_str(pinfo->cinfo, COL_INFO, "Request: ");
    } else if (source == XGT_SOURCE_SERVER) {
        col_set_str(pinfo->cinfo, COL_INFO, "Response: ");
    }

    /* Invoke ID */
    unsigned invoke_id;
    proto_tree_add_item_ret_uint(header_tree, hf_xgt_invoke_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &invoke_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, "[ID:%u] ", invoke_id);
    offset += 2;

    /* Length - validate against remaining data */
    ti = proto_tree_add_item_ret_uint(header_tree, hf_xgt_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &data_length);
    if (data_length > (unsigned)tvb_reported_length_remaining(tvb, offset + 4)) {
        expert_add_info(pinfo, ti, &ei_xgt_invalid_length);
    }
    offset += 2;

    /* FEnet Position */
    ti = proto_tree_add_item_ret_uint(header_tree, hf_xgt_fenet_position, tvb, offset, 1, ENC_LITTLE_ENDIAN, &fenet_pos);
    fenet_tree = proto_item_add_subtree(ti, ett_xgt_fenet_position);

    proto_tree_add_uint(fenet_tree, hf_xgt_fenet_slot, tvb, offset, 1, fenet_pos & 0x0F);
    proto_tree_add_uint(fenet_tree, hf_xgt_fenet_base, tvb, offset, 1, (fenet_pos >> 4) & 0x0F);
    offset += 1;

    /* Reserved2 / BCC */
    proto_tree_add_item(header_tree, hf_xgt_reserved2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return offset;
}

/* Helper function to translate XGT variable name to word address */
static char*
translate_xgt_address(wmem_allocator_t *scope, const char *var_name)
{
    if (!var_name || var_name[0] != '%') {
        return wmem_strdup(scope, var_name);
    }

    /* Skip % and extract memory type and address */
    const char *addr_part = var_name + 1;  /* Remove % */

    /* Find where the number starts */
    unsigned i = 0;
    while (addr_part[i] && !g_ascii_isdigit(addr_part[i])) {
        i++;
    }

    if (i == 0 || !addr_part[i]) {
        return wmem_strdup(scope, var_name);
    }

    /* Extract memory type (first letter only: D, M, P) */
    char mem_type = addr_part[0];

    /* Extract byte address and convert to word address */
    unsigned byte_addr = (unsigned)g_ascii_strtoull(&addr_part[i], NULL, 10);
    unsigned word_addr = byte_addr / 2;

    return wmem_strdup_printf(scope, "%c%u", mem_type, word_addr);
}

/* Dissect individual read/write block */
static int
dissect_xgt_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset,
                  bool is_request, bool is_write, unsigned data_type,
                  const char *request_var_name)
{
    proto_item *ti, *length_item;
    proto_tree *block_tree;
    unsigned var_length, data_length;
    uint8_t *var_name;
    unsigned start_offset = offset;

    /* Bounds check - need at least 2 bytes for length field */
    if (tvb_reported_length_remaining(tvb, offset) < 2) {
        expert_add_info(pinfo, tree, &ei_xgt_truncated_data);
        return tvb_captured_length(tvb);
    }

    block_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_xgt_block, &ti, "Variable Block");

    /* Variable length and name (only in requests or write response) */
    if (is_request || is_write) {
        length_item = proto_tree_add_item_ret_uint(block_tree, hf_xgt_variable_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &var_length);
        offset += 2;

        /* Validate variable length */
        if (var_length > 16) {
            expert_add_info(pinfo, length_item, &ei_xgt_invalid_length);
            proto_item_set_len(ti, offset - start_offset);
            return offset;
        }

        if (var_length > 0) {
            /* Bounds check for variable name */
            if (tvb_reported_length_remaining(tvb, offset) < var_length) {
                expert_add_info(pinfo, length_item, &ei_xgt_truncated_data);
                proto_item_set_len(ti, offset - start_offset);
                return tvb_captured_length(tvb);
            }

            var_name = (uint8_t *)tvb_get_string_enc(pinfo->pool, tvb, offset, var_length, ENC_ASCII);
            proto_tree_add_item(block_tree, hf_xgt_variable_name, tvb, offset, var_length, ENC_ASCII);
            proto_item_append_text(ti, ": %s", var_name);
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", var_name);
            offset += var_length;
        }
    }

    /* Data length and data (in write requests and all responses) */
    if (is_write || !is_request) {
        /* Bounds check for data length field */
        if (tvb_reported_length_remaining(tvb, offset) < 2) {
            expert_add_info(pinfo, ti, &ei_xgt_truncated_data);
            proto_item_set_len(ti, offset - start_offset);
            return tvb_captured_length(tvb);
        }

        length_item = proto_tree_add_item_ret_uint(block_tree, hf_xgt_data_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &data_length);
        offset += 2;

        /* Validate data length - reasonable upper limit */
        if (data_length > 8192) {
            expert_add_info(pinfo, length_item, &ei_xgt_invalid_length);
        }

        if (data_length > 0) {
            /* Bounds check for data */
            if (tvb_reported_length_remaining(tvb, offset) < data_length) {
                expert_add_info(pinfo, length_item, &ei_xgt_truncated_data);
                proto_item_set_len(ti, offset - start_offset);
                return tvb_captured_length(tvb);
            }

            /* For Continuous Block type, parse as individual words (similar to Modbus registers) */
            if (data_type == XGT_DTYPE_CONTINUOUS && data_length >= 2 && !is_request) {
                /* Add byte count field */
                proto_tree_add_uint(block_tree, hf_xgt_byte_count, tvb, offset, data_length, data_length);

                /* Parse data as 16-bit words */
                unsigned num_words = data_length / 2;
                unsigned i;
                unsigned word_offset = offset;

                /* Get translated base address from request variable name */
                char *base_addr_str = NULL;
                unsigned base_addr_num = 0;
                char mem_type = '\0';

                if (request_var_name) {
                    base_addr_str = translate_xgt_address(pinfo->pool, request_var_name);

                    /* Extract memory type and base address number */
                    if (base_addr_str && base_addr_str[0] && g_ascii_isalpha(base_addr_str[0])) {
                        mem_type = base_addr_str[0];
                        base_addr_num = (unsigned)g_ascii_strtoull(&base_addr_str[1], NULL, 10);
                    }
                }

                for (i = 0; i < num_words; i++) {
                    if (tvb_reported_length_remaining(tvb, word_offset) >= 2) {
                        uint16_t word_value = tvb_get_letohs(tvb, word_offset);

                        /* Display with translated address if available */
                        if (mem_type) {
                            char *addr_label = wmem_strdup_printf(pinfo->pool, "%c%u", mem_type, base_addr_num + i);
                            proto_tree_add_uint_format(block_tree, hf_xgt_word, tvb, word_offset, 2,
                                                        word_value, "%s (UINT16): %u", addr_label, word_value);
                        } else {
                            /* Fallback to Word N format */
                            proto_tree_add_uint_format(block_tree, hf_xgt_word, tvb, word_offset, 2,
                                                        word_value, "Word %u (UINT16): %u", i, word_value);
                        }
                        word_offset += 2;
                    }
                }

                /* Add data value to Info column for responses */
                if (!is_request) {
                    uint16_t first_value = tvb_get_letohs(tvb, offset);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "[%u bytes] = %u...", data_length, first_value);
                }
            } else if (data_length == 8 && data_type == XGT_DTYPE_LWORD) {
                /* For 64-bit values, show as uint64 using data_value field */
                uint64_t value = tvb_get_letoh64(tvb, offset);
                proto_tree_add_uint64_format(block_tree, hf_xgt_data_value_uint64, tvb, offset, data_length, value, "Data: %" G_GUINT64_FORMAT, value);
            } else if (data_length == 1 && (data_type == XGT_DTYPE_BIT || data_type == XGT_DTYPE_BYTE)) {
                uint8_t value = tvb_get_uint8(tvb, offset);
                proto_tree_add_uint_format(block_tree, hf_xgt_data_value_uint8, tvb, offset, data_length, value, "Data: %u", value);
            } else if (data_length == 2 && data_type == XGT_DTYPE_WORD) {
                uint16_t value = tvb_get_letohs(tvb, offset);
                proto_tree_add_uint_format(block_tree, hf_xgt_data_value_uint16, tvb, offset, data_length, value, "Data: %u", value);
            } else if (data_length == 4 && data_type == XGT_DTYPE_DWORD) {
                uint32_t value = tvb_get_letohl(tvb, offset);
                proto_tree_add_uint_format(block_tree, hf_xgt_data_value_uint32, tvb, offset, data_length, value, "Data: %u", value);
            } else {
                /* For multi-value or large data, show all bytes as hex */
                proto_tree_add_item(block_tree, hf_xgt_data, tvb, offset, data_length, ENC_NA);
            }

            /* Add data value to Info column for responses (for non-continuous types) */
            if (!is_request && data_type != XGT_DTYPE_CONTINUOUS) {
                if (data_length >= 2) {
                    /* For single values, show the value */
                    uint16_t value = tvb_get_letohs(tvb, offset);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "= %u", value);
                } else if (data_length == 1) {
                    /* For single byte */
                    uint8_t value = tvb_get_uint8(tvb, offset);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "= %u", value);
                }
            }

            offset += data_length;
        }
    }

    proto_item_set_len(ti, offset - start_offset);
    return offset;
}

/* Dissect XGT Instruction (Command and Data) */
static int
dissect_xgt_instruction(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, unsigned invoke_id)
{
    proto_tree *inst_tree, *status_tree;
    proto_item *ti, *cmd_item, *count_item, *error_item;
    unsigned command, error_status, error_code, block_count, data_type;
    unsigned i;
    bool is_request, is_write, is_status;
    const char *cmd_str;
    xgt_conv_info_t *conv_info = NULL;
    conversation_t *conversation = NULL;

    /* Bounds check - need at least 8 bytes (command, data type, reserved, error/count) */
    if (tvb_reported_length_remaining(tvb, offset) < 8) {
        expert_add_info(pinfo, tree, &ei_xgt_truncated_data);
        return tvb_captured_length(tvb);
    }

    ti = proto_tree_add_item(tree, proto_xgt, tvb, offset, -1, ENC_NA);
    inst_tree = proto_item_add_subtree(ti, ett_xgt_instruction);

    /* Command */
    cmd_item = proto_tree_add_item_ret_uint(inst_tree, hf_xgt_command, tvb, offset, 2, ENC_LITTLE_ENDIAN, &command);
    cmd_str = val_to_str_const(command, xgt_command_vals, "Unknown");
    col_append_str(pinfo->cinfo, COL_INFO, cmd_str);

    /* Warn about unknown commands */
    if (try_val_to_str(command, xgt_command_vals) == NULL) {
        expert_add_info(pinfo, cmd_item, &ei_xgt_invalid_command);
    }
    offset += 2;

    /* Determine request/response and command type */
    is_request = (command == XGT_CMD_READ_REQUEST || command == XGT_CMD_WRITE_REQUEST ||
                  command == XGT_CMD_STATUS_REQUEST);
    is_write = (command == XGT_CMD_WRITE_REQUEST || command == XGT_CMD_WRITE_RESPONSE);
    is_status = (command == XGT_CMD_STATUS_REQUEST || command == XGT_CMD_STATUS_RESPONSE);

    /* Set up conversation tracking for request-response matching */
    conversation = find_or_create_conversation(pinfo);
    conv_info = (xgt_conv_info_t *)conversation_get_proto_data(conversation, proto_xgt);

    if (!conv_info) {
        conv_info = wmem_new(wmem_file_scope(), xgt_conv_info_t);
        conv_info->invoke_id_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        conversation_add_proto_data(conversation, proto_xgt, conv_info);
    }

    /* Data Type */
    proto_tree_add_item_ret_uint(inst_tree, hf_xgt_data_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &data_type);

    /* Add data type to Info column */
    const char *dtype_str = val_to_str_const(data_type, xgt_data_type_vals, "Unknown");
    col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ", dtype_str);

    offset += 2;

    /* Reserved Area */
    proto_tree_add_item(inst_tree, hf_xgt_reserved_area, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Error Status (responses only) */
    if (!is_request) {
        error_item = proto_tree_add_item_ret_uint(inst_tree, hf_xgt_error_status, tvb, offset, 2, ENC_LITTLE_ENDIAN, &error_status);
        offset += 2;

        /* Error Code (if error exists) */
        if (error_status != XGT_ERROR_NONE) {
            /* Bounds check for error code */
            if (tvb_reported_length_remaining(tvb, offset) < 2) {
                expert_add_info(pinfo, error_item, &ei_xgt_truncated_data);
                return tvb_captured_length(tvb);
            }

            proto_tree_add_item_ret_uint(inst_tree, hf_xgt_error_code, tvb, offset, 2, ENC_LITTLE_ENDIAN, &error_code);
            expert_add_info_format(pinfo, error_item, &ei_xgt_error_response,
                                   "XGT Error Response: Error Code 0x%04x", error_code);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Error: 0x%04x)", error_code);
            offset += 2;
            return offset;
        }
    }

    /* Handle Status command separately */
    if (is_status) {
        if (!is_request) {
            /* Bounds check for data size field */
            if (tvb_reported_length_remaining(tvb, offset) < 2) {
                expert_add_info(pinfo, inst_tree, &ei_xgt_truncated_data);
                return tvb_captured_length(tvb);
            }

            /* Status response data */
            unsigned data_size;
            ti = proto_tree_add_item_ret_uint(inst_tree, hf_xgt_data_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &data_size);
            offset += 2;

            if (data_size >= 24) {
                /* Bounds check for status data */
                if (tvb_reported_length_remaining(tvb, offset) < 24) {
                    expert_add_info(pinfo, ti, &ei_xgt_truncated_data);
                    return tvb_captured_length(tvb);
                }

                ti = proto_tree_add_item(inst_tree, hf_xgt_status_data, tvb, offset, 24, ENC_NA);
                status_tree = proto_item_add_subtree(ti, ett_xgt_status);

                proto_tree_add_item(status_tree, hf_xgt_slot_info, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(status_tree, hf_xgt_cpu_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(status_tree, hf_xgt_ver_num, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(status_tree, hf_xgt_sys_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(status_tree, hf_xgt_padt_cnf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(status_tree, hf_xgt_cnf_er, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(status_tree, hf_xgt_cnf_war, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                /* Reserved 2 bytes */
                if (tvb_reported_length_remaining(tvb, offset) >= 2) {
                    offset += 2;
                }
            }
        }
        return offset;
    }

    /* Bounds check for block count field */
    if (tvb_reported_length_remaining(tvb, offset) < 2) {
        expert_add_info(pinfo, inst_tree, &ei_xgt_truncated_data);
        return tvb_captured_length(tvb);
    }

    /* Block/Variable Count */
    if (is_request) {
        count_item = proto_tree_add_item_ret_uint(inst_tree, hf_xgt_variable_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &block_count);
    } else {
        count_item = proto_tree_add_item_ret_uint(inst_tree, hf_xgt_block_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &block_count);
    }

    /* Add block count to Info column if more than 1 */
    if (block_count > 1) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Blocks:%u ", block_count);
    }

    /* Warn about suspicious counts */
    if (block_count > 100) {
        expert_add_info_format(pinfo, count_item, &ei_xgt_suspicious_count,
                               "Suspicious block count: %u (possible malformed packet)", block_count);
    }
    offset += 2;

    /* Process blocks/variables with bounds checking */
    for (i = 0; i < block_count && i < 256; i++) {
        /* Check if we have remaining data */
        if (tvb_reported_length_remaining(tvb, offset) < 2) {
            expert_add_info(pinfo, count_item, &ei_xgt_truncated_data);
            break;
        }

        /* Get variable name for request-response matching */
        char *var_name = NULL;

        /* For requests, extract variable name and save it */
        if (is_request && conv_info) {
            /* Check if already in map */
            var_name = (char *)wmem_map_lookup(conv_info->invoke_id_map, (void *)(uintptr_t)invoke_id);

            /* If not found, peek ahead to get variable name and store it */
            if (!var_name && tvb_reported_length_remaining(tvb, offset) >= 2) {
                uint16_t var_length = tvb_get_letohs(tvb, offset);
                if (var_length > 0 && var_length <= 16 &&
                    tvb_reported_length_remaining(tvb, offset + 2) >= var_length) {
                    var_name = (char *)tvb_get_string_enc(pinfo->pool, tvb, offset + 2, var_length, ENC_ASCII);
                    /* Store in conversation map */
                    wmem_map_insert(conv_info->invoke_id_map, (void *)(uintptr_t)invoke_id, wmem_strdup(wmem_file_scope(), var_name));
                }
            }
        }

        /* For responses, retrieve variable name from conversation map */
        if (!is_request && conv_info) {
            var_name = (char *)wmem_map_lookup(conv_info->invoke_id_map, (void *)(uintptr_t)invoke_id);
        }

        offset = dissect_xgt_block(tvb, pinfo, inst_tree, offset, is_request, is_write, data_type, var_name);

        /* Safety check to prevent infinite loops */
        if (offset >= tvb_captured_length(tvb)) {
            break;
        }
    }

    return offset;
}

/* Return length of XGT PDU */
static unsigned
get_xgt_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint16_t plen;

    /*
     * Get the length of the data from the header.
     * The length field is at offset 16-17 (little endian).
     */
    plen = tvb_get_letohs(tvb, offset + 16);

    /*
     * That length doesn't include the header itself;
     * add that in.
     */
    return plen + XGT_HEADER_LEN;
}

/* Dissect one complete XGT PDU */
static int
dissect_xgt_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *xgt_tree;
    unsigned offset = 0;
    unsigned invoke_id = 0;

    /* Set protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "XGT");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Create protocol tree */
    ti = proto_tree_add_item(tree, proto_xgt, tvb, 0, -1, ENC_NA);
    xgt_tree = proto_item_add_subtree(ti, ett_xgt);

    /* Extract invoke_id from header (offset 16) for conversation tracking */
    if (tvb_captured_length(tvb) >= 18) {
        invoke_id = tvb_get_letohs(tvb, 16);
    }

    /* Dissect header */
    offset = dissect_xgt_header(tvb, pinfo, xgt_tree, offset);

    /* Dissect instruction if present */
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        dissect_xgt_instruction(tvb, pinfo, xgt_tree, offset, invoke_id);
    }

    return tvb_captured_length(tvb);
}

/* Check if packet looks like XGT protocol */
static bool
is_xgt(tvbuff_t *tvb, packet_info *pinfo)
{
    /* Make sure there's at least enough data to check company ID */
    if (!tvb_bytes_exist(tvb, 0, XGT_HEADER_LEN))
        return false;

    /* Check that it actually looks like XGT */
    /* Verify Company ID */
    if (tvb_strneql(tvb, 0, XGT_COMPANY_ID, 8) != 0)
        return false;

    /* Since XGT is registered on specific ports, give it benefit of the doubt */
    if ((pinfo->srcport != XGT_TCP_PORT) && (pinfo->destport != XGT_TCP_PORT) &&
        (pinfo->srcport != XGT_UDP_PORT) && (pinfo->destport != XGT_UDP_PORT))
        return false;

    return true;
}

/* Code to dissect XGT messages over TCP */
static int
dissect_xgt_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!is_xgt(tvb, pinfo))
        return 0;

    /* Build up protocol tree and iterate over multiple packets */
    tcp_dissect_pdus(tvb, pinfo, tree, true, XGT_HEADER_LEN,
                     get_xgt_pdu_len, dissect_xgt_pdu, data);

    return tvb_captured_length(tvb);
}

/* Code to dissect XGT messages over UDP */
static int
dissect_xgt_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!is_xgt(tvb, pinfo))
        return 0;

    return dissect_xgt_pdu(tvb, pinfo, tree, data);
}

/* Register protocol */
void
proto_register_xgt(void)
{
    static hf_register_info hf[] = {
        /* Header fields */
        { &hf_xgt_company_id,
          { "Company ID", "xgt.company_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Company identification string", HFILL }
        },
        { &hf_xgt_reserved1,
          { "Reserved", "xgt.reserved1",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xgt_plc_info,
          { "PLC Info", "xgt.plc_info",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "PLC information field", HFILL }
        },
        { &hf_xgt_plc_info_cpu_type,
          { "CPU Type", "xgt.plc_info.cpu_type",
            FT_UINT16, BASE_DEC, VALS(xgt_cpu_type_vals), 0x003F,
            NULL, HFILL }
        },
        { &hf_xgt_plc_info_redundancy,
          { "Redundancy", "xgt.plc_info.redundancy",
            FT_BOOLEAN, 16, TFS(&tfs_slave_master), 0x0040,
            "Redundancy status", HFILL }
        },
        { &hf_xgt_plc_info_cpu_error,
          { "CPU Error", "xgt.plc_info.cpu_error",
            FT_BOOLEAN, 16, TFS(&tfs_error_normal), 0x0080,
            "CPU operation error status", HFILL }
        },
        { &hf_xgt_plc_info_sys_state,
          { "System State", "xgt.plc_info.sys_state",
            FT_UINT16, BASE_HEX, VALS(xgt_sys_state_vals), 0x1F00,
            NULL, HFILL }
        },
        { &hf_xgt_cpu_info,
          { "CPU Info", "xgt.cpu_info",
            FT_UINT8, BASE_HEX, VALS(xgt_cpu_info_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_xgt_source,
          { "Source", "xgt.source",
            FT_UINT8, BASE_HEX, VALS(xgt_source_vals), 0x0,
            "Source of frame", HFILL }
        },
        { &hf_xgt_invoke_id,
          { "Invoke ID", "xgt.invoke_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Frame sequence identifier", HFILL }
        },
        { &hf_xgt_length,
          { "Length", "xgt.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Application instruction length", HFILL }
        },
        { &hf_xgt_fenet_position,
          { "FEnet Position", "xgt.fenet_position",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "FEnet module position", HFILL }
        },
        { &hf_xgt_fenet_slot,
          { "Slot", "xgt.fenet_position.slot",
            FT_UINT8, BASE_DEC, NULL, 0x0F,
            "FEnet module slot number", HFILL }
        },
        { &hf_xgt_fenet_base,
          { "Base", "xgt.fenet_position.base",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            "FEnet module base number", HFILL }
        },
        { &hf_xgt_reserved2,
          { "Reserved/BCC", "xgt.reserved2",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        /* Instruction fields */
        { &hf_xgt_command,
          { "Command", "xgt.command",
            FT_UINT16, BASE_HEX, VALS(xgt_command_vals), 0x0,
            "Command code", HFILL }
        },
        { &hf_xgt_data_type,
          { "Data Type", "xgt.data_type",
            FT_UINT16, BASE_HEX, VALS(xgt_data_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_xgt_reserved_area,
          { "Reserved", "xgt.reserved_area",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xgt_error_status,
          { "Error Status", "xgt.error_status",
            FT_UINT16, BASE_HEX, VALS(xgt_error_status_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_xgt_error_code,
          { "Error Code", "xgt.error_code",
            FT_UINT16, BASE_HEX, VALS(xgt_error_code_vals), 0x0,
            "XGT protocol error code", HFILL }
        },
        { &hf_xgt_block_count,
          { "Block Count", "xgt.block_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xgt_variable_count,
          { "Variable Count", "xgt.variable_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xgt_variable_length,
          { "Variable Length", "xgt.variable_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of variable name", HFILL }
        },
        { &hf_xgt_variable_name,
          { "Variable Name", "xgt.variable_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xgt_data_length,
          { "Data Length", "xgt.data_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of data in bytes", HFILL }
        },
        { &hf_xgt_data,
          { "Data", "xgt.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* Status fields */
        { &hf_xgt_status_data,
          { "Status Data", "xgt.status_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xgt_slot_info,
          { "Slot Info", "xgt.status.slot_info",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xgt_cpu_type,
          { "CPU Type", "xgt.status.cpu_type",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_xgt_ver_num,
          { "Version Number", "xgt.status.ver_num",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "OS version number", HFILL }
        },
        { &hf_xgt_sys_state,
          { "System State", "xgt.status.sys_state",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "PLC mode and operation state", HFILL }
        },
        { &hf_xgt_padt_cnf,
          { "PADT Connection", "xgt.status.padt_cnf",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "XG5000 connection status", HFILL }
        },
        { &hf_xgt_cnf_er,
          { "Error Flags", "xgt.status.cnf_er",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "System error flags", HFILL }
        },
        { &hf_xgt_cnf_war,
          { "Warning Flags", "xgt.status.cnf_war",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "System warning flags", HFILL }
        },

        /* Data value fields */
        { &hf_xgt_data_value_uint8,
          { "Value (BYTE)", "xgt.data.value.uint8",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Data value as 8-bit unsigned integer", HFILL }
        },
        { &hf_xgt_data_value_uint16,
          { "Value (WORD)", "xgt.data.value.uint16",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Data value as 16-bit unsigned integer", HFILL }
        },
        { &hf_xgt_data_value_uint32,
          { "Value (DWORD)", "xgt.data.value.uint32",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Data value as 32-bit unsigned integer", HFILL }
        },
        { &hf_xgt_data_value_uint64,
          { "Value (LWORD)", "xgt.data.value.uint64",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Data value as 64-bit unsigned integer", HFILL }
        },
        { &hf_xgt_byte_count,
          { "Byte Count", "xgt.byte_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of data bytes", HFILL }
        },
        { &hf_xgt_word,
          { "Word", "xgt.word",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Word value (16-bit)", HFILL }
        }
    };

    static int *ett[] = {
        &ett_xgt,
        &ett_xgt_header,
        &ett_xgt_instruction,
        &ett_xgt_plc_info,
        &ett_xgt_fenet_position,
        &ett_xgt_block,
        &ett_xgt_status
    };

    static ei_register_info ei[] = {
        { &ei_xgt_invalid_length,
          { "xgt.invalid_length", PI_MALFORMED, PI_ERROR,
            "Invalid length field", EXPFILL }
        },
        { &ei_xgt_error_response,
          { "xgt.error_response", PI_RESPONSE_CODE, PI_WARN,
            "XGT Error Response", EXPFILL }
        },
        { &ei_xgt_truncated_data,
          { "xgt.truncated_data", PI_MALFORMED, PI_ERROR,
            "Truncated data (packet too short)", EXPFILL }
        },
        { &ei_xgt_invalid_command,
          { "xgt.invalid_command", PI_MALFORMED, PI_WARN,
            "Unknown or invalid command code", EXPFILL }
        },
        { &ei_xgt_cpu_error,
          { "xgt.cpu_error", PI_RESPONSE_CODE, PI_WARN,
            "CPU Error detected", EXPFILL }
        },
        { &ei_xgt_suspicious_count,
          { "xgt.suspicious_count", PI_MALFORMED, PI_WARN,
            "Suspicious count value", EXPFILL }
        }
    };

    expert_module_t *expert_xgt;

    /* Register protocol */
    proto_xgt = proto_register_protocol(
        "XGT FEnet Protocol",    /* name */
        "XGT",                 /* short name */
        "xgt"                  /* filter name */
    );

    proto_register_field_array(proto_xgt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register expert info */
    expert_xgt = expert_register_protocol(proto_xgt);
    expert_register_field_array(expert_xgt, ei, array_length(ei));
}

void
proto_reg_handoff_xgt(void)
{
    static dissector_handle_t xgt_tcp_handle;
    static dissector_handle_t xgt_udp_handle;

    xgt_tcp_handle = create_dissector_handle(dissect_xgt_tcp, proto_xgt);
    xgt_udp_handle = create_dissector_handle(dissect_xgt_udp, proto_xgt);

    dissector_add_uint("tcp.port", XGT_TCP_PORT, xgt_tcp_handle);
    dissector_add_uint("udp.port", XGT_UDP_PORT, xgt_udp_handle);
}
