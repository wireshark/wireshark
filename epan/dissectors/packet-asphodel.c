/* packet-asphodel.c
 * Routines for Asphodel dissection
 * Copyright 2018, Greg Schwendimann <gregs@suprocktech.com>
 * Copyright 2020, Jeffrey Nichols <jsnichols@suprocktech.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Asphodel: https://bitbucket.org/suprocktech/asphodel
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-tcp.h"

void proto_reg_handoff_asphodel(void);
void proto_register_asphodel(void);

// useful #defines copied from asphodel_protocol.h and asphodel_tcp.c
#define ASPHODEL_PROTOCOL_TYPE_RF_POWER     0x01
#define ASPHODEL_PROTOCOL_TYPE_RADIO        0x02
#define ASPHODEL_PROTOCOL_TYPE_REMOTE       0x04
#define ASPHODEL_PROTOCOL_TYPE_BOOTLOADER   0x08
#define ASPHODEL_TCP_MSG_TYPE_DEVICE_CMD    0x00
#define ASPHODEL_TCP_MSG_TYPE_DEVICE_STREAM 0x01
#define ASPHODEL_TCP_MSG_TYPE_REMOTE_CMD    0x02
#define ASPHODEL_TCP_MSG_TYPE_REMOTE_STREAM 0x03
#define ASPHODEL_TCP_MSG_TYPE_REMOTE_NOTIFY 0x06
#define ASPHODEL_CMD_REPLY_ERROR            0xFF

static const value_string asphodel_type_vals[] = {
    { ASPHODEL_TCP_MSG_TYPE_DEVICE_CMD, "DEVICE_CMD" },
    { ASPHODEL_TCP_MSG_TYPE_DEVICE_STREAM, "DEVICE_STREAM" },
    { ASPHODEL_TCP_MSG_TYPE_REMOTE_CMD, "REMOTE_CMD" },
    { ASPHODEL_TCP_MSG_TYPE_REMOTE_STREAM, "REMOTE_STREAM" },
    { ASPHODEL_TCP_MSG_TYPE_REMOTE_NOTIFY, "REMOTE_NOTIFY" },
    { 0, NULL }
};

static const value_string asphodel_cmd_vals[] = {
    { 0x00, "GET_PROTOCOL_VERSION" },
    { 0x01, "GET_BOARD_INFO" },
    { 0x02, "GET_USER_TAG_LOCATIONS" },
    { 0x03, "GET_BUILD_INFO" },
    { 0x04, "GET_BUILD_DATE" },
    { 0x05, "GET_CHIP_FAMILY" },
    { 0x06, "GET_CHIP_MODEL" },
    { 0x07, "GET_CHIP_ID" },
    { 0x08, "GET_NVM_SIZE" },
    { 0x09, "ERASE_NVM" },
    { 0x0A, "WRITE_NVM" },
    { 0x0B, "READ_NVM" },
    { 0x0C, "FLUSH" },
    { 0x0D, "RESET" },
    { 0x0E, "GET_BOOTLOADER_INFO" },
    { 0x0F, "BOOTLOADER_JUMP" },
    { 0x10, "GET_RGB_COUNT" },
    { 0x11, "GET_RGB_VALUES" },
    { 0x12, "SET_RGB" },
    { 0x13, "SET_RGB_INSTANT" },
    { 0x14, "GET_LED_COUNT" },
    { 0x15, "GET_LED_VALUE" },
    { 0x16, "SET_LED" },
    { 0x17, "SET_LED_INSTANT" },
    { 0x20, "GET_STREAM_COUNT_AND_ID" },
    { 0x21, "GET_STREAM_CHANNELS" },
    { 0x22, "GET_STREAM_FORMAT" },
    { 0x23, "ENABLE_STREAM" },
    { 0x24, "WARM_UP_STREAM" },
    { 0x25, "GET_STREAM_STATUS" },
    { 0x26, "GET_STREAM_RATE_INFO" },
    { 0x30, "GET_CHANNEL_COUNT" },
    { 0x31, "GET_CHANNEL_NAME" },
    { 0x32, "GET_CHANNEL_INFO" },
    { 0x33, "GET_CHANNEL_COEFFICIENTS" },
    { 0x34, "GET_CHANNEL_CHUNK" },
    { 0x35, "CHANNEL_SPECIFIC" },
    { 0x36, "GET_CHANNEL_CALIBRATION" },
    { 0x40, "GET_SUPPLY_COUNT" },
    { 0x41, "GET_SUPPLY_NAME" },
    { 0x42, "GET_SUPPLY_INFO" },
    { 0x43, "CHECK_SUPPLY" },
    { 0x50, "GET_CTRL_VAR_COUNT" },
    { 0x51, "GET_CTRL_VAR_NAME" },
    { 0x52, "GET_CTRL_VAR_INFO" },
    { 0x53, "GET_CTRL_VAR" },
    { 0x54, "SET_CTRL_VAR" },
    { 0x60, "GET_SETTING_COUNT" },
    { 0x61, "GET_SETTING_NAME" },
    { 0x62, "GET_SETTING_INFO" },
    { 0x63, "GET_SETTING_DEFAULT" },
    { 0x64, "GET_CUSTOM_ENUM_COUNTS" },
    { 0x65, "GET_CUSTOM_ENUM_VALUE_NAME" },
    { 0x66, "GET_SETTING_CATEGORY_COUNT" },
    { 0x67, "GET_SETTING_CATEGORY_NAME" },
    { 0x68, "GET_SETTING_CATERORY_SETTINGS" },
    { 0x70, "SET_DEVICE_MODE" },
    { 0x71, "GET_DEVICE_MODE" },
    { 0x80, "ENABLE_RF_POWER" },
    { 0x81, "GET_RF_POWER_STATUS" },
    { 0x82, "GET_RF_POWER_CTRL_VARS" },
    { 0x83, "RESET_RF_POWER_TIMEOUT" },
    { 0x90, "STOP_RADIO" },
    { 0x91, "START_RADIO_SCAN" },
    { 0x92, "GET_RADIO_SCAN_RESULTS" },
    { 0x93, "CONNECT_RADIO" },
    { 0x94, "GET_RADIO_STATUS" },
    { 0x95, "GET_RADIO_CTRL_VARS" },
    { 0x96, "GET_RADIO_DEFAULT_SERIAL" },
    { 0x97, "START_RADIO_SCAN_BOOT" },
    { 0x98, "CONNECT_RADIO_BOOT" },
    { 0x99, "GET_RADIO_EXTRA_SCAN_RESULTS" },
    { 0x9A, "STOP_REMOTE" },
    { 0x9B, "RESTART_REMOTE" },
    { 0x9C, "GET_REMOTE_STATUS" },
    { 0x9D, "RESTART_REMOTE_APP" },
    { 0x9E, "RESTART_REMOTE_BOOT" },
    { 0x9F, "GET_RADIO_SCAN_POWER" },
    { 0xA0, "BOOTLOADER_START_PROGRAM" },
    { 0xA1, "GET_BOOTLOADER_PAGE_INFO" },
    { 0xA2, "GET_BOOTLOADER_BLOCK_SIZES" },
    { 0xA3, "START_BOOTLOADER_PAGE" },
    { 0xA4, "WRITE_BOOTLOADER_CODE_BLOCK" },
    { 0xA5, "FINISH_BOOTLOADER_PAGE" },
    { 0xA6, "VERIFY_BOOTLOADER_PAGE" },
    { 0xE0, "GET_GPIO_PORT_COUNT" },
    { 0xE1, "GET_GPIO_PORT_NAME" },
    { 0xE2, "GET_GPIO_PORT_INFO" },
    { 0xE3, "GET_GPIO_PORT_VALUES" },
    { 0xE4, "SET_GPIO_PORT_MODES" },
    { 0xE5, "DISABLE_GPIO_PORT_OVERRIDES" },
    { 0xE6, "GET_BUS_COUNTS" },
    { 0xE7, "SET_SPI_CS_MODE" },
    { 0xE8, "DO_SPI_TRANSFER" },
    { 0xE9, "DO_I2C_WRITE" },
    { 0xEA, "DO_I2C_READ" },
    { 0xEB, "DO_I2C_WRITE_READ" },
    { 0xEC, "DO_RADIO_FIXED_TEST" },
    { 0xED, "DO_RADIO_SWEEP_TEST" },
    { 0xF0, "GET_INFO_REGION_COUNT" },
    { 0xF1, "GET_INFO_REGION_NAME" },
    { 0xF2, "GET_INFO_REGION" },
    { 0xF3, "GET_STACK_INFO" },
    { 0xFC, "ECHO_RAW" },
    { 0xFD, "ECHO_TRANSACTION" },
    { 0xFE, "ECHO_PARAMS" },
    { 0xFF, "REPLY_ERROR" },
    { 0, NULL }
};

static const value_string asphodel_err_vals[] = {
    { 0x01, "ERROR_CODE_UNSPECIFIED" },
    { 0x02, "ERROR_CODE_MALFORMED_COMMAND" },
    { 0x03, "ERROR_CODE_UNIMPLEMENTED_COMMAND" },
    { 0x04, "ERROR_CODE_BAD_CMD_LENGTH" },
    { 0x05, "ERROR_CODE_BAD_ADDRESS" },
    { 0x06, "ERROR_CODE_BAD_INDEX" },
    { 0x07, "ERROR_CODE_INVALID_DATA" },
    { 0x08, "ERROR_CODE_UNSUPPORTED" },
    { 0x09, "ERROR_CODE_BAD_STATE" },
    { 0x0A, "ERROR_CODE_I2C_ERROR" },
    { 0x0B, "ERROR_CODE_INCOMPLETE" },
    { 0, NULL }
};

static const true_false_string notify_connect_disconnect = {
    "Connect",
    "Disconnect"
};

static int proto_asphodel = -1;

// asphodel inquiry fields
static int hf_asphodel_version = -1;
static int hf_asphodel_identifier = -1;

// asphodel response fields
static int hf_asphodel_tcp_version = -1;
static int hf_asphodel_connected = -1;
static int hf_asphodel_max_incoming_param_length = -1;
static int hf_asphodel_max_outgoing_param_length = -1;
static int hf_asphodel_stream_packet_length = -1;
static int hf_asphodel_protocol_type = -1;
static int hf_asphodel_protocol_type_rf_power = -1;
static int hf_asphodel_protocol_type_radio = -1;
static int hf_asphodel_protocol_type_remote = -1;
static int hf_asphodel_protocol_type_bootloader = -1;
static int hf_asphodel_serial_number = -1;
static int hf_asphodel_board_rev = -1;
static int hf_asphodel_board_type = -1;
static int hf_asphodel_build_info = -1;
static int hf_asphodel_build_date = -1;
static int hf_asphodel_user_tag1 = -1;
static int hf_asphodel_user_tag2 = -1;
static int hf_asphodel_remote_max_incoming_param_length = -1;
static int hf_asphodel_remote_max_outgoing_param_length = -1;
static int hf_asphodel_remote_stream_packet_length = -1;

// asphodel tcp fields
static int hf_asphodel_length = -1;
static int hf_asphodel_type = -1;
static int hf_asphodel_seq = -1;
static int hf_asphodel_cmd = -1;
static int hf_asphodel_err_code = -1;
static int hf_asphodel_params = -1;
static int hf_asphodel_stream_data = -1;
static int hf_asphodel_notify = -1;
static int hf_asphodel_notify_serial = -1;

static gint ett_asphodel = -1;
static gint ett_asphodel_protocol_type = -1;

static expert_field ei_asphodel_bad_param_length = EI_INIT;
static expert_field ei_asphodel_bad_length = EI_INIT;
static expert_field ei_asphodel_cmd_error = EI_INIT;
static expert_field ei_asphodel_unknown_type = EI_INIT;

static dissector_handle_t asphodel_inquiry_handle;
static dissector_handle_t asphodel_response_handle;
static dissector_handle_t asphodel_tcp_handle;

static void
asphodel_fmt_version(gchar *result, guint32 version)
{
    guint8 major = version >> 8;
    guint8 minor = (version >> 4) & 0x0F;
    guint8 subminor = version & 0x0F;
    snprintf(result, ITEM_LABEL_LENGTH, "%d.%d.%d", major, minor, subminor);
}

static int
dissect_asphodel_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *asphodel_tree;
    guint32 length;

    ti = proto_tree_add_item(tree, proto_asphodel, tvb, 0, -1, ENC_NA);
    asphodel_tree = proto_item_add_subtree(ti, ett_asphodel);

    proto_tree_add_item_ret_uint(asphodel_tree, hf_asphodel_length, tvb, 0, 2, ENC_BIG_ENDIAN, &length);

    if (length == 0)
    {
        proto_item_set_text(ti, "Asphodel No Op");
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "No op");
    }
    else
    {
        guint32 type;
        proto_tree_add_item_ret_uint(asphodel_tree, hf_asphodel_type, tvb, 2, 1, ENC_NA, &type);

        // handle the text
        switch (type)
        {
        case ASPHODEL_TCP_MSG_TYPE_DEVICE_CMD:
            proto_item_set_text(ti, "Asphodel Command");
            break;
        case ASPHODEL_TCP_MSG_TYPE_REMOTE_CMD:
            proto_item_set_text(ti, "Asphodel Remote Command");
            break;
        case ASPHODEL_TCP_MSG_TYPE_DEVICE_STREAM:
            proto_item_set_text(ti, "Asphodel Stream Data");
            break;
        case ASPHODEL_TCP_MSG_TYPE_REMOTE_STREAM:
            proto_item_set_text(ti, "Asphodel Remote Stream Data");
            break;
        case ASPHODEL_TCP_MSG_TYPE_REMOTE_NOTIFY:
            proto_item_set_text(ti, "Asphodel Notify");
            break;
        default:
            // keep the default "Asphodel" item text
            break;
        }

        switch (type)
        {
        case ASPHODEL_TCP_MSG_TYPE_DEVICE_CMD:
        case ASPHODEL_TCP_MSG_TYPE_REMOTE_CMD:
            if (length >= 3)
            {
                guint32 cmd;
                proto_tree_add_item(asphodel_tree, hf_asphodel_seq, tvb, 3, 1, ENC_NA);
                proto_tree_add_item_ret_uint(asphodel_tree, hf_asphodel_cmd, tvb, 4, 1, ENC_NA, &cmd);

                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s", val_to_str(cmd, asphodel_cmd_vals, "Unknown type (0x%02x)"));

                if (cmd == ASPHODEL_CMD_REPLY_ERROR)
                {
                    if (length >= 4)
                    {
                        proto_tree_add_item(asphodel_tree, hf_asphodel_err_code, tvb, 5, 1, ENC_NA);
                        if (length >= 5)
                        {
                            proto_tree_add_item(asphodel_tree, hf_asphodel_params, tvb, 6, -1, ENC_NA);
                        }
                    }
                    else
                    {
                        // not long enough
                        expert_add_info(pinfo, ti, &ei_asphodel_bad_length);
                    }

                    // add a note that it's an error response
                    expert_add_info(pinfo, ti, &ei_asphodel_cmd_error);
                }
                else
                {
                    // normal command response
                    if (length >= 4)
                    {
                        proto_tree_add_item(asphodel_tree, hf_asphodel_params, tvb, 5, -1, ENC_NA);
                    }
                }
            }
            else
            {
                // not long enough
                expert_add_info(pinfo, ti, &ei_asphodel_bad_length);
            }
            break;
        case ASPHODEL_TCP_MSG_TYPE_DEVICE_STREAM:
        case ASPHODEL_TCP_MSG_TYPE_REMOTE_STREAM:
            if (length > 1)
            {
                proto_tree_add_item(asphodel_tree, hf_asphodel_stream_data, tvb, 3, -1, ENC_NA);
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Stream(%d)", length - 1);
            }
            else
            {
                // not long enough
                expert_add_info(pinfo, ti, &ei_asphodel_bad_length);
            }
            break;
        case ASPHODEL_TCP_MSG_TYPE_REMOTE_NOTIFY:
            if (length == 1) // disconnect
            {
                ti = proto_tree_add_boolean(asphodel_tree, hf_asphodel_notify, tvb, 2, 1, 0);
                proto_item_set_generated(ti);
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Notify Disconnect");
            }
            else if (length == 6) // connect
            {
                proto_tree *protocol_type_tree;

                ti = proto_tree_add_boolean(asphodel_tree, hf_asphodel_notify, tvb, 2, 1, 1);
                proto_item_set_generated(ti);
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Notify Connect");

                proto_tree_add_item(asphodel_tree, hf_asphodel_notify_serial, tvb, 3, 4, ENC_BIG_ENDIAN);

                // protocol type
                ti = proto_tree_add_item(asphodel_tree, hf_asphodel_protocol_type, tvb, 7, 1, ENC_NA);
                protocol_type_tree = proto_item_add_subtree(ti, ett_asphodel_protocol_type);
                proto_tree_add_item(protocol_type_tree, hf_asphodel_protocol_type_rf_power, tvb, 7, 1, ENC_NA);
                proto_tree_add_item(protocol_type_tree, hf_asphodel_protocol_type_radio, tvb, 7, 1, ENC_NA);
                proto_tree_add_item(protocol_type_tree, hf_asphodel_protocol_type_remote, tvb, 7, 1, ENC_NA);
                proto_tree_add_item(protocol_type_tree, hf_asphodel_protocol_type_bootloader, tvb, 7, 1, ENC_NA);
            }
            else
            {
                expert_add_info(pinfo, ti, &ei_asphodel_bad_length);
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Notify");
            }
            break;
        default:
            // unknown message type
            expert_add_info(pinfo, ti, &ei_asphodel_unknown_type);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Unknown(%02x)", type);
            break;
        }
    }

    return tvb_captured_length(tvb);
}

static guint
get_asphodel_tcp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return ((guint)tvb_get_ntohs(tvb, offset)) + 2;
}

static int
dissect_asphodel_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Asphodel");
    col_clear(pinfo->cinfo, COL_INFO);

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 2, get_asphodel_tcp_pdu_len, dissect_asphodel_tcp_pdu, data);
    return tvb_reported_length(tvb);
}

static int
dissect_asphodel_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *asphodel_tree;
    proto_tree *protocol_type_tree;
    conversation_t *conversation;
    guint offset;
    guint len;
    guint protocol_type;
    guint16 incoming_cmd_buffer_size;
    guint16 outgoing_cmd_buffer_size;
    guint16 remote_incoming_cmd_buffer_size;
    guint16 remote_outgoing_cmd_buffer_size;
    guint8 *serial_number;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Asphodel");

    ti = proto_tree_add_item(tree, proto_asphodel, tvb, 0, -1, ENC_NA);
    asphodel_tree = proto_item_add_subtree(ti, ett_asphodel);
    proto_item_set_text(ti, "Asphodel Response");

    if (tvb_captured_length(tvb) < 16)
    {
        // too short
        return 0;
    }

    proto_tree_add_item(asphodel_tree, hf_asphodel_tcp_version, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(asphodel_tree, hf_asphodel_connected, tvb, 1, 1, ENC_NA);

    incoming_cmd_buffer_size = tvb_get_ntohs(tvb, 2);
    ti = proto_tree_add_uint(asphodel_tree, hf_asphodel_max_incoming_param_length, tvb, 2, 2, incoming_cmd_buffer_size - 2);
    if (incoming_cmd_buffer_size <= 2)
    {
        expert_add_info(pinfo, ti, &ei_asphodel_bad_param_length);
    }

    outgoing_cmd_buffer_size = tvb_get_ntohs(tvb, 4);
    ti = proto_tree_add_uint(asphodel_tree, hf_asphodel_max_outgoing_param_length, tvb, 4, 2, outgoing_cmd_buffer_size - 2);
    if (outgoing_cmd_buffer_size <= 2)
    {
        expert_add_info(pinfo, ti, &ei_asphodel_bad_param_length);
    }

    proto_tree_add_item(asphodel_tree, hf_asphodel_stream_packet_length, tvb, 6, 2, ENC_BIG_ENDIAN);

    ti = proto_tree_add_item_ret_uint(asphodel_tree, hf_asphodel_protocol_type, tvb, 8, 1, ENC_NA, &protocol_type);
    protocol_type_tree = proto_item_add_subtree(ti, ett_asphodel_protocol_type);
    proto_tree_add_item(protocol_type_tree, hf_asphodel_protocol_type_rf_power, tvb, 8, 1, ENC_NA);
    proto_tree_add_item(protocol_type_tree, hf_asphodel_protocol_type_radio, tvb, 8, 1, ENC_NA);
    proto_tree_add_item(protocol_type_tree, hf_asphodel_protocol_type_remote, tvb, 8, 1, ENC_NA);
    proto_tree_add_item(protocol_type_tree, hf_asphodel_protocol_type_bootloader, tvb, 8, 1, ENC_NA);

    offset = 9;

    len = tvb_strsize(tvb, offset);
    proto_tree_add_item(asphodel_tree, hf_asphodel_serial_number, tvb, offset, len, ENC_UTF_8 | ENC_NA);
    serial_number = tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_UTF_8);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Asphodel Response (%s)", serial_number);
    offset += len;

    proto_tree_add_item(asphodel_tree, hf_asphodel_board_rev, tvb, offset, 1, ENC_NA);
    offset += 1;

    len = tvb_strsize(tvb, offset);
    proto_tree_add_item(asphodel_tree, hf_asphodel_board_type, tvb, offset, len, ENC_UTF_8 | ENC_NA);
    offset += len;

    len = tvb_strsize(tvb, offset);
    proto_tree_add_item(asphodel_tree, hf_asphodel_build_info, tvb, offset, len, ENC_UTF_8 | ENC_NA);
    offset += len;

    len = tvb_strsize(tvb, offset);
    proto_tree_add_item(asphodel_tree, hf_asphodel_build_date, tvb, offset, len, ENC_UTF_8 | ENC_NA);
    offset += len;

    len = tvb_strsize(tvb, offset);
    proto_tree_add_item(asphodel_tree, hf_asphodel_user_tag1, tvb, offset, len, ENC_UTF_8 | ENC_NA);
    offset += len;

    len = tvb_strsize(tvb, offset);
    proto_tree_add_item(asphodel_tree, hf_asphodel_user_tag2, tvb, offset, len, ENC_UTF_8 | ENC_NA);
    offset += len;

    if (protocol_type & ASPHODEL_PROTOCOL_TYPE_RADIO)
    {
        remote_incoming_cmd_buffer_size = tvb_get_ntohs(tvb, 2);
        ti = proto_tree_add_uint(asphodel_tree, hf_asphodel_remote_max_incoming_param_length, tvb, offset, 2, remote_incoming_cmd_buffer_size - 2);
        if (remote_incoming_cmd_buffer_size <= 2)
        {
            expert_add_info(pinfo, ti, &ei_asphodel_bad_param_length);
        }

        remote_outgoing_cmd_buffer_size = tvb_get_ntohs(tvb, 4);
        ti = proto_tree_add_uint(asphodel_tree, hf_asphodel_remote_max_outgoing_param_length, tvb, offset + 2, 2, remote_outgoing_cmd_buffer_size - 2);
        if (remote_outgoing_cmd_buffer_size <= 2)
        {
            expert_add_info(pinfo, ti, &ei_asphodel_bad_param_length);
        }

        proto_tree_add_item(asphodel_tree, hf_asphodel_remote_stream_packet_length, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    }

    conversation = find_conversation(pinfo->num, &pinfo->src, 0, CONVERSATION_UDP, pinfo->srcport, 0, NO_ADDR_B | NO_PORT_B);
    if (!conversation)
    {
        conversation = conversation_new(pinfo->num, &pinfo->src, 0, CONVERSATION_TCP, pinfo->srcport, 0, NO_ADDR2 | NO_PORT2);
        conversation_set_dissector(conversation, asphodel_tcp_handle);
    }

    return tvb_reported_length(tvb);
}

static int
dissect_asphodel_inquiry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *asphodel_tree;
    conversation_t *conversation;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Asphodel");
    col_set_str(pinfo->cinfo, COL_INFO, "Asphodel Inquiry");

    if (tree != NULL)
    {
        ti = proto_tree_add_item(tree, proto_asphodel, tvb, 0, -1, ENC_NA);
        asphodel_tree = proto_item_add_subtree(ti, ett_asphodel);
        proto_item_set_text(ti, "Asphodel Inquiry");

        if (tvb_captured_length(tvb) >= 2)
        {
            proto_tree_add_item(asphodel_tree, hf_asphodel_version, tvb, 0, 2, ENC_BIG_ENDIAN);

            if (tvb_captured_length(tvb) > 2)
            {
                proto_tree_add_item(asphodel_tree, hf_asphodel_identifier, tvb, 2, -1, ENC_UTF_8 | ENC_NA);
            }
        }
    }

    conversation = find_conversation(pinfo->num, &pinfo->src, 0, CONVERSATION_UDP, pinfo->srcport, 0, NO_ADDR_B | NO_PORT_B);
    if (!conversation)
    {
        conversation = conversation_new(pinfo->num, &pinfo->src, 0, CONVERSATION_UDP, pinfo->srcport, 0, NO_ADDR2 | NO_PORT2);
        conversation_set_dissector(conversation, asphodel_response_handle);
    }

    return tvb_reported_length(tvb);
}

static gboolean
dissect_asphodel_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < 11)
    {
        return FALSE;
    }

    if (tvb_memeql(tvb, 2, "Asphodel", 9) != 0)
    {
        return FALSE;
    }

    dissect_asphodel_inquiry(tvb, pinfo, tree, data);

    return TRUE;
}

void
proto_register_asphodel(void)
{
    expert_module_t *expert_asphodel;

    static hf_register_info hf[] = {
        { &hf_asphodel_version,
            { "Version", "asphodel.version",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(asphodel_fmt_version), 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_identifier,
            { "Identifier", "asphodel.identifier",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_tcp_version,
            { "TCP Version", "asphodel.tcp_version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_connected,
            { "Connected", "asphodel.connected",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_max_incoming_param_length,
            { "Max Incoming Param Length", "asphodel.max_incoming_param_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_max_outgoing_param_length,
            { "Max Outgoing Param Length", "asphodel.max_outgoing_param_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_stream_packet_length,
            { "Stream Packet Length", "asphodel.stream_packet_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_protocol_type,
            { "Protocol Type", "asphodel.protocol_type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_protocol_type_rf_power,
            { "RF Power", "asphodel.protocol_type.rf_power",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), ASPHODEL_PROTOCOL_TYPE_RF_POWER,
            NULL, HFILL }
        },
        { &hf_asphodel_protocol_type_radio,
            { "Radio", "asphodel.protocol_type.radio",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), ASPHODEL_PROTOCOL_TYPE_RADIO,
            NULL, HFILL }
        },
        { &hf_asphodel_protocol_type_remote,
            { "Remote", "asphodel.protocol_type.remote",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), ASPHODEL_PROTOCOL_TYPE_REMOTE,
            NULL, HFILL }
        },
        { &hf_asphodel_protocol_type_bootloader,
            { "Bootloader", "asphodel.protocol_type.bootloader",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), ASPHODEL_PROTOCOL_TYPE_BOOTLOADER,
            NULL, HFILL }
        },
        { &hf_asphodel_serial_number,
            { "Serial Number", "asphodel.serial_number",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_board_rev,
            { "Board Rev", "asphodel.board_rev",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_board_type,
            { "Board Type", "asphodel.board_type",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_build_info,
            { "Build Info", "asphodel.build_info",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_build_date,
            { "Build Date", "asphodel.build_date",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_user_tag1,
            { "User Tag 1", "asphodel.user_tag1",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_user_tag2,
            { "User Tag 2", "asphodel.user_tag2",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_remote_max_incoming_param_length,
            { "Remote Max Incoming Param Length", "asphodel.remote_max_incoming_param_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_remote_max_outgoing_param_length,
            { "Remote Max Outgoing Param Length", "asphodel.remote_max_outgoing_param_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_remote_stream_packet_length,
            { "Remote Stream Packet Length", "asphodel.remote_stream_packet_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_length,
            { "Length", "asphodel.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_type,
            { "Type", "asphodel.type",
            FT_UINT8, BASE_HEX, VALS(asphodel_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_seq,
            { "Sequence", "asphodel.seq",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_cmd,
            { "Command", "asphodel.cmd",
            FT_UINT8, BASE_HEX, VALS(asphodel_cmd_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_err_code,
            { "Error Code", "asphodel.err_code",
            FT_UINT8, BASE_HEX, VALS(asphodel_err_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_params,
            { "Command Parameter Data", "asphodel.params",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_stream_data,
            { "Stream Data", "asphodel.stream_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_notify,
            { "Notify", "asphodel.notify",
            FT_BOOLEAN, BASE_NONE, TFS(&notify_connect_disconnect), 0x0,
            NULL, HFILL }
        },
        { &hf_asphodel_notify_serial,
            { "Notify Serial Number", "asphodel.notify_serial",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_asphodel,
        &ett_asphodel_protocol_type,
    };

    static ei_register_info ei[] = {
        { &ei_asphodel_bad_param_length,
            { "asphodel.bad_param_length", PI_PROTOCOL, PI_WARN,
            "Bad parameter length", EXPFILL }
        },
        { &ei_asphodel_bad_length,
            { "asphodel.bad_cmd_length", PI_PROTOCOL, PI_WARN,
            "Bad length", EXPFILL }
        },
        { &ei_asphodel_cmd_error,
            { "asphodel.cmd_error", PI_RESPONSE_CODE, PI_NOTE,
            "Command error response", EXPFILL }
        },
        { &ei_asphodel_unknown_type,
            { "asphodel.unknown_type", PI_PROTOCOL, PI_WARN,
            "Unknown message type", EXPFILL }
        },
    };

    /* Register the protocol name and description */
    proto_asphodel = proto_register_protocol("Asphodel", "Asphodel", "asphodel");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_asphodel, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_asphodel = expert_register_protocol(proto_asphodel);
    expert_register_field_array(expert_asphodel, ei, array_length(ei));
}

void
proto_reg_handoff_asphodel(void)
{
    asphodel_inquiry_handle = create_dissector_handle(dissect_asphodel_inquiry, proto_asphodel);
    asphodel_response_handle = create_dissector_handle(dissect_asphodel_response, proto_asphodel);
    asphodel_tcp_handle = create_dissector_handle(dissect_asphodel_tcp, proto_asphodel);

    heur_dissector_add("udp", dissect_asphodel_heur_udp, "Asphodel over UDP",
                       "asphodel_inquiry", proto_asphodel, HEURISTIC_ENABLE);
    dissector_add_for_decode_as("udp.port", asphodel_response_handle);
    dissector_add_for_decode_as("tcp.port", asphodel_tcp_handle);
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
