/* packet-acr122.c
 * Routines for ACR122 USB NFC dongle
 *
 * Copyright 2013, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See thehf_class
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include "packet-usb.h"

static int proto_acr122                                                    = -1;

static int hf_class                                                        = -1;
static int hf_ins                                                          = -1;
static int hf_p1                                                           = -1;
static int hf_p2                                                           = -1;
static int hf_length                                                       = -1;
static int hf_status_word                                                  = -1;
static int hf_status_word_sw1                                              = -1;
static int hf_status_word_sw2                                              = -1;
static int hf_status_word_led_reserved                                     = -1;
static int hf_status_word_led_green                                        = -1;
static int hf_status_word_led_red                                          = -1;
static int hf_command                                                      = -1;
static int hf_response                                                     = -1;
static int hf_response_for                                                 = -1;
static int hf_picc_operating_auto_picc_polling                             = -1;
static int hf_picc_operating_auto_ats_generation                           = -1;
static int hf_picc_operating_polling_interval                              = -1;
static int hf_picc_operating_felica_424k                                   = -1;
static int hf_picc_operating_felica_212k                                   = -1;
static int hf_picc_operating_topaz                                         = -1;
static int hf_picc_operating_iso_14443_type_b                              = -1;
static int hf_picc_operating_iso_14443_type_a                              = -1;
static int hf_firmware_version                                             = -1;
static int hf_led_green_blinking_state                                     = -1;
static int hf_led_red_blinking_state                                       = -1;
static int hf_led_green_mask                                               = -1;
static int hf_led_red_mask                                                 = -1;
static int hf_led_initial_green_blinking_state                             = -1;
static int hf_led_initial_red_blinking_state                               = -1;
static int hf_led_final_green_state                                        = -1;
static int hf_led_final_red_state                                          = -1;
static int hf_led_t1_duration                                              = -1;
static int hf_led_t2_duration                                              = -1;
static int hf_led_number_of_repetition                                     = -1;
static int hf_led_link_to_buzzer                                           = -1;
static int hf_timeout                                                      = -1;
static int hf_poll_buzzer_status                                           = -1;
static int hf_key                                                          = -1;
static int hf_key_structure                                                = -1;
static int hf_key_number                                                   = -1;
static int hf_key_type                                                     = -1;
static int hf_block_number                                                 = -1;
static int hf_source_block_number                                          = -1;
static int hf_target_block_number                                          = -1;
static int hf_vb_op                                                        = -1;
static int hf_static_byte                                                  = -1;
static int hf_version                                                      = -1;
static int hf_value                                                        = -1;
static int hf_uid                                                          = -1;
static int hf_ats                                                          = -1;
static int hf_data                                                         = -1;

static gint ett_acr122                                                 = -1;
static gint ett_p1_item                                                    = -1;
static gint ett_p2_item                                                    = -1;
static gint ett_status_word                                                = -1;
static gint ett_status_word_sw2                                            = -1;

static expert_field ei_unknown_command_or_invalid_parameters          = EI_INIT;

static dissector_handle_t  pn532_handle;

static wmem_tree_t *command_info = NULL;

typedef struct command_data_t {
    guint32  bus_id;
    guint32  device_address;
    guint32  endpoint;

    guint8   command;
    guint32  command_frame_number;
    guint32  response_frame_number;
} command_data_t;

/* Not part of protocol, generated values */
#define CMD_UNKNOWN                                 0x00
#define CMD_GET_DATA_UID                            0x01
#define CMD_GET_DATA_ATS                            0x02
#define CMD_LOAD_AUTHENTICATION_KEYS                0x03
#define CMD_AUTHENTICATION_OBSOLETE                 0x04
#define CMD_AUTHENTICATION                          0x05
#define CMD_READ_BINARY_BLOCKS                      0x06
#define CMD_UPDATE_BINARY_BLOCKS                    0x07
#define CMD_VALUE_BLOCK_OPERATION                   0x08
#define CMD_READ_VALUE_BLOCK                        0x09
#define CMD_RESTORE_VALUE_BLOCK                     0x0A
#define CMD_DIRECT_TRANSMIT                         0x0B
#define CMD_BI_COLOR_AND_BUZZER_LED_CONTROL         0x0C
#define CMD_GET_FIRMWARE_VERSION                    0x0D
#define CMD_GET_PICC_OPERATING_PARAMETER            0x0E
#define CMD_SET_PICC_OPERATING_PARAMETER            0x0F
#define CMD_SET_TIMEOUT_PARAMETER                   0x10
#define CMD_SET_BUZZER_OUTPUT_FOR_CARD_DETECTION    0x11

static const value_string command_vals[] = {
    { CMD_GET_DATA_UID,                          "Get Data - UID" },
    { CMD_GET_DATA_ATS,                          "Get Data - ATS" },
    { CMD_LOAD_AUTHENTICATION_KEYS,              "Load Authentication Keys" },
    { CMD_AUTHENTICATION_OBSOLETE,               "Authentication (Obsolete)" },
    { CMD_AUTHENTICATION,                        "Authentication" },
    { CMD_READ_BINARY_BLOCKS,                    "Read Binary Blocks" },
    { CMD_UPDATE_BINARY_BLOCKS,                  "Update Binary Blocks" },
    { CMD_VALUE_BLOCK_OPERATION,                 "Value Block Operation" },
    { CMD_READ_VALUE_BLOCK,                      "Read Value Block" },
    { CMD_RESTORE_VALUE_BLOCK,                   "Restore Value Block" },
    { CMD_DIRECT_TRANSMIT,                       "Direct Transmit" },
    { CMD_BI_COLOR_AND_BUZZER_LED_CONTROL,       "Bi-Color and Buzzer LED Control" },
    { CMD_GET_FIRMWARE_VERSION,                  "Get Firmware Version" },
    { CMD_GET_PICC_OPERATING_PARAMETER,          "Get PICC Operating Parameter" },
    { CMD_SET_PICC_OPERATING_PARAMETER,          "Set PICC Operating Parameter" },
    { CMD_SET_TIMEOUT_PARAMETER,                 "Set Timeout Parameter" },
    { CMD_SET_BUZZER_OUTPUT_FOR_CARD_DETECTION,  "Set Buzzer Output for Card Detection" },
    { 0, NULL }
};
static value_string_ext command_vals_ext = VALUE_STRING_EXT_INIT(command_vals);

static const range_string status_word_rvals[] = {
    { 0x6300, 0x6300,   "Operation Fail" },
    { 0x6a81, 0x6a81,   "Function not Supported" },
    { 0x9000, 0x90FF,   "Success" },
    { 0, 0, NULL }
};

static const value_string link_to_buzzer_vals[] = {
    { 0x00,  "The buzzer will not turn on" },
    { 0x01,  "The buzzer will turn on during the T1 Duration" },
    { 0x02,  "The buzzer will turn on during the T2 Duration" },
    { 0x03,  "The buzzer will turn on during the T1 and T2 Duration" },
    { 0, NULL }
};

static const value_string key_structure_vals[] = {
    { 0x00,  "Key is loaded into the reader volatile memory" },
    { 0, NULL }
};

static const value_string poll_buzzer_status_vals[] = {
    { 0x00,  "Buzzer disabled on card detected" },
    { 0xFF,  "Buzzer enabled on card detected" },
    { 0, NULL }
};

static const value_string key_type_vals[] = {
    { 0x60,  "Type A" },
    { 0x61,  "Type B" },
    { 0, NULL }
};

static const value_string vb_op_vals[] = {
    { 0x00,  "Store the \"Value\" into the block. The block will then be converted to a value block." },
    { 0x01,  "Increment the value of the value block by the \"Value\". This command is only valid for value block." },
    { 0x02,  "Decrement the value of the value block by the \"Value\". This command is only valid for value block." },
    { 0, NULL }
};

void proto_register_acr122(void);
void proto_reg_handoff_acr122(void);

static void
duration_base(gchar *buf, guint32 value) {
        g_snprintf(buf, ITEM_LABEL_LENGTH, "%u.%03u s", value * 100 / 1000, value * 100 % 1000);
}

static void
timeout_base(gchar *buf, guint32 value) {
        if (value == 0x00)
            g_snprintf(buf, ITEM_LABEL_LENGTH, "No timeout check");
        else if (value == 0xFF)
            g_snprintf(buf, ITEM_LABEL_LENGTH, "Wait until the contactless chip responds");
        else if (value < 12)
            g_snprintf(buf, ITEM_LABEL_LENGTH, "%u [s]", value * 5);
        else
            g_snprintf(buf, ITEM_LABEL_LENGTH, "%u:%02u [mm:ss]", value * 5 / 60, value * 5 % 60);
}


static gint
dissect_acr122(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item      *main_item;
    proto_tree      *main_tree;
    proto_item      *p1_item;
    proto_tree      *p1_tree;
    proto_item      *p2_item;
    proto_tree      *p2_tree;
    proto_item      *sub_item;
    proto_item      *sub_tree;
    proto_item      *sw2_item;
    proto_item      *sw2_tree;
    gint             offset = 0;
    guint32          value;
    tvbuff_t        *next_tvb;
    guint8           acr_class;
    guint8           ins;
    guint8           p1;
    guint8           p2;
    guint8           length;
    guint8           command = CMD_UNKNOWN;
    command_data_t  *command_data;
    usb_conv_info_t *usb_conv_info;
    wmem_tree_key_t  key[5];
    guint32          bus_id;
    guint32          device_address;
    guint32          endpoint;
    guint32          k_bus_id;
    guint32          k_device_address;
    guint32          k_endpoint;
    guint32          k_frame_number;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ACR 122");
    col_clear(pinfo->cinfo, COL_INFO);

    main_item = proto_tree_add_item(tree, proto_acr122, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_acr122);

    if (!data) return offset;
    usb_conv_info = (usb_conv_info_t *) data;

    bus_id = usb_conv_info->bus_id;
    device_address = usb_conv_info->device_address;
    endpoint = usb_conv_info->endpoint;

    k_bus_id  = bus_id;
    k_device_address  = device_address;
    k_endpoint        = endpoint;
    k_frame_number    = pinfo->num;

    key[0].length = 1;
    key[0].key = &k_bus_id;
    key[1].length = 1;
    key[1].key = &k_device_address;
    key[2].length = 1;
    key[2].key = &k_endpoint;
    key[3].length = 1;
    key[3].key = &k_frame_number;
    key[4].length = 0;
    key[4].key = NULL;


    if (pinfo->p2p_dir == P2P_DIR_SENT) { /* Request */
        acr_class = tvb_get_guint8(tvb, offset);
        ins = tvb_get_guint8(tvb, offset + 1);
        p1 = tvb_get_guint8(tvb, offset + 2);
        p2 = tvb_get_guint8(tvb, offset + 3);
        length = tvb_get_guint8(tvb, offset + 4);

        /* Recognize command by simple heuristic */
        if (acr_class == 0xFF) {
            if (ins == 0xCA && p1 == 0x00 && p2 == 0x00 && length == 0)
                command = CMD_GET_DATA_UID;
            if (ins == 0xCA && p1 == 0x01 && p2 == 0x00 && length == 0)
                command = CMD_GET_DATA_ATS;
            else if (ins == 0x82 && length == 6)
                command = CMD_LOAD_AUTHENTICATION_KEYS;
            else if (ins == 0x88 && p1 == 0x00)
                command = CMD_AUTHENTICATION_OBSOLETE;
            else if (ins == 0x86 && p1 == 0x00 && p2 == 0x00 && length == 5)
                command = CMD_AUTHENTICATION;
            else if (ins == 0xB0 && p1 == 0x00)
                command = CMD_READ_BINARY_BLOCKS;
            else if (ins == 0xD6 && p1 == 0x00)
                command = CMD_UPDATE_BINARY_BLOCKS;
            else if (ins == 0xD7 && p1 == 0x00 && length == 5)
                command = CMD_VALUE_BLOCK_OPERATION;
            else if (ins == 0xB1 && p1 == 0x00 && length == 4)
                command = CMD_READ_VALUE_BLOCK;
            else if (ins == 0xD7 && p1 == 0x00 && length == 2)
                command = CMD_RESTORE_VALUE_BLOCK;
            else if (ins == 0x00 && p1 == 0x00 && p2 == 0x00)
                command = CMD_DIRECT_TRANSMIT;
            else if (ins == 0x00 && p1 == 0x40 && length == 4)
                command = CMD_BI_COLOR_AND_BUZZER_LED_CONTROL;
            else if (ins == 0x00 && p1 == 0x48 && p2 == 0x00)
                command = CMD_GET_FIRMWARE_VERSION;
            else if (ins == 0x00 && p1 == 0x50 && p2 == 0x00)
                command = CMD_GET_PICC_OPERATING_PARAMETER;
            else if (ins == 0x00 && p1 == 0x51 && length == 0)
                command = CMD_SET_PICC_OPERATING_PARAMETER;
            else if (ins == 0x00 && p1 == 0x41 && length == 0)
                command = CMD_SET_TIMEOUT_PARAMETER;
            else if (ins == 0x00 && p1 == 0x52 && length == 0)
                command = CMD_SET_BUZZER_OUTPUT_FOR_CARD_DETECTION;
        }

        sub_item = proto_tree_add_uint(main_tree, hf_command, tvb, offset, 4 + length, command);
        PROTO_ITEM_SET_GENERATED(sub_item);
        if (command == CMD_UNKNOWN)
            expert_add_info(pinfo, sub_item, &ei_unknown_command_or_invalid_parameters);

        col_add_fstr(pinfo->cinfo, COL_INFO, "Command: %s", val_to_str_ext_const(command, &command_vals_ext, "Unknown"));

        proto_tree_add_item(main_tree, hf_class, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(main_tree, hf_ins, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        p1_item = proto_tree_add_item(main_tree, hf_p1, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        p2_item = proto_tree_add_item(main_tree, hf_p2, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(main_tree, hf_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        switch (command) {
        case CMD_DIRECT_TRANSMIT:
            if (length > 0) {
                next_tvb = tvb_new_subset_length(tvb, offset, length);
                call_dissector_with_data(pn532_handle, next_tvb, pinfo, tree, usb_conv_info);
                offset += length;
            }
            break;
        case CMD_BI_COLOR_AND_BUZZER_LED_CONTROL:
            p2_tree = proto_item_add_subtree(p2_item, ett_p2_item);
            proto_tree_add_item(p2_tree, hf_led_green_blinking_state, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_led_red_blinking_state, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_led_green_mask, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_led_red_mask, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_led_initial_green_blinking_state, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_led_initial_red_blinking_state, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_led_final_green_state, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_led_final_red_state, tvb, offset - 2, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(main_tree, hf_led_t1_duration, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(main_tree, hf_led_t2_duration, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(main_tree, hf_led_number_of_repetition, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(main_tree, hf_led_link_to_buzzer, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case  CMD_GET_DATA_UID:
        case  CMD_GET_DATA_ATS:
            /* Nothing to decode */
            break;
        case CMD_LOAD_AUTHENTICATION_KEYS:
            p1_tree = proto_item_add_subtree(p1_item, ett_p1_item);
            proto_tree_add_item(p1_tree, hf_key_structure, tvb, offset - 3, 1, ENC_BIG_ENDIAN);

            p2_tree = proto_item_add_subtree(p2_item, ett_p2_item);
            proto_tree_add_item(p2_tree, hf_key_number, tvb, offset - 2, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(main_tree, hf_key, tvb, offset, 6, ENC_NA);
            offset += 6;
            break;
        case CMD_AUTHENTICATION_OBSOLETE:
            p2_tree = proto_item_add_subtree(p2_item, ett_p2_item);
            proto_tree_add_item(p2_tree, hf_block_number, tvb, offset - 2, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(main_tree, hf_key_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(main_tree, hf_key_number, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case CMD_AUTHENTICATION:
            proto_tree_add_item(main_tree, hf_version, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_block_number, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(main_tree, hf_key_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(main_tree, hf_key_number, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case CMD_READ_BINARY_BLOCKS:
            p2_tree = proto_item_add_subtree(p2_item, ett_p2_item);
            proto_tree_add_item(p2_tree, hf_block_number, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            break;
        case CMD_UPDATE_BINARY_BLOCKS:
            p2_tree = proto_item_add_subtree(p2_item, ett_p2_item);
            proto_tree_add_item(p2_tree, hf_block_number, tvb, offset - 2, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(main_tree, hf_data, tvb, offset, length, ENC_NA);
            offset += length;
            break;
        case CMD_VALUE_BLOCK_OPERATION:
            p2_tree = proto_item_add_subtree(p2_item, ett_p2_item);
            proto_tree_add_item(p2_tree, hf_block_number, tvb, offset - 2, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(main_tree, hf_vb_op, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(main_tree, hf_value, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case CMD_READ_VALUE_BLOCK:
            p2_tree = proto_item_add_subtree(p2_item, ett_p2_item);
            proto_tree_add_item(p2_tree, hf_block_number, tvb, offset - 2, 1, ENC_BIG_ENDIAN);

            break;
        case CMD_RESTORE_VALUE_BLOCK:
            p2_tree = proto_item_add_subtree(p2_item, ett_p2_item);
            proto_tree_add_item(p2_tree, hf_source_block_number, tvb, offset - 2, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(main_tree, hf_static_byte, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(main_tree, hf_target_block_number, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case CMD_SET_PICC_OPERATING_PARAMETER:
            p2_tree = proto_item_add_subtree(p2_item, ett_p2_item);
            proto_tree_add_item(p2_tree, hf_picc_operating_auto_picc_polling, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_picc_operating_auto_ats_generation, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_picc_operating_polling_interval, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_picc_operating_felica_424k, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_picc_operating_felica_212k, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_picc_operating_topaz, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_picc_operating_iso_14443_type_b, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(p2_tree, hf_picc_operating_iso_14443_type_a, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            break;
        case CMD_SET_TIMEOUT_PARAMETER:
            p2_tree = proto_item_add_subtree(p2_item, ett_p2_item);
            proto_tree_add_item(p2_tree, hf_timeout, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            break;
        case CMD_SET_BUZZER_OUTPUT_FOR_CARD_DETECTION:
            p2_tree = proto_item_add_subtree(p2_item, ett_p2_item);
            proto_tree_add_item(p2_tree, hf_poll_buzzer_status, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            break;
        case CMD_GET_PICC_OPERATING_PARAMETER:
            /* No parameters */
            break;
        }

        if (!pinfo->fd->flags.visited) {
            command_data = wmem_new(wmem_file_scope(), command_data_t);
            command_data->bus_id = bus_id;
            command_data->device_address = device_address;
            command_data->endpoint = endpoint;

            command_data->command = command;
            command_data->command_frame_number = pinfo->num;
            command_data->response_frame_number = 0;

            wmem_tree_insert32_array(command_info, key, command_data);
        }

    } else { /* Response */
        guint32       command_frame_number = 0;
        gboolean      use_status_word = FALSE;
        wmem_tree_t  *wmem_tree;

        key[3].length = 0;
        key[3].key = NULL;

        wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(command_info, key);
        if (wmem_tree) {
            command_data = (command_data_t *) wmem_tree_lookup32_le(wmem_tree, pinfo->num);

            if (command_data && (command_data->response_frame_number == 0 ||
                    command_data->response_frame_number == pinfo->num)) {

                command = command_data->command;
                command_frame_number = command_data->command_frame_number;
                if (!pinfo->fd->flags.visited && command_data->response_frame_number == 0) {
                    command_data->response_frame_number = pinfo->num;
                }
            }
        }

        sub_item = proto_tree_add_uint(main_tree, hf_response, tvb, offset, tvb_captured_length_remaining(tvb, offset), command);
        PROTO_ITEM_SET_GENERATED(sub_item);

        col_add_fstr(pinfo->cinfo, COL_INFO, "Response: %s", val_to_str_ext_const(command, &command_vals_ext, "Unknown"));

        if (command != CMD_UNKNOWN) {
            sub_item = proto_tree_add_uint(main_tree, hf_response_for, tvb, offset, tvb_captured_length_remaining(tvb, offset), command_frame_number);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }

        switch (command) {
        case CMD_GET_FIRMWARE_VERSION:
            proto_tree_add_item(main_tree, hf_firmware_version, tvb, offset, -1, ENC_NA | ENC_ASCII);
            offset += tvb_captured_length_remaining(tvb, offset);
            break;

        case CMD_DIRECT_TRANSMIT:
            use_status_word = TRUE;

            if (tvb_captured_length_remaining(tvb, offset) > 2) {
                next_tvb = tvb_new_subset_length(tvb, offset, tvb_captured_length_remaining(tvb, offset) - 2);
                call_dissector_with_data(pn532_handle, next_tvb, pinfo, tree, usb_conv_info);
                offset += tvb_captured_length_remaining(tvb, offset) - 2;
            }
            break;


        case CMD_READ_BINARY_BLOCKS:
            use_status_word = TRUE;
            proto_tree_add_item(main_tree, hf_data, tvb, offset, tvb_captured_length_remaining(tvb, offset) - 2, ENC_NA);
            offset += tvb_captured_length_remaining(tvb, offset) - 2;
            break;

        case CMD_READ_VALUE_BLOCK:
            use_status_word = TRUE;
            proto_tree_add_item(main_tree, hf_value, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;

        case CMD_GET_DATA_UID:
            use_status_word = TRUE;
            proto_tree_add_item(main_tree, hf_uid, tvb, offset, tvb_captured_length_remaining(tvb, offset) - 2, ENC_NA);
            offset += tvb_captured_length_remaining(tvb, offset) - 2;
            break;

        case CMD_GET_DATA_ATS:
            use_status_word = TRUE;
            proto_tree_add_item(main_tree, hf_ats, tvb, offset, tvb_captured_length_remaining(tvb, offset) - 2, ENC_NA);
            offset += tvb_captured_length_remaining(tvb, offset) - 2;
            break;

        case CMD_BI_COLOR_AND_BUZZER_LED_CONTROL:
        case CMD_LOAD_AUTHENTICATION_KEYS:
        case CMD_AUTHENTICATION:
        case CMD_AUTHENTICATION_OBSOLETE:
        case CMD_UPDATE_BINARY_BLOCKS:
        case CMD_VALUE_BLOCK_OPERATION:
        case CMD_RESTORE_VALUE_BLOCK:
        case CMD_SET_TIMEOUT_PARAMETER:
        case CMD_SET_BUZZER_OUTPUT_FOR_CARD_DETECTION:
        case CMD_SET_PICC_OPERATING_PARAMETER:
        case CMD_GET_PICC_OPERATING_PARAMETER:
        default:
            use_status_word = TRUE;
            break;
        }

        if (use_status_word) {
            value = tvb_get_ntohs(tvb, offset);
            col_append_fstr(pinfo->cinfo, COL_INFO, " - %s%s",  (((value & 0xFF00) != 0x9000) && (value & 0xFF00) != 0x6100) ? "Error: " : "", rval_to_str(value, status_word_rvals, "Unknown error"));

            if ((value & 0xFF00) == 0x6100)
                col_append_fstr(pinfo->cinfo, COL_INFO, " - Length %u", value & 0x00FF);

            sub_item = proto_tree_add_item(main_tree, hf_status_word, tvb, offset, 2, ENC_BIG_ENDIAN);
            sub_tree = proto_item_add_subtree(sub_item, ett_status_word);
            proto_tree_add_item(sub_tree, hf_status_word_sw1, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            sw2_item = proto_tree_add_item(sub_tree, hf_status_word_sw2, tvb, offset, 1, ENC_BIG_ENDIAN);

            if (command == CMD_BI_COLOR_AND_BUZZER_LED_CONTROL) {
                sw2_tree = proto_item_add_subtree(sw2_item, ett_status_word_sw2);

                col_append_fstr(pinfo->cinfo, COL_INFO, " - Red LED: %s, Green LED: %s", (value & 0x02) ? "On" : "Off", (value & 0x01) ? "On" : "Off");

                proto_tree_add_item(sw2_tree, hf_status_word_led_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sw2_tree, hf_status_word_led_green, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sw2_tree, hf_status_word_led_red, tvb, offset, 1, ENC_BIG_ENDIAN);
            } else if (command == CMD_SET_PICC_OPERATING_PARAMETER || command == CMD_GET_PICC_OPERATING_PARAMETER) {
                sw2_tree = proto_item_add_subtree(sw2_item, ett_status_word_sw2);
                proto_tree_add_item(sw2_tree, hf_picc_operating_auto_picc_polling, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sw2_tree, hf_picc_operating_auto_ats_generation, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sw2_tree, hf_picc_operating_polling_interval, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sw2_tree, hf_picc_operating_felica_424k, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sw2_tree, hf_picc_operating_felica_212k, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sw2_tree, hf_picc_operating_topaz, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sw2_tree, hf_picc_operating_iso_14443_type_b, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sw2_tree, hf_picc_operating_iso_14443_type_a, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            }
            offset += 1;
        }
    }

    return offset;
}

void
proto_register_acr122(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_class,
            { "Class",                           "acr122.class",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ins,
            { "Ins",                             "acr122.ins",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_p1,
            { "P1",                              "acr122.p1",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_p2,
            { "P2",                              "acr122.p2",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_length,
            { "Length",                          "acr122.length",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_status_word,
            { "Status Word",                     "acr122.status_word",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(status_word_rvals), 0x00,
            NULL, HFILL }
        },
        { &hf_status_word_sw1,
            { "SW1",                             "acr122.status_word.sw1",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_status_word_sw2,
            { "SW2",                             "acr122.status_word.sw2",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_command,
            { "Command",                         "acr122.command",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &command_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_response,
            { "Response",                         "acr122.response",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &command_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_response_for,
            { "Response for",                    "acr122.response_for",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_picc_operating_auto_picc_polling,
            { "Auto PICC Polling",               "acr122.picc_operating.auto_picc_polling",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_picc_operating_auto_ats_generation,
            { "ATS Generation",                  "acr122.picc_operating.ats_generation",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_picc_operating_polling_interval,
            { "Polling Interval",                "acr122.picc_operating.polling_interval",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_picc_operating_felica_424k,
            { "FeliCa 424k",                     "acr122.picc_operating.felica_424k",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_picc_operating_felica_212k,
            { "FeliCa 212k",                     "acr122.picc_operating.felica_212k",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_picc_operating_topaz,
            { "Topaz",                           "acr122.picc_operating.topaz",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_picc_operating_iso_14443_type_b,
            { "ISO 14443 Type B",                "acr122.picc_operating.iso_14443_type_b",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_picc_operating_iso_14443_type_a,
            { "ISO 14443 Type A",                "acr122.picc_operating.iso_14443_type_a",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_firmware_version,
            { "Firmware Version",                "acr122.firmware_version",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_led_green_blinking_state,
            { "Green LED Blinking",              "acr122.led.green.blinking",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_led_red_blinking_state,
            { "Red LED Blinking",                "acr122.led.red.blinking",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_led_green_mask,
            { "Green LED Mask",                  "acr122.led.green.mask",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_led_red_mask,
            { "Red LED Mask",                    "acr122.led.red.mask",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_led_initial_green_blinking_state,
            { "Initial Green LED Blinking",      "acr122.led.green.initial",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_led_initial_red_blinking_state,
            { "Initial Red LED Blinking",        "acr122.led.red.initial",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_led_final_green_state,
            { "Final Green LED",                 "acr122.led.green.final",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_led_final_red_state,
            { "Final Red LED",                   "acr122.led.red.final",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_led_t1_duration,
            { "T1 Duration",                     "acr122.led.t1_duration",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(duration_base), 0x00,
            "Initial Blinking State", HFILL }
        },
        { &hf_led_t2_duration,
            { "T2 Duration",                     "acr122.led.t2_duration",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(duration_base), 0x00,
            "Toggle Blinking State", HFILL }
        },
        { &hf_led_number_of_repetition,
            { "Number of Repetition",            "acr122.led.number_of_repetition",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_led_link_to_buzzer,
            { "Link to Buzzer",                  "acr122.led.link_to_buzzer",
            FT_UINT8, BASE_HEX, VALS(link_to_buzzer_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_poll_buzzer_status,
            { "Poll Buzzer Status",              "acr122.poll_buzzer_status",
            FT_UINT8, BASE_HEX, VALS(poll_buzzer_status_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_timeout,
            { "Timeout",                         "acr122.timeout",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(timeout_base), 0x00,
            NULL, HFILL }
        },
        { &hf_status_word_led_reserved,
            { "Reserved",                        "acr122.status_word.sw2.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_status_word_led_green,
            { "Current Green LED",               "acr122.status_word.sw2.led.green",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_status_word_led_red,
            { "Current Red LED",                 "acr122.status_word.sw2.led.red",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_key,
            { "Key",                             "acr122.key",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_key_structure,
            { "Key Structure",                   "acr122.key_structure",
            FT_UINT8, BASE_HEX, VALS(key_structure_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_key_number,
            { "Key Number",                      "acr122.key_number",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_key_type,
            { "Key Type",                        "acr122.key_type",
            FT_UINT8, BASE_HEX, VALS(key_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_block_number,
            { "Block Number",                    "acr122.block_number",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_source_block_number,
            { "Source Block Number",             "acr122.source_block_number",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_target_block_number,
            { "Target Block Number",             "acr122.target_block_number",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_static_byte,
            { "Static Byte",                     "acr122.static_byte",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vb_op,
            { "VB Op",                           "acr122.vb_op",
            FT_UINT8, BASE_HEX, VALS(vb_op_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_version,
            { "Version",                         "acr122.version",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_value,
            { "Value",                           "acr122.value",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_uid,
            { "UID",                             "acr122.uid",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ats,
            { "ATS",                             "acr122.ats",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_data,
            { "Data",                            "acr122.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_acr122,
        &ett_p1_item,
        &ett_p2_item,
        &ett_status_word,
        &ett_status_word_sw2
    };

    static ei_register_info ei[] = {
        { &ei_unknown_command_or_invalid_parameters, { "acr122.expert.unknown_command", PI_PROTOCOL, PI_NOTE, "Unknown command or invalid parameters", EXPFILL }},
    };

    command_info = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_acr122 = proto_register_protocol("Advanced Card Systems ACR122", "ACR 122", "acr122");
    register_dissector("acr122", dissect_acr122, proto_acr122);

    proto_register_field_array(proto_acr122, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module = expert_register_protocol(proto_acr122);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol(proto_acr122, NULL);
    prefs_register_static_text_preference(module, "version",
            "ACR122U USB NFC Reader - Application Programming Interface V2.02",
            "Version of protocol supported by this dissector.");
}

void
proto_reg_handoff_acr122(void)
{
    pn532_handle = find_dissector_add_dependency("pn532", proto_acr122);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
