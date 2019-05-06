/* packet-btmesh-provisioning.c
 * Routines for Bluetooth mesh Provisioning PDU dissection
 *
 * Copyright 2019, Piotr Winiarczyk <wino45@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: Mesh Profile v1.0
 * https://www.bluetooth.com/specifications/mesh-specifications
 */

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-btmesh.h"

#define PROVISIONING_INVITE_PDU          0x00
#define PROVISIONING_CAPABILITIES_PDU    0x01
#define PROVISIONING_START_PDU           0x02
#define PROVISIONING_PUBLIC_KEY_PDU      0x03
#define PROVISIONING_INPUT_COMPLETE_PDU  0x04
#define PROVISIONING_CONFIRMATION_PDU    0x05
#define PROVISIONING_RANDOM_PDU          0x06
#define PROVISIONING_DATA_PDU            0x07
#define PROVISIONING_COMPLETE_PDU        0x08
#define PROVISIONING_FAILED_PDU          0x09

#define NO_OOB_AUTHENTICATION_IS_USED     0x00
#define STATIC_OOB_AUTHENTICATION_IS_USED 0x01
#define OUTPUT_OOB_AUTHENTICATION_IS_USED 0x02
#define INPUT_OOB_AUTHENTICATION_IS_USED  0x03

void proto_register_btmesh_provisioning(void);

static int proto_btmesh_provisioning = -1;
static int hf_btmesh_provisioning_pdu_type = -1;
static int hf_btmesh_provisioning_pdu_padding = -1;

static int hf_btmesh_provisioning_attention_duration = -1;

static int hf_btmesh_provisioning_number_of_elements = -1;
static int hf_btmesh_provisioning_algorithms = -1;
static int hf_btmesh_provisioning_algorithms_p256 = -1;
static int hf_btmesh_provisioning_algorithms_rfu = -1;
static int hf_btmesh_provisioning_public_key_type = -1;
static int hf_btmesh_provisioning_public_key_type_oob = -1;
static int hf_btmesh_provisioning_public_key_type_rfu = -1;
static int hf_btmesh_provisioning_static_oob_type = -1;
static int hf_btmesh_provisioning_static_oob_type_static_oob_available = -1;
static int hf_btmesh_provisioning_static_oob_type_rfu = -1;
static int hf_btmesh_provisioning_output_oob_size = -1;
static int hf_btmesh_provisioning_output_oob_action = -1;
static int hf_btmesh_provisioning_output_oob_action_blink = -1;
static int hf_btmesh_provisioning_output_oob_action_beep = -1;
static int hf_btmesh_provisioning_output_oob_action_vibrate = -1;
static int hf_btmesh_provisioning_output_oob_action_output_numeric = -1;
static int hf_btmesh_provisioning_output_oob_action_output_alphanumeric = -1;
static int hf_btmesh_provisioning_output_oob_action_output_rfu = -1;
static int hf_btmesh_provisioning_input_oob_size = -1;
static int hf_btmesh_provisioning_input_oob_action = -1;
static int hf_btmesh_provisioning_input_oob_action_push = -1;
static int hf_btmesh_provisioning_input_oob_action_twist = -1;
static int hf_btmesh_provisioning_input_oob_action_input_numeric = -1;
static int hf_btmesh_provisioning_input_oob_action_input_alphanumeric = -1;
static int hf_btmesh_provisioning_input_oob_action_rfu = -1;
static int hf_btmesh_provisioning_algorithm = -1;
static int hf_btmesh_provisioning_public_key = -1;
static int hf_btmesh_provisioning_authentication_method = -1;
static int hf_btmesh_provisioning_authentication_action_no_oob_action = -1;
static int hf_btmesh_provisioning_authentication_action_static_oob_action = -1;
static int hf_btmesh_provisioning_authentication_action_output_oob_action = -1;
static int hf_btmesh_provisioning_authentication_action_input_oob_action = -1;
static int hf_btmesh_provisioning_authentication_size_no_oob_action = -1;
static int hf_btmesh_provisioning_authentication_size_static_oob_action = -1;
static int hf_btmesh_provisioning_authentication_size_output_oob_action = -1;
static int hf_btmesh_provisioning_authentication_size_input_oob_action = -1;
static int hf_btmesh_provisioning_public_key_x = -1;
static int hf_btmesh_provisioning_public_key_y = -1;
static int hf_btmesh_provisioning_confirmation = -1;
static int hf_btmesh_provisioning_random = -1;
static int hf_btmesh_provisioning_encrypted_provisioning_data = -1;
static int hf_btmesh_provisioning_decrypted_provisioning_data_mic = -1;
static int hf_btmesh_provisioning_error_code = -1;

static int hf_btmesh_provisioning_unknown_data = -1;

static int ett_btmesh_provisioning = -1;
static int ett_btmesh_provisioning_algorithms = -1;
static int ett_btmesh_provisioning_public_key_type = -1;
static int ett_btmesh_provisioning_static_oob_type = -1;
static int ett_btmesh_provisioning_output_oob_action = -1;
static int ett_btmesh_provisioning_output_oob_size = -1;
static int ett_btmesh_provisioning_input_oob_action = -1;
static int ett_btmesh_provisioning_input_oob_size = -1;
static int ett_btmesh_provisioning_algorithm = -1;
static int ett_btmesh_provisioning_public_key = -1;
static int ett_btmesh_provisioning_authentication_method = -1;
static int ett_btmesh_provisioning_authentication_action = -1;
static int ett_btmesh_provisioning_authentication_size = -1;
static int ett_btmesh_provisioning_error_code = -1;

static expert_field ei_btmesh_provisioning_unknown_opcode = EI_INIT;
static expert_field ei_btmesh_provisioning_unknown_payload = EI_INIT;
static expert_field ei_btmesh_provisioning_unknown_authentication_method = EI_INIT;
static expert_field ei_btmesh_provisioning_rfu_not_zero = EI_INIT;
static expert_field ei_btmesh_provisioning_in_rfu_range = EI_INIT;
static expert_field ei_btmesh_provisioning_prohibited = EI_INIT;
static expert_field ei_btmesh_provisioning_zero_elements = EI_INIT;

static const value_string btmesh_provisioning_pdu_type_format[] = {
    { 0, "Provisioning Invite PDU" },
    { 1, "Provisioning Capabilities PDU" },
    { 2, "Provisioning Start PDU" },
    { 3, "Provisioning Public Key PDU" },
    { 4, "Provisioning Input Complete PDU" },
    { 5, "Provisioning Confirmation PDU" },
    { 6, "Provisioning Random PDU" },
    { 7, "Provisioning Data PDU" },
    { 8, "Provisioning Complete PDU" },
    { 9, "Provisioning Failed PDU" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_error_code_format[] = {
    { 0, "Prohibited" },
    { 1, "Invalid PDU" },
    { 2, "Invalid Format" },
    { 3, "Unexpected PDU" },
    { 4, "Confirmation Failed" },
    { 5, "Out of Resources" },
    { 6, "Decryption Failed" },
    { 7, "Unexpected Error" },
    { 8, "Cannot Assign Addresses" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_algorithm_format[] = {
    { 0, "FIPS P-256 Elliptic Curve" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_public_key_format[] = {
    { 0, "No OOB Public Key is used" },
    { 1, "OOB Public Key is used" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_authentication_method_format[] = {
    { 0, "No OOB authentication is used" },
    { 1, "Static OOB authentication is used" },
    { 2, "Output OOB authentication is used" },
    { 3, "Input OOB authentication is used" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_authentication_action_no_oob_action_format[] = {
    { 0, "None" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_authentication_action_static_oob_action_format[] = {
    { 0, "None" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_authentication_action_output_oob_action_format[] = {
    { 0, "Blink" },
    { 1, "Beep" },
    { 2, "Vibrate" },
    { 3, "Output Numeric" },
    { 4, "Output Alphanumeric" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_authentication_action_input_oob_action_format[] = {
    { 0, "Push" },
    { 1, "Twist" },
    { 2, "Input Numeric" },
    { 3, "Input Alphanumeric" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_authentication_size_no_oob_action_format[] = {
    { 0, "None" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_authentication_size_static_oob_action_format[] = {
    { 0, "None" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_authentication_size_output_oob_action_format[] = {
    { 0, "Prohibited" },
    { 1, "The Output OOB size in characters to be used" },
    { 2, "The Output OOB size in characters to be used" },
    { 3, "The Output OOB size in characters to be used" },
    { 4, "The Output OOB size in characters to be used" },
    { 5, "The Output OOB size in characters to be used" },
    { 6, "The Output OOB size in characters to be used" },
    { 7, "The Output OOB size in characters to be used" },
    { 8, "The Output OOB size in characters to be used" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_authentication_size_input_oob_action_format[] = {
    { 0, "Prohibited" },
    { 1, "The Input OOB size in characters to be used" },
    { 2, "The Input OOB size in characters to be used" },
    { 3, "The Input OOB size in characters to be used" },
    { 4, "The Input OOB size in characters to be used" },
    { 5, "The Input OOB size in characters to be used" },
    { 6, "The Input OOB size in characters to be used" },
    { 7, "The Input OOB size in characters to be used" },
    { 8, "The Input OOB size in characters to be used" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_output_oob_size_format[] = {
    { 0, "The device does not support output OOB" },
    { 1, "Maximum size in octets supported by the device" },
    { 2, "Maximum size in octets supported by the device" },
    { 3, "Maximum size in octets supported by the device" },
    { 4, "Maximum size in octets supported by the device" },
    { 5, "Maximum size in octets supported by the device" },
    { 6, "Maximum size in octets supported by the device" },
    { 7, "Maximum size in octets supported by the device" },
    { 8, "Maximum size in octets supported by the device" },
    { 0, NULL }
};

static const value_string btmesh_provisioning_input_oob_size_format[] = {
    { 0, "The device does not support input OOB" },
    { 1, "Maximum size in octets supported by the device" },
    { 2, "Maximum size in octets supported by the device" },
    { 3, "Maximum size in octets supported by the device" },
    { 4, "Maximum size in octets supported by the device" },
    { 5, "Maximum size in octets supported by the device" },
    { 6, "Maximum size in octets supported by the device" },
    { 7, "Maximum size in octets supported by the device" },
    { 8, "Maximum size in octets supported by the device" },
    { 0, NULL }
};

static gint
dissect_btmesh_provisioning_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *item, *algorithms_item, *public_key_type_item;
    proto_item *static_oob_type_item, *output_oob_action_item, *input_oob_action_item;
    proto_tree *sub_tree, *algorithms_tree, *public_key_type_tree;
    proto_tree *static_oob_type_tree, *output_oob_action_tree, *input_oob_action_tree;
    proto_item *expert_item;
    proto_tree *expert_tree;
    int offset = 0;
    btle_mesh_transport_ctx_t *tr_ctx;
    btle_mesh_transport_ctx_t dummy_ctx = {E_BTMESH_TR_UNKNOWN, FALSE, 0};
    guint8 authentication_method, authentication_action, authentication_size;
    guint8 provisioning_algorithm;
    guint8 prohibited_value, output_oob_size, input_oob_size;
    guint16 rfu_uint16;
    guint8 no_of_elements;
    guint8 error_code;
    guint8 provisioning_public_key;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT Mesh Provisioning PDU");

    if (data == NULL) {
        tr_ctx = &dummy_ctx;
    } else {
        tr_ctx = (btle_mesh_transport_ctx_t *) data;
    }

    item = proto_tree_add_item(tree, proto_btmesh_provisioning, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_btmesh_provisioning);

    proto_tree_add_item(sub_tree, hf_btmesh_provisioning_pdu_type, tvb, offset, 1, ENC_NA);
    guint8 pdu_type = tvb_get_guint8(tvb, offset) & 0x3F;
    proto_tree_add_item(sub_tree, hf_btmesh_provisioning_pdu_padding, tvb, offset, 1, ENC_NA);
    guint8 pdu_padding = (tvb_get_guint8(tvb, offset) & 0xC0) >> 6;
    if (pdu_padding != 0) {
        //Padding should be 0
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_provisioning_rfu_not_zero, tvb, offset, -1);
    }
    offset += 1;

    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(pdu_type, btmesh_provisioning_pdu_type_format, "Unknown Provisioning PDU"));
    if (tr_ctx->fragmented) {
        switch (tr_ctx->transport) {
            case E_BTMESH_TR_ADV:
                col_append_fstr(pinfo->cinfo, COL_INFO," (Message fragment %u)", tr_ctx->segment_index);

            break;
            case E_BTMESH_TR_PROXY:
                col_append_str(pinfo->cinfo, COL_INFO," (Last Segment)");

            break;
            default:
            //No default is needed since this is an additional information only

            break;
        }
    }

    switch(pdu_type) {
        case PROVISIONING_INVITE_PDU:
            proto_tree_add_item(sub_tree, hf_btmesh_provisioning_attention_duration, tvb, offset, 1, ENC_NA);
            offset += 1;

        break;
        case PROVISIONING_CAPABILITIES_PDU:
            proto_tree_add_item(sub_tree, hf_btmesh_provisioning_number_of_elements, tvb, offset, 1, ENC_NA);
            no_of_elements = tvb_get_guint8(tvb, offset);
            if (no_of_elements == 0) {
                proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_provisioning_zero_elements, tvb, offset, -1);
            }
            offset += 1;

            algorithms_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_algorithms, tvb, offset, 2, ENC_NA);
            algorithms_tree = proto_item_add_subtree(algorithms_item, ett_btmesh_provisioning_algorithms);
            proto_tree_add_item(algorithms_tree, hf_btmesh_provisioning_algorithms_p256, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(algorithms_tree, hf_btmesh_provisioning_algorithms_rfu, tvb, offset, 2, ENC_NA);
            rfu_uint16 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) >> 1;
            if (rfu_uint16 != 0) {
                proto_tree_add_expert(algorithms_tree, pinfo, &ei_btmesh_provisioning_rfu_not_zero, tvb, offset, -1);
            }
            offset += 2;

            public_key_type_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_public_key_type, tvb, offset, 1, ENC_NA);
            public_key_type_tree = proto_item_add_subtree(public_key_type_item, ett_btmesh_provisioning_public_key_type);
            proto_tree_add_item(public_key_type_tree, hf_btmesh_provisioning_public_key_type_oob, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(public_key_type_tree, hf_btmesh_provisioning_public_key_type_rfu, tvb, offset, 1, ENC_NA);
            prohibited_value = tvb_get_guint8(tvb, offset) >> 1;
            if (prohibited_value != 0) {
                proto_tree_add_expert(public_key_type_tree, pinfo, &ei_btmesh_provisioning_prohibited, tvb, offset, -1);
            }
            offset += 1;

            static_oob_type_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_static_oob_type, tvb, offset, 1, ENC_NA);
            static_oob_type_tree = proto_item_add_subtree(static_oob_type_item, ett_btmesh_provisioning_static_oob_type);
            proto_tree_add_item(static_oob_type_tree, hf_btmesh_provisioning_static_oob_type_static_oob_available, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(static_oob_type_tree, hf_btmesh_provisioning_static_oob_type_rfu, tvb, offset, 1, ENC_NA);
            prohibited_value = tvb_get_guint8(tvb, offset) >> 1;
            if (prohibited_value != 0) {
                proto_tree_add_expert(static_oob_type_tree, pinfo, &ei_btmesh_provisioning_prohibited, tvb, offset, -1);
            }
            offset += 1;

            expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_output_oob_size, tvb, offset, 1, ENC_NA);
            output_oob_size = tvb_get_guint8(tvb, offset);
            if (output_oob_size >= 9) {
                expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_output_oob_size);
                proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
            }
            offset += 1;

            output_oob_action_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_output_oob_action, tvb, offset, 2, ENC_NA);
            output_oob_action_tree = proto_item_add_subtree(output_oob_action_item, ett_btmesh_provisioning_output_oob_action);
            proto_tree_add_item(output_oob_action_tree, hf_btmesh_provisioning_output_oob_action_blink, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(output_oob_action_tree, hf_btmesh_provisioning_output_oob_action_beep, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(output_oob_action_tree, hf_btmesh_provisioning_output_oob_action_vibrate, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(output_oob_action_tree, hf_btmesh_provisioning_output_oob_action_output_numeric, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(output_oob_action_tree, hf_btmesh_provisioning_output_oob_action_output_alphanumeric, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(output_oob_action_tree, hf_btmesh_provisioning_output_oob_action_output_rfu, tvb, offset, 2, ENC_NA);
            rfu_uint16 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) >> 5;
            if (rfu_uint16 != 0) {
                proto_tree_add_expert(output_oob_action_tree, pinfo, &ei_btmesh_provisioning_rfu_not_zero, tvb, offset, -1);
            }
            offset += 2;

            expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_input_oob_size, tvb, offset, 1, ENC_NA);
            input_oob_size = tvb_get_guint8(tvb, offset);
            if (input_oob_size >= 9) {
                expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_input_oob_size);
                proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
            }
            offset += 1;

            input_oob_action_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_input_oob_action, tvb, offset, 2, ENC_NA);
            input_oob_action_tree = proto_item_add_subtree(input_oob_action_item, ett_btmesh_provisioning_input_oob_action);
            proto_tree_add_item(input_oob_action_tree, hf_btmesh_provisioning_input_oob_action_push, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(input_oob_action_tree, hf_btmesh_provisioning_input_oob_action_twist, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(input_oob_action_tree, hf_btmesh_provisioning_input_oob_action_input_numeric, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(input_oob_action_tree, hf_btmesh_provisioning_input_oob_action_input_alphanumeric, tvb, offset, 2, ENC_NA);
            proto_tree_add_item(input_oob_action_tree, hf_btmesh_provisioning_input_oob_action_rfu, tvb, offset, 2, ENC_NA);
            rfu_uint16 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) >> 4;
            if (rfu_uint16 != 0) {
                proto_tree_add_expert(input_oob_action_tree, pinfo, &ei_btmesh_provisioning_rfu_not_zero, tvb, offset, -1);
            }
            offset += 2;

        break;
        case PROVISIONING_START_PDU:
            expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_algorithm, tvb, offset, 1, ENC_NA);
            provisioning_algorithm = tvb_get_guint8(tvb, offset);
            if (provisioning_algorithm >= 1) {
                expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_algorithm);
                proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
            }
            offset += 1;

            expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_public_key, tvb, offset, 1, ENC_NA);
            provisioning_public_key = tvb_get_guint8(tvb, offset);
            if (provisioning_public_key >= 2) {
                expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_public_key);
                proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
            }
            offset += 1;

            expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_authentication_method, tvb, offset, 1, ENC_NA);
            authentication_method = tvb_get_guint8(tvb, offset);
            offset += 1;

            switch(authentication_method){
                case NO_OOB_AUTHENTICATION_IS_USED:
                    expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_authentication_action_no_oob_action, tvb, offset, 1, ENC_NA);
                    authentication_action = tvb_get_guint8(tvb, offset);
                    if (authentication_action != 0) {
                        expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_authentication_action);
                        proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
                    }
                    offset += 1;

                    expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_authentication_size_no_oob_action, tvb, offset, 1, ENC_NA);
                    authentication_size = tvb_get_guint8(tvb, offset);
                    if (authentication_size != 0) {
                        expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_authentication_size);
                        proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
                    }
                    offset += 1;

                break;
                case STATIC_OOB_AUTHENTICATION_IS_USED:
                    expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_authentication_action_static_oob_action, tvb, offset, 1, ENC_NA);
                    authentication_action = tvb_get_guint8(tvb, offset);
                    if (authentication_action != 0) {
                        expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_authentication_action);
                        proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
                    }
                    offset += 1;

                    expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_authentication_size_static_oob_action, tvb, offset, 1, ENC_NA);
                    authentication_size = tvb_get_guint8(tvb, offset);
                    if (authentication_size != 0) {
                        expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_authentication_size);
                        proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
                    }
                    offset += 1;

                break;
                case OUTPUT_OOB_AUTHENTICATION_IS_USED:
                    expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_authentication_action_output_oob_action, tvb, offset, 1, ENC_NA);
                    authentication_action = tvb_get_guint8(tvb, offset);
                    if (authentication_action >= 5) {
                        expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_authentication_action);
                        proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
                    }
                    offset += 1;

                    expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_authentication_size_output_oob_action, tvb, offset, 1, ENC_NA);
                    authentication_size = tvb_get_guint8(tvb, offset);
                    if (authentication_size >= 9) {
                        expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_authentication_size);
                        proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
                    } else {
                        if (authentication_size == 0) {
                            expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_authentication_size);
                            proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_prohibited, tvb, offset, -1);
                        }
                    }
                    offset += 1;

                break;
                case INPUT_OOB_AUTHENTICATION_IS_USED:
                    expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_authentication_action_input_oob_action, tvb, offset, 1, ENC_NA);
                    authentication_action = tvb_get_guint8(tvb, offset);
                    if (authentication_action >= 4) {
                        expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_authentication_action);
                        proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
                    }
                    offset += 1;

                    expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_authentication_size_input_oob_action, tvb, offset, 1, ENC_NA);
                    authentication_size = tvb_get_guint8(tvb, offset);
                    if (authentication_size >= 9) {
                        expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_authentication_size);
                        proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
                    } else {
                        if (authentication_size == 0) {
                            expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_authentication_size);
                            proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_prohibited, tvb, offset, -1);
                        }
                    }
                    offset += 1;

                break;
                default:
                    //RFU authentication method, display parameters and flag it
                    expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_authentication_method);
                    proto_tree_add_item(expert_tree, hf_btmesh_provisioning_unknown_data, tvb, offset, -1, ENC_NA);
                    proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_unknown_authentication_method, tvb, offset, -1);
                    offset += tvb_captured_length_remaining(tvb, offset);

                break;
            }

        break;
        case PROVISIONING_PUBLIC_KEY_PDU:
            proto_tree_add_item(sub_tree, hf_btmesh_provisioning_public_key_x, tvb, offset, 32, ENC_NA);
            offset += 32;
            proto_tree_add_item(sub_tree, hf_btmesh_provisioning_public_key_y, tvb, offset, 32, ENC_NA);
            offset += 32;

        break;
        case PROVISIONING_INPUT_COMPLETE_PDU:

        break;
        case PROVISIONING_CONFIRMATION_PDU:
            proto_tree_add_item(sub_tree, hf_btmesh_provisioning_confirmation, tvb, offset, 16, ENC_NA);
            offset += 16;

        break;
        case PROVISIONING_RANDOM_PDU:
            proto_tree_add_item(sub_tree, hf_btmesh_provisioning_random, tvb, offset, 16, ENC_NA);
            offset += 16;

        break;
        case PROVISIONING_DATA_PDU:
            proto_tree_add_item(sub_tree, hf_btmesh_provisioning_encrypted_provisioning_data, tvb, offset, 25, ENC_NA);
            offset += 25;
            proto_tree_add_item(sub_tree, hf_btmesh_provisioning_decrypted_provisioning_data_mic, tvb, offset, 8, ENC_NA);
            offset += 8;

        break;
        case PROVISIONING_COMPLETE_PDU:
             //No parameters for this PDU
        break;
        case PROVISIONING_FAILED_PDU:
            expert_item = proto_tree_add_item(sub_tree, hf_btmesh_provisioning_error_code, tvb, offset, 1, ENC_NA);
            error_code = tvb_get_guint8(tvb, offset);
            if (error_code >= 9) {
                expert_tree = proto_item_add_subtree(expert_item, ett_btmesh_provisioning_error_code);
                proto_tree_add_expert(expert_tree, pinfo, &ei_btmesh_provisioning_in_rfu_range, tvb, offset, -1);
            }
            offset += 1;

        break;
        default:
            //Unknown PDU Type, display data and flag it
            proto_tree_add_item(sub_tree, hf_btmesh_provisioning_unknown_data, tvb, offset, -1, ENC_NA);
            proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_provisioning_unknown_opcode, tvb, offset, -1);
            offset += tvb_captured_length_remaining(tvb, offset);

        break;
    }
    //There is still some data but all data should be already disssected
    if (tvb_captured_length_remaining(tvb, offset) != 0) {
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_provisioning_unknown_payload, tvb, offset, -1);
    }

    return tvb_reported_length(tvb);
}

void
proto_register_btmesh_provisioning(void)
{
    static hf_register_info hf[] = {
        { &hf_btmesh_provisioning_pdu_type,
            { "Provisioning PDU Type", "provisioning.pdu_type",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_pdu_type_format), 0x3F,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_pdu_padding,
            { "Provisioning PDU Padding", "provisioning.pdu_padding",
                FT_UINT8, BASE_DEC, NULL, 0xC0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_attention_duration,
            { "Attention Duration", "provisioning.attention_duration",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_number_of_elements,
            { "Number of Elements", "provisioning.number_of_elements",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_algorithms,
            { "Algorithms", "provisioning.algorithms",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_algorithms_p256,
            { "FIPS P-256 Elliptic Curve", "provisioning.algorithms.p256",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0001,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_algorithms_rfu,
            { "RFU", "provisioning.algorithms.rfu",
                FT_UINT16, BASE_DEC, NULL, 0xFFFE,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_public_key_type,
            { "Public Key Type", "provisioning.public_key_type",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_public_key_type_oob,
            { "Public Key Type OOB", "provisioning.public_key_type.oob",
                FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x01,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_public_key_type_rfu,
            { "RFU", "provisioning.public_key_type.rfu",
                FT_UINT8, BASE_DEC, NULL, 0xFE,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_static_oob_type,
            { "Static OOB Type", "provisioning.static_oob_type",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_static_oob_type_static_oob_available,
            { "Static OOB Information", "provisioning.static_oob_type.static_oob_available",
                FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x01,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_static_oob_type_rfu,
            { "RFU", "provisioning.static_oob_type.rfu",
                FT_UINT8, BASE_DEC, NULL, 0xFE,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_output_oob_size,
            { "Output OOB Size", "provisioning.output_oob_size",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_output_oob_size_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_output_oob_action,
            { "Output OOB Action", "provisioning.output_oob_action",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_output_oob_action_blink,
            { "Blink", "provisioning.output_oob_action.blink",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0001,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_output_oob_action_beep,
            { "Beep", "provisioning.output_oob_action.beep",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0002,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_output_oob_action_vibrate,
            { "Vibrate", "provisioning.output_oob_action.vibrate",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0004,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_output_oob_action_output_numeric,
            { "Output Numeric", "provisioning.output_oob_action.output_numeric",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0008,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_output_oob_action_output_alphanumeric,
            { "Output Alphanumeric", "provisioning.output_oob_action.output_alphanumeric",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0010,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_output_oob_action_output_rfu,
            { "RFU", "provisioning.output_oob_action.rfu",
                FT_UINT16, BASE_DEC, NULL, 0xFFE0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_input_oob_size,
            { "Input OOB Size", "provisioning.input_oob_size",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_input_oob_size_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_input_oob_action,
            { "Input OOB Action", "provisioning.input_oob_action",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_input_oob_action_push,
            { "Push", "provisioning.input_oob_action.push",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0001,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_input_oob_action_twist,
            { "Twist", "provisioning.input_oob_action.twist",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0002,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_input_oob_action_input_numeric,
            { "Input Numeric", "provisioning.input_oob_action.input_numeric",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0004,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_input_oob_action_input_alphanumeric,
            { "Input Alphanumeric", "provisioning.input_oob_action.input_alphanumeric",
                FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0008,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_input_oob_action_rfu,
            { "RFU", "provisioning.input_oob_action.rfc",
                FT_UINT16, BASE_DEC, NULL, 0xFFF0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_algorithm,
            { "Algorithm", "provisioning.algorithm",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_algorithm_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_public_key,
            { "Public Key", "provisioning.public_key",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_public_key_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_authentication_method,
            { "Authentication Method", "provisioning.authentication_method",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_authentication_method_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_authentication_action_no_oob_action,
            { "No OOB Authentication Action", "provisioning.authentication_action.no_oob_action",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_authentication_action_no_oob_action_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_authentication_action_static_oob_action,
            { "Static OOB Authentication Action", "provisioning.authentication_action.static_oob_action",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_authentication_action_static_oob_action_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_authentication_action_output_oob_action,
            { "Output OOB Authentication Action", "provisioning.authentication_action.output_oob_action",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_authentication_action_output_oob_action_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_authentication_action_input_oob_action,
            { "Input OOB Authentication Action", "provisioning.authentication_action.input_oob_action",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_authentication_action_input_oob_action_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_authentication_size_no_oob_action,
            { "No OOB Authentication Size", "provisioning.authentication_size.no_oob_action",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_authentication_size_no_oob_action_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_authentication_size_static_oob_action,
            { "Static OOB Authentication Size", "provisioning.authentication_size.static_oob_action",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_authentication_size_static_oob_action_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_authentication_size_output_oob_action,
            { "Output OOB Authentication Size", "provisioning.authentication_size.output_oob_action",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_authentication_size_output_oob_action_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_authentication_size_input_oob_action,
            { "Input OOB Authentication Size", "provisioning.authentication_size.input_oob_action",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_authentication_size_input_oob_action_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_public_key_x,
            { "Public Key X", "provisioning.public_key_x",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_public_key_y,
            { "Public Key Y", "provisioning.public_key_y",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_confirmation,
            { "Confirmation", "provisioning.confirmation",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_random,
            { "Random", "provisioning.random",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_encrypted_provisioning_data,
            { "Encrypted Provisioning Data", "provisioning.encrypted_provisioning_data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_decrypted_provisioning_data_mic,
            { "Decrypted Provisioning Data MIC", "provisioning.decrypted_provisioning_data_mic",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_error_code,
            { "Error Code", "provisioning.error_code",
                FT_UINT8, BASE_DEC, VALS(btmesh_provisioning_error_code_format), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_provisioning_unknown_data,
            { "Unknown Data", "provisioning.unknown_data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_btmesh_provisioning,
        &ett_btmesh_provisioning_algorithms,
        &ett_btmesh_provisioning_public_key_type,
        &ett_btmesh_provisioning_static_oob_type,
        &ett_btmesh_provisioning_output_oob_action,
        &ett_btmesh_provisioning_output_oob_size,
        &ett_btmesh_provisioning_input_oob_action,
        &ett_btmesh_provisioning_input_oob_size,
        &ett_btmesh_provisioning_algorithm,
        &ett_btmesh_provisioning_public_key,
        &ett_btmesh_provisioning_authentication_method,
        &ett_btmesh_provisioning_authentication_action,
        &ett_btmesh_provisioning_authentication_size,
        &ett_btmesh_provisioning_error_code,
    };

    static ei_register_info ei[] = {
        { &ei_btmesh_provisioning_unknown_opcode,{ "provisioning.unknown_opcode", PI_PROTOCOL, PI_ERROR, "Unknown Opcode", EXPFILL } },
        { &ei_btmesh_provisioning_unknown_payload,{ "provisioning.unknown_payload", PI_PROTOCOL, PI_ERROR, "Unknown Payload", EXPFILL } },
        { &ei_btmesh_provisioning_unknown_authentication_method,{ "provisioning.unknown_authentication_method", PI_PROTOCOL, PI_ERROR, "Unknown Authentication Method", EXPFILL } },
        { &ei_btmesh_provisioning_rfu_not_zero,{ "provisioning.rfu_not_zero", PI_PROTOCOL, PI_WARN, "RFU value not equal to 0", EXPFILL } },
        { &ei_btmesh_provisioning_in_rfu_range,{ "provisioning.in_rfu_range", PI_PROTOCOL, PI_WARN, "Value in RFU range", EXPFILL } },
        { &ei_btmesh_provisioning_prohibited,{ "provisioning.prohibited", PI_PROTOCOL, PI_ERROR, "Prohibited value", EXPFILL } },
        { &ei_btmesh_provisioning_zero_elements,{ "provisioning.zero_elements", PI_PROTOCOL, PI_ERROR, "Number of Elements equal to 0 is Prohibited", EXPFILL } },
    };

    expert_module_t* expert_btmesh_provisioning;

    proto_btmesh_provisioning = proto_register_protocol("Bluetooth Mesh Provisioning PDU", "BT Mesh Provisioning", "provisioning");

    proto_register_field_array(proto_btmesh_provisioning, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_btmesh_provisioning = expert_register_protocol(proto_btmesh_provisioning);
    expert_register_field_array(expert_btmesh_provisioning, ei, array_length(ei));

    prefs_register_protocol_subtree("Bluetooth", proto_btmesh_provisioning, NULL);
    register_dissector("btmesh.provisioning", dissect_btmesh_provisioning_msg, proto_btmesh_provisioning);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
