/* packet-btatt.c
 * Routines for Bluetooth Attribute Protocol dissection
 *
 * Copyright 2012, Allan M. Madsen <allan.m@madsen.dk>
 * Copyright 2015, Michal Labedzki for Tieto Corporation
 *  - dissect GATT level attributes
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
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

#include "packet-bluetooth.h"
#include "packet-btl2cap.h"

/* Initialize the protocol and registered fields */
static int proto_btatt = -1;

static int hf_btatt_opcode = -1;
static int hf_btatt_handle = -1;
static int hf_btatt_starting_handle = -1;
static int hf_btatt_ending_handle = -1;
static int hf_btatt_group_end_handle = -1;
static int hf_btatt_value = -1;
static int hf_btatt_req_opcode_in_error = -1;
static int hf_btatt_handle_in_error = -1;
static int hf_btatt_error_code = -1;
static int hf_btatt_uuid16 = -1;
static int hf_btatt_uuid128 = -1;
static int hf_btatt_client_rx_mtu = -1;
static int hf_btatt_server_rx_mtu = -1;
static int hf_btatt_uuid_format = -1;
static int hf_btatt_length = -1;
static int hf_btatt_offset = -1;
static int hf_btatt_flags = -1;
static int hf_btatt_sign_counter = -1;
static int hf_btatt_signature = -1;
static int hf_btatt_attribute_data = -1;
static int hf_btatt_handles_info = -1;
static int hf_btatt_opcode_authentication_signature = -1;
static int hf_btatt_opcode_command = -1;
static int hf_btatt_opcode_method = -1;
static int hf_btatt_characteristic_properties = -1;
static int hf_btatt_characteristic_value_handle = -1;
static int hf_btatt_characteristic_properties_extended_properties = -1;
static int hf_btatt_characteristic_properties_authenticated_signed_writes = -1;
static int hf_btatt_characteristic_properties_indicate = -1;
static int hf_btatt_characteristic_properties_notify = -1;
static int hf_btatt_characteristic_properties_write = -1;
static int hf_btatt_characteristic_properties_write_without_response = -1;
static int hf_btatt_characteristic_properties_read = -1;
static int hf_btatt_characteristic_properties_broadcast = -1;
static int hf_btatt_information_data = -1;
static int hf_request_in_frame = -1;
static int hf_response_in_frame = -1;

static const int *hfx_btatt_opcode[] = {
    &hf_btatt_opcode_authentication_signature,
    &hf_btatt_opcode_command,
    &hf_btatt_opcode_method,
    NULL
};

static const int *hfx_btatt_characteristic_properties[] = {
    &hf_btatt_characteristic_properties_extended_properties,
    &hf_btatt_characteristic_properties_authenticated_signed_writes,
    &hf_btatt_characteristic_properties_indicate,
    &hf_btatt_characteristic_properties_notify,
    &hf_btatt_characteristic_properties_write,
    &hf_btatt_characteristic_properties_write_without_response,
    &hf_btatt_characteristic_properties_read,
    &hf_btatt_characteristic_properties_broadcast,
    NULL
};


/* Initialize the subtree pointers */
static gint ett_btatt = -1;
static gint ett_btatt_list = -1;
static gint ett_btatt_opcode = -1;
static gint ett_btatt_handle = -1;
static gint ett_btatt_characteristic_properties = -1;

static expert_field ei_btatt_uuid_format_unknown = EI_INIT;
static expert_field ei_btatt_handle_too_few = EI_INIT;

static wmem_tree_t *requests = NULL;
static wmem_tree_t *handle_to_uuid = NULL;

static dissector_handle_t btatt_handle;

/* Opcodes */
static const value_string opcode_vals[] = {
    {0x01, "Error Response"},
    {0x02, "Exchange MTU Request"},
    {0x03, "Exchange MTU Response"},
    {0x04, "Find Information Request"},
    {0x05, "Find Information Response"},
    {0x06, "Find By Type Value Request"},
    {0x07, "Find By Type Value Response"},
    {0x08, "Read By Type Request"},
    {0x09, "Read By Type Response"},
    {0x0a, "Read Request"},
    {0x0b, "Read Response"},
    {0x0c, "Read Blob Request"},
    {0x0d, "Read Blob Response"},
    {0x0e, "Read Multiple Request"},
    {0x0f, "Read Multiple Response"},
    {0x10, "Read By Group Type Request"},
    {0x11, "Read By Group Type Response"},
    {0x12, "Write Request"},
    {0x13, "Write Response"},
    {0x16, "Prepare Write Request"},
    {0x17, "Prepare Write Response"},
    {0x18, "Execute Write Request"},
    {0x19, "Execute Write Response"},
    {0x1B, "Handle Value Notification"},
    {0x1D, "Handle Value Indication"},
    {0x1E, "Handle Value Confirmation"},
    {0x52, "Write Command"},
    {0xD2, "Signed Write Command"},
    {0x0, NULL}
};

/* Error codes */
static const value_string error_vals[] = {
    {0x01, "Invalid Handle"},
    {0x02, "Read Not Permitted"},
    {0x03, "Write Not Permitted"},
    {0x04, "Invalid PDU"},
    {0x05, "Insufficient Authentication"},
    {0x06, "Request Not Supported"},
    {0x07, "Invalid Offset"},
    {0x08, "Insufficient Authorization"},
    {0x09, "Prepare Queue Full"},
    {0x0a, "Attribute Not Found"},
    {0x0b, "Attribute Not Long"},
    {0x0c, "Insufficient Encryption Key Size"},
    {0x0d, "Invalid Attribute Value Length"},
    {0x0e, "Unlikely Error"},
    {0x0f, "Insufficient Encryption"},
    {0x10, "Unsupported Group Type"},
    {0x11, "Insufficient Resources"},
    {0x80, "Application Error"},
    {0xfd, "Improper Client Characteristic Configuration Descriptor"},
    {0xfe, "Procedure Already In Progress"},
    {0xff, "Out of Range"},
    {0x0, NULL}
};

static const value_string uuid_format_vals[] = {
    {0x01, "16-bit UUIDs"},
    {0x02, "128-bit UUIDs"},
    {0x0, NULL}
};

static const value_string flags_vals[] = {
    {0x00, "Cancel All"},
    {0x01, "Immediately Write All"},
    {0x0, NULL}
};

union request_parameters_union {
    void *data;

    struct _mtu {
        guint16 mtu;
    } mtu;

    struct _read_by_type {
        guint16 starting_handle;
        guint16 ending_handle;
        uuid_t  uuid;
    } read_by_type;

    struct _find_information {
        guint16 starting_handle;
        guint16 ending_handle;
    } find_information;
};

typedef struct _request_data_t {
    guint8                          opcode;
    guint32                         request_in_frame;
    guint32                         response_in_frame;

    union request_parameters_union  parameters;
} request_data_t;

typedef struct _handle_data_t {
    uuid_t  uuid;
} handle_data_t;


void proto_register_btatt(void);
void proto_reg_handoff_btatt(void);

static request_data_t *
get_request(tvbuff_t *tvb, gint offset, packet_info *pinfo, guint8 opcode,
        bluetooth_data_t *bluetooth_data)
{
    request_data_t  *request_data;
    wmem_tree_key_t  key[4];
    wmem_tree_t     *sub_wmemtree;
    gint             frame_number;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 0;
    key[2].key    = NULL;

    frame_number = pinfo->fd->num;

    sub_wmemtree = (wmem_tree_t *) wmem_tree_lookup32_array(requests, key);
    request_data = (sub_wmemtree) ? (request_data_t *) wmem_tree_lookup32_le(sub_wmemtree, frame_number) : NULL;

    if (!request_data)
        return NULL;

    if (request_data->request_in_frame == pinfo->fd->num)
        return request_data;

    switch (opcode) {
    case 0x01: /* Error Response */
        if (tvb_captured_length_remaining(tvb, offset) < 1)
            return NULL;
        opcode = tvb_get_guint8(tvb, 1) + 1;
    case 0x03: /* Exchange MTU Response */
    case 0x05: /* Find Information Response */
    case 0x07: /* Find By Type Value Response */
    case 0x09: /* Read By Type Response */
    case 0x0b: /* Read Response */
    case 0x0d: /* Read Blob Response */
    case 0x0f: /* Read Multiple Response */
    case 0x11: /* Read By Group Type Response */
    case 0x13: /* Write Response */
    case 0x17: /* Prepare Write Response */
    case 0x19: /* Execute Write Response */
    case 0x1E: /* Handle Value Confirmation */
        if (request_data->opcode == opcode -1)
            return request_data;

        break;
    case 0x1B: /* Handle Value Notification */
    case 0x52: /* Write Command */
    case 0xD2: /* Signed Write Command */
        /* There is no response for them */
        return NULL;
    case 0x02: /* Exchange MTU Request */
    case 0x04: /* Find Information Request */
    case 0x06: /* Find By Type Value Request */
    case 0x08: /* Read By Type Request */
    case 0x0a: /* Read Request */
    case 0x0c: /* Read Blob Request */
    case 0x0e: /* Read Multiple Request */
    case 0x10: /* Read By Group Type Request */
    case 0x12: /* Write Request */
    case 0x16: /* Prepare Write Request */
    case 0x18: /* Execute Write Request */
    case 0x1D: /* Handle Value Indication */
    default:
        return NULL;
    }

    return NULL;
}

static void
save_request(packet_info *pinfo, guint8 opcode, union request_parameters_union parameters,
        bluetooth_data_t *bluetooth_data)
{
    wmem_tree_key_t  key[4];
    guint32          frame_number;
    request_data_t  *request_data;

    frame_number = pinfo->fd->num;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 1;
    key[2].key    = &frame_number;
    key[3].length = 0;
    key[3].key    = NULL;

    request_data = wmem_new(wmem_file_scope(), request_data_t);
    request_data->opcode = opcode;
    request_data->request_in_frame = frame_number;
    request_data->response_in_frame = 0;

    request_data->parameters = parameters;

    wmem_tree_insert32_array(requests, key, request_data);
}

static void
save_handle(packet_info *pinfo, uuid_t uuid, guint32 handle,
        bluetooth_data_t *bluetooth_data)
{
    wmem_tree_key_t  key[5];
    guint32          frame_number;
    handle_data_t   *handle_data;

    frame_number = pinfo->fd->num;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 1;
    key[2].key    = &handle;
    key[3].length = 1;
    key[3].key    = &frame_number;
    key[4].length = 0;
    key[4].key    = NULL;

    handle_data = wmem_new(wmem_file_scope(), handle_data_t);
    handle_data->uuid = uuid;

    wmem_tree_insert32_array(handle_to_uuid, key, handle_data);
}

static uuid_t
get_uuid_from_handle(packet_info *pinfo, guint32 handle,
        bluetooth_data_t *bluetooth_data)
{
    wmem_tree_key_t  key[4];
    guint32          frame_number;
    handle_data_t   *handle_data;
    wmem_tree_t     *sub_wmemtree;
    uuid_t           uuid;

    uuid.size = 0;
    uuid.bt_uuid = 0;

    frame_number = pinfo->fd->num;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 1;
    key[2].key    = &handle;
    key[3].length = 0;
    key[3].key    = NULL;

    sub_wmemtree = (wmem_tree_t *) wmem_tree_lookup32_array(handle_to_uuid, key);
    handle_data = (sub_wmemtree) ? (handle_data_t *) wmem_tree_lookup32_le(sub_wmemtree, frame_number) : NULL;

    if (handle_data)
        uuid = handle_data->uuid;

    return uuid;
}

static int
dissect_handle(proto_tree *tree, packet_info *pinfo, gint hf,
        tvbuff_t *tvb, gint offset, bluetooth_data_t *bluetooth_data)
{
    proto_item        *sub_item;
    proto_tree        *sub_tree;
    guint16            handle;
    uuid_t             uuid;

    sub_item = proto_tree_add_item(tree, hf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    handle = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    uuid = get_uuid_from_handle(pinfo, handle, bluetooth_data);
    if (uuid.size == 2 || uuid.size == 16) {
        proto_item_append_text(sub_item, " (%s)", print_uuid(&uuid));
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_handle);

        if (uuid.size == 2)
            sub_item = proto_tree_add_uint(sub_tree, hf_btatt_uuid16, tvb, 0, 0, uuid.bt_uuid);
        else
            sub_item = proto_tree_add_bytes(sub_tree, hf_btatt_uuid128, tvb, 0, 16, uuid.data);

        PROTO_ITEM_SET_GENERATED(sub_item);
    }

    return offset + 2;
}

static int
dissect_btatt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item        *main_item;
    proto_tree        *main_tree;
    proto_item        *sub_item;
    proto_tree        *sub_tree;
    int                offset = 0;
    guint8             opcode;
    guint8             request_opcode;
    bluetooth_data_t  *bluetooth_data;
    request_data_t    *request_data;

    bluetooth_data = (bluetooth_data_t *) data;

    if (tvb_length_remaining(tvb, 0) < 1)
        return 0;

    main_item = proto_tree_add_item(tree, proto_btatt, tvb, 0, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btatt);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATT");

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            break;
    }

    proto_tree_add_bitmask_with_flags(main_tree, tvb, offset, hf_btatt_opcode, ett_btatt_opcode,  hfx_btatt_opcode, ENC_NA, BMT_NO_APPEND);
    opcode = tvb_get_guint8(tvb, 0);
    offset++;

    request_data = get_request(tvb, offset, pinfo, opcode, bluetooth_data);

    col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(opcode, opcode_vals, "<unknown>"));

    switch (opcode) {
    case 0x01: /* Error Response */
        proto_tree_add_bitmask_with_flags(main_tree, tvb, offset, hf_btatt_req_opcode_in_error, ett_btatt_opcode,  hfx_btatt_opcode, ENC_NA, BMT_NO_APPEND);
        request_opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle_in_error, tvb, offset, bluetooth_data);

        col_append_fstr(pinfo->cinfo, COL_INFO, " - %s, Handle: 0x%04x",
                        val_to_str_const(tvb_get_guint8(tvb, offset), error_vals, "<unknown>"),
                        tvb_get_letohs(tvb, offset - 2));

        proto_tree_add_item(main_tree, hf_btatt_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        if (request_data && (request_opcode == 0x08 || request_opcode == 0x10)) {
            sub_item = proto_tree_add_uint(main_tree, hf_btatt_uuid16, tvb, 0, 0, request_data->parameters.read_by_type.uuid.bt_uuid);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }

        break;

    case 0x02: /* Exchange MTU Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Client Rx MTU: %u", tvb_get_letohs(tvb, offset));
        proto_tree_add_item(main_tree, hf_btatt_client_rx_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.mtu.mtu = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }

        break;

    case 0x03: /* Exchange MTU Response */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Server Rx MTU: %u", tvb_get_letohs(tvb, offset));
        proto_tree_add_item(main_tree, hf_btatt_server_rx_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x04: /* Find Information Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handles: 0x%04x..0x%04x",
                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));
        proto_tree_add_item(main_tree, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(main_tree, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.find_information.starting_handle = tvb_get_guint16(tvb, offset - 4, ENC_LITTLE_ENDIAN);
            request_parameters.find_information.ending_handle   = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }

        break;

    case 0x05: /* Find Information Response */
        {
            guint8  format = tvb_get_guint8(tvb, offset);
            uuid_t  uuid;
            guint16 handle;

            sub_item = proto_tree_add_item(main_tree, hf_btatt_uuid_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            if (format == 1) {
                while( tvb_length_remaining(tvb, offset) > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_btatt_information_data, tvb, offset, 4, ENC_NA),
                    sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

                    handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

                    proto_tree_add_item(sub_tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    uuid = get_uuid(tvb, offset, 2);
                    offset += 2;

                    proto_item_append_text(sub_item, ", Handle: 0x%04x, UUID: %s",
                            tvb_get_letohs(tvb, offset - 4),
                            print_uuid(&uuid));

                    if (!pinfo->fd->flags.visited && bluetooth_data)
                        save_handle(pinfo, uuid, handle, bluetooth_data);
                }
            }
            else if (format == 2) {
                while( tvb_length_remaining(tvb, offset) > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_btatt_information_data, tvb, offset, 4, ENC_NA),
                    sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

                    offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle,tvb, offset, bluetooth_data);
                    handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

                    proto_tree_add_item(sub_tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
                    uuid = get_uuid(tvb, offset, 16);
                    offset += 16;

                    proto_item_append_text(sub_item, ", Handle: 0x%04x, UUID: %s",
                            tvb_get_letohs(tvb, offset - 4),
                            print_uuid(&uuid));

                    if (!pinfo->fd->flags.visited && bluetooth_data)
                        save_handle(pinfo, uuid, handle, bluetooth_data);
                }
            }
            else {
                expert_add_info(pinfo, sub_item, &ei_btatt_uuid_format_unknown);
            }
        }
        break;

    case 0x06: /* Find By Type Value Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, Handles: 0x%04x..0x%04x",
                            val_to_str_ext_const(tvb_get_letohs(tvb, offset+4), &bluetooth_uuid_vals_ext, "<unknown>"),
                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

        proto_tree_add_item(main_tree, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(main_tree, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(main_tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length(tvb);

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.data = NULL;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }

        break;

    case 0x07: /* Find By Type Value Response */
        while( tvb_length_remaining(tvb, offset) > 0 ) {
            sub_item = proto_tree_add_none_format(main_tree, hf_btatt_handles_info, tvb, offset, 4,
                                            "Handles Info, Handle: 0x%04x, Group End Handle: 0x%04x",
                                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

            offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data);

            proto_tree_add_item(sub_tree, hf_btatt_group_end_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (!pinfo->fd->flags.visited && bluetooth_data && request_data)
                save_handle(pinfo, request_data->parameters.read_by_type.uuid,
                        tvb_get_guint16(tvb, offset - 4, ENC_LITTLE_ENDIAN),
                        bluetooth_data);

        }
        break;

    case 0x08: /* Read By Type Request */
    case 0x10: /* Read By Group Type Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, Handles: 0x%04x..0x%04x",
                            val_to_str_ext_const(tvb_get_letohs(tvb, offset+4), &bluetooth_uuid_vals_ext, "<unknown>"),
                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

        proto_tree_add_item(main_tree, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(main_tree, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (tvb_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(main_tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (!pinfo->fd->flags.visited && bluetooth_data) {
                union request_parameters_union  request_parameters;

                request_parameters.read_by_type.starting_handle = tvb_get_guint16(tvb, offset - 6, ENC_LITTLE_ENDIAN);
                request_parameters.read_by_type.ending_handle   = tvb_get_guint16(tvb, offset - 4, ENC_LITTLE_ENDIAN);
                request_parameters.read_by_type.uuid = get_uuid(tvb, offset - 2, 2);

                save_request(pinfo, opcode, request_parameters, bluetooth_data);
            }
        }
        else if (tvb_length_remaining(tvb, offset) == 16) {
            sub_item = proto_tree_add_item(main_tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
            proto_item_append_text(sub_item, " (%s)", val_to_str_ext_const(tvb_get_letohs(tvb, offset),
                                            &bluetooth_uuid_vals_ext, "<unknown>"));
            offset += 16;

            if (!pinfo->fd->flags.visited && bluetooth_data) {
                union request_parameters_union  request_parameters;

                request_parameters.read_by_type.starting_handle = tvb_get_guint16(tvb, offset - 20, ENC_LITTLE_ENDIAN);
                request_parameters.read_by_type.ending_handle   = tvb_get_guint16(tvb, offset - 18, ENC_LITTLE_ENDIAN);
                request_parameters.read_by_type.uuid = get_uuid(tvb, offset - 16, 16);

                save_request(pinfo, opcode, request_parameters, bluetooth_data);
            }
        }


        break;

    case 0x09: /* Read By Type Response */
        {
            guint8  length = tvb_get_guint8(tvb, offset);
            uuid_t  uuid;
            guint16 handle;

            proto_tree_add_item(main_tree, hf_btatt_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            if(length > 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Attribute List Length: %u",
                                        tvb_length_remaining(tvb, offset)/length);

                while (tvb_length_remaining(tvb, offset) >= length)
                {
                    sub_item = proto_tree_add_none_format(main_tree, hf_btatt_attribute_data, tvb,
                                                    offset, length, "Attribute Data, Handle: 0x%04x",
                                                    tvb_get_letohs(tvb, offset));

                    sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

                    offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data);

                    if (request_data && length - 2 == 5 &&
                            request_data->parameters.read_by_type.uuid.bt_uuid == UUID_GATT_CHARACTERISTIC_DECLARATION) {
                        proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_characteristic_properties, ett_btatt_characteristic_properties,  hfx_btatt_characteristic_properties, ENC_NA);
                        offset += 1;

                        offset = dissect_handle(sub_tree, pinfo, hf_btatt_characteristic_value_handle, tvb, offset, bluetooth_data);
                        handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

                        proto_tree_add_item(sub_tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        uuid = get_uuid(tvb, offset, 2);
                        proto_item_append_text(sub_item, ", Characteristic Handle: 0x%04x, UUID: %s", handle, print_uuid(&uuid));
                        offset += 2;

                        if (!pinfo->fd->flags.visited && bluetooth_data)
                            save_handle(pinfo, uuid, handle, bluetooth_data);

                    } else if (request_data && length - 2 == 19 &&
                            request_data->parameters.read_by_type.uuid.bt_uuid == UUID_GATT_CHARACTERISTIC_DECLARATION) {

                        proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_characteristic_properties, ett_btatt_characteristic_properties,  hfx_btatt_characteristic_properties, ENC_NA);
                        offset += 1;

                        offset = dissect_handle(sub_tree, pinfo, hf_btatt_characteristic_value_handle, tvb, offset, bluetooth_data);
                        handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

                        proto_tree_add_item(sub_tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
                        uuid = get_uuid(tvb, offset, 16);
                        proto_item_append_text(sub_item, ", Characteristic Handle: 0x%04x, UUID128: %s", tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN), print_uuid(&uuid));
                        offset += 16;

                        if (!pinfo->fd->flags.visited && bluetooth_data)
                            save_handle(pinfo, uuid, handle, bluetooth_data);
                    } else {
                        proto_tree_add_item(sub_tree, hf_btatt_value, tvb, offset, length - 2, ENC_NA);
                        offset += (length-2);
                    }
                }
            }

            if (request_data) {
                sub_item = proto_tree_add_uint(main_tree, hf_btatt_uuid16, tvb, 0, 0, request_data->parameters.read_by_type.uuid.bt_uuid);
                PROTO_ITEM_SET_GENERATED(sub_item);
            }
        }
        break;

    case 0x0a: /* Read Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x", tvb_get_letohs(tvb, offset));

        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data);

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.data = NULL;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x0b: /* Read Response */
    case 0x0d: /* Read Blob Response */
    case 0x0f: /* Multiple Read Response */
        proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length(tvb);
        break;

    case 0x0c: /* Read Blob Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x, Offset: %u",
                        tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data);

        proto_tree_add_item(main_tree, hf_btatt_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;


        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.data = NULL;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x0e: /* Multiple Read Request */
        if(tvb_length_remaining(tvb, offset) < 4) {
            expert_add_info(pinfo, main_item, &ei_btatt_handle_too_few);
            break;
        }

        col_append_str(pinfo->cinfo, COL_INFO, ", Handles: ");
        while (tvb_length_remaining(tvb, offset) >= 2) {
            offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data);
            col_append_fstr(pinfo->cinfo, COL_INFO, "0x%04x ", tvb_get_letohs(tvb, offset - 2));
        }

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.data = NULL;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x11: /* Read By Group Type Response */
        {
            guint8  length = tvb_get_guint8(tvb, offset);
            uuid_t  uuid;
            guint16 handle;

            proto_tree_add_item(main_tree, hf_btatt_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            if(length > 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Attribute List Length: %u", tvb_length_remaining(tvb, offset)/length);

                while (tvb_length_remaining(tvb, offset) >= length) {
                    sub_item = proto_tree_add_none_format(main_tree, hf_btatt_attribute_data, tvb, offset, length,
                                                    "Attribute Data, Handle: 0x%04x, Group End Handle: 0x%04x",
                                                    tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

                    sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

                    offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data);
                    handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

                    proto_tree_add_item(sub_tree, hf_btatt_group_end_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    if (request_data &&
                            (request_data->parameters.read_by_type.uuid.bt_uuid == UUID_GATT_PRIMARY_SERVICE_DECLARATION ||
                            request_data->parameters.read_by_type.uuid.bt_uuid == UUID_GATT_SECONDARY_SERVICE_DECLARATION) &&
                            (length - 4 == 2 || length - 4 == 16)) {
                        if (length - 4 == 2) {
                            proto_tree_add_item(sub_tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);

                            uuid = get_uuid(tvb, offset, 2);
                            proto_item_append_text(sub_item, ", UUID: %s", print_uuid(&uuid));

                            if (!pinfo->fd->flags.visited && bluetooth_data)
                                save_handle(pinfo, uuid, handle, bluetooth_data);
                        } else if (length - 4 == 16) {

                            proto_tree_add_item(sub_tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);

                            uuid = get_uuid(tvb, offset, 16);
                            proto_item_append_text(sub_item, ", UUID128: %s", print_uuid(&uuid));

                            if (!pinfo->fd->flags.visited && bluetooth_data)
                                save_handle(pinfo, uuid, handle, bluetooth_data);
                        }
                    } else {
                        proto_tree_add_item(sub_tree, hf_btatt_value, tvb, offset, length - 4, ENC_NA);
                    }
                    offset += (length-4);
                }
            }

            if (request_data) {
                sub_item = proto_tree_add_uint(main_tree, hf_btatt_uuid16, tvb, 0, 0, request_data->parameters.read_by_type.uuid.bt_uuid);
                PROTO_ITEM_SET_GENERATED(sub_item);
            }
        }
        break;

    case 0x12: /* Write Request */
    case 0x1d: /* Handle Value Indication */
    case 0x52: /* Write Command */
    case 0x1b: /* Handle Value Notification */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x", tvb_get_letohs(tvb, offset));

        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data);

        proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length(tvb);

        if (!pinfo->fd->flags.visited && bluetooth_data && (opcode == 0x12 || opcode == 0x1d)) {
            union request_parameters_union  request_parameters;

            request_parameters.data = NULL;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x16: /* Prepare Write Request */
    case 0x17: /* Prepare Write Response */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x, Offset: %u",
                        tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data);

        proto_tree_add_item(main_tree, hf_btatt_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length(tvb);

        if (!pinfo->fd->flags.visited && bluetooth_data && opcode == 0x16) {
            union request_parameters_union  request_parameters;

            request_parameters.data = NULL;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x18: /* Execute Write Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                        val_to_str_const(tvb_get_guint8(tvb, offset), flags_vals, "<unknown>"));
        proto_tree_add_item(main_tree, hf_btatt_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.data = NULL;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0xd2: /* Signed Write Command */
        {
            guint8 length;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x", tvb_get_letohs(tvb, offset));

            offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data);

            length = tvb_length_remaining(tvb, offset);
            if (length > 12) {
                proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, length-12, ENC_NA);
                offset+=length-12;
            }

            proto_tree_add_item(main_tree, hf_btatt_sign_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(main_tree, hf_btatt_signature, tvb, offset, 8, ENC_NA);
            offset+=8;
        break;
        }
    default:
        break;
    }

    if (request_data) {
        if (request_data->request_in_frame > 0  && request_data->request_in_frame != pinfo->fd->num) {
            sub_item = proto_tree_add_uint(main_tree, hf_request_in_frame, tvb, 0, 0, request_data->request_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }

        if (!pinfo->fd->flags.visited && request_data->response_in_frame == 0 &&
                pinfo->fd->num > request_data->request_in_frame)
            request_data->response_in_frame = pinfo->fd->num;

        if (request_data->response_in_frame > 0 && request_data->response_in_frame != pinfo->fd->num) {
            sub_item = proto_tree_add_uint(main_tree, hf_response_in_frame, tvb, 0, 0, request_data->response_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }
    }

    return offset;
}

void
proto_register_btatt(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        {&hf_btatt_opcode,
            {"Opcode", "btatt.opcode",
            FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_opcode_authentication_signature,
            {"Authentication Signature", "btatt.opcode.authentication_signature",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL}
        },
        {&hf_btatt_opcode_command,
            {"Command", "btatt.opcode.command",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL}
        },
        {&hf_btatt_opcode_method,
            {"Method", "btatt.opcode.method",
            FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x3F,
            NULL, HFILL}
        },
        {&hf_btatt_handles_info,
            {"Handles Info", "btatt.handles_info",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_attribute_data,
            {"Attribute Data", "btatt.attribute_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_handle,
            {"Handle", "btatt.handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_starting_handle,
            {"Starting Handle", "btatt.starting_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ending_handle,
            {"Ending Handle", "btatt.ending_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_group_end_handle,
            {"Group End Handle", "btatt.group_end_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_value,
            {"Value", "btatt.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_req_opcode_in_error,
            {"Request Opcode in Error", "btatt.req_opcode_in_error",
            FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_handle_in_error,
            {"Handle in Error", "btatt.handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uuid16,
            {"UUID", "btatt.uuid16",
            FT_UINT16, BASE_HEX |BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uuid128,
            {"UUID", "btatt.uuid128",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_client_rx_mtu,
            {"Client Rx MTU", "btatt.client_rx_mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_server_rx_mtu,
            {"Server Rx MTU", "btatt.server_rx_mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uuid_format,
            {"UUID Format", "btatt.uuid_format",
            FT_UINT8, BASE_HEX, VALS(uuid_format_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_length,
            {"Length", "btatt.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of Handle/Value Pair", HFILL}
        },
        {&hf_btatt_offset,
            {"Offset", "btatt.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_flags,
            {"Flags", "btatt.flags",
            FT_UINT8, BASE_HEX, VALS(flags_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_sign_counter,
            {"Sign Counter", "btatt.sign_counter",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_signature,
            {"Signature", "btatt.signature",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties,
            {"Characteristic Properties", "btatt.characteristic_properties",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_extended_properties,
            {"Extended Properties", "btatt.characteristic_properties.extended_properties",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_authenticated_signed_writes,
            {"Authenticated Signed Writes", "btatt.characteristic_properties.authenticated_signed_writes",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_indicate,
            {"Indicate", "btatt.characteristic_properties.indicate",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_notify,
            {"Notify", "btatt.characteristic_properties.notify",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_write,
            {"Write", "btatt.characteristic_properties.write",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_write_without_response,
            {"Write without Response", "btatt.characteristic_properties.write_without_response",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_read,
            {"Read", "btatt.characteristic_properties.read",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_broadcast,
            {"Broadcast", "btatt.characteristic_properties.broadcast",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_value_handle,
            {"Characteristic Value Handle", "btatt.handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_information_data,
            {"Information Data", "btatt.information_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_request_in_frame,
            {"Request in Frame", "btatt.request_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_response_in_frame,
            {"Response in Frame", "btatt.response_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_btatt,
        &ett_btatt_list,
        &ett_btatt_opcode,
        &ett_btatt_handle,
        &ett_btatt_characteristic_properties
    };

    static ei_register_info ei[] = {
        { &ei_btatt_uuid_format_unknown, { "btatt.uuid_format.unknown", PI_PROTOCOL, PI_WARN, "Unknown format", EXPFILL }},
        { &ei_btatt_handle_too_few, { "btatt.handle.too_few", PI_PROTOCOL, PI_WARN, "Too few handles, should be 2 or more", EXPFILL }},
    };

    expert_module_t* expert_btatt;

    /* Register the protocol name and description */
    proto_btatt = proto_register_protocol("Bluetooth Attribute Protocol", "BT ATT", "btatt");

    btatt_handle = new_register_dissector("btatt", dissect_btatt, proto_btatt);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btatt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_btatt = expert_register_protocol(proto_btatt);
    expert_register_field_array(expert_btatt, ei, array_length(ei));

    requests = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    handle_to_uuid = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    module = prefs_register_protocol(proto_btatt, NULL);
    prefs_register_static_text_preference(module, "att.version",
            "Bluetooth Protocol ATT version from Core 4.0",
            "Version of protocol supported by this dissector.");
}

void
proto_reg_handoff_btatt(void)
{
    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_ATT, btatt_handle);
    dissector_add_uint("btl2cap.cid", BTL2CAP_FIXED_CID_ATT, btatt_handle);
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
