/* packet-usbdfu.c
 * Routines for USB DFU dissection
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
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
#include "packet-usb.h"

static int proto_usb_dfu = -1;

static gint hf_setup_command = -1;
static gint hf_setup_unused = -1;
static gint hf_setup_interface = -1;
static gint hf_setup_length = -1;
static gint hf_setup_timeout = -1;
static gint hf_setup_block_number = -1;
static gint hf_response = -1;
static gint hf_command_in_frame = -1;
static gint hf_state = -1;
static gint hf_status = -1;
static gint hf_poll_timeout = -1;
static gint hf_iString = -1;
static gint hf_data = -1;
static gint hf_usb_dfu_descriptor = -1;
static gint hf_usb_dfu_descriptor_bmAttributes_reserved = -1;
static gint hf_usb_dfu_descriptor_bmAttributes_WillDetach = -1;
static gint hf_usb_dfu_descriptor_bmAttributes_ManifestationTolerant = -1;
static gint hf_usb_dfu_descriptor_bmAttributes_CanUpload = -1;
static gint hf_usb_dfu_descriptor_bmAttributes_CanDownload = -1;
static gint hf_usb_dfu_descriptor_wDetachTimeOut = -1;
static gint hf_usb_dfu_descriptor_wTransferSize = -1;
static gint hf_usb_dfu_descriptor_bcdDFUVersion = -1;

static gint ett_usb_dfu = -1;
static gint ett_usb_dfu_descriptor = -1;
static gint ett_command = -1;

static expert_field ei_unexpected_response = EI_INIT;
static expert_field ei_unknown_data = EI_INIT;
static expert_field ei_unexpected_data = EI_INIT;
static expert_field ei_descriptor_invalid_length = EI_INIT;
static expert_field ei_invalid_command_for_request_type = EI_INIT;

static dissector_handle_t usb_dfu_handle;

static wmem_tree_t *command_info = NULL;

typedef struct _command_data {
    guint32  bus_id;
    guint32  device_address;

    guint16  interface;
    guint8   command;
    guint32  command_frame_number;
    gint32   block_number;
} command_data_t;


static const value_string command_vals[] = {
    { 0x00,  "Detach" },
    { 0x01,  "Download" },
    { 0x02,  "Upload" },
    { 0x03,  "Get Status" },
    { 0x04,  "Clear Status" },
    { 0x05,  "Get State" },
    { 0x06,  "Abort" },
    { 0x00, NULL }
};
static value_string_ext(command_vals_ext) = VALUE_STRING_EXT_INIT(command_vals);

static const value_string state_vals[] = {
    {  0,  "appIdle" },
    {  1,  "appDetach" },
    {  2,  "dfuIdle" },
    {  3,  "dfuDownloadSync" },
    {  4,  "dfuDownloadBusy" },
    {  5,  "dfuDownloadIdle" },
    {  6,  "dfuManifestSync" },
    {  7,  "dfuManifest" },
    {  8,  "dfuManifestWaitReset" },
    {  9,  "dfuUploadIdle" },
    { 10,  "dfuError" },
    { 0x00, NULL }
};
static value_string_ext(state_vals_ext) = VALUE_STRING_EXT_INIT(state_vals);

static const value_string status_vals[] = {
    { 0x00,  "OK" },
    { 0x01,  "errTarget" },
    { 0x02,  "errFile" },
    { 0x03,  "errWrite" },
    { 0x04,  "errErase" },
    { 0x05,  "errCheckErased" },
    { 0x06,  "errProg" },
    { 0x07,  "errVerify" },
    { 0x08,  "errAddress" },
    { 0x09,  "errNotDone" },
    { 0x0A,  "errFirmware" },
    { 0x0B,  "errVendor" },
    { 0x0C,  "errUsbReset" },
    { 0x0D,  "errPowerOnReset" },
    { 0x0E,  "errUnknown" },
    { 0x0F,  "errStalledPkt" },
    { 0x00, NULL }
};
static value_string_ext(status_vals_ext) = VALUE_STRING_EXT_INIT(status_vals);

static const value_string descriptor_type_vals[] = {
    { 0x21,  "DFU FUNCTIONAL" },
    { 0x00, NULL }
};
static value_string_ext(descriptor_type_vals_ext) = VALUE_STRING_EXT_INIT(descriptor_type_vals);

void proto_register_usb_dfu(void);
void proto_reg_handoff_usb_dfu(void);


static gint
dissect_usb_dfu_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item       *main_item;
    proto_tree       *main_tree;
    proto_item       *length_item;
    gint              offset = 0;
    guint8            descriptor_length;
    guint8            descriptor_type;
    usb_conv_info_t  *usb_conv_info = (usb_conv_info_t *) data;

    if (!usb_conv_info) return offset;

    if (!(usb_conv_info->interfaceClass == IF_CLASS_APPLICATION_SPECIFIC &&
            usb_conv_info->interfaceSubclass == 0x01)) return offset;

    descriptor_length = tvb_get_guint8(tvb, offset);
    descriptor_type = tvb_get_guint8(tvb, offset + 1);

    switch (descriptor_type) {
    case 0x21:
        main_item = proto_tree_add_item(tree, hf_usb_dfu_descriptor, tvb, offset, -1, ENC_NA);
        main_tree = proto_item_add_subtree(main_item, ett_usb_dfu_descriptor);

        proto_item_append_text(main_item, ": %s", val_to_str_ext_const(descriptor_type, &descriptor_type_vals_ext, "Unknown"));

        length_item = dissect_usb_descriptor_header(main_tree, tvb, offset, &descriptor_type_vals_ext);
        if (descriptor_length != 7 && descriptor_length != 9)
            expert_add_info(pinfo, length_item, &ei_descriptor_invalid_length);
        offset += 2;

        proto_tree_add_item(main_tree, hf_usb_dfu_descriptor_bmAttributes_reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(main_tree, hf_usb_dfu_descriptor_bmAttributes_WillDetach, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(main_tree, hf_usb_dfu_descriptor_bmAttributes_ManifestationTolerant, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(main_tree, hf_usb_dfu_descriptor_bmAttributes_CanUpload, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(main_tree, hf_usb_dfu_descriptor_bmAttributes_CanDownload, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(main_tree, hf_usb_dfu_descriptor_wDetachTimeOut, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(main_tree, hf_usb_dfu_descriptor_wTransferSize, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (descriptor_length > 7) {
            proto_tree_add_item(main_tree, hf_usb_dfu_descriptor_bcdDFUVersion, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    }

    return offset;
}

static gint
dissect_usb_dfu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item       *main_item;
    proto_tree       *main_tree;
    proto_item       *command_item;
    proto_item       *sub_item;
    proto_tree       *command_tree;
    gint              offset = 0;
    gint              p2p_dir_save;
    guint8            command;
    gint16            command_response = -1;
    command_data_t   *command_data = NULL;
    wmem_tree_t      *wmem_tree;
    wmem_tree_key_t   key[5];
    guint32           bus_id;
    guint32           device_address;
    guint32           k_bus_id;
    guint32           k_device_address;
    guint32           k_frame_number;
    gint32            block_number = -1;
    usb_conv_info_t  *usb_conv_info = (usb_conv_info_t *)data;

    if (!usb_conv_info) return offset;

    bus_id         = usb_conv_info->bus_id;
    device_address = usb_conv_info->device_address;

    k_bus_id          = bus_id;
    k_device_address  = device_address;
    k_frame_number    = pinfo->num;

    key[0].length = 1;
    key[0].key = &k_bus_id;
    key[1].length = 1;
    key[1].key = &k_device_address;

    main_item = proto_tree_add_item(tree, proto_usb_dfu, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_usb_dfu);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USB DFU");

    p2p_dir_save = pinfo->p2p_dir;
    pinfo->p2p_dir = (usb_conv_info->is_request) ? P2P_DIR_SENT : P2P_DIR_RECV;

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction ");
        break;
    }

    if (usb_conv_info->is_setup) {
        guint16  interface;

        command_item = proto_tree_add_item(main_tree, hf_setup_command, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        command = tvb_get_guint8(tvb, offset);

        if (!((usb_conv_info->setup_requesttype == 0x21 && (command == 0x00 || command == 0x01 || command == 0x04 || command == 0x06)) ||
            (usb_conv_info->setup_requesttype == 0xa1 && (command == 0x02 || command == 0x03 || command == 0x05))))
            expert_add_info(pinfo, command_item, &ei_invalid_command_for_request_type);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, "Command: %s",
                val_to_str_ext_const(command, &command_vals_ext, "Unknown"));

        if (command == 0x00) { /* Detach */
            proto_tree_add_item(main_tree, hf_setup_timeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Timeout=%u", tvb_get_letohs(tvb, offset));
        } else if (command == 0x01 || command == 0x02) { /* Download || Upload */
            proto_tree_add_item(main_tree, hf_setup_block_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Block Number=%u", tvb_get_letohs(tvb, offset));
            block_number = tvb_get_letohs(tvb, offset);
        } else {
            proto_tree_add_item(main_tree, hf_setup_unused, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        }
        offset += 2;

        proto_tree_add_item(main_tree, hf_setup_interface, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        interface = tvb_get_letohs(tvb, offset);
        offset += 2;

        proto_tree_add_item(main_tree, hf_setup_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (command == 0x01) { /* Download */
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
            offset = tvb_captured_length(tvb);
        }

        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_expert(main_tree, pinfo, &ei_unexpected_data, tvb, offset, tvb_captured_length_remaining(tvb, offset));
            offset = tvb_captured_length(tvb);
        }

        /* Save request info (command_data) */
        if (!pinfo->fd->flags.visited && command != 21) {
            key[2].length = 1;
            key[2].key = &k_frame_number;
            key[3].length = 0;
            key[3].key = NULL;

            command_data = wmem_new(wmem_file_scope(), command_data_t);
            command_data->bus_id = bus_id;
            command_data->device_address = device_address;

            command_data->command = command;
            command_data->interface = interface;
            command_data->command_frame_number = pinfo->num;
            command_data->block_number = block_number;

            wmem_tree_insert32_array(command_info, key, command_data);
        }

        pinfo->p2p_dir = p2p_dir_save;

        return offset;
    }

    /* Get request info (command_data) */
    key[2].length = 0;
    key[2].key = NULL;

    wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(command_info, key);
    if (wmem_tree) {
        command_data = (command_data_t *) wmem_tree_lookup32_le(wmem_tree, pinfo->num);
        if (command_data) {
            command_response = command_data->command;
            block_number = command_data->block_number;
        }
    }

    if (!command_data) {
        col_append_str(pinfo->cinfo, COL_INFO, "Response: Unknown");

        proto_tree_add_expert(main_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_captured_length_remaining(tvb, offset));

        pinfo->p2p_dir = p2p_dir_save;

        return tvb_captured_length(tvb);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "Response: %s",
            val_to_str_ext_const(command_response, &command_vals_ext, "Unknown"));

    command_item = proto_tree_add_uint(main_tree, hf_response, tvb, offset, 0, command_response);
    command_tree = proto_item_add_subtree(command_item, ett_command);
    PROTO_ITEM_SET_GENERATED(command_item);

    if (command_data) {
        command_item = proto_tree_add_uint(main_tree, hf_setup_interface, tvb, offset, 0, command_data->interface);
        PROTO_ITEM_SET_GENERATED(command_item);

        command_item = proto_tree_add_uint(main_tree, hf_command_in_frame, tvb, offset, 0, command_data->command_frame_number);
        PROTO_ITEM_SET_GENERATED(command_item);
    }

    switch (command_response) {
    case 0x02: /* Upload */
        if (block_number != -1) {
            sub_item = proto_tree_add_uint(main_tree, hf_setup_block_number, tvb, offset, 0, block_number);
            PROTO_ITEM_SET_GENERATED(sub_item);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Block Number=%u", block_number);
        }

        proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
        offset = tvb_captured_length(tvb);

        break;
    case 0x03: /* Get Status */
        col_append_fstr(pinfo->cinfo, COL_INFO, " = Status: %s, PollTimeout: %u ms, State: %s",
                val_to_str_ext_const(tvb_get_guint8(tvb, offset), &status_vals_ext, "Unknown"),
                tvb_get_letoh24(tvb, offset + 1),
                val_to_str_ext_const(tvb_get_guint8(tvb, offset + 4), &state_vals_ext, "Unknown"));

        proto_tree_add_item(main_tree, hf_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(main_tree, hf_poll_timeout, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;

        proto_tree_add_item(main_tree, hf_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(main_tree, hf_iString, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        break;
    case 0x05: /* Get State */
        proto_tree_add_item(main_tree, hf_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s",
                val_to_str_ext_const(tvb_get_guint8(tvb, offset), &state_vals_ext, "Unknown"));

        offset += 1;

        break;
    case 0x00: /* Detach */
    case 0x01: /* Download */
    case 0x04: /* Clear Status */
    case 0x06: /* Abort */
    default:
        proto_tree_add_expert(command_tree, pinfo, &ei_unexpected_response, tvb, offset, 0);
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_expert(main_tree, pinfo, &ei_unknown_data, tvb, offset, -1);
            offset = tvb_captured_length(tvb);
        }
    }

    pinfo->p2p_dir = p2p_dir_save;

    return offset;
}

void
proto_register_usb_dfu(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {

        { &hf_setup_command,
          { "Command", "usbdfu.command",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &command_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_response,
          { "Response", "usbdfu.response",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &command_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_command_in_frame,
          { "Command Frame", "usbdfu.command_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_unused,
            { "Unused", "usbdfu.unused",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_interface,
            { "Interface", "usbdfu.interface",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_length,
            { "Length", "usbdfu.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_block_number,
            { "Block Number", "usbdfu.block_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_setup_timeout,
            { "Timeout", "usbdfu.timeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_state,
            { "State", "usbdfu.state",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &state_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_status,
            { "Status", "usbdfu.status",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &status_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_iString,
            { "iString", "usbdfu.iString",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_poll_timeout,
            { "Poll Timeout", "usbdfu.poll_timeout",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_data,
            { "Data", "usbdfu.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usb_dfu_descriptor,
            { "DFU Descriptor", "usbdfu.descriptor",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usb_dfu_descriptor_bmAttributes_reserved,
            { "Reserved", "usbdfu.descriptor.bmAttributes.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_usb_dfu_descriptor_bmAttributes_WillDetach,
            { "Will Detach", "usbdfu.descriptor.bmAttributes.WillDetach",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_usb_dfu_descriptor_bmAttributes_ManifestationTolerant,
            { "Manifestation Tolerant", "usbdfu.descriptor.bmAttributes.ManifestationTolerant",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_usb_dfu_descriptor_bmAttributes_CanUpload,
            { "Can Upload", "usbdfu.descriptor.bmAttributes.CanUpload",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_usb_dfu_descriptor_bmAttributes_CanDownload,
            { "Can Download", "usbdfu.descriptor.bmAttributes.CanDownload",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_usb_dfu_descriptor_wDetachTimeOut,
            { "wDetachTimeOut", "usbdfu.descriptor.wDetachTimeOut",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usb_dfu_descriptor_wTransferSize,
            { "wTransferSize", "usbdfu.descriptor.wTransferSize",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usb_dfu_descriptor_bcdDFUVersion,
            { "bcdDFUVersion", "usbdfu.descriptor.bcdDFUVersion",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_unexpected_response,               { "usb_dfu.unexpected_response",              PI_PROTOCOL, PI_ERROR,  "Unexpected response for this command", EXPFILL }},
        { &ei_unknown_data,                      { "usb_dfu.unknown_data",                     PI_PROTOCOL, PI_NOTE,   "Unknown data", EXPFILL }},
        { &ei_unexpected_data,                   { "usb_dfu.unexpected_data",                  PI_PROTOCOL, PI_WARN,   "Unexpected data", EXPFILL }},
        { &ei_invalid_command_for_request_type,  { "usb_dfu.invalid_command_for_request_type", PI_PROTOCOL, PI_WARN, "Invalid command for this Request Type", EXPFILL }},
        { &ei_descriptor_invalid_length,         { "usb_dfu.descriptor.invalid_length",        PI_PROTOCOL, PI_WARN, "Invalid Length", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_usb_dfu,
        &ett_usb_dfu_descriptor,
        &ett_command
    };

    command_info = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_usb_dfu = proto_register_protocol("USB Device Firmware Upgrade ", "USB DFU", "usbdfu");
    proto_register_field_array(proto_usb_dfu, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    usb_dfu_handle = register_dissector("usb_dfu", dissect_usb_dfu, proto_usb_dfu);

    expert_module = expert_register_protocol(proto_usb_dfu);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol(proto_usb_dfu, NULL);
    prefs_register_static_text_preference(module, "version",
            "USB DFU Specification 1.1",
            "Version of protocol supported by this dissector.");
}

void
proto_reg_handoff_usb_dfu(void)
{
    dissector_handle_t  usf_dfu_descriptor_handle;

    usf_dfu_descriptor_handle = create_dissector_handle(dissect_usb_dfu_descriptor, proto_usb_dfu);
    dissector_add_uint("usb.descriptor", IF_CLASS_APPLICATION_SPECIFIC, usf_dfu_descriptor_handle);

    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x1db5, usb_dfu_handle); /* IDBG in DFU mode */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x6001, usb_dfu_handle); /* Ubertooth Zero DFU */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x6003, usb_dfu_handle); /* Ubertooth One DFU */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x600f, usb_dfu_handle); /* Paparazzi Lisa/M (DFU) */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x6011, usb_dfu_handle); /* LeoLipo (DFU) */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x6017, usb_dfu_handle); /* Black Magic Debug Probe (DFU) */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x6044, usb_dfu_handle); /* Open Source USB CANBUS converter (DFU Mode) */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x6064, usb_dfu_handle); /* CPC FPGA (DFU) */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x6069, usb_dfu_handle); /* xser (DFU mode) */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x6082, usb_dfu_handle); /* Facecandy *USB DFU loader */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x6084, usb_dfu_handle); /* arcin arcade controller (USB DFU loader) */

    dissector_add_for_decode_as("usb.device",   usb_dfu_handle);
    dissector_add_for_decode_as("usb.protocol", usb_dfu_handle);
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
