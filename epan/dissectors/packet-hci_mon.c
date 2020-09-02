/* packet-hci_mon.c
 * Routines for Bluetooth Linux Monitor dissection
 *
 * Copyright 2013, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>

#include "packet-bluetooth.h"

static int proto_hci_mon = -1;

static int hf_adapter_id = -1;
static int hf_opcode = -1;
static int hf_type = -1;
static int hf_bus = -1;
static int hf_bd_addr = -1;
static int hf_name = -1;
static int hf_manufacturer = -1;
static int hf_system_note = -1;
static int hf_priority = -1;
static int hf_ident_length = -1;
static int hf_ident = -1;
static int hf_cookie = -1;
static int hf_format = -1;
static int hf_version = -1;
static int hf_revision = -1;
static int hf_flags = -1;
static int hf_flags_trusted_socket = -1;
static int hf_command_length = -1;
static int hf_command = -1;
static int hf_event = -1;

static gint ett_hci_mon = -1;
static gint ett_flags = -1;

static expert_field ei_unknown_data = EI_INIT;

static wmem_tree_t *adapter_to_disconnect_in_frame = NULL;

static dissector_handle_t hci_mon_handle;
static dissector_handle_t bthci_cmd_handle;
static dissector_handle_t bthci_evt_handle;
static dissector_handle_t bthci_acl_handle;
static dissector_handle_t bthci_sco_handle;

#define OPCODE_NEW_INDEX         0
#define OPCODE_DELETE_INDEX      1
#define OPCODE_HCI_COMMAND_PKT   2
#define OPCODE_HCI_EVENT_PKT     3
#define OPCODE_ACL_TX_PACKET     4
#define OPCODE_ACL_RX_PACKET     5
#define OPCODE_SCO_TX_PACKET     6
#define OPCODE_SCO_RX_PACKET     7
#define OPCODE_OPEN_INDEX        8
#define OPCODE_CLOSE_INDEX       9
#define OPCODE_INDEX_INFO        10
#define OPCODE_VENDOR_DIAGNOSTIC 11
#define OPCODE_SYSTEM_NOTE       12
#define OPCODE_USER_LOGGING      13
#define OPCODE_CONTROL_OPEN      14
#define OPCODE_CONTROL_CLOSE     15
#define OPCODE_CONTROL_COMMAND   16
#define OPCODE_CONTROL_EVENT     17

static const value_string opcode_vals[] = {
    { OPCODE_NEW_INDEX,         "New Index" },
    { OPCODE_DELETE_INDEX,      "Delete Index" },
    { OPCODE_HCI_COMMAND_PKT,   "HCI Command Packet" },
    { OPCODE_HCI_EVENT_PKT,     "HCI Event Packet" },
    { OPCODE_ACL_TX_PACKET,     "ACL Tx Packet" },
    { OPCODE_ACL_RX_PACKET,     "ACL Rx Packet" },
    { OPCODE_SCO_TX_PACKET,     "SCO Tx Packet" },
    { OPCODE_SCO_RX_PACKET,     "SCO Rx Packet" },
    { OPCODE_OPEN_INDEX,        "Open Index" },
    { OPCODE_CLOSE_INDEX,       "Close Index" },
    { OPCODE_INDEX_INFO,        "Index Info" },
    { OPCODE_VENDOR_DIAGNOSTIC, "Vendor Diagnostic" },
    { OPCODE_SYSTEM_NOTE,       "System Note" },
    { OPCODE_USER_LOGGING,      "User Logging" },
    { OPCODE_CONTROL_OPEN,      "Control Open" },
    { OPCODE_CONTROL_CLOSE,     "Control Close" },
    { OPCODE_CONTROL_COMMAND,   "Control Command" },
    { OPCODE_CONTROL_EVENT,     "Control Event" },
    { 0, NULL }
};
value_string_ext(hci_mon_opcode_vals_ext) = VALUE_STRING_EXT_INIT(opcode_vals);

static const value_string type_vals[] = {
    { 0x00,  "Virtual" },
    { 0x01,  "USB" },
    { 0x02,  "PC Card" },
    { 0x03,  "UART" },
    { 0x04,  "RS232" },
    { 0x05,  "PCI" },
    { 0x06,  "SDIO" },
    { 0x00, NULL }
};
static value_string_ext(type_vals_ext) = VALUE_STRING_EXT_INIT(type_vals);

static const value_string bus_vals[] = {
    { 0x00,  "BR/EDR" },
    { 0x01,  "AMP" },
    { 0x00, NULL }
};
static value_string_ext(bus_vals_ext) = VALUE_STRING_EXT_INIT(bus_vals);

#define CTRL_OPEN_RAW     0x0000
#define CTRL_OPEN_USER    0x0001
#define CTRL_OPEN_CONTROL 0x0002

static const value_string format_vals[] = {
    { CTRL_OPEN_RAW,     "Rqw" },
    { CTRL_OPEN_USER,    "User" },
    { CTRL_OPEN_CONTROL, "Control" },
    { 0x00, NULL }
};
static value_string_ext(format_vals_ext) = VALUE_STRING_EXT_INIT(format_vals);

#define EVENT_COMMAND_COMPLETE               0x0001
#define EVENT_COMMAND_STATUS                 0x0002
#define EVENT_CONTROLLER_ERROR               0x0003
#define EVENT_INDEX_ADDED                    0x0004
#define EVENT_INDEX_REMOVED                  0x0005
#define EVENT_NEW_SETTINGS                   0x0006
#define EVENT_CLASS_OF_DEVICE_CHANGED        0x0007
#define EVENT_LOCAL_NAME_CHANGED             0x0008
#define EVENT_NEW_LINK_KEY                   0x0009
#define EVENT_NEW_LONG_TERM_KEY              0x000a
#define EVENT_DEVICE_CONNECTED               0x000b
#define EVENT_DEVICE_DISCONNECTED            0x000c
#define EVENT_CONNECT_FAILED                 0x000d
#define EVENT_PIN_CODE_REQUEST               0x000e
#define EVENT_USER_CONFIRMATION_REQUEST      0x000f
#define EVENT_USER_PASSKEY_REQUEST           0x0010
#define EVENT_AUTHENTICAION_FAILED           0x0011
#define EVENT_DEVICE_FOUND                   0x0012
#define EVENT_DISCOVERING                    0x0013
#define EVENT_DEVICE_BLOCKED                 0x0014
#define EVENT_DEVICE_UNBLOCKED               0x0015
#define EVENT_DEVICE_UNPAIRED                0x0016
#define EVENT_PASSKEY_NOTIFY                 0x0017
#define EVENT_NEW_IRK                        0x0018
#define EVENT_NEW_CSRK                       0x0019
#define EVENT_DEVICE_ADDED                   0x001a
#define EVENT_DEVICE_REMOVED                 0x001b
#define EVENT_NEW_CONNECTION_PARAMETER       0x001c
#define EVENT_UNCONFIGURED_INDEX_ADDED       0x001d
#define EVENT_UNCONFIGURED_INDEX_REMOVED     0x001e
#define EVENT_NEW_CONFIGURATION_OPTIONS      0x001f
#define EVENT_EXTENDED_INDEX_ADDED           0x0020
#define EVENT_EXTENDED_INDEX_REMOVED         0x0021
#define EVENT_LOCAL_OUT_OF_BAND_DATA_UPDATED 0x0022
#define EVENT_ADVERTISING_ADDED              0x0023
#define EVENT_ADVERTISING_REMOVED            0x0024
#define EVENT_EXTENDED_INFO_CHANGED          0x0025
#define EVENT_PHY_CONFIGURATION_CHANGED      0x0026

static const value_string event_vals[] = {
    { EVENT_COMMAND_COMPLETE,               "Command complete" },
    { EVENT_COMMAND_STATUS,                 "Command status" },
    { EVENT_CONTROLLER_ERROR,               "Controller error" },
    { EVENT_INDEX_ADDED,                    "Index added" },
    { EVENT_INDEX_REMOVED,                  "Index removed" },
    { EVENT_NEW_SETTINGS,                   "New settings" },
    { EVENT_CLASS_OF_DEVICE_CHANGED,        "Class of device changed" },
    { EVENT_LOCAL_NAME_CHANGED,             "Local name changed" },
    { EVENT_NEW_LINK_KEY,                   "New link key" },
    { EVENT_NEW_LONG_TERM_KEY,              "New long-term key" },
    { EVENT_DEVICE_CONNECTED,               "Device connected" },
    { EVENT_DEVICE_DISCONNECTED,            "Device disconnected" },
    { EVENT_CONNECT_FAILED,                 "Connect failed" },
    { EVENT_PIN_CODE_REQUEST,               "PIN code request" },
    { EVENT_USER_CONFIRMATION_REQUEST,      "User confirmation request" },
    { EVENT_USER_PASSKEY_REQUEST,           "User passkey request" },
    { EVENT_AUTHENTICAION_FAILED,           "Authentication failed" },
    { EVENT_DEVICE_FOUND,                   "Device found" },
    { EVENT_DISCOVERING,                    "Discovering" },
    { EVENT_DEVICE_BLOCKED,                 "Device blocked" },
    { EVENT_DEVICE_UNBLOCKED,               "Device unblocked" },
    { EVENT_DEVICE_UNPAIRED,                "Device unpaired" },
    { EVENT_PASSKEY_NOTIFY,                 "Passkey notify" },
    { EVENT_NEW_IRK,                        "New IRK" },
    { EVENT_NEW_CSRK,                       "New CSRK" },
    { EVENT_DEVICE_ADDED,                   "Device added" },
    { EVENT_DEVICE_REMOVED,                 "Device removed" },
    { EVENT_NEW_CONNECTION_PARAMETER,       "New connection parameter" },
    { EVENT_UNCONFIGURED_INDEX_ADDED,       "Unconfigured index added" },
    { EVENT_UNCONFIGURED_INDEX_REMOVED,     "Unconfigured index removed" },
    { EVENT_NEW_CONFIGURATION_OPTIONS,      "New configuration options" },
    { EVENT_EXTENDED_INDEX_ADDED,           "Extended index added" },
    { EVENT_EXTENDED_INDEX_REMOVED,         "Extended index removed" },
    { EVENT_LOCAL_OUT_OF_BAND_DATA_UPDATED, "Local out-of-band data updated" },
    { EVENT_ADVERTISING_ADDED,              "Advertising added" },
    { EVENT_ADVERTISING_REMOVED,            "Advertising removed" },
    { EVENT_EXTENDED_INFO_CHANGED,          "Extended info changed" },
    { EVENT_PHY_CONFIGURATION_CHANGED,      "PHY configuration changed" },
    { 0x00, NULL }
};
static value_string_ext(event_vals_ext) = VALUE_STRING_EXT_INIT(event_vals);

void proto_register_hci_mon(void);
void proto_reg_handoff_hci_mon(void);

static gint
dissect_hci_mon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_tree       *hci_mon_item;
    proto_item       *hci_mon_tree;
    proto_item       *sub_item;
    gint              offset = 0;
    guint16           opcode;
    guint16           adapter_id;
    bluetooth_data_t *bluetooth_data;
    tvbuff_t         *next_tvb;
    guint32          *adapter_disconnect_in_frame;
    wmem_tree_t      *subtree;
    wmem_tree_key_t  key[4];
    guint32          k_interface_id;
    guint32          k_adapter_id;
    guint32          k_frame_number;
    guint32          ident_length;
    guint32          command_length;
    static int * const flags_fields[] = {
        &hf_flags_trusted_socket,
        NULL
    };

    bluetooth_data = (bluetooth_data_t *) data;

    /*
     * XXX - the raw data sent to a Bluetooth monitor socket has a 6-byte
     * header, the last 2 bytes of which are a big-endian length field,
     * giving the length of the payload.
     *
     * Somehow, the length field disappears.
     */
    DISSECTOR_ASSERT(bluetooth_data->previous_protocol_data_type == BT_PD_BTMON);
    adapter_id = bluetooth_data->previous_protocol_data.btmon->adapter_id;
    opcode = bluetooth_data->previous_protocol_data.btmon->opcode;

    if (opcode == 0x00 || opcode == 0x01)
        pinfo->p2p_dir = P2P_DIR_RECV;
    else if (opcode % 2)
        pinfo->p2p_dir = P2P_DIR_RECV;
    else
        pinfo->p2p_dir = P2P_DIR_SENT;

    hci_mon_item = proto_tree_add_item(tree, proto_hci_mon, tvb, offset, tvb_captured_length(tvb), ENC_NA);
    hci_mon_tree = proto_item_add_subtree(hci_mon_item, ett_hci_mon);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_MON");

    if (opcode == 0x00 || opcode == 0x01)
        col_set_str(pinfo->cinfo, COL_INFO, "Info ");
    else switch (pinfo->p2p_dir) {

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

    sub_item = proto_tree_add_uint(hci_mon_tree, hf_adapter_id,  tvb, offset, 0, adapter_id);
    proto_item_set_generated(sub_item);

    sub_item = proto_tree_add_uint(hci_mon_tree, hf_opcode, tvb, offset, 0, opcode);
    proto_item_set_generated(sub_item);

    col_append_fstr(pinfo->cinfo, COL_INFO, "Adapter Id: %u, Opcode: %s",
            adapter_id, val_to_str_ext_const(opcode, &hci_mon_opcode_vals_ext, "Unknown (%u)"));

    bluetooth_data->adapter_id = adapter_id;

    k_interface_id = bluetooth_data->interface_id;
    k_adapter_id   = adapter_id;
    k_frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key    = &k_interface_id;
    key[1].length = 1;
    key[1].key    = &k_adapter_id;

    if (!pinfo->fd->visited && opcode == 0x01) { /* Delete Index */
        guint32           *disconnect_in_frame;

        key[2].length = 1;
        key[2].key    = &k_frame_number;
        key[3].length = 0;
        key[3].key    = NULL;

        disconnect_in_frame = wmem_new(wmem_file_scope(), guint32);

        if (disconnect_in_frame) {
            *disconnect_in_frame = pinfo->num;

            wmem_tree_insert32_array(adapter_to_disconnect_in_frame, key, disconnect_in_frame);
        }
    }

    key[2].length = 0;
    key[2].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(adapter_to_disconnect_in_frame, key);
    adapter_disconnect_in_frame = (subtree) ? (guint32 *) wmem_tree_lookup32_le(subtree, k_frame_number) : NULL;
    if (adapter_disconnect_in_frame) {
        bluetooth_data->adapter_disconnect_in_frame = adapter_disconnect_in_frame;
    } else {
        bluetooth_data->adapter_disconnect_in_frame = &max_disconnect_in_frame;
    }

    pinfo->ptype = PT_BLUETOOTH;

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    switch(opcode) {
    case OPCODE_NEW_INDEX:
        proto_tree_add_item(hci_mon_tree, hf_bus, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(hci_mon_tree, hf_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        offset = dissect_bd_addr(hf_bd_addr, pinfo, hci_mon_tree, tvb, offset, TRUE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

        proto_tree_add_item(hci_mon_tree, hf_name, tvb, offset, 8, ENC_NA | ENC_ASCII);
        offset += 8;

        break;
    case OPCODE_DELETE_INDEX:
        /* No parameters */

        break;
    case OPCODE_HCI_COMMAND_PKT:
        call_dissector_with_data(bthci_cmd_handle, next_tvb, pinfo, tree, bluetooth_data);
        offset = tvb_reported_length(tvb);

        break;
   case OPCODE_HCI_EVENT_PKT:
        call_dissector_with_data(bthci_evt_handle, next_tvb, pinfo, tree, bluetooth_data);
        offset = tvb_reported_length(tvb);

        break;
   case OPCODE_ACL_TX_PACKET:
   case OPCODE_ACL_RX_PACKET:
        call_dissector_with_data(bthci_acl_handle, next_tvb, pinfo, tree, bluetooth_data);
        offset = tvb_reported_length(tvb);

        break;
   case OPCODE_SCO_TX_PACKET:
   case OPCODE_SCO_RX_PACKET:
        call_dissector_with_data(bthci_sco_handle, next_tvb, pinfo, tree, bluetooth_data);
        offset = tvb_reported_length(tvb);

        break;

    case OPCODE_OPEN_INDEX:
        /* No parameters */

        break;

    case OPCODE_CLOSE_INDEX:
        /* No parameters */

        break;

    case OPCODE_INDEX_INFO:
        offset = dissect_bd_addr(hf_bd_addr, pinfo, hci_mon_tree, tvb, offset, TRUE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

        proto_tree_add_item(hci_mon_tree, hf_manufacturer, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;

    case OPCODE_VENDOR_DIAGNOSTIC:
        /* XXX - what are the parameters, if any? */

        break;

    case OPCODE_SYSTEM_NOTE:
        /*
         * XXX - NUL-terminated, so that you always have a NUL at the
         * end of the message?
         *
         * Or is it data from userland, which might or might not be
         * NUL-terminated?
         *
         * We make it FT_STRINGZPAD, just in case.
         */
        proto_tree_add_item(hci_mon_tree, hf_system_note, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA | ENC_ASCII);
        offset = tvb_reported_length(tvb);

        break;

    case OPCODE_USER_LOGGING:
        proto_tree_add_item(hci_mon_tree, hf_priority, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item_ret_uint(hci_mon_tree, hf_priority, tvb, offset, 1, ENC_NA, &ident_length);
        offset += 1;

        /*
         * XXX - this is both counted and NUL-terminated, so you have
         * <length> bytes of string followed by a NUL.  We'll just
         * treat it as counted.
         */
        proto_tree_add_item(hci_mon_tree, hf_priority, tvb, offset, ident_length, ENC_NA | ENC_ASCII);
        offset += ident_length + 1; /* Skip the terminating NUL */

        break;

    case OPCODE_CONTROL_OPEN:
        proto_tree_add_item(hci_mon_tree, hf_cookie, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(hci_mon_tree, hf_format, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(hci_mon_tree, hf_version, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(hci_mon_tree, hf_revision, tvb, offset + 1, 2, ENC_LITTLE_ENDIAN);
        offset += 3;

        proto_tree_add_bitmask(hci_mon_tree, tvb, offset, hf_flags, ett_flags,
                               flags_fields, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item_ret_uint(hci_mon_tree, hf_command_length, tvb, offset, 1, ENC_NA, &command_length);
        offset += 1;

        /*
         * XXX - null-padded?  We assume so; the Linux kernel code, as of
         * the 5.3 kernel, always copies TASK_COMM_LEN bytes and sets the
         * command length to TASK_COMM_LEN.
         */
        proto_tree_add_item(hci_mon_tree, hf_command, tvb, offset, command_length, ENC_NA | ENC_ASCII);
        offset += command_length;

        break;

    case OPCODE_CONTROL_CLOSE:
        proto_tree_add_item(hci_mon_tree, hf_cookie, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;

    case OPCODE_CONTROL_COMMAND:
        proto_tree_add_item(hci_mon_tree, hf_cookie, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* XXX - different field for this opcode? */
        proto_tree_add_item(hci_mon_tree, hf_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;

    case OPCODE_CONTROL_EVENT:
        proto_tree_add_item(hci_mon_tree, hf_cookie, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(hci_mon_tree, hf_event, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* XXX - dissect the payload of the event */

        break;
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert(hci_mon_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_reported_length_remaining(tvb, offset));
        offset = tvb_reported_length(tvb);
    }

   /* NOTE: Oops... HCI_MON have special packet with length 0, but there is a pseudo-header with certain infos,
            mark it as dissected */
    if (opcode == 0x01)
        return 1;

    return offset;
}

void
proto_register_hci_mon(void)
{
    module_t *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        {  &hf_adapter_id,
            { "Adapter ID",                      "hci_mon.adapter_id",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_opcode,
            { "Opcode",                          "hci_mon.opcode",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &hci_mon_opcode_vals_ext, 0x00,
            NULL, HFILL }
        },
        {  &hf_type,
            { "Type",                            "hci_mon.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &type_vals_ext, 0x00,
            NULL, HFILL }
        },
        {  &hf_bus,
            { "Bus",                             "hci_mon.bus",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bus_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_bd_addr,
          { "BD_ADDR",                           "hci_mon.bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_name,
          { "Adapter Name",                      "hci_mon.adapter_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {  &hf_manufacturer,
            { "Manufacturer",                    "hci_mon.manufacturer",
            FT_UINT16, BASE_HEX, NULL, 0x000,
            NULL, HFILL }
        },
        { &hf_system_note,
          { "System Note",                       "hci_mon.system_note",
            FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_priority,
          { "Priority",                          "hci_mon.priority",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_ident_length,
          { "Ident Length",                      "hci_mon.ident_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_ident,
          { "Ident",                             "hci_mon.ident",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cookie,
          { "Cookie",                            "hci_mon.cookie",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_format,
          { "Format",                            "hci_mon.format",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &format_vals_ext, 0x00,
            NULL, HFILL}
        },
        { &hf_version,
          { "Version",                           "hci_mon.version",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_revision,
          { "Revision",                          "hci_mon.version_minor",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_flags,
          { "Flags",                             "hci_mon.flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_flags_trusted_socket,
          { "Trusted Socket",                    "hci_mon.flags.trusted_socket",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL}
        },
        { &hf_command_length,
          { "Command Length",                    "hci_mon.command_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_command,
          { "Command",                           "hci_mon.command",
            FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_event,
          { "Event",                            "hci_mon.event",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &event_vals_ext, 0x0,
            NULL, HFILL}
        }
    };

    static ei_register_info ei[] = {
        { &ei_unknown_data, { "hci_mon.unknown_data", PI_PROTOCOL, PI_WARN, "Unknown data", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_hci_mon,
        &ett_flags
    };

    proto_hci_mon = proto_register_protocol("Bluetooth Linux Monitor Transport", "HCI_MON", "hci_mon");
    proto_register_field_array(proto_hci_mon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    hci_mon_handle = register_dissector("hci_mon", dissect_hci_mon, proto_hci_mon);

    expert_module = expert_register_protocol(proto_hci_mon);
    expert_register_field_array(expert_module, ei, array_length(ei));

    adapter_to_disconnect_in_frame = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    module = prefs_register_protocol_subtree("Bluetooth", proto_hci_mon, NULL);
    prefs_register_static_text_preference(module, "bthci_mon.version",
            "Bluetooth Linux Monitor Transport introduced in BlueZ 5.x",
            "Version of protocol supported by this dissector.");
}

void
proto_reg_handoff_hci_mon(void)
{
    bthci_cmd_handle = find_dissector_add_dependency("bthci_cmd", proto_hci_mon);
    bthci_evt_handle = find_dissector_add_dependency("bthci_evt", proto_hci_mon);
    bthci_acl_handle = find_dissector_add_dependency("bthci_acl", proto_hci_mon);
    bthci_sco_handle = find_dissector_add_dependency("bthci_sco", proto_hci_mon);

    dissector_add_uint("bluetooth.encap", WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR, hci_mon_handle);
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
