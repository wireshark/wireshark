/* packet-hci_mon.c
 * Routines for Bluetooth Linux Monitor dissection
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
#include <wiretap/wtap.h>

#include "packet-bluetooth.h"

static int proto_hci_mon = -1;

static int hf_adapter_id = -1;
static int hf_opcode = -1;
static int hf_type = -1;
static int hf_bus = -1;
static int hf_bd_addr = -1;
static int hf_name = -1;

static gint ett_hci_mon = -1;

static expert_field ei_unknown_data = EI_INIT;

static wmem_tree_t *adapter_to_disconnect_in_frame = NULL;

static dissector_handle_t hci_mon_handle;
static dissector_handle_t bthci_cmd_handle;
static dissector_handle_t bthci_evt_handle;
static dissector_handle_t bthci_acl_handle;
static dissector_handle_t bthci_sco_handle;

static const value_string opcode_vals[] = {
    { 0x00,  "New Index" },
    { 0x01,  "Delete Index" },
    { 0x02,  "HCI Command Packet" },
    { 0x03,  "HCI Event Packet" },
    { 0x04,  "ACL Tx Packet" },
    { 0x05,  "ACL Rx Packet" },
    { 0x06,  "SCO Tx Packet" },
    { 0x07,  "SCO Rx Packet" },
    { 0x00, NULL }
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

    bluetooth_data = (bluetooth_data_t *) data;

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
    PROTO_ITEM_SET_GENERATED(sub_item);

    sub_item = proto_tree_add_uint(hci_mon_tree, hf_opcode, tvb, offset, 0, opcode);
    PROTO_ITEM_SET_GENERATED(sub_item);

    col_append_fstr(pinfo->cinfo, COL_INFO, "Adapter Id: %u, Opcode: %s",
            adapter_id, val_to_str_ext_const(opcode, &hci_mon_opcode_vals_ext, "Unknown"));

    bluetooth_data->adapter_id = adapter_id;

    k_interface_id = bluetooth_data->interface_id;
    k_adapter_id   = adapter_id;
    k_frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key    = &k_interface_id;
    key[1].length = 1;
    key[1].key    = &k_adapter_id;

    if (!pinfo->fd->flags.visited && opcode == 0x01) { /* Delete Index */
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
    case 0x00: /* New Index */
        proto_tree_add_item(hci_mon_tree, hf_bus, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(hci_mon_tree, hf_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        offset = dissect_bd_addr(hf_bd_addr, pinfo, hci_mon_tree, tvb, offset, TRUE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

        proto_tree_add_item(hci_mon_tree, hf_name, tvb, offset, 8, ENC_NA | ENC_ASCII);
        offset += 8;

        break;
    case 0x01: /* Delete Index */
        /* No parameters */

        break;
    case 0x02: /* HCI Command Packet */
        call_dissector_with_data(bthci_cmd_handle, next_tvb, pinfo, tree, bluetooth_data);
        offset = tvb_reported_length(tvb);

        break;
   case 0x03:  /* HCI Event Packet */
        call_dissector_with_data(bthci_evt_handle, next_tvb, pinfo, tree, bluetooth_data);
        offset = tvb_reported_length(tvb);

        break;
   case 0x04:  /* ACL Tx Packet */
   case 0x05:  /* ACL Rx Packet */
        call_dissector_with_data(bthci_acl_handle, next_tvb, pinfo, tree, bluetooth_data);
        offset = tvb_reported_length(tvb);

        break;
   case 0x06:  /* SCO Tx Packet */
   case 0x07:  /* SCO Rx Packet */
        call_dissector_with_data(bthci_sco_handle, next_tvb, pinfo, tree, bluetooth_data);
        offset = tvb_reported_length(tvb);

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
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &hci_mon_opcode_vals_ext, 0x00,
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
        }
    };

    static ei_register_info ei[] = {
        { &ei_unknown_data, { "hci_mon.unknown_data", PI_PROTOCOL, PI_WARN, "Unknown data", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_hci_mon,
    };

    proto_hci_mon = proto_register_protocol("Bluetooth Linux Monitor Transport", "HCI_MON", "hci_mon");
    proto_register_field_array(proto_hci_mon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    hci_mon_handle = register_dissector("hci_mon", dissect_hci_mon, proto_hci_mon);

    expert_module = expert_register_protocol(proto_hci_mon);
    expert_register_field_array(expert_module, ei, array_length(ei));

    adapter_to_disconnect_in_frame = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    module = prefs_register_protocol(proto_hci_mon, NULL);
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
