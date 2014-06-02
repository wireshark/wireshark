/* packet-hci_usb.c
 * Routines for Bluetooth HCI USB dissection
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
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
#include <epan/reassemble.h>
#include <epan/wmem/wmem.h>
#include <wiretap/wtap.h>

#include "packet-usb.h"
#include "packet-bluetooth-hci.h"

static int proto_hci_usb = -1;
static int hf_bthci_usb_data = -1;
static int hf_bthci_usb_packet_fragment = -1;
static int hf_bthci_usb_packet_complete = -1;
static int hf_bthci_usb_packet_unknown_fragment = -1;
static int hf_bthci_usb_setup_request = -1;
static int hf_bthci_usb_setup_value = -1;
static int hf_bthci_usb_setup_adapter_id = -1;
static int hf_bthci_usb_setup_length = -1;

static gint ett_hci_usb = -1;
static gint ett_hci_usb_msg_fragment = -1;
static gint ett_hci_usb_msg_fragments = -1;

static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;

static wmem_tree_t *chandle_sessions        = NULL;
static wmem_tree_t *chandle_to_bdaddr_table = NULL;
static wmem_tree_t *bdaddr_to_name_table    = NULL;
static wmem_tree_t *localhost_name          = NULL;
static wmem_tree_t *localhost_bdaddr        = NULL;
static wmem_tree_t *fragment_info_table     = NULL;

static reassembly_table hci_usb_reassembly_table;

static dissector_handle_t hci_usb_handle;
static dissector_handle_t bthci_cmd_handle;
static dissector_handle_t bthci_evt_handle;
static dissector_handle_t bthci_acl_handle;
static dissector_handle_t bthci_sco_handle;

typedef struct _fragment_info_t {
    gint remaining_length;
    gint fragment_id;
} fragment_info_t;

static const fragment_items hci_usb_msg_frag_items = {
    /* Fragment subtrees */
    &ett_hci_usb_msg_fragment,
    &ett_hci_usb_msg_fragments,
    /* Fragment fields */
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    /* Reassembled in field */
    &hf_msg_reassembled_in,
    /* Reassembled length field */
    &hf_msg_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Message fragments"
};

static const value_string request_vals[] = {
    { 0x00,  "Primary Controller Function" },
    { 0x2B,  "AMP Controller Function" },
    { 0xE0,  "Primary Controller Function (Historical)" },
    { 0x00, NULL }
};
static value_string_ext(request_vals_ext) = VALUE_STRING_EXT_INIT(request_vals);

static guint32 max_disconnect_in_frame = G_MAXUINT32;


void proto_register_hci_usb(void);
void proto_reg_handoff_hci_usb(void);

static gint
dissect_hci_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item     *ttree = NULL;
    proto_tree     *titem = NULL;
    proto_item     *pitem = NULL;
    gint            offset = 0;
    usb_conv_info_t *usb_conv_info;
    tvbuff_t       *next_tvb = NULL;
    hci_data_t     *hci_data;
    gint            p2p_dir_save;
    guint32         session_id;
    fragment_head  *reassembled;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    usb_conv_info = (usb_conv_info_t *)data;

    titem = proto_tree_add_item(tree, proto_hci_usb, tvb, offset, -1, ENC_NA);
    ttree = proto_item_add_subtree(titem, ett_hci_usb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_USB");

    p2p_dir_save = pinfo->p2p_dir;
    pinfo->p2p_dir = (usb_conv_info->is_request) ? P2P_DIR_SENT : P2P_DIR_RECV;

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_INFO, "Sent");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd");
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction");
        break;
    }

    if (usb_conv_info->is_setup) {
        proto_tree_add_item(ttree, hf_bthci_usb_setup_request, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(ttree, hf_bthci_usb_setup_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(ttree, hf_bthci_usb_setup_adapter_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(ttree, hf_bthci_usb_setup_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    session_id = usb_conv_info->bus_id << 16 | usb_conv_info->device_address << 8 | ((pinfo->p2p_dir == P2P_DIR_RECV) ? 1 : 0 ) << 7 | usb_conv_info->endpoint;

    hci_data = (hci_data_t *) wmem_new(wmem_packet_scope(), hci_data_t);
    if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
        hci_data->interface_id = pinfo->phdr->interface_id;
    else
        hci_data->interface_id = HCI_INTERFACE_DEFAULT;
    hci_data->adapter_id = usb_conv_info->bus_id << 8 | usb_conv_info->device_address;
/* TODO: adapter disconnect on some USB action, for now do not support adapter disconnection */
    hci_data->adapter_disconnect_in_frame = &max_disconnect_in_frame;
    hci_data->chandle_sessions = chandle_sessions;
    hci_data->chandle_to_bdaddr_table = chandle_to_bdaddr_table;
    hci_data->bdaddr_to_name_table = bdaddr_to_name_table;
    hci_data->localhost_bdaddr = localhost_bdaddr;
    hci_data->localhost_name = localhost_name;

    pinfo->ptype = PT_BLUETOOTH;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (!pinfo->fd->flags.visited && usb_conv_info->endpoint <= 0x02) {
        fragment_info_t  *fragment_info;

        fragment_info = (fragment_info_t *) wmem_tree_lookup32(fragment_info_table, session_id);
        if (fragment_info == NULL) {
            fragment_info = (fragment_info_t *) wmem_new(wmem_file_scope(), fragment_info_t);
            fragment_info->fragment_id = 0;
            fragment_info->remaining_length = 0;

            wmem_tree_insert32(fragment_info_table, session_id, fragment_info);
        }

        if (fragment_info->fragment_id == 0) {
            switch(usb_conv_info->endpoint)
            {
            case 0:
                fragment_info->remaining_length = tvb_get_guint8(tvb, offset + 2) + 3;
                break;
            case 1:
                fragment_info->remaining_length = tvb_get_guint8(tvb, offset + 1) + 2;
                break;
            case 2:
                fragment_info->remaining_length = tvb_get_letohs(tvb, offset + 2) + 4;
                break;
            }
        }

        fragment_info->remaining_length -= tvb_ensure_length_remaining(tvb, offset);

        fragment_add_seq_check(&hci_usb_reassembly_table,
                               tvb, offset, pinfo, session_id, NULL,
                               fragment_info->fragment_id, tvb_length_remaining(tvb, offset), (fragment_info->remaining_length == 0) ? FALSE : TRUE);
        if (fragment_info->remaining_length > 0)
            fragment_info->fragment_id += 1;
        else
            fragment_info->fragment_id = 0;
    }

    reassembled = fragment_get_reassembled_id(&hci_usb_reassembly_table, pinfo, session_id);
    if (reassembled && pinfo->fd->num < reassembled->reassembled_in) {
        pitem = proto_tree_add_item(ttree, hf_bthci_usb_packet_fragment, tvb, offset, -1, ENC_NA);
        PROTO_ITEM_SET_GENERATED(pitem);

        col_append_str(pinfo->cinfo, COL_INFO, " Fragment");
    } else if (reassembled && pinfo->fd->num == reassembled->reassembled_in) {
        pitem = proto_tree_add_item(ttree, hf_bthci_usb_packet_complete, tvb, offset, -1, ENC_NA);
        PROTO_ITEM_SET_GENERATED(pitem);

        if (reassembled->len > tvb_ensure_length_remaining(tvb, offset)) {
            next_tvb = process_reassembled_data(tvb, 0, pinfo,
                    "Reassembled HCI_USB",
                    reassembled, &hci_usb_msg_frag_items,
                    NULL, ttree);
        }

        switch(usb_conv_info->endpoint)
        {
        case 0:
            call_dissector_with_data(bthci_cmd_handle, next_tvb, pinfo, tree, hci_data);
            break;
        case 1:
            call_dissector_with_data(bthci_evt_handle, next_tvb, pinfo, tree, hci_data);
            break;
        case 2:
            call_dissector_with_data(bthci_acl_handle, next_tvb, pinfo, tree, hci_data);
            break;
        }
    } else {
        pitem = proto_tree_add_item(ttree, hf_bthci_usb_packet_unknown_fragment, tvb, offset, -1, ENC_NA);
        PROTO_ITEM_SET_GENERATED(pitem);
    }

    if (usb_conv_info->endpoint == 0x03) {
        call_dissector_with_data(bthci_sco_handle, next_tvb, pinfo, tree, hci_data);
    } else if (usb_conv_info->endpoint > 0x03) {
        proto_tree_add_item(ttree, hf_bthci_usb_data, tvb, offset, -1, ENC_NA);
    }

    offset += tvb_length_remaining(tvb, offset);

    pinfo->p2p_dir = p2p_dir_save;

    return offset;
}

void
proto_register_hci_usb(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        {  &hf_msg_fragments,
            { "Message fragments",               "hci_usb.msg.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_msg_fragment,
            { "Message fragment",                "hci_usb.msg.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_msg_fragment_overlap,
            { "Message fragment overlap",        "hci_usb.msg.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_msg_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data", "hci_usb.msg.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_msg_fragment_multiple_tails,
            { "Message has multiple tail fragments", "hci_usb.msg.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_msg_fragment_too_long_fragment,
            { "Message fragment too long",       "hci_usb.msg.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_msg_fragment_error,
            { "Message defragmentation error",   "hci_usb.msg.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_msg_fragment_count,
            { "Message fragment count",          "hci_usb.msg.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_msg_reassembled_in,
            { "Reassembled in",                  "hci_usb.msg.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {  &hf_msg_reassembled_length,
            { "Reassembled MP2T length",         "hci_usb.msg.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_usb_packet_fragment,
            { "Packet Fragment",                 "hci_usb.packet.fragment",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_usb_packet_complete,
            { "Packet Complete",                 "hci_usb.packet.complete",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_usb_packet_unknown_fragment,
            { "Unknown Packet Fragment",         "hci_usb.packet.unknown_fragment",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_usb_setup_request,
          { "bRequest",                          "hci_usb.setup.bRequest",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &request_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_bthci_usb_setup_value,
          { "wValue",                            "hci_usb.setup.wValue",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_bthci_usb_setup_adapter_id,
          { "Adapter ID",                        "hci_usb.setup.adapter_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_bthci_usb_setup_length,
          { "wLength",                           "hci_usb.setup.wLength",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_bthci_usb_data,
            { "Unknown Data",                    "hci_usb.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_hci_usb,
        &ett_hci_usb_msg_fragment,
        &ett_hci_usb_msg_fragments,
    };

    reassembly_table_init(&hci_usb_reassembly_table,
                          &addresses_reassembly_table_functions);
    fragment_info_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    chandle_sessions = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    chandle_to_bdaddr_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope()); /* adapter, chandle: bdaddr */
    bdaddr_to_name_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope()); /* bdaddr: name */
    localhost_bdaddr = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope()); /* adapter, frame: bdaddr */
    localhost_name = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope()); /* adapter, frame: name */

    proto_hci_usb = proto_register_protocol("Bluetooth HCI USB Transport", "HCI_USB", "hci_usb");
    proto_register_field_array(proto_hci_usb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    hci_usb_handle = new_register_dissector("hci_usb", dissect_hci_usb, proto_hci_usb);

    module = prefs_register_protocol(proto_hci_usb, NULL);
    prefs_register_static_text_preference(module, "bthci_usb.version",
            "Bluetooth HCI USB Transport from Core 4.0",
            "Version of protocol supported by this dissector.");
}

void
proto_reg_handoff_hci_usb(void)
{
    bthci_cmd_handle = find_dissector("bthci_cmd");
    bthci_evt_handle = find_dissector("bthci_evt");
    bthci_acl_handle = find_dissector("bthci_acl");
    bthci_sco_handle = find_dissector("bthci_sco");

    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x21e8, hci_usb_handle);
    dissector_add_uint("usb.product", (0x1131 << 16) | 0x1001, hci_usb_handle);
    dissector_add_uint("usb.product", (0x050d << 16) | 0x0081, hci_usb_handle);
    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x2198, hci_usb_handle);
    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x21e8, hci_usb_handle);
    dissector_add_uint("usb.product", (0x04bf << 16) | 0x0320, hci_usb_handle);
    dissector_add_uint("usb.product", (0x13d3 << 16) | 0x3375, hci_usb_handle);

    dissector_add_uint("usb.protocol", 0xE00101, hci_usb_handle);
    dissector_add_uint("usb.protocol", 0xE00104, hci_usb_handle);

    dissector_add_for_decode_as("usb.device", hci_usb_handle);
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
