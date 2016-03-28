/* packet-bthci_sco.c
 * Routines for the Bluetooth SCO dissection
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
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
#include <epan/addr_resolv.h>

#include "packet-bluetooth.h"
#include "packet-bthci_sco.h"

/* Initialize the protocol and registered fields */
static int proto_bthci_sco = -1;
static int hf_bthci_sco_reserved = -1;
static int hf_bthci_sco_packet_status = -1;
static int hf_bthci_sco_chandle = -1;
static int hf_bthci_sco_length = -1;
static int hf_bthci_sco_data = -1;

static int hf_bthci_sco_connect_in = -1;
static int hf_bthci_sco_disconnect_in = -1;
static int hf_bthci_sco_stream_number = -1;

/* Initialize the subtree pointers */
static gint ett_bthci_sco = -1;

wmem_tree_t *bthci_sco_stream_numbers = NULL;

static dissector_handle_t bthci_sco_handle;

static const value_string packet_status_vals[] = {
    { 0x00,   "Correctly Received Data"},
    { 0x01,   "Possibly Invalid Data"},
    { 0x02,   "No Data Received"},
    { 0x03,   "Data Partially Lost"},
    {0x0, NULL}
};

void proto_register_bthci_sco(void);
void proto_reg_handoff_bthci_sco(void);

/* Code to actually dissect the packets */
static gint
dissect_bthci_sco(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item               *ti;
    proto_tree               *bthci_sco_tree;
    gint                      offset = 0;
    guint16                   flags;
    bluetooth_data_t         *bluetooth_data;
    wmem_tree_key_t           key[6];
    guint32                   k_connection_handle;
    guint32                   k_frame_number;
    guint32                   k_interface_id;
    guint32                   k_adapter_id;
    remote_bdaddr_t          *remote_bdaddr;
    const gchar              *localhost_name;
    guint8                    localhost_bdaddr[6];
    const gchar              *localhost_ether_addr;
    gchar                    *localhost_addr_name;
    gint                      localhost_length;
    localhost_bdaddr_entry_t *localhost_bdaddr_entry;
    localhost_name_entry_t   *localhost_name_entry;
    chandle_session_t        *chandle_session;
    wmem_tree_t              *subtree;
    proto_item               *sub_item;
    bthci_sco_stream_number_t  *sco_stream_number;

    ti = proto_tree_add_item(tree, proto_bthci_sco, tvb, offset, tvb_captured_length(tvb), ENC_NA);
    bthci_sco_tree = proto_item_add_subtree(ti, ett_bthci_sco);

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_add_fstr(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            break;
    }

    proto_tree_add_item(bthci_sco_tree, hf_bthci_sco_reserved, tvb,      offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_sco_tree, hf_bthci_sco_packet_status, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_sco_tree, hf_bthci_sco_chandle, tvb,       offset, 2, ENC_LITTLE_ENDIAN);
    flags   = tvb_get_letohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(bthci_sco_tree, hf_bthci_sco_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    bluetooth_data = (bluetooth_data_t *) data;
    DISSECTOR_ASSERT(bluetooth_data);

    k_interface_id      = bluetooth_data->interface_id;
    k_adapter_id        = bluetooth_data->adapter_id;
    k_connection_handle = flags & 0x0fff;
    k_frame_number      = pinfo->num;

    key[0].length = 1;
    key[0].key    = &k_interface_id;
    key[1].length = 1;
    key[1].key    = &k_adapter_id;
    key[2].length = 0;
    key[2].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(bthci_sco_stream_numbers, key);
    sco_stream_number = (subtree) ? (bthci_sco_stream_number_t *) wmem_tree_lookup32_le(subtree, pinfo->num) : NULL;

    key[2].length = 1;
    key[2].key    = &k_connection_handle;
    key[3].length = 0;
    key[3].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(bluetooth_data->chandle_sessions, key);
    chandle_session = (subtree) ? (chandle_session_t *) wmem_tree_lookup32_le(subtree, pinfo->num) : NULL;
    if (!(chandle_session &&
            chandle_session->connect_in_frame < pinfo->num &&
            chandle_session->disconnect_in_frame > pinfo->num)){
        chandle_session = NULL;
    }

    key[3].length = 1;
    key[3].key    = &k_frame_number;
    key[4].length = 0;
    key[4].key    = NULL;

    /* remote bdaddr and name */
    remote_bdaddr = (remote_bdaddr_t *)wmem_tree_lookup32_array_le(bluetooth_data->chandle_to_bdaddr, key);
    if (remote_bdaddr && remote_bdaddr->interface_id == bluetooth_data->interface_id &&
            remote_bdaddr->adapter_id == bluetooth_data->adapter_id &&
            remote_bdaddr->chandle == (flags & 0x0fff)) {
        guint32         k_bd_addr_oui;
        guint32         k_bd_addr_id;
        guint32         bd_addr_oui;
        guint32         bd_addr_id;
        device_name_t  *device_name;
        const gchar    *remote_name;
        const gchar    *remote_ether_addr;
        gchar          *remote_addr_name;
        gint            remote_length;

        bd_addr_oui = remote_bdaddr->bd_addr[0] << 16 | remote_bdaddr->bd_addr[1] << 8 | remote_bdaddr->bd_addr[2];
        bd_addr_id  = remote_bdaddr->bd_addr[3] << 16 | remote_bdaddr->bd_addr[4] << 8 | remote_bdaddr->bd_addr[5];

        k_bd_addr_oui  = bd_addr_oui;
        k_bd_addr_id   = bd_addr_id;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_bd_addr_id;
        key[3].length = 1;
        key[3].key    = &k_bd_addr_oui;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        device_name = (device_name_t *)wmem_tree_lookup32_array_le(bluetooth_data->bdaddr_to_name, key);
        if (device_name && device_name->bd_addr_oui == bd_addr_oui && device_name->bd_addr_id == bd_addr_id)
            remote_name = device_name->name;
        else
            remote_name = "";

        remote_ether_addr = get_ether_name(remote_bdaddr->bd_addr);
        remote_length = (gint)(strlen(remote_ether_addr) + 3 + strlen(remote_name) + 1);
        remote_addr_name = (gchar *)wmem_alloc(pinfo->pool, remote_length);

        g_snprintf(remote_addr_name, remote_length, "%s (%s)", remote_ether_addr, remote_name);

        if (pinfo->p2p_dir == P2P_DIR_RECV) {
            set_address(&pinfo->net_src, AT_STRINGZ, (int)strlen(remote_name) + 1, remote_name);
            set_address(&pinfo->dl_src, AT_ETHER, 6, remote_bdaddr->bd_addr);
            set_address(&pinfo->src, AT_STRINGZ, (int)strlen(remote_addr_name) + 1, remote_addr_name);
        } else if (pinfo->p2p_dir == P2P_DIR_SENT) {
            set_address(&pinfo->net_dst, AT_STRINGZ, (int)strlen(remote_name) + 1, remote_name);
            set_address(&pinfo->dl_dst, AT_ETHER, 6, remote_bdaddr->bd_addr);
            set_address(&pinfo->dst, AT_STRINGZ, (int)strlen(remote_addr_name) + 1, remote_addr_name);
        }
    } else {
        if (pinfo->p2p_dir == P2P_DIR_RECV) {
            set_address(&pinfo->net_src, AT_STRINGZ, 1, "");
            set_address(&pinfo->dl_src, AT_STRINGZ, 1, "");
            set_address(&pinfo->src, AT_STRINGZ, 10, "remote ()");
        } else if (pinfo->p2p_dir == P2P_DIR_SENT) {
            set_address(&pinfo->net_dst, AT_STRINGZ, 1, "");
            set_address(&pinfo->dl_dst, AT_STRINGZ, 1, "");
            set_address(&pinfo->dst, AT_STRINGZ, 10, "remote ()");
        }
    }

    k_interface_id      = bluetooth_data->interface_id;
    k_adapter_id        = bluetooth_data->adapter_id;
    k_frame_number      = pinfo->num;

    /* localhost bdaddr and name */
    key[0].length = 1;
    key[0].key    = &k_interface_id;
    key[1].length = 1;
    key[1].key    = &k_adapter_id;
    key[2].length = 1;
    key[2].key    = &k_frame_number;
    key[3].length = 0;
    key[3].key    = NULL;


    localhost_bdaddr_entry = (localhost_bdaddr_entry_t *)wmem_tree_lookup32_array_le(bluetooth_data->localhost_bdaddr, key);
    if (localhost_bdaddr_entry && localhost_bdaddr_entry->interface_id == bluetooth_data->interface_id &&
        localhost_bdaddr_entry->adapter_id == bluetooth_data->adapter_id) {

        localhost_ether_addr = get_ether_name(localhost_bdaddr_entry->bd_addr);
        memcpy(localhost_bdaddr, localhost_bdaddr_entry->bd_addr, 6);
    } else {
        localhost_ether_addr = "localhost";
        /* XXX - is this the right value to use? */
        memset(localhost_bdaddr, 0, 6);
    }

    localhost_name_entry = (localhost_name_entry_t *)wmem_tree_lookup32_array_le(bluetooth_data->localhost_name, key);
    if (localhost_name_entry && localhost_name_entry->interface_id == bluetooth_data->interface_id &&
            localhost_name_entry->adapter_id == bluetooth_data->adapter_id)
        localhost_name = localhost_name_entry->name;
    else
        localhost_name = "";

    localhost_length = (gint)(strlen(localhost_ether_addr) + 3 + strlen(localhost_name) + 1);
    localhost_addr_name = (gchar *)wmem_alloc(pinfo->pool, localhost_length);

    g_snprintf(localhost_addr_name, localhost_length, "%s (%s)", localhost_ether_addr, localhost_name);

    if (pinfo->p2p_dir == P2P_DIR_RECV) {
        set_address(&pinfo->net_dst, AT_STRINGZ, (int)strlen(localhost_name) + 1, localhost_name);
        set_address(&pinfo->dl_dst, AT_ETHER, 6, localhost_bdaddr);
        set_address(&pinfo->dst, AT_STRINGZ, (int)strlen(localhost_addr_name) + 1, localhost_addr_name);
    } else if (pinfo->p2p_dir == P2P_DIR_SENT) {
        set_address(&pinfo->net_src, AT_STRINGZ, (int)strlen(localhost_name) + 1, localhost_name);
        set_address(&pinfo->dl_src, AT_ETHER, 6, localhost_bdaddr);
        set_address(&pinfo->src, AT_STRINGZ, (int)strlen(localhost_addr_name) + 1, localhost_addr_name);
    }

    proto_tree_add_item(bthci_sco_tree, hf_bthci_sco_data, tvb, offset, tvb_reported_length(tvb), ENC_NA);

    if (chandle_session) {
        sub_item = proto_tree_add_uint(bthci_sco_tree, hf_bthci_sco_connect_in, tvb, 0, 0, chandle_session->connect_in_frame);
        PROTO_ITEM_SET_GENERATED(sub_item);

        if (chandle_session->disconnect_in_frame < G_MAXUINT32) {
            sub_item = proto_tree_add_uint(bthci_sco_tree, hf_bthci_sco_disconnect_in, tvb, 0, 0, chandle_session->disconnect_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }
    }
    if (sco_stream_number) {
        sub_item = proto_tree_add_uint(bthci_sco_tree, hf_bthci_sco_stream_number, tvb, 0, 0, sco_stream_number->stream_number);
        PROTO_ITEM_SET_GENERATED(sub_item);
    }

    return tvb_reported_length(tvb);
}


void
proto_register_bthci_sco(void)
{
    static hf_register_info hf[] = {
        { &hf_bthci_sco_reserved,
            { "Reserved",                    "bthci_sco.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xC000,
            NULL, HFILL }
        },
        { &hf_bthci_sco_packet_status,
            { "Packet Status",               "bthci_sco.packet_status",
            FT_UINT16, BASE_HEX, VALS(packet_status_vals), 0x3000,
            NULL, HFILL }
        },
        { &hf_bthci_sco_chandle,
            { "Connection Handle",           "bthci_sco.chandle",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_bthci_sco_connect_in,
            { "Connect in frame",            "bthci_sco.connect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_sco_disconnect_in,
            { "Disconnect in frame",         "bthci_sco.disconnect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_sco_stream_number,
            { "Stream Number",               "bthci_sco.stream_number",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_sco_length,
            { "Data Total Length",           "bthci_sco.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_sco_data,
            { "Data",                        "bthci_sco.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
      &ett_bthci_sco
    };

    /* Register the protocol name and description */
    proto_bthci_sco = proto_register_protocol("Bluetooth HCI SCO Packet", "HCI_SCO", "bthci_sco");
    bthci_sco_handle = register_dissector("bthci_sco", dissect_bthci_sco, proto_bthci_sco);

    bthci_sco_stream_numbers = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bthci_sco, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_bthci_sco(void)
{
    dissector_add_uint("hci_h4.type", HCI_H4_TYPE_SCO, bthci_sco_handle);
    dissector_add_uint("hci_h1.type", BTHCI_CHANNEL_SCO, bthci_sco_handle);
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
