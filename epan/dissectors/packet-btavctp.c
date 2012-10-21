/* packet-btavctp.c
 * Routines for Bluetooth AVCTP dissection
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
 *
 * $Id$
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

#include "packet-btl2cap.h"
#include "packet-btsdp.h"
#include "packet-btavctp.h"

#define PACKET_TYPE_SINGLE    0x00
#define PACKET_TYPE_START     0x01
#define PACKET_TYPE_CONTINUE  0x02
#define PACKET_TYPE_END       0x03

static int proto_btavctp                        = -1;

static int hf_btavctp_transaction               = -1;
static int hf_btavctp_packet_type               = -1;
static int hf_btavctp_cr                        = -1;
static int hf_btavctp_ipid                      = -1;
static int hf_btavctp_rfa                       = -1;
static int hf_btavctp_pid                       = -1;
static int hf_btavctp_number_of_packets         = -1;

static gint ett_btavctp             = -1;

static dissector_handle_t btavrcp_handle = NULL;
static dissector_handle_t data_handle    = NULL;

typedef struct _fragment_t {
    guint   length;
    guint8  *data;
} fragment_t;

typedef struct _fragments_t {
    guint32      count;
    guint32      number_of_packets;
    guint32      pid;
    emem_tree_t  *fragment;
} fragments_t;

static emem_tree_t *reassembling = NULL;
static fragments_t *fragments    = NULL;

static const value_string packet_type_vals[] = {
    { PACKET_TYPE_SINGLE,   "Single" },
    { PACKET_TYPE_START,    "Start" },
    { PACKET_TYPE_CONTINUE, "Continue" },
    { PACKET_TYPE_END,      "End" },
    { 0, NULL }
};

static const value_string cr_vals[] = {
    { 0x00,   "Command" },
    { 0x01,   "Response" },
    { 0, NULL }
};

static const value_string ipid_vals[] = {
    { 0x00,   "Profile OK" },
    { 0x01,   "Invalid profile" },
    { 0, NULL }
};


static void
dissect_btavctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item      *ti;
    proto_tree      *btavctp_tree;
    proto_item      *pitem;
    btavctp_data_t  *avctp_data;
    btl2cap_data_t  *l2cap_data;
    tvbuff_t        *next_tvb;
    gint            offset = 0;
    guint           packet_type;
    guint           cr;
    guint           pid = 0;
    guint           transaction;
    guint           number_of_packets = 0;
    guint           length;
    guint           i_frame;
    fragment_t      *fragment;
    void            *save_private_data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AVCTP");
    col_clear(pinfo->cinfo, COL_INFO);

    l2cap_data = (btl2cap_data_t *) pinfo->private_data;

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_add_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_add_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        col_clear(pinfo->cinfo, COL_INFO);
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    ti = proto_tree_add_item(tree, proto_btavctp, tvb, offset, -1, ENC_NA);

    btavctp_tree = proto_item_add_subtree(ti, ett_btavctp);

    proto_tree_add_item(btavctp_tree, hf_btavctp_transaction,  tvb, offset, 1, ENC_BIG_ENDIAN);
    pitem = proto_tree_add_item(btavctp_tree, hf_btavctp_packet_type,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(btavctp_tree, hf_btavctp_cr,  tvb, offset, 1, ENC_BIG_ENDIAN);
    transaction = tvb_get_guint8(tvb, offset) >> 4;
    packet_type = (tvb_get_guint8(tvb, offset) & 0x0C) >> 2;
    cr = (tvb_get_guint8(tvb, offset) & 0x02) >> 1 ;

    if (packet_type == PACKET_TYPE_SINGLE || packet_type == PACKET_TYPE_START)
        proto_tree_add_item(btavctp_tree, hf_btavctp_ipid,  tvb, offset, 1, ENC_BIG_ENDIAN);
    else
        proto_tree_add_item(btavctp_tree, hf_btavctp_rfa,  tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (packet_type == PACKET_TYPE_START) {
        proto_tree_add_item(btavctp_tree, hf_btavctp_number_of_packets,  tvb, offset, 1, ENC_BIG_ENDIAN);
        number_of_packets = tvb_get_guint8(tvb, offset);
        offset++;
    }

    if (packet_type == PACKET_TYPE_SINGLE || packet_type == PACKET_TYPE_START) {
        proto_tree_add_item(btavctp_tree, hf_btavctp_pid,  tvb, offset, 2, ENC_BIG_ENDIAN);
        pid = tvb_get_ntohs(tvb, offset);
        offset +=2;
    }

    avctp_data = ep_alloc(sizeof(btavctp_data_t));
    avctp_data->cr = cr;
    avctp_data->psm = l2cap_data->psm;

    save_private_data = pinfo->private_data;
    pinfo->private_data = avctp_data;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s - Transaction: %u, PacketType: %s",
            val_to_str_const(cr, cr_vals, "unknown CR"), transaction,
            val_to_str_const(packet_type, packet_type_vals, "unknown packet type"));

    length = tvb_ensure_length_remaining(tvb, offset);

    /* reassembling */
    next_tvb = tvb_new_subset(tvb, offset, length, length);
    if (packet_type == PACKET_TYPE_SINGLE) {
        if (pid == BTSDP_AVRCP_SERVICE_UUID && btavrcp_handle != NULL)
            call_dissector(btavrcp_handle, next_tvb, pinfo, tree);
        else
            call_dissector(data_handle, next_tvb, pinfo, tree);
    } else {
        if (packet_type == PACKET_TYPE_START) {
            if(!pinfo->fd->flags.visited){
                fragment = se_alloc(sizeof(fragment_t));
                fragment->length = length;
                fragment->data = se_alloc(fragment->length);
                tvb_memcpy(tvb, fragment->data, offset, fragment->length);

                fragments = se_alloc(sizeof(fragments_t));
                fragments->number_of_packets = number_of_packets;
                fragments->pid = pid;

                fragments->count = 1;
                fragments->fragment = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "btavctp fragments");
                se_tree_insert32(fragments->fragment, fragments->count, fragment);

                se_tree_insert32(reassembling, pinfo->fd->num, fragments);

            } else {
                    fragments = se_tree_lookup32_le(reassembling, pinfo->fd->num);
            }

            call_dissector(data_handle, next_tvb, pinfo, tree);

        } else if (packet_type == PACKET_TYPE_CONTINUE) {
            if(!pinfo->fd->flags.visited) {
                if (fragments != NULL) {
                    fragment = se_alloc(sizeof(fragment_t));
                    fragment->length = length;
                    fragment->data = se_alloc(fragment->length);
                    tvb_memcpy(tvb, fragment->data, offset, fragment->length);

                    fragments->count++;
                    se_tree_insert32(fragments->fragment, fragments->count, fragment);

                    se_tree_insert32(reassembling, pinfo->fd->num, fragments);
                }
            } else {
                    fragments = se_tree_lookup32_le(reassembling, pinfo->fd->num);
            }

            call_dissector(data_handle, next_tvb, pinfo, tree);

        } else if (packet_type == PACKET_TYPE_END) {
            guint    i_length = 0;
            guint8   *reassembled;

            if(!pinfo->fd->flags.visited){

                if (fragments != NULL) {
                    fragment = se_alloc(sizeof(fragment_t));
                    fragment->length = length;
                    fragment->data = se_alloc(fragment->length);
                    tvb_memcpy(tvb, fragment->data, offset, fragment->length);

                    fragments->count++;
                    se_tree_insert32(fragments->fragment, fragments->count, fragment);

                    se_tree_insert32(reassembling, pinfo->fd->num, fragments);
                }
            } else {
                fragments = se_tree_lookup32_le(reassembling, pinfo->fd->num);
            }

            length = 0;
            if (!fragments || fragments->count != fragments->number_of_packets) {
                expert_add_info_format(pinfo, pitem, PI_PROTOCOL, PI_WARN,
                    "Unexpected frame");
                call_dissector(data_handle, next_tvb, pinfo, tree);
            } else {
                for (i_frame = 1; i_frame <= fragments->count; ++i_frame) {
                    fragment = se_tree_lookup32_le(fragments->fragment, i_frame);
                    length += fragment->length;
                }

                reassembled = se_alloc(length);

                for (i_frame = 1; i_frame <= fragments->count; ++i_frame) {
                    fragment = se_tree_lookup32_le(fragments->fragment, i_frame);
                    memcpy(reassembled + i_length,
                            fragment->data,
                            fragment->length);
                    i_length += fragment->length;
                }

                next_tvb = tvb_new_child_real_data(tvb, reassembled, length, length);
                add_new_data_source(pinfo, next_tvb, "Reassembled AVCTP");

                if (fragments->pid == BTSDP_AVRCP_SERVICE_UUID && btavrcp_handle != NULL) {
                    call_dissector(btavrcp_handle, next_tvb, pinfo, tree);
                } else {
                    call_dissector(data_handle, next_tvb, pinfo, tree);
                }
            }

            fragments = NULL;
        } else {
                call_dissector(data_handle, next_tvb, pinfo, tree);
        }
    }

    pinfo->private_data = save_private_data;
}

void
proto_register_btavctp(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        { &hf_btavctp_transaction,
            { "Transaction",          "btavctp.transaction",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_btavctp_packet_type,
            { "Packet Type",          "btavctp.packet_type",
            FT_UINT8, BASE_HEX, VALS(packet_type_vals), 0x0C,
            NULL, HFILL }
        },
        { &hf_btavctp_cr,
            { "C/R",                  "btavctp.cr",
            FT_UINT8, BASE_HEX, VALS(cr_vals), 0x02,
            NULL, HFILL }
        },
        { &hf_btavctp_ipid,
            { "IPID",                 "btavctp.ipid",
            FT_UINT8, BASE_HEX, VALS(ipid_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_btavctp_rfa,
            { "RFA",                  "btavctp.rfa",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavctp_pid,
            { "Profile Identifier",   "btavctp.pid",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &vs_service_classes_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_btavctp_number_of_packets,
            { "Number of packets",    "btavctp.nop",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_btavctp
    };

    reassembling = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "btavctp reassembling");

    proto_btavctp = proto_register_protocol("Bluetooth AVCTP Protocol", "AVCTP", "btavctp");
    register_dissector("btavctp", dissect_btavctp, proto_btavctp);

    proto_register_field_array(proto_btavctp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module = prefs_register_protocol(proto_btavctp, NULL);
    prefs_register_static_text_preference(module, "avctp.version",
            "Bluetooth Protocol AVCTP version: 1.4",
            "Version of protocol supported by this dissector.");
}


void
proto_reg_handoff_btavctp(void)
{
    dissector_handle_t btavctp_handle;

    btavctp_handle = find_dissector("btavctp");
    btavrcp_handle = find_dissector("btavrcp");
    data_handle    = find_dissector("data");

    dissector_add_uint("btl2cap.service", BTSDP_AVCTP_PROTOCOL_UUID, btavctp_handle);

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_AVCTP_CTRL, btavctp_handle);
    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_AVCTP_BRWS, btavctp_handle);

    dissector_add_handle("btl2cap.cid", btavctp_handle);
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
