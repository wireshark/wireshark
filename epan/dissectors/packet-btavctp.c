/* packet-btavctp.c
 * Routines for Bluetooth AVCTP dissection
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
#include <epan/expert.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>

#include "packet-bluetooth.h"
#include "packet-btl2cap.h"
#include "packet-btsdp.h"
#include "packet-btavctp.h"

#define PACKET_TYPE_SINGLE    0x00
#define PACKET_TYPE_START     0x01
#define PACKET_TYPE_CONTINUE  0x02
#define PACKET_TYPE_END       0x03

int proto_btavctp = -1;

static int hf_btavctp_transaction               = -1;
static int hf_btavctp_packet_type               = -1;
static int hf_btavctp_cr                        = -1;
static int hf_btavctp_ipid                      = -1;
static int hf_btavctp_rfa                       = -1;
static int hf_btavctp_pid                       = -1;
static int hf_btavctp_number_of_packets         = -1;

static gint ett_btavctp             = -1;

static expert_field ei_btavctp_unexpected_frame = EI_INIT;
static expert_field ei_btavctp_invalid_profile = EI_INIT;

static dissector_handle_t btavctp_handle;

typedef struct _fragment_t {
    guint   length;
    guint8  *data;
} fragment_t;

typedef struct _fragments_t {
    guint32      interface_id;
    guint32      adapter_id;
    guint32      chandle;
    guint32      psm;
    guint32      count;
    guint32      number_of_packets;
    guint32      pid;
    wmem_tree_t  *fragment;
} fragments_t;

static wmem_tree_t *reassembling = NULL;
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

void proto_register_btavctp(void);
void proto_reg_handoff_btavctp(void);

static gint
dissect_btavctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item      *ti;
    proto_tree      *btavctp_tree;
    proto_item      *pitem;
    proto_item      *ipid_item = NULL;
    btavctp_data_t  *avctp_data;
    tvbuff_t        *next_tvb;
    gint            offset = 0;
    guint           packet_type;
    guint           cr;
    guint           pid = 0;
    guint           transaction;
    guint           number_of_packets = 0;
    guint           length;
    guint           i_frame;
    gboolean        ipid = FALSE;
    guint32         interface_id;
    guint32         adapter_id;
    guint32         chandle;
    guint32         psm;
    gint            previous_proto;

    previous_proto = (GPOINTER_TO_INT(wmem_list_frame_data(wmem_list_frame_prev(wmem_list_tail(pinfo->layers)))));
    if (previous_proto == proto_btl2cap) {
        btl2cap_data_t  *l2cap_data;

        l2cap_data = (btl2cap_data_t *) data;

        interface_id = l2cap_data->interface_id;
        adapter_id   = l2cap_data->adapter_id;
        chandle      = l2cap_data->chandle;
        psm          = l2cap_data->psm;
    } else {
        interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = HCI_ADAPTER_DEFAULT;
        chandle      = 0;
        psm          = 0;
    }

    ti = proto_tree_add_item(tree, proto_btavctp, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
    btavctp_tree = proto_item_add_subtree(ti, ett_btavctp);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AVCTP");
    col_clear(pinfo->cinfo, COL_INFO);

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

    proto_tree_add_item(btavctp_tree, hf_btavctp_transaction,  tvb, offset, 1, ENC_BIG_ENDIAN);
    pitem = proto_tree_add_item(btavctp_tree, hf_btavctp_packet_type,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(btavctp_tree, hf_btavctp_cr,  tvb, offset, 1, ENC_BIG_ENDIAN);
    transaction = tvb_get_guint8(tvb, offset) >> 4;
    packet_type = (tvb_get_guint8(tvb, offset) & 0x0C) >> 2;
    cr = (tvb_get_guint8(tvb, offset) & 0x02) >> 1 ;

    if (packet_type == PACKET_TYPE_SINGLE || packet_type == PACKET_TYPE_START) {
        ipid_item = proto_tree_add_item(btavctp_tree, hf_btavctp_ipid,  tvb, offset, 1, ENC_BIG_ENDIAN);
        ipid = tvb_get_guint8(tvb, offset) & 0x01;
    } else {
        proto_tree_add_item(btavctp_tree, hf_btavctp_rfa,  tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset++;

    if (packet_type == PACKET_TYPE_START) {
        proto_tree_add_item(btavctp_tree, hf_btavctp_number_of_packets,  tvb, offset, 1, ENC_BIG_ENDIAN);
        number_of_packets = tvb_get_guint8(tvb, offset);
        offset++;
    }

    if (packet_type == PACKET_TYPE_SINGLE || packet_type == PACKET_TYPE_START) {
        proto_tree_add_item(btavctp_tree, hf_btavctp_pid,  tvb, offset, 2, ENC_BIG_ENDIAN);
        pid = tvb_get_ntohs(tvb, offset);

        if (p_get_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID ) == NULL) {
            guint8 *value_data;
            bluetooth_uuid_t  uuid;

            uuid.size = 2;
            uuid.bt_uuid = pid;
            uuid.data[0] = pid >> 8;
            uuid.data[1] = pid & 0xFF;

            value_data = wmem_strdup(wmem_file_scope(), print_numeric_uuid(&uuid));

            p_add_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID, value_data);
        }
        offset +=2;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s - Transaction: %u, PacketType: %s",
            val_to_str_const(cr, cr_vals, "unknown CR"), transaction,
            val_to_str_const(packet_type, packet_type_vals, "unknown packet type"));

    if (ipid) {
        expert_add_info(pinfo, ipid_item, &ei_btavctp_invalid_profile);
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid profile");
        if (tvb_captured_length_remaining(tvb, offset) == 0)
            return offset;
    }

    avctp_data = wmem_new(wmem_packet_scope(), btavctp_data_t);
    avctp_data->cr           = cr;
    avctp_data->interface_id = interface_id;
    avctp_data->adapter_id   = adapter_id;
    avctp_data->chandle      = chandle;
    avctp_data->psm          = psm;

    length = tvb_reported_length_remaining(tvb, offset);

    /* reassembling */
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    if (packet_type == PACKET_TYPE_SINGLE) {
        bluetooth_uuid_t  uuid;

        uuid.size = 2;
        uuid.bt_uuid = pid;
        uuid.data[0] = pid >> 8;
        uuid.data[1] = pid & 0xFF;

        if (!dissector_try_string(bluetooth_uuid_table, print_numeric_uuid(&uuid), next_tvb, pinfo, tree, avctp_data)) {
            call_data_dissector(next_tvb, pinfo, tree);
        }

    } else {
        fragment_t     *fragment;
        wmem_tree_key_t key[6];
        guint32         frame_number;

        frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &chandle;
        key[3].length = 1;
        key[3].key = &psm;
        key[4].length = 1;
        key[4].key = &frame_number;
        key[5].length = 0;
        key[5].key = NULL;

        if (packet_type == PACKET_TYPE_START) {
            if (!pinfo->fd->flags.visited) {
                fragment = wmem_new(wmem_file_scope(), fragment_t);
                fragment->length = length;
                fragment->data = (guint8 *) wmem_alloc(wmem_file_scope(), fragment->length);
                tvb_memcpy(tvb, fragment->data, offset, fragment->length);

                fragments = wmem_new(wmem_file_scope(), fragments_t);
                fragments->number_of_packets = number_of_packets;
                fragments->pid = pid;

                fragments->count = 1;
                fragments->fragment = wmem_tree_new(wmem_file_scope());
                wmem_tree_insert32(fragments->fragment, fragments->count, fragment);

                fragments->interface_id = interface_id;
                fragments->adapter_id   = adapter_id;
                fragments->chandle      = chandle;
                fragments->psm          = psm;

                wmem_tree_insert32_array(reassembling, key, fragments);

            } else {
                fragments = (fragments_t *)wmem_tree_lookup32_array_le(reassembling, key);
                if (!(fragments && fragments->interface_id == interface_id &&
                        fragments->adapter_id == adapter_id &&
                        fragments->chandle == chandle &&
                        fragments->psm == psm))
                    fragments = NULL;
            }

            call_data_dissector(next_tvb, pinfo, tree);

        } else if (packet_type == PACKET_TYPE_CONTINUE) {
            fragments = (fragments_t *)wmem_tree_lookup32_array_le(reassembling, key);
            if (!(fragments && fragments->interface_id == interface_id &&
                    fragments->adapter_id == adapter_id &&
                    fragments->chandle == chandle &&
                    fragments->psm == psm))
                fragments = NULL;

            if (!pinfo->fd->flags.visited && fragments != NULL) {
                fragment = wmem_new(wmem_file_scope(), fragment_t);
                fragment->length = length;
                fragment->data = (guint8 *) wmem_alloc(wmem_file_scope(), fragment->length);
                tvb_memcpy(tvb, fragment->data, offset, fragment->length);

                fragments->count++;
                wmem_tree_insert32(fragments->fragment, fragments->count, fragment);

                fragments->interface_id = interface_id;
                fragments->adapter_id   = adapter_id;
                fragments->chandle      = chandle;
                fragments->psm          = psm;

                frame_number = pinfo->num;

                key[0].length = 1;
                key[0].key = &interface_id;
                key[1].length = 1;
                key[1].key = &adapter_id;
                key[2].length = 1;
                key[2].key = &chandle;
                key[3].length = 1;
                key[3].key = &psm;
                key[4].length = 1;
                key[4].key = &frame_number;
                key[5].length = 0;
                key[5].key = NULL;

                wmem_tree_insert32_array(reassembling, key, fragments);
            }

            call_data_dissector(next_tvb, pinfo, tree);

        } else if (packet_type == PACKET_TYPE_END) {
            guint    i_length = 0;

            fragments = (fragments_t *)wmem_tree_lookup32_array_le(reassembling, key);
            if (!(fragments && fragments->interface_id == interface_id &&
                    fragments->adapter_id == adapter_id &&
                    fragments->chandle == chandle &&
                    fragments->psm == psm))
                fragments = NULL;

            if (!pinfo->fd->flags.visited && fragments != NULL) {
                fragment = wmem_new(wmem_file_scope(), fragment_t);
                fragment->length = length;
                fragment->data = (guint8 *) wmem_alloc(wmem_file_scope(), fragment->length);
                tvb_memcpy(tvb, fragment->data, offset, fragment->length);

                fragments->count++;
                wmem_tree_insert32(fragments->fragment, fragments->count, fragment);

                fragments->interface_id = interface_id;
                fragments->adapter_id   = adapter_id;
                fragments->chandle      = chandle;
                fragments->psm          = psm;

                frame_number = pinfo->num;

                key[0].length = 1;
                key[0].key = &interface_id;
                key[1].length = 1;
                key[1].key = &adapter_id;
                key[2].length = 1;
                key[2].key = &chandle;
                key[3].length = 1;
                key[3].key = &psm;
                key[4].length = 1;
                key[4].key = &frame_number;
                key[5].length = 0;
                key[5].key = NULL;

                wmem_tree_insert32_array(reassembling, key, fragments);
            }

            length = 0;
            if (!fragments || fragments->count != fragments->number_of_packets) {
                expert_add_info(pinfo, pitem, &ei_btavctp_unexpected_frame);
                call_data_dissector(next_tvb, pinfo, tree);
            } else {
                guint8   *reassembled;
                bluetooth_uuid_t  uuid;

                for (i_frame = 1; i_frame <= fragments->count; ++i_frame) {
                    fragment = (fragment_t *)wmem_tree_lookup32_le(fragments->fragment, i_frame);
                    length += fragment->length;
                }

                reassembled = (guint8 *) wmem_alloc(pinfo->pool, length);

                for (i_frame = 1; i_frame <= fragments->count; ++i_frame) {
                    fragment = (fragment_t *)wmem_tree_lookup32_le(fragments->fragment, i_frame);
                    memcpy(reassembled + i_length,
                            fragment->data,
                            fragment->length);
                    i_length += fragment->length;
                }

                next_tvb = tvb_new_child_real_data(tvb, reassembled, length, length);
                add_new_data_source(pinfo, next_tvb, "Reassembled AVCTP");

                uuid.size = 2;
                uuid.bt_uuid = fragments->pid;
                uuid.data[0] = fragments->pid >> 8;
                uuid.data[1] = fragments->pid & 0xFF;

                if (!dissector_try_string(bluetooth_uuid_table, print_numeric_uuid(&uuid), next_tvb, pinfo, tree, avctp_data)) {
                    call_data_dissector(next_tvb, pinfo, tree);
                }
            }

            fragments = NULL;
        } else {
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }

    return offset;
}

void
proto_register_btavctp(void)
{
    module_t *module;
    expert_module_t* expert_btavctp;

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
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0x00,
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

    static ei_register_info ei[] = {
        { &ei_btavctp_unexpected_frame, { "btavctp.unexpected_frame", PI_PROTOCOL, PI_WARN, "Unexpected frame", EXPFILL }},
        { &ei_btavctp_invalid_profile,  { "btavctp.invalid_profile",  PI_PROTOCOL, PI_NOTE, "Invalid Profile", EXPFILL }},
    };

    /* Decode As handling */
    reassembling = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_btavctp = proto_register_protocol("Bluetooth AVCTP Protocol", "BT AVCTP", "btavctp");
    btavctp_handle = register_dissector("btavctp", dissect_btavctp, proto_btavctp);

    proto_register_field_array(proto_btavctp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_btavctp = expert_register_protocol(proto_btavctp);
    expert_register_field_array(expert_btavctp, ei, array_length(ei));

    module = prefs_register_protocol(proto_btavctp, NULL);
    prefs_register_static_text_preference(module, "avctp.version",
            "Bluetooth Protocol AVCTP version: 1.4",
            "Version of protocol supported by this dissector.");
}


void
proto_reg_handoff_btavctp(void)
{
    dissector_add_string("bluetooth.uuid", "17", btavctp_handle);

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_AVCTP_CTRL, btavctp_handle);
    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_AVCTP_BRWS, btavctp_handle);

    dissector_add_for_decode_as("btl2cap.cid", btavctp_handle);
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
