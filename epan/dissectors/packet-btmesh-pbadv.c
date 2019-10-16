/* packet-btmesh-pbadv.c
 * Routines for Bluetooth mesh PB-ADV dissection
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
#include <epan/reassemble.h>
#include <epan/expert.h>

#include "packet-btmesh.h"

#define BTMESH_PB_ADV_NOT_USED 0

#define TRANSACTION_START           0x00
#define TRANSACTION_ACKNOWLEDGMENT  0x01
#define TRANSACTION_CONTINUATION    0x02
#define PROVISIONING_BEARER_CONTROL 0x03

#define LINK_OPEN  0x00
#define LINK_ACK   0x01
#define LINK_CLOSE 0x02

void proto_register_btmesh_pbadv(void);
void proto_reg_handoff_btmesh_pbadv(void);

static int proto_btmesh_pbadv = -1;

static dissector_handle_t btmesh_provisioning_handle;

static int hf_btmesh_pbadv_linkid = -1;
static int hf_btmesh_pbadv_trnumber = -1;

static int hf_btmesh_generic_provisioning_control_format = -1;
static int hf_btmesh_gpcf_segn = -1;
static int hf_btmesh_gpcf_total_length = -1;
//TODO - check FCS
static int hf_btmesh_gpcf_fcs = -1;
static int hf_btmesh_gpcf_padding = -1;
static int hf_btmesh_gpcf_segment_index = -1;
static int hf_btmesh_gpcf_bearer_opcode = -1;
static int hf_btmesh_gpcf_bearer_opcode_device_UUID = -1;
static int hf_btmesh_gpcf_bearer_opcode_reason = -1;
static int hf_btmesh_gpcf_bearer_unknown_data = -1;

static int hf_btmesh_gpp_payload = -1;
static int hf_btmesh_gpp_payload_fragment = -1;
static int hf_btmesh_gpp_fragments = -1;
static int hf_btmesh_gpp_fragment = -1;
static int hf_btmesh_gpp_fragment_overlap = -1;
static int hf_btmesh_gpp_fragment_overlap_conflict = -1;
static int hf_btmesh_gpp_fragment_multiple_tails = -1;
static int hf_btmesh_gpp_fragment_too_long_fragment = -1;
static int hf_btmesh_gpp_fragment_error = -1;
static int hf_btmesh_gpp_fragment_count = -1;
static int hf_btmesh_gpp_reassembled_length = -1;

static int ett_btmesh_pbadv = -1;
static int ett_btmesh_generic_provisioning = -1;
static int ett_btmesh_gpp_fragments = -1;
static int ett_btmesh_gpp_fragment = -1;

static expert_field ei_btmesh_gpcf_unknown_opcode = EI_INIT;
static expert_field ei_btmesh_gpcf_unknown_payload = EI_INIT;

static const fragment_items btmesh_gpp_frag_items = {
    &ett_btmesh_gpp_fragments,
    &ett_btmesh_gpp_fragment,

    &hf_btmesh_gpp_fragments,
    &hf_btmesh_gpp_fragment,
    &hf_btmesh_gpp_fragment_overlap,
    &hf_btmesh_gpp_fragment_overlap_conflict,
    &hf_btmesh_gpp_fragment_multiple_tails,
    &hf_btmesh_gpp_fragment_too_long_fragment,
    &hf_btmesh_gpp_fragment_error,
    &hf_btmesh_gpp_fragment_count,
    NULL,
    &hf_btmesh_gpp_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

static const value_string btmesh_generic_provisioning_control_format[] = {
    { 0, "Transaction Start" },
    { 1, "Transaction Acknowledgment" },
    { 2, "Transaction Continuation" },
    { 3, "Provisioning Bearer Control" },
    { 0, NULL }
};

static const value_string btmesh_gpcf_bearer_opcode_format[] = {
    { 0, "Link Open" },
    { 1, "Link ACK" },
    { 2, "Link Close" },
    { 0, NULL }
};

static const value_string btmesh_gpcf_bearer_opcode_reason_format[] = {
    { 0, "Success" },
    { 1, "Timeout" },
    { 2, "Fail" },
    { 0, NULL }
};

/* needed for packet reassembly */
static reassembly_table pbadv_reassembly_table;

typedef struct _pbadv_fragment_key {
    guint32 link_id;
    guint8 transaction_number;
} pbadv_fragment_key;

static guint
pbadv_fragment_hash(gconstpointer k)
{
    const pbadv_fragment_key* key = (const pbadv_fragment_key*) k;
    guint hash_val;

    hash_val = 0;

    hash_val += key->link_id;
    hash_val += key->transaction_number;
    return hash_val;
}

static gint
pbadv_fragment_equal(gconstpointer k1, gconstpointer k2)
{
    const pbadv_fragment_key* key1 = (const pbadv_fragment_key*) k1;
    const pbadv_fragment_key* key2 = (const pbadv_fragment_key*) k2;

    return ((key1->link_id == key2->link_id) && (key1->transaction_number == key2->transaction_number)
            ? TRUE : FALSE);
}

static void *
pbadv_fragment_temporary_key(const packet_info *pinfo _U_, const guint32 id _U_,
                              const void *data)
{
    pbadv_fragment_key *key = g_slice_new(pbadv_fragment_key);
    const pbadv_fragment_key *pbadv = (const pbadv_fragment_key *)data;

    key->link_id = pbadv->link_id;
    key->transaction_number = pbadv->transaction_number;

    return key;
}

static void
pbadv_fragment_free_temporary_key(gpointer ptr)
{
    pbadv_fragment_key *key = (pbadv_fragment_key *)ptr;

    g_slice_free(pbadv_fragment_key, key);
}

static void *
pbadv_fragment_persistent_key(const packet_info *pinfo _U_, const guint32 id _U_,
                              const void *data)
{
    pbadv_fragment_key *key = g_slice_new(pbadv_fragment_key);
    const pbadv_fragment_key *pbadv = (const pbadv_fragment_key *)data;

    key->link_id = pbadv->link_id;
    key->transaction_number = pbadv->transaction_number;

    return key;
}

static void
pbadv_fragment_free_persistent_key(gpointer ptr)
{
    pbadv_fragment_key *key = (pbadv_fragment_key *)ptr;
    if (key) {
        g_slice_free(pbadv_fragment_key, key);
    }
}

static const reassembly_table_functions pbadv_reassembly_table_functions = {
    pbadv_fragment_hash,
    pbadv_fragment_equal,
    pbadv_fragment_temporary_key,
    pbadv_fragment_persistent_key,
    pbadv_fragment_free_temporary_key,
    pbadv_fragment_free_persistent_key
};

static gint
dissect_btmesh_pbadv_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    proto_item *item;
    proto_tree *sub_tree, *sub_tree_generic_provisioning;
    proto_item *ti;
    gboolean defragment = FALSE;
    int offset = 0;
    btle_mesh_transport_ctx_t tr_ctx;
    guint8 segn, length;
    guint32 total_length;
    guint8 gpcf_bearer_opcode;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT Mesh PB-ADV");

    item = proto_tree_add_item(tree, proto_btmesh_pbadv, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_btmesh_pbadv);

    guint32 pbadv_link_id = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_btmesh_pbadv_linkid, tvb, offset, 4, ENC_NA);
    offset += 4;

    guint8 pbadv_trnumber = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(sub_tree, hf_btmesh_pbadv_trnumber, tvb, offset, 1, ENC_NA);
    offset += 1;

    pbadv_fragment_key frg_key;
    frg_key.link_id = pbadv_link_id;
    frg_key.transaction_number = pbadv_trnumber;

    sub_tree_generic_provisioning = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_btmesh_generic_provisioning, &ti, "Generic Provisioning PDU");

    proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_generic_provisioning_control_format, tvb, offset, 1, ENC_NA);
    guint8 gpcf = tvb_get_guint8(tvb, offset) & 0x03;

    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(gpcf, btmesh_generic_provisioning_control_format, "Unknown PDU"));

    fragment_head *fd_head = NULL;
    gint segment_index = -1;

    switch (gpcf) {
        //Transaction Start
        case TRANSACTION_START:
            proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpcf_segn, tvb, offset, 1, ENC_NA);
            segn = (tvb_get_guint8(tvb, offset) & 0xFC) >> 2;
            offset += 1;
            total_length = (guint32)tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpcf_total_length, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpcf_fcs, tvb, offset, 1, ENC_NA);
            offset += 1;
            segment_index = 0;
            defragment = TRUE;
            if (segn == 0) {
                if (btmesh_provisioning_handle) {
                    length = tvb_reported_length(tvb);
                    tr_ctx.transport = E_BTMESH_TR_ADV;
                    tr_ctx.fragmented = FALSE;
                    tr_ctx.segment_index = 0;
                    call_dissector_with_data(btmesh_provisioning_handle, tvb_new_subset_length(tvb, offset, length),
                        pinfo, proto_tree_get_root(sub_tree_generic_provisioning), &tr_ctx);
                } else {
                    proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpp_payload, tvb, offset, -1, ENC_NA);
                }
            } else {
                //Segmentation
                if (!pinfo->fd->visited) {
                    //First fragment can be delivered out of order, and can be the last one.
                    fd_head = fragment_get(&pbadv_reassembly_table, pinfo, BTMESH_PB_ADV_NOT_USED, &frg_key);
                    if (fd_head) {
                        fragment_set_tot_len(&pbadv_reassembly_table, pinfo, BTMESH_PB_ADV_NOT_USED, &frg_key, total_length);
                    }
                    fd_head = fragment_add(&pbadv_reassembly_table,
                        tvb, offset, pinfo,
                        BTMESH_PB_ADV_NOT_USED, &frg_key,
                        0,
                        tvb_captured_length_remaining(tvb, offset),
                        TRUE);
                    if (!fd_head) {
                       //Set the length only when not reassembled
                       fragment_set_tot_len(&pbadv_reassembly_table, pinfo, BTMESH_PB_ADV_NOT_USED, &frg_key, total_length);
                    }
                } else {
                    proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpp_payload_fragment, tvb, offset, -1, ENC_NA);
                }
            }

        break;
        //Transaction Acknowledgment
        case TRANSACTION_ACKNOWLEDGMENT:
            proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpcf_padding, tvb, offset, 1, ENC_NA);

        break;
        //Transaction Continuation
        case TRANSACTION_CONTINUATION:
            proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpcf_segment_index, tvb, offset, 1, ENC_NA);
            segment_index = (tvb_get_guint8(tvb, offset) & 0xFC) >> 2;
            defragment = TRUE;
            offset += 1;
            //Segmentation
            if (!pinfo->fd->visited) {
                fragment_add(&pbadv_reassembly_table,
                    tvb, offset, pinfo,
                    BTMESH_PB_ADV_NOT_USED, &frg_key,
                    20 + (segment_index - 1) * 23,
                    tvb_captured_length_remaining(tvb, offset),
                    TRUE);
            } else {
                proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpp_payload_fragment, tvb, offset, -1, ENC_NA);
            }

        break;
        //Provisioning Bearer Control
        case PROVISIONING_BEARER_CONTROL:
            proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpcf_bearer_opcode, tvb, offset, 1, ENC_NA);
            gpcf_bearer_opcode = (tvb_get_guint8(tvb, offset) & 0xFC) >> 2;
            offset += 1;
            switch(gpcf_bearer_opcode) {
                case LINK_OPEN:
                    proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpcf_bearer_opcode_device_UUID, tvb, offset, 16, ENC_NA);
                    offset += 16;

                break;
                case LINK_ACK:
                    //No data in this PDU

                break;
                case LINK_CLOSE:
                    proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpcf_bearer_opcode_reason, tvb, offset, 1, ENC_NA);
                    offset += 1;

                break;
                default:
                    //Unknown data
                    proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpcf_bearer_unknown_data, tvb, offset, -1, ENC_NA);
                    offset += tvb_captured_length_remaining(tvb, offset);
                    proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_gpcf_unknown_opcode, tvb, offset, -1);
                break;
            }
            //There is still some data but all data should be already disssected
            if (tvb_captured_length_remaining(tvb, offset) != 0) {
                proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_gpcf_unknown_payload, tvb, offset, -1);
            }

        break;
    }
    //Second pass
    if (pinfo->fd->visited && defragment ) {
        fd_head = fragment_get(&pbadv_reassembly_table, pinfo, BTMESH_PB_ADV_NOT_USED, &frg_key);
        if (fd_head && (fd_head->flags&FD_DEFRAGMENTED)) {
            tvbuff_t *next_tvb;
            next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Provisioning PDU", fd_head, &btmesh_gpp_frag_items, NULL, sub_tree_generic_provisioning);
            if (next_tvb) {
                col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
                if (btmesh_provisioning_handle) {
                    tr_ctx.transport = E_BTMESH_TR_ADV;
                    tr_ctx.fragmented = TRUE;
                    tr_ctx.segment_index = segment_index;
                    call_dissector_with_data(btmesh_provisioning_handle, next_tvb, pinfo,
                        proto_tree_get_root(sub_tree_generic_provisioning), &tr_ctx);
                } else {
                    proto_tree_add_item(sub_tree_generic_provisioning, hf_btmesh_gpp_payload, next_tvb, 0, -1, ENC_NA);
                }
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO," (Message fragment %u)", segment_index);
            }
        }
    }

    return tvb_reported_length(tvb);
}

static void
pbadv_init_routine(void)
{
    reassembly_table_register(&pbadv_reassembly_table, &pbadv_reassembly_table_functions);
}

void
proto_register_btmesh_pbadv(void)
{
    static hf_register_info hf[] = {
        //PB-ADV
        { &hf_btmesh_pbadv_linkid,
            { "Link ID", "pbadv.linkid",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_pbadv_trnumber,
            { "Transaction Number", "pbadv.trnumber",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        //Generic Provisioning Control
        { &hf_btmesh_generic_provisioning_control_format,
            { "Generic Provisioning Control Format", "pbadv.gen_prov.gpcf",
                FT_UINT8, BASE_DEC, VALS(btmesh_generic_provisioning_control_format), 0x03,
                NULL, HFILL }
        },
        { &hf_btmesh_gpcf_segn,
            { "The last segment number", "pbadv.gen_prov.gpcf.segn",
                FT_UINT8, BASE_DEC, NULL, 0xFC,
                NULL, HFILL }
        },
        { &hf_btmesh_gpcf_total_length,
            { "Total Length", "pbadv.gen_prov.gpcf.total_length",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_gpcf_fcs,
            { "Frame Check Sequence", "pbadv.gen_prov.gpcf.fcs",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_gpcf_padding,
            { "Padding", "pbadv.gen_prov.gpcf.padding",
                FT_UINT8, BASE_DEC, NULL, 0xFC,
                NULL, HFILL }
        },
        { &hf_btmesh_gpcf_segment_index,
            { "Segment number of the transaction", "pbadv.gen_prov.gpcf.segment_index",
                FT_UINT8, BASE_DEC, NULL, 0xFC,
                NULL, HFILL }
        },
        { &hf_btmesh_gpcf_bearer_opcode,
            { "Bearer Opcode", "pbadv.gen_prov.gpcf.bearer_opcode",
                FT_UINT8, BASE_DEC, VALS(btmesh_gpcf_bearer_opcode_format), 0xFC,
                NULL, HFILL }
        },
        { &hf_btmesh_gpcf_bearer_opcode_device_UUID,
            { "Device UUID", "pbadv.gen_prov.gpcf.bearer_opcode.device_uuid",
                FT_GUID, BASE_NONE, NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_btmesh_gpcf_bearer_opcode_reason,
            { "Reason", "pbadv.gen_prov.gpcf.bearer_opcode.reason",
                FT_UINT8, BASE_DEC, VALS(btmesh_gpcf_bearer_opcode_reason_format), 0x00,
                NULL, HFILL }
        },
        { &hf_btmesh_gpcf_bearer_unknown_data,
            { "Unknown Data", "pbadv.gen_prov.gpcf.unknown_data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        //Generic Provisioning Payload
        { &hf_btmesh_gpp_payload,
            { "Generic Provisioning Payload", "pbadv.gen_prov.gpp.payload",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_gpp_payload_fragment,
            { "Generic Provisioning Payload Fragment", "pbadv.gen_prov.gpp.payload.fragment",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        //Generic Provisioning Payload Reassembly
        { &hf_btmesh_gpp_fragments,
            { "Reassembled Generic Provisioning Payload Fragments", "pbadv.gen_prov.gpp.fragments",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Generic Provisioning Payload Fragments", HFILL }
        },
        { &hf_btmesh_gpp_fragment,
            { "Generic Provisioning Payload Fragment", "pbadv.gen_prov.gpp.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_gpp_fragment_overlap,
            { "Fragment overlap", "pbadv.gen_prov.gpp.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_btmesh_gpp_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "pbadv.gen_prov.gpp.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_btmesh_gpp_fragment_multiple_tails,
            { "Multiple tail fragments found", "pbadv.gen_prov.gpp.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_btmesh_gpp_fragment_too_long_fragment,
            { "Fragment too long", "pbadv.gen_prov.gpp.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }
        },
        { &hf_btmesh_gpp_fragment_error,
            { "Defragmentation error", "pbadv.gen_prov.gpp.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_btmesh_gpp_fragment_count,
            { "Fragment count", "pbadv.gen_prov.gpp.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_gpp_reassembled_length,
            { "Reassembled Generic Provisioning Payload length", "pbadv.gen_prov.gpp.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_btmesh_pbadv,
        &ett_btmesh_generic_provisioning,
        &ett_btmesh_gpp_fragments,
        &ett_btmesh_gpp_fragment,
    };

    static ei_register_info ei[] = {
        { &ei_btmesh_gpcf_unknown_opcode,{ "pbadv.gpcf.unknown_opcode", PI_PROTOCOL, PI_WARN, "Unknown Opcode", EXPFILL } },
        { &ei_btmesh_gpcf_unknown_payload,{ "pbadv.gpcf.unknown_payload", PI_PROTOCOL, PI_ERROR, "Unknown Payload", EXPFILL } },
    };

    expert_module_t* expert_btmesh_pbadv;

    proto_btmesh_pbadv = proto_register_protocol("Bluetooth Mesh PB-ADV", "BT Mesh PB-ADV", "pbadv");

    proto_register_field_array(proto_btmesh_pbadv, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_btmesh_pbadv = expert_register_protocol(proto_btmesh_pbadv);
    expert_register_field_array(expert_btmesh_pbadv, ei, array_length(ei));

    prefs_register_protocol_subtree("Bluetooth", proto_btmesh_pbadv, NULL);
    register_dissector("btmesh.pbadv", dissect_btmesh_pbadv_msg, proto_btmesh_pbadv);

    register_init_routine(&pbadv_init_routine);
}

void
proto_reg_handoff_btmesh_pbadv(void)
{
    btmesh_provisioning_handle = find_dissector("btmesh.provisioning");
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
