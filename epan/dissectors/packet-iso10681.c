/* packet-iso10681.c
 * ISO 10681-2 ISO FlexRay TP
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2021-2021 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Also see packet-iso15765.c / packet-iso15765.h
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/decode_as.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

#include "packet-iso10681.h"
#include "packet-flexray.h"

void proto_register_iso10681(void);
void proto_reg_handoff_iso10681(void);

/* StartFrame or StartFrameAck */
#define ISO10681_TYPE_MASK                  0xF0
#define ISO10681_TYPE_START_FRAME           4
#define ISO10681_TYPE_CONSECUTIVE_FRAME_1   5
#define ISO10681_TYPE_CONSECUTIVE_FRAME_2   6
#define ISO10681_TYPE_CONSECUTIVE_FRAME_EOB 7
#define ISO10681_TYPE_FLOW_CONTROL          8
#define ISO10681_TYPE_LAST_FRAME            9

#define ISO10681_TYPE_PART2_MASK            0x0F

#define ISO10681_FLOW_STATUS_CTS            3
#define ISO10681_FLOW_STATUS_ACK_RETRY      4
#define ISO10681_FLOW_STATUS_WAIT           5
#define ISO10681_FLOW_STATUS_ABORT          6
#define ISO10681_FLOW_STATUS_OVERFLOW       7

typedef struct iso10681_identifier {
    guint32  id;
    guint32  seq;
    guint16  frag_id;
    gboolean last;
} iso10681_identifier_t;

typedef struct iso10681_frame {
    guint32  seq;
    guint32  offset;
    guint32  len;
    gboolean error;
    gboolean complete;
    guint16  last_frag_id;
    guint8   frag_id_high[16];
} iso10681_frame_t;

static const value_string iso10681_message_types[] = {
        {ISO10681_TYPE_START_FRAME,           "Start Frame"},
        {ISO10681_TYPE_CONSECUTIVE_FRAME_1,   "Consecutive Frame 1"},
        {ISO10681_TYPE_CONSECUTIVE_FRAME_2,   "Consecutive Frame 2"},
        {ISO10681_TYPE_CONSECUTIVE_FRAME_EOB, "Consecutive Frame EOB"},
        {ISO10681_TYPE_FLOW_CONTROL,          "Flow Control"},
        {ISO10681_TYPE_LAST_FRAME,            "Last Frame"},
        {0, NULL}
};

static const value_string iso10681_flow_status_values[] = {
        {ISO10681_FLOW_STATUS_CTS,            "Continue to Send"},
        {ISO10681_FLOW_STATUS_ACK_RETRY,      "Ack/Retry"},
        {ISO10681_FLOW_STATUS_WAIT,           "Wait"},
        {ISO10681_FLOW_STATUS_ABORT,          "Abort"},
        {ISO10681_FLOW_STATUS_OVERFLOW,       "Overflow"},
        {0, NULL}
};

static const value_string iso10681_start_type2_values[] = {
        {0,      "Unacknowledged"},
        {1,      "Acknowledged"},
        {0, NULL}
};

static const value_string iso10681_fc_bc_scexp_values[] = {
        {0,      "0 cycles"},
        {1,      "1 cycle"},
        {2,      "3 cycles"},
        {3,      "7 cycles"},
        {4,      "15 cycles"},
        {5,      "31 cycles"},
        {6,      "63 cycles"},
        {7,      "127 cycles"},
        {0, NULL}
};

static const value_string iso10681_fc_ack_values[] = {
        {0,      "Acknowledge"},
        {1,      "Retry Request"},
        {0, NULL}
};

static int hf_iso10681_target_address = -1;
static int hf_iso10681_source_address = -1;
static int hf_iso10681_type = -1;
static int hf_iso10681_type2 = -1;
static int hf_iso10681_frame_payload_length = -1;
static int hf_iso10681_message_length = -1;
static int hf_iso10681_sequence_number = -1;
static int hf_iso10681_fc_flow_status = -1;
static int hf_iso10681_fc_bandwidth_control = -1;
static int hf_iso10681_fc_bc_separation_cycle_exp = -1;
static int hf_iso10681_fc_bc_max_num_pdu_per_cycle = -1;
static int hf_iso10681_fc_buffer_size = -1;
static int hf_iso10681_fc_ack = -1;
static int hf_iso10681_fc_byte_position = -1;


static gint ett_iso10681 = -1;
static gint ett_iso10681_bandwidth_control = -1;

static expert_field ei_iso10681_message_type_bad = EI_INIT;

static int proto_iso10681 = -1;
static dissector_handle_t iso10681_handle_flexray = NULL;

static dissector_table_t subdissector_table;

static range_t   *iso10681_flexray_ids = NULL;
static gboolean   iso10681_spread_over_multiple_cycles = TRUE;

static reassembly_table iso10681_reassembly_table;
static wmem_map_t *iso10681_frame_table = NULL;
static wmem_map_t *iso10681_seq_table = NULL;
static guint32     next_seqnum = 0;


static int hf_iso10681_fragments = -1;
static int hf_iso10681_fragment = -1;
static int hf_iso10681_fragment_overlap = -1;
static int hf_iso10681_fragment_overlap_conflicts = -1;
static int hf_iso10681_fragment_multiple_tails = -1;
static int hf_iso10681_fragment_too_long_fragment = -1;
static int hf_iso10681_fragment_error = -1;
static int hf_iso10681_fragment_count = -1;
static int hf_iso10681_reassembled_in = -1;
static int hf_iso10681_reassembled_length = -1;

static gint ett_iso10681_fragment = -1;
static gint ett_iso10681_fragments = -1;

static const fragment_items iso10681_frag_items = {
        /* Fragment subtrees */
        &ett_iso10681_fragment,
        &ett_iso10681_fragments,
        /* Fragment fields */
        &hf_iso10681_fragments,
        &hf_iso10681_fragment,
        &hf_iso10681_fragment_overlap,
        &hf_iso10681_fragment_overlap_conflicts,
        &hf_iso10681_fragment_multiple_tails,
        &hf_iso10681_fragment_too_long_fragment,
        &hf_iso10681_fragment_error,
        &hf_iso10681_fragment_count,
        /* Reassembled in field */
        &hf_iso10681_reassembled_in,
        /* Reassembled length field */
        &hf_iso10681_reassembled_length,
        /* Reassembled data field */
        NULL,
        "ISO10681 fragments"
};

static guint32
iso10681_seqnum(guint32 frame_id, gboolean new_seqnum) {
    guint32   *ret;

    ret = (guint32 *)wmem_map_lookup(iso10681_seq_table, GUINT_TO_POINTER(frame_id));

    if (ret == NULL) {
        ret = wmem_new0(wmem_file_scope(), guint32);
        *ret = next_seqnum++;
        wmem_map_insert(iso10681_seq_table, GUINT_TO_POINTER(frame_id), ret);
    } else {
        if (new_seqnum) {
            (*ret) = next_seqnum++;
        }
    }

    return *ret;
}

static int
dissect_iso10681(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 frame_id, guint32 frame_length _U_) {
    proto_tree *iso10681_tree;
    proto_item *ti;
    proto_item *ti_type;
    guint32     type;
    guint32     offset;

    iso10681_identifier_t* iso10681_info;
    gboolean    fragmented = FALSE;
    guint32     seqnum = 0;

    guint32     data_length = 0;
    guint32     full_len = 0;
    guint32     target_addr = 0;
    guint32     source_addr = 0;

    tvbuff_t*   next_tvb = NULL;
    gboolean    complete = FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO10681");
    col_clear(pinfo->cinfo, COL_INFO);

    iso10681_info = (iso10681_identifier_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_iso10681, 0);

    if (!iso10681_info) {
        iso10681_info = wmem_new0(wmem_file_scope(), iso10681_identifier_t);
        iso10681_info->id = frame_id;
        iso10681_info->last = FALSE;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_iso10681, 0, iso10681_info);
    }

    ti = proto_tree_add_item(tree, proto_iso10681, tvb, 0, -1, ENC_NA);
    iso10681_tree = proto_item_add_subtree(ti, ett_iso10681);

    proto_tree_add_item_ret_uint(iso10681_tree, hf_iso10681_target_address, tvb, 0, 2, ENC_BIG_ENDIAN, &target_addr);
    proto_tree_add_item_ret_uint(iso10681_tree, hf_iso10681_source_address, tvb, 2, 2, ENC_BIG_ENDIAN, &source_addr);
    offset = 4;

    ti_type = proto_tree_add_item_ret_uint(iso10681_tree, hf_iso10681_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(type, iso10681_message_types, "Unknown (0x%02x)"));

    switch (type) {
        case ISO10681_TYPE_START_FRAME: {
            guint32 type2_value;
            proto_tree_add_item_ret_uint(iso10681_tree, hf_iso10681_type2, tvb, offset, 1, ENC_BIG_ENDIAN, &type2_value);
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(type2_value, iso10681_start_type2_values, "Unknown (0x%x)"));

            proto_tree_add_item_ret_uint(iso10681_tree, hf_iso10681_frame_payload_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN, &data_length);
            proto_tree_add_item_ret_uint(iso10681_tree, hf_iso10681_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN, &full_len);
            offset += 4;

            fragmented = TRUE;
            seqnum = 0;

            if (!(pinfo->fd->visited)) {
                iso10681_frame_t *iso10681_frame = wmem_new0(wmem_file_scope(), iso10681_frame_t);
                iso10681_frame->seq = iso10681_info->seq = iso10681_seqnum(frame_id, TRUE);
                iso10681_frame->len = full_len;

                wmem_map_insert(iso10681_frame_table, GUINT_TO_POINTER(iso10681_info->seq), iso10681_frame);
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, " (Segment Length: %d, Total Len: %d)", data_length, full_len);

            break;
        }
        case ISO10681_TYPE_CONSECUTIVE_FRAME_1:
        case ISO10681_TYPE_CONSECUTIVE_FRAME_2:
        case ISO10681_TYPE_CONSECUTIVE_FRAME_EOB: {
            proto_tree_add_item_ret_uint(iso10681_tree, hf_iso10681_sequence_number, tvb, offset, 1, ENC_BIG_ENDIAN, &seqnum);
            proto_tree_add_item_ret_uint(iso10681_tree, hf_iso10681_frame_payload_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN, &data_length);
            offset += 2;

            fragmented = TRUE;

            if (!(pinfo->fd->visited)) {
                iso10681_info->seq = iso10681_seqnum(frame_id, FALSE);
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, " (Segment Length: %d, Sequence Number: %d)", data_length, seqnum);
            break;
        }
        case ISO10681_TYPE_LAST_FRAME: {
            proto_tree_add_item_ret_uint(iso10681_tree, hf_iso10681_frame_payload_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN, &data_length);
            proto_tree_add_item_ret_uint(iso10681_tree, hf_iso10681_message_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN, &full_len);
            offset += 4;

            fragmented = TRUE;

            if (!(pinfo->fd->visited)) {
                iso10681_info->seq = iso10681_seqnum(frame_id, FALSE);
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, " (Segment Length: %d, Total Len: %d)", data_length, full_len);
            break;
        }
        case ISO10681_TYPE_FLOW_CONTROL: {
            guint flow_status = 0;
            proto_tree_add_item_ret_uint(iso10681_tree, hf_iso10681_fc_flow_status, tvb, offset, 1, ENC_BIG_ENDIAN, &flow_status);

            switch (flow_status) {
            case ISO10681_FLOW_STATUS_CTS: {
                static int * const bandwidth_control[] = {
                    &hf_iso10681_fc_bc_max_num_pdu_per_cycle,
                    &hf_iso10681_fc_bc_separation_cycle_exp,
                    NULL
                };

                proto_tree_add_bitmask(iso10681_tree, tvb, offset + 1, hf_iso10681_fc_bandwidth_control, ett_iso10681_bandwidth_control,
                                       bandwidth_control, ENC_BIG_ENDIAN);
                proto_tree_add_item(iso10681_tree, hf_iso10681_fc_buffer_size, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                break;
            }
            case ISO10681_FLOW_STATUS_ACK_RETRY:
                proto_tree_add_item(iso10681_tree, hf_iso10681_fc_ack, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(iso10681_tree, hf_iso10681_fc_byte_position, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                break;
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, " (Flow Status: %s)", val_to_str(flow_status, iso10681_flow_status_values, "unknown (0x%x)"));
            break;
        }
        default:
            expert_add_info_format(pinfo, ti_type, &ei_iso10681_message_type_bad, "Bad Message Type value %u", type);
            return offset;
    }

    /* show data */
    if (data_length > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length, ' '));
    }

    if (fragmented) {
        tvbuff_t *new_tvb = NULL;
        iso10681_frame_t *iso10681_frame;
        guint16 frag_id = seqnum;

        /* Get frame information */
        iso10681_frame = (iso10681_frame_t *)wmem_map_lookup(iso10681_frame_table, GUINT_TO_POINTER(iso10681_info->seq));
        if (iso10681_frame != NULL) {
            if (type == ISO10681_TYPE_LAST_FRAME) {
                frag_id = iso10681_frame->last_frag_id + 1;
            }

            if (!(pinfo->fd->visited)) {
                frag_id += ((iso10681_frame->frag_id_high[frag_id]++) * 16);
                /* Save the frag_id for subsequent dissection */
                iso10681_info->frag_id = frag_id;
            }

            if (!iso10681_frame->error) {
                gboolean       save_fragmented = pinfo->fragmented;
                guint32        len = data_length;
                fragment_head *frag_msg;

                /* Check if it's the last packet */
                if (!(pinfo->fd->visited)) {
                    /* Update the last_frag_id */
                    if (frag_id > iso10681_frame->last_frag_id) {
                        iso10681_frame->last_frag_id = frag_id;
                    }

                    iso10681_frame->offset += len;
                    if (iso10681_frame->offset >= iso10681_frame->len) {
                        iso10681_info->last = TRUE;
                        iso10681_frame->complete = TRUE;
                        len -= (iso10681_frame->offset - iso10681_frame->len);
                    }
                }
                pinfo->fragmented = TRUE;

                /* Add fragment to fragment table */
                frag_msg = fragment_add_seq_check(&iso10681_reassembly_table, tvb, offset, pinfo, iso10681_info->seq, NULL,
                                                  iso10681_info->frag_id, len, !iso10681_info->last);

                new_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Message", frag_msg, &iso10681_frag_items, NULL,
                                                   iso10681_tree);

                if (frag_msg && frag_msg->reassembled_in != pinfo->num) {
                    col_append_frame_number(pinfo, COL_INFO, " [Reassembled in #%u]", frag_msg->reassembled_in);
                }

                pinfo->fragmented = save_fragmented;
            }

            if (new_tvb) {
                /* This is a complete TVB to dissect */
                next_tvb = new_tvb;
                complete = TRUE;
            } else {
                next_tvb = tvb_new_subset_length_caplen(tvb, offset, data_length, data_length);
            }
        }
    }

    if (next_tvb) {
        iso10681_info_t iso10681data;
        iso10681data.id = frame_id;
        iso10681data.len = frame_length;
        iso10681data.target_address = target_addr;
        iso10681data.source_address = source_addr;

        if (!complete || !dissector_try_payload_new(subdissector_table, next_tvb, pinfo, tree, TRUE, &iso10681data)) {
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_iso10681_flexray(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data) {
    DISSECTOR_ASSERT(data);
    flexray_info_t *flexray_info = (flexray_info_t *)data;
    guint32 id = flexray_flexrayinfo_to_flexrayid(flexray_info);

    if (iso10681_spread_over_multiple_cycles) {
        /* masking out the cycle */
        id |= FLEXRAY_ID_CYCLE_MASK;
    }

    return dissect_iso10681(tvb, pinfo, tree, id, tvb_captured_length(tvb));
}

void
proto_register_iso10681(void) {
    module_t *iso10681_module;

    static hf_register_info hf[] = {
        { &hf_iso10681_source_address, {
            "Source Address", "iso10681.source_address",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_iso10681_target_address, {
            "Target Address", "iso10681.target_address",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_iso10681_type, {
            "Type", "iso10681.type",
            FT_UINT8, BASE_HEX, VALS(iso10681_message_types), ISO10681_TYPE_MASK, NULL, HFILL } },
        { &hf_iso10681_type2, {
            "Type Ack", "iso10681.type_ack",
            FT_UINT8, BASE_HEX, VALS(iso10681_start_type2_values), ISO10681_TYPE_PART2_MASK, NULL, HFILL } },
        { &hf_iso10681_frame_payload_length, {
            "Frame Payload Length", "iso10681.frame_payload_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_iso10681_message_length, {
            "Message Length", "iso10681.message_length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_iso10681_sequence_number, {
            "Sequence Number", "iso10681.sequence_number",
            FT_UINT8, BASE_DEC, NULL, ISO10681_TYPE_PART2_MASK, NULL, HFILL } },
        { &hf_iso10681_fc_flow_status, {
            "Flow Status", "iso10681.flow_status",
            FT_UINT8, BASE_DEC, VALS(iso10681_flow_status_values), ISO10681_TYPE_PART2_MASK, NULL, HFILL } },
        { &hf_iso10681_fc_bandwidth_control, {
            "Bandwidth Control", "iso10681.bandwidth_control",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_iso10681_fc_bc_separation_cycle_exp, {
            "Separation Cycle Exp", "iso10681.bandwidth_control.separation_cycle_exp",
            FT_UINT8, BASE_DEC, VALS(iso10681_fc_bc_scexp_values), 0x07, NULL, HFILL } },
        { &hf_iso10681_fc_bc_max_num_pdu_per_cycle, {
            "Max Number of PDUs per Cycle", "iso10681.bandwidth_control.max_number_pdus_per_cycle",
            FT_UINT8, BASE_DEC, NULL, 0xF8, NULL, HFILL } },
        { &hf_iso10681_fc_buffer_size, {
            "Buffer Size", "iso10681.buffer_size",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_iso10681_fc_ack, {
            "Ack", "iso10681.ack",
            FT_UINT8, BASE_HEX, VALS(iso10681_fc_ack_values), 0, NULL, HFILL } },
        { &hf_iso10681_fc_byte_position, {
            "Byte Position", "iso10681.byte_position",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },

        { &hf_iso10681_fragments, {
            "Message fragments", "iso10681.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso10681_fragment, {
            "Message fragment", "iso10681.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso10681_fragment_overlap, {
            "Message fragment overlap", "iso10681.fragment.overlap",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_iso10681_fragment_overlap_conflicts, {
            "Message fragment overlapping with conflicting data", "iso10681.fragment.overlap.conflicts",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_iso10681_fragment_multiple_tails, {
            "Message has multiple tail fragments", "iso10681.fragment.multiple_tails",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_iso10681_fragment_too_long_fragment, {
            "Message fragment too long", "iso10681.fragment.too_long_fragment",
            FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        { &hf_iso10681_fragment_error, {
            "Message defragmentation error", "iso10681.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso10681_fragment_count, {
            "Message fragment count", "iso10681.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_iso10681_reassembled_in, {
            "Reassembled in", "iso10681.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso10681_reassembled_length, {
            "Reassembled length", "iso10681.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
                    &ett_iso10681,
                    &ett_iso10681_bandwidth_control,
                    &ett_iso10681_fragment,
                    &ett_iso10681_fragments,
            };

    static ei_register_info ei[] = {
            {
                    &ei_iso10681_message_type_bad, { "iso10681.message_type.bad", PI_MALFORMED, PI_ERROR, "Bad Message Type value", EXPFILL }
            },
    };

    expert_module_t* expert_iso10681;

    proto_iso10681 = proto_register_protocol (
            "ISO10681 Protocol", /* name       */
            "ISO 10681",         /* short name */
            "iso10681"           /* abbrev     */
    );
    iso10681_handle_flexray = register_dissector("iso10681", dissect_iso10681_flexray, proto_iso10681);

    /* Register configuration options */
    iso10681_module = prefs_register_protocol(proto_iso10681, proto_reg_handoff_iso10681);
    prefs_register_range_preference(iso10681_module, "flexray.flexrayids", "FlexRay IDs",
        "FlexRay IDs (combined) - 4bit Bus-ID (0 any), 4bit Channel, 16bit Frame-ID, 8bit Cycle (0xff any)",
        &iso10681_flexray_ids, 0xffffffff);

    prefs_register_bool_preference(iso10681_module, "spread_over_cycles", "Ignore Cycle when matching",
        "TP frames are spread over multiple cycles. Cycle is ignored for matching.",
        &iso10681_spread_over_multiple_cycles);

    proto_register_field_array(proto_iso10681, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_iso10681 = expert_register_protocol(proto_iso10681);
    expert_register_field_array(expert_iso10681, ei, array_length(ei));

    iso10681_seq_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
    iso10681_frame_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);

    reassembly_table_register(&iso10681_reassembly_table, &addresses_reassembly_table_functions);

    subdissector_table = register_decode_as_next_proto(proto_iso10681, "iso10681.subdissector", "ISO10681 next level dissector", NULL);
}

void
proto_reg_handoff_iso10681(void) {
    static gboolean initialized = FALSE;

    if (!initialized) {
        dissector_add_for_decode_as("flexray.subdissector", iso10681_handle_flexray);

        initialized = TRUE;
    } else {
        dissector_delete_all("flexray.combined_id", iso10681_handle_flexray);
    }

    dissector_add_uint_range("flexray.combined_id", iso10681_flexray_ids, iso10681_handle_flexray);
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
