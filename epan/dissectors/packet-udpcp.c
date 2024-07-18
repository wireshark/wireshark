/* packet-udpcp.c
 *
 * Routines for UDPCP packet dissection (UDP-based reliable communication protocol).
 * Described in the Open Base Station Initiative Reference Point 1 Specification
 * (see https://web.archive.org/web/20171206005927/http://www.obsai.com/specs/RP1%20Spec%20v2_1.pdf, Appendix A)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* TODO:
 * - Calculate/verify Checksum field
  */

#include "config.h"

#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/prefs.h>


void proto_register_udpcp(void);

static int proto_udpcp;

static int hf_udpcp_checksum;
static int hf_udpcp_msg_type;
static int hf_udpcp_version;

static int hf_udpcp_packet_transfer_options;
static int hf_udpcp_n;
static int hf_udpcp_c;
static int hf_udpcp_s;
static int hf_udpcp_d;
static int hf_udpcp_reserved;

static int hf_udpcp_fragment_amount;
static int hf_udpcp_fragment_number;

static int hf_udpcp_message_id;
static int hf_udpcp_message_data_length;

static int hf_udpcp_payload;

static int hf_udpcp_ack_frame;
static int hf_udpcp_sn_frame;


/* For reassembly */
static int hf_udpcp_fragments;
static int hf_udpcp_fragment;
static int hf_udpcp_fragment_overlap;
static int hf_udpcp_fragment_overlap_conflict;
static int hf_udpcp_fragment_multiple_tails;
static int hf_udpcp_fragment_too_long_fragment;
static int hf_udpcp_fragment_error;
static int hf_udpcp_fragment_count;
static int hf_udpcp_reassembled_in;
static int hf_udpcp_reassembled_length;
static int hf_udpcp_reassembled_data;


/* Subtrees */
static int ett_udpcp;
static int ett_udpcp_packet_transfer_options;
static int ett_udpcp_fragments;
static int ett_udpcp_fragment;

static const fragment_items udpcp_frag_items = {
  &ett_udpcp_fragment,
  &ett_udpcp_fragments,
  &hf_udpcp_fragments,
  &hf_udpcp_fragment,
  &hf_udpcp_fragment_overlap,
  &hf_udpcp_fragment_overlap_conflict,
  &hf_udpcp_fragment_multiple_tails,
  &hf_udpcp_fragment_too_long_fragment,
  &hf_udpcp_fragment_error,
  &hf_udpcp_fragment_count,
  &hf_udpcp_reassembled_in,
  &hf_udpcp_reassembled_length,
  &hf_udpcp_reassembled_data,
  "UDPCP fragments"
};


static expert_field ei_udpcp_checksum_should_be_zero;
static expert_field ei_udpcp_d_not_zero_for_data;
static expert_field ei_udpcp_reserved_not_zero;
static expert_field ei_udpcp_n_s_ack;
static expert_field ei_udpcp_payload_wrong_size;
static expert_field ei_udpcp_wrong_sequence_number;
static expert_field ei_udpcp_no_ack;
static expert_field ei_udpcp_no_sn_frame;

static dissector_handle_t udpcp_handle;


void proto_reg_handoff_udpcp (void);

/* User definable values */
static range_t *global_udpcp_port_range;

#define DATA_FORMAT 0x01
#define ACK_FORMAT  0x02


static const value_string msg_type_vals[] = {
  { DATA_FORMAT,   "Data Packet" },
  { ACK_FORMAT,    "Ack Packet" },
  { 0,     NULL }
};

typedef struct {
    /* Protocol is bi-directional, so need to distinguish */
    uint16_t first_dest_port;
    address first_dest_address;

    /* Main these so can link between SN frames and ACKs */
    wmem_tree_t *sn_table_first;
    wmem_tree_t *ack_table_first;
    wmem_tree_t *sn_table_second;
    wmem_tree_t *ack_table_second;

    /* Remember next expected message-id in each direction */
    uint32_t next_message_id_first;
    uint32_t next_message_id_second;
} udpcp_conversation_t;


/* Framenum -> expected_sequence_number */
static wmem_tree_t *sequence_number_result_table;


/* Reassembly table. */
static reassembly_table udpcp_reassembly_table;

static void *udpcp_temporary_key(const packet_info *pinfo _U_, const uint32_t id _U_, const void *data)
{
    return (void *)data;
}

static void *udpcp_persistent_key(const packet_info *pinfo _U_, const uint32_t id _U_,
                                     const void *data)
{
    return (void *)data;
}

static void udpcp_free_temporary_key(void *ptr _U_)
{
}

static void udpcp_free_persistent_key(void *ptr _U_)
{
}

static reassembly_table_functions udpcp_reassembly_table_functions =
{
    g_direct_hash,
    g_direct_equal,
    udpcp_temporary_key,
    udpcp_persistent_key,
    udpcp_free_temporary_key,
    udpcp_free_persistent_key
};


/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

/* Reassemble by default */
static bool global_udpcp_reassemble = true;

/* By default do try to decode payload as XML/SOAP */
static bool global_udpcp_decode_payload_as_soap = true;


static dissector_handle_t xml_handle;

/******************************/
/* Main dissection function.  */
static int
dissect_udpcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *udpcp_tree;
    proto_item *root_ti;
    int offset = 0;

    /* Must be at least 12 bytes */
    if (tvb_reported_length(tvb) < 12) {
        return 0;
    }

    /* Has to be Data or Ack format. */
    uint32_t msg_type = tvb_get_uint8(tvb, 4) >> 6;
    if ((msg_type != DATA_FORMAT) && (msg_type != ACK_FORMAT)) {
        return 0;
    }

    /* Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDPCP");

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_udpcp, tvb, offset, -1, ENC_NA);
    udpcp_tree = proto_item_add_subtree(root_ti, ett_udpcp);

    /* Checksum */
    uint32_t checksum;
    proto_item *checksum_ti = proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_checksum, tvb, offset, 4, ENC_BIG_ENDIAN, &checksum);
    offset += 4;

    /* Msg-type */
    proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN, &msg_type);
    col_add_str(pinfo->cinfo, COL_INFO,
                (msg_type == DATA_FORMAT) ? "[Data] " : "[Ack]  ");
    proto_item_append_text(root_ti, (msg_type == DATA_FORMAT) ? " [Data]" : " [Ack]");

    /* Version */
    proto_tree_add_item(udpcp_tree, hf_udpcp_version, tvb, offset, 1, ENC_BIG_ENDIAN);


    /***************************/
    /* Packet Transfer Options */
    proto_item *packet_transfer_options_ti =
            proto_tree_add_string_format(udpcp_tree, hf_udpcp_packet_transfer_options, tvb, offset, 2,
                                         "", "Packet Transfer Options (");
    proto_tree *packet_transfer_options_tree =
            proto_item_add_subtree(packet_transfer_options_ti, ett_udpcp_packet_transfer_options);
    uint32_t n, c, s, d;

    /* N */
    proto_tree_add_item_ret_uint(packet_transfer_options_tree, hf_udpcp_n, tvb, offset, 1, ENC_BIG_ENDIAN, &n);
    if (n) {
        proto_item_append_text(packet_transfer_options_ti, "N");
    }

    /* C */
    proto_tree_add_item_ret_uint(packet_transfer_options_tree, hf_udpcp_c, tvb, offset, 1, ENC_BIG_ENDIAN, &c);
    if (c) {
       proto_item_append_text(packet_transfer_options_ti, "C");
    }
    if (!c && checksum) {
        /* Expert info warning that checksum should be 0 if !c */
        expert_add_info(pinfo, checksum_ti, &ei_udpcp_checksum_should_be_zero);
    }

    /* S */
    proto_tree_add_item_ret_uint(packet_transfer_options_tree, hf_udpcp_s, tvb, offset, 1, ENC_BIG_ENDIAN, &s);
    offset++;
    if (s) {
        proto_item_append_text(packet_transfer_options_ti, "S");
    }

    /* D */
    proto_item *d_ti = proto_tree_add_item_ret_uint(packet_transfer_options_tree, hf_udpcp_d, tvb, offset, 1, ENC_BIG_ENDIAN, &d);
    if (d) {
        proto_item_append_text(packet_transfer_options_ti, "D");
    }
    /* Expert info if D not zero for data */
    if ((msg_type == DATA_FORMAT) && d) {
        expert_add_info(pinfo, d_ti, &ei_udpcp_d_not_zero_for_data);
    }

    /* Reserved */
    uint32_t reserved;
    proto_item *reserved_ti = proto_tree_add_item_ret_uint(packet_transfer_options_tree, hf_udpcp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved);
    offset++;
    /* Expert info if reserved not 0 */
    if (reserved) {
        expert_add_info(pinfo, reserved_ti, &ei_udpcp_reserved_not_zero);
    }

    proto_item_append_text(packet_transfer_options_ti, ")");
    /*************************/


    /* Fragment Amount & Fragment Number */
    uint32_t fragment_amount, fragment_number;
    proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_fragment_amount, tvb, offset, 1, ENC_BIG_ENDIAN, &fragment_amount);
    offset++;
    proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_fragment_number, tvb, offset, 1, ENC_BIG_ENDIAN, &fragment_number);
    offset++;

    /* Message ID & Message Data Length */
    uint32_t message_id;
    proto_item *message_id_ti = proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_message_id, tvb, offset, 2, ENC_BIG_ENDIAN, &message_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Msg_ID=%3u", message_id);
    offset += 2;
    uint32_t data_length;
    proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_message_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &data_length);
    offset += 2;

    if (msg_type == DATA_FORMAT) {
        if (!data_length) {
            /* This could just be a sync frame */
            if (!message_id && !n && !s) {
                col_append_str(pinfo->cinfo, COL_INFO, "  [Sync]");
            }
        }

        /* Show if/when this frame should be acknowledged */
        if (!n && !s) {
            proto_item_append_text(packet_transfer_options_ti, " (All packets ACKd)");
        }
        else if (!n && s) {
            proto_item_append_text(packet_transfer_options_ti, " (Last fragment ACKd)");
        }
        if (n) {
            proto_item_append_text(packet_transfer_options_ti, " (Not ACKd)");
        }

        /* Show fragment numbering.  Ignore confusing 0-based fragment numbering.. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "  [Frag %u/%u]",
                        fragment_number+1, fragment_amount);

        /* There is data */
        if ((fragment_amount == 1) && (fragment_number == 0) && data_length) {
            /* Not fragmented - show payload now */
            proto_item *data_ti = proto_tree_add_item(udpcp_tree, hf_udpcp_payload, tvb, offset, -1, ENC_ASCII);
            col_append_fstr(pinfo->cinfo, COL_INFO, "  Data (%u bytes)", data_length);

            /* Check length is as signalled */
            if (data_length != (uint32_t)tvb_reported_length_remaining(tvb, offset)) {
                expert_add_info_format(pinfo, data_ti, &ei_udpcp_payload_wrong_size, "Data length field was %u but %u bytes found",
                                       data_length, tvb_reported_length_remaining(tvb, offset));
            }

            if (global_udpcp_decode_payload_as_soap) {
                /* Send to XML dissector */
                tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector_only(xml_handle, next_tvb, pinfo, tree, NULL);
            }
        }
        else {
            /* Fragmented */
            if (global_udpcp_reassemble && data_length) {
                /* Reassembly */
                /* Set fragmented flag. */
                bool save_fragmented = pinfo->fragmented;
                pinfo->fragmented = true;
                fragment_head *fh;
                unsigned frag_data_len = tvb_reported_length_remaining(tvb, offset);

                /* Add this fragment into reassembly */
                fh = fragment_add_seq_check(&udpcp_reassembly_table, tvb, offset, pinfo,
                                            message_id,                                    /* id */
                                            GUINT_TO_POINTER(message_id),                  /* data */
                                            fragment_number,                               /* frag_number */
                                            frag_data_len,                                 /* frag_data_len */
                                            (fragment_number < (fragment_amount-1))        /* more_frags */
                                            );

                bool update_col_info = true;
                /* See if this completes an SDU */
                tvbuff_t *next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled UDPCP Payload",
                                                              fh, &udpcp_frag_items,
                                                              &update_col_info, udpcp_tree);
                if (next_tvb) {
                    /* Have reassembled data */
                    proto_item *data_ti = proto_tree_add_item(udpcp_tree, hf_udpcp_payload, next_tvb, 0, -1, ENC_ASCII);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "  Reassembled Data (%u bytes)", data_length);

                    /* Check length is as signalled */
                    if (data_length != (uint32_t)tvb_reported_length_remaining(next_tvb, 0)) {
                        expert_add_info_format(pinfo, data_ti, &ei_udpcp_payload_wrong_size, "Data length field was %u but %u bytes found (reassembled)",
                                               data_length, tvb_reported_length_remaining(next_tvb, 0));
                    }

                    if (global_udpcp_decode_payload_as_soap) {
                        /* Send to XML dissector */
                        call_dissector_only(xml_handle, next_tvb, pinfo, tree, NULL);
                    }
                }

                /* Restore fragmented flag */
                pinfo->fragmented = save_fragmented;
            }
        }
    }
    else if (msg_type == ACK_FORMAT) {
        /* N and S should be set - complain if not */
        if (!n || !s) {
            expert_add_info(pinfo, packet_transfer_options_ti, &ei_udpcp_n_s_ack);
        }

        if (d) {
            /* Duplicate data detected */
            proto_item_append_text(packet_transfer_options_ti, " (duplicate)");
            col_append_str(pinfo->cinfo, COL_INFO, " (duplicate)");
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, "  ACK for Msg_ID=%3u", message_id);
    }

    /* Look up conversation */
    if (!PINFO_FD_VISITED(pinfo)) {
        /* First pass */
        conversation_t *p_conv;
        udpcp_conversation_t *p_conv_data;

        p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                                   conversation_pt_to_conversation_type(pinfo->ptype),
                                   pinfo->destport, pinfo->srcport,
                                   0 /* options */);

        /* Look up data from conversation */
        p_conv_data = (udpcp_conversation_t *)conversation_get_proto_data(p_conv, proto_udpcp);

        /* Create new data for conversation data if not found */
        if (!p_conv_data) {
            p_conv_data = wmem_new(wmem_file_scope(), udpcp_conversation_t);

            /* Set initial values */
            p_conv_data->first_dest_port = pinfo->destport;
            copy_address(&p_conv_data->first_dest_address, &pinfo->dst);
            p_conv_data->next_message_id_first = 0;
            p_conv_data->next_message_id_second = 0;

            /* SN and ACK tables */
            p_conv_data->sn_table_first = wmem_tree_new(wmem_file_scope());
            p_conv_data->ack_table_first = wmem_tree_new(wmem_file_scope());
            p_conv_data->sn_table_second = wmem_tree_new(wmem_file_scope());
            p_conv_data->ack_table_second = wmem_tree_new(wmem_file_scope());

            /* Store in conversation */
            conversation_add_proto_data(p_conv, proto_udpcp, p_conv_data);
        }

        /* Check which direction this is in */
        bool first_dir = (pinfo->destport == p_conv_data->first_dest_port) &&
                             addresses_equal(&pinfo->dst, &p_conv_data->first_dest_address);

        /* Check for expected sequence number */
        if (msg_type == DATA_FORMAT) {
            if (first_dir) {
                if (message_id != p_conv_data->next_message_id_first) {
                    wmem_tree_insert32(sequence_number_result_table, pinfo->num, GUINT_TO_POINTER(p_conv_data->next_message_id_first));
                }
                /* Only inc when have seen last fragment */
                if (fragment_number == fragment_amount-1) {
                    p_conv_data->next_message_id_first = message_id + 1;
                }

                /* Store SN entry in table */
                wmem_tree_insert32(p_conv_data->sn_table_first, message_id, GUINT_TO_POINTER(pinfo->num));
            }
            /* 2nd Direction */
            else {
                if (message_id != p_conv_data->next_message_id_second) {
                    wmem_tree_insert32(sequence_number_result_table, pinfo->num, GUINT_TO_POINTER(p_conv_data->next_message_id_second));
                }
                /* Only inc when have seen last fragment */
                if (fragment_number == fragment_amount-1) {
                    p_conv_data->next_message_id_second = message_id + 1;
                }

                /* Store SN entry in table */
                wmem_tree_insert32(p_conv_data->sn_table_second, message_id, GUINT_TO_POINTER(pinfo->num));
            }
        }

        if (msg_type == ACK_FORMAT) {
            /* N.B., directions reversed here to apply to data direction */
            if (first_dir) {
                wmem_tree_insert32(p_conv_data->ack_table_first, message_id, GUINT_TO_POINTER(pinfo->num));
            }
            else {
                wmem_tree_insert32(p_conv_data->ack_table_second, message_id, GUINT_TO_POINTER(pinfo->num));
            }
        }
    }
    else {
        /* Later passes - look up conversation here */
        conversation_t *p_conv;
        udpcp_conversation_t *p_conv_data;

        p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                                   conversation_pt_to_conversation_type(pinfo->ptype),
                                   pinfo->destport, pinfo->srcport,
                                   0 /* options */);

        /* Look up data from conversation */
        p_conv_data = (udpcp_conversation_t *)conversation_get_proto_data(p_conv, proto_udpcp);
        if (!p_conv_data) {
            /* TODO: error if not found? */
            return offset;
        }

        /* Check which direction this is in */
        bool first_dir = (pinfo->destport == p_conv_data->first_dest_port) &&
                             addresses_equal(&pinfo->dst, &p_conv_data->first_dest_address);


        if (msg_type == DATA_FORMAT) {
            /* Check for unexpected sequence number, but not if message_id is still 0 (as it may be repeated) */
            if (message_id > 1) {
                if (wmem_tree_contains32(sequence_number_result_table, pinfo->num)) {
                    uint32_t seqno = GPOINTER_TO_UINT(wmem_tree_lookup32(sequence_number_result_table, pinfo->num));
                    expert_add_info_format(pinfo, message_id_ti, &ei_udpcp_wrong_sequence_number, "SN %u expected, but found %u instead",
                                           seqno, message_id);
                }
            }

            /* Look for ACK for this data PDU, link or expert info */
            wmem_tree_t *ack_table = (first_dir) ? p_conv_data->ack_table_second : p_conv_data->ack_table_first;
            if (wmem_tree_contains32(ack_table, message_id)) {
                uint32_t ack = GPOINTER_TO_UINT(wmem_tree_lookup32(ack_table, message_id));
                proto_tree_add_uint(udpcp_tree,  hf_udpcp_ack_frame, tvb, 0, 0, ack);
            }
            else {
                expert_add_info_format(pinfo, message_id_ti, &ei_udpcp_no_ack, "No ACK seen for this data frame (message_id=%u",
                                       message_id);

            }

        }
        else if (msg_type == ACK_FORMAT) {
            /* Look up corresponding Data frame, link or expert info */
            wmem_tree_t *sn_table = (first_dir) ? p_conv_data->sn_table_second : p_conv_data->sn_table_first;
            if (wmem_tree_contains32(sn_table, message_id)) {
                uint32_t sn_frame = GPOINTER_TO_UINT(wmem_tree_lookup32(sn_table, message_id));
                proto_tree_add_uint(udpcp_tree,  hf_udpcp_sn_frame, tvb, 0, 0, sn_frame);
            }
            else {
                expert_add_info_format(pinfo, message_id_ti, &ei_udpcp_no_sn_frame, "No SN frame seen corresponding to this ACK (message_id=%u",
                                       message_id);
            }
        }
    }

    return offset;
}

void
proto_register_udpcp(void)
{
  static hf_register_info hf[] = {
      { &hf_udpcp_checksum,
        { "Checksum", "udpcp.checksum", FT_UINT32, BASE_HEX,
          NULL, 0x0, "Adler32 checksum", HFILL }},
      { &hf_udpcp_msg_type,
        { "Msg Type", "udpcp.msg-type", FT_UINT8, BASE_HEX,
          VALS(msg_type_vals), 0xc0, NULL, HFILL }},
      { &hf_udpcp_version,
        { "Version", "udpcp.version", FT_UINT8, BASE_HEX,
          NULL, 0x38, NULL, HFILL }},

      { &hf_udpcp_packet_transfer_options,
        { "Packet Transport Options", "udpcp.pto", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
      { &hf_udpcp_n,
        { "N", "udpcp.n", FT_UINT8, BASE_HEX,
          NULL, 0x04, "Along with S bit, indicates whether acknowledgements should be sent", HFILL }},
      { &hf_udpcp_c,
        { "C", "udpcp.c", FT_UINT8, BASE_HEX,
          NULL, 0x02, "When set, the checksum should be valid", HFILL }},
      { &hf_udpcp_s,
        { "S", "udpcp.s", FT_UINT8, BASE_HEX,
          NULL, 0x01, "Along with N bit, indicates whether acknowledgements should be sent", HFILL }},
      { &hf_udpcp_d,
        { "D", "udpcp.d", FT_UINT8, BASE_HEX,
          NULL, 0x80, "For ACK, indicates duplicate ACK", HFILL }},
      { &hf_udpcp_reserved,
        { "Reserved", "udpcp.reserved", FT_UINT8, BASE_HEX,
          NULL, 0x7f, "Shall be set to 0", HFILL }},

      { &hf_udpcp_fragment_amount,
        { "Fragment Amount", "udpcp.fragment-amount", FT_UINT8, BASE_DEC,
          NULL, 0x0, "Total number of fragments of a message", HFILL }},
      { &hf_udpcp_fragment_number,
        { "Fragment Number", "udpcp.fragment-number", FT_UINT8, BASE_DEC,
          NULL, 0x0, "Fragment number of current packet within msg.  Starts at 0", HFILL }},

      { &hf_udpcp_message_id,
        { "Message ID", "udpcp.message-id", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_udpcp_message_data_length,
        { "Message Data Length", "udpcp.message-data-length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_udpcp_payload,
        { "Payload", "udpcp.payload", FT_BYTES, BASE_SHOW_ASCII_PRINTABLE,
          NULL, 0x0, "Complete or reassembled payload", HFILL }},

      /* Reassembly */
      { &hf_udpcp_fragment,
        { "Fragment", "udpcp.fragment", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_udpcp_fragments,
        { "Fragments", "udpcp.fragments", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_udpcp_fragment_overlap,
        { "Fragment overlap", "udpcp.fragment.overlap", FT_BOOLEAN, BASE_NONE,
          NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},
      { &hf_udpcp_fragment_overlap_conflict,
        { "Conflicting data in fragment overlap", "udpcp.fragment.overlap.conflict",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Overlapping fragments contained conflicting data", HFILL }},
      { &hf_udpcp_fragment_multiple_tails,
        { "Multiple tail fragments found", "udpcp.fragment.multipletails",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Several tails were found when defragmenting the packet", HFILL }},
      { &hf_udpcp_fragment_too_long_fragment,
        { "Fragment too long", "udpcp.fragment.toolongfragment",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Fragment contained data past end of packet", HFILL }},
      { &hf_udpcp_fragment_error,
        { "Defragmentation error", "udpcp.fragment.error", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},
      { &hf_udpcp_fragment_count,
        { "Fragment count", "udpcp.fragment.count", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_udpcp_reassembled_in,
        { "Reassembled payload in frame", "udpcp.reassembled_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This payload packet is reassembled in this frame", HFILL }},
      { &hf_udpcp_reassembled_length,
        { "Reassembled payload length", "udpcp.reassembled.length", FT_UINT32, BASE_DEC,
          NULL, 0x0, "The total length of the reassembled payload", HFILL }},
      { &hf_udpcp_reassembled_data,
        { "Reassembled data", "udpcp.reassembled.data", FT_BYTES, BASE_NONE,
          NULL, 0x0, "The reassembled payload", HFILL }},

      { &hf_udpcp_ack_frame,
        { "Ack Frame", "udpcp.ack-frame", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, "Frame that ACKs this data", HFILL }},
      { &hf_udpcp_sn_frame,
        { "SN Frame", "udpcp.sn-frame", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, "Data frame ACKd by this one", HFILL }},
    };

    static int *ett[] = {
        &ett_udpcp,
        &ett_udpcp_packet_transfer_options,
        &ett_udpcp_fragments,
        &ett_udpcp_fragment
    };

    static ei_register_info ei[] = {
        { &ei_udpcp_checksum_should_be_zero, { "udpcp.checksum-not-zero", PI_CHECKSUM, PI_WARN, "Checksum should be zero if !C.", EXPFILL }},
        { &ei_udpcp_d_not_zero_for_data,     { "udpcp.d-not-zero-data", PI_SEQUENCE, PI_ERROR, "D should be zero for data frames", EXPFILL }},
        { &ei_udpcp_reserved_not_zero,       { "udpcp.reserved-not-zero", PI_MALFORMED, PI_WARN, "Reserved bits not zero", EXPFILL }},
        { &ei_udpcp_n_s_ack,                 { "udpcp.n-s-set-ack", PI_MALFORMED, PI_ERROR, "N or S set for ACK frame", EXPFILL }},
        { &ei_udpcp_payload_wrong_size,      { "udpcp.payload-wrong-size", PI_MALFORMED, PI_ERROR, "Payload seen does not match size field", EXPFILL }},
        { &ei_udpcp_wrong_sequence_number,   { "udpcp.sequence-number-wrong", PI_SEQUENCE, PI_WARN, "Unexpected sequence number", EXPFILL }},
        { &ei_udpcp_no_ack,                  { "udpcp.no-ack", PI_SEQUENCE, PI_WARN, "No ACK seen for data frame", EXPFILL }},
        { &ei_udpcp_no_sn_frame,             { "udpcp.no-sn-frame", PI_SEQUENCE, PI_WARN, "No SN frame seen for ACK", EXPFILL }},
    };

    module_t *udpcp_module;
    expert_module_t *expert_udpcp;

    proto_udpcp = proto_register_protocol("UDPCP", "UDPCP", "udpcp");
    proto_register_field_array(proto_udpcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_udpcp = expert_register_protocol(proto_udpcp);
    expert_register_field_array(expert_udpcp, ei, array_length(ei));

    udpcp_handle = register_dissector("udpcp", dissect_udpcp, proto_udpcp);

    /* Register reassembly table. */
    reassembly_table_register(&udpcp_reassembly_table,
                              &udpcp_reassembly_table_functions);

    /* Preferences */
    udpcp_module = prefs_register_protocol(proto_udpcp, NULL);

    /* Payload reassembly */
    prefs_register_bool_preference(udpcp_module, "attempt_reassembly",
                                   "Reassemble payload",
                                   "",
                                   &global_udpcp_reassemble);

    /* Whether to try XML dissector on payload.
     * TODO: are there any other payload types we might see? */
    prefs_register_bool_preference(udpcp_module, "attempt_xml_decode",
        "Call XML dissector for payload",
        "",
        &global_udpcp_decode_payload_as_soap);

    sequence_number_result_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}

static void
apply_udpcp_prefs(void)
{
    global_udpcp_port_range = prefs_get_range_value("udpcp", "udp.port");
}

void
proto_reg_handoff_udpcp(void)
{
    dissector_add_uint_range_with_preference("udp.port", "", udpcp_handle);
    apply_udpcp_prefs();

    xml_handle = find_dissector("xml");
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
