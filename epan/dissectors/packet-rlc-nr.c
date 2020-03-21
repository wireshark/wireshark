/* Routines for NR RLC disassembly
 *
 * Pascal Quantin
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>

#include "packet-rlc-nr.h"
#include "packet-pdcp-nr.h"


/* Described in:
 * 3GPP TS 38.322 NR; Radio Link Control (RLC) protocol specification v15.0.0
 */

/* TODO:
- add sequence analysis
- add AM reassembly
- take configuration of reordering timer, and stop reassembly if timeout exceeded?
- add tap info
- call more upper layer dissectors once they appear
*/

void proto_register_rlc_nr(void);
void proto_reg_handoff_rlc_nr(void);

/********************************/
/* Preference settings          */

/* By default do call PDCP/RRC dissectors for SDU data */
static gboolean global_rlc_nr_call_pdcp_for_srb = TRUE;

enum pdcp_for_drb { PDCP_drb_off, PDCP_drb_SN_12, PDCP_drb_SN_18, PDCP_drb_SN_signalled};
static const enum_val_t pdcp_drb_col_vals[] = {
    {"pdcp-drb-off",           "Off",                 PDCP_drb_off},
    {"pdcp-drb-sn-12",         "12-bit SN",           PDCP_drb_SN_12},
    {"pdcp-drb-sn-18",         "18-bit SN",           PDCP_drb_SN_18},
    {"pdcp-drb-sn-signalling", "Use signalled value", PDCP_drb_SN_signalled},
    {NULL, NULL, -1}
};
/* Separate config for UL/DL */
static gint global_rlc_nr_call_pdcp_for_ul_drb = (gint)PDCP_drb_off;
static gint global_rlc_nr_call_pdcp_for_dl_drb = (gint)PDCP_drb_off;


static gboolean global_rlc_nr_call_rrc_for_ccch = TRUE;

/* Preference to expect RLC headers without payloads */
static gboolean global_rlc_nr_headers_expected = FALSE;

/* Attempt reassembly of UM frames.  TODO: if add AM reassembly, might prefer just one preference? */
static gboolean global_rlc_nr_reassemble_um_pdus = FALSE;

/* Tree storing UE related parameters */
typedef struct rlc_ue_parameters {
    guint32 id;
    guint8 pdcp_sn_bits_ul;
    guint8 pdcp_sn_bits_dl;
} rlc_ue_parameters;
static wmem_tree_t *ue_parameters_tree;


/**************************************************/
/* Initialize the protocol and registered fields. */
int proto_rlc_nr = -1;

extern int proto_pdcp_nr;

static dissector_handle_t pdcp_nr_handle;
static dissector_handle_t nr_rrc_bcch_bch;
static dissector_handle_t nr_rrc_bcch_dl_sch;
static dissector_handle_t nr_rrc_pcch;
static dissector_handle_t nr_rrc_ul_ccch;
static dissector_handle_t nr_rrc_ul_ccch1;
static dissector_handle_t nr_rrc_dl_ccch;


/* Decoding context */
static int hf_rlc_nr_context = -1;
static int hf_rlc_nr_context_mode = -1;
static int hf_rlc_nr_context_direction = -1;
static int hf_rlc_nr_context_ueid = -1;
static int hf_rlc_nr_context_bearer_type = -1;
static int hf_rlc_nr_context_bearer_id = -1;
static int hf_rlc_nr_context_pdu_length = -1;
static int hf_rlc_nr_context_sn_length = -1;

/* Transparent mode fields */
static int hf_rlc_nr_tm = -1;
static int hf_rlc_nr_tm_data = -1;

/* Unacknowledged mode fields */
static int hf_rlc_nr_um = -1;
static int hf_rlc_nr_um_header = -1;
static int hf_rlc_nr_um_si = -1;
static int hf_rlc_nr_um_reserved = -1;
static int hf_rlc_nr_um_sn6 = -1;
static int hf_rlc_nr_um_sn12 = -1;
static int hf_rlc_nr_um_so = -1;
static int hf_rlc_nr_um_data = -1;

/* Acknowledged mode fields */
static int hf_rlc_nr_am = -1;
static int hf_rlc_nr_am_header = -1;
static int hf_rlc_nr_am_data_control = -1;
static int hf_rlc_nr_am_p = -1;
static int hf_rlc_nr_am_si = -1;
static int hf_rlc_nr_am_sn12 = -1;
static int hf_rlc_nr_am_sn18 = -1;
static int hf_rlc_nr_am_reserved = -1;
static int hf_rlc_nr_am_so = -1;
static int hf_rlc_nr_am_data = -1;

/* Control fields */
static int hf_rlc_nr_am_cpt = -1;
static int hf_rlc_nr_am_ack_sn = -1;
static int hf_rlc_nr_am_e1 = -1;
static int hf_rlc_nr_am_e2 = -1;
static int hf_rlc_nr_am_e3 = -1;
static int hf_rlc_nr_am_nack_sn = -1;
static int hf_rlc_nr_am_so_start = -1;
static int hf_rlc_nr_am_so_end = -1;
static int hf_rlc_nr_am_nack_range = -1;
static int hf_rlc_nr_am_nacks = -1;

static int hf_rlc_nr_header_only = -1;

static int hf_rlc_nr_fragments = -1;
static int hf_rlc_nr_fragment = -1;
static int hf_rlc_nr_fragment_overlap = -1;
static int hf_rlc_nr_fragment_overlap_conflict = -1;
static int hf_rlc_nr_fragment_multiple_tails = -1;
static int hf_rlc_nr_fragment_too_long_fragment = -1;
static int hf_rlc_nr_fragment_error = -1;
static int hf_rlc_nr_fragment_count = -1;
static int hf_rlc_nr_reassembled_in = -1;
static int hf_rlc_nr_reassembled_length = -1;
static int hf_rlc_nr_reassembled_data = -1;



/* Subtrees. */
static int ett_rlc_nr = -1;
static int ett_rlc_nr_context = -1;
static int ett_rlc_nr_um_header = -1;
static int ett_rlc_nr_am_header = -1;
static int ett_rlc_nr_fragments = -1;
static int ett_rlc_nr_fragment = -1;


static const fragment_items rlc_nr_frag_items = {
  &ett_rlc_nr_fragment,
  &ett_rlc_nr_fragments,
  &hf_rlc_nr_fragments,
  &hf_rlc_nr_fragment,
  &hf_rlc_nr_fragment_overlap,
  &hf_rlc_nr_fragment_overlap_conflict,
  &hf_rlc_nr_fragment_multiple_tails,
  &hf_rlc_nr_fragment_too_long_fragment,
  &hf_rlc_nr_fragment_error,
  &hf_rlc_nr_fragment_count,
  &hf_rlc_nr_reassembled_in,
  &hf_rlc_nr_reassembled_length,
  &hf_rlc_nr_reassembled_data,
  "RLC PDU fragments"
};


static expert_field ei_rlc_nr_context_mode = EI_INIT;
static expert_field ei_rlc_nr_am_nack_sn = EI_INIT;
static expert_field ei_rlc_nr_am_nack_sn_ahead_ack = EI_INIT;
static expert_field ei_rlc_nr_am_nack_sn_ack_same = EI_INIT;
static expert_field ei_rlc_nr_am_nack_range = EI_INIT;
static expert_field ei_rlc_nr_am_cpt = EI_INIT;
static expert_field ei_rlc_nr_um_data_no_data = EI_INIT;
static expert_field ei_rlc_nr_am_data_no_data = EI_INIT;
static expert_field ei_rlc_nr_am_nack_sn_partial = EI_INIT;
static expert_field ei_rlc_nr_bytes_after_status_pdu_complete = EI_INIT;
static expert_field ei_rlc_nr_um_sn = EI_INIT;
static expert_field ei_rlc_nr_am_sn = EI_INIT;
static expert_field ei_rlc_nr_header_only = EI_INIT;
static expert_field ei_rlc_nr_reserved_bits_not_zero = EI_INIT;
static expert_field ei_rlc_nr_no_per_frame_info = EI_INIT;
static expert_field ei_rlc_nr_unknown_udp_framing_tag = EI_INIT;

/* Value-strings */
static const value_string direction_vals[] =
{
    { DIRECTION_UPLINK,   "Uplink" },
    { DIRECTION_DOWNLINK, "Downlink" },
    { 0, NULL }
};

static const value_string rlc_mode_short_vals[] =
{
    { RLC_TM_MODE, "TM" },
    { RLC_UM_MODE, "UM" },
    { RLC_AM_MODE, "AM" },
    { 0, NULL }
};

static const value_string rlc_mode_vals[] =
{
    { RLC_TM_MODE, "Transparent Mode" },
    { RLC_UM_MODE, "Unacknowledged Mode" },
    { RLC_AM_MODE, "Acknowledged Mode" },
    { 0, NULL }
};

static const value_string rlc_bearer_type_vals[] =
{
    { BEARER_TYPE_CCCH,        "CCCH" },
    { BEARER_TYPE_BCCH_BCH,    "BCCH BCH" },
    { BEARER_TYPE_PCCH,        "PCCH" },
    { BEARER_TYPE_SRB,         "SRB" },
    { BEARER_TYPE_DRB,         "DRB" },
    { BEARER_TYPE_BCCH_DL_SCH, "BCCH DL-SCH" },
    { 0, NULL }
};

static const value_string seg_info_vals[] =
{
    { 0, "Data field contains all bytes of an RLC SDU" },
    { 1, "Data field contains the first segment of an RLC SDU" },
    { 2, "Data field contains the last segment of an RLC SDU" },
    { 3, "Data field contains neither the first nor last segment of an RLC SDU" },
    { 0, NULL }
};

static const true_false_string data_or_control_vals =
{
    "Data PDU",
    "Control PDU"
};

static const true_false_string polling_bit_vals =
{
    "Status report is requested",
    "Status report not requested"
};

static const value_string control_pdu_type_vals[] =
{
    { 0, "STATUS PDU" },
    { 0, NULL }
};

static const true_false_string am_e1_vals =
{
    "A set of NACK_SN, E1, E2 and E3 follows",
    "A set of NACK_SN, E1, E2 and E3 does not follow"
};

static const true_false_string am_e2_vals =
{
    "A set of SOstart and SOend follows for this NACK_SN",
    "A set of SOstart and SOend does not follow for this NACK_SN"
};

static const true_false_string am_e3_vals =
{
    "NACK range field follows for this NACK_SN",
    "NACK range field does not follow for this NACK_SN"
};

static const true_false_string header_only_vals =
{
    "RLC PDU Headers only",
    "RLC PDU Headers and body present"
};

/* Reassembly state */
static reassembly_table pdu_reassembly_table;

static guint pdu_hash(gconstpointer k _U_)
{
    return GPOINTER_TO_UINT(k);
}

static gint pdu_equal(gconstpointer k1, gconstpointer k2)
{
    return k1 == k2;
}

static gpointer pdu_temporary_key(const packet_info *pinfo _U_, const guint32 id _U_, const void *data _U_)
{
    return (gpointer)data;
}

static gpointer pdu_persistent_key(const packet_info *pinfo _U_, const guint32 id _U_,
                                         const void *data)
{
    return (gpointer)data;
}

static void pdu_free_temporary_key(gpointer ptr _U_)
{
}

static void pdu_free_persistent_key(gpointer ptr _U_)
{
}

reassembly_table_functions pdu_reassembly_table_functions =
{
    pdu_hash,
    pdu_equal,
    pdu_temporary_key,
    pdu_persistent_key,
    pdu_free_temporary_key,
    pdu_free_persistent_key
};


/********************************************************/
/* Forward declarations & functions                     */
static void dissect_rlc_nr_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_udp_framing);


/* Write the given formatted text to:
   - the info column
   - the top-level RLC PDU item
   - another subtree item (if supplied) */
static void write_pdu_label_and_info(proto_item *pdu_ti, proto_item *sub_ti,
                                     packet_info *pinfo, const char *format, ...)
{
    #define MAX_INFO_BUFFER 256
    static char info_buffer[MAX_INFO_BUFFER];

    va_list ap;

    va_start(ap, format);
    g_vsnprintf(info_buffer, MAX_INFO_BUFFER, format, ap);
    va_end(ap);

    /* Add to indicated places */
    col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
    proto_item_append_text(pdu_ti, "%s", info_buffer);
    if (sub_ti != NULL) {
        proto_item_append_text(sub_ti, "%s", info_buffer);
    }
}

/* Version of function above, where no g_vsnprintf() call needed
   - the info column
   - the top-level RLC PDU item
   - another subtree item (if supplied) */
static void write_pdu_label_and_info_literal(proto_item *pdu_ti, proto_item *sub_ti,
                                             packet_info *pinfo, const char *info_buffer)
{
    /* Add to indicated places */
    col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
    proto_item_append_text(pdu_ti, "%s", info_buffer);
    if (sub_ti != NULL) {
        proto_item_append_text(sub_ti, "%s", info_buffer);
    }
}

/* Show in the info column how many bytes are in the UM/AM PDU, and indicate
   whether or not the beginning and end are included in this packet */
static void show_PDU_in_info(packet_info *pinfo,
                             proto_item *top_ti,
                             gint32 length,
                             guint8 seg_info)
{
    /* Reflect this PDU in the info column */
    if (length > 0) {
        write_pdu_label_and_info(top_ti, NULL, pinfo,
                                 "  %s%u-byte%s%s",
                                 (seg_info & 0x02) ? ".." : "[",
                                 length,
                                 (length > 1) ? "s" : "",
                                 (seg_info & 0x01) ? ".." : "]");
    } else {
        write_pdu_label_and_info(top_ti, NULL, pinfo,
                                 "  %sunknown-bytes%s",
                                 (seg_info & 0x02) ? ".." : "[",
                                 (seg_info & 0x01) ? ".." : "]");
    }
}


/* Show an SDU. If configured, pass to PDCP/RRC dissector */
static void show_PDU_in_tree(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, gint offset, gint length,
                             rlc_nr_info *rlc_info, guint32 seg_info, gboolean is_reassembled)
{
    wmem_tree_key_t key[3];
    guint32 id;
    rlc_ue_parameters *params;

    /* Add raw data (according to mode) */
    if (!is_reassembled) {
        proto_tree_add_item(tree, (rlc_info->rlcMode == RLC_AM_MODE) ?
                            hf_rlc_nr_am_data : hf_rlc_nr_um_data,
                            tvb, offset, length, ENC_NA);
    }

    if ((seg_info == 0) || is_reassembled) {  /* i.e. contains whole SDU */
        if ((global_rlc_nr_call_pdcp_for_srb && (rlc_info->bearerType == BEARER_TYPE_SRB)) ||
            ((rlc_info->bearerType == BEARER_TYPE_DRB) &&
                 (((rlc_info->direction == PDCP_NR_DIRECTION_UPLINK) &&   (global_rlc_nr_call_pdcp_for_ul_drb != PDCP_drb_off)) ||
                  ((rlc_info->direction == PDCP_NR_DIRECTION_DOWNLINK) && (global_rlc_nr_call_pdcp_for_dl_drb != PDCP_drb_off)))))
        {

            /* Get whole PDU into tvb */
            tvbuff_t *pdcp_tvb = tvb_new_subset_length(tvb, offset, length);

            /* Reuse or allocate struct */
            struct pdcp_nr_info *p_pdcp_nr_info;
            p_pdcp_nr_info = (pdcp_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0);
            if (p_pdcp_nr_info == NULL) {
                p_pdcp_nr_info = wmem_new0(wmem_file_scope(), pdcp_nr_info);
                /* Store info in packet */
                p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0, p_pdcp_nr_info);
            }

            /* Fill in struct params. */
            p_pdcp_nr_info->direction = rlc_info->direction;
            p_pdcp_nr_info->ueid = rlc_info->ueid;

            gint seqnum_len;

            switch (rlc_info->bearerType) {
                case BEARER_TYPE_SRB:
                    p_pdcp_nr_info->plane = NR_SIGNALING_PLANE;
                    p_pdcp_nr_info->bearerType = Bearer_DCCH;
                    p_pdcp_nr_info->seqnum_length = 12;
                    break;

                case BEARER_TYPE_DRB:
                    p_pdcp_nr_info->plane = NR_USER_PLANE;
                    p_pdcp_nr_info->bearerType = Bearer_DCCH;

                    seqnum_len = (rlc_info->direction == PDCP_NR_DIRECTION_UPLINK) ?
                                       global_rlc_nr_call_pdcp_for_ul_drb :
                                       global_rlc_nr_call_pdcp_for_dl_drb;
                    switch (seqnum_len) {
                        case PDCP_drb_SN_12:
                            p_pdcp_nr_info->seqnum_length = 12;
                            break;
                        case PDCP_drb_SN_18:
                            p_pdcp_nr_info->seqnum_length = 18;
                            break;
                        case PDCP_drb_SN_signalled:
                            /* Use whatever was signalled (i.e. in RRC) */
                            id = (rlc_info->bearerId << 16) | rlc_info->ueid;
                            key[0].length = 1;
                            key[0].key = &id;
                            key[1].length = 1;
                            key[1].key = &pinfo->num;
                            key[2].length = 0;
                            key[2].key = NULL;

                            params = (rlc_ue_parameters *)wmem_tree_lookup32_array_le(ue_parameters_tree, key);
                            if (params && (params->id != id)) {
                                params = NULL;
                            }
                            if (params) {
                                if (p_pdcp_nr_info->direction == DIRECTION_UPLINK) {
                                    p_pdcp_nr_info->seqnum_length = params->pdcp_sn_bits_ul;
                                }
                                else {
                                    p_pdcp_nr_info->seqnum_length = params->pdcp_sn_bits_dl;
                                }
                            }
                            break;

                    }
                    break;

                default:
                    /* Shouldn't get here */
                    return;
            }
            p_pdcp_nr_info->bearerId = rlc_info->bearerId;

            /* Assume no SDAP present */
            p_pdcp_nr_info->sdap_header = 0;
            p_pdcp_nr_info->rohc.rohc_compression = FALSE;
            p_pdcp_nr_info->is_retx = FALSE;
            p_pdcp_nr_info->pdu_length = length;

            TRY {
                call_dissector_only(pdcp_nr_handle, pdcp_tvb, pinfo, tree, NULL);
            }
            CATCH_ALL {
            }
            ENDTRY
        }
    }
}

/***************************************************/
/* Transparent mode PDU. Call RRC if configured to */
static void dissect_rlc_nr_tm(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree,
                              int offset,
                              rlc_nr_info *p_rlc_nr_info,
                              proto_item *top_ti)
{
    proto_item *raw_tm_ti;
    proto_item *tm_ti;

    /* Create hidden TM root */
    tm_ti = proto_tree_add_string_format(tree, hf_rlc_nr_tm,
                                         tvb, offset, 0, "", "TM");
    proto_item_set_hidden(tm_ti);

    /* Remaining bytes are all data */
    raw_tm_ti = proto_tree_add_item(tree, hf_rlc_nr_tm_data, tvb, offset, -1, ENC_NA);
    if (!global_rlc_nr_call_rrc_for_ccch) {
        write_pdu_label_and_info(top_ti, NULL, pinfo,
                                 "                               [%u-bytes]", tvb_reported_length_remaining(tvb, offset));
    }

    if (global_rlc_nr_call_rrc_for_ccch) {
        tvbuff_t *rrc_tvb = tvb_new_subset_remaining(tvb, offset);
        volatile dissector_handle_t protocol_handle;

        switch (p_rlc_nr_info->bearerType) {
        case BEARER_TYPE_BCCH_BCH:
            protocol_handle = nr_rrc_bcch_bch;
            break;
        case BEARER_TYPE_BCCH_DL_SCH:
            protocol_handle = nr_rrc_bcch_dl_sch;
            break;
        case BEARER_TYPE_PCCH:
            protocol_handle = nr_rrc_pcch;
            break;
        case BEARER_TYPE_CCCH:
            if (p_rlc_nr_info->direction == DIRECTION_UPLINK) {
                protocol_handle = (tvb_reported_length(rrc_tvb) == 8) ?
                                    nr_rrc_ul_ccch1 : nr_rrc_ul_ccch;
            } else {
                protocol_handle = nr_rrc_dl_ccch;
            }
            break;
        case BEARER_TYPE_SRB:
        case BEARER_TYPE_DRB:
        default:
                /* Shouldn't happen, just return... */
                return;
        }

        /* Hide raw view of bytes */
        proto_item_set_hidden(raw_tm_ti);

        /* Call it (catch exceptions) */
        TRY {
            call_dissector_only(protocol_handle, rrc_tvb, pinfo, tree, NULL);
        }
        CATCH_ALL {
        }
        ENDTRY
    }
}



/***************************************************/
/* Unacknowledged mode PDU                         */
static void dissect_rlc_nr_um(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree,
                               int offset,
                               rlc_nr_info *p_rlc_nr_info,
                               proto_item *top_ti)
{
    guint32 seg_info, sn;
    guint64 reserved;
    proto_item *um_ti;
    proto_tree *um_header_tree;
    proto_item *um_header_ti;
    gboolean is_truncated = FALSE;
    proto_item *truncated_ti;
    proto_item *reserved_ti;
    int start_offset = offset;
    guint32 so = 0;

    /* Hidden UM root */
    um_ti = proto_tree_add_string_format(tree, hf_rlc_nr_um,
                                         tvb, offset, 0, "", "UM");
    proto_item_set_hidden(um_ti);

    /* Add UM header subtree */
    um_header_ti = proto_tree_add_string_format(tree, hf_rlc_nr_um_header,
                                                tvb, offset, 0,
                                                "", "UM header");
    um_header_tree = proto_item_add_subtree(um_header_ti,
                                            ett_rlc_nr_um_header);

    /* Segmentation Info */
    proto_tree_add_item_ret_uint(um_header_tree, hf_rlc_nr_um_si, tvb, offset, 1, ENC_BIG_ENDIAN, &seg_info);
    if (seg_info == 0) {
        reserved_ti = proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_nr_um_reserved,
                                                  tvb, (offset<<3)+2, 6, &reserved, ENC_BIG_ENDIAN);
        offset++;
        if (reserved) {
            expert_add_info(pinfo, reserved_ti, &ei_rlc_nr_reserved_bits_not_zero);
        }
        write_pdu_label_and_info(top_ti, um_header_ti, pinfo, "                             ");
    } else {
        if (p_rlc_nr_info->sequenceNumberLength == UM_SN_LENGTH_6_BITS) {
            proto_tree_add_item_ret_uint(um_header_tree, hf_rlc_nr_um_sn6, tvb, offset, 1, ENC_BIG_ENDIAN, &sn);
            offset++;
        } else if (p_rlc_nr_info->sequenceNumberLength == UM_SN_LENGTH_12_BITS) {
            reserved_ti = proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_nr_um_reserved, tvb,
                                                      (offset<<3)+2, 2, &reserved, ENC_BIG_ENDIAN);
            if (reserved) {
                expert_add_info(pinfo, reserved_ti, &ei_rlc_nr_reserved_bits_not_zero);
            }
            proto_tree_add_item_ret_uint(um_header_tree, hf_rlc_nr_um_sn12, tvb, offset, 2, ENC_BIG_ENDIAN, &sn);
            offset += 2;
        } else {
            /* Invalid length of sequence number */
            proto_tree_add_expert_format(um_header_tree, pinfo, &ei_rlc_nr_um_sn, tvb, 0, 0,
                                         "Invalid sequence number length (%u bits)",
                                         p_rlc_nr_info->sequenceNumberLength);
            return;
        }
        if (seg_info >= 2) {
            proto_tree_add_item_ret_uint(um_header_tree, hf_rlc_nr_um_so, tvb, offset, 2, ENC_BIG_ENDIAN, &so);
            offset += 2;
            write_pdu_label_and_info(top_ti, um_header_ti, pinfo, "            SN=%-6u SO=%-4u", sn, so);
        } else {
            write_pdu_label_and_info(top_ti, um_header_ti, pinfo, "            SN=%-6u        ", sn);
        }
    }

    proto_item_set_len(um_header_ti, offset-start_offset);

    if (global_rlc_nr_headers_expected) {
        /* There might not be any data, if only headers (plus control data) were logged */
        is_truncated = (tvb_captured_length_remaining(tvb, offset) == 0);
        truncated_ti = proto_tree_add_boolean(tree, hf_rlc_nr_header_only, tvb, 0, 0,
                                              is_truncated);
        if (is_truncated) {
            proto_item_set_generated(truncated_ti);
            expert_add_info(pinfo, truncated_ti, &ei_rlc_nr_header_only);
            show_PDU_in_info(pinfo, top_ti, p_rlc_nr_info->pduLength - offset, seg_info);
            return;
        } else {
            proto_item_set_hidden(truncated_ti);
        }
    }

    tvbuff_t *next_tvb = NULL;
    /* Handle reassembly. */
    if (global_rlc_nr_reassemble_um_pdus && seg_info && tvb_reported_length_remaining(tvb, offset) > 0) {
        // Set fragmented flag.
        gboolean save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;
        fragment_head *fh;
        gboolean more_frags = seg_info & 0x01;
        /* TODO: This should be unique enough, but is there a way to get frame number of first frame in reassembly table? */
        guint32 id = p_rlc_nr_info->direction +       /* 1 bit */
                    (p_rlc_nr_info->ueid<<1) +        /* 7 bits */
                    (p_rlc_nr_info->bearerId<<8) +    /* 5 bits */
                    (sn<<13);                         /* Leave 19 bits for SN - overlaps with other fields but room to overflow into msb */

        fh = fragment_add(&pdu_reassembly_table, tvb, offset, pinfo,
                          id,                                         /* id */
                          GUINT_TO_POINTER(id),                       /* data */
                          so,                                         /* frag_offset */
                          tvb_reported_length_remaining(tvb, offset), /* frag_data_len */
                          more_frags                                  /* more_frags */
                          );

        gboolean update_col_info = TRUE;
        next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled RLC SDU",
                                            fh, &rlc_nr_frag_items,
                                            &update_col_info, tree);
        pinfo->fragmented = save_fragmented;
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        show_PDU_in_tree(pinfo, tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
                         p_rlc_nr_info, seg_info, FALSE);
        show_PDU_in_info(pinfo, top_ti, tvb_reported_length_remaining(tvb, offset), seg_info);
        /* Also add reassembled PDU */
        if (next_tvb) {
            add_new_data_source(pinfo, next_tvb, "Reassembled RLC-NR PDU");
            show_PDU_in_tree(pinfo, tree, next_tvb, 0, tvb_captured_length(next_tvb),
                             p_rlc_nr_info, seg_info, TRUE);
        }
    } else if (!global_rlc_nr_headers_expected) {
        /* Report that expected data was missing (unless we know it might happen) */
        expert_add_info(pinfo, um_header_ti, &ei_rlc_nr_um_data_no_data);
    }
}



/* Dissect an AM STATUS PDU */
static void dissect_rlc_nr_am_status_pdu(tvbuff_t *tvb,
                                         packet_info *pinfo,
                                         proto_tree *tree,
                                         proto_item *status_ti,
                                         int offset,
                                         proto_item *top_ti,
                                         rlc_nr_info *p_rlc_nr_info)
{
    guint8     sn_size, reserved_bits1, reserved_bits2;
    guint32    cpt, sn_limit, nack_count = 0;
    guint64    ack_sn, nack_sn;
    guint64    e1, e2, e3, reserved;
    guint32    so_start, so_end, nack_range;
    int        bit_offset = offset << 3;
    proto_item *ti;

    /****************************************************************/
    /* Part of RLC control PDU header                               */

    /* Control PDU Type (CPT) */
    ti = proto_tree_add_item_ret_uint(tree, hf_rlc_nr_am_cpt, tvb, offset, 1, ENC_BIG_ENDIAN, &cpt);
    if (cpt != 0) {
        /* Protest and stop - only know about STATUS PDUs */
        expert_add_info_format(pinfo, ti, &ei_rlc_nr_am_cpt,
                               "RLC Control frame type %u not handled", cpt);
        return;
    }

    if (p_rlc_nr_info->sequenceNumberLength == AM_SN_LENGTH_12_BITS) {
        sn_size = 12;
        sn_limit = 4096;
        reserved_bits1 = 7;
        reserved_bits2 = 1;
    } else if (p_rlc_nr_info->sequenceNumberLength == AM_SN_LENGTH_18_BITS) {
        sn_size = 18;
        sn_limit = 262044;
        reserved_bits1 = 1;
        reserved_bits2 = 3;
    } else {
        proto_tree_add_expert_format(tree, pinfo, &ei_rlc_nr_am_sn, tvb, 0, 0,
                                     "Invalid sequence number length (%u bits)",
                                     p_rlc_nr_info->sequenceNumberLength);
        return;
    }

    /* The Status PDU itself starts 4 bits into the byte */
    bit_offset += 4;

    /* ACK SN */
    proto_tree_add_bits_ret_val(tree, hf_rlc_nr_am_ack_sn, tvb,
                                bit_offset, sn_size, &ack_sn, ENC_BIG_ENDIAN);
    bit_offset += sn_size;
    write_pdu_label_and_info(top_ti, status_ti, pinfo, "  ACK_SN=%-6u", (guint32)ack_sn);

    /* E1 */
    proto_tree_add_bits_ret_val(tree, hf_rlc_nr_am_e1, tvb,
                                bit_offset, 1, &e1, ENC_BIG_ENDIAN);
    bit_offset++;

    /* Reserved bits */
    ti = proto_tree_add_bits_ret_val(tree, hf_rlc_nr_am_reserved, tvb, bit_offset,
                                     reserved_bits1, &reserved, ENC_BIG_ENDIAN);
    bit_offset += reserved_bits1;
    if (reserved) {
        expert_add_info(pinfo, ti, &ei_rlc_nr_reserved_bits_not_zero);
    }

    /* Optional, extra fields */
    while (e1) {
        proto_item *nack_ti;

        /****************************/
        /* Read NACK_SN, E1, E2, E3 */

        /* NACK_SN */
        nack_ti = proto_tree_add_bits_ret_val(tree, hf_rlc_nr_am_nack_sn, tvb,
                                              bit_offset, sn_size, &nack_sn, ENC_BIG_ENDIAN);
        bit_offset += sn_size;
        write_pdu_label_and_info(top_ti, NULL, pinfo, "  NACK_SN=%-6u", (guint32)nack_sn);

        /* We shouldn't NACK the ACK_SN! */
        if (nack_sn == ack_sn) {
            expert_add_info_format(pinfo, nack_ti, &ei_rlc_nr_am_nack_sn_ack_same,
                                   "Status PDU shouldn't ACK and NACK the same sequence number (%" G_GINT64_MODIFIER "u)",
                                   ack_sn);
        }

        /* NACK should always be 'behind' the ACK */
        if ((sn_limit + ack_sn - nack_sn) % sn_limit > (sn_limit>>1)) {
            expert_add_info(pinfo, nack_ti, &ei_rlc_nr_am_nack_sn_ahead_ack);
        }

        nack_count++;

        /* E1 */
        proto_tree_add_bits_ret_val(tree, hf_rlc_nr_am_e1, tvb,
                                    bit_offset, 1, &e1, ENC_BIG_ENDIAN);
        bit_offset++;

        /* E2 */
        proto_tree_add_bits_ret_val(tree, hf_rlc_nr_am_e2, tvb,
                                    bit_offset, 1, &e2, ENC_BIG_ENDIAN);
        bit_offset++;

        /* Report as expert info */
        if (e2) {
            expert_add_info_format(pinfo, nack_ti, &ei_rlc_nr_am_nack_sn_partial,
                                   "Status PDU reports NACK (partial) on %s for UE %u",
                                   val_to_str_const(p_rlc_nr_info->direction, direction_vals, "Unknown"),
                                   p_rlc_nr_info->ueid);
        } else {
            expert_add_info_format(pinfo, nack_ti, &ei_rlc_nr_am_nack_sn,
                                   "Status PDU reports NACK on %s for UE %u",
                                   val_to_str_const(p_rlc_nr_info->direction, direction_vals, "Unknown"),
                                   p_rlc_nr_info->ueid);
        }

        /* E3 */
        proto_tree_add_bits_ret_val(tree, hf_rlc_nr_am_e3, tvb,
                                    bit_offset, 1, &e3, ENC_BIG_ENDIAN);
        bit_offset++;

        /* Reserved bits */
        ti = proto_tree_add_bits_ret_val(tree, hf_rlc_nr_am_reserved, tvb, bit_offset,
                                         reserved_bits2, &reserved, ENC_BIG_ENDIAN);
        bit_offset += reserved_bits2;
        if (reserved) {
            expert_add_info(pinfo, ti, &ei_rlc_nr_reserved_bits_not_zero);
        }

        if (e2) {
            /* Read SOstart, SOend */
            proto_tree_add_item_ret_uint(tree, hf_rlc_nr_am_so_start, tvb,
                                         bit_offset>>3, 2, ENC_BIG_ENDIAN, &so_start);
            bit_offset += 16;

            proto_tree_add_item_ret_uint(tree, hf_rlc_nr_am_so_end, tvb,
                                         bit_offset>>3, 2, ENC_BIG_ENDIAN, &so_end);
            bit_offset += 16;


            if (so_end == 0xffff) {
                write_pdu_label_and_info(top_ti, NULL, pinfo,
                                         " (SOstart=%u SOend=<END-OF_SDU>)",
                                         so_start);
            } else {
                write_pdu_label_and_info(top_ti, NULL, pinfo,
                                         " (SOstart=%u SOend=%u)",
                                         so_start, so_end);
            }
        }

        if (e3) {
            proto_item *nack_range_ti;

            /* Read NACK range */
            nack_range_ti = proto_tree_add_item_ret_uint(tree, hf_rlc_nr_am_nack_range, tvb,
                                                         bit_offset>>3, 1, ENC_BIG_ENDIAN, &nack_range);
            bit_offset += 8;
            if (nack_range == 0) {
                expert_add_info(pinfo, nack_range_ti, &ei_rlc_nr_am_nack_range);
            } else {
                nack_count += nack_range-1;
            }

            write_pdu_label_and_info(top_ti, NULL, pinfo," NACK range=%u", nack_range);
        }
    }

    if (nack_count > 0) {
        proto_item *count_ti = proto_tree_add_uint(tree, hf_rlc_nr_am_nacks, tvb, 0, 1, nack_count);
        proto_item_set_generated(count_ti);
        proto_item_append_text(status_ti, "  (%u NACKs)", nack_count);
    }

    /* Check that we've reached the end of the PDU. If not, show malformed */
    offset = (bit_offset+7) / 8;
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        expert_add_info_format(pinfo, status_ti, &ei_rlc_nr_bytes_after_status_pdu_complete,
                               "%cL %u bytes remaining after Status PDU complete",
                               (p_rlc_nr_info->direction == DIRECTION_UPLINK) ? 'U' : 'D',
                               tvb_reported_length_remaining(tvb, offset));
    }

    /* Set selected length of control tree */
    proto_item_set_len(status_ti, offset);
}


/***************************************************/
/* Acknowledged mode PDU                           */
static void dissect_rlc_nr_am(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree,
                              int offset,
                              rlc_nr_info *p_rlc_nr_info,
                              proto_item *top_ti)
{
    gboolean dc, polling;
    guint32 seg_info, sn;
    guint64 reserved;
    proto_item *am_ti;
    proto_tree *am_header_tree;
    proto_item *am_header_ti;
    gint   start_offset = offset;
    gboolean is_truncated = FALSE;
    proto_item *truncated_ti;
    proto_item *reserved_ti;

    /* Hidden AM root */
    am_ti = proto_tree_add_string_format(tree, hf_rlc_nr_am,
                                         tvb, offset, 0, "", "AM");
    proto_item_set_hidden(am_ti);

    /* Add AM header subtree */
    am_header_ti = proto_tree_add_string_format(tree, hf_rlc_nr_am_header,
                                                tvb, offset, 0,
                                                "", "AM Header ");
    am_header_tree = proto_item_add_subtree(am_header_ti,
                                            ett_rlc_nr_am_header);

    /* First bit is Data/Control flag */
    proto_tree_add_item_ret_boolean(am_header_tree, hf_rlc_nr_am_data_control,
                                    tvb, offset, 1, ENC_BIG_ENDIAN, &dc);

    if (dc == 0) {
        /**********************/
        /* Status PDU         */
        write_pdu_label_and_info_literal(top_ti, NULL, pinfo, " [CONTROL]");

        /* Control PDUs are a completely separate format  */
        dissect_rlc_nr_am_status_pdu(tvb, pinfo, am_header_tree, am_header_ti,
                                     offset, top_ti, p_rlc_nr_info);
        return;
    }

    /**********************/
    /* Data PDU           */
    write_pdu_label_and_info_literal(top_ti, NULL, pinfo, " [DATA]");

    /* Polling bit */
    proto_tree_add_item_ret_boolean(am_header_tree, hf_rlc_nr_am_p, tvb,
                                    offset, 1, ENC_BIG_ENDIAN, &polling);

    write_pdu_label_and_info_literal(top_ti, NULL, pinfo, (polling) ? " (P) " : "     ");
    if (polling) {
        proto_item_append_text(am_header_ti, " (P) ");
    }

    /* Segmentation Info */
    proto_tree_add_item_ret_uint(am_header_tree, hf_rlc_nr_am_si, tvb,
                                 offset, 1, ENC_BIG_ENDIAN, &seg_info);

    /* Sequence Number */
    if (p_rlc_nr_info->sequenceNumberLength == AM_SN_LENGTH_12_BITS) {
        proto_tree_add_item_ret_uint(am_header_tree, hf_rlc_nr_am_sn12, tvb,
                                     offset, 2, ENC_BIG_ENDIAN, &sn);
        offset += 2;
    } else if (p_rlc_nr_info->sequenceNumberLength == AM_SN_LENGTH_18_BITS) {
        reserved_ti = proto_tree_add_bits_ret_val(am_header_tree, hf_rlc_nr_am_reserved, tvb,
                                                  (offset<<3)+4, 2, &reserved, ENC_BIG_ENDIAN);
        if (reserved) {
            expert_add_info(pinfo, reserved_ti, &ei_rlc_nr_reserved_bits_not_zero);
        }
        proto_tree_add_item_ret_uint(am_header_tree, hf_rlc_nr_am_sn18, tvb,
                                     offset, 3, ENC_BIG_ENDIAN, &sn);
        offset += 3;
    } else {
        /* Invalid length of sequence number */
        proto_tree_add_expert_format(am_header_tree, pinfo, &ei_rlc_nr_am_sn, tvb, 0, 0,
                                     "Invalid sequence number length (%u bits)",
                                     p_rlc_nr_info->sequenceNumberLength);
        return;
    }

    /* Segmentation Information */
    if (seg_info >= 2) {
        guint32 so;

        proto_tree_add_item_ret_uint(am_header_tree, hf_rlc_nr_am_so, tvb,
                                     offset, 2, ENC_BIG_ENDIAN, &so);
        offset += 2;
        write_pdu_label_and_info(top_ti, am_header_ti, pinfo, "SN=%-6u SO=%-4u",sn, so);
    } else {
        write_pdu_label_and_info(top_ti, am_header_ti, pinfo, "SN=%-6u        ", sn);
    }

    /* Header is now complete */
    proto_item_set_len(am_header_ti, offset-start_offset);

    /* There might not be any data, if only headers (plus control data) were logged */
    if (global_rlc_nr_headers_expected) {
        is_truncated = (tvb_captured_length_remaining(tvb, offset) == 0);
        truncated_ti = proto_tree_add_boolean(tree, hf_rlc_nr_header_only, tvb, 0, 0,
                                              is_truncated);
        if (is_truncated) {
            proto_item_set_generated(truncated_ti);
            expert_add_info(pinfo, truncated_ti, &ei_rlc_nr_header_only);
            show_PDU_in_info(pinfo, top_ti, p_rlc_nr_info->pduLength - offset, seg_info);
            return;
        } else {
            proto_item_set_hidden(truncated_ti);
        }
    }

    /* Data */
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        show_PDU_in_tree(pinfo, tree, tvb, offset, tvb_reported_length_remaining(tvb, offset),
                         p_rlc_nr_info, seg_info, FALSE);
        show_PDU_in_info(pinfo, top_ti, tvb_reported_length_remaining(tvb, offset), seg_info);
    } else if (!global_rlc_nr_headers_expected) {
        /* Report that expected data was missing (unless we know it might happen) */
        expert_add_info(pinfo, am_header_ti, &ei_rlc_nr_am_data_no_data);
    }
}


/* Heuristic dissector looks for supported framing protocol (see header file for details) */
static gboolean dissect_rlc_nr_heur(tvbuff_t *tvb, packet_info *pinfo,
                                    proto_tree *tree, void *data _U_)
{
    gint        offset = 0;
    rlc_nr_info *p_rlc_nr_info;
    tvbuff_t    *rlc_tvb;
    guint8      tag;

    /* Do this again on re-dissection to re-discover offset of actual PDU */

    /* Needs to be at least as long as:
       - the signature string
       - fixed header bytes
       - tag for data
       - at least one byte of RLC PDU payload */
    if (tvb_captured_length_remaining(tvb, offset) < (gint)(strlen(RLC_NR_START_STRING)+2+2)) {
        return FALSE;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, RLC_NR_START_STRING, (gint)strlen(RLC_NR_START_STRING)) != 0) {
        return FALSE;
    }
    offset += (gint)strlen(RLC_NR_START_STRING);


    /* If redissecting, use previous info struct (if available) */
    p_rlc_nr_info = (rlc_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_nr, 0);
    if (p_rlc_nr_info == NULL) {
        /* Allocate new info struct for this frame */
        p_rlc_nr_info = wmem_new0(wmem_file_scope(), struct rlc_nr_info);

        /* Read fixed fields */
        p_rlc_nr_info->rlcMode = tvb_get_guint8(tvb, offset++);
        p_rlc_nr_info->sequenceNumberLength = tvb_get_guint8(tvb, offset++);

        /* Read optional fields */
        do {
            /* Process next tag */
            tag = tvb_get_guint8(tvb, offset++);
            switch (tag) {
                case RLC_NR_DIRECTION_TAG:
                    p_rlc_nr_info->direction = tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case RLC_NR_UEID_TAG:
                    p_rlc_nr_info->ueid = tvb_get_ntohs(tvb, offset);
                    offset += 2;
                    break;
                case RLC_NR_BEARER_TYPE_TAG:
                    p_rlc_nr_info->bearerType = tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case RLC_NR_BEARER_ID_TAG:
                    p_rlc_nr_info->bearerId = tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case RLC_NR_PAYLOAD_TAG:
                    /* Have reached data, so set payload length and get out of loop */
                    p_rlc_nr_info->pduLength = tvb_reported_length_remaining(tvb, offset);
                    break;
                default:
                    /* It must be a recognised tag */
                    {
                        proto_item *ti;
                        proto_tree *subtree;

                        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC-NR");
                        col_clear(pinfo->cinfo, COL_INFO);
                        ti = proto_tree_add_item(tree, proto_rlc_nr, tvb, offset, tvb_reported_length(tvb), ENC_NA);
                        subtree = proto_item_add_subtree(ti, ett_rlc_nr);
                        proto_tree_add_expert(subtree, pinfo, &ei_rlc_nr_unknown_udp_framing_tag,
                                              tvb, offset-1, 1);
                    }
                    wmem_free(wmem_file_scope(), p_rlc_nr_info);
                    return TRUE;
            }
        } while (tag != RLC_NR_PAYLOAD_TAG);

        /* Store info in packet */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_rlc_nr, 0, p_rlc_nr_info);
    } else {
        offset = tvb_reported_length(tvb) - p_rlc_nr_info->pduLength;
    }

    /**************************************/
    /* OK, now dissect as RLC NR          */

    /* Create tvb that starts at actual RLC PDU */
    rlc_tvb = tvb_new_subset_remaining(tvb, offset);
    dissect_rlc_nr_common(rlc_tvb, pinfo, tree, TRUE);
    return TRUE;
}

/*****************************/
/* Main dissection function. */
/*****************************/

static int dissect_rlc_nr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_rlc_nr_common(tvb, pinfo, tree, FALSE);
    return tvb_captured_length(tvb);
}

static void dissect_rlc_nr_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_udp_framing)
{
    proto_tree             *rlc_nr_tree;
    proto_tree             *context_tree;
    proto_item             *top_ti;
    proto_item             *context_ti;
    proto_item             *ti;
    proto_item             *mode_ti;
    gint                   offset = 0;
    struct rlc_nr_info     *p_rlc_nr_info;

    /* Set protocol name */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC-NR");

    /* Create protocol tree. */
    top_ti = proto_tree_add_item(tree, proto_rlc_nr, tvb, offset, -1, ENC_NA);
    rlc_nr_tree = proto_item_add_subtree(top_ti, ett_rlc_nr);


    /* Look for packet info! */
    p_rlc_nr_info = (rlc_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_nr, 0);

    /* Can't dissect anything without it... */
    if (p_rlc_nr_info == NULL) {
        proto_tree_add_expert(rlc_nr_tree, pinfo, &ei_rlc_nr_no_per_frame_info, tvb, offset, -1);
        return;
    }

    /* Clear info column when using UDP framing */
    if (is_udp_framing) {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    /*****************************************/
    /* Show context information              */

    /* Create context root */
    context_ti = proto_tree_add_string_format(rlc_nr_tree, hf_rlc_nr_context,
                                              tvb, offset, 0, "", "Context");
    context_tree = proto_item_add_subtree(context_ti, ett_rlc_nr_context);
    proto_item_set_generated(context_ti);

    ti = proto_tree_add_uint(context_tree, hf_rlc_nr_context_direction,
                             tvb, 0, 0, p_rlc_nr_info->direction);
    proto_item_set_generated(ti);

    mode_ti = proto_tree_add_uint(context_tree, hf_rlc_nr_context_mode,
                                  tvb, 0, 0, p_rlc_nr_info->rlcMode);
    proto_item_set_generated(mode_ti);

    if (p_rlc_nr_info->ueid != 0) {
        ti = proto_tree_add_uint(context_tree, hf_rlc_nr_context_ueid,
                                 tvb, 0, 0, p_rlc_nr_info->ueid);
        proto_item_set_generated(ti);
    }

    ti = proto_tree_add_uint(context_tree, hf_rlc_nr_context_bearer_type,
                             tvb, 0, 0, p_rlc_nr_info->bearerType);
    proto_item_set_generated(ti);

    if ((p_rlc_nr_info->bearerType == BEARER_TYPE_SRB) ||
        (p_rlc_nr_info->bearerType == BEARER_TYPE_DRB)) {
        ti = proto_tree_add_uint(context_tree, hf_rlc_nr_context_bearer_id,
                                 tvb, 0, 0, p_rlc_nr_info->bearerId);
        proto_item_set_generated(ti);
    }

    ti = proto_tree_add_uint(context_tree, hf_rlc_nr_context_pdu_length,
                             tvb, 0, 0, p_rlc_nr_info->pduLength);
    proto_item_set_generated(ti);

    if (p_rlc_nr_info->rlcMode != RLC_TM_MODE) {
        ti = proto_tree_add_uint(context_tree, hf_rlc_nr_context_sn_length,
                                 tvb, 0, 0, p_rlc_nr_info->sequenceNumberLength);
        proto_item_set_generated(ti);
    }

    /* Append highlights to top-level item */
    if (p_rlc_nr_info->ueid != 0) {
        proto_item_append_text(top_ti, "   UEId=%u", p_rlc_nr_info->ueid);
        col_append_fstr(pinfo->cinfo, COL_INFO, "UEId=%-4u ", p_rlc_nr_info->ueid);
    }

    /* Append context highlights to info column */
    write_pdu_label_and_info(top_ti, NULL, pinfo,
                             " [%s] [%s] ",
                             (p_rlc_nr_info->direction == 0) ? "UL" : "DL",
                             val_to_str_const(p_rlc_nr_info->rlcMode, rlc_mode_short_vals, "Unknown"));

    if (p_rlc_nr_info->bearerId == 0) {
        write_pdu_label_and_info(top_ti, NULL, pinfo, "%s   ",
                                 val_to_str_const(p_rlc_nr_info->bearerType, rlc_bearer_type_vals, "Unknown"));
    } else {
        write_pdu_label_and_info(top_ti, NULL, pinfo, "%s:%-2u",
                                 val_to_str_const(p_rlc_nr_info->bearerType, rlc_bearer_type_vals, "Unknown"),
                                 p_rlc_nr_info->bearerId);
    }

    /* Dissect the RLC PDU itself. Format depends upon mode... */
    switch (p_rlc_nr_info->rlcMode) {

        case RLC_TM_MODE:
            dissect_rlc_nr_tm(tvb, pinfo, rlc_nr_tree, offset, p_rlc_nr_info, top_ti);
            break;

        case RLC_UM_MODE:
            dissect_rlc_nr_um(tvb, pinfo, rlc_nr_tree, offset, p_rlc_nr_info, top_ti);
            break;

        case RLC_AM_MODE:
            dissect_rlc_nr_am(tvb, pinfo, rlc_nr_tree, offset, p_rlc_nr_info, top_ti);
            break;

        default:
            /* Error - unrecognised mode */
            expert_add_info_format(pinfo, mode_ti, &ei_rlc_nr_context_mode,
                                   "Unrecognised RLC Mode set (%u)", p_rlc_nr_info->rlcMode);
            break;
    }
}


/* Configure number of PDCP SN bits to use for DRB channels */
void set_rlc_nr_drb_pdcp_seqnum_length(packet_info *pinfo, guint16 ueid, guint8 drbid,
                                       guint8 userplane_seqnum_length_ul,
                                       guint8 userplane_seqnum_length_dl)
{
    wmem_tree_key_t key[3];
    guint32 id;
    rlc_ue_parameters *params;

    if (PINFO_FD_VISITED(pinfo)) {
        return;
    }

    id = (drbid << 16) | ueid;
    key[0].length = 1;
    key[0].key = &id;
    key[1].length = 1;
    key[1].key = &pinfo->num;
    key[2].length = 0;
    key[2].key = NULL;

    params = (rlc_ue_parameters *)wmem_tree_lookup32_array_le(ue_parameters_tree, key);
    if (params && (params->id != id)) {
        params = NULL;
    }
    if (params == NULL) {
        params = (rlc_ue_parameters *)wmem_new(wmem_file_scope(), rlc_ue_parameters);
        params->id = id;
        wmem_tree_insert32_array(ue_parameters_tree, key, (void *)params);
    }
    params->pdcp_sn_bits_ul = userplane_seqnum_length_ul;
    params->pdcp_sn_bits_dl = userplane_seqnum_length_dl;
}


void proto_register_rlc_nr(void)
{
    static hf_register_info hf[] =
    {
        /**********************************/
        /* Items for decoding context     */
        { &hf_rlc_nr_context,
            { "Context",
              "rlc-nr.context", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_context_mode,
            { "RLC Mode",
              "rlc-nr.mode", FT_UINT8, BASE_DEC, VALS(rlc_mode_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_context_direction,
            { "Direction",
              "rlc-nr.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_rlc_nr_context_ueid,
            { "UEId",
              "rlc-nr.ueid", FT_UINT16, BASE_DEC, 0, 0x0,
              "User Equipment Identifier associated with message", HFILL
            }
        },
        { &hf_rlc_nr_context_bearer_type,
            { "Bearer Type",
              "rlc-nr.bearer-type", FT_UINT16, BASE_DEC, VALS(rlc_bearer_type_vals), 0x0,
              "Bearer Type associated with message", HFILL
            }
        },
        { &hf_rlc_nr_context_bearer_id,
            { "Bearer Id",
              "rlc-nr.bearer-id", FT_UINT16, BASE_DEC, 0, 0x0,
              "Bearer ID associated with message", HFILL
            }
        },
        { &hf_rlc_nr_context_pdu_length,
            { "PDU Length",
              "rlc-nr.pdu-length", FT_UINT16, BASE_DEC, 0, 0x0,
              "Length of PDU (in bytes)", HFILL
            }
        },
        { &hf_rlc_nr_context_sn_length,
            { "Sequence Number length",
              "rlc-nr.seqnum-length", FT_UINT8, BASE_DEC, 0, 0x0,
              "Length of sequence number in bits", HFILL
            }
        },

        /* Transparent mode fields */
        { &hf_rlc_nr_tm,
            { "TM",
              "rlc-nr.tm", FT_STRING, BASE_NONE, NULL, 0x0,
              "Transparent Mode", HFILL
            }
        },
        { &hf_rlc_nr_tm_data,
            { "TM Data",
              "rlc-nr.tm.data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Transparent Mode Data", HFILL
            }
        },

        /* Unacknowledged mode fields */
        { &hf_rlc_nr_um,
            { "UM",
              "rlc-nr.um", FT_STRING, BASE_NONE, NULL, 0x0,
              "Unacknowledged Mode", HFILL
            }
        },
        { &hf_rlc_nr_um_header,
            { "UM Header",
              "rlc-nr.um.header", FT_STRING, BASE_NONE, NULL, 0x0,
              "Unacknowledged Mode Header", HFILL
            }
        },
        { &hf_rlc_nr_um_si,
            { "Segmentation Info",
              "rlc-nr.um.si", FT_UINT8, BASE_HEX, VALS(seg_info_vals), 0xc0,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_um_reserved,
            { "Reserved",
              "rlc-nr.um.reserved", FT_UINT8, BASE_HEX, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_um_sn6,
            { "Sequence Number",
              "rlc-nr.um.sn", FT_UINT8, BASE_DEC, 0, 0x3f,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_um_sn12,
            { "Sequence Number",
              "rlc-nr.um.sn", FT_UINT16, BASE_DEC, 0, 0x0fff,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_um_so,
            { "Segment Offset",
              "rlc-nr.um.so", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_um_data,
            { "UM Data",
              "rlc-nr.um.data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Unacknowledged Mode Data", HFILL
            }
        },

        /* Acknowledged mode fields */
        { &hf_rlc_nr_am,
            { "AM",
              "rlc-nr.am", FT_STRING, BASE_NONE, NULL, 0x0,
              "Acknowledged Mode", HFILL
            }
        },
        { &hf_rlc_nr_am_header,
            { "AM Header",
              "rlc-nr.am.header", FT_STRING, BASE_NONE, NULL, 0x0,
              "Acknowledged Mode Header", HFILL
            }
        },
        { &hf_rlc_nr_am_data_control,
            { "Data/Control",
              "rlc-nr.am.dc", FT_BOOLEAN, 8, TFS(&data_or_control_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_am_p,
            { "Polling Bit",
              "rlc-nr.am.p", FT_BOOLEAN, 8, TFS(&polling_bit_vals), 0x40,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_am_si,
            { "Segmentation Info",
              "rlc-nr.am.si", FT_UINT8, BASE_HEX, VALS(seg_info_vals), 0x30,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_am_sn12,
            { "Sequence Number",
              "rlc-nr.am.sn", FT_UINT16, BASE_DEC, 0, 0x0fff,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_am_sn18,
            { "Sequence Number",
              "rlc-nr.am.sn", FT_UINT24, BASE_DEC, 0, 0x03ffff,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_am_reserved,
            { "Reserved",
              "rlc-nr.am.reserved", FT_UINT8, BASE_HEX, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_am_so,
            { "Segment Offset",
              "rlc-nr.am.so", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_am_data,
            { "AM Data",
              "rlc-nr.am.data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Acknowledged Mode Data", HFILL
            }
        },

        { &hf_rlc_nr_am_cpt,
            { "Control PDU Type",
              "rlc-nr.am.cpt", FT_UINT8, BASE_HEX, VALS(control_pdu_type_vals), 0x70,
              "AM Control PDU Type", HFILL
            }
        },
        { &hf_rlc_nr_am_ack_sn,
            { "ACK Sequence Number",
              "rlc-nr.am.ack-sn", FT_UINT24, BASE_DEC, 0, 0x0,
              "Sequence Number we expect to receive next", HFILL
            }
        },
        { &hf_rlc_nr_am_e1,
            { "Extension bit 1",
              "rlc-nr.am.e1", FT_BOOLEAN, BASE_NONE, TFS(&am_e1_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_am_e2,
            { "Extension bit 2",
              "rlc-nr.am.e2", FT_BOOLEAN, BASE_NONE, TFS(&am_e2_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_am_e3,
            { "Extension bit 3",
              "rlc-nr.am.e3", FT_BOOLEAN, BASE_NONE, TFS(&am_e3_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_nr_am_nacks,
            { "Number of NACKs",
              "rlc-nr.am.nacks", FT_UINT32, BASE_DEC, 0, 0x0,
              "Number of NACKs in this status PDU", HFILL
            }
        },
        { &hf_rlc_nr_am_nack_sn,
            { "NACK Sequence Number",
              "rlc-nr.am.nack-sn", FT_UINT24, BASE_DEC, 0, 0x0,
              "Negative Acknowledgement Sequence Number", HFILL
            }
        },
        { &hf_rlc_nr_am_so_start,
            { "SO start",
              "rlc-nr.am.so-start", FT_UINT16, BASE_DEC, 0, 0x0,
              "Segment Offset Start byte index", HFILL
            }
        },
        { &hf_rlc_nr_am_so_end,
            { "SO end",
              "rlc-nr.am.so-end", FT_UINT16, BASE_DEC, 0, 0x0,
              "Segment Offset End byte index", HFILL
            }
        },
        { &hf_rlc_nr_am_nack_range,
            { "NACK range",
              "rlc-nr.am.nack-range", FT_UINT16, BASE_DEC, 0, 0x0,
              "Number of consecutively lost RLC SDUs starting from and including NACK_SN", HFILL
            }
        },

        { &hf_rlc_nr_header_only,
            { "RLC PDU Header only",
              "rlc-nr.header-only", FT_BOOLEAN, BASE_NONE, TFS(&header_only_vals), 0x0,
              NULL, HFILL
            }
        },

        { &hf_rlc_nr_fragment,
          { "RLC-NR fragment",
            "rlc-nr.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rlc_nr_fragments,
          { "RLC-NR fragments",
            "rlc-nr.fragments", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rlc_nr_fragment_overlap,
          { "Fragment overlap",
            "rlc-nr.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_rlc_nr_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap",
            "rlc-nr.fragment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_rlc_nr_fragment_multiple_tails,
          { "Multiple tail fragments found",
            "rlc-nr.fragment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_rlc_nr_fragment_too_long_fragment,
          { "Fragment too long",
            "rlc-nr.fragment.toolongfragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }
        },
        { &hf_rlc_nr_fragment_error,
          { "Defragmentation error",
            "rlc-nr.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_rlc_nr_fragment_count,
          { "Fragment count",
            "rlc-nr.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rlc_nr_reassembled_in,
          { "Reassembled RLC-NR in frame",
            "rlc-nr.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This RLC-NR packet is reassembled in this frame", HFILL }
        },
        { &hf_rlc_nr_reassembled_length,
          { "Reassembled RLC-NR length",
            "rlc-nr.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }
        },
        { &hf_rlc_nr_reassembled_data,
          { "Reassembled payload",
            "rlc-nr.reassembled.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "The reassembled payload", HFILL }
        },

    };

    static gint *ett[] =
    {
        &ett_rlc_nr,
        &ett_rlc_nr_context,
        &ett_rlc_nr_um_header,
        &ett_rlc_nr_am_header,
        &ett_rlc_nr_fragment,
        &ett_rlc_nr_fragments
    };

    static ei_register_info ei[] = {
        { &ei_rlc_nr_reserved_bits_not_zero, { "rlc-nr.reserved-bits-not-zero", PI_MALFORMED, PI_ERROR, "Reserved bits not zero", EXPFILL }},
        { &ei_rlc_nr_um_sn, { "rlc-nr.um.sn.invalid", PI_MALFORMED, PI_ERROR, "Invalid sequence number length", EXPFILL }},
        { &ei_rlc_nr_am_sn, { "rlc-nr.am.sn.invalid", PI_MALFORMED, PI_ERROR, "Invalid sequence number length", EXPFILL }},
        { &ei_rlc_nr_header_only, { "rlc-nr.header-only.expert", PI_SEQUENCE, PI_NOTE, "RLC PDU SDUs have been omitted", EXPFILL }},
        { &ei_rlc_nr_am_cpt, { "rlc-nr.am.cpt.invalid", PI_MALFORMED, PI_ERROR, "RLC Control frame type not handled", EXPFILL }},
        { &ei_rlc_nr_am_nack_sn_ack_same, { "rlc-nr.am.nack-sn.ack-same", PI_MALFORMED, PI_ERROR, "Status PDU shouldn't ACK and NACK the same sequence number", EXPFILL }},
        { &ei_rlc_nr_am_nack_range, { "rlc-nr.am.nack-sn.nack-range", PI_MALFORMED, PI_ERROR, "Status PDU shouldnot contain a NACK range vith value 0", EXPFILL }},
        { &ei_rlc_nr_am_nack_sn_ahead_ack, { "rlc-nr.am.nack-sn.ahead-ack", PI_MALFORMED, PI_ERROR, "NACK must not be ahead of ACK in status PDU", EXPFILL }},
        { &ei_rlc_nr_am_nack_sn_partial, { "rlc-nr.am.nack-sn.partial", PI_SEQUENCE, PI_WARN, "Status PDU reports NACK (partial)", EXPFILL }},
        { &ei_rlc_nr_am_nack_sn, { "rlc-nr.am.nack-sn.expert", PI_SEQUENCE, PI_WARN, "Status PDU reports NACK", EXPFILL }},
        { &ei_rlc_nr_bytes_after_status_pdu_complete, { "rlc-nr.bytes-after-status-pdu-complete", PI_MALFORMED, PI_ERROR, "bytes remaining after Status PDU complete", EXPFILL }},
        { &ei_rlc_nr_um_data_no_data, { "rlc-nr.um-data.no-data", PI_MALFORMED, PI_ERROR, "UM data PDU doesn't contain any data", EXPFILL }},
        { &ei_rlc_nr_am_data_no_data, { "rlc-nr.am-data.no-data", PI_MALFORMED, PI_ERROR, "AM data PDU doesn't contain any data", EXPFILL }},
        { &ei_rlc_nr_context_mode, { "rlc-nr.mode.invalid", PI_MALFORMED, PI_ERROR, "Unrecognised RLC Mode set", EXPFILL }},
        { &ei_rlc_nr_no_per_frame_info, { "rlc-nr.no-per-frame-info", PI_UNDECODED, PI_ERROR, "Can't dissect NR RLC frame because no per-frame info was attached!", EXPFILL }},
        { &ei_rlc_nr_unknown_udp_framing_tag, { "rlc-nr.unknown-udp-framing-tag", PI_UNDECODED, PI_WARN, "Unknown UDP framing tag, aborting dissection", EXPFILL }}
    };

    module_t *rlc_nr_module;
    expert_module_t* expert_rlc_nr;

    /* Register protocol. */
    proto_rlc_nr = proto_register_protocol("RLC-NR", "RLC-NR", "rlc-nr");
    proto_register_field_array(proto_rlc_nr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_rlc_nr = expert_register_protocol(proto_rlc_nr);
    expert_register_field_array(expert_rlc_nr, ei, array_length(ei));

    /* Allow other dissectors to find this one by name. */
    register_dissector("rlc-nr", dissect_rlc_nr, proto_rlc_nr);

    /* Preferences */
    rlc_nr_module = prefs_register_protocol(proto_rlc_nr, NULL);

    prefs_register_bool_preference(rlc_nr_module, "call_pdcp_for_srb",
        "Call PDCP dissector for SRB PDUs",
        "Call PDCP dissector for signalling PDUs.  Note that without reassembly, it can"
        "only be called for complete PDUs (i.e. not segmented over RLC)",
        &global_rlc_nr_call_pdcp_for_srb);

    prefs_register_enum_preference(rlc_nr_module, "call_pdcp_for_ul_drb",
        "Call PDCP dissector for UL DRB PDUs",
        "Call PDCP dissector for UL user-plane PDUs.  Note that without reassembly, it can"
        "only be called for complete PDUs (i.e. not segmented over RLC)",
        &global_rlc_nr_call_pdcp_for_ul_drb, pdcp_drb_col_vals, FALSE);

    prefs_register_enum_preference(rlc_nr_module, "call_pdcp_for_dl_drb",
        "Call PDCP dissector for DL DRB PDUs",
        "Call PDCP dissector for DL user-plane PDUs.  Note that without reassembly, it can"
        "only be called for complete PDUs (i.e. not segmented over RLC)",
        &global_rlc_nr_call_pdcp_for_dl_drb, pdcp_drb_col_vals, FALSE);

    prefs_register_bool_preference(rlc_nr_module, "call_rrc_for_ccch",
        "Call RRC dissector for CCCH PDUs",
        "Call RRC dissector for CCCH PDUs",
        &global_rlc_nr_call_rrc_for_ccch);

    prefs_register_bool_preference(rlc_nr_module, "header_only_mode",
        "May see RLC headers only",
        "When enabled, if data is not present, don't report as an error, but instead "
        "add expert info to indicate that headers were omitted",
        &global_rlc_nr_headers_expected);

    prefs_register_bool_preference(rlc_nr_module, "reassemble_um_frames",
        "Try to reassemble UM frames",
        "N.B. This should be considered experimental/incomplete, in that it doesn't try to discard reassembled state "
        "when reestablishmenment happens, or in certain packet-loss cases",
        &global_rlc_nr_reassemble_um_pdus);

    ue_parameters_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    /* Register reassembly table. */
    reassembly_table_register(&pdu_reassembly_table, &pdu_reassembly_table_functions);
}

void proto_reg_handoff_rlc_nr(void)
{
    /* Add as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_rlc_nr_heur, "RLC-NR over UDP", "rlc_nr_udp", proto_rlc_nr, HEURISTIC_DISABLE);

    pdcp_nr_handle = find_dissector("pdcp-nr");
    nr_rrc_bcch_bch = find_dissector_add_dependency("nr-rrc.bcch.bch", proto_rlc_nr);
    nr_rrc_bcch_dl_sch = find_dissector_add_dependency("nr-rrc.bcch.dl.sch", proto_rlc_nr);
    nr_rrc_pcch = find_dissector_add_dependency("nr-rrc.pcch", proto_pdcp_nr);
    nr_rrc_ul_ccch = find_dissector_add_dependency("nr-rrc.ul.ccch", proto_rlc_nr);
    nr_rrc_ul_ccch1 = find_dissector_add_dependency("nr-rrc.ul.ccch1", proto_rlc_nr);
    nr_rrc_dl_ccch = find_dissector_add_dependency("nr-rrc.dl.ccch", proto_rlc_nr);
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
