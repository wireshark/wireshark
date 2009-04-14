/* Routines for LTE RLC disassembly
 *
 * Martin Mathieson
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include "packet-rlc-lte.h"


/* Described in:
 * 3GPP TS 36.322 Evolved Universal Terrestial Radio Access (E-UTRA)
 * Radio Link Control (RLC) Protocol specification
 */

/* TODO:
   - AM sequence analysis/re-assembly
*/


/* By default try to analyse the sequence of messages for UM/AM channels */
static gboolean global_rlc_lte_sequence_analysis = TRUE;



/* Initialize the protocol and registered fields. */
int proto_rlc_lte = -1;

/* Decoding context */
static int hf_rlc_lte_context_mode = -1;
static int hf_rlc_lte_context_direction = -1;
static int hf_rlc_lte_context_priority = -1;
static int hf_rlc_lte_context_ueid = -1;
static int hf_rlc_lte_context_channel_type = -1;
static int hf_rlc_lte_context_channel_id = -1;
static int hf_rlc_lte_context_pdu_length = -1;
static int hf_rlc_lte_context_um_sn_length = -1;

/* Transparent mode fields */
static int hf_rlc_lte_tm_data = -1;

/* Unacknowledged mode fields */
static int hf_rlc_lte_um_header = -1;
static int hf_rlc_lte_um_fi = -1;
static int hf_rlc_lte_um_fixed_e = -1;
static int hf_rlc_lte_um_sn = -1;
static int hf_rlc_lte_um_fixed_reserved = -1;
static int hf_rlc_lte_um_data = -1;
static int hf_rlc_lte_extension_part = -1;

/* Extended header (common to UM and AM) */
static int hf_rlc_lte_extension_e = -1;
static int hf_rlc_lte_extension_li = -1;
static int hf_rlc_lte_extension_padding = -1;


/* Acknowledged mode fields */
static int hf_rlc_lte_am_header = -1;
static int hf_rlc_lte_am_data_control = -1;
static int hf_rlc_lte_am_rf = -1;
static int hf_rlc_lte_am_p = -1;
static int hf_rlc_lte_am_fi = -1;
static int hf_rlc_lte_am_fixed_e = -1;
static int hf_rlc_lte_am_fixed_sn = -1;
static int hf_rlc_lte_am_segment_lsf = -1;
static int hf_rlc_lte_am_segment_so = -1;
static int hf_rlc_lte_am_data = -1;

/* Control fields */
static int hf_rlc_lte_am_cpt = -1;
static int hf_rlc_lte_am_ack_sn = -1;
static int hf_rlc_lte_am_e1 = -1;
static int hf_rlc_lte_am_e2 = -1;
static int hf_rlc_lte_am_nack_sn = -1;
static int hf_rlc_lte_am_so_start = -1;
static int hf_rlc_lte_am_so_end = -1;

static int hf_rlc_lte_predefined_pdu = -1;

/* Sequence Analysis */
static int hf_rlc_lte_sequence_analysis = -1;
static int hf_rlc_lte_sequence_analysis_previous_frame = -1;
static int hf_rlc_lte_sequence_analysis_expected_sn = -1;
static int hf_rlc_lte_sequence_analysis_framing_info_correct = -1;


/* Subtrees. */
static int ett_rlc_lte = -1;
static int ett_rlc_lte_um_header = -1;
static int ett_rlc_lte_am_header = -1;
static int ett_rlc_lte_extension_part = -1;
static int ett_rlc_lte_sequence_analysis = -1;


static const value_string direction_vals[] =
{
    { DIRECTION_UPLINK,      "Uplink"},
    { DIRECTION_DOWNLINK,    "Downlink"},
    { 0, NULL }
};

static const value_string rlc_mode_short_vals[] =
{
    { RLC_TM_MODE,      "TM"},
    { RLC_UM_MODE,      "UM"},
    { RLC_AM_MODE,      "AM"},
    { RLC_PREDEF,       "PREDEFINED"},
    { 0, NULL }
};

static const value_string rlc_mode_vals[] =
{
    { RLC_TM_MODE,      "Transparent Mode"},
    { RLC_UM_MODE,      "Unacknowledged Mode"},
    { RLC_AM_MODE,      "Acknowledged Mode"},
    { 0, NULL }
};


static const value_string rlc_channel_type_vals[] =
{
    { CHANNEL_TYPE_CCCH,     "CCCH"},
    { CHANNEL_TYPE_BCCH,     "BCCH"},
    { CHANNEL_TYPE_PCCH,     "PCCH"},
    { CHANNEL_TYPE_SRB,      "SRB"},
    { CHANNEL_TYPE_DRB,      "DRB"},
    { 0, NULL }
};


static const value_string framing_info_vals[] =
{
    { 0,      "First byte begins an RLC SDU and last byte ends an RLC SDU"},
    { 1,      "First byte begins an RLC SDU and last byte does not end an RLC SDU"},
    { 2,      "First byte does not begin an RLC SDU and last byte ends an RLC SDU"},
    { 3,      "First byte does not begin an RLC SDU and last byte does not end an RLC SDU"},
    { 0, NULL }
};

static const value_string fixed_extension_vals[] =
{
    { 0,      "Data field follows from the octet following the fixed part of the header"},
    { 1,      "A set of E field and LI field follows from the octet following the fixed part of the header"},
    { 0, NULL }
};

static const value_string extension_extension_vals[] =
{
    { 0,      "Data field follows from the octet following the LI field following this E field"},
    { 1,      "A set of E field and LI field follows from the bit following the LI field following this E field"},
    { 0, NULL }
};

static const value_string data_or_control_vals[] =
{
    { 0,      "Control PDU"},
    { 1,      "Data PDU"},
    { 0, NULL }
};

static const value_string resegmentation_flag_vals[] =
{
    { 0,      "AMD PDU"},
    { 1,      "AND PDU segment"},
    { 0, NULL }
};

static const value_string polling_bit_vals[] =
{
    { 0,      "Status report not requested"},
    { 1,      "Status report is requested"},
    { 0, NULL }
};


static const value_string lsf_vals[] =
{
    { 0,      "Last byte of the AMD PDU segment does not correspond to the last byte of an AMD PDU"},
    { 1,      "Last byte of the AMD PDU segment corresponds to the last byte of an AND PDU"},
    { 0, NULL }
};


static const value_string control_pdu_type_vals[] =
{
    { 0,      "STATUS PDU"},
    { 0, NULL }
};

static const value_string am_e1_vals[] =
{
    { 0,      "A set of NACK_SN, E1 and E2 does not follow"},
    { 1,      "A set of NACK_SN, E1 and E2 follows"},
    { 0, NULL }
};

static const value_string am_e2_vals[] =
{
    { 0,      "A set of SOstart and SOend does not follow for this NACK_SN"},
    { 1,      "A set of SOstart and SOend follows for this NACK_SN"},
    { 0, NULL }
};



/**********************************************************************************/
/* These are for keeping track of UM/AM extension headers, and the lengths found  */
/* in them                                                                        */
guint8  s_number_of_extensions = 0;
#define MAX_RLC_SDUS 64
guint16 s_lengths[MAX_RLC_SDUS];


/* Dissect extension headers (common to both UM and AM) */
static int dissect_rlc_lte_extension_header(tvbuff_t *tvb, packet_info *pinfo,
                                            proto_tree *tree,
                                            int offset)
{
    guint8  isOdd;
    guint64 extension = 1;
    guint64 length;

    /* Reset this count */
    s_number_of_extensions = 0;

    while (extension && (s_number_of_extensions < MAX_RLC_SDUS)) {
        proto_tree *extension_part_tree;
        proto_item *extension_part_ti;

        isOdd = (s_number_of_extensions % 2);

        /* Extension part subtree */
        extension_part_ti = proto_tree_add_string_format(tree,
                                                         hf_rlc_lte_extension_part,
                                                         tvb, offset, 2,
                                                         "",
                                                         "Extension Part");
        extension_part_tree = proto_item_add_subtree(extension_part_ti,
                                                     ett_rlc_lte_extension_part);

        /* Read next extension */
        proto_tree_add_bits_ret_val(extension_part_tree, hf_rlc_lte_extension_e, tvb,
                                   (offset*8) + ((isOdd) ? 4 : 0),
                                    1,
                                    &extension, FALSE);

        /* Read length field */
        proto_tree_add_bits_ret_val(extension_part_tree, hf_rlc_lte_extension_li, tvb,
                                   (offset*8) + ((isOdd) ? 5 : 1),
                                    11,
                                    &length, FALSE);

        proto_item_append_text(extension_part_tree, " (length=%u)", (guint16)length);

        /* Move on to byte of next extension */
        if (isOdd) {
            offset += 2;
        } else {
            offset++;
        }

        s_lengths[s_number_of_extensions++] = (guint16)length;
    }

    /* May need to skip padding after last extension part */
    isOdd = (s_number_of_extensions % 2);
    if (isOdd) {
        guint8 padding;
        proto_item *ti;

        padding = tvb_get_guint8(tvb, offset) & 0x0f;
        ti = proto_tree_add_item(tree, hf_rlc_lte_extension_padding,
                                 tvb, offset, 1, FALSE);
        if (padding != 0) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                      "Extension Header padding not zero (found 0x%x)", padding);
        }
        offset++;
    }

    return offset;
}


/* Show in the info column how many bytes are in the UM/AM PDU, and indicate
   whether or not the beginning and end are included in this packet */
static void show_PDU_in_info(packet_info *pinfo,
                             guint16 length,
                             gboolean first_includes_start,
                             gboolean last_includes_end)
{
    /* Reflect this PDU in the info column */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "  %s%u-byte%s%s",
                        (first_includes_start) ? "[" : "..",
                        length,
                        (length > 1) ? "s" : "",
                        (last_includes_end) ? "]" : "..");
    }
}



/*********************************************************************/
/* UM/AM sequence analysis                                           */

/* Types for RLC channel hash table                                   */
/* This table is maintained during initial dissection of RLC          */
/* frames, mapping from rlc_channel_hash_key -> rlc_channel_status    */

/* Channel key */
typedef struct
{
    guint16 ueId;
    guint8  channelType;
    guint8  channelId;
    guint8  direction;
} rlc_channel_hash_key;

/* Conversation-type status for channel */
typedef struct
{
    guint16  previousSequenceNumber;
    guint32  previousFrameNum;
    gboolean previousSegmentIncomplete;
} rlc_channel_status;


/* Hash table functions for RLC channels */

/* Equal keys */
static gint rlc_channel_equal(gconstpointer v, gconstpointer v2)
{
    const rlc_channel_hash_key* val1 = v;
    const rlc_channel_hash_key* val2 = v2;

    /* All fields must match */
    return ((val1->ueId        == val2->ueId) &&
            (val1->channelType == val2->channelType) &&
            (val1->channelId   == val2->channelId) &&
            (val1->direction   == val2->direction));
}

/* Compute a hash value for a given key. */
static guint rlc_channel_hash_func(gconstpointer v)
{
    const rlc_channel_hash_key* val1 = v;

    /* TODO: check/reduce multipliers */
    return ((val1->ueId * 1024) + (val1->channelType*64) + (val1->channelId*2) + val1->direction);
}

/* The channel hash table instance itself        */
static GHashTable *rlc_lte_channel_hash = NULL;




/* Types for frame report hash table                                    */
/* This is a table from framenum -> state_report_in_frame               */
/* This is necessary because the per-packet info is already being used  */
/* for conext information before the dissector is called                */

/* Info to attach to frame when first read, recording what to show about sequence */
typedef struct
{
    guint8  sequenceExpectedCorrect;
    guint16 sequenceExpected;
    guint32 previousFrameNum;
    guint8  previousSegmentIncomplete;
} state_report_in_frame;


/* Hash table functions for frame reports */

/* Equal keys */
static gint rlc_frame_equal(gconstpointer v, gconstpointer v2)
{
    return (v == v2);
}

/* Compute a hash value for a given key. */
static guint rlc_frame_hash_func(gconstpointer v)
{
    return (guint)v;
}

/* The frame report hash table instance itself   */
static GHashTable *rlc_lte_frame_report_hash = NULL;



/* Add to the tree values associated with sequence analysis for this frame */
static void addChannelSequenceInfo(state_report_in_frame *p,
                                   guint16 sequenceNumber,
                                   guint8  newSegmentStarted,
                                   packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    proto_tree *seqnum_tree;
    proto_item *seqnum_ti;
    proto_item *ti;

    /* Create subtree */
    seqnum_ti = proto_tree_add_string_format(tree,
                                             hf_rlc_lte_sequence_analysis,
                                             tvb, 0, 0,
                                             "",
                                             "Sequence Analysis");
    seqnum_tree = proto_item_add_subtree(seqnum_ti,
                                         ett_rlc_lte_sequence_analysis);
    PROTO_ITEM_SET_GENERATED(seqnum_ti);

    /* Previous channel frame */
    if (p->previousFrameNum != 0) {
        proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_previous_frame,
                            tvb, 0, 0, p->previousFrameNum);
    }

    /* Expected sequence number */
    ti = proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_expected_sn,
                            tvb, 0, 0, p->sequenceExpected);
    PROTO_ITEM_SET_GENERATED(ti);
    if (!p->sequenceExpectedCorrect) {
        /* Incorrect sequence number */
        expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                               "Wrong Sequence Number - got %u, expected %u",
                               sequenceNumber, p->sequenceExpected);
    }
    else {
        /* Correct sequence number, so check frame indication bits consistent */
        if (p->previousSegmentIncomplete) {
            /* Previous segment was incomplete, so this PDU should continue it */
            if (newSegmentStarted) {
                ti = proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_framing_info_correct,
                                         tvb, 0, 0, FALSE);
                if (!p->sequenceExpectedCorrect) {
                    expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                           "Last segment of previous PDU was not continued");
                }
            }
            else {
               ti = proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_framing_info_correct,
                                         tvb, 0, 0, TRUE);
            }
        }
        else {
            /* Previous segment was complete, so this PDU should start a new one */
            if (!newSegmentStarted) {
                ti = proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_framing_info_correct,
                                         tvb, 0, 0, FALSE);
                if (!p->sequenceExpectedCorrect) {
                    expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                           "Last segment of previous PDU was complete, but new segmeng was not started");
                }
            }
            else {
               ti = proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_framing_info_correct,
                                         tvb, 0, 0, TRUE);
            }

        }
        PROTO_ITEM_SET_GENERATED(ti);
    }
}

/* Update the channel status and set report for this frame */
static void checkChannelSequenceInfo(packet_info *pinfo, tvbuff_t *tvb,
                                     rlc_lte_info *p_rlc_lte_info,
                                     guint16 sequenceNumber,
                                     guint8 first_includes_start, guint8 last_includes_end,
                                     proto_tree *tree)
{
    rlc_channel_hash_key   channel_key;
    rlc_channel_hash_key   *p_channel_key;
    rlc_channel_status     *p_channel_status;
    state_report_in_frame  *p_report_in_frame = NULL;
    guint8                 createdChannel = FALSE;
    guint16                expectedSequenceNumber;

    /* If find stat_report_in_frame already, use that and get out */
    if (pinfo->fd->flags.visited) {
        p_report_in_frame = (state_report_in_frame*)g_hash_table_lookup(rlc_lte_frame_report_hash,
                                                                        &pinfo->fd->num);
        if (p_report_in_frame != NULL) {
            addChannelSequenceInfo(p_report_in_frame, sequenceNumber, first_includes_start,
                                   pinfo, tree, tvb);
            return;
        }
        else {
            /* Give up - we must have tried already... */
            return;
        }
    }


    /**************************************************/
    /* Create or find an entry for this channel state */
    channel_key.ueId = p_rlc_lte_info->ueid;
    channel_key.channelType = p_rlc_lte_info->channelType;
    channel_key.channelId = p_rlc_lte_info->channelId;
    channel_key.direction = p_rlc_lte_info->direction;

    /* Do the table lookup */
    p_channel_status = (rlc_channel_status*)g_hash_table_lookup(rlc_lte_channel_hash, &channel_key);

    /* Create table entry if necessary */
    if (p_channel_status == NULL) {
        createdChannel = TRUE;

        /* Allocate a new key and value */
        p_channel_key = se_alloc(sizeof(rlc_channel_hash_key));
        p_channel_status = se_alloc0(sizeof(rlc_channel_status));

        /* Just give up if allocations failed */
        if (!p_channel_key || !p_channel_status) {
            return;
        }

        /* Copy key contents */
        memcpy(p_channel_key, &channel_key, sizeof(rlc_channel_hash_key));

        /* Add entry */
        g_hash_table_insert(rlc_lte_channel_hash, p_channel_key, p_channel_status);
    }

    /* Create space for frame state_report */
    p_report_in_frame = se_alloc(sizeof(state_report_in_frame));

    /* Set expected sequence number.
       Wrap according to number of bits in SN */
    if (!createdChannel) {
        guint16 snLimit = 4096;  /* AM default */
        if (p_rlc_lte_info->rlcMode == RLC_UM_MODE) {
            if (p_rlc_lte_info->UMSequenceNumberLength == 5) {
                snLimit = 32;
            }
            else {
                snLimit = 1024;
            }
        }
        expectedSequenceNumber = (p_channel_status->previousSequenceNumber + 1) % snLimit;
    }
    else {
        expectedSequenceNumber = 0;
    }

    /* Set report info regarding sequence number */
    if (sequenceNumber == expectedSequenceNumber) {
        p_report_in_frame->sequenceExpectedCorrect = TRUE;
    }
    else {
        p_report_in_frame->sequenceExpectedCorrect = FALSE;
    }
    p_report_in_frame->sequenceExpected = expectedSequenceNumber;
    p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;
    p_report_in_frame->previousSegmentIncomplete = p_channel_status->previousSegmentIncomplete;

    /* Associate with this frame number */
    g_hash_table_insert(rlc_lte_frame_report_hash, &pinfo->fd->num, p_report_in_frame);

    /* Update channel status to remember *this* frame */
    p_channel_status->previousFrameNum = pinfo->fd->num;
    p_channel_status->previousSequenceNumber = sequenceNumber;
    p_channel_status->previousSegmentIncomplete = !last_includes_end;

    /* Add state report for this frame into tree */
    addChannelSequenceInfo(p_report_in_frame, sequenceNumber, first_includes_start,
                           pinfo, tree, tvb);
}





/***************************************************/
/* Unacknowledged mode PDU                         */
static void dissect_rlc_lte_um(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree,
                               int offset,
                               rlc_lte_info *p_rlc_lte_info)
{
    guint64 framing_info;
    gboolean first_includes_start;
    gboolean last_includes_end;
    guint64 fixed_extension;
    guint64 sn;
    gint    start_offset = offset;
    proto_tree *um_header_tree;
    proto_item *um_header_ti;

    /* Add UM header subtree */
    um_header_ti = proto_tree_add_string_format(tree,
                                                hf_rlc_lte_um_header,
                                                tvb, offset, 0,
                                                "",
                                                "UM header");
    um_header_tree = proto_item_add_subtree(um_header_ti,
                                            ett_rlc_lte_um_header);


    /*******************************/
    /* Fixed UM header             */
    if (p_rlc_lte_info->UMSequenceNumberLength == UM_SN_LENGTH_5_BITS) {
        /* Framing info (2 bits) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_fi,
                                    tvb, offset*8, 2,
                                    &framing_info, FALSE);

        /* Extension (1 bit) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_fixed_e, tvb,
                                    (offset*8) + 2, 1,
                                    &fixed_extension, FALSE);

        /* Sequence Number (5 bit) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_sn, tvb,
                                    (offset*8) + 3, 5,
                                    &sn, FALSE);
        offset++;
    }
    else if (p_rlc_lte_info->UMSequenceNumberLength == UM_SN_LENGTH_10_BITS) {
        guint8 reserved;
        proto_item *ti;

        /* Check 3 Reserved bits */
        reserved = (tvb_get_guint8(tvb, offset) & 0xe0) >> 5;
        ti = proto_tree_add_item(um_header_tree, hf_rlc_lte_um_fixed_reserved, tvb, offset, 1, FALSE);
        if (reserved != 0) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                      "RLC UM Fixed header Reserved bits not zero (found 0x%x)", reserved);
        }

        /* Framing info (2 bits) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_fi,
                                    tvb, (offset*8)+3, 2,
                                    &framing_info, FALSE);

        /* Extension (1 bit) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_fixed_e, tvb,
                                    (offset*8) + 5, 1,
                                    &fixed_extension, FALSE);

        /* Sequence Number (10 bits) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_sn, tvb,
                                    (offset*8) + 6, 10,
                                    &sn, FALSE);
        offset += 2;
    }
    else {
        /* Invalid length of sequence number */
        proto_item *ti;
        ti = proto_tree_add_text(um_header_tree, tvb, 0, 0, "Invalid sequence number length (%u bits)",
                                 p_rlc_lte_info->UMSequenceNumberLength);
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "Invalid sequence number length (%u bits)",
                               p_rlc_lte_info->UMSequenceNumberLength);
        return;
    }

    /* Show SN in info column */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "  SN=%04u",
                        (guint16)sn);
    }

    /* Show SN in UM header root */
    proto_item_append_text(um_header_ti, " (SN=%u)", (guint16)sn);
    proto_item_set_len(um_header_ti, offset-start_offset);


    /*************************************/
    /* UM header extension               */
    if (fixed_extension) {
        offset = dissect_rlc_lte_extension_header(tvb, pinfo, tree, offset);
    }


    /* Extract these 2 flags from framing_info */
    first_includes_start = ((guint8)framing_info & 0x02) == 0;
    last_includes_end =    ((guint8)framing_info & 0x01) == 0;


    /* Call sequence analysis function now */
    if (global_rlc_lte_sequence_analysis) {
        checkChannelSequenceInfo(pinfo, tvb, p_rlc_lte_info,
                                (guint16)sn, first_includes_start, last_includes_end,
                                um_header_tree);
    }


    /*************************************/
    /* Data                              */
    if (s_number_of_extensions > 0) {
        /* Show each data segment separately */
        int n;
        for (n=0; n < s_number_of_extensions; n++) {
            proto_tree_add_item(tree, hf_rlc_lte_um_data, tvb, offset, s_lengths[n], FALSE);
            show_PDU_in_info(pinfo, s_lengths[n],
                             (n==0) ? first_includes_start : TRUE,
                             TRUE);
            tvb_ensure_bytes_exist(tvb, offset, s_lengths[n]);
            offset += s_lengths[n];
        }
    }

    /* Final data element */
    proto_tree_add_item(tree, hf_rlc_lte_um_data, tvb, offset, -1, FALSE);
    show_PDU_in_info(pinfo, (guint16)tvb_length_remaining(tvb, offset),
                     (s_number_of_extensions == 0) ? first_includes_start : TRUE,
                     last_includes_end);
}




/* Dissect an AM STATUS PDU */
static void dissect_rlc_lte_am_status_pdu(tvbuff_t *tvb,
                                          packet_info *pinfo,
                                          proto_tree *tree,
                                          int offset)
{
    guint8     cpt;
    guint64    ack_sn, nack_sn;
    guint64    e1 = 0, e2 = 0;
    guint64    so_start, so_end;
    int        bit_offset = offset * 8;
    proto_item *ti;

    /****************************************************************/
    /* Part of RLC control PDU header                               */

    /* Control PDU Type (CPT) */
    cpt = (tvb_get_guint8(tvb, offset) & 0xf0) >> 4;
    ti = proto_tree_add_item(tree, hf_rlc_lte_am_cpt, tvb, offset, 1, FALSE);
    if (cpt != 0) {
        /* Protest and stop - only know about STATUS PDUs */
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "RLC Control frame type %u not handled", cpt);
        return;
    }


    /*****************************************************************/
    /* STATUS PDU                                                    */

    /* The PDU itself starts 4 bits into the byte */
    bit_offset += 4;

    /* ACK SN */
    proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_ack_sn, tvb,
                                bit_offset, 10, &ack_sn, FALSE);
    bit_offset += 10;
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "  ACK_SN=%u", (guint16)ack_sn);
    }


    /* E1 */
    proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_e1, tvb,
                                bit_offset, 1, &e1, FALSE);

    /* Skip another bit to byte-align the next bit... */
    bit_offset++;

    /* Optional, extra fields */
    do {
        if (e1) {
            proto_item *nack_ti;

            /****************************/
            /* Read NACK_SN, E1, E2     */

            /* NACK_SN */
            nack_ti = proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_nack_sn, tvb,
                                                  bit_offset, 10, &nack_sn, FALSE);
            bit_offset += 10;
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "  NACK_SN=%u", (guint16)nack_sn);
            }
            expert_add_info_format(pinfo, nack_ti, PI_SEQUENCE, PI_WARN,
                                   "Status PDU reports NACK for SN=%u", (guint16)nack_sn);


            /* E1 */
            proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_e1, tvb,
                                        bit_offset, 1, &e1, FALSE);
            bit_offset++;

            /* E2 */
            proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_e2, tvb,
                                        bit_offset, 1, &e2, FALSE);
            bit_offset++;
        }

        if (e2) {
            /* Read SOstart, SOend */
            proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_so_start, tvb,
                                        bit_offset, 15, &so_start, FALSE);
            bit_offset += 15;

            proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_so_end, tvb,
                                        bit_offset, 15, &so_end, FALSE);
            bit_offset += 15;

            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "  (SOstart=%u SOend=%u)",
                                (guint16)so_start, (guint16)so_end);

                if ((guint16)so_end == 0x7fff) {
                    col_append_str(pinfo->cinfo, COL_INFO, " (missing portion reaches end of AMD PDU)");
                }
            }

            /* Reset this flag here */
            e2 = 0;
        }
    } while (e1 || e2);

}


/***************************************************/
/* Acknowledged mode PDU                           */
static void dissect_rlc_lte_am(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree,
                               int offset,
                               rlc_lte_info *p_rlc_lte_info _U_)
{
    guint8 is_data;
    guint8 is_segment;
    guint8 polling;
    guint8 fixed_extension;
    guint8 framing_info;
    gboolean first_includes_start;
    gboolean last_includes_end;
    proto_tree *am_header_tree;
    proto_item *am_header_ti;
    gint   start_offset = offset;
    guint16    sn;

    /* Add UM header subtree */
    am_header_ti = proto_tree_add_string_format(tree,
                                                hf_rlc_lte_am_header,
                                                tvb, offset, 0,
                                                "",
                                                "AM header");
    am_header_tree = proto_item_add_subtree(am_header_ti,
                                            ett_rlc_lte_am_header);


    /*******************************************/
    /* First bit is Data/Control flag           */
    is_data = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_data_control, tvb, offset, 1, FALSE);
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, (is_data) ? " [DATA]" : " [CONTROL]");
    }


    /**************************************************/
    /* Control PDUs are a completely separate format  */
    if (!is_data) {
        dissect_rlc_lte_am_status_pdu(tvb, pinfo, am_header_tree, offset);
        return;
    }


    /******************************/
    /* Data PDU fixed header      */

    /* Re-segmentation Flag (RF) field */
    is_segment = (tvb_get_guint8(tvb, offset) & 0x40) >> 6;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_rf, tvb, offset, 1, FALSE);

    /* Polling bit */
    polling = (tvb_get_guint8(tvb, offset) & 0x20) >> 5;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_p, tvb, offset, 1, FALSE);
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, (polling) ? " (P) " : "     ");
    }
    if (polling) {
        proto_item_append_text(am_header_ti, " (P)");
    }

    /* Framing Info */
    framing_info = (tvb_get_guint8(tvb, offset) & 0x18) >> 3;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_fi, tvb, offset, 1, FALSE);

    /* Extension bit */
    fixed_extension = (tvb_get_guint8(tvb, offset) & 0x04) >> 2;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_fixed_e, tvb, offset, 1, FALSE);

    /* Sequence Number */
    sn = tvb_get_ntohs(tvb, offset) & 0x03ff;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_fixed_sn, tvb, offset, 2, FALSE);
    offset += 2;

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "sn=%u", sn);
    }


    /* Show SN in AM header root */
    proto_item_append_text(am_header_ti, " (SN=%u)", sn);
    proto_item_set_len(am_header_ti, offset-start_offset);

    /***************************************/
    /* Dissect extra segment header fields */
    if (is_segment) {
        /* Last Segment Field (LSF) */
        proto_tree_add_item(am_header_tree, hf_rlc_lte_am_segment_lsf, tvb, offset, 1, FALSE);

        /* SO */
        proto_tree_add_item(am_header_tree, hf_rlc_lte_am_segment_so, tvb, offset, 2, FALSE);

        offset += 2;
    }

    /*************************************/
    /* AM header extension               */
    if (fixed_extension) {
        offset = dissect_rlc_lte_extension_header(tvb, pinfo, tree, offset);
    }


    /* Extract these 2 flags from framing_info */
    first_includes_start = (framing_info & 0x02) == 0;
    last_includes_end =    (framing_info & 0x01) == 0;


    /* Call sequence analysis function now (pretty limited for AM) */
#if 0
    if (global_rlc_lte_sequence_analysis) {
        checkChannelSequenceInfo(pinfo, tvb, p_rlc_lte_info, (guint16)sn,
                                 first_includes_start, last_includes_end,
                                 am_header_tree);
    }
#endif


    /*************************************/
    /* Data                        */
    if (s_number_of_extensions > 0) {
        /* Show each data segment separately */
        int n;
        for (n=0; n < s_number_of_extensions; n++) {
            proto_tree_add_item(tree, hf_rlc_lte_am_data, tvb, offset, s_lengths[n], FALSE);
            show_PDU_in_info(pinfo, s_lengths[n],
                             (n==0) ? first_includes_start : TRUE,
                             TRUE);
            tvb_ensure_bytes_exist(tvb, offset, s_lengths[n]);
            offset += s_lengths[n];
        }
    }

    /* Final data element */
    proto_tree_add_item(tree, hf_rlc_lte_am_data, tvb, offset, -1, FALSE);
    show_PDU_in_info(pinfo, (guint16)tvb_length_remaining(tvb, offset),
                     (s_number_of_extensions == 0) ? first_includes_start : TRUE,
                     last_includes_end);
}



/*****************************/
/* Main dissection function. */
/*****************************/

void dissect_rlc_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree             *rlc_lte_tree;
    proto_item             *ti;
    proto_item             *mode_ti;
    gint                   offset = 0;
    struct rlc_lte_info    *p_rlc_lte_info = NULL;

    /* Set protocol name */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC-LTE");
    }

    /* Create protocol tree. */
    ti = proto_tree_add_item(tree, proto_rlc_lte, tvb, offset, -1, FALSE);
    rlc_lte_tree = proto_item_add_subtree(ti, ett_rlc_lte);


    /* Look for packet info! */
    p_rlc_lte_info = p_get_proto_data(pinfo->fd, proto_rlc_lte);

    /* Can't dissect anything without it... */
    if (p_rlc_lte_info == NULL) {
        proto_item *ti =
            proto_tree_add_text(rlc_lte_tree, tvb, offset, -1,
                                "Can't dissect LTE RLC frame because no per-frame info was attached!");
        PROTO_ITEM_SET_GENERATED(ti);
        return;
    }

    /*****************************************/
    /* Show context information              */
    /* TODO: hide inside own tree?           */

    ti = proto_tree_add_uint(rlc_lte_tree, hf_rlc_lte_context_direction,
                             tvb, 0, 0, p_rlc_lte_info->direction);
    PROTO_ITEM_SET_GENERATED(ti);

    mode_ti = proto_tree_add_uint(rlc_lte_tree, hf_rlc_lte_context_mode,
                                  tvb, 0, 0, p_rlc_lte_info->rlcMode);
    PROTO_ITEM_SET_GENERATED(mode_ti);

    if (p_rlc_lte_info->ueid != 0) {
        ti = proto_tree_add_uint(rlc_lte_tree, hf_rlc_lte_context_ueid,
                                 tvb, 0, 0, p_rlc_lte_info->ueid);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    ti = proto_tree_add_uint(rlc_lte_tree, hf_rlc_lte_context_priority,
                             tvb, 0, 0, p_rlc_lte_info->priority);
    PROTO_ITEM_SET_GENERATED(ti);

    ti = proto_tree_add_uint(rlc_lte_tree, hf_rlc_lte_context_channel_type,
                             tvb, 0, 0, p_rlc_lte_info->channelType);
    PROTO_ITEM_SET_GENERATED(ti);

    if ((p_rlc_lte_info->channelType == CHANNEL_TYPE_SRB) ||
        (p_rlc_lte_info->channelType == CHANNEL_TYPE_DRB)) {
        ti = proto_tree_add_uint(rlc_lte_tree, hf_rlc_lte_context_channel_id,
                                 tvb, 0, 0, p_rlc_lte_info->channelId);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    ti = proto_tree_add_uint(rlc_lte_tree, hf_rlc_lte_context_pdu_length,
                             tvb, 0, 0, p_rlc_lte_info->pduLength);
    PROTO_ITEM_SET_GENERATED(ti);

    if (p_rlc_lte_info->rlcMode == RLC_UM_MODE) {
        ti = proto_tree_add_uint(rlc_lte_tree, hf_rlc_lte_context_um_sn_length,
                                 tvb, 0, 0, p_rlc_lte_info->UMSequenceNumberLength);
        PROTO_ITEM_SET_GENERATED(ti);
    }


    /* Append context highlights to info column */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "[%s] [%s] ",
                     (p_rlc_lte_info->direction == 0) ? "UL" : "DL",
                     val_to_str(p_rlc_lte_info->rlcMode, rlc_mode_short_vals, "Unknown"));
        if (p_rlc_lte_info->ueid != 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "UEId=%u ", p_rlc_lte_info->ueid);
        }
        if (p_rlc_lte_info->channelId == 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
                            val_to_str(p_rlc_lte_info->channelType, rlc_channel_type_vals, "Unknown"));
        }
        else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s:%u",
                            val_to_str(p_rlc_lte_info->channelType, rlc_channel_type_vals, "Unknown"),
                            p_rlc_lte_info->channelId);
        }
    }

    /* Reset this count */
    s_number_of_extensions = 0;

    /* Dissect the RLC PDU itself. Format depends upon mode... */
    switch (p_rlc_lte_info->rlcMode) {

        case RLC_TM_MODE:
            /* Remaining bytes are all data */
            proto_tree_add_item(rlc_lte_tree, hf_rlc_lte_tm_data, tvb, offset, -1, FALSE);
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "   [%u-bytes]",
                               tvb_length_remaining(tvb, offset));
            }
            break;

        case RLC_UM_MODE:
            dissect_rlc_lte_um(tvb, pinfo, rlc_lte_tree, offset, p_rlc_lte_info);
            break;

        case RLC_AM_MODE:
            dissect_rlc_lte_am(tvb, pinfo, rlc_lte_tree, offset, p_rlc_lte_info);
            break;

        case RLC_PREDEF:
            /* Predefined data (i.e. not containing a valid RLC header */
            proto_tree_add_item(rlc_lte_tree, hf_rlc_lte_predefined_pdu, tvb, offset, -1, FALSE);
            break;

        default:
            /* Error - unrecognised mode */
            expert_add_info_format(pinfo, mode_ti, PI_MALFORMED, PI_ERROR,
                                   "Unrecognised RLC Mode set (%u)", p_rlc_lte_info->rlcMode);
            break;
    }
}



/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in wireshark */
static void
rlc_lte_init_protocol(void)
{
    /* Destroy any existing hashes. */
    if (rlc_lte_channel_hash) {
        g_hash_table_destroy(rlc_lte_channel_hash);
    }

    if (rlc_lte_frame_report_hash) {
        g_hash_table_destroy(rlc_lte_frame_report_hash);
    }

    /* Now create them over */
    rlc_lte_channel_hash = g_hash_table_new(rlc_channel_hash_func, rlc_channel_equal);
    rlc_lte_frame_report_hash = g_hash_table_new(rlc_frame_hash_func, rlc_frame_equal);
}




void proto_register_rlc_lte(void)
{
    static hf_register_info hf[] =
    {
        /**********************************/
        /* Items for decoding context     */
        { &hf_rlc_lte_context_mode,
            { "RLC Mode",
              "rlc-lte.mode", FT_UINT8, BASE_DEC, VALS(rlc_mode_vals), 0x0,
              "RLC Mode", HFILL
            }
        },
        { &hf_rlc_lte_context_direction,
            { "Direction",
              "rlc-lte.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_rlc_lte_context_priority,
            { "Priority",
              "rlc-lte.priority", FT_UINT8, BASE_DEC, 0, 0x0,
              "Priority", HFILL
            }
        },
        { &hf_rlc_lte_context_ueid,
            { "UEId",
              "rlc-lte.ueid", FT_UINT16, BASE_DEC, 0, 0x0,
              "User Equipment Identifier associated with message", HFILL
            }
        },
        { &hf_rlc_lte_context_channel_type,
            { "Channel Type",
              "rlc-lte.channel-type", FT_UINT16, BASE_DEC, VALS(rlc_channel_type_vals), 0x0,
              "Channel Type associated with message", HFILL
            }
        },
        { &hf_rlc_lte_context_channel_id,
            { "Channel ID",
              "rlc-lte.channel-id", FT_UINT16, BASE_DEC, 0, 0x0,
              "Channel ID associated with message", HFILL
            }
        },
        { &hf_rlc_lte_context_pdu_length,
            { "PDU Length",
              "rlc-lte.pdu_length", FT_UINT16, BASE_DEC, 0, 0x0,
              "Length of PDU (in bytes)", HFILL
            }
        },
        { &hf_rlc_lte_context_um_sn_length,
            { "UM Sequence number length",
              "rlc-lte.um-seqnum-length", FT_UINT8, BASE_DEC, 0, 0x0,
              "Length of UM sequence number in bits", HFILL
            }
        },


        /* Transparent mode fields */
        { &hf_rlc_lte_tm_data,
            { "TM Data",
              "rlc-lte.tm.data", FT_BYTES, BASE_HEX, 0, 0x0,
              "Transparent Mode Data", HFILL
            }
        },

        /* Unacknowledged mode fields */
        { &hf_rlc_lte_um_header,
            { "UM Header",
              "rlc-lte.um.header", FT_STRING, BASE_NONE, NULL, 0x0,
              "Unackowledged Mode Header", HFILL
            }
        },
        { &hf_rlc_lte_um_fi,
            { "Framing Info",
              "rlc-lte.um.fi", FT_UINT8, BASE_HEX, VALS(framing_info_vals), 0x0,
              "Framing Info", HFILL
            }
        },
        { &hf_rlc_lte_um_fixed_e,
            { "Extension",
              "rlc-lte.um.fixed.e", FT_UINT8, BASE_HEX, VALS(fixed_extension_vals), 0x0,
              "Extension in fixed part of UM header", HFILL
            }
        },
        { &hf_rlc_lte_um_sn,
            { "Sequence number",
              "rlc-lte.um.sn", FT_UINT8, BASE_DEC, 0, 0x0,
              "Unacknowledged Mode Sequence Number", HFILL
            }
        },
        { &hf_rlc_lte_um_fixed_reserved,
            { "Reserved",
              "rlc-lte.um.reserved", FT_UINT8, BASE_DEC, 0, 0xe0,
              "Unacknowledged Mode Fixed header reserved bits", HFILL
            }
        },
        { &hf_rlc_lte_um_data,
            { "UM Data",
              "rlc-lte.um.data", FT_BYTES, BASE_HEX, 0, 0x0,
              "Unacknowledged Mode Data", HFILL
            }
        },
        { &hf_rlc_lte_extension_part,
            { "Extension Part",
              "rlc-lte.extension-part", FT_STRING, BASE_NONE, 0, 0x0,
              "Extension Part", HFILL
            }
        },


        { &hf_rlc_lte_extension_e,
            { "Extension",
              "rlc-lte.extension.e", FT_UINT8, BASE_HEX, VALS(extension_extension_vals), 0x0,
              "Extension in extended part of the header", HFILL
            }
        },
        { &hf_rlc_lte_extension_li,
            { "Length Indicator",
              "rlc-lte.extension.li", FT_UINT16, BASE_DEC, 0, 0x0,
              "Length Indicator", HFILL
            }
        },
        { &hf_rlc_lte_extension_padding,
            { "Padding",
              "rlc-lte.extension.padding", FT_UINT8, BASE_HEX, 0, 0x0f,
              "Extension header padding", HFILL
            }
        },


        { &hf_rlc_lte_am_header,
            { "UM Header",
              "rlc-lte.am.header", FT_STRING, BASE_NONE, NULL, 0x0,
              "Ackowledged Mode Header", HFILL
            }
        },
        { &hf_rlc_lte_am_data_control,
            { "Frame type",
              "rlc-lte.am.frame_type", FT_UINT8, BASE_HEX, VALS(data_or_control_vals), 0x80,
              "AM Frame Type (Control or Data)", HFILL
            }
        },
        { &hf_rlc_lte_am_rf,
            { "Re-segmentation Flag",
              "rlc-lte.am.rf", FT_UINT8, BASE_HEX, VALS(resegmentation_flag_vals), 0x40,
              "AM Re-segmentation Flag", HFILL
            }
        },
        { &hf_rlc_lte_am_p,
            { "Polling Bit",
              "rlc-lte.am.p", FT_UINT8, BASE_HEX, VALS(polling_bit_vals), 0x20,
              "Polling Bit", HFILL
            }
        },
        { &hf_rlc_lte_am_fi,
            { "Framing Info",
              "rlc-lte.am.fi", FT_UINT8, BASE_HEX, VALS(framing_info_vals), 0x18,
              "AM Framing Info", HFILL
            }
        },
        { &hf_rlc_lte_am_fixed_e,
            { "Extension",
              "rlc-lte.am.fixed.e", FT_UINT8, BASE_HEX, VALS(fixed_extension_vals), 0x04,
              "Fixed Extension Bit", HFILL
            }
        },
        { &hf_rlc_lte_am_fixed_sn,
            { "Sequence Number",
              "rlc-lte.am.fixed.sn", FT_UINT16, BASE_HEX, 0, 0x03ff,
              "AM Fixed Sequence Number", HFILL
            }
        },
        { &hf_rlc_lte_am_segment_lsf,
            { "Last Segment Flag",
              "rlc-lte.am.segment.lsf", FT_UINT8, BASE_HEX, VALS(lsf_vals), 0x80,
              "Last Segment Flag", HFILL
            }
        },
        { &hf_rlc_lte_am_segment_so,
            { "Segment Offset",
              "rlc-lte.am.segment.offset", FT_UINT16, BASE_DEC, 0, 0x7fff,
              "Segment Offset", HFILL
            }
        },
        { &hf_rlc_lte_am_data,
            { "AM Data",
              "rlc-lte.am.data", FT_BYTES, BASE_HEX, 0, 0x0,
              "Acknowledged Mode Data", HFILL
            }
        },


        { &hf_rlc_lte_am_cpt,
            { "Control PDU Type",
              "rlc-lte.am.cpt", FT_UINT8, BASE_HEX, VALS(control_pdu_type_vals), 0x70,
              "AM Control PDU Type", HFILL
            }
        },
        { &hf_rlc_lte_am_ack_sn,
            { "ACK Sequence Number",
              "rlc-lte.am.ack-sn", FT_UINT16, BASE_DEC, 0, 0x0,
              "Sequence Number we're next expecting to receive", HFILL
            }
        },
        { &hf_rlc_lte_am_e1,
            { "Extension bit 1",
              "rlc-lte.am.e1", FT_UINT8, BASE_HEX, VALS(am_e1_vals), 0x0,
              "Extension bit 1", HFILL
            }
        },
        { &hf_rlc_lte_am_e2,
            { "Extension bit 2",
              "rlc-lte.am.e2", FT_UINT8, BASE_HEX, VALS(am_e2_vals), 0x0,
              "Extension bit 2", HFILL
            }
        },
        { &hf_rlc_lte_am_nack_sn,
            { "NACK Sequence Number",
              "rlc-lte.am.nack-sn", FT_UINT16, BASE_DEC, 0, 0x0,
              "Negative Acknowledgement Sequence Number", HFILL
            }
        },
        { &hf_rlc_lte_am_so_start,
            { "SO Start",
              "rlc-lte.am.so-start", FT_UINT16, BASE_DEC, 0, 0x0,
              "SO Start", HFILL
            }
        },
        { &hf_rlc_lte_am_so_end,
            { "SO End",
              "rlc-lte.am.so-end", FT_UINT16, BASE_DEC, 0, 0x0,
              "SO End", HFILL
            }
        },

        { &hf_rlc_lte_predefined_pdu,
            { "Predefined data",
              "rlc-lte.predefined-data", FT_BYTES, BASE_HEX, 0, 0x0,
              "Predefined test data", HFILL
            }
        },

        { &hf_rlc_lte_sequence_analysis,
            { "Sequence Analysis",
              "rlc-lte.sequence-analysis", FT_STRING, BASE_NONE, 0, 0x0,
              "Sequence Analysis", HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_previous_frame,
            { "Previous frame for channel",
              "rlc-lte.sequence-analysis.previous-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              "Previous frame for channel", HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_expected_sn,
            { "Expected SN",
              "rlc-lte.sequence-analysis.expected-sn", FT_UINT16, BASE_DEC, 0, 0x0,
              "Expected SN", HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_framing_info_correct,
            { "Frame info continued correctly",
              "rlc-lte.sequence-analysis.framing-info-correct", FT_UINT8, BASE_DEC, 0, 0x0,
              "Frame info continued correctly", HFILL
            }
        },
    };

    static gint *ett[] =
    {
        &ett_rlc_lte,
        &ett_rlc_lte_um_header,
        &ett_rlc_lte_am_header,
        &ett_rlc_lte_extension_part,
        &ett_rlc_lte_sequence_analysis
    };

    module_t *rlc_lte_module;

    /* Register protocol. */
    proto_rlc_lte = proto_register_protocol("RLC-LTE", "RLC-LTE", "rlc-lte");
    proto_register_field_array(proto_rlc_lte, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name. */
    register_dissector("rlc-lte", dissect_rlc_lte, proto_rlc_lte);

    /* Preferences */
    rlc_lte_module = prefs_register_protocol(proto_rlc_lte, NULL);

    prefs_register_bool_preference(rlc_lte_module, "do_sequence_analysis",
        "Do sequence analysis for UM/AM channels",
        "Attempt to keep track of PDUs for UM/AM channels, and point out problems",
        &global_rlc_lte_sequence_analysis);

    register_init_routine(&rlc_lte_init_protocol);
}


