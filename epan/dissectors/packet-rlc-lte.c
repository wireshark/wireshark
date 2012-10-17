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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/tap.h>

#include "packet-mac-lte.h"
#include "packet-rlc-lte.h"
#include "packet-pdcp-lte.h"


/* Described in:
 * 3GPP TS 36.322 Evolved Universal Terrestial Radio Access (E-UTRA)
 * Radio Link Control (RLC) Protocol specification
 */

/* TODO:
   - add intermediate results to segments leading to final reassembly
   - use multiple active rlc_channel_reassembly_info's per channel
   - sequence analysis gets confused when we change cells and skip back
     to SN 0. Maybe add cell-id to context and add to channel/result key?
*/

/********************************/
/* Preference settings          */

#define SEQUENCE_ANALYSIS_MAC_ONLY 1
#define SEQUENCE_ANALYSIS_RLC_ONLY 2

/* By default don't try to analyse the sequence of messages for AM/UM channels */
static gint global_rlc_lte_am_sequence_analysis = FALSE;
static gint global_rlc_lte_um_sequence_analysis = FALSE;

/* By default don't call PDCP/RRC dissectors for SDU data */
static gboolean global_rlc_lte_call_pdcp_for_srb = FALSE;

enum pdcp_for_drb { PDCP_drb_off, PDCP_drb_SN_7, PDCP_drb_SN_12, PDCP_drb_SN_signalled, PDCP_drb_SN_15};
static enum_val_t pdcp_drb_col_vals[] = {
    {"pdcp-drb-off",           "Off",                 PDCP_drb_off},
    {"pdcp-drb-sn-7",          "7-bit SN",            PDCP_drb_SN_7},
    {"pdcp-drb-sn-12",         "12-bit SN",           PDCP_drb_SN_12},
    {"pdcp-drb-sn-15",         "15-bit SN",           PDCP_drb_SN_15},
    {"pdcp-drb-sn-signalling", "Use signalled value", PDCP_drb_SN_signalled},
    {NULL, NULL, -1}
};
static gint global_rlc_lte_call_pdcp_for_drb = (gint)PDCP_drb_off;
static gint signalled_pdcp_sn_bits = 12;

static gboolean global_rlc_lte_call_rrc_for_ccch = FALSE;
static gboolean global_rlc_lte_call_rrc_for_mcch = FALSE;

/* Preference to expect RLC headers without payloads */
static gboolean global_rlc_lte_headers_expected = FALSE;

/* Heuristic dissection */
static gboolean global_rlc_lte_heur = FALSE;

/* Re-assembly of segments */
static gboolean global_rlc_lte_reassembly = FALSE;

/**************************************************/
/* Initialize the protocol and registered fields. */
int proto_rlc_lte = -1;

extern int proto_mac_lte;
extern int proto_pdcp_lte;

static dissector_handle_t pdcp_lte_handle;

static int rlc_lte_tap = -1;

/* Decoding context */
static int hf_rlc_lte_context = -1;
static int hf_rlc_lte_context_mode = -1;
static int hf_rlc_lte_context_direction = -1;
static int hf_rlc_lte_context_priority = -1;
static int hf_rlc_lte_context_ueid = -1;
static int hf_rlc_lte_context_channel_type = -1;
static int hf_rlc_lte_context_channel_id = -1;
static int hf_rlc_lte_context_pdu_length = -1;
static int hf_rlc_lte_context_um_sn_length = -1;

/* Transparent mode fields */
static int hf_rlc_lte_tm = -1;
static int hf_rlc_lte_tm_data = -1;

/* Unacknowledged mode fields */
static int hf_rlc_lte_um = -1;
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
static int hf_rlc_lte_am = -1;
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
static int hf_rlc_lte_am_nacks = -1;
static int hf_rlc_lte_am_so_start = -1;
static int hf_rlc_lte_am_so_end = -1;

static int hf_rlc_lte_predefined_pdu = -1;
static int hf_rlc_lte_header_only = -1;

/* Sequence Analysis */
static int hf_rlc_lte_sequence_analysis = -1;
static int hf_rlc_lte_sequence_analysis_ok = -1;
static int hf_rlc_lte_sequence_analysis_previous_frame = -1;
static int hf_rlc_lte_sequence_analysis_next_frame = -1;
static int hf_rlc_lte_sequence_analysis_expected_sn = -1;
static int hf_rlc_lte_sequence_analysis_framing_info_correct = -1;

static int hf_rlc_lte_sequence_analysis_mac_retx = -1;
static int hf_rlc_lte_sequence_analysis_retx = -1;
static int hf_rlc_lte_sequence_analysis_repeated = -1;
static int hf_rlc_lte_sequence_analysis_skipped = -1;

static int hf_rlc_lte_sequence_analysis_repeated_nack = -1;
static int hf_rlc_lte_sequence_analysis_repeated_nack_original_frame = -1;

static int hf_rlc_lte_sequence_analysis_ack_out_of_range = -1;
static int hf_rlc_lte_sequence_analysis_ack_out_of_range_opposite_frame = -1;

/* Reassembly */
static int hf_rlc_lte_reassembly_source = -1;
static int hf_rlc_lte_reassembly_source_number_of_segments = -1;
static int hf_rlc_lte_reassembly_source_total_length = -1;
static int hf_rlc_lte_reassembly_source_segment = -1;
static int hf_rlc_lte_reassembly_source_segment_sn = -1;
static int hf_rlc_lte_reassembly_source_segment_framenum = -1;
static int hf_rlc_lte_reassembly_source_segment_length = -1;

/* Subtrees. */
static int ett_rlc_lte = -1;
static int ett_rlc_lte_context = -1;
static int ett_rlc_lte_um_header = -1;
static int ett_rlc_lte_am_header = -1;
static int ett_rlc_lte_extension_part = -1;
static int ett_rlc_lte_sequence_analysis = -1;
static int ett_rlc_lte_reassembly_source = -1;
static int ett_rlc_lte_reassembly_source_segment = -1;

/* Value-strings */
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
    { RLC_PREDEF,       "PREDEFINED"},  /* For data testing */
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
    { CHANNEL_TYPE_CCCH,         "CCCH"},
    { CHANNEL_TYPE_BCCH_BCH,     "BCCH_BCH"},
    { CHANNEL_TYPE_PCCH,         "PCCH"},
    { CHANNEL_TYPE_SRB,          "SRB"},
    { CHANNEL_TYPE_DRB,          "DRB"},
    { CHANNEL_TYPE_BCCH_DL_SCH,  "BCCH_DL_SCH"},
    { CHANNEL_TYPE_MCCH,         "MCCH"},
    { 0, NULL }
};

static const value_string framing_info_vals[] =
{
    { 0,      "First byte begins a RLC SDU and last byte ends a RLC SDU"},
    { 1,      "First byte begins a RLC SDU and last byte does not end a RLC SDU"},
    { 2,      "First byte does not begin a RLC SDU and last byte ends a RLC SDU"},
    { 3,      "First byte does not begin a RLC SDU and last byte does not end a RLC SDU"},
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
    { 1,      "AMD PDU segment"},
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
    { 1,      "Last byte of the AMD PDU segment corresponds to the last byte of an AMD PDU"},
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

static const value_string header_only_vals[] =
{
    { 0,      "RLC PDU Headers and body present"},
    { 1,      "RLC PDU Headers only"},
    { 0, NULL }
};



/**********************************************************************************/
/* These are for keeping track of UM/AM extension headers, and the lengths found  */
/* in them                                                                        */
static guint8  s_number_of_extensions = 0;
#define MAX_RLC_SDUS 64
static guint16 s_lengths[MAX_RLC_SDUS];


/*********************************************************************/
/* UM/AM sequence analysis                                           */

/* Types for RLC channel hash table                                   */
/* This table is maintained during initial dissection of RLC          */
/* frames, mapping from channel_hash_key -> sequence_analysis_report  */

/* Channel key */
typedef struct
{
    unsigned  ueId : 16;
    unsigned  channelType : 3;
    unsigned  channelId : 5;
    unsigned  direction : 1;
} channel_hash_key;


/******************************************************************/
/* State maintained for AM/UM reassembly                          */

typedef struct rlc_segment {
    guint32 frameNum;
    guint16 SN;
    guint8 *data;
    guint16 length;
} rlc_segment;

typedef struct rlc_channel_reassembly_info
{
    guint16 number_of_segments;
    #define RLC_MAX_SEGMENTS 100
    rlc_segment segments[RLC_MAX_SEGMENTS];
} rlc_channel_reassembly_info;




/*******************************************************************/
/* Conversation-type status for sequence analysis on channel       */
typedef struct
{
    guint8   rlcMode;

    /* For UM, we always expect the SN to keep advancing, and these fields
       keep track of this.
       For AM, these correspond to new data */
    guint16  previousSequenceNumber;
    guint32  previousFrameNum;
    gboolean previousSegmentIncomplete;

    /* Accumulate info about current segmented SDU */
    struct rlc_channel_reassembly_info *reassembly_info;
} channel_sequence_analysis_status;

/* The sequence analysis channel hash table */
static GHashTable *sequence_analysis_channel_hash = NULL;


/* Types for sequence analysis frame report hash table                  */
/* This is a table from framenum -> state_report_in_frame               */
/* This is necessary because the per-packet info is already being used  */
/* for context information before the dissector is called               */

/* Info to attach to frame when first read, recording what to show about sequence */
typedef enum { 
    SN_OK, SN_Repeated, SN_MAC_Retx, SN_Retx, SN_Missing, ACK_Out_of_Window, SN_Error
} sequence_analysis_state;


typedef struct
{
    gboolean  sequenceExpectedCorrect;
    guint16   sequenceExpected;
    guint32   previousFrameNum;
    gboolean  previousSegmentIncomplete;
    guint32   nextFrameNum;

    guint16   firstSN;
    guint16   lastSN;

    /* AM/UM */
    sequence_analysis_state state;
} sequence_analysis_report;


/* The sequence analysis frame report hash table instance itself   */
static GHashTable *sequence_analysis_report_hash = NULL;


static gpointer get_report_hash_key(guint16 SN, guint32 frameNumber,
                                    rlc_lte_info *p_rlc_lte_info,
                                    gboolean do_persist);




/* The reassembly result hash table */
static GHashTable *reassembly_report_hash = NULL;


/* Create a new struct for reassembly */
static void reassembly_reset(channel_sequence_analysis_status *status)
{
    status->reassembly_info = se_alloc0(sizeof(rlc_channel_reassembly_info));
}

/* Hide previous one */
static void reassembly_destroy(channel_sequence_analysis_status *status)
{
    /* Just "leak" it. There seems to be no way to free this memory... */
    status->reassembly_info = NULL;
}

/* Add a new segment to the accumulating segmented SDU */
static void reassembly_add_segment(channel_sequence_analysis_status *status,
                                   guint16 SN, guint32 frame,
                                   tvbuff_t *tvb, gint offset, gint length)
{
    int segment_number =  status->reassembly_info->number_of_segments;
    guint8 *segment_data;

    /* Give up if reach segment limit */
    if (segment_number >= (RLC_MAX_SEGMENTS-1)) {
        reassembly_destroy(status);
        return;
    }

    segment_data = se_alloc(length);
    /* TODO: is there a better way to do this? */
    memcpy(segment_data, tvb_get_ptr(tvb, offset, length), length);

    /* Add new segment */
    status->reassembly_info->segments[segment_number].frameNum = frame;
    status->reassembly_info->segments[segment_number].SN = SN;
    status->reassembly_info->segments[segment_number].data = segment_data;
    status->reassembly_info->segments[segment_number].length = length;

    status->reassembly_info->number_of_segments++;
}


/* Record the current & complete segmented SDU by mapping from this frame number to
   struct with segment info. */
static void reassembly_record(channel_sequence_analysis_status *status, packet_info *pinfo,
                              guint16 SN, rlc_lte_info *p_rlc_lte_info)
{
    /* Just store existing info in hash table */
    g_hash_table_insert(reassembly_report_hash,
                        get_report_hash_key(SN, pinfo->fd->num, p_rlc_lte_info, TRUE),
                        status->reassembly_info);
}

/* Create and return a tvb based upon contents of reassembly info */
static tvbuff_t* reassembly_get_reassembled_tvb(rlc_channel_reassembly_info *reassembly_info,
                                                tvbuff_t *parent_tvb, packet_info *pinfo)
{
    gint n;
    guint   combined_length = 0;
    guint8 *combined_data;
    guint combined_offset = 0;
    tvbuff_t *reassembled_tvb;

    /* Allocate buffer big enough to hold re-assembled data */
    for (n=0; n < reassembly_info->number_of_segments; n++) {
        combined_length += reassembly_info->segments[n].length;
    }
    combined_data = ep_alloc(combined_length);

    /* Copy data into contiguous buffer */
    for (n=0; n < reassembly_info->number_of_segments; n++) {
        guint8 *data = reassembly_info->segments[n].data;
        int length = reassembly_info->segments[n].length;
        memcpy(combined_data+combined_offset, data, length);
        combined_offset += length;
    }

    /* Create and return tvb with this data */
    reassembled_tvb = tvb_new_child_real_data(parent_tvb, combined_data, combined_offset, combined_offset);
    add_new_data_source(pinfo, reassembled_tvb, "Reassembled SDU");
    return reassembled_tvb;
}

/* Show where the segments came from for a reassembled SDU */
static void reassembly_show_source(rlc_channel_reassembly_info *reassembly_info,
                                   proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    int n;
    proto_item *source_ti, *ti;
    proto_tree *source_tree;
    proto_item *segment_ti;
    proto_tree *segment_tree;
    guint      total_length=0;

    /* Create root of source info */
    source_ti = proto_tree_add_item(tree,
                                    hf_rlc_lte_reassembly_source,
                                    tvb, 0, 0, ENC_ASCII|ENC_NA);
    source_tree = proto_item_add_subtree(source_ti, ett_rlc_lte_reassembly_source);
    PROTO_ITEM_SET_GENERATED(source_ti);

    for (n=0; n < reassembly_info->number_of_segments; n++) {
        total_length += reassembly_info->segments[n].length;
    }
    proto_item_append_text(source_ti, " %u segments, %u bytes", reassembly_info->number_of_segments,
                           total_length);

    /* Number of segments */
    ti = proto_tree_add_uint(source_tree,
                             hf_rlc_lte_reassembly_source_number_of_segments,
                             tvb, 0, 0, reassembly_info->number_of_segments);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Total length */
    ti = proto_tree_add_uint(source_tree,
                             hf_rlc_lte_reassembly_source_total_length,
                             tvb, 0, 0, total_length);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Now add info about each segment in turn */
    for (n=0; n < reassembly_info->number_of_segments; n++) {

        /* Add next segment as a subtree */
        rlc_segment *segment = &(reassembly_info->segments[n]);
        proto_item_append_text(source_ti, " (SN=%u frame=%u len=%u)",
                               segment->SN, segment->frameNum, segment->length);

        /* N.B. assume last segment from passed-in tvb! */
        segment_ti = proto_tree_add_item(source_tree,
                                         hf_rlc_lte_reassembly_source_segment,
                                         tvb,
                                         (n == reassembly_info->number_of_segments-1) ? offset : 0,
                                         (n == reassembly_info->number_of_segments-1) ? segment->length : 0,
                                         ENC_NA);
        segment_tree = proto_item_add_subtree(segment_ti, ett_rlc_lte_reassembly_source_segment);
        proto_item_append_text(segment_ti, " (SN=%u frame=%u length=%u)",
                               segment->SN, segment->frameNum, segment->length);
        PROTO_ITEM_SET_GENERATED(segment_ti);

        /* Add details to segment tree */
        ti = proto_tree_add_uint(segment_tree, hf_rlc_lte_reassembly_source_segment_sn,
                                 tvb, 0, 0, segment->SN);
        PROTO_ITEM_SET_GENERATED(ti);
        ti = proto_tree_add_uint(segment_tree, hf_rlc_lte_reassembly_source_segment_framenum,
                                 tvb, 0, 0, segment->frameNum);
        PROTO_ITEM_SET_GENERATED(ti);
        ti = proto_tree_add_uint(segment_tree, hf_rlc_lte_reassembly_source_segment_length,
                                 tvb, 0, 0, segment->length);
        PROTO_ITEM_SET_GENERATED(ti);
    }
}




/******************************************************************/
/* Conversation-type status for repeated NACK checking on channel */
typedef struct
{
    guint16         noOfNACKs;
    guint16         NACKs[MAX_NACKs];
    guint32         frameNum;
} channel_repeated_nack_status;

static GHashTable *repeated_nack_channel_hash = NULL;

typedef struct {
    guint16         noOfNACKsRepeated;
    guint16         repeatedNACKs[MAX_NACKs];
    guint32         previousFrameNum;
} channel_repeated_nack_report;

static GHashTable *repeated_nack_report_hash = NULL;



/********************************************************/
/* Forward declarations & functions                     */
static void dissect_rlc_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


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



/* Dissect extension headers (common to both UM and AM) */
static int dissect_rlc_lte_extension_header(tvbuff_t *tvb, packet_info *pinfo _U_,
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
                                    &extension, ENC_BIG_ENDIAN);

        /* Read length field */
        proto_tree_add_bits_ret_val(extension_part_tree, hf_rlc_lte_extension_li, tvb,
                                    (offset*8) + ((isOdd) ? 5 : 1),
                                    11,
                                    &length, ENC_BIG_ENDIAN);

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
        proto_tree_add_item(tree, hf_rlc_lte_extension_padding,
                            tvb, offset++, 1, ENC_BIG_ENDIAN);
    }

    return offset;
}


/* Show in the info column how many bytes are in the UM/AM PDU, and indicate
   whether or not the beginning and end are included in this packet */
static void show_PDU_in_info(packet_info *pinfo,
                             proto_item *top_ti,
                             gint32 length,
                             gboolean first_includes_start,
                             gboolean last_includes_end)
{
    /* Reflect this PDU in the info column */
    if (length > 0) {
        write_pdu_label_and_info(top_ti, NULL, pinfo,
                                 "  %s%u-byte%s%s",
                                 (first_includes_start) ? "[" : "..",
                                 length,
                                 (length > 1) ? "s" : "",
                                 (last_includes_end) ? "]" : "..");
    }
    else {
        write_pdu_label_and_info(top_ti, NULL, pinfo,
                                 "  %sunknown-bytes%s",
                                 (first_includes_start) ? "[" : "..",
                                 (last_includes_end) ? "]" : "..");
    }
}


/* Show an SDU. If configured, pass to PDCP/RRC dissector */
static void show_PDU_in_tree(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, gint offset, gint length,
                             rlc_lte_info *rlc_info, gboolean whole_pdu, rlc_channel_reassembly_info *reassembly_info,
                             sequence_analysis_state state)
{
    /* Add raw data (according to mode) */
    proto_item *data_ti = proto_tree_add_item(tree,
                                              (rlc_info->rlcMode == RLC_AM_MODE) ?
                                                    hf_rlc_lte_am_data :
                                                    hf_rlc_lte_um_data,
                                              tvb, offset, length, ENC_NA);

    if (whole_pdu || (reassembly_info != NULL)) {
        if (((global_rlc_lte_call_pdcp_for_srb) && (rlc_info->channelType == CHANNEL_TYPE_SRB)) ||
            ((global_rlc_lte_call_pdcp_for_drb != PDCP_drb_off) && (rlc_info->channelType == CHANNEL_TYPE_DRB))) {
            /* Send whole PDU to PDCP */

            /* TODO: made static to avoid compiler warning... */
            static tvbuff_t *pdcp_tvb = NULL;
            struct pdcp_lte_info *p_pdcp_lte_info;

            /* Get tvb for passing to LTE PDCP dissector */
            if (reassembly_info == NULL) {
                pdcp_tvb = tvb_new_subset(tvb, offset, length, length);
            }
            else {
                /* Get combined tvb. */
                pdcp_tvb = reassembly_get_reassembled_tvb(reassembly_info, tvb, pinfo);
                reassembly_show_source(reassembly_info, tree, tvb, offset);
            }

            /* Reuse or allocate struct */
            p_pdcp_lte_info = p_get_proto_data(pinfo->fd, proto_pdcp_lte);
            if (p_pdcp_lte_info == NULL) {
                p_pdcp_lte_info = se_alloc0(sizeof(struct pdcp_lte_info));
                /* Store info in packet */
                p_add_proto_data(pinfo->fd, proto_pdcp_lte, p_pdcp_lte_info);
            }

            p_pdcp_lte_info->ueid = rlc_info->ueid;
            p_pdcp_lte_info->channelType = Channel_DCCH;
            p_pdcp_lte_info->channelId = rlc_info->channelId;
            p_pdcp_lte_info->direction = rlc_info->direction;
            p_pdcp_lte_info->is_retx = (state != SN_OK);

            /* Set plane and sequence number length */
            p_pdcp_lte_info->no_header_pdu = FALSE;
            if (rlc_info->channelType == CHANNEL_TYPE_SRB) {
                p_pdcp_lte_info->plane = SIGNALING_PLANE;
                p_pdcp_lte_info->seqnum_length = 5;
            }
            else {
                p_pdcp_lte_info->plane = USER_PLANE;
                switch (global_rlc_lte_call_pdcp_for_drb) {
                    case PDCP_drb_SN_7:
                        p_pdcp_lte_info->seqnum_length = 7;
                        break;
                    case PDCP_drb_SN_12:
                        p_pdcp_lte_info->seqnum_length = 12;
                        break;
                    case PDCP_drb_SN_15:
                        p_pdcp_lte_info->seqnum_length = 15;
                        break;
                    case PDCP_drb_SN_signalled:
                        /* Use whatever was signalled (e.g. in RRC) */
                        p_pdcp_lte_info->seqnum_length = signalled_pdcp_sn_bits;
                        break;

                    default:
                        DISSECTOR_ASSERT(FALSE);
                        break;
                }
            }

            p_pdcp_lte_info->rohc_compression = FALSE;

            TRY {
                call_dissector_only(pdcp_lte_handle, pdcp_tvb, pinfo, tree, NULL);
            }
            CATCH_ALL {
            }
            ENDTRY

            PROTO_ITEM_SET_HIDDEN(data_ti);
        }
        else if (global_rlc_lte_call_rrc_for_mcch && (rlc_info->channelType == CHANNEL_TYPE_MCCH)) {
            /* Send whole PDU to RRC */
            static tvbuff_t *rrc_tvb = NULL;
            volatile dissector_handle_t protocol_handle;

            /* Get tvb for passing to LTE RRC dissector */
            if (reassembly_info == NULL) {
                rrc_tvb = tvb_new_subset(tvb, offset, length, length);
            }
            else {
                /* Get combined tvb. */
                rrc_tvb = reassembly_get_reassembled_tvb(reassembly_info, tvb, pinfo);
                reassembly_show_source(reassembly_info, tree, tvb, offset);
            }

            /* Get dissector handle */
            protocol_handle = find_dissector("lte_rrc.mcch");

            TRY {
                call_dissector_only(protocol_handle, rrc_tvb, pinfo, tree, NULL);
            }
            CATCH_ALL {
            }
            ENDTRY

            PROTO_ITEM_SET_HIDDEN(data_ti);
        }
    }
}

/* Hash table functions for RLC channels */

/* Equal keys */
static gint rlc_channel_equal(gconstpointer v, gconstpointer v2)
{
    const channel_hash_key* val1 = v;
    const channel_hash_key* val2 = v2;

    /* All fields must match */
    /* N.B. Currently fits into one word, so could return (*v == *v2)
       if we're sure they're initialised to 0... */
    return ((val1->ueId        == val2->ueId) &&
            (val1->channelType == val2->channelType) &&
            (val1->channelId   == val2->channelId) &&
            (val1->direction   == val2->direction));
}

/* Compute a hash value for a given key. */
static guint rlc_channel_hash_func(gconstpointer v)
{
    const channel_hash_key* val1 = v;

    /* TODO: check/reduce multipliers */
    return ((val1->ueId * 1024) + (val1->channelType*64) + (val1->channelId*2) + val1->direction);
}


/*************************************************************************/
/* Result hash                                                           */

typedef struct {
    guint32            frameNumber;
    unsigned           SN :             10;
    unsigned           channelType :    2;
    unsigned           channelId:       5;
    unsigned           direction:       1;
} rlc_result_hash_key;

static gint rlc_result_hash_equal(gconstpointer v, gconstpointer v2)
{
    const rlc_result_hash_key* val1 = (rlc_result_hash_key *)v;
    const rlc_result_hash_key* val2 = (rlc_result_hash_key *)v2;

    /* All fields must match */
    return (memcmp(val1, val2, sizeof(rlc_result_hash_key)) == 0);
}

/* Compute a hash value for a given key. */
static guint rlc_result_hash_func(gconstpointer v)
{
    const rlc_result_hash_key* val1 = (rlc_result_hash_key *)v;

    /* TODO: check collision-rate / execution-time of these multipliers?  */
    return val1->frameNumber + (val1->SN<<13) +
                               (val1->channelType<<5) +
                               (val1->channelId<<18) +
                               (val1->direction<<9);
}

/* Convenience function to get a pointer for the hash_func to work with */
static gpointer get_report_hash_key(guint16 SN, guint32 frameNumber,
                                    rlc_lte_info *p_rlc_lte_info,
                                    gboolean do_persist)
{
    static rlc_result_hash_key key;
    rlc_result_hash_key *p_key;

    /* Only allocate a struct when will be adding entry */
    if (do_persist) {
        p_key = se_new0(rlc_result_hash_key);
    }
    else {
        memset(&key, 0, sizeof(rlc_result_hash_key));
        p_key = &key;
    }

    /* Fill in details, and return pointer */
    p_key->frameNumber = frameNumber;
    p_key->SN = SN;
    p_key->channelType = p_rlc_lte_info->channelType;
    p_key->channelId = p_rlc_lte_info->channelId;
    p_key->direction = p_rlc_lte_info->direction;

    return p_key;
}




/* Add to the tree values associated with sequence analysis for this frame */
static void addChannelSequenceInfo(sequence_analysis_report *p,
                                   gboolean isControlFrame,
                                   rlc_lte_info *p_rlc_lte_info,
                                   guint16   sequenceNumber,
                                   gboolean  newSegmentStarted,
                                   rlc_lte_tap_info *tap_info,
                                   packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    proto_tree *seqnum_tree;
    proto_item *seqnum_ti;
    proto_item *ti;

    /* Create subtree */
    seqnum_ti = proto_tree_add_string_format(tree,
                                             hf_rlc_lte_sequence_analysis,
                                             tvb, 0, 0,
                                             "", "Sequence Analysis");
    seqnum_tree = proto_item_add_subtree(seqnum_ti,
                                         ett_rlc_lte_sequence_analysis);
    PROTO_ITEM_SET_GENERATED(seqnum_ti);

    if (p->previousFrameNum != 0) {
        ti = proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_previous_frame,
                                 tvb, 0, 0, p->previousFrameNum);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    switch (p_rlc_lte_info->rlcMode) {
        case RLC_AM_MODE:

            /********************************************/
            /* AM                                       */
            /********************************************/

            switch (p->state) {
                case SN_OK:
                    if (isControlFrame) {
                        return;
                    }

                    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ok,
                                                tvb, 0, 0, TRUE);
                    PROTO_ITEM_SET_GENERATED(ti);
                    proto_item_append_text(seqnum_ti, " - OK");

                    /* Link to next SN in channel (if known) */
                    if (p->nextFrameNum != 0) {
                        proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_next_frame,
                                            tvb, 0, 0, p->nextFrameNum);
                    }
                    break;

                case SN_MAC_Retx:
                    if (isControlFrame) {
                        return;
                    }

                    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ok,
                                                tvb, 0, 0, FALSE);
                    PROTO_ITEM_SET_GENERATED(ti);
                    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_mac_retx,
                                                tvb, 0, 0, TRUE);
                    PROTO_ITEM_SET_GENERATED(ti);
                    expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                           "AM Frame retransmitted for %s on UE %u - due to MAC retx!",
                                           val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                           p_rlc_lte_info->ueid);
                    proto_item_append_text(seqnum_ti, " - MAC retx of SN %u", p->firstSN);
                    break;

                case SN_Retx:
                    if (isControlFrame) {
                        return;
                    }

                    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ok,
                                                tvb, 0, 0, FALSE);
                    PROTO_ITEM_SET_GENERATED(ti);
                    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_retx,
                                                tvb, 0, 0, TRUE);
                    PROTO_ITEM_SET_GENERATED(ti);
                    expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                           "AM Frame retransmitted for %s on UE %u - most likely in response to NACK",
                                           val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                           p_rlc_lte_info->ueid);
                    proto_item_append_text(seqnum_ti, " - SN %u retransmitted", p->firstSN);
                    break;

                case SN_Repeated:
                    if (isControlFrame) {
                        return;
                    }

                    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ok,
                                                tvb, 0, 0, FALSE);
                    PROTO_ITEM_SET_GENERATED(ti);
                    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_repeated,
                                                tvb, 0, 0, TRUE);
                    PROTO_ITEM_SET_GENERATED(ti);
                    expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                           "AM SN Repeated for %s for UE %u - probably because didn't receive Status PDU?",
                                           val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                           p_rlc_lte_info->ueid);
                    proto_item_append_text(seqnum_ti, "- SN %u Repeated", p->firstSN);
                    break;

                case SN_Missing:
                    if (isControlFrame) {
                        return;
                    }

                    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ok,
                                                tvb, 0, 0, FALSE);
                    PROTO_ITEM_SET_GENERATED(ti);
                    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_skipped,
                                                tvb, 0, 0, TRUE);
                    PROTO_ITEM_SET_GENERATED(ti);
                    if (p->lastSN != p->firstSN) {
                        expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                               "AM SNs (%u to %u) missing for %s on UE %u",
                                               p->firstSN, p->lastSN,
                                               val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                               p_rlc_lte_info->ueid);
                        proto_item_append_text(seqnum_ti, " - SNs missing (%u to %u)",
                                               p->firstSN, p->lastSN);
                        tap_info->missingSNs = ((1024 + p->lastSN - p->firstSN) % 1024) + 1;
                    }
                    else {
                        expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                               "AM SN (%u) missing for %s on UE %u",
                                               p->firstSN,
                                               val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                               p_rlc_lte_info->ueid);
                        proto_item_append_text(seqnum_ti, " - SN missing (%u)", p->firstSN);
                        tap_info->missingSNs = 1;
                    }
                    break;

                case ACK_Out_of_Window:
                    if (!isControlFrame) {
                        return;
                    }


                    /* Not OK */
                    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ok,
                                                tvb, 0, 0, FALSE);
                    /* Out of range */
                    PROTO_ITEM_SET_GENERATED(ti);
                    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ack_out_of_range,
                                                tvb, 0, 0, TRUE);
                    PROTO_ITEM_SET_GENERATED(ti);

                    /* Link back to last seen SN in other direction */
                    ti = proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_ack_out_of_range_opposite_frame,
                                             tvb, 0, 0, p->previousFrameNum);
                    PROTO_ITEM_SET_GENERATED(ti);

                    /* Expert error */
                    expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_ERROR,
                                           "AM ACK for SN %u - but last received SN in other direction is %u for UE %u",
                                           p->firstSN, p->sequenceExpected,
                                           p_rlc_lte_info->ueid);
                    proto_item_append_text(seqnum_ti, "- ACK SN %u Outside Rx Window - last received SN is %u",
                                           p->firstSN, p->sequenceExpected);

                    break;

                default:
                    return;
            }
            break;

        case RLC_UM_MODE:

            /********************************************/
            /* UM                                       */
            /********************************************/

            /* Expected sequence number */
            ti = proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_expected_sn,
                                    tvb, 0, 0, p->sequenceExpected);
            PROTO_ITEM_SET_GENERATED(ti);
            if (p->sequenceExpectedCorrect) {
                PROTO_ITEM_SET_HIDDEN(ti);
            }

            if (!p->sequenceExpectedCorrect) {
                /* Work out SN wrap (in case needed below) */
                guint16 snLimit;
                if (p_rlc_lte_info->UMSequenceNumberLength == 5) {
                    snLimit = 32;
                }
                else {
                    snLimit = 1024;
                }

                switch (p->state) {
                    case SN_Missing:
                        ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ok,
                                                    tvb, 0, 0, FALSE);
                        PROTO_ITEM_SET_GENERATED(ti);
                        ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_skipped,
                                                    tvb, 0, 0, TRUE);
                        PROTO_ITEM_SET_GENERATED(ti);
                        if (p->lastSN != p->firstSN) {
                            expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                                   "UM SNs (%u to %u) missing for %s on UE %u",
                                                   p->firstSN, p->lastSN,
                                                   val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                                   p_rlc_lte_info->ueid);
                            proto_item_append_text(seqnum_ti, " - SNs missing (%u to %u)",
                                                   p->firstSN, p->lastSN);
                            tap_info->missingSNs = ((snLimit + p->lastSN - p->firstSN) % snLimit) + 1;
                        }
                        else {
                            expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                                   "UM SN (%u) missing for %s on UE %u",
                                                   p->firstSN,
                                                   val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                                   p_rlc_lte_info->ueid);
                            proto_item_append_text(seqnum_ti, " - SN missing (%u)",
                                                   p->firstSN);
                            tap_info->missingSNs = 1;
                        }
                        break;

                    case SN_Repeated:
                        ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ok,
                                                    tvb, 0, 0, FALSE);
                        PROTO_ITEM_SET_GENERATED(ti);
                        ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_repeated,
                                                    tvb, 0, 0, TRUE);
                        PROTO_ITEM_SET_GENERATED(ti);
                        expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                               "UM SN (%u) repeated for %s for UE %u",
                                               p->firstSN,
                                               val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                               p_rlc_lte_info->ueid);
                        proto_item_append_text(seqnum_ti, "- SN %u Repeated",
                                               p->firstSN);
                        break;

                    case SN_MAC_Retx:
                        ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ok,
                                                    tvb, 0, 0, FALSE);
                        PROTO_ITEM_SET_GENERATED(ti);
                        ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_mac_retx,
                                                    tvb, 0, 0, TRUE);
                        PROTO_ITEM_SET_GENERATED(ti);
                        expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                               "UM Frame retransmitted for %s on UE %u - due to MAC retx!",
                                               val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                               p_rlc_lte_info->ueid);
                        break;

                    default:
                        /* Incorrect sequence number */
                        expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                               "Wrong Sequence Number for %s on UE %u - got %u, expected %u",
                                               val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                               p_rlc_lte_info->ueid, sequenceNumber, p->sequenceExpected);
                        break;
                }

            }
            else {
                /* Correct sequence number, so check frame indication bits consistent */
                if (p->previousSegmentIncomplete) {
                    /* Previous segment was incomplete, so this PDU should continue it */
                    if (newSegmentStarted) {
                        ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_framing_info_correct,
                                                     tvb, 0, 0, FALSE);
                        if (!p->sequenceExpectedCorrect) {
                            expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                                   "Last segment of previous PDU was not continued for UE %u",
                                                   p_rlc_lte_info->ueid);
                        }
                    }
                    else {
                       ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_framing_info_correct,
                                                   tvb, 0, 0, TRUE);
                       PROTO_ITEM_SET_HIDDEN(ti);
                    }
                }
                else {
                    /* Previous segment was complete, so this PDU should start a new one */
                    if (!newSegmentStarted) {
                        ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_framing_info_correct,
                                                    tvb, 0, 0, FALSE);
                        if (!p->sequenceExpectedCorrect) {
                            expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                                   "Last segment of previous PDU was complete, but new segment was not started");
                        }
                    }
                    else {
                       ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_framing_info_correct,
                                                   tvb, 0, 0, TRUE);
                       PROTO_ITEM_SET_HIDDEN(ti);
                    }

                }
                PROTO_ITEM_SET_GENERATED(ti);

                /* Set OK here! */
                ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ok,
                                            tvb, 0, 0, TRUE);
                PROTO_ITEM_SET_GENERATED(ti);
                proto_item_append_text(seqnum_ti, " - OK");
            }

            /* Next channel frame */
            if (p->nextFrameNum != 0) {
                ti = proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_next_frame,
                                         tvb, 0, 0, p->nextFrameNum);
                PROTO_ITEM_SET_GENERATED(ti);
            }
    }
}

/* Update the channel status and set report for this frame */
static sequence_analysis_state checkChannelSequenceInfo(packet_info *pinfo, tvbuff_t *tvb,
                                                        rlc_lte_info *p_rlc_lte_info,
                                                        gboolean isControlFrame,
                                                        guint8 number_of_segments,
                                                        guint16 firstSegmentOffset,
                                                        guint16 firstSegmentLength,
                                                        guint16 lastSegmentOffset,
                                                        guint16 sequenceNumber,
                                                        gboolean first_includes_start, gboolean last_includes_end,
                                                        gboolean is_resegmented _U_,
                                                        rlc_lte_tap_info *tap_info,
                                                        proto_tree *tree)
{
    channel_hash_key   channel_key;
    channel_hash_key   *p_channel_key;
    channel_sequence_analysis_status     *p_channel_status;
    sequence_analysis_report *p_report_in_frame = NULL;
    gboolean               createdChannel = FALSE;
    guint16                expectedSequenceNumber = 0;
    guint16                snLimit = 0;

    /* If find stat_report_in_frame already, use that and get out */
    if (pinfo->fd->flags.visited) {
        p_report_in_frame = (sequence_analysis_report*)g_hash_table_lookup(sequence_analysis_report_hash,
                                                                           get_report_hash_key(sequenceNumber,
                                                                                               pinfo->fd->num,
                                                                                               p_rlc_lte_info,
                                                                                               FALSE));
        if (p_report_in_frame != NULL) {
            addChannelSequenceInfo(p_report_in_frame, isControlFrame, p_rlc_lte_info,
                                   sequenceNumber, first_includes_start,
                                   tap_info, pinfo, tree, tvb);
            return p_report_in_frame->state;
        }

        /* Don't just give up here... */
    }


    /**************************************************/
    /* Create or find an entry for this channel state */
    channel_key.ueId = p_rlc_lte_info->ueid;
    channel_key.channelType = p_rlc_lte_info->channelType;
    channel_key.channelId = p_rlc_lte_info->channelId;
    channel_key.direction = p_rlc_lte_info->direction;

    /* Do the table lookup */
    p_channel_status = (channel_sequence_analysis_status*)g_hash_table_lookup(sequence_analysis_channel_hash, &channel_key);

    /* Create table entry if necessary */
    if (p_channel_status == NULL) {
        createdChannel = TRUE;

        /* Allocate a new value and duplicate key contents */
        p_channel_status = se_alloc0(sizeof(channel_sequence_analysis_status));
        p_channel_key = se_memdup(&channel_key, sizeof(channel_hash_key));

        /* Set mode */
        p_channel_status->rlcMode = p_rlc_lte_info->rlcMode;

        /* Add entry */
        g_hash_table_insert(sequence_analysis_channel_hash, p_channel_key, p_channel_status);
    }

    /* Create space for frame state_report */
    p_report_in_frame = se_alloc0(sizeof(sequence_analysis_report));


    /* Deal with according to channel mode */
    switch (p_channel_status->rlcMode) {
        case RLC_UM_MODE:

            if (p_rlc_lte_info->UMSequenceNumberLength == 5) {
                snLimit = 32;
            }
            else {
                snLimit = 1024;
            }

            /* Work out expected sequence number */
            if (!createdChannel) {
                expectedSequenceNumber = (p_channel_status->previousSequenceNumber + 1) % snLimit;
            }
            else {
                /* Whatever we got is fine.. */
                expectedSequenceNumber = sequenceNumber;
            }

            /* Set report for this frame */
            /* For UM, sequence number is always expectedSequence number */
            p_report_in_frame->sequenceExpectedCorrect = (sequenceNumber == expectedSequenceNumber);

            /* For wrong sequence number... */
            if (!p_report_in_frame->sequenceExpectedCorrect) {

                reassembly_destroy(p_channel_status);

                /* Don't get confused by MAC (HARQ) retx */
                if (is_mac_lte_frame_retx(pinfo, p_rlc_lte_info->direction)) {
                    p_report_in_frame->state = SN_MAC_Retx;
                    p_report_in_frame->firstSN = sequenceNumber;
                }

                /* Frames are not missing if we get an earlier sequence number again */
                /* TODO: taking time into account would give better idea of whether missing or repeated... */
                else if (((snLimit + sequenceNumber - expectedSequenceNumber) % snLimit) < 10) {
                    p_report_in_frame->state = SN_Missing;
                    tap_info->missingSNs = (snLimit + sequenceNumber - expectedSequenceNumber) % snLimit;
                    p_report_in_frame->firstSN = expectedSequenceNumber;
                    p_report_in_frame->lastSN = (snLimit + sequenceNumber - 1) % snLimit;

                    p_report_in_frame->sequenceExpected = expectedSequenceNumber;
                    p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;
                    p_report_in_frame->previousSegmentIncomplete = p_channel_status->previousSegmentIncomplete;

                    /* Update channel status to remember *this* frame */
                    p_channel_status->previousFrameNum = pinfo->fd->num;
                    p_channel_status->previousSequenceNumber = sequenceNumber;
                    p_channel_status->previousSegmentIncomplete = !last_includes_end;
                }
                else {
                    /* An SN has been repeated */
                    p_report_in_frame->state = SN_Repeated;
                    p_report_in_frame->firstSN = sequenceNumber;

                    p_report_in_frame->sequenceExpected = expectedSequenceNumber;
                    p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;
                }
            }
            else {
                /* SN was OK */
                p_report_in_frame->sequenceExpected = expectedSequenceNumber;
                p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;
                p_report_in_frame->previousSegmentIncomplete = p_channel_status->previousSegmentIncomplete;

                /* Update channel status to remember *this* frame */
                p_channel_status->previousFrameNum = pinfo->fd->num;
                p_channel_status->previousSequenceNumber = sequenceNumber;
                p_channel_status->previousSegmentIncomplete = !last_includes_end;

                if (p_channel_status->reassembly_info) {
                    /* Add next segment to reassembly info */
                    reassembly_add_segment(p_channel_status, sequenceNumber, pinfo->fd->num,
                                           tvb, firstSegmentOffset, firstSegmentLength);

                    /* The end of existing reassembly? */
                    if (!first_includes_start &&
                        ((number_of_segments > 1) || last_includes_end)) {

                        reassembly_record(p_channel_status, pinfo, sequenceNumber, p_rlc_lte_info);
                        reassembly_destroy(p_channel_status);
                    }
                }

                /* The start of a new reassembly? */
                if (!last_includes_end &&
                    ((number_of_segments > 1) || first_includes_start)) {

                    guint16 lastSegmentLength = tvb_length(tvb)-lastSegmentOffset;

                    if (global_rlc_lte_reassembly) {
                        reassembly_reset(p_channel_status);
                        reassembly_add_segment(p_channel_status, sequenceNumber,
                                               pinfo->fd->num,
                                               tvb, lastSegmentOffset, lastSegmentLength);
                    }
                }

                if (p_report_in_frame->previousFrameNum != 0) {
                    /* Get report for previous frame */
                    sequence_analysis_report *p_previous_report;
                    if (p_rlc_lte_info->UMSequenceNumberLength == 5) {
                        snLimit = 32;
                    }
                    else {
                        snLimit = 1024;
                    }

                    p_previous_report = (sequence_analysis_report*)g_hash_table_lookup(sequence_analysis_report_hash,
                                                                                       get_report_hash_key((sequenceNumber+snLimit-1) % snLimit,
                                                                                                           p_report_in_frame->previousFrameNum,
                                                                                                           p_rlc_lte_info,
                                                                                                           FALSE));
                    /* It really shouldn't be NULL... */
                    if (p_previous_report != NULL) {
                        /* Point it forward to this one */
                        p_previous_report->nextFrameNum = pinfo->fd->num;
                    }
                }
            }

            break;

        case RLC_AM_MODE:

            /* Work out expected sequence number */
            if (!createdChannel) {
                expectedSequenceNumber = (p_channel_status->previousSequenceNumber + 1) % 1024;
            }
            else {
                /* Whatever we got is fine.. */
                expectedSequenceNumber = sequenceNumber;
            }

            /* For AM, may be:
               - expected Sequence number OR
               - previous frame repeated
               - old SN being sent (in response to NACK)
               - new SN, but with frames missed out
               Assume window whose front is at expectedSequenceNumber */

            /* First of all, check to see whether frame is judged to be MAC Retx */
            if (is_mac_lte_frame_retx(pinfo, p_rlc_lte_info->direction)) {
                /* Just report that this is a MAC Retx */
                p_report_in_frame->state = SN_MAC_Retx;
                p_report_in_frame->firstSN = sequenceNumber;

                /* No channel state to update */
                break;
            }

            if (sequenceNumber != expectedSequenceNumber) {
                /* Don't trash reassembly info if this looks like a close  retx... */
                if (((1024 + sequenceNumber - expectedSequenceNumber) % 1024) < 50) {
                    reassembly_destroy(p_channel_status);
                }
            }

            /* Expected? */
            if (sequenceNumber == expectedSequenceNumber) {
                /* Set report for this frame */
                p_report_in_frame->sequenceExpectedCorrect = TRUE;
                p_report_in_frame->sequenceExpected = expectedSequenceNumber;
                p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;
                p_report_in_frame->previousSegmentIncomplete = p_channel_status->previousSegmentIncomplete;
                p_report_in_frame->state = SN_OK;

                /* Update channel status */
                p_channel_status->previousSequenceNumber = sequenceNumber;
                p_channel_status->previousFrameNum = pinfo->fd->num;
                p_channel_status->previousSegmentIncomplete = !last_includes_end;


                if (p_channel_status->reassembly_info) {

                    /* Add next segment to reassembly info */
                    reassembly_add_segment(p_channel_status, sequenceNumber, pinfo->fd->num,
                                           tvb, firstSegmentOffset, firstSegmentLength);

                    /* The end of existing reassembly? */
                    if (!first_includes_start &&
                        ((number_of_segments > 1) || last_includes_end)) {

                        reassembly_record(p_channel_status, pinfo,
                                          sequenceNumber, p_rlc_lte_info);
                        reassembly_destroy(p_channel_status);
                    }
                }

                /* The start of a new reassembly? */
                if (!last_includes_end &&
                    ((number_of_segments > 1) || first_includes_start)) {

                    guint16 lastSegmentLength = tvb_length(tvb)-lastSegmentOffset;
                    if (global_rlc_lte_reassembly) {
                        reassembly_reset(p_channel_status);
                        reassembly_add_segment(p_channel_status, sequenceNumber,
                                               pinfo->fd->num,
                                               tvb, lastSegmentOffset, lastSegmentLength);
                    }
                }

                if (p_report_in_frame->previousFrameNum != 0) {
                    /* Get report for previous frame */
                    sequence_analysis_report *p_previous_report;
                    p_previous_report = (sequence_analysis_report*)g_hash_table_lookup(sequence_analysis_report_hash,
                                                                                       get_report_hash_key((sequenceNumber+1023) % 1024,
                                                                                                           p_report_in_frame->previousFrameNum,
                                                                                                           p_rlc_lte_info,
                                                                                                           FALSE));
                    /* It really shouldn't be NULL... */
                    if (p_previous_report != NULL) {
                        /* Point it forward to this one */
                        p_previous_report->nextFrameNum = pinfo->fd->num;
                    }
                }

            }

            /* Previous subframe repeated? */
            else if (((sequenceNumber+1) % 1024) == expectedSequenceNumber) {
                p_report_in_frame->state = SN_Repeated;

                /* Set report for this frame */
                p_report_in_frame->sequenceExpectedCorrect = FALSE;
                p_report_in_frame->sequenceExpected = expectedSequenceNumber;
                p_report_in_frame->firstSN = sequenceNumber;
                p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;
                p_report_in_frame->previousSegmentIncomplete = p_channel_status->previousSegmentIncomplete;


                /* Really should be nothing to update... */
                p_channel_status->previousSequenceNumber = sequenceNumber;
                p_channel_status->previousFrameNum = pinfo->fd->num;
                p_channel_status->previousSegmentIncomplete = !last_includes_end;
            }

            else {
                /* Need to work out if new (with skips, or likely a retx (due to NACK)) */
                int delta  = (1024 + expectedSequenceNumber - sequenceNumber) % 1024;

                /* Rx window is 512, so check to see if this is a retx */
                if (delta < 512) {
                    /* Probably a retx due to receiving NACK */
                    p_report_in_frame->state = SN_Retx;

                    p_report_in_frame->firstSN = sequenceNumber;
                    /* Don't update anything in channel state */
                }

                else {
                    /* Ahead of expected SN. Assume frames have been missed */
                    p_report_in_frame->state = SN_Missing;

                    p_report_in_frame->firstSN = expectedSequenceNumber;
                    p_report_in_frame->lastSN = (1024 + sequenceNumber-1) % 1024;

                    /* Update channel state - forget about missed SNs */
                    p_report_in_frame->sequenceExpected = expectedSequenceNumber;
                    p_channel_status->previousSequenceNumber = sequenceNumber;
                    p_channel_status->previousFrameNum = pinfo->fd->num;
                    p_channel_status->previousSegmentIncomplete = !last_includes_end;
                }
            }
            break;

        default:
            /* Shouldn't get here! */
            return SN_Error;
    }

    /* Associate with this frame number */
    g_hash_table_insert(sequence_analysis_report_hash,
                        get_report_hash_key(sequenceNumber, pinfo->fd->num, p_rlc_lte_info, TRUE),
                        p_report_in_frame);

    /* Add state report for this frame into tree */
    addChannelSequenceInfo(p_report_in_frame, isControlFrame, p_rlc_lte_info, sequenceNumber,
                           first_includes_start, tap_info, pinfo, tree, tvb);

    return p_report_in_frame->state;
}


/* Add to the tree values associated with sequence analysis for this frame */
static void addChannelRepeatedNACKInfo(channel_repeated_nack_report *p,
                                       rlc_lte_info *p_rlc_lte_info,
                                       packet_info *pinfo, proto_tree *tree,
                                       tvbuff_t *tvb)
{
    proto_tree *seqnum_tree;
    proto_item *seqnum_ti;
    proto_item *ti;
    gint       n;

    /* Create subtree */
    seqnum_ti = proto_tree_add_string_format(tree,
                                             hf_rlc_lte_sequence_analysis,
                                             tvb, 0, 0,
                                             "", "Sequence Analysis");
    seqnum_tree = proto_item_add_subtree(seqnum_ti,
                                         ett_rlc_lte_sequence_analysis);
    PROTO_ITEM_SET_GENERATED(seqnum_ti);

    /* OK = FALSE */
    ti = proto_tree_add_boolean(seqnum_tree, hf_rlc_lte_sequence_analysis_ok,
                                tvb, 0, 0, FALSE);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Add each repeated NACK as item & expert info */
    for (n=0; n < p->noOfNACKsRepeated; n++) {

        ti = proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_repeated_nack,
                                 tvb, 0, 0, p->repeatedNACKs[n]);
        PROTO_ITEM_SET_GENERATED(ti);

        expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_ERROR,
                               "Same SN  (%u) NACKd for %s on UE %u in successive Status PDUs",
                               p->repeatedNACKs[n],
                               val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                               p_rlc_lte_info->ueid);
    }

    /* Link back to previous status report */
    ti = proto_tree_add_uint(seqnum_tree, hf_rlc_lte_sequence_analysis_repeated_nack_original_frame,
                             tvb, 0, 0, p->previousFrameNum);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Append count to sequence analysis root */
    proto_item_append_text(seqnum_ti, " - %u SNs repeated from previous Status PDU",
                           p->noOfNACKsRepeated);
}


/* Update the channel repeated NACK status and set report for this frame */
static void checkChannelRepeatedNACKInfo(packet_info *pinfo,
                                         rlc_lte_info *p_rlc_lte_info,
                                         rlc_lte_tap_info *tap_info,
                                         proto_tree *tree,
                                         tvbuff_t *tvb)
{
    channel_hash_key   channel_key;
    channel_hash_key   *p_channel_key;
    channel_repeated_nack_status     *p_channel_status;
    channel_repeated_nack_report  *p_report_in_frame = NULL;

    guint16         noOfNACKsRepeated = 0;
    guint16         repeatedNACKs[MAX_NACKs];
    gint            n, i, j;

    /* If find state_report_in_frame already, use that and get out */
    if (pinfo->fd->flags.visited) {
        p_report_in_frame = (channel_repeated_nack_report*)g_hash_table_lookup(repeated_nack_report_hash,
                                                                               get_report_hash_key(0, pinfo->fd->num,
                                                                                                   p_rlc_lte_info, FALSE));
        if (p_report_in_frame != NULL) {
            addChannelRepeatedNACKInfo(p_report_in_frame, p_rlc_lte_info,
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
    memset(repeatedNACKs, 0, sizeof(repeatedNACKs));

    /* Do the table lookup */
    p_channel_status = (channel_repeated_nack_status*)g_hash_table_lookup(repeated_nack_channel_hash, &channel_key);

    /* Create table entry if necessary */
    if (p_channel_status == NULL) {

        /* Allocate a new key and value */
        p_channel_key = se_alloc(sizeof(channel_hash_key));
        p_channel_status = se_alloc0(sizeof(channel_repeated_nack_status));

        /* Copy key contents */
        memcpy(p_channel_key, &channel_key, sizeof(channel_hash_key));

        /* Add entry to table */
        g_hash_table_insert(repeated_nack_channel_hash, p_channel_key, p_channel_status);
    }

    /* Compare NACKs in channel status with NACKs in tap_info.
       Note any that are repeated */
    for (i=0; i < p_channel_status->noOfNACKs; i++) {
        for (j=0; j < MIN(tap_info->noOfNACKs, MAX_NACKs); j++) {
            if (tap_info->NACKs[j] == p_channel_status->NACKs[i]) {
                /* Don't add the same repeated NACK twice! */
                if ((noOfNACKsRepeated == 0) ||
                    (repeatedNACKs[noOfNACKsRepeated-1] != p_channel_status->NACKs[i])) {

                    repeatedNACKs[noOfNACKsRepeated++] = p_channel_status->NACKs[i];
                }
            }
        }
    }

    /* Copy NACKs from tap_info into channel status for next time! */
    p_channel_status->noOfNACKs = 0;
    for (n=0; n < MIN(tap_info->noOfNACKs, MAX_NACKs); n++) {
        p_channel_status->NACKs[p_channel_status->noOfNACKs++] = tap_info->NACKs[n];
    }

    if (noOfNACKsRepeated >= 1) {
        /* Create space for frame state_report */
        p_report_in_frame = se_alloc(sizeof(channel_repeated_nack_report));

        /* Copy in found duplicates */
        for (n=0; n < MIN(tap_info->noOfNACKs, MAX_NACKs); n++) {
            p_report_in_frame->repeatedNACKs[n] = repeatedNACKs[n];
        }
        p_report_in_frame->noOfNACKsRepeated = noOfNACKsRepeated;

        p_report_in_frame->previousFrameNum = p_channel_status->frameNum;

        /* Associate with this frame number */
        g_hash_table_insert(repeated_nack_report_hash,
                            get_report_hash_key(0, pinfo->fd->num,
                                                p_rlc_lte_info, TRUE),
                            p_report_in_frame);

        /* Add state report for this frame into tree */
        addChannelRepeatedNACKInfo(p_report_in_frame, p_rlc_lte_info,
                                   pinfo, tree, tvb);
    }

    /* Save frame number for next comparison */
    p_channel_status->frameNum = pinfo->fd->num;
}

/* Check that the ACK is consistent with data the expected sequence number
   in the other direction */
static void checkChannelACKWindow(guint16 ack_sn,
                                  packet_info *pinfo,
                                  rlc_lte_info *p_rlc_lte_info,
                                  rlc_lte_tap_info *tap_info,
                                  proto_tree *tree,
                                  tvbuff_t *tvb)
{
    channel_hash_key   channel_key;
    channel_sequence_analysis_status  *p_channel_status;
    sequence_analysis_report  *p_report_in_frame = NULL;

    /* If find stat_report_in_frame already, use that and get out */
    if (pinfo->fd->flags.visited) {
        p_report_in_frame = (sequence_analysis_report*)g_hash_table_lookup(sequence_analysis_report_hash,
                                                                           get_report_hash_key(0, pinfo->fd->num,
                                                                                               p_rlc_lte_info,
                                                                                               FALSE));
        if (p_report_in_frame != NULL) {
            /* Add any info to tree */
            addChannelSequenceInfo(p_report_in_frame, TRUE, p_rlc_lte_info,
                                   0, FALSE,
                                   tap_info, pinfo, tree, tvb);
            return;
        }
        else {
            /* Give up - we must have tried already... */
            return;
        }
    }

    /*******************************************************************/
    /* Find an entry for this channel state (in the opposite direction */
    channel_key.ueId = p_rlc_lte_info->ueid;
    channel_key.channelType = p_rlc_lte_info->channelType;
    channel_key.channelId = p_rlc_lte_info->channelId;
    channel_key.direction =
        (p_rlc_lte_info->direction == DIRECTION_UPLINK) ? DIRECTION_DOWNLINK : DIRECTION_UPLINK;

    /* Do the table lookup */
    p_channel_status = (channel_sequence_analysis_status*)g_hash_table_lookup(sequence_analysis_channel_hash, &channel_key);

    /* Create table entry if necessary */
    if (p_channel_status == NULL) {
        return;
    }

    /* Is it in the rx window? This test will catch if its ahead, but we don't
       really know what the back of the tx window is... */
    if (((1024 + p_channel_status->previousSequenceNumber+1 - ack_sn) % 1024) > 512) {

        /* Set result */
        p_report_in_frame = se_alloc0(sizeof(sequence_analysis_report));
        p_report_in_frame->state = ACK_Out_of_Window;
        p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;
        p_report_in_frame->sequenceExpected = p_channel_status->previousSequenceNumber;
        p_report_in_frame->firstSN = ack_sn;

        /* Associate with this frame number */
        g_hash_table_insert(sequence_analysis_report_hash,
                            get_report_hash_key(0, pinfo->fd->num,
                                                p_rlc_lte_info, TRUE),
                            p_report_in_frame);

        /* Add state report for this frame into tree */
        addChannelSequenceInfo(p_report_in_frame, TRUE, p_rlc_lte_info, 0,
                               FALSE, tap_info, pinfo, tree, tvb);
    }
}




/***************************************************/
/* Transparent mode PDU. Call RRC if configured to */
static void dissect_rlc_lte_tm(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree,
                               int offset,
                               rlc_lte_info *p_rlc_lte_info,
                               proto_item *top_ti)
{
    proto_item *raw_tm_ti;
    proto_item *tm_ti;

    /* Create hidden TM root */
    tm_ti = proto_tree_add_string_format(tree, hf_rlc_lte_tm,
                                         tvb, offset, 0, "", "TM");
    PROTO_ITEM_SET_HIDDEN(tm_ti);

    /* Remaining bytes are all data */
    raw_tm_ti = proto_tree_add_item(tree, hf_rlc_lte_tm_data, tvb, offset, -1, ENC_NA);
    if (!global_rlc_lte_call_rrc_for_ccch) {
        write_pdu_label_and_info(top_ti, NULL, pinfo,
                                 "   [%u-bytes]", tvb_length_remaining(tvb, offset));
    }

    if (global_rlc_lte_call_rrc_for_ccch) {
        tvbuff_t *rrc_tvb = tvb_new_subset(tvb, offset, -1, tvb_length_remaining(tvb, offset));
        volatile dissector_handle_t protocol_handle = 0;

        switch (p_rlc_lte_info->channelType) {
            case CHANNEL_TYPE_CCCH:
                if (p_rlc_lte_info->direction == DIRECTION_UPLINK) {
                    protocol_handle = find_dissector("lte_rrc.ul_ccch");
                }
                else {
                    protocol_handle = find_dissector("lte_rrc.dl_ccch");
                }
                break;

            case CHANNEL_TYPE_BCCH_BCH:
                protocol_handle = find_dissector("lte_rrc.bcch_bch");
                break;
            case CHANNEL_TYPE_BCCH_DL_SCH:
                protocol_handle = find_dissector("lte_rrc.bcch_dl_sch");
                break;
            case CHANNEL_TYPE_PCCH:
                protocol_handle = find_dissector("lte_rrc.pcch");
                break;

            case CHANNEL_TYPE_SRB:
            case CHANNEL_TYPE_DRB:
            case CHANNEL_TYPE_MCCH:

            default:
                /* Shouldn't happen, just return... */
                return;
        }

        /* Hide raw view of bytes */
        PROTO_ITEM_SET_HIDDEN(raw_tm_ti);

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
static void dissect_rlc_lte_um(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree,
                               int offset,
                               rlc_lte_info *p_rlc_lte_info,
                               proto_item *top_ti,
                               rlc_lte_tap_info *tap_info)
{
    guint64 framing_info;
    gboolean first_includes_start;
    gboolean last_includes_end;
    guint64 fixed_extension;
    guint64 sn;
    gint    start_offset = offset;
    proto_item *um_ti;
    proto_tree *um_header_tree;
    proto_item *um_header_ti;
    gboolean is_truncated;
    proto_item *truncated_ti;
    rlc_channel_reassembly_info *reassembly_info = NULL;
    sequence_analysis_state seq_anal_state = SN_OK;

    /* Hidden UM root */
    um_ti = proto_tree_add_string_format(tree, hf_rlc_lte_um,
                                         tvb, offset, 0, "", "UM");
    PROTO_ITEM_SET_HIDDEN(um_ti);

    /* Add UM header subtree */
    um_header_ti = proto_tree_add_string_format(tree, hf_rlc_lte_um_header,
                                                tvb, offset, 0,
                                                "", "UM header");
    um_header_tree = proto_item_add_subtree(um_header_ti,
                                            ett_rlc_lte_um_header);


    /*******************************/
    /* Fixed UM header             */
    if (p_rlc_lte_info->UMSequenceNumberLength == UM_SN_LENGTH_5_BITS) {
        /* Framing info (2 bits) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_fi,
                                    tvb, offset*8, 2,
                                    &framing_info, ENC_BIG_ENDIAN);

        /* Extension (1 bit) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_fixed_e, tvb,
                                    (offset*8) + 2, 1,
                                    &fixed_extension, ENC_BIG_ENDIAN);

        /* Sequence Number (5 bit) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_sn, tvb,
                                    (offset*8) + 3, 5,
                                    &sn, ENC_BIG_ENDIAN);
        offset++;
    }
    else if (p_rlc_lte_info->UMSequenceNumberLength == UM_SN_LENGTH_10_BITS) {
        guint8 reserved;
        proto_item *ti;

        /* Check 3 Reserved bits */
        reserved = (tvb_get_guint8(tvb, offset) & 0xe0) >> 5;
        ti = proto_tree_add_item(um_header_tree, hf_rlc_lte_um_fixed_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (reserved != 0) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                      "RLC UM Fixed header Reserved bits not zero (found 0x%x)", reserved);
        }

        /* Framing info (2 bits) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_fi,
                                    tvb, (offset*8)+3, 2,
                                    &framing_info, ENC_BIG_ENDIAN);

        /* Extension (1 bit) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_fixed_e, tvb,
                                    (offset*8) + 5, 1,
                                    &fixed_extension, ENC_BIG_ENDIAN);

        /* Sequence Number (10 bits) */
        proto_tree_add_bits_ret_val(um_header_tree, hf_rlc_lte_um_sn, tvb,
                                    (offset*8) + 6, 10,
                                    &sn, ENC_BIG_ENDIAN);
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

    tap_info->sequenceNumber = (guint16)sn;

    /* Show SN in info column */
    write_pdu_label_and_info(top_ti, um_header_ti, pinfo, "  SN=%-4u", (guint16)sn);

    proto_item_set_len(um_header_ti, offset-start_offset);


    /*************************************/
    /* UM header extension               */
    if (fixed_extension) {
        offset = dissect_rlc_lte_extension_header(tvb, pinfo, um_header_tree, offset);
    }

    /* Extract these 2 flags from framing_info */
    first_includes_start = ((guint8)framing_info & 0x02) == 0;
    last_includes_end =    ((guint8)framing_info & 0x01) == 0;

    if (global_rlc_lte_headers_expected) {
        /* There might not be any data, if only headers (plus control data) were logged */
        is_truncated = (tvb_length_remaining(tvb, offset) == 0);
        truncated_ti = proto_tree_add_uint(tree, hf_rlc_lte_header_only, tvb, 0, 0,
                                           is_truncated);
        if (is_truncated) {
            int n;
            PROTO_ITEM_SET_GENERATED(truncated_ti);
            expert_add_info_format(pinfo, truncated_ti, PI_SEQUENCE, PI_NOTE,
                                   "RLC PDU SDUs have been omitted");

            /* Show in the info column how long the data would be */
            for (n=0; n < s_number_of_extensions; n++) {
                show_PDU_in_info(pinfo, top_ti, s_lengths[n],
                                 (n==0) ? first_includes_start : TRUE,
                                 TRUE);
                offset += s_lengths[n];
            }
            /* Last one */
            show_PDU_in_info(pinfo, top_ti, p_rlc_lte_info->pduLength - offset,
                             (s_number_of_extensions == 0) ? first_includes_start : TRUE,
                             last_includes_end);
            return;
        }
        else {
            PROTO_ITEM_SET_HIDDEN(truncated_ti);
        }
    }

    /* Show number of extensions in header root */
    if (s_number_of_extensions > 0) {
        proto_item_append_text(um_header_ti, " (%u extensions)", s_number_of_extensions);
    }

    /* Call sequence analysis function now */
    if (((global_rlc_lte_um_sequence_analysis == SEQUENCE_ANALYSIS_MAC_ONLY) &&
         (p_get_proto_data(pinfo->fd, proto_mac_lte) != NULL)) ||
        ((global_rlc_lte_um_sequence_analysis == SEQUENCE_ANALYSIS_RLC_ONLY) &&
         (p_get_proto_data(pinfo->fd, proto_mac_lte) == NULL))) {

        guint16 lastSegmentOffset = offset;
        if (s_number_of_extensions >= 1) {
            int n;
            lastSegmentOffset = offset;
            for (n=0; n < s_number_of_extensions; n++) {
                lastSegmentOffset += s_lengths[n];
            }
        }

        seq_anal_state = checkChannelSequenceInfo(pinfo, tvb, p_rlc_lte_info,
                                                  FALSE,
                                                  s_number_of_extensions+1,
                                                  offset,
                                                  s_number_of_extensions ?
                                                      s_lengths[0] :
                                                      p_rlc_lte_info->pduLength - offset,
                                                  lastSegmentOffset,
                                                  (guint16)sn, first_includes_start, last_includes_end,
                                                  FALSE, /* UM doesn't re-segment */
                                                  tap_info, um_header_tree);
    }


    /*************************************/
    /* Data                              */

    reassembly_info = (rlc_channel_reassembly_info *)g_hash_table_lookup(reassembly_report_hash,
                                                                         get_report_hash_key((guint16)sn, pinfo->fd->num,
                                                                                             p_rlc_lte_info, FALSE));

    if (s_number_of_extensions > 0) {
        /* Show each data segment separately */
        int n;
        for (n=0; n < s_number_of_extensions; n++) {
            show_PDU_in_tree(pinfo, tree, tvb, offset, s_lengths[n], p_rlc_lte_info,
                             (n==0) ? first_includes_start : TRUE,
                             (n==0) ? reassembly_info : NULL,
                             seq_anal_state);
            show_PDU_in_info(pinfo, top_ti, s_lengths[n],
                             (n==0) ? first_includes_start : TRUE,
                             TRUE);
            tvb_ensure_bytes_exist(tvb, offset, s_lengths[n]);
            offset += s_lengths[n];
        }
    }

    /* Final data element */
    show_PDU_in_tree(pinfo, tree, tvb, offset, -1, p_rlc_lte_info,
                     ((s_number_of_extensions == 0) ? first_includes_start : TRUE) && last_includes_end,
                     (s_number_of_extensions == 0) ? reassembly_info : NULL,
                     seq_anal_state);
    show_PDU_in_info(pinfo, top_ti, (guint16)tvb_length_remaining(tvb, offset),
                     (s_number_of_extensions == 0) ? first_includes_start : TRUE,
                     last_includes_end);
}



/* Dissect an AM STATUS PDU */
static void dissect_rlc_lte_am_status_pdu(tvbuff_t *tvb,
                                          packet_info *pinfo,
                                          proto_tree *tree,
                                          proto_item *status_ti,
                                          int offset,
                                          proto_item *top_ti,
                                          rlc_lte_info *p_rlc_lte_info,
                                          rlc_lte_tap_info *tap_info)
{
    guint8     cpt;
    guint64    ack_sn, nack_sn;
    guint16    nack_count = 0;
    guint64    e1 = 0, e2 = 0;
    guint64    so_start, so_end;
    int        bit_offset = offset * 8;
    proto_item *ti;

    /****************************************************************/
    /* Part of RLC control PDU header                               */

    /* Control PDU Type (CPT) */
    cpt = (tvb_get_guint8(tvb, offset) & 0xf0) >> 4;
    ti = proto_tree_add_item(tree, hf_rlc_lte_am_cpt, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (cpt != 0) {
        /* Protest and stop - only know about STATUS PDUs */
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "RLC Control frame type %u not handled", cpt);
        return;
    }

    /* The Status PDU itself starts 4 bits into the byte */
    bit_offset += 4;

    /* ACK SN */
    proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_ack_sn, tvb,
                                bit_offset, 10, &ack_sn, ENC_BIG_ENDIAN);
    bit_offset += 10;
    write_pdu_label_and_info(top_ti, status_ti, pinfo, "  ACK_SN=%-4u", (guint16)ack_sn);

    tap_info->ACKNo = (guint16)ack_sn;

    /* E1 */
    proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_e1, tvb,
                                bit_offset, 1, &e1, ENC_BIG_ENDIAN);

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
                                                  bit_offset, 10, &nack_sn, ENC_BIG_ENDIAN);
            bit_offset += 10;
            write_pdu_label_and_info(top_ti, NULL, pinfo, "  NACK_SN=%-4u", (guint16)nack_sn);

            /* We shouldn't NACK the ACK_SN! */
            if (nack_sn == ack_sn) {
                expert_add_info_format(pinfo, nack_ti, PI_MALFORMED, PI_ERROR,
                                       "Status PDU shouldn't ACK and NACK the same sequence number (%" G_GINT64_MODIFIER "u)",
                                       ack_sn);
            }

            /* NACK should always be 'behind' the ACK */
            if ((1024 + ack_sn - nack_sn) % 1024 > 512) {
                expert_add_info_format(pinfo, nack_ti, PI_MALFORMED, PI_ERROR,
                                       "NACK must not be ahead of ACK in status PDU");
            }

            /* Copy into struct, but don't exceed buffer */
            if (nack_count < MAX_NACKs) {
                tap_info->NACKs[nack_count++] = (guint16)nack_sn;
            }
            else {
                /* Let it get bigger than the array for accurate stats... */
                nack_count++;
            }

            /* E1 */
            proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_e1, tvb,
                                        bit_offset, 1, &e1, ENC_BIG_ENDIAN);
            bit_offset++;

            /* E2 */
            proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_e2, tvb,
                                        bit_offset, 1, &e2, ENC_BIG_ENDIAN);

            /* Report as expert info */
            if (e2) {
                expert_add_info_format(pinfo, nack_ti, PI_SEQUENCE, PI_WARN,
                                       "Status PDU reports NACK (partial) on %s for UE %u",
                                       val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                       p_rlc_lte_info->ueid);
            }
            else {
                expert_add_info_format(pinfo, nack_ti, PI_SEQUENCE, PI_WARN,
                                       "Status PDU reports NACK on %s for UE %u",
                                       val_to_str_const(p_rlc_lte_info->direction, direction_vals, "Unknown"),
                                       p_rlc_lte_info->ueid);
            }

            bit_offset++;
        }

        if (e2) {
            /* Read SOstart, SOend */
            proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_so_start, tvb,
                                        bit_offset, 15, &so_start, ENC_BIG_ENDIAN);
            bit_offset += 15;

            proto_tree_add_bits_ret_val(tree, hf_rlc_lte_am_so_end, tvb,
                                        bit_offset, 15, &so_end, ENC_BIG_ENDIAN);
            bit_offset += 15;


            if ((guint16)so_end == 0x7fff) {
                write_pdu_label_and_info(top_ti, NULL, pinfo,
                                         " (SOstart=%u SOend=<END-OF_PDU>)",
                                         (guint16)so_start);
            }
            else {
                write_pdu_label_and_info(top_ti, NULL, pinfo,
                                         " (SOstart=%u SOend=%u)",
                                         (guint16)so_start, (guint16)so_end);
            }

            /* Reset this flag here */
            e2 = 0;
        }
    } while (e1 || e2);

    if (nack_count > 0) {
        proto_item *count_ti = proto_tree_add_uint(tree, hf_rlc_lte_am_nacks, tvb, 0, 1, nack_count);
        PROTO_ITEM_SET_GENERATED(count_ti);
        proto_item_append_text(status_ti, "  (%u NACKs)", nack_count);
        tap_info->noOfNACKs = nack_count;
    }

    /* Check that we've reached the end of the PDU. If not, show malformed */
    offset = (bit_offset+7) / 8;
    if (tvb_length_remaining(tvb, offset) > 0) {
        expert_add_info_format(pinfo, status_ti, PI_MALFORMED, PI_ERROR,
                               "%cL %u bytes remaining after Status PDU complete",
                               (p_rlc_lte_info->direction == DIRECTION_UPLINK) ? 'U' : 'D',
                               tvb_length_remaining(tvb, offset));
    }

    /* Set selected length of control tree */
    proto_item_set_len(status_ti, offset);

    /* Repeated NACK analysis & check ACK-SN is in range */
    if (((global_rlc_lte_am_sequence_analysis == SEQUENCE_ANALYSIS_MAC_ONLY) &&
         (p_get_proto_data(pinfo->fd, proto_mac_lte) != NULL)) ||
        ((global_rlc_lte_am_sequence_analysis == SEQUENCE_ANALYSIS_RLC_ONLY) &&
         (p_get_proto_data(pinfo->fd, proto_mac_lte) == NULL))) {

        if (!is_mac_lte_frame_retx(pinfo, p_rlc_lte_info->direction)) {
            checkChannelRepeatedNACKInfo(pinfo, p_rlc_lte_info, tap_info, tree, tvb);
            checkChannelACKWindow((guint16)ack_sn, pinfo, p_rlc_lte_info, tap_info, tree, tvb);
        }
     }
}


/***************************************************/
/* Acknowledged mode PDU                           */
static void dissect_rlc_lte_am(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree,
                               int offset,
                               rlc_lte_info *p_rlc_lte_info,
                               proto_item *top_ti,
                               rlc_lte_tap_info *tap_info)
{
    guint8 is_data;
    guint8 is_resegmented;
    guint8 polling;
    guint8 fixed_extension;
    guint8 framing_info;
    gboolean first_includes_start;
    gboolean last_includes_end;
    proto_item *am_ti;
    proto_tree *am_header_tree;
    proto_item *am_header_ti;
    gint   start_offset = offset;
    guint16    sn;
    gboolean is_truncated;
    proto_item *truncated_ti;
    rlc_channel_reassembly_info *reassembly_info = NULL;
    sequence_analysis_state seq_anal_state = SN_OK;

    /* Hidden AM root */
    am_ti = proto_tree_add_string_format(tree, hf_rlc_lte_am,
                                         tvb, offset, 0, "", "AM");
    PROTO_ITEM_SET_HIDDEN(am_ti);

    /* Add AM header subtree */
    am_header_ti = proto_tree_add_string_format(tree, hf_rlc_lte_am_header,
                                                tvb, offset, 0,
                                                "", "AM Header ");
    am_header_tree = proto_item_add_subtree(am_header_ti,
                                            ett_rlc_lte_am_header);

    /* First bit is Data/Control flag           */
    is_data = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_data_control, tvb, offset, 1, ENC_BIG_ENDIAN);
    tap_info->isControlPDU = !is_data;

    if (!is_data) {
        /**********************/
        /* Status PDU         */
        write_pdu_label_and_info(top_ti, NULL, pinfo, " [CONTROL]");

        /* Control PDUs are a completely separate format  */
        dissect_rlc_lte_am_status_pdu(tvb, pinfo, am_header_tree, am_header_ti,
                                      offset, top_ti,
                                      p_rlc_lte_info, tap_info);
        return;
    }

    /******************************/
    /* Data PDU fixed header      */

    /* Re-segmentation Flag (RF) field */
    is_resegmented = (tvb_get_guint8(tvb, offset) & 0x40) >> 6;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_rf, tvb, offset, 1, ENC_BIG_ENDIAN);
    tap_info->isResegmented = is_resegmented;

    write_pdu_label_and_info(top_ti, NULL, pinfo,
                             (is_resegmented) ? " [DATA-SEGMENT]" : " [DATA]");

    /* Polling bit */
    polling = (tvb_get_guint8(tvb, offset) & 0x20) >> 5;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_p, tvb, offset, 1, ENC_BIG_ENDIAN);

    write_pdu_label_and_info(top_ti, NULL, pinfo, (polling) ? " (P) " : "     ");
    if (polling) {
        proto_item_append_text(am_header_ti, " (P) ");
    }

    /* Framing Info */
    framing_info = (tvb_get_guint8(tvb, offset) & 0x18) >> 3;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_fi, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Extension bit */
    fixed_extension = (tvb_get_guint8(tvb, offset) & 0x04) >> 2;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_fixed_e, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Sequence Number */
    sn = tvb_get_ntohs(tvb, offset) & 0x03ff;
    proto_tree_add_item(am_header_tree, hf_rlc_lte_am_fixed_sn, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    tap_info->sequenceNumber = sn;

    write_pdu_label_and_info(top_ti, am_header_ti, pinfo, "sn=%-4u", sn);

    /***************************************/
    /* Dissect extra segment header fields */
    if (is_resegmented) {
        guint16 segmentOffset;

        /* Last Segment Field (LSF) */
        proto_tree_add_item(am_header_tree, hf_rlc_lte_am_segment_lsf, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* SO */
        segmentOffset = tvb_get_ntohs(tvb, offset) & 0x7fff;
        proto_tree_add_item(am_header_tree, hf_rlc_lte_am_segment_so, tvb, offset, 2, ENC_BIG_ENDIAN);
        write_pdu_label_and_info(top_ti, am_header_ti, pinfo, " SO=%u ", segmentOffset);
        offset += 2;
    }

    /*************************************/
    /* AM header extension               */
    if (fixed_extension) {
        offset = dissect_rlc_lte_extension_header(tvb, pinfo, am_header_tree, offset);
    }

    /* Header is now complete */
    proto_item_set_len(am_header_ti, offset-start_offset);

    /* Show number of extensions in header root */
    if (s_number_of_extensions > 0) {
        proto_item_append_text(am_header_ti, " (%u extensions)", s_number_of_extensions);
    }

    /* Extract these 2 flags from framing_info */
    first_includes_start = (framing_info & 0x02) == 0;
    last_includes_end =    (framing_info & 0x01) == 0;

    /* There might not be any data, if only headers (plus control data) were logged */
    if (global_rlc_lte_headers_expected) {
        is_truncated = (tvb_length_remaining(tvb, offset) == 0);
        truncated_ti = proto_tree_add_uint(tree, hf_rlc_lte_header_only, tvb, 0, 0,
                                           is_truncated);
        if (is_truncated) {
            int n;
            PROTO_ITEM_SET_GENERATED(truncated_ti);
            expert_add_info_format(pinfo, truncated_ti, PI_SEQUENCE, PI_NOTE,
                                   "RLC PDU SDUs have been omitted");
            /* Show in the info column how long the data would be */
            for (n=0; n < s_number_of_extensions; n++) {
                show_PDU_in_info(pinfo, top_ti, s_lengths[n],
                                 (n==0) ? first_includes_start : TRUE,
                                 TRUE);
                offset += s_lengths[n];
            }
            /* Last one */
            show_PDU_in_info(pinfo, top_ti, p_rlc_lte_info->pduLength - offset,
                             (s_number_of_extensions == 0) ? first_includes_start : TRUE,
                             last_includes_end);

            /* Just return now */
            return;
        }
        else {
            PROTO_ITEM_SET_HIDDEN(truncated_ti);
        }
    }

    /* Call sequence analysis function now */
    if (((global_rlc_lte_am_sequence_analysis == SEQUENCE_ANALYSIS_MAC_ONLY) &&
         (p_get_proto_data(pinfo->fd, proto_mac_lte) != NULL)) ||
        ((global_rlc_lte_am_sequence_analysis == SEQUENCE_ANALYSIS_RLC_ONLY) &&
         (p_get_proto_data(pinfo->fd, proto_mac_lte) == NULL))) {

        guint16 firstSegmentLength;
        guint16 lastSegmentOffset = offset;
        if (s_number_of_extensions >= 1) {
            int n;
            for (n=0; n < s_number_of_extensions; n++) {
                lastSegmentOffset += s_lengths[n];
            }

            firstSegmentLength = s_lengths[0];
        }
        else {
            firstSegmentLength = tvb_length_remaining(tvb, offset);
        }

        seq_anal_state = checkChannelSequenceInfo(pinfo, tvb, p_rlc_lte_info, FALSE,
                                                  s_number_of_extensions+1,
                                                  offset, firstSegmentLength,
                                                  lastSegmentOffset,
                                                  (guint16)sn,
                                                  first_includes_start, last_includes_end,
                                                  is_resegmented, tap_info, tree);
    }


    /*************************************/
    /* Data                              */

    reassembly_info = (rlc_channel_reassembly_info *)g_hash_table_lookup(reassembly_report_hash,
                                                                         get_report_hash_key((guint16)sn, pinfo->fd->num,
                                                                                             p_rlc_lte_info, FALSE));

    if (s_number_of_extensions > 0) {
        /* Show each data segment separately */
        int n;
        for (n=0; n < s_number_of_extensions; n++) {
            show_PDU_in_tree(pinfo, tree, tvb, offset, s_lengths[n], p_rlc_lte_info,
                             (n==0) ? first_includes_start : TRUE,
                             (n==0) ? reassembly_info : NULL,
                             seq_anal_state);
            show_PDU_in_info(pinfo, top_ti, s_lengths[n],
                             (n==0) ? first_includes_start : TRUE,
                             TRUE);
            tvb_ensure_bytes_exist(tvb, offset, s_lengths[n]);
            offset += s_lengths[n];
        }
    }

    /* Final data element */
    if (tvb_length_remaining(tvb, offset) > 0) {
        show_PDU_in_tree(pinfo, tree, tvb, offset, -1, p_rlc_lte_info,
                         ((s_number_of_extensions == 0) ? first_includes_start : TRUE) && last_includes_end,
                         (s_number_of_extensions == 0) ? reassembly_info : NULL,
                         seq_anal_state);
        show_PDU_in_info(pinfo, top_ti, (guint16)tvb_length_remaining(tvb, offset),
                         (s_number_of_extensions == 0) ? first_includes_start : TRUE,
                         last_includes_end);
    }
    else {
        /* Report that expected data was missing (unless we know it might happen) */
        if (!global_rlc_lte_headers_expected) {
            if (s_number_of_extensions > 0) {
                expert_add_info_format(pinfo, am_header_ti, PI_MALFORMED, PI_ERROR,
                                      "AM data PDU doesn't contain any data beyond extensions");
            }
            else {
                expert_add_info_format(pinfo, am_header_ti, PI_MALFORMED, PI_ERROR,
                                      "AM data PDU doesn't contain any data");
            }
        }
    }
}


/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static gboolean dissect_rlc_lte_heur(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, void *data _U_)
{
    gint                 offset = 0;
    struct rlc_lte_info  *p_rlc_lte_info;
    tvbuff_t             *rlc_tvb;
    guint8               tag = 0;
    gboolean             infoAlreadySet = FALSE;
    gboolean             umSeqNumLengthTagPresent = FALSE;

    /* This is a heuristic dissector, which means we get all the UDP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */

    if (!global_rlc_lte_heur) {
        return FALSE;
    }

    /* Do this again on re-dissection to re-discover offset of actual PDU */

    /* Needs to be at least as long as:
       - the signature string
       - fixed header bytes
       - tag for data
       - at least one byte of RLC PDU payload */
    if ((size_t)tvb_length_remaining(tvb, offset) < (strlen(RLC_LTE_START_STRING)+1+2)) {
        return FALSE;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, RLC_LTE_START_STRING, (gint)strlen(RLC_LTE_START_STRING)) != 0) {
        return FALSE;
    }
    offset += (gint)strlen(RLC_LTE_START_STRING);


    /* If redissecting, use previous info struct (if available) */
    p_rlc_lte_info = p_get_proto_data(pinfo->fd, proto_rlc_lte);
    if (p_rlc_lte_info == NULL) {
        /* Allocate new info struct for this frame */
        p_rlc_lte_info = se_alloc0(sizeof(struct rlc_lte_info));
        infoAlreadySet = FALSE;
    }
    else {
        infoAlreadySet = TRUE;
    }


    /* Read fixed fields */
    p_rlc_lte_info->rlcMode = tvb_get_guint8(tvb, offset++);

    /* Read optional fields */
    while (tag != RLC_LTE_PAYLOAD_TAG) {
        /* Process next tag */
        tag = tvb_get_guint8(tvb, offset++);
        switch (tag) {
            case RLC_LTE_UM_SN_LENGTH_TAG:
                p_rlc_lte_info->UMSequenceNumberLength = tvb_get_guint8(tvb, offset);
                offset++;
                umSeqNumLengthTagPresent = TRUE;
                break;
            case RLC_LTE_DIRECTION_TAG:
                p_rlc_lte_info->direction = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case RLC_LTE_PRIORITY_TAG:
                p_rlc_lte_info->priority = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case RLC_LTE_UEID_TAG:
                p_rlc_lte_info->ueid = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case RLC_LTE_CHANNEL_TYPE_TAG:
                p_rlc_lte_info->channelType = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case RLC_LTE_CHANNEL_ID_TAG:
                p_rlc_lte_info->channelId = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;

            case RLC_LTE_PAYLOAD_TAG:
                /* Have reached data, so set payload length and get out of loop */
                p_rlc_lte_info->pduLength= tvb_length_remaining(tvb, offset);
                continue;

            default:
                /* It must be a recognised tag */
                return FALSE;
        }
    }

    if ((p_rlc_lte_info->rlcMode == RLC_UM_MODE) && (umSeqNumLengthTagPresent == FALSE)) {
        /* Conditional field is not present */
        return FALSE;
    }

    if (!infoAlreadySet) {
        /* Store info in packet */
        p_add_proto_data(pinfo->fd, proto_rlc_lte, p_rlc_lte_info);
    }

    /**************************************/
    /* OK, now dissect as RLC LTE         */

    /* Create tvb that starts at actual RLC PDU */
    rlc_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb)-offset);
    dissect_rlc_lte(rlc_tvb, pinfo, tree);
    return TRUE;
}



/*****************************/
/* Main dissection function. */
/*****************************/

static void dissect_rlc_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree             *rlc_lte_tree;
    proto_tree             *context_tree;
    proto_item             *top_ti;
    proto_item             *context_ti;
    proto_item             *ti;
    proto_item             *mode_ti;
    gint                   offset = 0;
    struct rlc_lte_info    *p_rlc_lte_info = NULL;

    /* Allocate and Zero tap struct */
    rlc_lte_tap_info *tap_info = ep_alloc0(sizeof(rlc_lte_tap_info));

    /* Set protocol name */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC-LTE");

    /* Create protocol tree. */
    top_ti = proto_tree_add_item(tree, proto_rlc_lte, tvb, offset, -1, ENC_NA);
    rlc_lte_tree = proto_item_add_subtree(top_ti, ett_rlc_lte);


    /* Look for packet info! */
    p_rlc_lte_info = p_get_proto_data(pinfo->fd, proto_rlc_lte);

    /* Can't dissect anything without it... */
    if (p_rlc_lte_info == NULL) {
        ti = proto_tree_add_text(rlc_lte_tree, tvb, offset, -1,
                                 "Can't dissect LTE RLC frame because no per-frame info was attached!");
        PROTO_ITEM_SET_GENERATED(ti);
        return;
    }

    /*****************************************/
    /* Show context information              */

    /* Create context root */
    context_ti = proto_tree_add_string_format(rlc_lte_tree, hf_rlc_lte_context,
                                              tvb, offset, 0, "", "Context");
    context_tree = proto_item_add_subtree(context_ti, ett_rlc_lte_context);
    PROTO_ITEM_SET_GENERATED(context_ti);

    ti = proto_tree_add_uint(context_tree, hf_rlc_lte_context_direction,
                             tvb, 0, 0, p_rlc_lte_info->direction);
    PROTO_ITEM_SET_GENERATED(ti);

    mode_ti = proto_tree_add_uint(context_tree, hf_rlc_lte_context_mode,
                                  tvb, 0, 0, p_rlc_lte_info->rlcMode);
    PROTO_ITEM_SET_GENERATED(mode_ti);

    if (p_rlc_lte_info->ueid != 0) {
        ti = proto_tree_add_uint(context_tree, hf_rlc_lte_context_ueid,
                                 tvb, 0, 0, p_rlc_lte_info->ueid);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    if ((p_rlc_lte_info->priority >= 1) && (p_rlc_lte_info->priority <=16)) {
        ti = proto_tree_add_uint(context_tree, hf_rlc_lte_context_priority,
                                 tvb, 0, 0, p_rlc_lte_info->priority);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    ti = proto_tree_add_uint(context_tree, hf_rlc_lte_context_channel_type,
                             tvb, 0, 0, p_rlc_lte_info->channelType);
    PROTO_ITEM_SET_GENERATED(ti);

    if ((p_rlc_lte_info->channelType == CHANNEL_TYPE_SRB) ||
        (p_rlc_lte_info->channelType == CHANNEL_TYPE_DRB)) {
        ti = proto_tree_add_uint(context_tree, hf_rlc_lte_context_channel_id,
                                 tvb, 0, 0, p_rlc_lte_info->channelId);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    ti = proto_tree_add_uint(context_tree, hf_rlc_lte_context_pdu_length,
                             tvb, 0, 0, p_rlc_lte_info->pduLength);
    PROTO_ITEM_SET_GENERATED(ti);

    if (p_rlc_lte_info->rlcMode == RLC_UM_MODE) {
        ti = proto_tree_add_uint(context_tree, hf_rlc_lte_context_um_sn_length,
                                 tvb, 0, 0, p_rlc_lte_info->UMSequenceNumberLength);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* Append highlights to top-level item */
    if (p_rlc_lte_info->ueid != 0) {
        proto_item_append_text(top_ti, "   UEId=%u", p_rlc_lte_info->ueid);
    }

    if (p_rlc_lte_info->channelId == 0) {
        proto_item_append_text(top_ti, " (%s) ",
                               val_to_str_const(p_rlc_lte_info->channelType, rlc_channel_type_vals, "Unknown"));
    }
    else {
        proto_item_append_text(top_ti, " (%s:%u) ",
                               val_to_str_const(p_rlc_lte_info->channelType, rlc_channel_type_vals, "Unknown"),
                               p_rlc_lte_info->channelId);
    }

    /* Append context highlights to info column */
    write_pdu_label_and_info(top_ti, NULL, pinfo,
                             "[%s] [%s] ",
                             (p_rlc_lte_info->direction == 0) ? "UL" : "DL",
                             val_to_str_const(p_rlc_lte_info->rlcMode, rlc_mode_short_vals, "Unknown"));
    if (p_rlc_lte_info->ueid != 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "UEId=%-4u ", p_rlc_lte_info->ueid);
    }
    if (p_rlc_lte_info->channelId == 0) {
        write_pdu_label_and_info(top_ti, NULL, pinfo, "%s",
                                 val_to_str_const(p_rlc_lte_info->channelType, rlc_channel_type_vals, "Unknown"));
    }
    else {
        write_pdu_label_and_info(top_ti, NULL, pinfo, "%s:%-2u",
                                 val_to_str_const(p_rlc_lte_info->channelType, rlc_channel_type_vals, "Unknown"),
                                 p_rlc_lte_info->channelId);
    }

    /* Set context-info parts of tap struct */
    tap_info->rlcMode = p_rlc_lte_info->rlcMode;
    tap_info->direction = p_rlc_lte_info->direction;
    tap_info->priority = p_rlc_lte_info->priority;
    tap_info->ueid = p_rlc_lte_info->ueid;
    tap_info->channelType = p_rlc_lte_info->channelType;
    tap_info->channelId = p_rlc_lte_info->channelId;
    tap_info->pduLength = p_rlc_lte_info->pduLength;
    tap_info->UMSequenceNumberLength = p_rlc_lte_info->UMSequenceNumberLength;
    tap_info->loggedInMACFrame = (p_get_proto_data(pinfo->fd, proto_mac_lte) != NULL);

    tap_info->time = pinfo->fd->abs_ts;

    /* Reset this count */
    s_number_of_extensions = 0;

    /* Dissect the RLC PDU itself. Format depends upon mode... */
    switch (p_rlc_lte_info->rlcMode) {

        case RLC_TM_MODE:
            dissect_rlc_lte_tm(tvb, pinfo, rlc_lte_tree, offset, p_rlc_lte_info, top_ti);
            break;

        case RLC_UM_MODE:
            dissect_rlc_lte_um(tvb, pinfo, rlc_lte_tree, offset, p_rlc_lte_info, top_ti,
                               tap_info);
            break;

        case RLC_AM_MODE:
            dissect_rlc_lte_am(tvb, pinfo, rlc_lte_tree, offset, p_rlc_lte_info, top_ti,
                               tap_info);
            break;

        case RLC_PREDEF:
            /* Predefined data (i.e. not containing a valid RLC header */
            proto_tree_add_item(rlc_lte_tree, hf_rlc_lte_predefined_pdu, tvb, offset, -1, ENC_NA);
            write_pdu_label_and_info(top_ti, NULL, pinfo, "   [%u-bytes]",
                                     tvb_length_remaining(tvb, offset));
            break;

        default:
            /* Error - unrecognised mode */
            expert_add_info_format(pinfo, mode_ti, PI_MALFORMED, PI_ERROR,
                                   "Unrecognised RLC Mode set (%u)", p_rlc_lte_info->rlcMode);
            break;
    }

    /* Queue tap info */
    tap_queue_packet(rlc_lte_tap, pinfo, tap_info);
}



/* Initializes the hash tables each time a new
 * file is loaded or re-loaded in wireshark */
static void
rlc_lte_init_protocol(void)
{
    /* Destroy any existing hashes. */
    if (sequence_analysis_channel_hash) {
        g_hash_table_destroy(sequence_analysis_channel_hash);
    }
    if (sequence_analysis_report_hash) {
        g_hash_table_destroy(sequence_analysis_report_hash);
    }
    if (repeated_nack_channel_hash) {
        g_hash_table_destroy(repeated_nack_channel_hash);
    }
    if (repeated_nack_report_hash) {
        g_hash_table_destroy(repeated_nack_report_hash);
    }
    if (reassembly_report_hash) {
        g_hash_table_destroy(reassembly_report_hash);
    }

    /* Now create them over */
    sequence_analysis_channel_hash = g_hash_table_new(rlc_channel_hash_func, rlc_channel_equal);
    sequence_analysis_report_hash = g_hash_table_new(rlc_result_hash_func, rlc_result_hash_equal);

    repeated_nack_channel_hash = g_hash_table_new(rlc_channel_hash_func, rlc_channel_equal);
    repeated_nack_report_hash = g_hash_table_new(rlc_result_hash_func, rlc_result_hash_equal);
    reassembly_report_hash = g_hash_table_new(rlc_result_hash_func, rlc_result_hash_equal);
}


/* Configure number of PDCP SN bits to use for DRB channels.
   TODO: currently assume all UEs/Channels will use the same length... */
void set_rlc_lte_drb_pdcp_seqnum_length(guint16 ueid _U_, guint8 drbid _U_,
                                        guint8 userplane_seqnum_length)
{
    signalled_pdcp_sn_bits = userplane_seqnum_length;
}


void proto_register_rlc_lte(void)
{
    static hf_register_info hf[] =
    {
        /**********************************/
        /* Items for decoding context     */
        { &hf_rlc_lte_context,
            { "Context",
              "rlc-lte.context", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_context_mode,
            { "RLC Mode",
              "rlc-lte.mode", FT_UINT8, BASE_DEC, VALS(rlc_mode_vals), 0x0,
              NULL, HFILL
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
              NULL, HFILL
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
              "rlc-lte.pdu-length", FT_UINT16, BASE_DEC, 0, 0x0,
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
        { &hf_rlc_lte_tm,
            { "TM",
              "rlc-lte.tm", FT_STRING, BASE_NONE, NULL, 0x0,
              "Transparent Mode", HFILL
            }
        },
        { &hf_rlc_lte_tm_data,
            { "TM Data",
              "rlc-lte.tm.data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Transparent Mode Data", HFILL
            }
        },

        /* Unacknowledged mode fields */
        { &hf_rlc_lte_um,
            { "UM",
              "rlc-lte.um", FT_STRING, BASE_NONE, NULL, 0x0,
              "Unackowledged Mode", HFILL
            }
        },
        { &hf_rlc_lte_um_header,
            { "UM Header",
              "rlc-lte.um.header", FT_STRING, BASE_NONE, NULL, 0x0,
              "Unackowledged Mode Header", HFILL
            }
        },
        { &hf_rlc_lte_um_fi,
            { "Framing Info",
              "rlc-lte.um.fi", FT_UINT8, BASE_HEX, VALS(framing_info_vals), 0x0,
              NULL, HFILL
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
              "rlc-lte.um.data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Unacknowledged Mode Data", HFILL
            }
        },
        { &hf_rlc_lte_extension_part,
            { "Extension Part",
              "rlc-lte.extension-part", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
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
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_extension_padding,
            { "Padding",
              "rlc-lte.extension.padding", FT_UINT8, BASE_HEX, 0, 0x0f,
              "Extension header padding", HFILL
            }
        },

        { &hf_rlc_lte_am,
            { "AM",
              "rlc-lte.am", FT_STRING, BASE_NONE, NULL, 0x0,
              "Ackowledged Mode", HFILL
            }
        },
        { &hf_rlc_lte_am_header,
            { "AM Header",
              "rlc-lte.am.header", FT_STRING, BASE_NONE, NULL, 0x0,
              "Ackowledged Mode Header", HFILL
            }
        },
        { &hf_rlc_lte_am_data_control,
            { "Frame type",
              "rlc-lte.am.frame-type", FT_UINT8, BASE_HEX, VALS(data_or_control_vals), 0x80,
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
              NULL, HFILL
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
              "rlc-lte.am.fixed.sn", FT_UINT16, BASE_DEC, 0, 0x03ff,
              "AM Fixed Sequence Number", HFILL
            }
        },
        { &hf_rlc_lte_am_segment_lsf,
            { "Last Segment Flag",
              "rlc-lte.am.segment.lsf", FT_UINT8, BASE_HEX, VALS(lsf_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_am_segment_so,
            { "Segment Offset",
              "rlc-lte.am.segment.offset", FT_UINT16, BASE_DEC, 0, 0x7fff,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_am_data,
            { "AM Data",
              "rlc-lte.am.data", FT_BYTES, BASE_NONE, 0, 0x0,
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
              "Sequence Number we expect to receive next", HFILL
            }
        },
        { &hf_rlc_lte_am_e1,
            { "Extension bit 1",
              "rlc-lte.am.e1", FT_UINT8, BASE_HEX, VALS(am_e1_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_am_e2,
            { "Extension bit 2",
              "rlc-lte.am.e2", FT_UINT8, BASE_HEX, VALS(am_e2_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_am_nacks,
            { "Number of NACKs",
              "rlc-lte.am.nacks", FT_UINT16, BASE_DEC, 0, 0x0,
              "Number of NACKs in this status PDU", HFILL
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
              "Segment Offset Start byte index", HFILL
            }
        },
        { &hf_rlc_lte_am_so_end,
            { "SO End",
              "rlc-lte.am.so-end", FT_UINT16, BASE_DEC, 0, 0x0,
              "Segment Offset End byte index", HFILL
            }
        },

        { &hf_rlc_lte_predefined_pdu,
            { "Predefined data",
              "rlc-lte.predefined-data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Predefined test data", HFILL
            }
        },

        { &hf_rlc_lte_sequence_analysis,
            { "Sequence Analysis",
              "rlc-lte.sequence-analysis", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_ok,
            { "OK",
              "rlc-lte.sequence-analysis.ok", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_previous_frame,
            { "Previous frame for channel",
              "rlc-lte.sequence-analysis.previous-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_next_frame,
            { "Next frame for channel",
              "rlc-lte.sequence-analysis.next-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_expected_sn,
            { "Expected SN",
              "rlc-lte.sequence-analysis.expected-sn", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_framing_info_correct,
            { "Frame info continued correctly",
              "rlc-lte.sequence-analysis.framing-info-correct", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_mac_retx,
            { "Frame retransmitted by MAC",
              "rlc-lte.sequence-analysis.mac-retx", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_retx,
            { "Retransmitted frame",
              "rlc-lte.sequence-analysis.retx", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_skipped,
            { "Skipped frames",
              "rlc-lte.sequence-analysis.skipped-frames", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_repeated,
            { "Repeated frame",
              "rlc-lte.sequence-analysis.repeated-frame", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_repeated_nack,
            { "Repeated NACK",
              "rlc-lte.sequence-analysis.repeated-nack", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_repeated_nack_original_frame,
            { "Frame with previous status PDU",
              "rlc-lte.sequence-analysis.repeated-nack.original-frame",  FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },

        { &hf_rlc_lte_sequence_analysis_ack_out_of_range,
            { "Out of range ACK",
              "rlc-lte.sequence-analysis.ack-out-of-range", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_sequence_analysis_ack_out_of_range_opposite_frame,
            { "Frame with most recent SN",
              "rlc-lte.sequence-analysis.ack-out-of-range.last-sn-frame",  FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },

        { &hf_rlc_lte_reassembly_source,
            { "Reassembly Source",
              "rlc-lte.reassembly-info", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_reassembly_source_number_of_segments,
            { "Number of segments",
              "rlc-lte.reassembly-info.number-of-segments", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_reassembly_source_total_length,
            { "Total length",
              "rlc-lte.reassembly-info.total-length", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_reassembly_source_segment,
            { "Segment",
              "rlc-lte.reassembly-info.segment", FT_NONE, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_reassembly_source_segment_sn,
            { "SN",
              "rlc-lte.reassembly-info.segment.sn", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_reassembly_source_segment_framenum,
            { "Frame",
              "rlc-lte.reassembly-info.segment.frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_rlc_lte_reassembly_source_segment_length,
            { "Length",
              "rlc-lte.reassembly-info.segment.length", FT_UINT32, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },

        { &hf_rlc_lte_header_only,
            { "RLC PDU Header only",
              "rlc-lte.header-only", FT_UINT8, BASE_DEC, VALS(header_only_vals), 0x0,
              NULL, HFILL
            }
        },
    };

    static gint *ett[] =
    {
        &ett_rlc_lte,
        &ett_rlc_lte_context,
        &ett_rlc_lte_um_header,
        &ett_rlc_lte_am_header,
        &ett_rlc_lte_extension_part,
        &ett_rlc_lte_sequence_analysis,
        &ett_rlc_lte_reassembly_source,
        &ett_rlc_lte_reassembly_source_segment
    };

    static enum_val_t sequence_analysis_vals[] = {
        {"no-analysis", "No-Analysis",     FALSE},
        {"mac-only",    "Only-MAC-frames", SEQUENCE_ANALYSIS_MAC_ONLY},
        {"rlc-only",    "Only-RLC-frames", SEQUENCE_ANALYSIS_RLC_ONLY},
        {NULL, NULL, -1}
    };

    module_t *rlc_lte_module;

    /* Register protocol. */
    proto_rlc_lte = proto_register_protocol("RLC-LTE", "RLC-LTE", "rlc-lte");
    proto_register_field_array(proto_rlc_lte, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name. */
    register_dissector("rlc-lte", dissect_rlc_lte, proto_rlc_lte);

    /* Register the tap name */
    rlc_lte_tap = register_tap("rlc-lte");

    /* Preferences */
    rlc_lte_module = prefs_register_protocol(proto_rlc_lte, NULL);

    prefs_register_enum_preference(rlc_lte_module, "do_sequence_analysis_am",
        "Do sequence analysis for AM channels",
        "Attempt to keep track of PDUs for AM channels, and point out problems",
        &global_rlc_lte_am_sequence_analysis, sequence_analysis_vals, FALSE);

    prefs_register_enum_preference(rlc_lte_module, "do_sequence_analysis",
        "Do sequence analysis for UM channels",
        "Attempt to keep track of PDUs for UM channels, and point out problems",
        &global_rlc_lte_um_sequence_analysis, sequence_analysis_vals, FALSE);

    prefs_register_bool_preference(rlc_lte_module, "call_pdcp_for_srb",
        "Call PDCP dissector for SRB PDUs",
        "Call PDCP dissector for signalling PDUs.  Note that without reassembly, it can"
        "only be called for complete PDus (i.e. not segmented over RLC)",
        &global_rlc_lte_call_pdcp_for_srb);

    prefs_register_enum_preference(rlc_lte_module, "call_pdcp_for_drb",
        "Call PDCP dissector for DRB PDUs",
        "Call PDCP dissector for user-plane PDUs.  Note that without reassembly, it can"
        "only be called for complete PDUs (i.e. not segmented over RLC)",
        &global_rlc_lte_call_pdcp_for_drb, pdcp_drb_col_vals, FALSE);


    prefs_register_bool_preference(rlc_lte_module, "call_rrc_for_ccch",
        "Call RRC dissector for CCCH PDUs",
        "Call RRC dissector for CCCH PDUs",
        &global_rlc_lte_call_rrc_for_ccch);

    prefs_register_bool_preference(rlc_lte_module, "call_rrc_for_mcch",
        "Call RRC dissector for MCCH PDUs",
        "Call RRC dissector for MCCH PDUs",
        &global_rlc_lte_call_rrc_for_mcch);

    prefs_register_bool_preference(rlc_lte_module, "heuristic_rlc_lte_over_udp",
        "Try Heuristic LTE-RLC over UDP framing",
        "When enabled, use heuristic dissector to find RLC-LTE frames sent with "
        "UDP framing",
        &global_rlc_lte_heur);

    prefs_register_bool_preference(rlc_lte_module, "header_only_mode",
        "May see RLC headers only",
        "When enabled, if data is not present, don't report as an error, but instead "
        "add expert info to indicate that headers were omitted",
        &global_rlc_lte_headers_expected);

    prefs_register_bool_preference(rlc_lte_module, "reassembly",
        "Attempt SDU reassembly",
        "When enabled, attempts to re-assemble upper-layer SDUs that are split over "
        "more than one RLC PDU.  Note: does not currently support out-of-order or "
        "re-segmentation. N.B. sequence analysis must also be turned on in order "
        "for reassembly to work",
        &global_rlc_lte_reassembly);


    register_init_routine(&rlc_lte_init_protocol);
}

void
proto_reg_handoff_rlc_lte(void)
{
    /* Add as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_rlc_lte_heur, proto_rlc_lte);

    pdcp_lte_handle = find_dissector("pdcp-lte");
}
