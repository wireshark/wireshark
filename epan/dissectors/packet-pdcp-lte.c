/* Routines for LTE PDCP
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <epan/emem.h>

#include "packet-rlc-lte.h"
#include "packet-pdcp-lte.h"

/* Described in:
 * 3GPP TS 36.323 Evolved Universal Terrestrial Radio Access (E-UTRA)
 *                Packet Data Convergence Protocol (PDCP) specification v11.0.0
 */


/* TODO:
   - Support for deciphering
   - Verify MAC authentication bytes
   - Add Relay Node user plane data PDU dissection
*/


/* Initialize the protocol and registered fields. */
int proto_pdcp_lte = -1;

extern int proto_rlc_lte;

/* Configuration (info known outside of PDU) */
static int hf_pdcp_lte_configuration = -1;
static int hf_pdcp_lte_direction = -1;
static int hf_pdcp_lte_ueid = -1;
static int hf_pdcp_lte_channel_type = -1;
static int hf_pdcp_lte_channel_id = -1;

static int hf_pdcp_lte_rohc_compression = -1;
static int hf_pdcp_lte_rohc_mode = -1;
static int hf_pdcp_lte_rohc_rnd = -1;
static int hf_pdcp_lte_rohc_udp_checksum_present = -1;
static int hf_pdcp_lte_rohc_profile = -1;

static int hf_pdcp_lte_no_header_pdu = -1;
static int hf_pdcp_lte_plane = -1;
static int hf_pdcp_lte_seqnum_length = -1;
static int hf_pdcp_lte_cid_inclusion_info = -1;
static int hf_pdcp_lte_large_cid_present = -1;

/* PDCP header fields */
static int hf_pdcp_lte_control_plane_reserved = -1;
static int hf_pdcp_lte_seq_num_5 = -1;
static int hf_pdcp_lte_seq_num_7 = -1;
static int hf_pdcp_lte_reserved3 = -1;
static int hf_pdcp_lte_seq_num_12 = -1;
static int hf_pdcp_lte_seq_num_15 = -1;
static int hf_pdcp_lte_signalling_data = -1;
static int hf_pdcp_lte_mac = -1;
static int hf_pdcp_lte_data_control = -1;
static int hf_pdcp_lte_user_plane_data = -1;
static int hf_pdcp_lte_control_pdu_type = -1;
static int hf_pdcp_lte_fms = -1;
static int hf_pdcp_lte_reserved4 = -1;
static int hf_pdcp_lte_fms2 = -1;
static int hf_pdcp_lte_bitmap = -1;
static int hf_pdcp_lte_bitmap_not_received = -1;


/* Sequence Analysis */
static int hf_pdcp_lte_sequence_analysis = -1;
static int hf_pdcp_lte_sequence_analysis_ok = -1;
static int hf_pdcp_lte_sequence_analysis_previous_frame = -1;
static int hf_pdcp_lte_sequence_analysis_next_frame = -1;
static int hf_pdcp_lte_sequence_analysis_expected_sn = -1;

static int hf_pdcp_lte_sequence_analysis_repeated = -1;
static int hf_pdcp_lte_sequence_analysis_skipped = -1;




/* Protocol subtree. */
static int ett_pdcp = -1;
static int ett_pdcp_configuration = -1;
static int ett_pdcp_packet = -1;
static int ett_pdcp_lte_sequence_analysis = -1;
static int ett_pdcp_report_bitmap = -1;


static const value_string direction_vals[] =
{
    { DIRECTION_UPLINK,      "Uplink"},
    { DIRECTION_DOWNLINK,    "Downlink"},
    { 0, NULL }
};


static const value_string pdcp_plane_vals[] = {
    { SIGNALING_PLANE,    "Signalling" },
    { USER_PLANE,         "User" },
    { 0,   NULL }
};

static const value_string logical_channel_vals[] = {
    { Channel_DCCH,  "DCCH"},
    { Channel_BCCH,  "BCCH"},
    { Channel_CCCH,  "CCCH"},
    { Channel_PCCH,  "PCCH"},
    { 0,             NULL}
};

static const value_string rohc_mode_vals[] = {
    { UNIDIRECTIONAL,            "Unidirectional" },
    { OPTIMISTIC_BIDIRECTIONAL,  "Optimistic Bidirectional" },
    { RELIABLE_BIDIRECTIONAL,    "Reliable Bidirectional" },
    { 0,   NULL }
};


/* Values taken from:
   http://www.iana.org/assignments/rohc-pro-ids/rohc-pro-ids.txt */
static const value_string rohc_profile_vals[] = {
    { 0x0000,   "ROHC uncompressed" },      /* [RFC5795] */
    { 0x0001,   "ROHC RTP" },               /* [RFC3095] */
    { 0x0101,   "ROHCv2 RTP" },             /* [RFC5225] */
    { 0x0002,   "ROHC UDP" },               /* [RFC3095] */
    { 0x0102,   "ROHCv2 UDP" },             /* [RFC5225] */
    { 0x0003,   "ROHC ESP" },               /* [RFC3095] */
    { 0x0103,   "ROHCv2 ESP" },             /* [RFC5225] */
    { 0x0004,   "ROHC IP" },                /* [RFC3843] */
    { 0x0104,   "ROHCv2 IP" },              /* [RFC5225] */
    { 0x0005,   "ROHC LLA" },               /* [RFC4362] */
    { 0x0105,   "ROHC LLA with R-mode" },   /* [RFC3408] */
    { 0x0006,   "ROHC TCP" },               /* [RFC4996] */
    { 0x0007,   "ROHC RTP/UDP-Lite" },      /* [RFC4019] */
    { 0x0107,   "ROHCv2 RTP/UDP-Lite" },    /* [RFC5225] */
    { 0x0008,   "ROHC UDP-Lite" },          /* [RFC4019] */
    { 0x0108,   "ROHCv2 UDP-Lite" },        /* [RFC5225] */
    { 0,   NULL }
};

static const value_string pdu_type_vals[] = {
    { 0,   "Control PDU" },
    { 1,   "Data PDU" },
    { 0,   NULL }
};

static const value_string feedback_ack_vals[] = {
    { 0,   "ACK" },
    { 1,   "NACK" },
    { 2,   "STATIC-NACK" },
    { 0,   NULL }
};

static const value_string feedback_option_vals[] = {
    { 1,   "CRC" },
    { 2,   "REJECT" },
    { 3,   "SN-Not-Valid" },
    { 4,   "SN" },
    { 5,   "Clock" },
    { 6,   "Jitter" },
    { 7,   "Loss" },
    { 0,   NULL }
};

static const value_string control_pdu_type_vals[] = {
    { 0,   "PDCP Status report" },
    { 1,   "Header Compression Feedback Information" },
    { 0,   NULL }
};

static const value_string t_vals[] = {
    { 0,   "ID message format" },
    { 1,   "TS message format" },
    { 0,   NULL }
};

static const value_string ip_protocol_vals[] = {
    { 6,   "TCP" },
    { 17,  "UDP" },
    { 0,   NULL }
};


static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t rohc_handle;
static dissector_handle_t data_handle;


#define SEQUENCE_ANALYSIS_RLC_ONLY  1
#define SEQUENCE_ANALYSIS_PDCP_ONLY 2

/* Preference variables */
static gboolean global_pdcp_dissect_user_plane_as_ip = FALSE;
static gboolean global_pdcp_dissect_signalling_plane_as_rrc = FALSE;
static gint     global_pdcp_check_sequence_numbers = FALSE;
static gboolean global_pdcp_dissect_rohc = FALSE;

/* Which layer info to show in the info column */
enum layer_to_show {
    ShowRLCLayer, ShowPDCPLayer, ShowTrafficLayer
};
static gint     global_pdcp_lte_layer_to_show = (gint)ShowRLCLayer;



/**************************************************/
/* Sequence number analysis                       */

/* Channel key */
typedef struct
{
    /* Using bit fields to fit into 32 bits, so avoiding the need to allocate
       heap memory for these structs */
    unsigned           ueId : 16;
    unsigned           plane : 2;
    unsigned           channelId : 6;
    unsigned           direction : 1;
    unsigned           notUsed : 7;
} pdcp_channel_hash_key;

/* Channel state */
typedef struct
{
    guint16  previousSequenceNumber;
    guint32  previousFrameNum;
} pdcp_channel_status;

/* The sequence analysis channel hash table.
   Maps key -> status */
static GHashTable *pdcp_sequence_analysis_channel_hash = NULL;

/* Equal keys */
static gint pdcp_channel_equal(gconstpointer v, gconstpointer v2)
{
    /* Key fits in 4 bytes, so just compare pointers! */
    return (v == v2);
}

/* Compute a hash value for a given key. */
static guint pdcp_channel_hash_func(gconstpointer v)
{
    /* Just use pointer, as the fields are all in this value */
    return GPOINTER_TO_UINT(v);
}


/* Hash table types & functions for frame reports */

typedef struct {
    guint32            frameNumber;
    unsigned           SN :       15;
    unsigned           plane :    2;
    unsigned           channelId: 5;
    unsigned           direction: 1;
    unsigned           notUsed :  9;
} pdcp_result_hash_key;

static gint pdcp_result_hash_equal(gconstpointer v, gconstpointer v2)
{
    const pdcp_result_hash_key* val1 = (const pdcp_result_hash_key *)v;
    const pdcp_result_hash_key* val2 = (const pdcp_result_hash_key *)v2;

    /* All fields must match */
    return (memcmp(val1, val2, sizeof(pdcp_result_hash_key)) == 0);
}

/* Compute a hash value for a given key. */
static guint pdcp_result_hash_func(gconstpointer v)
{
    const pdcp_result_hash_key* val1 = (const pdcp_result_hash_key *)v;

    /* TODO: check collision-rate / execution-time of these multipliers?  */
    return val1->frameNumber + (val1->channelId<<13) +
                               (val1->plane<<5) +
                               (val1->SN<<18) +
                               (val1->direction<<9);
}

/* pdcp_channel_hash_key fits into the pointer, so just copy the value into
   a guint, cast to apointer and return that as the key */
static gpointer get_channel_hash_key(pdcp_channel_hash_key *key)
{
    guint  asInt = 0;
    /* TODO: assert that sizeof(pdcp_channel_hash_key) <= sizeof(guint) ? */
    memcpy(&asInt, key, sizeof(pdcp_channel_hash_key));
    return GUINT_TO_POINTER(asInt);
}

/* Convenience function to get a pointer for the hash_func to work with */
static gpointer get_report_hash_key(guint16 SN, guint32 frameNumber,
                                    pdcp_lte_info *p_pdcp_lte_info,
                                    gboolean do_persist)
{
    static pdcp_result_hash_key  key;
    pdcp_result_hash_key        *p_key;

    /* Only allocate a struct when will be adding entry */
    if (do_persist) {
        p_key = se_new(pdcp_result_hash_key);
    }
    else {
        memset(&key, 0, sizeof(pdcp_result_hash_key));
        p_key = &key;
    }

    /* Fill in details, and return pointer */
    p_key->frameNumber = frameNumber;
    p_key->SN = SN;
    p_key->plane = (guint8)p_pdcp_lte_info->plane;
    p_key->channelId = p_pdcp_lte_info->channelId;
    p_key->direction = p_pdcp_lte_info->direction;
    p_key->notUsed = 0;

    return p_key;
}


/* Info to attach to frame when first read, recording what to show about sequence */
typedef struct
{
    gboolean sequenceExpectedCorrect;
    guint16  sequenceExpected;
    guint32  previousFrameNum;
    guint32  nextFrameNum;

    guint16  firstSN;
    guint16  lastSN;

    enum { SN_OK, SN_Repeated, SN_MAC_Retx, SN_Retx, SN_Missing} state;
} pdcp_sequence_report_in_frame;

/* The sequence analysis frame report hash table instance itself   */
static GHashTable *pdcp_lte_sequence_analysis_report_hash = NULL;



/* Add to the tree values associated with sequence analysis for this frame */
static void addChannelSequenceInfo(pdcp_sequence_report_in_frame *p,
                                   pdcp_lte_info *p_pdcp_lte_info,
                                   guint16   sequenceNumber,
                                   packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    proto_tree *seqnum_tree;
    proto_item *seqnum_ti;
    proto_item *ti_expected_sn;
    proto_item *ti;

    /* Create subtree */
    seqnum_ti = proto_tree_add_string_format(tree,
                                             hf_pdcp_lte_sequence_analysis,
                                             tvb, 0, 0,
                                             "", "Sequence Analysis");
    seqnum_tree = proto_item_add_subtree(seqnum_ti,
                                         ett_pdcp_lte_sequence_analysis);
    PROTO_ITEM_SET_GENERATED(seqnum_ti);


    /* Previous channel frame */
    if (p->previousFrameNum != 0) {
        proto_tree_add_uint(seqnum_tree, hf_pdcp_lte_sequence_analysis_previous_frame,
                            tvb, 0, 0, p->previousFrameNum);
    }

    /* Expected sequence number */
    ti_expected_sn = proto_tree_add_uint(seqnum_tree, hf_pdcp_lte_sequence_analysis_expected_sn,
                                         tvb, 0, 0, p->sequenceExpected);
    PROTO_ITEM_SET_GENERATED(ti_expected_sn);

    /* Make sure we have recognised SN length */
    switch (p_pdcp_lte_info->seqnum_length) {
        case PDCP_SN_LENGTH_5_BITS:
        case PDCP_SN_LENGTH_7_BITS:
        case PDCP_SN_LENGTH_12_BITS:
        case PDCP_SN_LENGTH_15_BITS:
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    switch (p->state) {
        case SN_OK:
            PROTO_ITEM_SET_HIDDEN(ti_expected_sn);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_ok,
                                        tvb, 0, 0, TRUE);
            PROTO_ITEM_SET_GENERATED(ti);
            proto_item_append_text(seqnum_ti, " - OK");

            /* Link to next SN in channel (if known) */
            if (p->nextFrameNum != 0) {
                proto_tree_add_uint(seqnum_tree, hf_pdcp_lte_sequence_analysis_next_frame,
                                    tvb, 0, 0, p->nextFrameNum);
            }
            break;

        case SN_Missing:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_ok,
                                        tvb, 0, 0, FALSE);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_skipped,
                                        tvb, 0, 0, TRUE);
            PROTO_ITEM_SET_GENERATED(ti);
            if (p->lastSN != p->firstSN) {
                expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                       "PDCP SNs (%u to %u) missing for %s on UE %u (%s-%u)",
                                       p->firstSN, p->lastSN,
                                       val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                       p_pdcp_lte_info->ueid,
                                       val_to_str_const(p_pdcp_lte_info->channelType, logical_channel_vals, "Unknown"),
                                       p_pdcp_lte_info->channelId);
                proto_item_append_text(seqnum_ti, " - SNs missing (%u to %u)",
                                       p->firstSN, p->lastSN);
            }
            else {
                expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                       "PDCP SN (%u) missing for %s on UE %u (%s-%u)",
                                       p->firstSN,
                                       val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                       p_pdcp_lte_info->ueid,
                                       val_to_str_const(p_pdcp_lte_info->channelType, logical_channel_vals, "Unknown"),
                                       p_pdcp_lte_info->channelId);
                proto_item_append_text(seqnum_ti, " - SN missing (%u)",
                                       p->firstSN);
            }
            break;

        case SN_Repeated:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_ok,
                                        tvb, 0, 0, FALSE);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_lte_sequence_analysis_repeated,
                                        tvb, 0, 0, TRUE);
            PROTO_ITEM_SET_GENERATED(ti);
            expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                   "PDCP SN (%u) repeated for %s for UE %u (%s-%u)",
                                   p->firstSN,
                                   val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                   p_pdcp_lte_info->ueid,
                                   val_to_str_const(p_pdcp_lte_info->channelType, logical_channel_vals, "Unknown"),
                                   p_pdcp_lte_info->channelId);
            proto_item_append_text(seqnum_ti, "- SN %u Repeated",
                                   p->firstSN);
            break;

        default:
            /* Incorrect sequence number */
            expert_add_info_format(pinfo, ti_expected_sn, PI_SEQUENCE, PI_WARN,
                                   "Wrong Sequence Number for %s on UE %u (%s-%u) - got %u, expected %u",
                                   val_to_str_const(p_pdcp_lte_info->direction, direction_vals, "Unknown"),
                                   p_pdcp_lte_info->ueid,
                                   val_to_str_const(p_pdcp_lte_info->channelType, logical_channel_vals, "Unknown"),
                                   p_pdcp_lte_info->channelId,
                                   sequenceNumber, p->sequenceExpected);
            break;
    }
}


/* Update the channel status and set report for this frame */
static void checkChannelSequenceInfo(packet_info *pinfo, tvbuff_t *tvb,
                                     pdcp_lte_info *p_pdcp_lte_info,
                                     guint16 sequenceNumber,
                                     proto_tree *tree)
{
    pdcp_channel_hash_key          channel_key;
    pdcp_channel_status           *p_channel_status;
    pdcp_sequence_report_in_frame *p_report_in_frame      = NULL;
    gboolean                       createdChannel         = FALSE;
    guint16                        expectedSequenceNumber = 0;
    guint16                        snLimit                = 0;

    /* If find stat_report_in_frame already, use that and get out */
    if (pinfo->fd->flags.visited) {
        p_report_in_frame =
            (pdcp_sequence_report_in_frame*)g_hash_table_lookup(pdcp_lte_sequence_analysis_report_hash,
                                                                get_report_hash_key(sequenceNumber,
                                                                                    pinfo->fd->num,
                                                                                    p_pdcp_lte_info, FALSE));
        if (p_report_in_frame != NULL) {
            addChannelSequenceInfo(p_report_in_frame, p_pdcp_lte_info,
                                   sequenceNumber,
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
    channel_key.ueId = p_pdcp_lte_info->ueid;
    channel_key.plane = p_pdcp_lte_info->plane;
    channel_key.channelId = p_pdcp_lte_info->channelId;
    channel_key.direction = p_pdcp_lte_info->direction;
    channel_key.notUsed = 0;

    /* Do the table lookup */
    p_channel_status = (pdcp_channel_status*)g_hash_table_lookup(pdcp_sequence_analysis_channel_hash,
                                                                 get_channel_hash_key(&channel_key));

    /* Create table entry if necessary */
    if (p_channel_status == NULL) {
        createdChannel = TRUE;

        /* Allocate a new value and duplicate key contents */
        p_channel_status = se_new0(pdcp_channel_status);

        /* Add entry */
        g_hash_table_insert(pdcp_sequence_analysis_channel_hash,
                            get_channel_hash_key(&channel_key), p_channel_status);
    }

    /* Create space for frame state_report */
    p_report_in_frame = se_new(pdcp_sequence_report_in_frame);
    p_report_in_frame->nextFrameNum = 0;

    switch (p_pdcp_lte_info->seqnum_length) {
        case PDCP_SN_LENGTH_5_BITS:
            snLimit = 32;
            break;
        case PDCP_SN_LENGTH_7_BITS:
            snLimit = 128;
            break;
        case PDCP_SN_LENGTH_12_BITS:
            snLimit = 4096;
            break;
        case PDCP_SN_LENGTH_15_BITS:
            snLimit = 32768;
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    /* Work out expected sequence number */
    if (!createdChannel) {
        expectedSequenceNumber = (p_channel_status->previousSequenceNumber + 1) % snLimit;
    }
    else {
        expectedSequenceNumber = sequenceNumber;
    }

    /* Set report for this frame */
    /* For PDCP, sequence number is always expectedSequence number */
    p_report_in_frame->sequenceExpectedCorrect = (sequenceNumber == expectedSequenceNumber);

    /* For wrong sequence number... */
    if (!p_report_in_frame->sequenceExpectedCorrect) {

        /* Frames are not missing if we get an earlier sequence number again */
        if (((snLimit + expectedSequenceNumber - sequenceNumber) % snLimit) > 15) {
            p_report_in_frame->state = SN_Missing;
            p_report_in_frame->firstSN = expectedSequenceNumber;
            p_report_in_frame->lastSN = (snLimit + sequenceNumber - 1) % snLimit;

            p_report_in_frame->sequenceExpected = expectedSequenceNumber;
            p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;

            /* Update channel status to remember *this* frame */
            p_channel_status->previousFrameNum = pinfo->fd->num;
            p_channel_status->previousSequenceNumber = sequenceNumber;
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
        p_report_in_frame->state = SN_OK;
        p_report_in_frame->sequenceExpected = expectedSequenceNumber;
        p_report_in_frame->previousFrameNum = p_channel_status->previousFrameNum;

        /* Update channel status to remember *this* frame */
        p_channel_status->previousFrameNum = pinfo->fd->num;
        p_channel_status->previousSequenceNumber = sequenceNumber;

        if (p_report_in_frame->previousFrameNum != 0) {
            /* Get report for previous frame */
            pdcp_sequence_report_in_frame *p_previous_report;
            p_previous_report = (pdcp_sequence_report_in_frame*)g_hash_table_lookup(pdcp_lte_sequence_analysis_report_hash,
                                                                                    get_report_hash_key((sequenceNumber+32767) % 32768,
                                                                                                        p_report_in_frame->previousFrameNum,
                                                                                                        p_pdcp_lte_info,
                                                                                                        FALSE));
            /* It really shouldn't be NULL... */
            if (p_previous_report != NULL) {
                /* Point it forward to this one */
                p_previous_report->nextFrameNum = pinfo->fd->num;
            }
        }
    }

    /* Associate with this frame number */
    g_hash_table_insert(pdcp_lte_sequence_analysis_report_hash,
                        get_report_hash_key(sequenceNumber, pinfo->fd->num,
                                            p_pdcp_lte_info, TRUE),
                        p_report_in_frame);

    /* Add state report for this frame into tree */
    addChannelSequenceInfo(p_report_in_frame, p_pdcp_lte_info, sequenceNumber,
                           pinfo, tree, tvb);
}


/* Write the given formatted text to:
   - the info column
   - the top-level RLC PDU item */
static void write_pdu_label_and_info(proto_item *pdu_ti,
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
}



/***************************************************************/



/* Show in the tree the config info attached to this frame, as generated fields */
static void show_pdcp_config(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                             pdcp_lte_info *p_pdcp_info)
{
    proto_item *ti;
    proto_tree *configuration_tree;
    proto_item *configuration_ti = proto_tree_add_item(tree,
                                                       hf_pdcp_lte_configuration,
                                                       tvb, 0, 0, ENC_ASCII|ENC_NA);
    configuration_tree = proto_item_add_subtree(configuration_ti, ett_pdcp_configuration);

    /* Direction */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_direction, tvb, 0, 0,
                             p_pdcp_info->direction);
    PROTO_ITEM_SET_GENERATED(ti);

    /* Plane */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_plane, tvb, 0, 0,
                             p_pdcp_info->plane);
    PROTO_ITEM_SET_GENERATED(ti);

    /* UEId */
    if (p_pdcp_info->ueid != 0) {
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_ueid, tvb, 0, 0,
                                 p_pdcp_info->ueid);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* Channel type */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_channel_type, tvb, 0, 0,
                             p_pdcp_info->channelType);
    PROTO_ITEM_SET_GENERATED(ti);
    if (p_pdcp_info->channelId != 0) {
        /* Channel type */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_channel_id, tvb, 0, 0,
                                 p_pdcp_info->channelId);
        PROTO_ITEM_SET_GENERATED(ti);
    }


    /* User-plane-specific fields */
    if (p_pdcp_info->plane == USER_PLANE) {

        /* No Header PDU */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_no_header_pdu, tvb, 0, 0,
                                 p_pdcp_info->no_header_pdu);
        PROTO_ITEM_SET_GENERATED(ti);

        if (!p_pdcp_info->no_header_pdu) {

            /* Seqnum length */
            ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_seqnum_length, tvb, 0, 0,
                                     p_pdcp_info->seqnum_length);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    /* ROHC compression */
    ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_lte_rohc_compression, tvb, 0, 0,
                                p_pdcp_info->rohc_compression);
    PROTO_ITEM_SET_GENERATED(ti);

    /* ROHC-specific settings */
    if (p_pdcp_info->rohc_compression) {

        /* Show ROHC mode */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_mode, tvb, 0, 0,
                                 p_pdcp_info->mode);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Show RND */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_rnd, tvb, 0, 0,
                                 p_pdcp_info->rnd);
        PROTO_ITEM_SET_GENERATED(ti);

        /* UDP Checksum */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_udp_checksum_present, tvb, 0, 0,
                                 p_pdcp_info->udp_checkum_present);
        PROTO_ITEM_SET_GENERATED(ti);

        /* ROHC profile */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_rohc_profile, tvb, 0, 0,
                                 p_pdcp_info->profile);
        PROTO_ITEM_SET_GENERATED(ti);

        /* CID Inclusion Info */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_cid_inclusion_info, tvb, 0, 0,
                                 p_pdcp_info->cid_inclusion_info);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Large CID */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_lte_large_cid_present, tvb, 0, 0,
                                 p_pdcp_info->large_cid_present);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* Append summary to configuration root */
    proto_item_append_text(configuration_ti, "(direction=%s, plane=%s",
                           val_to_str_const(p_pdcp_info->direction, direction_vals, "Unknown"),
                           val_to_str_const(p_pdcp_info->plane, pdcp_plane_vals, "Unknown"));

    if (p_pdcp_info->rohc_compression) {
        const char *mode = val_to_str_const(p_pdcp_info->mode, rohc_mode_vals, "Error");
        proto_item_append_text(configuration_ti, ", mode=%c, profile=%s",
                               mode[0],
                               val_to_str_const(p_pdcp_info->profile, rohc_profile_vals, "Unknown"));
    }
    proto_item_append_text(configuration_ti, ")");
    PROTO_ITEM_SET_GENERATED(configuration_ti);

    /* Show plane in info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s: ",
                    val_to_str_const(p_pdcp_info->plane, pdcp_plane_vals, "Unknown"));

}


/* Look for an RRC dissector for signalling data (using channel type and direction) */
static dissector_handle_t lookup_rrc_dissector_handle(struct pdcp_lte_info  *p_pdcp_info)
{
    dissector_handle_t rrc_handle = 0;

    switch (p_pdcp_info->channelType)
    {
        case Channel_CCCH:
            if (p_pdcp_info->direction == DIRECTION_UPLINK) {
                rrc_handle = find_dissector("lte_rrc.ul_ccch");
            }
            else {
                rrc_handle = find_dissector("lte_rrc.dl_ccch");
            }
            break;
        case Channel_PCCH:
            rrc_handle = find_dissector("lte_rrc.pcch");
            break;
        case Channel_BCCH:
            switch (p_pdcp_info->BCCHTransport) {
                case BCH_TRANSPORT:
                    rrc_handle = find_dissector("lte_rrc.bcch_bch");
                    break;
                case DLSCH_TRANSPORT:
                    rrc_handle = find_dissector("lte_rrc.bcch_dl_sch");
                    break;
            }
            break;
        case Channel_DCCH:
            if (p_pdcp_info->direction == DIRECTION_UPLINK) {
                rrc_handle = find_dissector("lte_rrc.ul_dcch");
            }
            else {
                rrc_handle = find_dissector("lte_rrc.dl_dcch");
            }
            break;


        default:
            break;
    }

    return rrc_handle;
}


/* Forwad declarations */
static void dissect_pdcp_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Heuristic dissection */
static gboolean global_pdcp_lte_heur = FALSE;

/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static gboolean dissect_pdcp_lte_heur(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, void *data _U_)
{
    gint                  offset                 = 0;
    struct pdcp_lte_info *p_pdcp_lte_info;
    tvbuff_t             *pdcp_tvb;
    guint8                tag                    = 0;
    gboolean              infoAlreadySet         = FALSE;
    gboolean              seqnumLengthTagPresent = FALSE;

    /* This is a heuristic dissector, which means we get all the UDP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */

    if (!global_pdcp_lte_heur) {
        return FALSE;
    }

    /* Do this again on re-dissection to re-discover offset of actual PDU */

    /* Needs to be at least as long as:
       - the signature string
       - fixed header bytes
       - tag for data
       - at least one byte of PDCP PDU payload */
    if ((size_t)tvb_length_remaining(tvb, offset) < (strlen(PDCP_LTE_START_STRING)+3+2)) {
        return FALSE;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, PDCP_LTE_START_STRING, strlen(PDCP_LTE_START_STRING)) != 0) {
        return FALSE;
    }
    offset += (gint)strlen(PDCP_LTE_START_STRING);


    /* If redissecting, use previous info struct (if available) */
    p_pdcp_lte_info = (pdcp_lte_info *)p_get_proto_data(pinfo->fd, proto_pdcp_lte);
    if (p_pdcp_lte_info == NULL) {
        /* Allocate new info struct for this frame */
        p_pdcp_lte_info = se_new0(pdcp_lte_info);
        infoAlreadySet = FALSE;
    }
    else {
        infoAlreadySet = TRUE;
    }


    /* Read fixed fields */
    p_pdcp_lte_info->no_header_pdu = tvb_get_guint8(tvb, offset++);
    p_pdcp_lte_info->plane = tvb_get_guint8(tvb, offset++);
    p_pdcp_lte_info->rohc_compression = tvb_get_guint8(tvb, offset++);

    /* Read optional fields */
    while (tag != PDCP_LTE_PAYLOAD_TAG) {
        /* Process next tag */
        tag = tvb_get_guint8(tvb, offset++);
        switch (tag) {
            case PDCP_LTE_SEQNUM_LENGTH_TAG:
                p_pdcp_lte_info->seqnum_length = tvb_get_guint8(tvb, offset);
                offset++;
                seqnumLengthTagPresent = TRUE;
                break;
            case PDCP_LTE_DIRECTION_TAG:
                p_pdcp_lte_info->direction = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_LOG_CHAN_TYPE_TAG:
                p_pdcp_lte_info->channelType = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_BCCH_TRANSPORT_TYPE_TAG:
                p_pdcp_lte_info->BCCHTransport = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_IP_VERSION_TAG:
                p_pdcp_lte_info->rohc_ip_version = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case PDCP_LTE_ROHC_CID_INC_INFO_TAG:
                p_pdcp_lte_info->cid_inclusion_info = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_LARGE_CID_PRES_TAG:
                p_pdcp_lte_info->large_cid_present = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_MODE_TAG:
                p_pdcp_lte_info->mode = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_RND_TAG:
                p_pdcp_lte_info->rnd = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_UDP_CHECKSUM_PRES_TAG:
                p_pdcp_lte_info->udp_checkum_present = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case PDCP_LTE_ROHC_PROFILE_TAG:
                p_pdcp_lte_info->profile = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;

            case PDCP_LTE_PAYLOAD_TAG:
                /* Have reached data, so get out of loop */
                continue;

            default:
                /* It must be a recognised tag */
                return FALSE;
        }
    }

    if ((p_pdcp_lte_info->plane == USER_PLANE) && (seqnumLengthTagPresent == FALSE)) {
        /* Conditional field is not present */
        return FALSE;
    }

    if (!infoAlreadySet) {
        /* Store info in packet */
        p_add_proto_data(pinfo->fd, proto_pdcp_lte, p_pdcp_lte_info);
    }

    /**************************************/
    /* OK, now dissect as PDCP LTE        */

    /* Create tvb that starts at actual PDCP PDU */
    pdcp_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb)-offset);
    dissect_pdcp_lte(pdcp_tvb, pinfo, tree);
    return TRUE;
}


/******************************/
/* Main dissection function.  */
static void dissect_pdcp_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    const char           *mode;
    proto_tree           *pdcp_tree           = NULL;
    proto_item           *root_ti             = NULL;
    gint                  offset              = 0;
    gint                  rohc_offset;
    struct pdcp_lte_info *p_pdcp_info;
    rohc_info            *p_rohc_info         = NULL;
    tvbuff_t             *rohc_tvb            = NULL;

    /* Append this protocol name rather than replace. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-LTE");

    /* Look for attached packet info! */
    p_pdcp_info = p_get_proto_data(pinfo->fd, proto_pdcp_lte);
    /* Can't dissect anything without it... */
    if (p_pdcp_info == NULL) {
        return;
    }

    /* Don't want to overwrite the RLC Info column if configured not to */
    if ((global_pdcp_lte_layer_to_show == ShowRLCLayer) &&
        (p_get_proto_data(pinfo->fd, proto_rlc_lte) != NULL)) {

        col_set_writable(pinfo->cinfo, FALSE);
    }
    else {
        /* TODO: won't help with multiple PDCP-or-traffic PDUs / frame... */
        col_clear(pinfo->cinfo, COL_INFO);
        col_set_writable(pinfo->cinfo, TRUE);
    }

    /* Create pdcp tree. */
    if (tree) {
        root_ti = proto_tree_add_item(tree, proto_pdcp_lte, tvb, offset, -1, ENC_NA);
        pdcp_tree = proto_item_add_subtree(root_ti, ett_pdcp);
    }

    /* Set mode string */
    mode = val_to_str_const(p_pdcp_info->mode, rohc_mode_vals, "Error");

    /* Show configuration (attached packet) info in tree */
    if (pdcp_tree) {
        show_pdcp_config(pinfo, tvb, pdcp_tree, p_pdcp_info);
    }

    /* Show ROHC mode */
    if (p_pdcp_info->rohc_compression) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (mode=%c)", mode[0]);
    }


    /* Handle PDCP header (if present) */
    if (!p_pdcp_info->no_header_pdu) {

        /* TODO: shouldn't need to initialise this one!! */
        guint16  seqnum = 0;
        gboolean seqnum_set = FALSE;

        guint8  first_byte = tvb_get_guint8(tvb, offset);

        /*****************************/
        /* Signalling plane messages */
        if (p_pdcp_info->plane == SIGNALING_PLANE) {
            guint32 mac;
            guint32 data_length;

            /* Verify 3 reserved bits are 0 */
            guint8 reserved = (first_byte & 0xe0) >> 5;
            proto_item *ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_control_plane_reserved,
                                                 tvb, offset, 1, ENC_BIG_ENDIAN);
            if (reserved != 0) {
                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                       "PDCP signalling header reserved bits not zero");
            }

            /* 5-bit sequence number */
            seqnum = first_byte & 0x1f;
            seqnum_set = TRUE;
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_5, tvb, offset, 1, ENC_BIG_ENDIAN);
            write_pdu_label_and_info(root_ti, pinfo, " sn=%-2u ", seqnum);
            offset++;

            /* RRC data is all but last 4 bytes.
               Call lte-rrc dissector (according to direction and channel type) */
            if (global_pdcp_dissect_signalling_plane_as_rrc) {
                /* Get appropriate dissector handle */
                dissector_handle_t rrc_handle = lookup_rrc_dissector_handle(p_pdcp_info);

                if (rrc_handle != 0) {
                    /* Call RRC dissector if have one */
                    tvbuff_t *payload_tvb = tvb_new_subset(tvb, offset,
                                                           tvb_length_remaining(tvb, offset) - 4,
                                                           tvb_length_remaining(tvb, offset) - 4);
                    gboolean was_writable = col_get_writable(pinfo->cinfo);

                    /* We always want to see this in the info column */
                    col_set_writable(pinfo->cinfo, TRUE);

                    call_dissector_only(rrc_handle, payload_tvb, pinfo, pdcp_tree, NULL);

                    /* Restore to whatever it was */
                    col_set_writable(pinfo->cinfo, was_writable);
                }
                else {
                     /* Just show data */
                        proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, tvb, offset,
                                            tvb_length_remaining(tvb, offset) - 4, ENC_NA);
                }
            }
            else {
                /* Just show as unparsed data */
                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, tvb, offset,
                                    tvb_length_remaining(tvb, offset) - 4, ENC_NA);
            }

            data_length = tvb_length_remaining(tvb, offset) - 4;
            offset += data_length;

            /* Last 4 bytes are MAC */
            mac = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_mac, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            col_append_fstr(pinfo->cinfo, COL_INFO, " MAC=0x%08x (%u bytes data)",
                            mac, data_length);

        }
        else if (p_pdcp_info->plane == USER_PLANE) {

            /**********************************/
            /* User-plane messages            */
            gboolean pdu_type = (first_byte & 0x80) >> 7;

            /* Data/Control flag */
            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_data_control, tvb, offset, 1, ENC_BIG_ENDIAN);

            if (pdu_type == 1) {
                /*****************************/
                /* Use-plane Data            */

                /* Number of sequence number bits depends upon config */
                switch (p_pdcp_info->seqnum_length) {
                    case PDCP_SN_LENGTH_7_BITS:
                        seqnum = first_byte & 0x7f;
                        seqnum_set = TRUE;
                        proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_7, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        break;
                    case PDCP_SN_LENGTH_12_BITS:
                        {
                            proto_item *ti;
                            guint8 reserved_value;

                            /* 3 reserved bits */
                            ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_reserved3, tvb, offset, 1, ENC_BIG_ENDIAN);
                            reserved_value = (first_byte & 0x70) >> 4;

                            /* Complain if not 0 */
                            if (reserved_value != 0) {
                                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                                       "Reserved bits have value 0x%x - should be 0x0",
                                                       reserved_value);
                            }

                            /* 12-bit sequence number */
                            seqnum = tvb_get_ntohs(tvb, offset) & 0x0fff;
                            seqnum_set = TRUE;
                            proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_12, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;
                        }
                        break;
                    case PDCP_SN_LENGTH_15_BITS:
                        seqnum = tvb_get_ntohs(tvb, offset) & 0x7fff;
                        seqnum_set = TRUE;
                        proto_tree_add_item(pdcp_tree, hf_pdcp_lte_seq_num_15, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        break;
                    default:
                        /* Not a recognised data format!!!!! */
                        return;
                }

                write_pdu_label_and_info(root_ti, pinfo, " (SN=%u)", seqnum);
            }
            else {
                /*******************************/
                /* User-plane Control messages */
                guint8 control_pdu_type = (first_byte & 0x70) >> 4;
                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_control_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);

                switch (control_pdu_type) {
                    case 0:    /* PDCP status report */
                        {
                            guint16 fms;
                            guint16 modulo;
                            guint   not_received = 0;
                            guint   sn;
                            proto_tree *bitmap_tree;
                            proto_item *bitmap_ti = NULL;

                            if (p_pdcp_info->seqnum_length == PDCP_SN_LENGTH_12_BITS) {
                                /* First-Missing-Sequence SN */
                                fms = tvb_get_ntohs(tvb, offset) & 0x0fff;
                                sn = (fms + 1) % 4096;
                                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_fms, tvb,
                                                    offset, 2, ENC_BIG_ENDIAN);
                                offset += 2;
                                modulo = 4096;
                            } else {
                                proto_item *ti;
                                guint8 reserved_value;

                                /* 5 reserved bits */
                                ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_reserved4, tvb, offset, 2, ENC_BIG_ENDIAN);
                                reserved_value = (tvb_get_ntohs(tvb, offset) & 0x0f80)>>7;
                                offset++;

                                /* Complain if not 0 */
                                if (reserved_value != 0) {
                                    expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                                           "Reserved bits have value 0x%x - should be 0x0",
                                                           reserved_value);
                                }

                                /* First-Missing-Sequence SN */
                                fms = tvb_get_ntohs(tvb, offset) & 0x7fff;
                                sn = (fms + 1) % 32768;
                                proto_tree_add_item(pdcp_tree, hf_pdcp_lte_fms2, tvb,
                                                    offset, 2, ENC_BIG_ENDIAN);
                                offset += 2;
                                modulo = 32768;
                            }

                            /* Bitmap tree */
                            if (tvb_length_remaining(tvb, offset) > 0) {
                                bitmap_ti = proto_tree_add_item(pdcp_tree, hf_pdcp_lte_bitmap, tvb,
                                                                offset, -1, ENC_NA);
                                bitmap_tree = proto_item_add_subtree(bitmap_ti, ett_pdcp_report_bitmap);


                                /* For each byte... */
                                for ( ; tvb_length_remaining(tvb, offset); offset++) {
                                    guint bit_offset = 0;
                                    /* .. look for error (0) in each bit */
                                    for ( ; bit_offset < 8; bit_offset++) {
                                        if ((tvb_get_guint8(tvb, offset) >> (7-bit_offset) & 0x1) == 0) {
                                            proto_tree_add_boolean_bits_format_value(bitmap_tree, hf_pdcp_lte_bitmap_not_received, tvb, offset*8 + bit_offset,
                                                                                     1, 0, " (SN=%u)", sn);
                                            not_received++;
                                        }
                                        sn = (sn + 1) % modulo;
                                    }
                                }
                            }

                            if (bitmap_ti != NULL) {
                                proto_item_append_text(bitmap_ti, " (%u SNs not received)", not_received);
                            }
                            write_pdu_label_and_info(root_ti, pinfo, " Status Report (fms=%u) not-received=%u",
                                                    fms, not_received);
                        }
                        return;

                    case 1:     /* ROHC Feedback */
                        offset++;
                        break;  /* Drop-through to dissect feedback */

                    default:    /* Reserved */
                        return;
                }
            }
        }
        else {
            /* Invalid plane setting...! */
            write_pdu_label_and_info(root_ti, pinfo, " - INVALID PLANE (%u)",
                                     p_pdcp_info->plane);
            return;
        }

        /* Do sequence analysis if configured to. */
        if (seqnum_set) {
            gboolean do_analysis = FALSE;

            switch (global_pdcp_check_sequence_numbers) {
                case FALSE:
                    break;
                case SEQUENCE_ANALYSIS_RLC_ONLY:
                    if ((p_get_proto_data(pinfo->fd, proto_rlc_lte) != NULL) &&
                        !p_pdcp_info->is_retx) {
                        do_analysis = TRUE;
                    }
                    break;
                case SEQUENCE_ANALYSIS_PDCP_ONLY:
                    if (p_get_proto_data(pinfo->fd, proto_rlc_lte) == NULL) {
                        do_analysis = TRUE;
                    }
                    break;
            }

            if (do_analysis) {
                checkChannelSequenceInfo(pinfo, tvb, p_pdcp_info,
                                         (guint16)seqnum, pdcp_tree);
            }
        }
    }
    else {
        /* Show that its a no-header PDU */
        write_pdu_label_and_info(root_ti, pinfo, " No-Header ");
    }

    /* If not compressed with ROHC, show as user-plane data */
    if (!p_pdcp_info->rohc_compression) {
        gint payload_length = tvb_length_remaining(tvb, offset);
        if (payload_length > 0) {
            if (p_pdcp_info->plane == USER_PLANE) {
                if (global_pdcp_dissect_user_plane_as_ip) {
                    tvbuff_t *payload_tvb = tvb_new_subset_remaining(tvb, offset);

                    /* Don't update info column for ROHC unless configured to */
                    if (global_pdcp_lte_layer_to_show != ShowTrafficLayer) {
                        col_set_writable(pinfo->cinfo, FALSE);
                    }

                    switch (tvb_get_guint8(tvb, offset) & 0xf0) {
                        case 0x40:
                            call_dissector_only(ip_handle, payload_tvb, pinfo, pdcp_tree, NULL);
                            break;
                        case 0x60:
                            call_dissector_only(ipv6_handle, payload_tvb, pinfo, pdcp_tree, NULL);
                            break;
                        default:
                            call_dissector_only(data_handle, payload_tvb, pinfo, pdcp_tree, NULL);
                            break;
                    }

                    /* Freeze the columns again because we don't want other layers writing to info */
                    if (global_pdcp_lte_layer_to_show == ShowTrafficLayer) {
                        col_set_writable(pinfo->cinfo, FALSE);
                    }

                }
                else {
                    proto_tree_add_item(pdcp_tree, hf_pdcp_lte_user_plane_data, tvb, offset, -1, ENC_NA);
                }
            }
            else {
                if (global_pdcp_dissect_signalling_plane_as_rrc) {
                    /* Get appropriate dissector handle */
                    dissector_handle_t rrc_handle = lookup_rrc_dissector_handle(p_pdcp_info);

                    if (rrc_handle != 0) {
                        /* Call RRC dissector if have one */
                        tvbuff_t *payload_tvb = tvb_new_subset(tvb, offset,
                                                               payload_length,
                                                               payload_length);

                        call_dissector_only(rrc_handle, payload_tvb, pinfo, pdcp_tree, NULL);
                    }
                    else {
                         /* Just show data */
                         proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, tvb, offset,
                                             payload_length, ENC_NA);
                    }
                }
                else {
                    proto_tree_add_item(pdcp_tree, hf_pdcp_lte_signalling_data, tvb, offset, -1, ENC_NA);
                }
            }

            write_pdu_label_and_info(root_ti, pinfo, "(%u bytes data)",
                                     payload_length);
        }

        /* Let RLC write to columns again */
        col_set_writable(pinfo->cinfo, global_pdcp_lte_layer_to_show == ShowRLCLayer);

        return;
    }


    /***************************/
    /* ROHC packets            */
    /***************************/


    /* Only attempt ROHC if configured to */
    if (!global_pdcp_dissect_rohc) {
        col_append_fstr(pinfo->cinfo, COL_PROTOCOL, "|ROHC(%s)",
                        val_to_str_const(p_pdcp_info->profile, rohc_profile_vals, "Unknown"));
        return;
    }

    rohc_offset = offset;
    rohc_tvb = tvb_new_subset_remaining(tvb, rohc_offset);

    /* RoHC settings */
    p_rohc_info = ep_new(rohc_info);

    p_rohc_info->rohc_compression    = p_pdcp_info->rohc_compression;
    p_rohc_info->rohc_ip_version     = p_pdcp_info->rohc_ip_version;
    p_rohc_info->cid_inclusion_info  = p_pdcp_info->cid_inclusion_info;
    p_rohc_info->large_cid_present   = p_pdcp_info->large_cid_present;
    p_rohc_info->mode                = p_pdcp_info->mode;
    p_rohc_info->rnd                 = p_pdcp_info->rnd;
    p_rohc_info->udp_checkum_present = p_pdcp_info->udp_checkum_present;
    p_rohc_info->profile             = p_pdcp_info->profile;
    p_rohc_info->last_created_item   = NULL;

    pinfo->private_data = p_rohc_info;

    /* Only enable writing to column if configured to show ROHC */
    if (global_pdcp_lte_layer_to_show != ShowTrafficLayer) {
        col_set_writable(pinfo->cinfo, FALSE);
    }
    else {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    /* Call the ROHC dissector */
    call_dissector(rohc_handle, rohc_tvb, pinfo, tree);

    /* Let RLC write to columns again */
    col_set_writable(pinfo->cinfo, global_pdcp_lte_layer_to_show == ShowRLCLayer);
}

/* Initializes the hash tables each time a new
 * file is loaded or re-loaded in wireshark */
static void pdcp_lte_init_protocol(void)
{
    /* Destroy any existing hashes. */
    if (pdcp_sequence_analysis_channel_hash) {
        g_hash_table_destroy(pdcp_sequence_analysis_channel_hash);
    }
    if (pdcp_lte_sequence_analysis_report_hash) {
        g_hash_table_destroy(pdcp_lte_sequence_analysis_report_hash);
    }


    /* Now create them over */
    pdcp_sequence_analysis_channel_hash = g_hash_table_new(pdcp_channel_hash_func, pdcp_channel_equal);
    pdcp_lte_sequence_analysis_report_hash = g_hash_table_new(pdcp_result_hash_func, pdcp_result_hash_equal);
}



void proto_register_pdcp(void)
{
    static hf_register_info hf[] =
    {
        { &hf_pdcp_lte_configuration,
            { "Configuration",
              "pdcp-lte.configuration", FT_STRING, BASE_NONE, NULL, 0x0,
              "Configuration info passed into dissector", HFILL
            }
        },

        { &hf_pdcp_lte_rohc_compression,
            { "ROHC Compression",
              "pdcp-lte.rohc.compression", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_mode,
            { "ROHC Mode",
              "pdcp-lte.rohc.mode", FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_rnd,
            { "RND",  /* TODO: true/false vals? */
              "pdcp-lte.rohc.rnd", FT_UINT8, BASE_DEC, NULL, 0x0,
              "RND of outer ip header", HFILL
            }
        },
        { &hf_pdcp_lte_rohc_udp_checksum_present,
            { "UDP Checksum",  /* TODO: true/false vals? */
              "pdcp-lte.rohc.checksum-present", FT_UINT8, BASE_DEC, NULL, 0x0,
              "UDP Checksum present", HFILL
            }
        },
        { &hf_pdcp_lte_direction,
            { "Direction",
              "pdcp-lte.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_pdcp_lte_ueid,
            { "UE",
              "pdcp-lte.ueid", FT_UINT16, BASE_DEC, 0, 0x0,
              "UE Identifier", HFILL
            }
        },
        { &hf_pdcp_lte_channel_type,
            { "Channel type",
              "pdcp-lte.channel-type", FT_UINT8, BASE_DEC, VALS(logical_channel_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_channel_id,
            { "Channel Id",
              "pdcp-lte.channel-id", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_rohc_profile,
            { "ROHC profile",
              "pdcp-lte.rohc.profile", FT_UINT8, BASE_DEC, VALS(rohc_profile_vals), 0x0,
              "ROHC Mode", HFILL
            }
        },
        { &hf_pdcp_lte_no_header_pdu,
            { "No Header PDU",
              "pdcp-lte.no-header_pdu", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_plane,
            { "Plane",
              "pdcp-lte.plane", FT_UINT8, BASE_DEC, VALS(pdcp_plane_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_seqnum_length,
            { "Seqnum length",
              "pdcp-lte.seqnum_length", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Sequence Number Length", HFILL
            }
        },


        { &hf_pdcp_lte_cid_inclusion_info,
            { "CID Inclusion Info",
              "pdcp-lte.cid-inclusion-info", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_large_cid_present,
            { "Large CID Present",
              "pdcp-lte.large-cid-present", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_lte_control_plane_reserved,
            { "Reserved",
              "pdcp-lte.reserved", FT_UINT8, BASE_DEC, NULL, 0xe0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_5,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT8, BASE_DEC, NULL, 0x1f,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_7,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT8, BASE_DEC, NULL, 0x7f,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_reserved3,
            { "Reserved",
              "pdcp-lte.reserved3", FT_UINT8, BASE_HEX, NULL, 0x70,
              "3 reserved bits", HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_12,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_seq_num_15,
            { "Seq Num",
              "pdcp-lte.seq-num", FT_UINT16, BASE_DEC, NULL, 0x7fff,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_lte_signalling_data,
            { "Signalling Data",
              "pdcp-lte.signalling-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_mac,
            { "MAC",
              "pdcp-lte.mac", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_data_control,
            { "PDU Type",
              "pdcp-lte.pdu-type", FT_UINT8, BASE_HEX, VALS(pdu_type_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_user_plane_data,
            { "User-Plane Data",
              "pdcp-lte.user-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_control_pdu_type,
            { "Control PDU Type",
              "pdcp-lte.control-pdu-type", FT_UINT8, BASE_HEX, VALS(control_pdu_type_vals), 0x70,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_fms,
            { "First Missing Sequence Number",
              "pdcp-lte.fms", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "First Missing PDCP Sequence Number", HFILL
            }
        },
        { &hf_pdcp_lte_reserved4,
            { "Reserved",
              "pdcp-lte.reserved4", FT_UINT16, BASE_HEX, NULL, 0x0f80,
              "5 reserved bits", HFILL
            }
        },
        { &hf_pdcp_lte_fms2,
            { "First Missing Sequence Number",
              "pdcp-lte.fms", FT_UINT16, BASE_DEC, NULL, 0x07fff,
              "First Missing PDCP Sequence Number", HFILL
            }
        },
        { &hf_pdcp_lte_bitmap,
            { "Bitmap",
              "pdcp-lte.bitmap", FT_NONE, BASE_NONE, NULL, 0x0,
              "Status report bitmap (0=error, 1=OK)", HFILL
            }
        },
        { &hf_pdcp_lte_bitmap_not_received,
            { "Not Received",
              "pdcp-lte.bitmap.error", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              "Status report PDU error", HFILL
            }
        },


        { &hf_pdcp_lte_sequence_analysis,
            { "Sequence Analysis",
              "pdcp-lte.sequence-analysis", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_ok,
            { "OK",
              "pdcp-lte.sequence-analysis.ok", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_previous_frame,
            { "Previous frame for channel",
              "pdcp-lte.sequence-analysis.previous-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_next_frame,
            { "Next frame for channel",
              "pdcp-lte.sequence-analysis.next-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_expected_sn,
            { "Expected SN",
              "pdcp-lte.sequence-analysis.expected-sn", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_skipped,
            { "Skipped frames",
              "pdcp-lte.sequence-analysis.skipped-frames", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_lte_sequence_analysis_repeated,
            { "Repeated frame",
              "pdcp-lte.sequence-analysis.repeated-frame", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },


    };

    static gint *ett[] =
    {
        &ett_pdcp,
        &ett_pdcp_configuration,
        &ett_pdcp_packet,
        &ett_pdcp_lte_sequence_analysis,
        &ett_pdcp_report_bitmap
    };

    static const enum_val_t sequence_analysis_vals[] = {
        {"no-analysis", "No-Analysis",      FALSE},
        {"rlc-only",    "Only-RLC-frames",  SEQUENCE_ANALYSIS_RLC_ONLY},
        {"pdcp-only",   "Only-PDCP-frames", SEQUENCE_ANALYSIS_PDCP_ONLY},
        {NULL, NULL, -1}
    };

    static const enum_val_t show_info_col_vals[] = {
        {"show-rlc", "RLC Info", ShowRLCLayer},
        {"show-pdcp", "PDCP Info", ShowPDCPLayer},
        {"show-traffic", "Traffic Info", ShowTrafficLayer},
        {NULL, NULL, -1}
    };

    module_t *pdcp_lte_module;


    /* Register protocol. */
    proto_pdcp_lte = proto_register_protocol("PDCP-LTE", "PDCP-LTE", "pdcp-lte");
    proto_register_field_array(proto_pdcp_lte, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name. */
    register_dissector("pdcp-lte", dissect_pdcp_lte, proto_pdcp_lte);

    pdcp_lte_module = prefs_register_protocol(proto_pdcp_lte, NULL);

    /* Obsolete preferences */
    prefs_register_obsolete_preference(pdcp_lte_module, "show_feedback_option_tag_length");

    /* Dissect uncompressed user-plane data as IP */
    prefs_register_bool_preference(pdcp_lte_module, "show_user_plane_as_ip",
        "Show uncompressed User-Plane data as IP",
        "Show uncompressed User-Plane data as IP",
        &global_pdcp_dissect_user_plane_as_ip);

    /* Dissect unciphered signalling data as RRC */
    prefs_register_bool_preference(pdcp_lte_module, "show_signalling_plane_as_rrc",
        "Show unciphered Signalling-Plane data as RRC",
        "Show unciphered Signalling-Plane data as RRC",
        &global_pdcp_dissect_signalling_plane_as_rrc);

    /* Check for missing sequence numbers */
    prefs_register_enum_preference(pdcp_lte_module, "check_sequence_numbers",
        "Do sequence number analysis",
        "Do sequence number analysis",
        &global_pdcp_check_sequence_numbers, sequence_analysis_vals, FALSE);

    /* Attempt to dissect ROHC messages */
    prefs_register_bool_preference(pdcp_lte_module, "dissect_rohc",
        "Attempt to decode ROHC data",
        "Attempt to decode ROHC data",
        &global_pdcp_dissect_rohc);

    prefs_register_bool_preference(pdcp_lte_module, "heuristic_pdcp_lte_over_udp",
        "Try Heuristic LTE-PDCP over UDP framing",
        "When enabled, use heuristic dissector to find PDCP-LTE frames sent with "
        "UDP framing",
        &global_pdcp_lte_heur);

    prefs_register_enum_preference(pdcp_lte_module, "layer_to_show",
        "Which layer info to show in Info column",
        "Can show RLC, PDCP or Traffic layer info in Info column",
        &global_pdcp_lte_layer_to_show, show_info_col_vals, FALSE);

    register_init_routine(&pdcp_lte_init_protocol);
}

void proto_reg_handoff_pdcp_lte(void)
{
    /* Add as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_pdcp_lte_heur, proto_pdcp_lte);

    ip_handle   = find_dissector("ip");
    ipv6_handle = find_dissector("ipv6");
    rohc_handle = find_dissector("rohc");
    data_handle = find_dissector("data");
}

