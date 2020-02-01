/* packet-pdcp-nr.c
 * Routines for nr PDCP
 *
 * Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/proto_data.h>

#include <wsutil/wsgcrypt.h>


#include "packet-rlc-nr.h"
#include "packet-pdcp-nr.h"

void proto_register_pdcp_nr(void);
void proto_reg_handoff_pdcp_nr(void);

/* Described in:
 * 3GPP TS 38.323 Technical Specification Group Radio Access Netowrk; NR;
 *                Packet Data Convergence Protocol (PDCP) specification (Release 15.1.0)
 */


/* TODO:
   - Deciphering, but should refactor and share LTE implementation
*/


/* Initialize the protocol and registered fields. */
int proto_pdcp_nr = -1;

extern int proto_rlc_nr;

/* Configuration (info known outside of PDU) */
static int hf_pdcp_nr_configuration = -1;
static int hf_pdcp_nr_direction = -1;
static int hf_pdcp_nr_ueid = -1;
static int hf_pdcp_nr_bearer_type = -1;
static int hf_pdcp_nr_bearer_id = -1;
static int hf_pdcp_nr_plane = -1;
static int hf_pdcp_nr_seqnum_length = -1;

static int hf_pdcp_nr_rohc_compression = -1;
static int hf_pdcp_nr_rohc_mode = -1;
static int hf_pdcp_nr_rohc_rnd = -1;
static int hf_pdcp_nr_rohc_udp_checksum_present = -1;
static int hf_pdcp_nr_rohc_profile = -1;
static int hf_pdcp_nr_cid_inclusion_info = -1;
static int hf_pdcp_nr_large_cid_present = -1;

/* PDCP header fields */
static int hf_pdcp_nr_control_plane_reserved = -1;
static int hf_pdcp_nr_reserved3 = -1;
static int hf_pdcp_nr_seq_num_12 = -1;
static int hf_pdcp_nr_reserved5 = -1;
static int hf_pdcp_nr_seq_num_18 = -1;
static int hf_pdcp_nr_signalling_data = -1;
static int hf_pdcp_nr_mac = -1;
static int hf_pdcp_nr_data_control = -1;
static int hf_pdcp_nr_user_plane_data = -1;
static int hf_pdcp_nr_control_pdu_type = -1;
static int hf_pdcp_nr_fmc = -1;
static int hf_pdcp_nr_reserved4 = -1;
static int hf_pdcp_nr_bitmap = -1;
static int hf_pdcp_nr_bitmap_byte = -1;

/* Sequence Analysis */
static int hf_pdcp_nr_sequence_analysis = -1;
static int hf_pdcp_nr_sequence_analysis_ok = -1;
static int hf_pdcp_nr_sequence_analysis_previous_frame = -1;
static int hf_pdcp_nr_sequence_analysis_next_frame = -1;
static int hf_pdcp_nr_sequence_analysis_expected_sn = -1;
static int hf_pdcp_nr_sequence_analysis_repeated = -1;
static int hf_pdcp_nr_sequence_analysis_skipped = -1;


/* Protocol subtree. */
static int ett_pdcp = -1;
static int ett_pdcp_configuration = -1;
static int ett_pdcp_packet = -1;
static int ett_pdcp_nr_sequence_analysis = -1;
static int ett_pdcp_report_bitmap = -1;

static expert_field ei_pdcp_nr_sequence_analysis_wrong_sequence_number = EI_INIT;
static expert_field ei_pdcp_nr_reserved_bits_not_zero = EI_INIT;
static expert_field ei_pdcp_nr_sequence_analysis_sn_repeated = EI_INIT;
static expert_field ei_pdcp_nr_sequence_analysis_sn_missing = EI_INIT;
static expert_field ei_pdcp_nr_unknown_udp_framing_tag = EI_INIT;
static expert_field ei_pdcp_nr_missing_udp_framing_tag = EI_INIT;



static const value_string direction_vals[] =
{
    { PDCP_NR_DIRECTION_UPLINK,      "Uplink"},
    { PDCP_NR_DIRECTION_DOWNLINK,    "Downlink"},
    { 0, NULL }
};


static const value_string pdcp_plane_vals[] = {
    { NR_SIGNALING_PLANE,    "Signalling" },
    { NR_USER_PLANE,         "User" },
    { 0,   NULL }
};

static const value_string bearer_type_vals[] = {
    { Bearer_DCCH,        "DCCH"},
    { Bearer_BCCH_BCH,    "BCCH_BCH"},
    { Bearer_BCCH_DL_SCH, "BCCH_DL_SCH"},
    { Bearer_CCCH,        "CCCH"},
    { Bearer_PCCH,        "PCCH"},
    { 0,                  NULL}
};

static const value_string rohc_mode_vals[] = {
    { UNIDIRECTIONAL,            "Unidirectional" },
    { OPTIMISTIC_BIDIRECTIONAL,  "Optimistic Bidirectional" },
    { RELIABLE_BIDIRECTIONAL,    "Reliable Bidirectional" },
    { 0,   NULL }
};


/* Entries taken from Table 5.7.1-1.
   Descriptions from http://www.iana.org/assignments/rohc-pro-ids/rohc-pro-ids.txt */
static const value_string rohc_profile_vals[] = {
    { 0x0000,   "ROHC uncompressed" },      /* [RFC5795] */
    { 0x0001,   "ROHC RTP" },               /* [RFC3095] */
    { 0x0002,   "ROHC UDP" },               /* [RFC3095] */
    { 0x0003,   "ROHC ESP" },               /* [RFC3095] */
    { 0x0004,   "ROHC IP" },                /* [RFC3843] */
    { 0x0006,   "ROHC TCP" },               /* [RFC4996] */

    { 0x0101,   "ROHCv2 RTP" },             /* [RFC5225] */
    { 0x0102,   "ROHCv2 UDP" },             /* [RFC5225] */
    { 0x0103,   "ROHCv2 ESP" },             /* [RFC5225] */
    { 0x0104,   "ROHCv2 IP" },              /* [RFC5225] */
    { 0,   NULL }
};

static const true_false_string pdu_type_bit = {
    "Data PDU",
    "Control PDU"
};


static const value_string control_pdu_type_vals[] = {
    { 0,   "PDCP status report" },
    { 1,   "Interspersed ROHC feedback packet" },
    { 0,   NULL }
};

#if 0
static const value_string integrity_algorithm_vals[] = {
    { 0,   "NIA0" },
    { 1,   "NIA1" },
    { 2,   "NIA2" },
    { 3,   "NIA3" },
    { 0,   NULL }
};

static const value_string ciphering_algorithm_vals[] = {
    { 0,   "NEA0" },
    { 1,   "NEA1" },
    { 2,   "NEA2" },
    { 3,   "NEA3" },
    { 0,   NULL }
};
#endif


/* SDAP header fields and tree */
static int proto_sdap = -1;
static int hf_sdap_rdi = -1;
static int hf_sdap_rqi = -1;
static int hf_sdap_qfi = -1;
static int hf_sdap_data_control = -1;
static int hf_sdap_reserved = -1;
static gint ett_sdap = -1;

static const true_false_string sdap_rdi = {
    "To store QoS flow to DRB mapping rule",
    "No action"
};

static const true_false_string sdap_rqi = {
    "To inform NAS that RQI bit is set to 1",
    "No action"
};


static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t rohc_handle;
static dissector_handle_t nr_rrc_ul_ccch;
static dissector_handle_t nr_rrc_ul_ccch1;
static dissector_handle_t nr_rrc_dl_ccch;
static dissector_handle_t nr_rrc_pcch;
static dissector_handle_t nr_rrc_bcch_bch;
static dissector_handle_t nr_rrc_bcch_dl_sch;
static dissector_handle_t nr_rrc_ul_dcch;
static dissector_handle_t nr_rrc_dl_dcch;


#define SEQUENCE_ANALYSIS_RLC_ONLY  1
#define SEQUENCE_ANALYSIS_PDCP_ONLY 2

/* Preference variables */
static gboolean global_pdcp_dissect_user_plane_as_ip = TRUE;
static gboolean global_pdcp_dissect_signalling_plane_as_rrc = TRUE;
static gint     global_pdcp_check_sequence_numbers = TRUE;
static gboolean global_pdcp_dissect_rohc = FALSE;

/* Which layer info to show in the info column */
enum layer_to_show {
    ShowRLCLayer, ShowPDCPLayer, ShowTrafficLayer
};
static gint     global_pdcp_nr_layer_to_show = (gint)ShowRLCLayer;


/* Function to be called from outside this module (e.g. in a plugin) to get per-packet data */
pdcp_nr_info *get_pdcp_nr_proto_data(packet_info *pinfo)
{
    return (pdcp_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0);
}

/* Function to be called from outside this module (e.g. in a plugin) to set per-packet data */
void set_pdcp_nr_proto_data(packet_info *pinfo, pdcp_nr_info *p_pdcp_nr_info)
{
    p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0, p_pdcp_nr_info);
}



/**************************************************/
/* Sequence number analysis                       */

/* Bearer key */
typedef struct
{
    /* Using bit fields to fit into 32 bits, so avoiding the need to allocate
       heap memory for these structs */
    guint           ueId : 16;
    guint           plane : 2;
    guint           bearerId : 6;
    guint           direction : 1;
    guint           notUsed : 7;
} pdcp_bearer_hash_key;

/* Bearer state */
typedef struct
{
    guint32  previousSequenceNumber;
    guint32  previousFrameNum;
    guint32  hfn;
} pdcp_bearer_status;

/* The sequence analysis bearer hash table.
   Maps key -> status */
static wmem_map_t *pdcp_sequence_analysis_bearer_hash = NULL;


/* Hash table types & functions for frame reports */

typedef struct {
    guint32         frameNumber;
    guint32         SN :       18;
    guint32         plane :    2;
    guint32         bearerId: 5;
    guint32         direction: 1;
    guint32         notUsed :  6;
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

    /* TODO: This is a bit random.  */
    return val1->frameNumber + (val1->bearerId<<7) +
                               (val1->plane<<12) +
                               (val1->SN<<14) +
                               (val1->direction<<6);
}

/* pdcp_bearer_hash_key fits into the pointer, so just copy the value into
   a guint, cast to a pointer and return that as the key */
static gpointer get_bearer_hash_key(pdcp_bearer_hash_key *key)
{
    guint  asInt = 0;
    /* TODO: assert that sizeof(pdcp_bearer_hash_key) <= sizeof(guint) ? */
    memcpy(&asInt, key, sizeof(pdcp_bearer_hash_key));
    return GUINT_TO_POINTER(asInt);
}

/* Convenience function to get a pointer for the hash_func to work with */
static gpointer get_report_hash_key(guint32 SN, guint32 frameNumber,
                                    pdcp_nr_info *p_pdcp_nr_info,
                                    gboolean do_persist)
{
    static pdcp_result_hash_key  key;
    pdcp_result_hash_key        *p_key;

    /* Only allocate a struct when will be adding entry */
    if (do_persist) {
        p_key = wmem_new(wmem_file_scope(), pdcp_result_hash_key);
    }
    else {
        memset(&key, 0, sizeof(pdcp_result_hash_key));
        p_key = &key;
    }

    /* Fill in details, and return pointer */
    p_key->frameNumber = frameNumber;
    p_key->SN = SN;
    p_key->plane = (guint8)p_pdcp_nr_info->plane;
    p_key->bearerId = p_pdcp_nr_info->bearerId;
    p_key->direction = p_pdcp_nr_info->direction;
    p_key->notUsed = 0;

    return p_key;
}


/* Info to attach to frame when first read, recording what to show about sequence */
typedef enum
{
    SN_OK, SN_Repeated, SN_MAC_Retx, SN_Retx, SN_Missing
} sequence_state;
typedef struct
{
    gboolean sequenceExpectedCorrect;
    guint32  sequenceExpected;
    guint32  previousFrameNum;
    guint32  nextFrameNum;

    guint32  firstSN;
    guint32  lastSN;
    guint32  hfn;

    sequence_state state;
} pdcp_sequence_report_in_frame;

/* The sequence analysis frame report hash table.
   Maps pdcp_result_hash_key* -> pdcp_sequence_report_in_frame* */
static wmem_map_t *pdcp_nr_sequence_analysis_report_hash = NULL;


/* Add to the tree values associated with sequence analysis for this frame */
static void addBearerSequenceInfo(pdcp_sequence_report_in_frame *p,
                                   pdcp_nr_info *p_pdcp_nr_info,
                                   guint32   sequenceNumber,
                                   packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb)
{
    proto_tree *seqnum_tree;
    proto_item *seqnum_ti;
    proto_item *ti_expected_sn;
    proto_item *ti;

    /* Create subtree */
    seqnum_ti = proto_tree_add_string_format(tree,
                                             hf_pdcp_nr_sequence_analysis,
                                             tvb, 0, 0,
                                             "", "Sequence Analysis");
    seqnum_tree = proto_item_add_subtree(seqnum_ti,
                                         ett_pdcp_nr_sequence_analysis);
    proto_item_set_generated(seqnum_ti);


    /* Previous bearer frame */
    if (p->previousFrameNum != 0) {
        proto_tree_add_uint(seqnum_tree, hf_pdcp_nr_sequence_analysis_previous_frame,
                            tvb, 0, 0, p->previousFrameNum);
    }

    /* Expected sequence number */
    ti_expected_sn = proto_tree_add_uint(seqnum_tree, hf_pdcp_nr_sequence_analysis_expected_sn,
                                         tvb, 0, 0, p->sequenceExpected);
    proto_item_set_generated(ti_expected_sn);

    /* Make sure we have recognised SN length */
    switch (p_pdcp_nr_info->seqnum_length) {
        case PDCP_NR_SN_LENGTH_12_BITS:
        case PDCP_NR_SN_LENGTH_18_BITS:
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    switch (p->state) {
        case SN_OK:
            proto_item_set_hidden(ti_expected_sn);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_nr_sequence_analysis_ok,
                                        tvb, 0, 0, TRUE);
            proto_item_set_generated(ti);
            proto_item_append_text(seqnum_ti, " - OK");

            /* Link to next SN in bearer (if known) */
            if (p->nextFrameNum != 0) {
                proto_tree_add_uint(seqnum_tree, hf_pdcp_nr_sequence_analysis_next_frame,
                                    tvb, 0, 0, p->nextFrameNum);
            }

            break;

        case SN_Missing:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_nr_sequence_analysis_ok,
                                        tvb, 0, 0, FALSE);
            proto_item_set_generated(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_nr_sequence_analysis_skipped,
                                        tvb, 0, 0, TRUE);
            proto_item_set_generated(ti);
            if (p->lastSN != p->firstSN) {
                expert_add_info_format(pinfo, ti, &ei_pdcp_nr_sequence_analysis_sn_missing,
                                       "PDCP SNs (%u to %u) missing for %s on UE %u (%s-%u)",
                                       p->firstSN, p->lastSN,
                                       val_to_str_const(p_pdcp_nr_info->direction, direction_vals, "Unknown"),
                                       p_pdcp_nr_info->ueid,
                                       val_to_str_const(p_pdcp_nr_info->bearerType, bearer_type_vals, "Unknown"),
                                       p_pdcp_nr_info->bearerId);
                proto_item_append_text(seqnum_ti, " - SNs missing (%u to %u)",
                                       p->firstSN, p->lastSN);
            }
            else {
                expert_add_info_format(pinfo, ti, &ei_pdcp_nr_sequence_analysis_sn_missing,
                                       "PDCP SN (%u) missing for %s on UE %u (%s-%u)",
                                       p->firstSN,
                                       val_to_str_const(p_pdcp_nr_info->direction, direction_vals, "Unknown"),
                                       p_pdcp_nr_info->ueid,
                                       val_to_str_const(p_pdcp_nr_info->bearerType, bearer_type_vals, "Unknown"),
                                       p_pdcp_nr_info->bearerId);
                proto_item_append_text(seqnum_ti, " - SN missing (%u)",
                                       p->firstSN);
            }
            break;

        case SN_Repeated:
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_nr_sequence_analysis_ok,
                                        tvb, 0, 0, FALSE);
            proto_item_set_generated(ti);
            ti = proto_tree_add_boolean(seqnum_tree, hf_pdcp_nr_sequence_analysis_repeated,
                                        tvb, 0, 0, TRUE);
            proto_item_set_generated(ti);
            expert_add_info_format(pinfo, ti, &ei_pdcp_nr_sequence_analysis_sn_repeated,
                                   "PDCP SN (%u) repeated for %s for UE %u (%s-%u)",
                                   p->firstSN,
                                   val_to_str_const(p_pdcp_nr_info->direction, direction_vals, "Unknown"),
                                   p_pdcp_nr_info->ueid,
                                   val_to_str_const(p_pdcp_nr_info->bearerType, bearer_type_vals, "Unknown"),
                                   p_pdcp_nr_info->bearerId);
            proto_item_append_text(seqnum_ti, "- SN %u Repeated",
                                   p->firstSN);
            break;

        default:
            /* Incorrect sequence number */
            expert_add_info_format(pinfo, ti_expected_sn, &ei_pdcp_nr_sequence_analysis_wrong_sequence_number,
                                   "Wrong Sequence Number for %s on UE %u (%s-%u) - got %u, expected %u",
                                   val_to_str_const(p_pdcp_nr_info->direction, direction_vals, "Unknown"),
                                   p_pdcp_nr_info->ueid,
                                   val_to_str_const(p_pdcp_nr_info->bearerType, bearer_type_vals, "Unknown"),
                                   p_pdcp_nr_info->bearerId,
                                   sequenceNumber, p->sequenceExpected);
            break;
    }
}


/* Update the bearer status and set report for this frame */
static void checkBearerSequenceInfo(packet_info *pinfo, tvbuff_t *tvb,
                                     pdcp_nr_info *p_pdcp_nr_info,
                                     guint32 sequenceNumber,
                                     proto_tree *tree)
{
    pdcp_bearer_hash_key          bearer_key;
    pdcp_bearer_status           *p_bearer_status;
    pdcp_sequence_report_in_frame *p_report_in_frame      = NULL;
    gboolean                       createdBearer          = FALSE;
    guint32                        expectedSequenceNumber = 0;
    guint32                        snLimit                = 0;

    /* If find stat_report_in_frame already, use that and get out */
    if (pinfo->fd->visited) {
        p_report_in_frame =
            (pdcp_sequence_report_in_frame*)wmem_map_lookup(pdcp_nr_sequence_analysis_report_hash,
                                                            get_report_hash_key(sequenceNumber,
                                                                                pinfo->num,
                                                                                p_pdcp_nr_info, FALSE));
        if (p_report_in_frame != NULL) {
            addBearerSequenceInfo(p_report_in_frame, p_pdcp_nr_info,
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
    /* Create or find an entry for this bearer state */
    bearer_key.ueId = p_pdcp_nr_info->ueid;
    bearer_key.plane = p_pdcp_nr_info->plane;
    bearer_key.bearerId = p_pdcp_nr_info->bearerId;
    bearer_key.direction = p_pdcp_nr_info->direction;
    bearer_key.notUsed = 0;

    /* Do the table lookup */
    p_bearer_status = (pdcp_bearer_status*)wmem_map_lookup(pdcp_sequence_analysis_bearer_hash,
                                                             get_bearer_hash_key(&bearer_key));

    /* Create table entry if necessary */
    if (p_bearer_status == NULL) {
        createdBearer = TRUE;

        /* Allocate a new value and duplicate key contents */
        p_bearer_status = wmem_new0(wmem_file_scope(), pdcp_bearer_status);

        /* Add entry */
        wmem_map_insert(pdcp_sequence_analysis_bearer_hash,
                        get_bearer_hash_key(&bearer_key), p_bearer_status);
    }

    /* Create space for frame state_report */
    p_report_in_frame = wmem_new(wmem_file_scope(), pdcp_sequence_report_in_frame);
    p_report_in_frame->nextFrameNum = 0;

    switch (p_pdcp_nr_info->seqnum_length) {
        case PDCP_NR_SN_LENGTH_12_BITS:
            snLimit = 4096;
            break;
        case PDCP_NR_SN_LENGTH_18_BITS:
            snLimit = 262144;
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    /* Work out expected sequence number */
    if (!createdBearer) {
        expectedSequenceNumber = (p_bearer_status->previousSequenceNumber + 1) % snLimit;
    }
    else {
        expectedSequenceNumber = sequenceNumber;
    }

    /* Set report for this frame */
    /* For PDCP, sequence number is always expectedSequence number */
    p_report_in_frame->sequenceExpectedCorrect = (sequenceNumber == expectedSequenceNumber);
    p_report_in_frame->hfn = p_bearer_status->hfn;

    /* For wrong sequence number... */
    if (!p_report_in_frame->sequenceExpectedCorrect) {

        /* Frames are not missing if we get an earlier sequence number again */
        if (((snLimit + expectedSequenceNumber - sequenceNumber) % snLimit) > 15) {
            p_report_in_frame->state = SN_Missing;
            p_report_in_frame->firstSN = expectedSequenceNumber;
            p_report_in_frame->lastSN = (snLimit + sequenceNumber - 1) % snLimit;

            p_report_in_frame->sequenceExpected = expectedSequenceNumber;
            p_report_in_frame->previousFrameNum = p_bearer_status->previousFrameNum;

            /* Update Bearer status to remember *this* frame */
            p_bearer_status->previousFrameNum = pinfo->num;
            p_bearer_status->previousSequenceNumber = sequenceNumber;
        }
        else {
            /* An SN has been repeated */
            p_report_in_frame->state = SN_Repeated;
            p_report_in_frame->firstSN = sequenceNumber;

            p_report_in_frame->sequenceExpected = expectedSequenceNumber;
            p_report_in_frame->previousFrameNum = p_bearer_status->previousFrameNum;
        }
    }
    else {
        /* SN was OK */
        p_report_in_frame->state = SN_OK;
        p_report_in_frame->sequenceExpected = expectedSequenceNumber;
        p_report_in_frame->previousFrameNum = p_bearer_status->previousFrameNum;
        /* SN has rolled around, inc hfn! */
        if (!createdBearer && (sequenceNumber == 0)) {
            /* TODO: not worrying about HFN rolling over for now! */
            p_bearer_status->hfn++;
            p_report_in_frame->hfn = p_bearer_status->hfn;
        }

        /* Update Bearer status to remember *this* frame */
        p_bearer_status->previousFrameNum = pinfo->num;
        p_bearer_status->previousSequenceNumber = sequenceNumber;

        if (p_report_in_frame->previousFrameNum != 0) {
            /* Get report for previous frame */
            pdcp_sequence_report_in_frame *p_previous_report;
            p_previous_report = (pdcp_sequence_report_in_frame*)wmem_map_lookup(pdcp_nr_sequence_analysis_report_hash,
                                                                                get_report_hash_key((sequenceNumber+262144) % 262144,
                                                                                                    p_report_in_frame->previousFrameNum,
                                                                                                    p_pdcp_nr_info,
                                                                                                    FALSE));
            /* It really shouldn't be NULL... */
            if (p_previous_report != NULL) {
                /* Point it forward to this one */
                p_previous_report->nextFrameNum = pinfo->num;
            }
        }
    }

    /* Associate with this frame number */
    wmem_map_insert(pdcp_nr_sequence_analysis_report_hash,
                    get_report_hash_key(sequenceNumber, pinfo->num,
                                        p_pdcp_nr_info, TRUE),
                    p_report_in_frame);

    /* Add state report for this frame into tree */
    addBearerSequenceInfo(p_report_in_frame, p_pdcp_nr_info, sequenceNumber,
                           pinfo, tree, tvb);
}




/* Result is (ueid, framenum) -> pdcp_security_info_t*  */
typedef struct  ueid_frame_t {
    guint32 framenum;
    guint16 ueid;
} ueid_frame_t;



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
    /* TODO: gets called a lot, so a shame there isn't a proto_item_append_string() */
    proto_item_append_text(pdu_ti, "%s", info_buffer);
}



/***************************************************************/



/* Show in the tree the config info attached to this frame, as generated fields */
static void show_pdcp_config(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                             pdcp_nr_info *p_pdcp_info)
{
    proto_item *ti;
    proto_tree *configuration_tree;
    proto_item *configuration_ti = proto_tree_add_item(tree,
                                                       hf_pdcp_nr_configuration,
                                                       tvb, 0, 0, ENC_ASCII|ENC_NA);
    configuration_tree = proto_item_add_subtree(configuration_ti, ett_pdcp_configuration);

    /* Direction */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_direction, tvb, 0, 0,
                             p_pdcp_info->direction);
    proto_item_set_generated(ti);

    /* Plane */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_plane, tvb, 0, 0,
                             p_pdcp_info->plane);
    proto_item_set_generated(ti);

    /* UEId */
    if (p_pdcp_info->ueid != 0) {
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_ueid, tvb, 0, 0,
                                 p_pdcp_info->ueid);
        proto_item_set_generated(ti);
        write_pdu_label_and_info(configuration_ti, pinfo, "UEId=%3u", p_pdcp_info->ueid);
    }

    /* Bearer type */
    ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_bearer_type, tvb, 0, 0,
                             p_pdcp_info->bearerType);
    proto_item_set_generated(ti);
    if (p_pdcp_info->bearerId != 0) {
        /* Bearer type */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_bearer_id, tvb, 0, 0,
                                 p_pdcp_info->bearerId);
        proto_item_set_generated(ti);
    }

    /* Show channel type in root/Info */
    if (p_pdcp_info->bearerType == Bearer_DCCH) {
        write_pdu_label_and_info(configuration_ti, pinfo, "   %s-%u  ",
                                 (p_pdcp_info->plane == NR_SIGNALING_PLANE) ? "SRB" : "DRB",
                                 p_pdcp_info->bearerId);
    }
    else {
        write_pdu_label_and_info(configuration_ti, pinfo, "   %s",
                                 val_to_str_const(p_pdcp_info->bearerType, bearer_type_vals, "Unknown"));
    }

    if (p_pdcp_info->plane == NR_USER_PLANE) {
        /* Seqnum length */
        ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_seqnum_length, tvb, 0, 0,
                                 p_pdcp_info->seqnum_length);
        proto_item_set_generated(ti);

        /* ROHC compression */
        ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_rohc_compression, tvb, 0, 0,
                                    p_pdcp_info->rohc.rohc_compression);
        proto_item_set_generated(ti);

        /* ROHC-specific settings */
        if (p_pdcp_info->rohc.rohc_compression) {

            /* Show ROHC mode */
            ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_rohc_mode, tvb, 0, 0,
                                     p_pdcp_info->rohc.mode);
            proto_item_set_generated(ti);

            /* Show RND */
            ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_rohc_rnd, tvb, 0, 0,
                                        p_pdcp_info->rohc.rnd);
            proto_item_set_generated(ti);

            /* UDP Checksum */
            ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_rohc_udp_checksum_present, tvb, 0, 0,
                                        p_pdcp_info->rohc.udp_checksum_present);
            proto_item_set_generated(ti);

            /* ROHC profile */
            ti = proto_tree_add_uint(configuration_tree, hf_pdcp_nr_rohc_profile, tvb, 0, 0,
                                     p_pdcp_info->rohc.profile);
            proto_item_set_generated(ti);

            /* CID Inclusion Info */
            ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_cid_inclusion_info, tvb, 0, 0,
                                        p_pdcp_info->rohc.cid_inclusion_info);
            proto_item_set_generated(ti);

            /* Large CID */
            ti = proto_tree_add_boolean(configuration_tree, hf_pdcp_nr_large_cid_present, tvb, 0, 0,
                                        p_pdcp_info->rohc.large_cid_present);
            proto_item_set_generated(ti);
        }
    }

    /* Append summary to configuration root */
    proto_item_append_text(configuration_ti, "(direction=%s, plane=%s",
                           val_to_str_const(p_pdcp_info->direction, direction_vals, "Unknown"),
                           val_to_str_const(p_pdcp_info->plane, pdcp_plane_vals, "Unknown"));

    if (p_pdcp_info->rohc.rohc_compression) {
        const char *mode = val_to_str_const(p_pdcp_info->rohc.mode, rohc_mode_vals, "Error");
        proto_item_append_text(configuration_ti, ", mode=%c, profile=%s",
                               mode[0],
                               val_to_str_const(p_pdcp_info->rohc.profile, rohc_profile_vals, "Unknown"));
    }
    proto_item_append_text(configuration_ti, ")");
    proto_item_set_generated(configuration_ti);

    /* Show plane in info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s: ",
                    val_to_str_const(p_pdcp_info->plane, pdcp_plane_vals, "Unknown"));

}


/* Look for an RRC dissector for signalling data (using Bearer type and direction) */
static dissector_handle_t lookup_rrc_dissector_handle(struct pdcp_nr_info  *p_pdcp_info, guint32 data_length)
{
    dissector_handle_t rrc_handle = NULL;

    switch (p_pdcp_info->bearerType)
    {
        case Bearer_CCCH:
            if (p_pdcp_info->direction == PDCP_NR_DIRECTION_UPLINK) {
                rrc_handle = (data_length == 8) ? nr_rrc_ul_ccch1 : nr_rrc_ul_ccch;
            } else {
                rrc_handle = nr_rrc_dl_ccch;
            }
            break;
        case Bearer_PCCH:
            rrc_handle = nr_rrc_pcch;
            break;
        case Bearer_BCCH_BCH:
            rrc_handle = nr_rrc_bcch_bch;
            break;
        case Bearer_BCCH_DL_SCH:
            rrc_handle = nr_rrc_bcch_dl_sch;
            break;
        case Bearer_DCCH:
            if (p_pdcp_info->direction == PDCP_NR_DIRECTION_UPLINK) {
                rrc_handle = nr_rrc_ul_dcch;
            } else {
                rrc_handle = nr_rrc_dl_dcch;
            }
            break;

        default:
            break;
    }

    return rrc_handle;
}


/* Forwad declarations */
static int dissect_pdcp_nr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

static void report_heur_error(proto_tree *tree, packet_info *pinfo, expert_field *eiindex,
                              tvbuff_t *tvb, gint start, gint length)
{
    proto_item *ti;
    proto_tree *subtree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-NR");
    col_clear(pinfo->cinfo, COL_INFO);
    ti = proto_tree_add_item(tree, proto_pdcp_nr, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_pdcp);
    proto_tree_add_expert(subtree, pinfo, eiindex, tvb, start, length);
}

/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static gboolean dissect_pdcp_nr_heur(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, void *data _U_)
{
    gint                  offset                 = 0;
    struct pdcp_nr_info *p_pdcp_nr_info;
    tvbuff_t             *pdcp_tvb;
    guint8                tag                    = 0;
    gboolean              seqnumLengthTagPresent = FALSE;

    /* Needs to be at least as long as:
       - the signature string
       - fixed header byte(s)
       - tag for data
       - at least one byte of PDCP PDU payload.
      However, let attempted dissection show if there are any tags at all. */
    gint min_length = (gint)(strlen(PDCP_NR_START_STRING) + 3); /* signature */

    if (tvb_captured_length_remaining(tvb, offset) < min_length) {
        return FALSE;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, PDCP_NR_START_STRING, strlen(PDCP_NR_START_STRING)) != 0) {
        return FALSE;
    }
    offset += (gint)strlen(PDCP_NR_START_STRING);


    /* If redissecting, use previous info struct (if available) */
    p_pdcp_nr_info = (pdcp_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0);
    if (p_pdcp_nr_info == NULL) {
        /* Allocate new info struct for this frame */
        p_pdcp_nr_info = wmem_new0(wmem_file_scope(), pdcp_nr_info);

        /* Read fixed fields */
        p_pdcp_nr_info->plane = (enum pdcp_nr_plane)tvb_get_guint8(tvb, offset++);
        if (p_pdcp_nr_info->plane == NR_SIGNALING_PLANE) {
            /* Signalling plane always has 12 SN bits */
            p_pdcp_nr_info->seqnum_length = PDCP_NR_SN_LENGTH_12_BITS;
        }

        /* Read tagged fields */
        while (tag != PDCP_NR_PAYLOAD_TAG) {
            /* Process next tag */
            tag = tvb_get_guint8(tvb, offset++);
            switch (tag) {
                case PDCP_NR_SEQNUM_LENGTH_TAG:
                    p_pdcp_nr_info->seqnum_length = tvb_get_guint8(tvb, offset);
                    offset++;
                    seqnumLengthTagPresent = TRUE;
                    break;
                case PDCP_NR_DIRECTION_TAG:
                    p_pdcp_nr_info->direction = tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_NR_BEARER_TYPE_TAG:
                    p_pdcp_nr_info->bearerType = (NRBearerType)tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_NR_BEARER_ID_TAG:
                    p_pdcp_nr_info->bearerId = tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_NR_UEID_TAG:
                    p_pdcp_nr_info->ueid = tvb_get_ntohs(tvb, offset);
                    offset += 2;
                    break;
                case PDCP_NR_ROHC_COMPRESSION_TAG:
                    p_pdcp_nr_info->rohc.rohc_compression = TRUE;
                    break;
                case PDCP_NR_ROHC_IP_VERSION_TAG:
                    p_pdcp_nr_info->rohc.rohc_ip_version = tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_NR_ROHC_CID_INC_INFO_TAG:
                    p_pdcp_nr_info->rohc.cid_inclusion_info = TRUE;
                    break;
                case PDCP_NR_ROHC_LARGE_CID_PRES_TAG:
                    p_pdcp_nr_info->rohc.large_cid_present = TRUE;
                    break;
                case PDCP_NR_ROHC_MODE_TAG:
                    p_pdcp_nr_info->rohc.mode = (enum rohc_mode)tvb_get_guint8(tvb, offset);
                    offset++;
                    break;
                case PDCP_NR_ROHC_RND_TAG:
                    p_pdcp_nr_info->rohc.rnd = TRUE;
                    break;
                case PDCP_NR_ROHC_UDP_CHECKSUM_PRES_TAG:
                    p_pdcp_nr_info->rohc.udp_checksum_present = TRUE;
                    break;
                case PDCP_NR_ROHC_PROFILE_TAG:
                    p_pdcp_nr_info->rohc.profile = tvb_get_ntohs(tvb, offset);
                    offset += 2;
                    break;
                case PDCP_NR_MACI_PRES_TAG:
                    p_pdcp_nr_info->maci_present = TRUE;
                    break;
                case PDCP_NR_SDAP_HEADER_TAG:
                    p_pdcp_nr_info->sdap_header = tvb_get_guint8(tvb, offset) & 0x03;
                    offset++;
                    break;

                case PDCP_NR_PAYLOAD_TAG:
                    /* Have reached data, so get out of loop */
                    p_pdcp_nr_info->pdu_length = tvb_reported_length_remaining(tvb, offset);
                    continue;

                default:
                    /* It must be a recognised tag */
                    report_heur_error(tree, pinfo, &ei_pdcp_nr_unknown_udp_framing_tag, tvb, offset-1, 1);
                    wmem_free(wmem_file_scope(), p_pdcp_nr_info);
                    return TRUE;
            }
        }

        if ((p_pdcp_nr_info->plane == NR_USER_PLANE) && (seqnumLengthTagPresent == FALSE)) {
            /* Conditional field is not present */
            report_heur_error(tree, pinfo, &ei_pdcp_nr_missing_udp_framing_tag, tvb, 0, offset);
            wmem_free(wmem_file_scope(), p_pdcp_nr_info);
            return TRUE;
        }

        /* Store info in packet */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0, p_pdcp_nr_info);
    }
    else {
        offset = tvb_reported_length(tvb) - p_pdcp_nr_info->pdu_length;
    }

    /**************************************/
    /* OK, now dissect as PDCP nr         */

    /* Create tvb that starts at actual PDCP PDU */
    pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
    dissect_pdcp_nr(pdcp_tvb, pinfo, tree, data);
    return TRUE;
}


/******************************/
/* Main dissection function.  */
static int dissect_pdcp_nr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    const char           *mode;
    proto_tree           *pdcp_tree          = NULL;
    proto_item           *root_ti            = NULL;
    proto_item           *ti;
    gint                 offset              = 0;
    struct pdcp_nr_info  *p_pdcp_info;
    tvbuff_t             *rohc_tvb           = NULL;

    tvbuff_t *payload_tvb;

    /* Set protocol name. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PDCP-NR");

    /* Look for attached packet info! */
    p_pdcp_info = (struct pdcp_nr_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_nr, 0);
    /* Can't dissect anything without it... */
    if (p_pdcp_info == NULL) {
        if (!data) {
            return 0;
        }
        p_pdcp_info = (struct pdcp_nr_info *)data;
    }

    /* Don't want to overwrite the RLC Info column if configured not to */
    if ((global_pdcp_nr_layer_to_show == ShowRLCLayer) &&
        (p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_nr, 0) != NULL)) {

        col_set_writable(pinfo->cinfo, COL_INFO, FALSE);
    }
    else {
        /* TODO: won't help with multiple PDCP-or-traffic PDUs / frame... */
        col_clear(pinfo->cinfo, COL_INFO);
        col_set_writable(pinfo->cinfo, COL_INFO, TRUE);
    }

    /* Create pdcp tree. */
    if (tree) {
        root_ti = proto_tree_add_item(tree, proto_pdcp_nr, tvb, offset, -1, ENC_NA);
        pdcp_tree = proto_item_add_subtree(root_ti, ett_pdcp);
    }

    /* Set mode string */
    mode = val_to_str_const(p_pdcp_info->rohc.mode, rohc_mode_vals, "Error");

    /*****************************************************/
    /* Show configuration (attached packet) info in tree */
    if (pdcp_tree) {
        show_pdcp_config(pinfo, tvb, pdcp_tree, p_pdcp_info);
    }

    /* Show ROHC mode */
    if (p_pdcp_info->rohc.rohc_compression) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (mode=%c)", mode[0]);
    }


    /***********************************/
    /* Handle PDCP header              */

    guint32  seqnum = 0;
    gboolean seqnum_set = FALSE;

    guint8  first_byte = tvb_get_guint8(tvb, offset);

    /*****************************/
    /* Signalling plane messages */
    if (p_pdcp_info->plane == NR_SIGNALING_PLANE) {
        /* Always 12 bits SN */
        /* Verify 4 reserved bits are 0 */
        guint8 reserved = (first_byte & 0xf0) >> 4;
        ti = proto_tree_add_item(pdcp_tree, hf_pdcp_nr_control_plane_reserved,
                                 tvb, offset, 1, ENC_BIG_ENDIAN);
        if (reserved != 0) {
            expert_add_info_format(pinfo, ti, &ei_pdcp_nr_reserved_bits_not_zero,
                                   "PDCP signalling header reserved bits not zero");
        }

        /* 12-bit sequence number */
        proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_seq_num_12, tvb, offset, 2, ENC_BIG_ENDIAN, &seqnum);
        seqnum_set = TRUE;
        write_pdu_label_and_info(root_ti, pinfo, " (SN=%-4u)", seqnum);
        offset += 2;

        if (tvb_captured_length_remaining(tvb, offset) == 0) {
            /* Only PDCP header was captured, stop dissection here */
            return offset;
        }
    }
    else if (p_pdcp_info->plane == NR_USER_PLANE) {

        /**********************************/
        /* User-plane messages            */
        gboolean is_user_plane;

        /* Data/Control flag */
        proto_tree_add_item_ret_boolean(pdcp_tree, hf_pdcp_nr_data_control, tvb, offset, 1, ENC_BIG_ENDIAN, &is_user_plane);

        if (is_user_plane) {
            /*****************************/
            /* User-plane Data           */
            guint32 reserved_value;

            /* Number of sequence number bits depends upon config */
            switch (p_pdcp_info->seqnum_length) {
            case PDCP_NR_SN_LENGTH_12_BITS:
                /* 3 reserved bits */
                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_reserved3, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);

                /* Complain if not 0 */
                if (reserved_value != 0) {
                    expert_add_info_format(pinfo, ti, &ei_pdcp_nr_reserved_bits_not_zero,
                                           "Reserved bits have value 0x%x - should be 0x0",
                                           reserved_value);
                }

                /* 12-bit sequence number */
                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_seq_num_12, tvb, offset, 2, ENC_BIG_ENDIAN, &seqnum);
                seqnum_set = TRUE;
                offset += 2;
                break;
            case PDCP_NR_SN_LENGTH_18_BITS:
                /* 5 reserved bits */
                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_reserved5, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);

                /* Complain if not 0 */
                if (reserved_value != 0) {
                    expert_add_info_format(pinfo, ti, &ei_pdcp_nr_reserved_bits_not_zero,
                                           "Reserved bits have value 0x%x - should be 0x0",
                                           reserved_value);
                }

                /* 18-bit sequence number */
                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_seq_num_18, tvb, offset, 3, ENC_BIG_ENDIAN, &seqnum);
                seqnum_set = TRUE;
                offset += 3;
                break;
            default:
                /* Not a recognised data format!!!!! */
                return 1;
            }

            write_pdu_label_and_info(root_ti, pinfo, " (SN=%-6u)", seqnum);
        }
        else {
            /*******************************/
            /* User-plane Control messages */
            guint32 control_pdu_type;
            proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_control_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN, &control_pdu_type);

            switch (control_pdu_type) {
            case 0:    /* PDCP status report */
            {
                guint32 fmc;
                guint   not_received = 0;
                guint   i, j, l;
                guint32 len, bit_offset;
                proto_tree *bitmap_tree;
                proto_item *bitmap_ti = NULL;
                gchar  *buff = NULL;
#define BUFF_SIZE 89
                guint32 reserved_value;

                /* 4 bits reserved */
                ti = proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_reserved4, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved_value);

                /* Complain if not 0 */
                if (reserved_value != 0) {
                    expert_add_info_format(pinfo, ti, &ei_pdcp_nr_reserved_bits_not_zero,
                                           "Reserved bits have value 0x%x - should be 0x0",
                                           reserved_value);
                }
                offset++;

                /* First-Missing-Count */
                proto_tree_add_item_ret_uint(pdcp_tree, hf_pdcp_nr_fmc, tvb, offset, 4, ENC_BIG_ENDIAN, &fmc);
                offset += 4;


                /* Bitmap tree */
                if (tvb_reported_length_remaining(tvb, offset) > 0) {
                    bitmap_ti = proto_tree_add_item(pdcp_tree, hf_pdcp_nr_bitmap, tvb,
                                                    offset, -1, ENC_NA);
                    bitmap_tree = proto_item_add_subtree(bitmap_ti, ett_pdcp_report_bitmap);

                    buff = (gchar *)wmem_alloc(wmem_packet_scope(), BUFF_SIZE);
                    len = tvb_reported_length_remaining(tvb, offset);
                    bit_offset = offset<<3;

                    /* For each byte... */
                    for (i=0; i<len; i++) {
                        guint8 bits = tvb_get_bits8(tvb, bit_offset, 8);
                        for (l=0, j=0; l<8; l++) {
                            if ((bits << l) & 0x80) {
                                if (bitmap_tree) {
                                    // TODO: better to do mod and show as SN instead?
                                    j += g_snprintf(&buff[j], BUFF_SIZE-j, "%10u,", (unsigned)(fmc+(8*i)+l+1));
                                }
                            } else {
                                if (bitmap_tree) {
                                    j += (guint)g_strlcpy(&buff[j], "          ,", BUFF_SIZE-j);
                                }
                                not_received++;
                            }
                        }
                        if (bitmap_tree) {
                            proto_tree_add_uint_format(bitmap_tree, hf_pdcp_nr_bitmap_byte, tvb, bit_offset/8, 1, bits, "%s", buff);
                        }
                        bit_offset += 8;
                    }
                }

                if (bitmap_ti != NULL) {
                    proto_item_append_text(bitmap_ti, " (%u SNs not received)", not_received);
                }
                write_pdu_label_and_info(root_ti, pinfo, " Status Report (fmc=%u) not-received=%u",
                                         fmc, not_received);
            }
                return 1;

            case 1:     /* ROHC Feedback */
                offset++;
                break;  /* Drop-through to dissect feedback */
            }
        }
    }
    else {
        /* Invalid plane setting...! */
        write_pdu_label_and_info(root_ti, pinfo, " - INVALID PLANE (%u)",
                                 p_pdcp_info->plane);
        return 1;
    }

    /* Do sequence analysis if configured to. */
    if (seqnum_set) {
        gboolean do_analysis = FALSE;

        switch (global_pdcp_check_sequence_numbers) {
        case FALSE:
            break;
        case SEQUENCE_ANALYSIS_RLC_ONLY:
            if ((p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_nr, 0) != NULL) &&
                    !p_pdcp_info->is_retx) {
                do_analysis = TRUE;
            }
            break;
        case SEQUENCE_ANALYSIS_PDCP_ONLY:
            if (p_get_proto_data(wmem_file_scope(), pinfo, proto_rlc_nr, 0) == NULL) {
                do_analysis = TRUE;
            }
            break;
        }

        if (do_analysis) {
            checkBearerSequenceInfo(pinfo, tvb, p_pdcp_info,
                                     seqnum, pdcp_tree);
        }
    }


    /*******************************************************/
    /* Now deal with the payload                           */
    /*******************************************************/

    payload_tvb = tvb;

    if (p_pdcp_info->plane == NR_SIGNALING_PLANE) {
        guint32 data_length;

        /* Compute payload length (no MAC on common control Bearers) */
        data_length = tvb_reported_length_remaining(payload_tvb, offset)-4;


        /* RRC data is all but last 4 bytes.
           Call nr-rrc dissector (according to direction and Bearer type) if we have valid data */
        if (global_pdcp_dissect_signalling_plane_as_rrc) {
            /* Get appropriate dissector handle */
            dissector_handle_t rrc_handle = lookup_rrc_dissector_handle(p_pdcp_info, data_length);

            if (rrc_handle != NULL) {
                /* Call RRC dissector if have one */
                tvbuff_t *rrc_payload_tvb = tvb_new_subset_length(payload_tvb, offset, data_length);
                gboolean was_writable = col_get_writable(pinfo->cinfo, COL_INFO);

                /* We always want to see this in the info column */
                col_set_writable(pinfo->cinfo, COL_INFO, TRUE);

                call_dissector_only(rrc_handle, rrc_payload_tvb, pinfo, pdcp_tree, NULL);

                /* Restore to whatever it was */
                col_set_writable(pinfo->cinfo, COL_INFO, was_writable);
            }
            else {
                 /* Just show data */
                    proto_tree_add_item(pdcp_tree, hf_pdcp_nr_signalling_data, payload_tvb, offset,
                                        data_length, ENC_NA);
            }
        }
        else {
            /* Just show as unparsed data */
            proto_tree_add_item(pdcp_tree, hf_pdcp_nr_signalling_data, payload_tvb, offset,
                                data_length, ENC_NA);
        }

        if (p_pdcp_info->bearerType == Bearer_DCCH) {
            p_pdcp_info->maci_present = TRUE;
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%u bytes data)", data_length);
        }
    }
    else if (tvb_captured_length_remaining(payload_tvb, offset)) {
        /* User-plane payload here. */
        gint payload_length = tvb_reported_length_remaining(payload_tvb, offset) - ((p_pdcp_info->maci_present) ? 4 : 0);

        if ((p_pdcp_info->direction == PDCP_NR_DIRECTION_UPLINK &&
             p_pdcp_info->sdap_header & PDCP_NR_UL_SDAP_HEADER_PRESENT) ||
            (p_pdcp_info->direction == PDCP_NR_DIRECTION_DOWNLINK &&
             p_pdcp_info->sdap_header & PDCP_NR_DL_SDAP_HEADER_PRESENT)) {
            proto_item *sdap_ti;
            proto_tree *sdap_tree;

            sdap_ti = proto_tree_add_item(pdcp_tree, proto_sdap, payload_tvb, offset, 1, ENC_NA);
            sdap_tree = proto_item_add_subtree(sdap_ti, ett_sdap);
            if (p_pdcp_info->direction == PDCP_NR_DIRECTION_UPLINK) {
                proto_tree_add_item(sdap_tree, hf_sdap_data_control, payload_tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sdap_tree, hf_sdap_reserved, payload_tvb, offset, 1, ENC_NA);
            } else {
                proto_tree_add_item(sdap_tree, hf_sdap_rdi, payload_tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sdap_tree, hf_sdap_rqi, payload_tvb, offset, 1, ENC_NA);
            }
            proto_tree_add_item(sdap_tree, hf_sdap_qfi, payload_tvb, offset, 1, ENC_NA);
            offset++;
            payload_length--;
        }

        if (payload_length > 0) {
            /* If not compressed with ROHC, show as user-plane data */
            if (!p_pdcp_info->rohc.rohc_compression) {
                /* Not attempting to decode payload if ciphering is enabled
                  (and NULL ciphering is not being used) */
                if (global_pdcp_dissect_user_plane_as_ip) {
                    tvbuff_t *ip_payload_tvb = tvb_new_subset_length(payload_tvb, offset, payload_length);

                    /* Don't update info column for ROHC unless configured to */
                    if (global_pdcp_nr_layer_to_show != ShowTrafficLayer) {
                        col_set_writable(pinfo->cinfo, COL_INFO, FALSE);
                    }

                    switch (tvb_get_guint8(ip_payload_tvb, 0) & 0xf0) {
                        case 0x40:
                            call_dissector_only(ip_handle, ip_payload_tvb, pinfo, pdcp_tree, NULL);
                            break;
                        case 0x60:
                            call_dissector_only(ipv6_handle, ip_payload_tvb, pinfo, pdcp_tree, NULL);
                            break;
                        default:
                            call_data_dissector(ip_payload_tvb, pinfo, pdcp_tree);
                            break;
                    }

                    /* Freeze the columns again because we don't want other layers writing to info */
                    if (global_pdcp_nr_layer_to_show == ShowTrafficLayer) {
                        col_set_writable(pinfo->cinfo, COL_INFO, FALSE);
                    }

                }
                else {
                    proto_tree_add_item(pdcp_tree, hf_pdcp_nr_user_plane_data, payload_tvb, offset, payload_length, ENC_NA);
                }
            }
            else {
                /***************************/
                /* ROHC packets            */
                /***************************/

                /* Only attempt ROHC if configured to */
                if (!global_pdcp_dissect_rohc) {
                    col_append_fstr(pinfo->cinfo, COL_PROTOCOL, "|ROHC(%s)",
                                    val_to_str_const(p_pdcp_info->rohc.profile, rohc_profile_vals, "Unknown"));
                    proto_tree_add_item(pdcp_tree, hf_pdcp_nr_user_plane_data, payload_tvb, offset, payload_length, ENC_NA);
                }
                else {
                    rohc_tvb = tvb_new_subset_length(payload_tvb, offset, payload_length);

                    /* Only enable writing to column if configured to show ROHC */
                    if (global_pdcp_nr_layer_to_show != ShowTrafficLayer) {
                        col_set_writable(pinfo->cinfo, COL_INFO, FALSE);
                    }
                    else {
                        col_clear(pinfo->cinfo, COL_INFO);
                    }

                    /* Call the ROHC dissector */
                    call_dissector_with_data(rohc_handle, rohc_tvb, pinfo, tree, &p_pdcp_info->rohc);
                }
            }
        }
    }

    /* MAC */
    if (p_pdcp_info->maci_present) {
        /* Last 4 bytes are MAC */
        gint mac_offset = tvb_reported_length(tvb)-4;
        guint32 mac = tvb_get_ntohl(payload_tvb, mac_offset);
        proto_tree_add_item(pdcp_tree, hf_pdcp_nr_mac, payload_tvb, mac_offset, 4, ENC_BIG_ENDIAN);

        col_append_fstr(pinfo->cinfo, COL_INFO, " MAC=0x%08x", mac);
    }

    /* Let RLC write to columns again */
    col_set_writable(pinfo->cinfo, COL_INFO, global_pdcp_nr_layer_to_show == ShowRLCLayer);

    return tvb_captured_length(tvb);
}


void proto_register_pdcp_nr(void)
{
    static hf_register_info hf_pdcp[] =
    {
        { &hf_pdcp_nr_configuration,
            { "Configuration",
              "pdcp-nr.configuration", FT_STRING, BASE_NONE, NULL, 0x0,
              "Configuration info passed into dissector", HFILL
            }
        },
        { &hf_pdcp_nr_direction,
            { "Direction",
              "pdcp-nr.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_pdcp_nr_ueid,
            { "UE",
              "pdcp-nr.ueid", FT_UINT16, BASE_DEC, 0, 0x0,
              "UE Identifier", HFILL
            }
        },
        { &hf_pdcp_nr_bearer_type,
            { "Bearer type",
              "pdcp-nr.Bearer-type", FT_UINT8, BASE_DEC, VALS(bearer_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_bearer_id,
            { "Bearer Id",
              "pdcp-nr.bearer-id", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_plane,
            { "Plane",
              "pdcp-nr.plane", FT_UINT8, BASE_DEC, VALS(pdcp_plane_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_seqnum_length,
            { "Seqnum length",
              "pdcp-nr.seqnum_length", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Sequence Number Length", HFILL
            }
        },

        { &hf_pdcp_nr_rohc_compression,
            { "ROHC Compression",
              "pdcp-nr.rohc.compression", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_rohc_mode,
            { "ROHC Mode",
              "pdcp-nr.rohc.mode", FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_rohc_rnd,
            { "RND",
              "pdcp-nr.rohc.rnd", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              "RND of outer ip header", HFILL
            }
        },
        { &hf_pdcp_nr_rohc_udp_checksum_present,
            { "UDP Checksum",
              "pdcp-nr.rohc.checksum-present", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              "UDP Checksum present", HFILL
            }
        },
        { &hf_pdcp_nr_rohc_profile,
            { "ROHC profile",
              "pdcp-nr.rohc.profile", FT_UINT8, BASE_DEC, VALS(rohc_profile_vals), 0x0,
              "ROHC Mode", HFILL
            }
        },
        { &hf_pdcp_nr_cid_inclusion_info,
            { "CID Inclusion Info",
              "pdcp-nr.cid-inclusion-info", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_large_cid_present,
            { "Large CID Present",
              "pdcp-nr.large-cid-present", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_nr_control_plane_reserved,
            { "Reserved",
              "pdcp-nr.reserved", FT_UINT8, BASE_DEC, NULL, 0xf0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_reserved3,
            { "Reserved",
              "pdcp-nr.reserved3", FT_UINT8, BASE_HEX, NULL, 0x70,
              "3 reserved bits", HFILL
            }
        },
        { &hf_pdcp_nr_seq_num_12,
            { "Seq Num",
              "pdcp-nr.seq-num", FT_UINT16, BASE_DEC, NULL, 0x0fff,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_nr_reserved5,
            { "Reserved",
              "pdcp-nr.reserved5", FT_UINT8, BASE_HEX, NULL, 0x7c,
              "5 reserved bits", HFILL
            }
        },
        { &hf_pdcp_nr_seq_num_18,
            { "Seq Num",
              "pdcp-nr.seq-num", FT_UINT24, BASE_DEC, NULL, 0x3ffff,
              "PDCP Seq num", HFILL
            }
        },
        { &hf_pdcp_nr_signalling_data,
            { "Signalling Data",
              "pdcp-nr.signalling-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_mac,
            { "MAC",
              "pdcp-nr.mac", FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_data_control,
            { "PDU Type",
              "pdcp-nr.pdu-type", FT_BOOLEAN, 8, TFS(&pdu_type_bit), 0x80,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_user_plane_data,
            { "User-Plane Data",
              "pdcp-nr.user-data", FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_control_pdu_type,
            { "Control PDU Type",
              "pdcp-nr.control-pdu-type", FT_UINT8, BASE_HEX, VALS(control_pdu_type_vals), 0x70,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_fmc,
            { "First Missing Count",
              "pdcp-nr.fmc", FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_reserved4,
            { "Reserved",
              "pdcp-nr.reserved4", FT_UINT8, BASE_HEX, NULL, 0x0f,
              "4 reserved bits", HFILL
            }
        },
        { &hf_pdcp_nr_bitmap,
            { "Bitmap",
              "pdcp-nr.bitmap", FT_NONE, BASE_NONE, NULL, 0x0,
              "Status report bitmap (0=error, 1=OK)", HFILL
            }
        },
        { &hf_pdcp_nr_bitmap_byte,
            { "Bitmap byte",
              "pdcp-nr.bitmap.byte", FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL
            }
        },

        { &hf_pdcp_nr_sequence_analysis,
            { "Sequence Analysis",
              "pdcp-nr.sequence-analysis", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_ok,
            { "OK",
              "pdcp-nr.sequence-analysis.ok", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_previous_frame,
            { "Previous frame for Bearer",
              "pdcp-nr.sequence-analysis.previous-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_next_frame,
            { "Next frame for Bearer",
              "pdcp-nr.sequence-analysis.next-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_expected_sn,
            { "Expected SN",
              "pdcp-nr.sequence-analysis.expected-sn", FT_UINT32, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_skipped,
            { "Skipped frames",
              "pdcp-nr.sequence-analysis.skipped-frames", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_pdcp_nr_sequence_analysis_repeated,
            { "Repeated frame",
              "pdcp-nr.sequence-analysis.repeated-frame", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
    };

    static hf_register_info hf_sdap[] =
    {
        { &hf_sdap_rdi,
            { "RDI",
              "sdap.rdi", FT_BOOLEAN, 8, TFS(&sdap_rdi), 0x80,
              NULL, HFILL
            }
        },
        { &hf_sdap_rqi,
            { "RQI",
              "sdap.rqi", FT_BOOLEAN, 8, TFS(&sdap_rqi), 0x40,
              NULL, HFILL
            }
        },
        { &hf_sdap_qfi,
            { "QFI",
              "sdap.qfi", FT_UINT8, BASE_DEC, NULL, 0x3f,
              NULL, HFILL
            }
        },
        { &hf_sdap_data_control,
            { "PDU Type",
              "sdap.reserved", FT_BOOLEAN, 8, TFS(&pdu_type_bit), 0x80,
              NULL, HFILL
            }
        },
        { &hf_sdap_reserved,
            { "Reserved",
              "sdap.reserved", FT_UINT8, BASE_HEX, NULL, 0x40,
              NULL, HFILL
            }
        }
    };

    static gint *ett[] =
    {
        &ett_pdcp,
        &ett_pdcp_configuration,
        &ett_pdcp_packet,
        &ett_pdcp_nr_sequence_analysis,
        &ett_pdcp_report_bitmap,
        &ett_sdap
    };

    static ei_register_info ei[] = {
        { &ei_pdcp_nr_sequence_analysis_sn_missing, { "pdcp-nr.sequence-analysis.sn-missing", PI_SEQUENCE, PI_WARN, "PDCP SN missing", EXPFILL }},
        { &ei_pdcp_nr_sequence_analysis_sn_repeated, { "pdcp-nr.sequence-analysis.sn-repeated", PI_SEQUENCE, PI_WARN, "PDCP SN repeated", EXPFILL }},
        { &ei_pdcp_nr_sequence_analysis_wrong_sequence_number, { "pdcp-nr.sequence-analysis.wrong-sequence-number", PI_SEQUENCE, PI_WARN, "Wrong Sequence Number", EXPFILL }},
        { &ei_pdcp_nr_reserved_bits_not_zero, { "pdcp-nr.reserved-bits-not-zero", PI_MALFORMED, PI_ERROR, "Reserved bits not zero", EXPFILL }},
        { &ei_pdcp_nr_unknown_udp_framing_tag, { "pdcp-nr.unknown-udp-framing-tag", PI_UNDECODED, PI_WARN, "Unknown UDP framing tag, aborting dissection", EXPFILL }},
        { &ei_pdcp_nr_missing_udp_framing_tag, { "pdcp-nr.missing-udp-framing-tag", PI_UNDECODED, PI_WARN, "Missing UDP framing conditional tag, aborting dissection", EXPFILL }}
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

    module_t *pdcp_nr_module;
    expert_module_t* expert_pdcp_nr;

    /* Register protocol. */
    proto_pdcp_nr = proto_register_protocol("PDCP-NR", "PDCP-NR", "pdcp-nr");
    proto_register_field_array(proto_pdcp_nr, hf_pdcp, array_length(hf_pdcp));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pdcp_nr = expert_register_protocol(proto_pdcp_nr);
    expert_register_field_array(expert_pdcp_nr, ei, array_length(ei));
    proto_sdap = proto_register_protocol("SDAP", "SDAP", "sdap");
    proto_register_field_array(proto_sdap, hf_sdap, array_length(hf_sdap));

    /* Allow other dissectors to find this one by name. */
    register_dissector("pdcp-nr", dissect_pdcp_nr, proto_pdcp_nr);

    pdcp_nr_module = prefs_register_protocol(proto_pdcp_nr, NULL);

    /* Dissect uncompressed user-plane data as IP */
    prefs_register_bool_preference(pdcp_nr_module, "show_user_plane_as_ip",
        "Show uncompressed User-Plane data as IP",
        "Show uncompressed User-Plane data as IP",
        &global_pdcp_dissect_user_plane_as_ip);

    /* Dissect unciphered signalling data as RRC */
    prefs_register_bool_preference(pdcp_nr_module, "show_signalling_plane_as_rrc",
        "Show unciphered Signalling-Plane data as RRC",
        "Show unciphered Signalling-Plane data as RRC",
        &global_pdcp_dissect_signalling_plane_as_rrc);

    /* Check for missing sequence numbers */
    prefs_register_enum_preference(pdcp_nr_module, "check_sequence_numbers",
        "Do sequence number analysis",
        "Do sequence number analysis",
        &global_pdcp_check_sequence_numbers, sequence_analysis_vals, FALSE);

    /* Attempt to dissect ROHC messages */
    prefs_register_bool_preference(pdcp_nr_module, "dissect_rohc",
        "Attempt to decode ROHC data",
        "Attempt to decode ROHC data",
        &global_pdcp_dissect_rohc);

    prefs_register_obsolete_preference(pdcp_nr_module, "heuristic_pdcp_nr_over_udp");

    prefs_register_enum_preference(pdcp_nr_module, "layer_to_show",
        "Which layer info to show in Info column",
        "Can show RLC, PDCP or Traffic layer info in Info column",
        &global_pdcp_nr_layer_to_show, show_info_col_vals, FALSE);


    pdcp_sequence_analysis_bearer_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
    pdcp_nr_sequence_analysis_report_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), pdcp_result_hash_func, pdcp_result_hash_equal);
}

void proto_reg_handoff_pdcp_nr(void)
{
    /* Add as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_pdcp_nr_heur, "PDCP-NR over UDP", "pdcp_nr_udp", proto_pdcp_nr, HEURISTIC_DISABLE);

    ip_handle              = find_dissector_add_dependency("ip", proto_pdcp_nr);
    ipv6_handle            = find_dissector_add_dependency("ipv6", proto_pdcp_nr);
    rohc_handle            = find_dissector_add_dependency("rohc", proto_pdcp_nr);
    nr_rrc_ul_ccch         = find_dissector_add_dependency("nr-rrc.ul.ccch", proto_pdcp_nr);
    nr_rrc_ul_ccch1        = find_dissector_add_dependency("nr-rrc.ul.ccch1", proto_pdcp_nr);
    nr_rrc_dl_ccch         = find_dissector_add_dependency("nr-rrc.dl.ccch", proto_pdcp_nr);
    nr_rrc_pcch            = find_dissector_add_dependency("nr-rrc.pcch", proto_pdcp_nr);
    nr_rrc_bcch_bch        = find_dissector_add_dependency("nr-rrc.bcch.bch", proto_pdcp_nr);
    nr_rrc_bcch_dl_sch     = find_dissector_add_dependency("nr-rrc.bcch.dl.sch", proto_pdcp_nr);
    nr_rrc_ul_dcch         = find_dissector_add_dependency("nr-rrc.ul.dcch", proto_pdcp_nr);
    nr_rrc_dl_dcch         = find_dissector_add_dependency("nr-rrc.dl.dcch", proto_pdcp_nr);
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
