/* Routines for LTE MAC disassembly
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
#include <epan/tap.h>

#include "packet-mac-lte.h"


/* Described in:
 * 3GPP TS 36.321 Evolved Universal Terrestrial Radio Access (E-UTRA)
 *                Medium Access Control (MAC) protocol specification (Release 8)
 */


/* TODO:
   - TDD mode?
   - compare Msg3 with contention resolution body
   - add a preference so that padding can be verified against an expected pattern?
*/

/* Initialize the protocol and registered fields. */
int proto_mac_lte = -1;

static int mac_lte_tap = -1;

/* Decoding context */
static int hf_mac_lte_context_radio_type = -1;
static int hf_mac_lte_context_direction = -1;
static int hf_mac_lte_context_rnti = -1;
static int hf_mac_lte_context_rnti_type = -1;
static int hf_mac_lte_context_ueid = -1;
static int hf_mac_lte_context_subframe_number = -1;
static int hf_mac_lte_context_predefined_frame = -1;
static int hf_mac_lte_context_length = -1;
static int hf_mac_lte_context_bch_transport_channel = -1;
static int hf_mac_lte_context_retx_count = -1;
static int hf_mac_lte_context_crc_status = -1;

/* MAC SCH header fields */
static int hf_mac_lte_ulsch_header = -1;
static int hf_mac_lte_dlsch_header = -1;
static int hf_mac_lte_sch_subheader = -1;

static int hf_mac_lte_sch_reserved = -1;
static int hf_mac_lte_dlsch_lcid = -1;
static int hf_mac_lte_ulsch_lcid = -1;
static int hf_mac_lte_sch_extended = -1;
static int hf_mac_lte_sch_format = -1;
static int hf_mac_lte_sch_length = -1;

static int hf_mac_lte_sch_header_only = -1;

/* Data */
static int hf_mac_lte_sch_sdu = -1;
static int hf_mac_lte_bch_pdu = -1;
static int hf_mac_lte_pch_pdu = -1;
static int hf_mac_lte_predefined_pdu = -1;
static int hf_mac_lte_raw_pdu = -1;
static int hf_mac_lte_padding_data = -1;
static int hf_mac_lte_padding_length = -1;


/* RAR fields */
static int hf_mac_lte_rar = -1;
static int hf_mac_lte_rar_headers = -1;
static int hf_mac_lte_rar_header = -1;
static int hf_mac_lte_rar_extension = -1;
static int hf_mac_lte_rar_t = -1;
static int hf_mac_lte_rar_bi = -1;
static int hf_mac_lte_rar_rapid = -1;
static int hf_mac_lte_rar_reserved = -1;
static int hf_mac_lte_rar_body = -1;
static int hf_mac_lte_rar_reserved2 = -1;
static int hf_mac_lte_rar_ta = -1;
static int hf_mac_lte_rar_ul_grant = -1;
static int hf_mac_lte_rar_ul_grant_hopping = -1;
static int hf_mac_lte_rar_ul_grant_fsrba = -1;
static int hf_mac_lte_rar_ul_grant_tmcs = -1;
static int hf_mac_lte_rar_ul_grant_tcsp = -1;
static int hf_mac_lte_rar_ul_grant_ul_delay = -1;
static int hf_mac_lte_rar_ul_grant_cqi_request = -1;
static int hf_mac_lte_rar_temporary_crnti = -1;

/* Common channel control values */
static int hf_mac_lte_control_bsr = -1;
static int hf_mac_lte_control_bsr_lcg_id = -1;
static int hf_mac_lte_control_bsr_buffer_size = -1;
static int hf_mac_lte_control_bsr_buffer_size_1 = -1;
static int hf_mac_lte_control_bsr_buffer_size_2 = -1;
static int hf_mac_lte_control_bsr_buffer_size_3 = -1;
static int hf_mac_lte_control_bsr_buffer_size_4 = -1;
static int hf_mac_lte_control_crnti = -1;
static int hf_mac_lte_control_timing_advance = -1;
static int hf_mac_lte_control_ue_contention_resolution_identity = -1;
static int hf_mac_lte_control_power_headroom_reserved = -1;
static int hf_mac_lte_control_power_headroom = -1;
static int hf_mac_lte_control_padding = -1;


/* Subtrees. */
static int ett_mac_lte = -1;
static int ett_mac_lte_context = -1;
static int ett_mac_lte_ulsch_header = -1;
static int ett_mac_lte_dlsch_header = -1;
static int ett_mac_lte_sch_subheader = -1;
static int ett_mac_lte_rar_headers = -1;
static int ett_mac_lte_rar_header = -1;
static int ett_mac_lte_rar_body = -1;
static int ett_mac_lte_rar_ul_grant = -1;
static int ett_mac_lte_bsr = -1;
static int ett_mac_lte_bch = -1;
static int ett_mac_lte_pch = -1;



/* Constants and value strings */

static const value_string radio_type_vals[] =
{
    { FDD_RADIO,      "FDD"},
    { TDD_RADIO,      "TDD"},
    { 0, NULL }
};


static const value_string direction_vals[] =
{
    { DIRECTION_UPLINK,      "Uplink"},
    { DIRECTION_DOWNLINK,    "Downlink"},
    { 0, NULL }
};


static const value_string rnti_type_vals[] =
{
    { NO_RNTI,     "NO-RNTI"},
    { P_RNTI,      "P-RNTI"},
    { RA_RNTI,     "RA-RNTI"},
    { C_RNTI,      "C-RNTI"},
    { SI_RNTI,     "SI-RNTI"},
    { 0, NULL }
};

static const value_string bch_transport_channel_vals[] =
{
    { SI_RNTI,      "DL-SCH"},
    { NO_RNTI,      "BCH"},
    { 0, NULL }
};

static const value_string crc_status_vals[] =
{
    { 0,      "CRC Status Failed"},
    { 1,      "CRC Status OK"},
    { 0, NULL }
};



#define UE_CONTENTION_RESOLUTION_IDENTITY_LCID 0x1c
#define TIMING_ADVANCE_LCID                    0x1d
#define DRX_COMMAND_LCID                       0x1e
#define PADDING_LCID                           0x1f

static const value_string dlsch_lcid_vals[] =
{
    { 0,                                        "CCCH"},
    { 1,                                        "1"},
    { 2,                                        "2"},
    { 3,                                        "3"},
    { 4,                                        "4"},
    { 5,                                        "5"},
    { 6,                                        "6"},
    { 7,                                        "7"},
    { 8,                                        "8"},
    { 9,                                        "9"},
    { 10,                                       "10"},
    { UE_CONTENTION_RESOLUTION_IDENTITY_LCID,   "UE Contention Resolution Identity"},
    { TIMING_ADVANCE_LCID                   ,   "Timing Advance"},
    { DRX_COMMAND_LCID                      ,   "DRX Command"},
    { PADDING_LCID                          ,   "Padding" },
    { 0, NULL }
};

#define POWER_HEADROOM_REPORT_LCID    0x1a
#define CRNTI_LCID                    0x1b
#define TRUNCATED_BSR_LCID            0x1c
#define SHORT_BSR_LCID                0x1d
#define LONG_BSR_LCID                 0x1e

static const value_string ulsch_lcid_vals[] =
{
    { 0,                            "CCCH"},
    { 1,                            "1"},
    { 2,                            "2"},
    { 3,                            "3"},
    { 4,                            "4"},
    { 5,                            "5"},
    { 6,                            "6"},
    { 7,                            "7"},
    { 8,                            "8"},
    { 9,                            "9"},
    { 10,                           "10"},
    { POWER_HEADROOM_REPORT_LCID,   "Power Headroom Report"},
    { CRNTI_LCID,                   "C-RNTI"},
    { TRUNCATED_BSR_LCID,           "Truncated BSR"},
    { SHORT_BSR_LCID,               "Short BSR"},
    { LONG_BSR_LCID,                "Long BSR"},
    { PADDING_LCID,                 "Padding" },
    { 0, NULL }
};


static const value_string format_vals[] =
{
    { 0,      "Data length is < 128 bytes"},
    { 1,      "Data length is >= 128 bytes"},
    { 0, NULL }
};


static const value_string rar_type_vals[] =
{
    { 0,      "Backoff Indicator present"},
    { 1,      "RAPID present"},
    { 0, NULL }
};


static const value_string rar_bi_vals[] =
{
    { 0,      "0"},
    { 1,      "10"},
    { 2,      "20"},
    { 3,      "30"},
    { 4,      "40"},
    { 5,      "60"},
    { 6,      "80"},
    { 7,      "120"},
    { 8,      "160"},
    { 9,      "240"},
    { 10,     "320"},
    { 11,     "480"},
    { 12,     "960"},
    { 0, NULL }
};


static const value_string buffer_size_vals[] =
{
    { 0,      "BS = 0"},
    { 1,      "0   < BS <= 10"},
    { 2,      "10  < BS <= 12"},
    { 3,      "12  < BS <= 14"},
    { 4,      "14  < BS <= 17"},
    { 5,      "17  < BS <= 19"},
    { 6,      "19  < BS <= 22"},
    { 7,      "22  < BS <= 26"},
    { 8,      "26  < BS <= 31"},
    { 9,      "31  < BS <= 36"},
    { 10,     "36  < BS <= 42"},
    { 11,     "42  < BS <= 49"},
    { 12,     "49  < BS <= 57"},
    { 13,     "47  < BS <= 67"},
    { 14,     "67  < BS <= 78"},
    { 15,     "78  < BS <= 91"},
    { 16,     "91  < BS <= 107"},
    { 17,     "107 < BS <= 125"},
    { 18,     "125 < BS <= 146"},
    { 19,     "146 < BS <= 171"},
    { 20,     "171 < BS <= 200"},
    { 21,     "200 < BS <= 234"},
    { 22,     "234 < BS <= 274"},
    { 23,     "274 < BS <= 321"},
    { 24,     "321 < BS <= 376"},
    { 25,     "376 < BS <= 440"},
    { 26,     "440 < BS <= 515"},
    { 27,     "515 < BS <= 603"},
    { 28,     "603 < BS <= 706"},
    { 29,     "706 < BS <= 826"},
    { 30,     "826 < BS <= 967"},
    { 31,     "967  < BS <= 1132"},
    { 32,     "1132 < BS <= 1326"},
    { 33,     "1326 < BS <= 1552"},
    { 34,     "1552 < BS <= 1817"},
    { 35,     "1817 < BS <= 2127"},
    { 36,     "2127 < BS <= 2490"},
    { 37,     "2490 < BS <= 2915"},
    { 38,     "2915 < BS <= 3413"},
    { 39,     "3413 < BS <= 3995"},
    { 40,     "3995 < BS <= 4677"},
    { 41,     "4677 < BS <= 5476"},
    { 42,     "5476 < BS <= 6411"},
    { 43,     "6411 < BS <= 7505"},
    { 44,     "7505 < BS <= 8787"},
    { 45,     "8787 < BS <= 10276"},
    { 46,     "10287 < BS <= 12043"},
    { 47,     "12043 < BS <= 14099"},
    { 48,     "14099 < BS <= 16507"},
    { 49,     "16507 < BS <= 19325"},
    { 50,     "19325 < BS <= 22624"},
    { 51,     "22624 < BS <= 26487"},
    { 52,     "26487 < BS <= 31009"},
    { 53,     "31009 < BS <= 36304"},
    { 54,     "36304 < BS <= 42502"},
    { 55,     "42502 < BS <= 49759"},
    { 56,     "49759 < BS <= 58255"},
    { 57,     "58255 < BS <= 68201"},
    { 58,     "68201 < BS <= 79846"},
    { 59,     "79846 < BS <= 93479"},
    { 60,     "93479 < BS <= 109439"},
    { 61,     "109439 < BS <= 128125"},
    { 62,     "128125 < BS <= 150000"},
    { 63,     "BS > 150000"},
    { 0, NULL }
};

static const value_string header_only_vals[] =
{
    { 0,      "MAC PDU Headers and body present"},
    { 1,      "MAC PDU Headers only"},
    { 0, NULL }
};

static const value_string predefined_frame_vals[] =
{
    { 0,      "Real MAC PDU present - will dissect"},
    { 1,      "Predefined frame present - will not dissect"},
    { 0, NULL }
};


/* By default check and warn about reserved bits not being zero.
   December '08 spec says they should be ignored... */
static gboolean global_mac_lte_check_reserved_bits = TRUE;

/* If this PDU has been NACK'd (by HARQ) more than a certain number of times,
   we trigger an expert warning. */
static gint global_mac_lte_retx_counter_trigger = 3;

/* By default try to decode transparent data (BCH, PCH and CCCH) data using LTE RRC dissector */
static gboolean global_mac_lte_attempt_rrc_decode = TRUE;

/* Control whether decoding details of RAR UL grant or not */
static gboolean global_mac_lte_decode_rar_ul_grant = TRUE;

/* Whether should attempt to dissect frames failing CRC check */
static gboolean global_mac_lte_dissect_crc_failures = FALSE;

/* Forward declarations */
void proto_reg_handoff_mac_lte(void);
void dissect_mac_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/* Heuristic dissection */
static gboolean global_mac_lte_heur = FALSE;

static gboolean dissect_mac_lte_heur(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree)
{
    gint                 offset = 0;
    struct mac_lte_info  *p_mac_lte_info;
    tvbuff_t             *mac_tvb;
    guint8               tag = 0;
    gboolean             infoAlreadySet = FALSE;

    /* This is a heuristic dissector, which means we get all the UDP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */

    if (!global_mac_lte_heur) {
        return FALSE;
    }

    /* If redissecting, use previous info struct (if available) */
    p_mac_lte_info = p_get_proto_data(pinfo->fd, proto_mac_lte);
    if (p_mac_lte_info == NULL) {
        /* Allocate new info struct for this frame */
        p_mac_lte_info = se_alloc0(sizeof(struct mac_lte_info));
        if (p_mac_lte_info == NULL) {
            return FALSE;
        }
        infoAlreadySet = FALSE;
    }
    else {
        infoAlreadySet = TRUE;
    }

    /* Do this again on re-dissection to re-discover offset of actual PDU */
    
    /* Needs to be at least as long as:
       - the signature string
       - fixed header bytes
       - tag for data
       - at least one byte of MAC PDU payload */
    if ((size_t)tvb_length_remaining(tvb, offset) < (strlen(MAC_LTE_START_STRING)+3+2)) {
        return FALSE;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, MAC_LTE_START_STRING, (gint)strlen(MAC_LTE_START_STRING)) != 0) {
        return FALSE;
    }
    offset += (gint)strlen(MAC_LTE_START_STRING);

    /* Read fixed fields */
    p_mac_lte_info->radioType = tvb_get_guint8(tvb, offset++);
    p_mac_lte_info->direction = tvb_get_guint8(tvb, offset++);
    p_mac_lte_info->rntiType = tvb_get_guint8(tvb, offset++);

    /* Read optional fields */
    while (tag != MAC_LTE_PAYLOAD_TAG) {
        /* Process next tag */
        tag = tvb_get_guint8(tvb, offset++);
        switch (tag) {
            case MAC_LTE_RNTI_TAG:
                p_mac_lte_info->rnti = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case MAC_LTE_UEID_TAG:
                p_mac_lte_info->ueid = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case MAC_LTE_SUBFRAME_TAG:
                p_mac_lte_info->subframeNumber = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case MAC_LTE_PREDFINED_DATA_TAG:
                p_mac_lte_info->isPredefinedData = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_RETX_TAG:
                p_mac_lte_info->reTxCount = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_CRC_STATUS_TAG:
                p_mac_lte_info->crcStatusValid = TRUE;
                p_mac_lte_info->crcStatus = tvb_get_guint8(tvb, offset);
                offset++;
                break;

            case MAC_LTE_PAYLOAD_TAG:
                /* Have reached data, so set payload length and get out of loop */
                p_mac_lte_info->length= tvb_length_remaining(tvb, offset);
                continue;

            default:
                /* It must be a recognised tag */
                return FALSE;
        }

        if (!infoAlreadySet) {
            /* Store info in packet */
            p_add_proto_data(pinfo->fd, proto_mac_lte, p_mac_lte_info);
        }
    }


    /**************************************/
    /* OK, now dissect as MAC LTE         */

    /* Create tvb that starts at actual MAC PDU */
    mac_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb)-offset);
    dissect_mac_lte(mac_tvb, pinfo, tree);
    return TRUE;
}

/* Dissect a single Random Access Reponse body */
static gint dissect_rar_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              gint offset, guint8 rapid)
{
    guint8 reserved;
    guint start_body_offset = offset;
    proto_item *ti;
    proto_item *rar_body_ti;
    proto_tree *rar_body_tree;
    proto_item *ul_grant_ti;
    guint16 timing_advance;
    guint32 ul_grant;
    guint16 temp_crnti;

    /* Create tree for this Body */
    rar_body_ti = proto_tree_add_item(tree,
                                      hf_mac_lte_rar_body,
                                      tvb, offset, 0, FALSE);
    rar_body_tree = proto_item_add_subtree(rar_body_ti, ett_mac_lte_rar_body);

    /* Dissect an RAR entry */

    /* Check reserved bit */
    reserved = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;
    ti = proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_reserved2, tvb, offset, 1, FALSE);
    if (global_mac_lte_check_reserved_bits && (reserved != 0)) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                      "MAC RAR header Reserved bit not zero (found 0x%x)", reserved);
    }

    /* Timing Advance */
    timing_advance = (tvb_get_ntohs(tvb, offset) & 0x7ff0) >> 4;
    proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_ta, tvb, offset, 2, FALSE);
    offset++;

    /* UL Grant */
    ul_grant = (tvb_get_ntohl(tvb, offset) & 0x0fffff00) >> 8;
    ul_grant_ti = proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_ul_grant, tvb, offset, 3, FALSE);

    /* Break these 20 bits down as described in 36.213, section 6.2 */
    if (global_mac_lte_decode_rar_ul_grant) {
        /* Create subtree for UL grant break-down */
        proto_tree *ul_grant_tree = proto_item_add_subtree(ul_grant_ti, ett_mac_lte_rar_ul_grant);

        /* Hopping flag (1 bit) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_hopping,
                            tvb, offset, 1, FALSE);

        /* Fixed sized resource block assignment (10 bits) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_fsrba,
                            tvb, offset, 2, FALSE);

        /* Truncated Modulation and coding scheme (4 bits) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_tmcs,
                            tvb, offset+1, 2, FALSE);

        /* TPC command for scheduled PUSCH (3 bits) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_tcsp,
                            tvb, offset+2, 1, FALSE);

        /* UL delay (1 bit) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_ul_delay,
                            tvb, offset+2, 1, FALSE);

        /* CQI request (1 bit) */
        proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_cqi_request,
                            tvb, offset+2, 1, FALSE);
    }

    offset += 3;

    /* Temporary C-RNTI */
    temp_crnti = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_temporary_crnti, tvb, offset, 2, FALSE);
    offset += 2;

    proto_item_append_text(rar_body_ti, " RAPID=%u (TA=%u, UL-Grant=%u, Temp C-RNTI=%u)",
                           rapid, timing_advance, ul_grant, temp_crnti);

    col_append_fstr(pinfo->cinfo, COL_INFO, "(RAPID=%u: TA=%u, UL-Grant=%u, Temp C-RNTI=%u) ",
                    rapid, timing_advance, ul_grant, temp_crnti);

    proto_item_set_len(rar_body_ti, offset-start_body_offset);

    return offset;
}


/* Dissect Random Access Reponse (RAR) PDU */
static void dissect_rar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        gint offset, mac_lte_info *p_mac_lte_info, mac_lte_tap_info *tap_info)
{
    gint     number_of_rars = 0;   /* No of RAR bodies expected following headers */
    guint8   rapids[64];
    gboolean backoff_indicator_seen = FALSE;
    guint8   extension;
    gint     n;
    proto_tree *rar_headers_tree;
    proto_item *ti;
    proto_item *rar_headers_ti;
    int        start_headers_offset = offset;

    col_append_fstr(pinfo->cinfo, COL_INFO, "RAR (RA-RNTI=%u, SF=%u) ",
                    p_mac_lte_info->rnti, p_mac_lte_info->subframeNumber);

    /* Create hidden 'virtual root' so can filter on mac-lte.rar */
    ti = proto_tree_add_item(tree, hf_mac_lte_rar, tvb, offset, -1, FALSE);
    PROTO_ITEM_SET_HIDDEN(ti);

    /* Create headers tree */
    rar_headers_ti = proto_tree_add_item(tree,
                                         hf_mac_lte_rar_headers,
                                         tvb, offset, 0, FALSE);
    rar_headers_tree = proto_item_add_subtree(rar_headers_ti, ett_mac_lte_rar_headers);


    /***************************/
    /* Read the header entries */
    do {
        int start_header_offset = offset;
        proto_tree *rar_header_tree;
        proto_item *rar_header_ti;
        guint8 type_value;
        guint8 first_byte = tvb_get_guint8(tvb, offset);

        /* Create tree for this header */
        rar_header_ti = proto_tree_add_item(rar_headers_tree,
                                            hf_mac_lte_rar_header,
                                            tvb, offset, 0, FALSE);
        rar_header_tree = proto_item_add_subtree(rar_header_ti, ett_mac_lte_rar_header);

        /* Extension */
        extension = (first_byte & 0x80) >> 7;
        proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_extension, tvb, offset, 1, FALSE);

        /* Type */
        type_value = (first_byte & 0x40) >> 6;
        proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_t, tvb, offset, 1, FALSE);

        if (type_value == 0) {
            /* Backoff Indicator (BI) case */

            guint8 reserved;
            guint8 backoff_indicator;
            proto_item *ti;
            proto_item *bi_ti;

            /* 2 Reserved bits */
            reserved = (tvb_get_guint8(tvb, offset) & 0x30) >> 4;
            ti = proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_reserved, tvb, offset, 1, FALSE);
            if (global_mac_lte_check_reserved_bits && (reserved != 0)) {
                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                       "MAC RAR header Reserved bits not zero (found 0x%x)", reserved);
            }

            /* Backoff Indicator */
            backoff_indicator = tvb_get_guint8(tvb, offset) & 0x0f;
            bi_ti = proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_bi, tvb, offset, 1, FALSE);

            /* As of March 2009 spec, it must be first, and may only appear once */
            if (backoff_indicator_seen) {
                expert_add_info_format(pinfo, bi_ti, PI_MALFORMED, PI_ERROR,
                                       "MAC RAR PDU has > 1 Backoff Indicator subheader present");
            }
            backoff_indicator_seen = TRUE;

            proto_item_append_text(rar_header_ti, "(Backoff Indicator=%sms)",
                                   val_to_str(backoff_indicator, rar_bi_vals, "Illegal-value "));

            col_append_fstr(pinfo->cinfo, COL_INFO, "(Backoff Indicator=%s ms) ",
                            val_to_str(backoff_indicator, rar_bi_vals, "Illegal-value"));

            /* If present, it must be the first subheader */
            if (number_of_rars > 0) {
                expert_add_info_format(pinfo, bi_ti, PI_MALFORMED, PI_WARN,
                                       "Backoff Indicator must appear as first subheader");
            }

        }
        else {
            /* RAPID case */
            rapids[number_of_rars] = tvb_get_guint8(tvb, offset) & 0x3f;
            proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_rapid, tvb, offset, 1, FALSE);

            proto_item_append_text(rar_header_ti, "(RAPID=%u)", rapids[number_of_rars]);

            number_of_rars++;
        }

        offset++;

        /* Finalise length of header tree selection */
        proto_item_set_len(rar_header_ti, offset - start_header_offset);

    } while (extension);

    /* Append summary to headers root */
    proto_item_append_text(rar_headers_ti, " (%u RARs%s)",
                           number_of_rars,
                           backoff_indicator_seen ? ", BI" : "");

    /* Set length for headers root */
    proto_item_set_len(rar_headers_ti, offset-start_headers_offset);


    /***************************/
    /* Read any indicated RARs */
    for (n=0; n < number_of_rars; n++) {
        offset = dissect_rar_entry(tvb, pinfo, tree, offset, rapids[n]);
    }

    /* Update TAP info */
    tap_info->number_of_rars += number_of_rars;

    /* Warn if we don't seem to have reached the end of the frame yet */
    if (tvb_length_remaining(tvb, offset) != 0) {
           expert_add_info_format(pinfo, rar_headers_ti, PI_MALFORMED, PI_ERROR,
                                  "%u bytes remaining after RAR PDU dissected",
                                  tvb_length_remaining(tvb, offset));
    }
}


/* Dissect BCH PDU */
static void dissect_bch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        int offset, mac_lte_info *p_mac_lte_info)
{
    proto_item *ti;

    col_append_fstr(pinfo->cinfo, COL_INFO, "BCH PDU (%u bytes, on %s transport)  ",
                    tvb_length_remaining(tvb, offset),
                    val_to_str(p_mac_lte_info->rntiType,
                               bch_transport_channel_vals,
                               "Unknown"));

    /* Show which transport layer it came in on (inferred from RNTI type) */
    ti = proto_tree_add_uint(tree, hf_mac_lte_context_bch_transport_channel,
                             tvb, offset, 0, p_mac_lte_info->rntiType);
    PROTO_ITEM_SET_GENERATED(ti);

    /****************************************/
    /* Whole frame is BCH data              */

    /* Raw data */
    ti = proto_tree_add_item(tree, hf_mac_lte_bch_pdu,
                             tvb, offset, -1, FALSE);

    if (global_mac_lte_attempt_rrc_decode) {
        /* Attempt to decode payload using LTE RRC dissector */
        tvbuff_t *rrc_tvb = tvb_new_subset(tvb, offset, -1, tvb_length_remaining(tvb, offset));

        /* Get appropriate dissector handle */
        dissector_handle_t protocol_handle = 0;
        if (p_mac_lte_info->rntiType == SI_RNTI) {
            protocol_handle = find_dissector("lte-rrc.bcch.dl.sch");
        }
        else {
            protocol_handle = find_dissector("lte-rrc.bcch.bch");
        }

        /* Hide raw view of bytes */
        PROTO_ITEM_SET_HIDDEN(ti);

        /* Call it (catch exceptions so that stats will be updated) */
        /* TODO: couldn't avoid warnings for 'ti' by using volatile
                 (with gcc 3.4.6)                                   */
/*        TRY {                                                         */
            call_dissector_only(protocol_handle, rrc_tvb, pinfo, tree);
/*        }                                                             */
/*        CATCH_ALL {                                                   */
/*        }                                                             */
/*        ENDTRY                                                        */
    }

    /* Check that this *is* downlink! */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "BCH data should not be received in Uplink!");
    }
}


/* Dissect PCH PDU */
static void dissect_pch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        int offset, guint8 direction)
{
    proto_item *ti;

    col_append_fstr(pinfo->cinfo, COL_INFO, "PCH PDU (%u bytes)  ",
                    tvb_length_remaining(tvb, offset));

    /****************************************/
    /* Whole frame is PCH data              */

    /* Always show as raw data */
    ti = proto_tree_add_item(tree, hf_mac_lte_pch_pdu,
                             tvb, offset, -1, FALSE);

    if (global_mac_lte_attempt_rrc_decode) {

        /* Attempt to decode payload using LTE RRC dissector */
        tvbuff_t *rrc_tvb = tvb_new_subset(tvb, offset, -1, tvb_length_remaining(tvb, offset));

        /* Get appropriate dissector handle */
        dissector_handle_t protocol_handle = find_dissector("lte-rrc.pcch");

        /* Hide raw view of bytes */
        PROTO_ITEM_SET_HIDDEN(ti);

        /* Call it (catch exceptions so that stats will be updated) */
        TRY {
            call_dissector_only(protocol_handle, rrc_tvb, pinfo, tree);
        }
        CATCH_ALL {
        }
        ENDTRY
    }

    /* Check that this *is* downlink! */
    if (direction == DIRECTION_UPLINK) {
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "PCH data should not be received in Uplink!");
    }
}


/* Does this header entry correspond to a fixed-sized control element? */
static int is_fixed_sized_control_element(guint8 lcid, guint8 direction)
{
    if (direction == DIRECTION_UPLINK) {
        /* Uplink */
        switch (lcid) {
            case POWER_HEADROOM_REPORT_LCID:
            case CRNTI_LCID:
            case TRUNCATED_BSR_LCID:
            case SHORT_BSR_LCID:
            case LONG_BSR_LCID:
                return TRUE;

            default:
                return FALSE;
        }
    }
    else {
        /* Assume Downlink */
        switch (lcid) {
            case UE_CONTENTION_RESOLUTION_IDENTITY_LCID:
            case TIMING_ADVANCE_LCID:
            case DRX_COMMAND_LCID:
                return TRUE;

            default:
                return FALSE;
        }
    }
}


/* Is this a BSR report header? */
static int is_bsr_lcid(guint8 lcid)
{
    return ((lcid == TRUNCATED_BSR_LCID) ||
            (lcid == SHORT_BSR_LCID) ||
            (lcid == LONG_BSR_LCID));
}


#define MAX_HEADERS_IN_PDU 1024

/* UL-SCH and DL-SCH formats have much in common, so handle them in a common
   function */
static void dissect_ulsch_or_dlsch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   volatile int offset, guint8 direction,
                                   mac_lte_info *p_mac_lte_info, mac_lte_tap_info *tap_info)
{
    guint8          extension;
    volatile guint8 n;
    proto_item      *truncated_ti;
    proto_item      *padding_length_ti;

    /* Keep track of LCIDs and lengths as we dissect the header */
    volatile guint8 number_of_headers = 0;
    guint8  lcids[MAX_HEADERS_IN_PDU];
    gint16  pdu_lengths[MAX_HEADERS_IN_PDU];

    proto_item *pdu_header_ti;
    proto_tree *pdu_header_tree;

    gboolean   have_seen_data_header = FALSE;
    gboolean   have_seen_bsr = FALSE;
    gboolean   expecting_body_data = FALSE;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s: (SF=%u) ",
                    (direction == DIRECTION_UPLINK) ? "UL-SCH" : "DL-SCH",
                    p_mac_lte_info->subframeNumber);

    /* Add PDU block header subtree */
    pdu_header_ti = proto_tree_add_string_format(tree,
                                                 (direction == DIRECTION_UPLINK) ?
                                                    hf_mac_lte_ulsch_header :
                                                    hf_mac_lte_dlsch_header,
                                                 tvb, offset, 0,
                                                 "",
                                                 "MAC PDU Header");
    pdu_header_tree = proto_item_add_subtree(pdu_header_ti,
                                             (direction == DIRECTION_UPLINK) ?
                                                    ett_mac_lte_ulsch_header :
                                                    ett_mac_lte_dlsch_header);


    /************************************************************************/
    /* Dissect each sub-header.                                             */
    do {
        guint8 reserved;
        guint64 length = 0;
        proto_item *pdu_subheader_ti;
        proto_tree *pdu_subheader_tree;
        proto_item *lcid_ti;
        proto_item *ti;
        gint       offset_start_subheader = offset;
        guint8 first_byte = tvb_get_guint8(tvb, offset);

        /* Add PDU block header subtree */
        pdu_subheader_ti = proto_tree_add_string_format(pdu_header_tree,
                                                        hf_mac_lte_sch_subheader,
                                                        tvb, offset, 0,
                                                        "",
                                                        "Sub-header");
        pdu_subheader_tree = proto_item_add_subtree(pdu_subheader_ti,
                                                    ett_mac_lte_sch_subheader);

        /* Check 1st 2 reserved bits */
        reserved = (first_byte & 0xc0) >> 6;
        ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_reserved,
                                 tvb, offset, 1, FALSE);
        if (global_mac_lte_check_reserved_bits && (reserved != 0)) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                   "MAC U/DL-SCH header Reserved bits not zero");
        }

        /* Extended bit */
        extension = (first_byte & 0x20) >> 5;
        proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_extended,
                            tvb, offset, 1, FALSE);

        /* LCID.  Has different meaning depending upon direction. */
        lcids[number_of_headers] = first_byte & 0x1f;
        if (direction == DIRECTION_UPLINK) {
            lcid_ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_ulsch_lcid,
                                          tvb, offset, 1, FALSE);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%s",
                            val_to_str(lcids[number_of_headers],
                                       ulsch_lcid_vals, "(Unknown LCID)"));
        }
        else {
            lcid_ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_dlsch_lcid,
                                          tvb, offset, 1, FALSE);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%s",
                            val_to_str(lcids[number_of_headers],
                                       dlsch_lcid_vals, "(Unknown LCID)"));
        }
        offset++;

        /* Remember if we've seen a data subheader */
        if (lcids[number_of_headers] <= 10) {
            have_seen_data_header = TRUE;
            expecting_body_data = TRUE;
        }

        /* Show an expert item if a contol subheader (except Padding) appears
           *after* a data PDU */
        if (have_seen_data_header &&
            (lcids[number_of_headers] > 10) && (lcids[number_of_headers] != PADDING_LCID)) {
            expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_ERROR,
                                   "Control subheaders should not appear after data subheaders");
        }

        /* Show an expert item if we're seeing more then one BSR in a frame */
        if ((direction == DIRECTION_UPLINK) && is_bsr_lcid(lcids[number_of_headers])) {
            if (have_seen_bsr) {
                expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_ERROR,
                                      "There shouldn't be > 1 BSR in a frame");
            }
            have_seen_bsr = TRUE;
        }


        /********************************************************************/
        /* Length field follows if not the last header or for a fixed-sized
           control element */
        if (!extension) {
            if (is_fixed_sized_control_element(lcids[number_of_headers], direction)) {
                pdu_lengths[number_of_headers] = 0;
            }
            else {
                pdu_lengths[number_of_headers] = -1;
            }
        }
        else {
            if (!is_fixed_sized_control_element(lcids[number_of_headers], direction) &&
                (lcids[number_of_headers] != PADDING_LCID)) {

                guint8  format;

                /* F(ormat) bit tells us how long the length field is */
                format = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;
                proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_format,
                                    tvb, offset, 1, FALSE);

                /* Now read length field itself */
                if (format) {
                    /* >= 128 - use 15 bits */
                    proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_sch_length,
                                                tvb, offset*8 + 1, 15, &length, FALSE);

                    offset += 2;
                }
                else {
                    /* Less than 128 - only 7 bits */
                    proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_sch_length,
                                                tvb, offset*8 + 1, 7, &length, FALSE);
                    offset++;
                }
                pdu_lengths[number_of_headers] = (gint16)length;
            }
            else {
                pdu_lengths[number_of_headers] = 0;
            }
        }


        /* Close off description in info column */
        switch (pdu_lengths[number_of_headers]) {
            case 0:
                col_append_str(pinfo->cinfo, COL_INFO, ") ");
                break;
            case -1:
                col_append_str(pinfo->cinfo, COL_INFO, ":remainder) ");
                break;
            default:
                col_append_fstr(pinfo->cinfo, COL_INFO, ":%u bytes) ",
                                pdu_lengths[number_of_headers]);
                break;
        }

        /* Append summary to subheader root */
        proto_item_append_text(pdu_subheader_ti, " (lcid=%s",
                               val_to_str(lcids[number_of_headers],
                                          (direction == DIRECTION_UPLINK) ?
                                              ulsch_lcid_vals :
                                              dlsch_lcid_vals,
                                          "Unknown"));

        switch (pdu_lengths[number_of_headers]) {
            case -1:
                proto_item_append_text(pdu_subheader_ti, ", length is remainder)");
                break;
            case 0:
                proto_item_append_text(pdu_subheader_ti, ")");
                break;
            default:
                proto_item_append_text(pdu_subheader_ti, ", length=%u)",
                                       pdu_lengths[number_of_headers]);
                break;
        }


        /* Flag unknown lcid values in expert info */
        if (strncmp(val_to_str(lcids[number_of_headers],
                               (direction == DIRECTION_UPLINK) ? ulsch_lcid_vals : dlsch_lcid_vals,
                               "Unknown"),
                    "Unknown",
                    sizeof("Unknown")) == 0) {
            expert_add_info_format(pinfo, pdu_subheader_ti, PI_MALFORMED, PI_ERROR,
                                       "Unexpected LCID received (%u)", lcids[number_of_headers]);
        }

        /* Set length of this subheader */
        proto_item_set_len(pdu_subheader_ti, offset- offset_start_subheader);

        number_of_headers++;
    } while (extension);

    /* Append summary to overall PDU header root */
    proto_item_append_text(pdu_header_ti, " (%u subheaders)",
                           number_of_headers);

    /* And set its length to offset */
    proto_item_set_len(pdu_header_ti, offset);


    /* TODO: some valid PDUs don't have any bodies, so don't want expert info.
       Use expecting_body_data to track this */

    /* There might not be any data, if only headers were logged */
    truncated_ti = proto_tree_add_uint(tree, hf_mac_lte_sch_header_only, tvb, 0, 0,
                                       tvb_length_remaining(tvb, offset) == 0);
    if (tvb_length_remaining(tvb, offset) == 0) {
        PROTO_ITEM_SET_GENERATED(truncated_ti);
        expert_add_info_format(pinfo, truncated_ti, PI_SEQUENCE, PI_NOTE,
                               "MAC PDU SDUs have been ommitted");
        return;
    }
    else {
        PROTO_ITEM_SET_HIDDEN(truncated_ti);
    }


    /************************************************************************/
    /* Dissect SDUs / control elements / padding.                           */
    /************************************************************************/

    for (n=0; n < number_of_headers; n++) {

        /* Data SDUs treated identically for Uplink or downlink channels */
        if (lcids[n] <= 10) {
            proto_item *sdu_ti;
            volatile guint16 data_length = (pdu_lengths[n] == -1) ?
                                                tvb_length_remaining(tvb, offset) :
                                                pdu_lengths[n];

            /* Dissect SDU */
            sdu_ti = proto_tree_add_bytes_format(tree, hf_mac_lte_sch_sdu, tvb, offset, pdu_lengths[n],
                                                 tvb_get_ptr(tvb, offset, pdu_lengths[n]),
                                                 "SDU (%s, length=%u bytes)",
                                                 val_to_str(lcids[n],
                                                            (direction == DIRECTION_UPLINK) ?
                                                                ulsch_lcid_vals :
                                                                dlsch_lcid_vals,
                                                            "Unknown"),
                                                 data_length);

            /* CCCH frames can be dissected directly by LTE RRC... */
            if ((lcids[n] == 0) && global_mac_lte_attempt_rrc_decode) {
                tvbuff_t *rrc_tvb = tvb_new_subset(tvb, offset, data_length, data_length);

                /* Get appropriate dissector handle */
                volatile dissector_handle_t protocol_handle = 0;
                if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
                    protocol_handle = find_dissector("lte-rrc.ul.ccch");
                }
                else {
                    protocol_handle = find_dissector("lte-rrc.dl.ccch");
                }

                /* Hide raw view of bytes */
                PROTO_ITEM_SET_HIDDEN(sdu_ti);

                /* Call it (catch exceptions so that stats will be updated) */
                TRY {
                    call_dissector_only(protocol_handle, rrc_tvb, pinfo, tree);
                }
                CATCH_ALL {
                }
                ENDTRY
            }

            offset += data_length;

            /* Update tap byte count for this channel */
            tap_info->bytes_for_lcid[lcids[n]] += data_length;
            tap_info->sdus_for_lcid[lcids[n]]++;
        }
        else {
            /* See if its a control PDU type */
            if (direction == DIRECTION_DOWNLINK) {

                /****************************/
                /* DL-SCH Control PDUs      */
                switch (lcids[n]) {
                    case UE_CONTENTION_RESOLUTION_IDENTITY_LCID:
                        proto_tree_add_item(tree, hf_mac_lte_control_ue_contention_resolution_identity,
                                            tvb, offset, 6, FALSE);
                        offset += 6;
                        break;
                    case TIMING_ADVANCE_LCID:
                        /* TODO: check 2 reserved bits? */
                        proto_tree_add_item(tree, hf_mac_lte_control_timing_advance,
                                            tvb, offset, 1, FALSE);
                        offset++;
                        break;
                    case DRX_COMMAND_LCID:
                        /* No payload */
                        break;
                    case PADDING_LCID:
                        /* No payload, unless its the last subheader, in which case
                           it extends to the end of the PDU */
                        if (n == (number_of_headers-1)) {
                            if (tvb_length_remaining(tvb, offset) > 0) {
                                proto_tree_add_item(tree, hf_mac_lte_padding_data,
                                                    tvb, offset, -1, FALSE);
                            }
                            padding_length_ti = proto_tree_add_int(tree, hf_mac_lte_padding_length,
                                                                   tvb, offset, 0,
                                                                   p_mac_lte_info->length - offset);
                            PROTO_ITEM_SET_GENERATED(padding_length_ti);

                            /* Make sure the PDU isn't bigger than reported! */
                            if (offset > p_mac_lte_info->length) {
                                expert_add_info_format(pinfo, padding_length_ti, PI_MALFORMED, PI_ERROR,
                                                       "MAC PDU is longer than reported length (reported=%u, actual=%u)",
                                                       p_mac_lte_info->length, offset);
                            }
                        }
                        break;

                    default:
                        break;
                }
            }
            else {

                /**********************************/
                /* UL-SCH Control PDUs            */
                switch (lcids[n]) {
                    case POWER_HEADROOM_REPORT_LCID:
                        {
                            proto_item *ti;
                            guint8 reserved;

                            /* Check 2 Reserved bits */
                            reserved = (tvb_get_guint8(tvb, offset) & 0xc0) >> 6;
                            ti = proto_tree_add_item(tree, hf_mac_lte_control_power_headroom_reserved,
                                                     tvb, offset, 1, FALSE);
                            if (global_mac_lte_check_reserved_bits && (reserved != 0)) {
                                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                          "Power Headroom Reserved bits not zero (found 0x%x)", reserved);
                            }
                        }

                        proto_tree_add_item(tree, hf_mac_lte_control_power_headroom,
                                            tvb, offset, 1, FALSE);
                        offset++;
                        break;
                    case CRNTI_LCID:
                        proto_tree_add_item(tree, hf_mac_lte_control_crnti,
                                            tvb, offset, 2, FALSE);
                        offset += 2;
                        break;
                    case TRUNCATED_BSR_LCID:
                    case SHORT_BSR_LCID:
                        {
                            proto_tree *bsr_tree;
                            proto_item *bsr_ti;
                            guint8 lcgid;
                            guint8 buffer_size;

                            bsr_ti = proto_tree_add_string_format(tree,
                                                                  hf_mac_lte_control_bsr,
                                                                  tvb, offset, 1,
                                                                  "",
                                                                  "BSR");
                            bsr_tree = proto_item_add_subtree(bsr_ti, ett_mac_lte_bsr);

                            /* LCG ID */
                            lcgid = (tvb_get_guint8(tvb, offset) & 0xc0) >> 6;
                            proto_tree_add_item(bsr_tree, hf_mac_lte_control_bsr_lcg_id,
                                                        tvb, offset, 1, FALSE);
                            /* Buffer Size */
                            buffer_size = tvb_get_guint8(tvb, offset) & 0x3f;
                            proto_tree_add_item(bsr_tree, hf_mac_lte_control_bsr_buffer_size,
                                                tvb, offset, 1, FALSE);
                            offset++;

                            proto_item_append_text(bsr_ti, " (lcgid=%u  %s)",
                                                   lcgid,
                                                   val_to_str(buffer_size, buffer_size_vals, "Unknown"));
                        }
                        break;
                    case LONG_BSR_LCID:
                        {
                            proto_tree *bsr_tree;
                            proto_item *bsr_ti;
                            bsr_ti = proto_tree_add_string_format(tree,
                                                                  hf_mac_lte_control_bsr,
                                                                  tvb, offset, 3,
                                                                  "",
                                                                  "Long BSR");
                            bsr_tree = proto_item_add_subtree(bsr_ti, ett_mac_lte_bsr);

                            proto_tree_add_item(bsr_tree, hf_mac_lte_control_bsr_buffer_size_1,
                                                tvb, offset, 1, FALSE);
                            proto_tree_add_item(bsr_tree, hf_mac_lte_control_bsr_buffer_size_2,
                                                tvb, offset, 1, FALSE);
                            offset++;
                            proto_tree_add_item(bsr_tree, hf_mac_lte_control_bsr_buffer_size_3,
                                                tvb, offset, 1, FALSE);
                            offset++;
                            proto_tree_add_item(bsr_tree, hf_mac_lte_control_bsr_buffer_size_4,
                                                tvb, offset, 1, FALSE);
                            offset++;
                        }
                        break;
                    case PADDING_LCID:
                        /* No payload, unless its the last subheader, in which case
                           it extends to the end of the PDU */
                        if (n == (number_of_headers-1)) {
                            if (tvb_length_remaining(tvb, offset) > 0) {
                                proto_tree_add_item(tree, hf_mac_lte_padding_data,
                                                    tvb, offset, -1, FALSE);
                            }
                            padding_length_ti = proto_tree_add_int(tree, hf_mac_lte_padding_length,
                                                                   tvb, offset, 0,
                                                                   p_mac_lte_info->length - offset);
                            PROTO_ITEM_SET_GENERATED(padding_length_ti);

                            /* Make sure the PDU isn't bigger than reported! */
                            if (offset > p_mac_lte_info->length) {
                                expert_add_info_format(pinfo, padding_length_ti, PI_MALFORMED, PI_ERROR,
                                                       "MAC PDU is longer than reported length (reported=%u, actual=%u)",
                                                       p_mac_lte_info->length, offset);
                            }
                        }

                        break;

                    default:
                        break;
                }
            }
        }
    }
}



/*****************************/
/* Main dissection function. */
void dissect_mac_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree             *mac_lte_tree;
    proto_item             *ti;
    gint                   offset = 0;
    struct mac_lte_info   *p_mac_lte_info = NULL;

    static mac_lte_tap_info tap_info;
    memset(&tap_info, 0, sizeof(mac_lte_tap_info));

    /* Set protocol name */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC-LTE");

    /* Create protocol tree. */
    ti = proto_tree_add_item(tree, proto_mac_lte, tvb, offset, -1, FALSE);
    mac_lte_tree = proto_item_add_subtree(ti, ett_mac_lte);


    /* Look for packet info! */
    p_mac_lte_info = p_get_proto_data(pinfo->fd, proto_mac_lte);

    /* Can't dissect anything without it... */
    if (p_mac_lte_info == NULL) {
        proto_item *ti =
            proto_tree_add_text(mac_lte_tree, tvb, offset, -1,
                                "Can't dissect LTE MAC frame because no per-frame info was attached!");
        PROTO_ITEM_SET_GENERATED(ti);
        return;
    }

    /* Clear info column */
    col_clear(pinfo->cinfo, COL_INFO);


    /*****************************************/
    /* Show context information              */

    ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_radio_type,
                             tvb, 0, 0, p_mac_lte_info->radioType);
    PROTO_ITEM_SET_GENERATED(ti);

    ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_direction,
                             tvb, 0, 0, p_mac_lte_info->direction);
    PROTO_ITEM_SET_GENERATED(ti);

    if (p_mac_lte_info->ueid != 0) {
        ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_ueid,
                                 tvb, 0, 0, p_mac_lte_info->ueid);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_subframe_number,
                             tvb, 0, 0, p_mac_lte_info->subframeNumber);
    PROTO_ITEM_SET_GENERATED(ti);

    if (p_mac_lte_info->rntiType != NO_RNTI) {
        ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_rnti,
                                 tvb, 0, 0, p_mac_lte_info->rnti);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_rnti_type,
                             tvb, 0, 0, p_mac_lte_info->rntiType);
    PROTO_ITEM_SET_GENERATED(ti);

    ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_predefined_frame,
                             tvb, 0, 0, p_mac_lte_info->isPredefinedData);
    if (p_mac_lte_info->isPredefinedData) {
        PROTO_ITEM_SET_GENERATED(ti);
    }
    else {
        PROTO_ITEM_SET_HIDDEN(ti);
    }

    ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_length,
                             tvb, 0, 0, p_mac_lte_info->length);
    PROTO_ITEM_SET_GENERATED(ti);

    if (p_mac_lte_info->reTxCount) {
        ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_retx_count,
                                 tvb, 0, 0, p_mac_lte_info->reTxCount);
        PROTO_ITEM_SET_GENERATED(ti);

        if (p_mac_lte_info->reTxCount >= global_mac_lte_retx_counter_trigger) {
            expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_ERROR,
                                   "Frame has now been NACK'd %u times",
                                   p_mac_lte_info->reTxCount);
        }
    }

    if (p_mac_lte_info->crcStatusValid) {
        ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_crc_status,
                                 tvb, 0, 0, p_mac_lte_info->crcStatus);
        PROTO_ITEM_SET_GENERATED(ti);
        if (p_mac_lte_info->crcStatus != TRUE) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                   "Frame has CRC error");
            col_append_fstr(pinfo->cinfo, COL_INFO, "<CRC FAILURE> ");
        }
    }


    /* Set context-info parts of tap struct */
    tap_info.rnti = p_mac_lte_info->rnti;
    tap_info.rntiType = p_mac_lte_info->rntiType;
    tap_info.isPredefinedData = p_mac_lte_info->isPredefinedData;
    tap_info.reTxCount = p_mac_lte_info->reTxCount;
    tap_info.crcStatusValid = p_mac_lte_info->crcStatusValid;
    tap_info.crcStatus = p_mac_lte_info->crcStatus;
    tap_info.direction = p_mac_lte_info->direction;

    /* Also set total number of bytes (won't be used for UL/DL-SCH) */
    tap_info.single_number_of_bytes = tvb_length_remaining(tvb, offset);

    /* If we know its predefined data, don't try to decode any further */
    if (p_mac_lte_info->isPredefinedData) {
        proto_tree_add_item(mac_lte_tree, hf_mac_lte_predefined_pdu, tvb, offset, -1, FALSE);
        col_append_fstr(pinfo->cinfo, COL_INFO, "Predefined data (%u bytes)", tvb_length_remaining(tvb, offset));

        /* Queue tap info */
        if (!pinfo->in_error_pkt) {
            tap_queue_packet(mac_lte_tap, pinfo, &tap_info);
        }

        return;
    }

    /* IF CRC status failed, just do decode as raw bytes */
    if (!global_mac_lte_dissect_crc_failures &&
        (p_mac_lte_info->crcStatusValid && !p_mac_lte_info->crcStatus)) {

        proto_tree_add_item(mac_lte_tree, hf_mac_lte_raw_pdu, tvb, offset, -1, FALSE);
        col_append_fstr(pinfo->cinfo, COL_INFO, "Raw data (%u bytes)", tvb_length_remaining(tvb, offset));

        /* Queue tap info */
        if (!pinfo->in_error_pkt) {
            tap_queue_packet(mac_lte_tap, pinfo, &tap_info);
        }

        return;
    }



    /* Dissect the MAC PDU itself. Format depends upon RNTI type. */
    switch (p_mac_lte_info->rntiType) {

        case P_RNTI:
            /* PCH PDU */
            dissect_pch(tvb, pinfo, mac_lte_tree, offset, p_mac_lte_info->direction);
            break;

        case RA_RNTI:
            /* RAR PDU */
            dissect_rar(tvb, pinfo, mac_lte_tree, offset, p_mac_lte_info, &tap_info);
            break;

        case C_RNTI:
            /* Can be UL-SCH or DL-SCH */
            dissect_ulsch_or_dlsch(tvb, pinfo, mac_lte_tree, offset, p_mac_lte_info->direction,
                                   p_mac_lte_info, &tap_info);
            break;

        case SI_RNTI:
            /* BCH over DL-SCH */
            dissect_bch(tvb, pinfo, mac_lte_tree, offset, p_mac_lte_info);
            break;

        case NO_RNTI:
            /* Must be BCH over BCH... */
            dissect_bch(tvb, pinfo, mac_lte_tree, offset, p_mac_lte_info);
            break;


        default:
            break;
    }

    /* Queue tap info */
    /* TODO: if any of above (esp RRC dissection) throws exception, this isn't reached,
       but if call too early, won't have details... */
    tap_queue_packet(mac_lte_tap, pinfo, &tap_info);
}


void proto_register_mac_lte(void)
{
    static hf_register_info hf[] =
    {
        /**********************************/
        /* Items for decoding context     */
        { &hf_mac_lte_context_radio_type,
            { "Radio Type",
              "mac-lte.radio-type", FT_UINT8, BASE_DEC, VALS(radio_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_direction,
            { "Direction",
              "mac-lte.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_mac_lte_context_rnti,
            { "RNTI",
              "mac-lte.rnti", FT_UINT16, BASE_DEC, 0, 0x0,
              "RNTI associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_rnti_type,
            { "RNTI Type",
              "mac-lte.rnti-type", FT_UINT8, BASE_DEC, VALS(rnti_type_vals), 0x0,
              "Type of RNTI associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_ueid,
            { "UEId",
              "mac-lte.ueid", FT_UINT16, BASE_DEC, 0, 0x0,
              "User Equipment Identifier associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_subframe_number,
            { "Subframe",
              "mac-lte.subframe", FT_UINT16, BASE_DEC, 0, 0x0,
              "Subframe number associate with message", HFILL
            }
        },
        { &hf_mac_lte_context_predefined_frame,
            { "Predefined frame",
              "mac-lte.is-predefined-frame", FT_UINT8, BASE_DEC, VALS(predefined_frame_vals), 0x0,
              "Predefined test frame (or real MAC PDU)", HFILL
            }
        },
        { &hf_mac_lte_context_length,
            { "Length of frame",
              "mac-lte.length", FT_UINT8, BASE_DEC, 0, 0x0,
              "Original length of frame (including SDUs and padding)", HFILL
            }
        },
        { &hf_mac_lte_context_bch_transport_channel,
            { "Transport channel",
              "mac-lte.bch-transport-channel", FT_UINT8, BASE_DEC, VALS(bch_transport_channel_vals), 0x0,
              "Transport channel BCH data was carried on", HFILL
            }
        },
        { &hf_mac_lte_context_retx_count,
            { "ReTX count",
              "mac-lte.retx-count", FT_UINT8, BASE_DEC, 0, 0x0,
              "Number of times this PDU has been retransmitted", HFILL
            }
        },
        { &hf_mac_lte_context_crc_status,
            { "CRC Status",
              "mac-lte.crc-status", FT_UINT8, BASE_DEC, VALS(crc_status_vals), 0x0,
              "CRC Status as reported by PHY", HFILL
            }
        },


        /*******************************************/
        /* MAC shared channel header fields        */
        { &hf_mac_lte_ulsch_header,
            { "UL-SCH Header",
              "mac-lte.ulsch.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dlsch_header,
            { "DL-SCH Header",
              "mac-lte.dlsch.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_subheader,
            { "SCH sub-header",
              "mac-lte.sch.subheader", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_reserved,
            { "SCH reserved bits",
              "mac-lte.sch.reserved", FT_UINT8, BASE_HEX, NULL, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_extended,
            { "Extension",
              "mac-lte.sch.extended", FT_UINT8, BASE_HEX, 0, 0x20,
              "Extension - i.e. further headers after this one", HFILL
            }
        },
        { &hf_mac_lte_dlsch_lcid,
            { "LCID",
              "mac-lte.dlsch.lcid", FT_UINT8, BASE_HEX, VALS(dlsch_lcid_vals), 0x1f,
              "DL-SCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_ulsch_lcid,
            { "LCID",
              "mac-lte.ulsch.lcid", FT_UINT8, BASE_HEX, VALS(ulsch_lcid_vals), 0x1f,
              "UL-SCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_sch_format,
            { "Format",
              "mac-lte.sch.format", FT_UINT8, BASE_HEX, VALS(format_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_length,
            { "Length",
              "mac-lte.sch.length", FT_UINT16, BASE_DEC, 0, 0x0,
              "Length of MAC SDU or MAC control element", HFILL
            }
        },
        { &hf_mac_lte_sch_header_only,
            { "MAC PDU Header only",
              "mac-lte.sch.header-only", FT_UINT8, BASE_DEC, VALS(header_only_vals), 0x0,
              NULL, HFILL
            }
        },

        /********************************/
        /* Data                         */
        { &hf_mac_lte_sch_sdu,
            { "SDU",
              "mac-lte.sch.sdu", FT_BYTES, BASE_NONE, 0, 0x0,
              "Shared channel SDU", HFILL
            }
        },
        { &hf_mac_lte_bch_pdu,
            { "BCH PDU",
              "mac-lte.bch.pdu", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_pch_pdu,
            { "PCH PDU",
              "mac-lte.pch.pdu", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_predefined_pdu,
            { "Predefined data",
              "mac-lte.predefined-data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Predefined test data", HFILL
            }
        },
        { &hf_mac_lte_raw_pdu,
            { "Raw data",
              "mac-lte.raw-data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Raw bytes of PDU (e.g. if CRC failed)", HFILL
            }
        },
        { &hf_mac_lte_padding_data,
            { "Padding data",
              "mac-lte.padding-data", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_padding_length,
            { "Padding length",
              "mac-lte.padding-length", FT_INT32, BASE_DEC, 0, 0x0,
              "Length of padding data not included at end of frame", HFILL
            }
        },



        /*********************************/
        /* RAR fields                    */
        { &hf_mac_lte_rar,
            { "RAR",
              "mac-lte.rar", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_headers,
            { "RAR Headers",
              "mac-lte.rar.headers", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_header,
            { "RAR Header",
              "mac-lte.rar.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_extension,
            { "Extension",
              "mac-lte.rar.e", FT_UINT8, BASE_HEX, 0, 0x80,
              "Extension - i.e. further RAR headers after this one", HFILL
            }
        },
        { &hf_mac_lte_rar_t,
            { "Type",
              "mac-lte.rar.t", FT_UINT8, BASE_HEX, VALS(rar_type_vals), 0x40,
              "Type field indicating whether the payload is RAPID or BI", HFILL
            }
        },
        { &hf_mac_lte_rar_bi,
            { "BI",
              "mac-lte.rar.bi", FT_UINT8, BASE_HEX, VALS(rar_bi_vals), 0x0f,
              "Backoff Indicator (ms)", HFILL
            }
        },
        { &hf_mac_lte_rar_rapid,
            { "RAPID",
              "mac-lte.rar.rapid", FT_UINT8, BASE_HEX_DEC, 0, 0x3f,
              "Random Access Preamble IDentifier", HFILL
            }
        },
        { &hf_mac_lte_rar_reserved,
            { "Reserved",
              "mac-lte.rar.reserved", FT_UINT8, BASE_HEX, 0, 0x30,
              "Reserved bits in RAR header - should be 0", HFILL
            }
        },

        { &hf_mac_lte_rar_body,
            { "RAR Body",
              "mac-lte.rar.body", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_reserved2,
            { "Reserved",
              "mac-lte.rar.reserved2", FT_UINT8, BASE_HEX, 0, 0x80,
              "Reserved bit in RAR body - should be 0", HFILL
            }
        },
        { &hf_mac_lte_rar_ta,
            { "Timing Advance",
              "mac-lte.rar.ta", FT_UINT16, BASE_DEC, 0, 0x7ff0,
              "Required adjustment to uplink transmission timing", HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant,
            { "UL Grant",
              "mac-lte.rar.ul-grant", FT_UINT24, BASE_DEC, 0, 0x0fffff,
              "Size of UL Grant", HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_hopping,
            { "Hopping Flag",
              "mac-lte.rar.ul-grant.hopping", FT_UINT8, BASE_DEC, 0, 0x08,
              "Size of UL Grant", HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_fsrba,
            { "Fixed sized resource block assignment",
              "mac-lte.rar.ul-grant.fsrba", FT_UINT16, BASE_DEC, 0, 0x07fe,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_tmcs,
            { "Truncated Modulation and coding scheme",
              "mac-lte.rar.ul-grant.tmcs", FT_UINT16, BASE_DEC, 0, 0x01e0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_tcsp,
            { "TPC command for scheduled PUSCH",
              "mac-lte.rar.ul-grant.tcsp", FT_UINT8, BASE_DEC, 0, 0x01c,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_ul_delay,
            { "UL Delay",
              "mac-lte.rar.ul-grant.ul-delay", FT_UINT8, BASE_DEC, 0, 0x02,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_cqi_request,
            { "CQI Request",
              "mac-lte.rar.ul-grant.cqi-request", FT_UINT8, BASE_DEC, 0, 0x01,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_temporary_crnti,
            { "Temporary C-RNTI",
              "mac-lte.rar.temporary-crnti", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },

        /**********************/
        /* Control PDU fields */
        { &hf_mac_lte_control_bsr,
            { "BSR",
              "mac-lte.control.bsr", FT_STRING, BASE_NONE, 0, 0x0,
              "Buffer Status Report", HFILL
            }
        },
        { &hf_mac_lte_control_bsr_lcg_id,
            { "Logical Channel Group ID",
              "mac-lte.control.bsr.lcg-id", FT_UINT8, BASE_DEC, 0, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_bsr_buffer_size,
            { "Buffer Size",
              "mac-lte.control.bsr.buffer-size", FT_UINT8, BASE_DEC, VALS(buffer_size_vals), 0x3f,
              "Buffer Size available in all channels in group", HFILL
            }
        },
        { &hf_mac_lte_control_bsr_buffer_size_1,
            { "Buffer Size 1",
              "mac-lte.control.bsr.buffer-size-1", FT_UINT8, BASE_DEC, VALS(buffer_size_vals), 0xfc,
              "Buffer Size available in for 1st channel in group", HFILL
            }
        },
        { &hf_mac_lte_control_bsr_buffer_size_2,
            { "Buffer Size 2",
              "mac-lte.control.bsr.buffer-size-2", FT_UINT16, BASE_DEC, VALS(buffer_size_vals), 0x03c0,
              "Buffer Size available in for 2nd channel in group", HFILL
            }
        },
        { &hf_mac_lte_control_bsr_buffer_size_3,
            { "Buffer Size 3",
              "mac-lte.control.bsr.buffer-size-3", FT_UINT16, BASE_DEC, VALS(buffer_size_vals), 0x0fc0,
              "Buffer Size available in for 3rd channel in group", HFILL
            }
        },
        { &hf_mac_lte_control_bsr_buffer_size_4,
            { "Buffer Size 4",
              "mac-lte.control.bsr.buffer-size-4", FT_UINT8, BASE_DEC, VALS(buffer_size_vals), 0x3f,
              "Buffer Size available in for 4th channel in group", HFILL
            }
        },
        { &hf_mac_lte_control_crnti,
            { "C-RNTI",
              "mac-lte.control.crnti", FT_UINT16, BASE_DEC, 0, 0x0,
              "C-RNTI for the UE", HFILL
            }
        },
        { &hf_mac_lte_control_timing_advance,
            { "Timing Advance",
              "mac-lte.control.timing-advance", FT_UINT8, BASE_DEC, 0, 0x3f,
              "Timing Advance (0-1282 - see 36.213, 4.2.3)", HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_identity,
            { "UE Contention Resolution Identity",
              "mac-lte.control.ue-contention-resolution-identity", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_power_headroom_reserved,
            { "Reserved",
              "mac-lte.control.power-headroom.reserved", FT_UINT8, BASE_DEC, 0, 0xc0,
              "Reserved bits, should be 0", HFILL
            }
        },
        { &hf_mac_lte_control_power_headroom,
            { "Power Headroom",
              "mac-lte.control.power-headroom", FT_UINT8, BASE_DEC, 0, 0x3f,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_padding,
            { "Padding",
              "mac-lte.control.padding", FT_NONE, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
    };

    static gint *ett[] =
    {
        &ett_mac_lte,
        &ett_mac_lte_context,
        &ett_mac_lte_rar_headers,
        &ett_mac_lte_rar_header,
        &ett_mac_lte_rar_body,
        &ett_mac_lte_rar_ul_grant,
        &ett_mac_lte_ulsch_header,
        &ett_mac_lte_dlsch_header,
        &ett_mac_lte_sch_subheader,
        &ett_mac_lte_bch,
        &ett_mac_lte_bsr,
        &ett_mac_lte_pch
    };

    module_t *mac_lte_module;

    /* Register protocol. */
    proto_mac_lte = proto_register_protocol("MAC-LTE", "MAC-LTE", "mac-lte");
    proto_register_field_array(proto_mac_lte, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name. */
    register_dissector("mac-lte", dissect_mac_lte, proto_mac_lte);

    /* Register the tap name */
    mac_lte_tap = register_tap("mac-lte");

    /* Preferences */
    mac_lte_module = prefs_register_protocol(proto_mac_lte, NULL);

    /* Obsolete this preference? (TODO: just delete since never in proper release?) */
    prefs_register_obsolete_preference(mac_lte_module, "single_rar");

    prefs_register_bool_preference(mac_lte_module, "check_reserved_bits",
        "Warn if reserved bits are not 0",
        "When set, an expert warning will indicate if reserved bits are not zero",
        &global_mac_lte_check_reserved_bits);

    prefs_register_uint_preference(mac_lte_module, "retx_count_warn",
        "Number of Re-Transmits before expert warning triggered",
        "Number of Re-Transmits before expert warning triggered",
        10, &global_mac_lte_retx_counter_trigger);

    prefs_register_bool_preference(mac_lte_module, "attempt_rrc_decode",
        "Attempt to decode BCH, PCH and CCCH data using LTE RRC dissector",
        "Attempt to decode BCH, PCH and CCCH data using LTE RRC dissector",
        &global_mac_lte_attempt_rrc_decode);

    prefs_register_bool_preference(mac_lte_module, "decode_rar_ul_grant",
        "Attempt to decode details of RAR UL grant field",
        "Attempt to decode details of RAR UL grant field",
        &global_mac_lte_decode_rar_ul_grant);

    prefs_register_bool_preference(mac_lte_module, "attempt_to_dissect_crc_failures",
        "Dissect frames that have failed CRC check",
        "Attempt to dissect frames that have failed CRC check",
        &global_mac_lte_dissect_crc_failures);

    prefs_register_bool_preference(mac_lte_module, "heuristic_mac_lte_over_udp",
        "Try Heuristic LTE-MAC over UDP framing",
        "When enabled, use heuristic dissector to find MAC-LTE frames sent with "
        "UDP framing",
        &global_mac_lte_heur);
}

void
proto_reg_handoff_mac_lte(void)
{
    static dissector_handle_t mac_lte_handle;
    if (!mac_lte_handle) {
        mac_lte_handle = find_dissector("mac-lte");

        /* Add as a heuristic UDP dissector */
        heur_dissector_add("udp", dissect_mac_lte_heur, proto_mac_lte);
    }
}

