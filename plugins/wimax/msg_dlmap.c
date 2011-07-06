/* msg_dlmap.c
 * WiMax MAC Management DL-MAP Message decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Mike Harvey <michael.harvey@intel.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "crc.h"
#include "wimax_bits.h"

extern gint proto_wimax;
extern	gboolean include_cor2_changes;

#define MAC_MGMT_MSG_DLMAP 2

#define XBIT(var, bits, desc) \
    do { \
    var = BIT_BITS(bit, bufptr, bits); \
    proto_tree_add_text(tree, tvb, BITHI(bit, bits), desc ": %d", var); \
    bit += bits; \
    } while(0)

#define VBIT(var, bits, hf) \
    do { \
    var = BIT_BITS(bit, bufptr, bits); \
    proto_tree_add_uint(tree, hf, tvb, BITHI(bit,bits), var); \
    bit += bits; \
    } while(0)

#define XNIB(var, nibs, desc) \
    do { \
    var = NIB_NIBS(nib, bufptr, nibs); \
    proto_tree_add_text(tree, tvb, NIBHI(nib, nibs), desc ": %d", var); \
    nib += nibs; \
    } while(0)

gint harq = 0; /* 1 if HARQ enabled (TODO) */
gint fusc = 0; /* 1 if current zone permutation is FUSC or optional FUSC (TODO) */
gint tusc = 0; /* 1 if current zone permutation is AMC, TUSC1 or TUSC2 (TODO) */
gint ir_type = 0; /* reduced AAS map (TODO) */
gint RCID_Type = 0;
gint N_layer = 0;
gint STC_Zone_Dedicated_Pilots = 0;
gint STC_Zone_Matrix = 0;
gint INC_CID = 0;
gint sub_dl_ul_map = 0;


extern gint man_ofdma;

gint proto_mac_mgmt_msg_dlmap_decoder = -1;

static gint ett_dlmap = -1;
static gint ett_dlmap_ie = -1;
/* static gint ett_dlmap_c_ie = -1; */
static gint ett_109x = -1; /* SUB-DL-UL-MAP */
static gint ett_109x_dl = -1;
static gint ett_109x_ul = -1;
static gint ett_275_phy = -1;
static gint ett_275_1 = -1;
static gint ett_277 = -1;
static gint ett_277b = -1;
static gint ett_278 = -1;
static gint ett_279 = -1;
static gint ett_280 = -1;
static gint ett_281 = -1;
static gint ett_282 = -1;
static gint ett_283 = -1;
static gint ett_284 = -1;
static gint ett_285 = -1;
static gint ett_286 = -1;
static gint ett_286a = -1;
static gint ett_286b = -1;
static gint ett_286c = -1;
static gint ett_286d = -1;
static gint ett_286e = -1;
static gint ett_286f = -1;
static gint ett_286g = -1;
static gint ett_286h = -1;
static gint ett_286i = -1;
static gint ett_286j = -1;
static gint ett_286k = -1;
static gint ett_286l = -1;
static gint ett_286m = -1;
static gint ett_286n = -1;
static gint ett_286o = -1;
static gint ett_286p = -1;
static gint ett_286q = -1;
static gint ett_286r = -1;
static gint ett_286s = -1;
static gint ett_286t = -1;
static gint ett_286u = -1;
static gint ett_286v = -1;
static gint ett_286w = -1;
static gint ett_286x = -1;
static gint ett_286y = -1;
static gint ett_286z = -1;
static gint ett_305  = -1;
/* static gint ett_305_dl = -1; */
static gint ett_308a = -1;

#define DCD_DOWNLINK_BURST_PROFILE     1
#define DCD_BS_EIRP                    2
#define DCD_FRAME_DURATION             3
#define DCD_PHY_TYPE                   4
#define DCD_POWER_ADJUSTMENT           5
#define DCD_CHANNEL_NR                 6
#define DCD_TTG                        7
#define DCD_RTG                        8
#define DCD_RSS                        9
#define DCD_CHANNEL_SWITCH_FRAME_NR    10
#define DCD_FREQUENCY                  12
#define DCD_BS_ID                      13
#define DCD_FRAME_DURATION_CODE        14
#define DCD_FRAME_NR                   15
#define DCD_SIZE_CQICH_ID              16
#define DCD_H_ARQ_ACK_DELAY            17
#define DCD_MAC_VERSION                148
#define DCD_RESTART_COUNT              154

#define DCD_BURST_FREQUENCY            1
#define DCD_BURST_FEC_CODE_TYPE        150
#define DCD_BURST_DIUC_EXIT_THRESHOLD  151
#define DCD_BURST_DIUC_ENTRY_THRESHOLD 152
#define DCD_BURST_TCS_ENABLE           153

#define DCD_TLV_T_541_TYPE_FUNCTION_ACTION                              1
#define DCD_TLV_T542_TRIGGER_VALUE                                      2
#define DCD_TLV_T_543_TRIGGER_AVERAGING_DURATION                        3
#define DCD_TLV_T_19_PERMUTATION_TYPE_FOR_BROADCAST_REGION_IN_HARQ_ZONE 19
#define DCD_TLV_T_20_MAXIMUM_RETRANSMISSION                             20
#define DCD_TLV_T_21_DEFAULT_RSSI_AND_CINR_AVERAGING_PARAMETER          21
#define DCD_TLV_T_22_DL_AMC_ALLOCATED_PHYSICAL_BANDS_BITMAP             22
#define DCD_TLV_T_31_H_ADD_THRESHOLD                                    31
#define DCD_TLV_T_32_H_DELETE_THRESHOLD                                 32
#define DCD_TLV_T_33_ASR                                                33
#define DCD_TLV_T_34_DL_REGION_DEFINITION                               34
#define DCD_TLV_T_35_PAGING_GROUP_ID                                    35
#define DCD_TLV_T_36_TUSC1_PERMUTATION_ACTIVE_SUBCHANNELS_BITMAP        36
#define DCD_TLV_T_37_TUSC2_PERMUTATION_ACTIVE_SUBCHANNELS_BITMAP        37
#define DCD_TLV_T_45_PAGING_INTERVAL_LENGTH                             45
#define DCD_TLV_T_50_HO_TYPE_SUPPORT                                    50
#define DCD_TLV_T_51_HYSTERSIS_MARGIN                                   51
#define DCD_TLV_T_52_TIME_TO_TRIGGER_DURATION                           52
#define DCD_TLV_T_54_TRIGGER                                            54
#define DCD_TLV_T_153_DOWNLINK_BURST_PROFILE_FOR_MULTIPLE_FEC_TYPES     153

#define DL_MAP_NCT_PMP  0
#define DL_MAP_NCT_DM   1
#define DL_MAP_NCT_PTP  2

/* NCT messages */
static const value_string nct_msgs[] =
{
    { DL_MAP_NCT_PMP, "PMP" },
    { DL_MAP_NCT_PMP, "DM" },
    { DL_MAP_NCT_PMP, "PTP" },
    { 0,  NULL }
};

/* Repetition Coding Indications */
static const value_string rep_msgs[] =
{
    { 0, "No Repetition Coding" },
    { 1, "Repetition Coding of 2 Used" },
    { 2, "Repetition Coding of 4 Used" },
    { 3, "Repetition Coding of 6 Used" },
    { 0,  NULL }
};

/* DL Frame Prefix Coding Indications */
static const value_string boost_msgs[] =
{
    { 0, "Normal (not boosted)" },
    { 1, "+6dB" },
    { 2, "-6dB" },
    { 3, "+9dB" },
    { 4, "+3dB" },
    { 5, "-3dB" },
    { 6, "-9dB" },
    { 7, "-12dB" },
    { 0,  NULL }
};

/* OFDMA frame duration ms (Table 320)*/
static const value_string frame_duration[] =
{
	{ 0, "reserved"},
	{ 1, "2 ms"},
	{ 2, "2.5 ms"},
	{ 3, "4 ms"},
	{ 4, "5 ms"},
	{ 5, "8 ms"},
	{ 6, "10 ms"},
	{ 7, "12.5 ms"},
	{ 8, "20 ms"},
	{ 0, NULL}
};

/* OFDMA frames per second (Table 320)*/
static const value_string frames_per_second[] =
{
	{ 0, "reserved"},
	{ 1, "500"},
	{ 2, "400"},
	{ 3, "250"},
	{ 4, "200"},
	{ 5, "125"},
	{ 6, "100"},
	{ 7, "80"},
	{ 8, "50"},
	{ 0, NULL}
};

/* dl-map fields */
static gint hf_dlmap_message_type = -1;

static gint hf_dlmap_phy_fdur = -1;
static gint hf_dlmap_phy_fdur_ms = -1;
static gint hf_dlmap_phy_fdur_per_sec = -1;
static gint hf_dlmap_phy_fnum = -1;
static gint hf_dlmap_fch_expected = -1;
static gint hf_dlmap_dcd = -1;
static gint hf_dlmap_bsid = -1;
static gint hf_dlmap_ofdma_sym = -1;
static gint hf_dlmap_ie = -1;
static gint hf_dlmap_ie_diuc = -1;
static gint hf_dlmap_ie_ncid = -1;
static gint hf_dlmap_ie_cid = -1;
static gint hf_dlmap_ie_offsym = -1;
static gint hf_dlmap_ie_offsub = -1;
static gint hf_dlmap_ie_boosting = -1;
static gint hf_dlmap_ie_numsym = -1;
static gint hf_dlmap_ie_numsub = -1;
static gint hf_dlmap_ie_rep = -1;
static gint hf_dlmap_ie_offsym2 = -1;
static gint hf_dlmap_ie_offsub2 = -1;
static gint hf_dlmap_ie_boosting2 = -1;
static gint hf_dlmap_ie_numsym2 = -1;
static gint hf_dlmap_ie_numsub2 = -1;
static gint hf_dlmap_ie_rep2 = -1;

static gint hf_dlmap_xie_diuc = -1;
static gint hf_dlmap_xie_len = -1;

static gint hf_dlmapc_compr = -1;
static gint hf_dlmapc_ulmap = -1;
static gint hf_dlmapc_rsv = -1;
static gint hf_dlmapc_len = -1;
static gint hf_dlmapc_sync = -1;
static gint hf_dlmapc_opid = -1;
static gint hf_dlmapc_secid = -1;
static gint hf_dlmapc_count = -1;

static gint hf_109x_cmi = -1;
static gint hf_109x_len = -1;
static gint hf_109x_rcid = -1;
static gint hf_109x_haoi = -1;
static gint hf_109x_dl = -1;
static gint hf_109x_ul = -1;
static gint hf_109x_dlie = -1;
static gint hf_109x_symofs = -1;
static gint hf_109x_subofs = -1;
static gint hf_109x_rsv = -1;

static gint hf_308a_cmi = -1;
static gint hf_308a_ulmap = -1;
static gint hf_308a_type = -1;
static gint hf_308a_mult = -1;
static gint hf_308a_rsv = -1;
static gint hf_mac_header_compress_dlmap_crc = -1;

/********************************************************************
 * DL-MAP Miscellaneous IEs and TLVs
 *******************************************************************/

gint RCID_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb, gint RCID_Type_lcl)
{
    /* RCID_IE 8.4.5.3 and 8.4.5.3.20.1 */
    /* offset of IE in bits, length is variable  */
    gint bit = offset;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint Prefix = 0;
    gint cid = 0;

    if (RCID_Type_lcl == 0)
        length = 16;
    else {
        Prefix = BIT_BIT(bit, bufptr);
        if (Prefix == 1) length = 12;
        else if (RCID_Type_lcl == 1) length = 12;
        else if (RCID_Type_lcl == 2) length = 8;
        else if (RCID_Type_lcl == 3) length = 4;
    }

    ti = proto_tree_add_text(diuc_tree, tvb, BITHI(bit, length), "RCID_IE");
    tree = proto_item_add_subtree(ti, ett_286j);

    if (RCID_Type_lcl == 0) {
        XBIT(cid, 16, "CID");
    } else {
        proto_tree_add_text(tree, tvb, BITHI(bit,1), "Prefix: %d", Prefix);
        bit++;

        if (Prefix == 1) {
            /* RCID 11 */
            XBIT(cid, 11, "CID11");
        } else {
            if (RCID_Type_lcl == 1) {
                /* RCID 11 */
                XBIT(cid, 11, "CID11");
            } else if (RCID_Type_lcl == 2) {
                /* RCID 7 */
                XBIT(cid, 7, "CID7");
            } else if (RCID_Type_lcl == 3) {
                /* RCID 3 */
                XBIT(cid, 3, "CID3");
            }
        }
    }

    proto_item_append_text(ti, " (CID = %d)", cid);

    return length; /* return length in bits */
}

/********************************************************************
 * DL-MAP Extended-2 HARQ sub-burst IEs (8.4.5.3.21)
 *******************************************************************/

gint Dedicated_DL_Control_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.3.20 */
    /* offset of IE in nibbles, length is variable */
    gint nib;
    gint nibble;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint len;

    nib = offset;

    length = NIB_NIBBLE(nib, bufptr); /* length in nibbles */

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(nib, length+1), "Dedicated_DL_Control_IE");
    tree = proto_item_add_subtree(ti, ett_286i);

    proto_tree_add_text(tree, tvb, NIBHI(nib,1), "Length: %d", length);
    nib++;
    nibble = NIB_NIBBLE(nib, bufptr);
    proto_tree_add_text(tree, tvb, NIBHI(nib,1), "Control Header: %d", nibble);
    nib++;
    if ((nibble & 1) == 1) {
        nibble = NIB_NIBBLE(nib, bufptr);
        proto_tree_add_text(tree, tvb, NIBHI(nib,1), "Num SDMA Layers: %d", (nibble >> 2) & 0x3);
        /* Bit padding */
        if ((nib*4)+2 < (offset+length)*4) {
            len = ((offset + length - nib) * 4) - 2;
            proto_tree_add_text(tree, tvb, BITHI(nib*4, len), "Reserved bits");
        }
    } else {
        /* Nibble padding */
        if (nib < offset+length) {
            len = (offset + length) - nib;
            proto_tree_add_text(tree, tvb, NIBHI(nib,len), "Reserved bits");
        }
    }
    return (length + 1);
}

gint Dedicated_MIMO_DL_Control_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* offset of IE in bits, length is variable */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint mci, cqi, cmi, matrix = 0, pad, CQICH_num, mimo_mode;
    gint j;

    bit = offset;

    /* 8.4.5.3.21 table 286t */
    ti = proto_tree_add_text(diuc_tree, tvb, BITHI(bit, 1), "Dedicated MIMO DL Control IE");
    tree = proto_item_add_subtree(ti, ett_286t);

    XBIT(length, 5, "Length (nibbles)");
    XBIT(mci, 1, "Control Header (MIMO Control Info)");
    XBIT(cqi, 1, "Control Header (CQI Control Info)");
    XBIT(cmi, 1, "Control Header (Closed MIMO Control Info)");
    XBIT(N_layer, 2, "N_layer");

    /* MIMO Control Info */
    if (mci == 1) {
        XBIT(matrix, 2, "Matrix");
        if (STC_Zone_Dedicated_Pilots == 1) {
            XBIT(data, 2, "Num_Beamformed_Streams");
        }
    }

    /* CQICH Control Info */
    if (cqi == 1) {
        CQICH_num = 0;
        XBIT(data, 3, "Period");
        XBIT(data, 3, "Frame Offset");
        XBIT(data, 4, "Duration");
        for (j = 0; j < N_layer; j++) {
            XBIT(data, 6, "Allocation Index");
        }
        XBIT(CQICH_num, 2, "CQICH_Num");
        for (j = 0; j < CQICH_num; j++) {
            XBIT(data, 3, "Feedback type");
            XBIT(data, 6, "Allocation index");
        }
    }

    /* Closed MIMO Control Info */
    if (cmi == 1) {
        if (mci == 1) {
            mimo_mode = matrix;
        } else {
            mimo_mode = STC_Zone_Matrix;
        }
        if (mimo_mode == 0 || mimo_mode == 1) {
            XBIT(data, 3, "Antenna Grouping Index");
        } else if (mimo_mode == 2) {
            XBIT(data, 2, "Num_stream");
            XBIT(data, 3, "Antenna Selection Index");
        } else if (mimo_mode == 3) {
            XBIT(data, 2, "Num_stream");
            XBIT(data, 6, "Codebook Precoding Index");
        }
    }

    /* padding to nibble */
    pad = BIT_PADDING(bit,4);
    if(pad){
        proto_tree_add_text(tree, tvb, BITHI(bit,pad), "Padding: %d bits", pad);
        bit += pad;
    }

    return (bit - offset);
}

gint DL_HARQ_Chase_sub_burst_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.3.21 DL_HARQ_Chase_sub_burst_IE */
    /* offset of IE in nibbles, length is variable */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint nsub, ddci, dur, sbi, res, diuc, rci, ind, per, ofs;
    gint j;

    bit = NIB_TO_BIT(offset);

    /* 8.4.5.3.21 table 286m */
    ti = proto_tree_add_text(diuc_tree, tvb, BITHI(bit, length), "DL_HARQ_Chase_sub_burst_IE");
    tree = proto_item_add_subtree(ti, ett_286m);

    XBIT(nsub, 4, "N sub burst[ISI]");
    XBIT(data, 4, "N ACK channel");

    nsub += 1;
    for (j = 0; j < nsub; j++) {
        bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
        XBIT(dur, 10, "Duration");
        XBIT(sbi,  1, "Sub-Burst DIUC Indicator");
        XBIT(res,  1, "Reserved");

        if (sbi == 1) {
            XBIT(diuc, 4, "DIUC");
            XBIT(rci, 2, "Repetition Coding Indication");
            XBIT(res, 2, "Reserved");
        }

        XBIT(data, 4, "ACID");
        XBIT(data, 1, "AI_SN");
        XBIT(data, 1, "ACK disable");
        XBIT(ddci, 2, "Dedicated DL Control Indicator");

        if ((ddci & 1) == 1) {
            XBIT(dur, 4, "Duration (d)");
            if (dur != 0) {
                XBIT(ind, 6, "Allocation Index");
                XBIT(per, 3, "Period (p)");
                XBIT(ofs, 3, "Frame offset");
            }
        }

        if ((ddci & 2) == 2) {
            bit += Dedicated_DL_Control_IE(tree, bufptr, BIT_TO_NIB(bit), length, tvb) * 4;
        }
    }

    /* proto_tree_add_text(tree, tvb, BITHI(bit,4), "(DL HARQ Chase sub-burst IE)"); */
    return (BIT_TO_NIB(bit) - offset);
}

gint DL_HARQ_IR_CTC_sub_burst_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* offset of IE in nibbles, length is variable */
    gint bit;
    guint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    proto_item *generic_item = NULL;
    gint nsub, ddci, dur, ind, per, ofs;
    gint j;
    guint32	   calculated_crc;

    bit = NIB_TO_BIT(offset);

    /* 8.4.5.3.21 table 286n */
    ti = proto_tree_add_text(diuc_tree, tvb, BITHI(bit, 4), "DL HARQ IR CTC sub-burst IE");
    tree = proto_item_add_subtree(ti, ett_286n);

    XBIT(nsub, 4, "N sub burst[ISI]");
    XBIT(data, 4, "N ACK channel");

    nsub += 1;
    for (j = 0; j < nsub; j++) {
        bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);

        XBIT(data, 4, "N(EP)");
        XBIT(data, 4, "N(SCH)");
        XBIT(data, 2, "SPID");
        XBIT(data, 4, "ACID");
        XBIT(data, 1, "AI_SN");
        XBIT(data, 1, "ACK disable");
        XBIT(data, 2, "Reserved");
        XBIT(ddci, 2, "Dedicated DL Control Indicator");

        if ((ddci & 1) == 1) {
            XBIT(dur, 4, "Duration (d)");

            if (dur != 0) {
                XBIT(ind, 6, "Allocation Index");
                XBIT(per, 3, "Period (p)");
                XBIT(ofs, 3, "Frame offset");
            }
        }
        if ((ddci & 2) == 2) {
            bit += Dedicated_DL_Control_IE(tree, bufptr, BIT_TO_NIB(bit), length, tvb);
        }
    }

    if (include_cor2_changes)
    {
        /* CRC-16 is always appended */
        data = BIT_BITS(bit, bufptr, 16);
        generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
        /* calculate the CRC */
        calculated_crc = wimax_mac_calc_crc16(tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
        if (data != calculated_crc)
        {
            proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
        }
        bit += 16;
    }

    return (BIT_TO_NIB(bit) - offset);
}

gint DL_HARQ_IR_CC_sub_burst_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* offset of IE in nibbles, length is variable */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    proto_item *generic_item = NULL;
    gint nsub, sbdi, ddci, dur, ind, per, ofs;
    gint j;
    guint16 calculated_crc;

    bit = NIB_TO_BIT(offset);

    /* 8.4.5.3.21 table 286o */
    ti = proto_tree_add_text(diuc_tree, tvb, BITHI(bit, 4), "DL HARQ IR CC sub-burst IE");
    tree = proto_item_add_subtree(ti, ett_286o);

    XBIT(nsub, 4, "N sub burst[ISI]");
    XBIT(data, 4, "N ACK channel");

    nsub += 1;
    for (j = 0; j < nsub; j++) {
        bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type) / 4;

        XBIT(data, 10, "Duration");
        XBIT(sbdi,  1, "Sub-Burst DIUC Indicator");
        XBIT(data,  1, "Reserved");

        if (sbdi) {
            XBIT(data, 4, "DIUC");
            XBIT(data, 2, "Repetition Coding Indication");
            XBIT(data, 2, "Reserved");
        }

        XBIT(data, 4, "ACID");
        XBIT(data, 1, "AI_SN");
        XBIT(data, 2, "SPID");
        XBIT(data, 1, "ACK disable");
        XBIT(ddci, 2, "Dedicated DL Control Indicator");
        XBIT(data, 2, "Reserved");

        if (ddci & 1) {
            XBIT(dur, 4, "Duration (d)");

            if (dur != 0) {
                XBIT(ind, 6, "Allocation Index");
                XBIT(per, 3, "Period (p)");
                XBIT(ofs, 3, "Frame offset");
            }
        }
        if ((ddci & 2) == 2) {
            bit += Dedicated_DL_Control_IE(tree, bufptr, BIT_TO_NIB(bit), length, tvb);
        }
    }

    if (include_cor2_changes)
    {
        /* CRC-16 is always appended */
        data = BIT_BITS(bit, bufptr, 16);
        generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
        /* calculate the CRC */
        calculated_crc = wimax_mac_calc_crc16(tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
        if (data != calculated_crc)
        {
            proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
        }
        bit += 16;
    }

    return (BIT_TO_NIB(bit) - offset);
}

gint MIMO_DL_Chase_HARQ_sub_burst_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* offset of IE in nibbles, length is variable */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    proto_item *generic_item = NULL;
    gint nsub, mui, dci, akd;
    gint i, j;
    guint16 calculated_crc;

    bit = NIB_TO_BIT(offset);

    /* 8.4.5.3.21 table 286p */
    ti = proto_tree_add_text(diuc_tree, tvb, BITHI(bit, 1), "MIMO DL Chase HARQ sub-burst IE");
    tree = proto_item_add_subtree(ti, ett_286p);

    XBIT(nsub, 4, "N sub burst[ISI]");
    XBIT(data, 6, "N ACK channel");

    nsub += 1;
    for (j = 0; j < nsub; j++) {
        XBIT(mui, 1, "MU Indicator");
        XBIT(dci, 1, "Dedicated MIMO DL Control Indicator");
        XBIT(akd, 1, "ACK Disable");
        if (mui == 0) {
            bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
        }
        if (dci == 1) {
            bit += Dedicated_MIMO_DL_Control_IE(tree, bufptr, bit, length, tvb);
        }
        XBIT(data, 10, "Duration");
        for (i = 0; i < N_layer; i++) {
            if (mui == 1) {
                bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
            }
            XBIT(data, 4, "DIUC");
            XBIT(data, 2, "Repetition Coding Indication");
            if (akd == 0) {
                XBIT(data, 4, "ACID");
                XBIT(data, 1, "AI_SN");
            }
        }
    }
    /* Padding to nibble */
    data = BIT_PADDING(bit, 4);
    if (data) {
        proto_tree_add_text(tree, tvb, BITHI(bit,data), "Padding: %d bits", data);
        bit += data;
    }

    if (include_cor2_changes)
    {
        /* CRC-16 is always appended */
        data = BIT_BITS(bit, bufptr, 16);
        generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
        /* calculate the CRC */
        calculated_crc = wimax_mac_calc_crc16(tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
        if (data != calculated_crc)
        {
            proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
        }
        bit += 16;
    }

    return (BIT_TO_NIB(bit) - offset);
}

gint MIMO_DL_IR_HARQ_sub_burst_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* offset of IE in nibbles, length is variable */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    proto_item *generic_item = NULL;
    gint nsub, mui, dci, akd;
    gint i, j;
    guint16 calculated_crc;

    bit = NIB_TO_BIT(offset);

    /* 8.4.5.3.21 table 286q */
    ti = proto_tree_add_text(diuc_tree, tvb, BITHI(bit, 4), "MIMO DL IR HARQ sub-burst IE");
    tree = proto_item_add_subtree(ti, ett_286q);

    XBIT(nsub, 4, "N sub burst[ISI]");
    XBIT(data, 6, "N ACK channel");

    nsub += 1;
    for (j = 0; j < nsub; j++) {
        XBIT(mui, 1, "MU Indicator");
        XBIT(dci, 1, "Dedicated MIMO DL Control Indicator");
        XBIT(akd, 1, "ACK Disable");
        if (mui == 0) {
            bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
        }
        if (dci == 1) {
            bit += Dedicated_MIMO_DL_Control_IE(tree, bufptr, bit, length, tvb);
        }
        XBIT(data, 4, "N(SCH)");
        for (i = 0; i < N_layer; i++) {
            if (mui == 1) {
                bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
            }
            XBIT(data, 4, "N(EP)");
            if (akd) {
                XBIT(data, 2, "SPID");
                XBIT(data, 4, "ACID");
                XBIT(data, 1, "AI_SN");
            }
        }
    }

    if (include_cor2_changes)
    {
        /* CRC-16 is always appended */
        data = BIT_BITS(bit, bufptr, 16);
        generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
        /* calculate the CRC */
        calculated_crc = wimax_mac_calc_crc16(tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
        if (data != calculated_crc)
        {
            proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
        }
        bit += 16;
    }

    return (BIT_TO_NIB(bit) - offset);
}

gint MIMO_DL_IR_HARQ_for_CC_sub_burst_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* offset of IE in nibbles, length is variable */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    proto_item *generic_item = NULL;
    gint nsub, mui, dci, akd;
    gint i, j;
    guint16 calculated_crc;

    bit = NIB_TO_BIT(offset);

    /* 8.4.5.3.21 table 286r */
    ti = proto_tree_add_text(diuc_tree, tvb, BITHI(bit, 1), "MIMO DL IR HARQ for CC sub-burst IE");
    tree = proto_item_add_subtree(ti, ett_286r);

    XBIT(nsub, 4, "N sub burst[ISI]");
    XBIT(data, 6, "N ACK channel");

    nsub += 1;
    for (j = 0; j < nsub; j++) {
        XBIT(mui, 1, "MU Indicator");
        XBIT(dci, 1, "Dedicated MIMO DL Control Indicator");
        XBIT(akd, 1, "ACK Disable");
        if (mui == 0) {
            bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
        }
        if (dci == 1) {
            bit += Dedicated_MIMO_DL_Control_IE(tree, bufptr, bit, length, tvb);
        }
        XBIT(data, 10, "Duration");
        for (i = 0; i < N_layer; i++) {
            if (mui == 1) {
                bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
            }
            XBIT(data, 4, "DIUC");
            XBIT(data, 2, "Repetition Coding Indication");
            if (akd == 0) {
                XBIT(data, 4, "ACID");
                XBIT(data, 1, "AI_SN");
                XBIT(data, 2, "SPID");
            }
        }
    }

    if (include_cor2_changes)
    {
        /* CRC-16 is always appended */
        data = BIT_BITS(bit, bufptr, 16);
        generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
        /* calculate the CRC */
        calculated_crc = wimax_mac_calc_crc16(tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
        if (data != calculated_crc)
        {
            proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
        }
        bit += 16;
    }

    return (BIT_TO_NIB(bit) - offset);
}

gint MIMO_DL_STC_HARQ_sub_burst_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* offset of IE in nibbles, length is variable */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    proto_item *generic_item = NULL;
    gint nsub, sbi, txc, akd, dmci;
    gint j;
    guint16 calculated_crc;

    bit = NIB_TO_BIT(offset);

    /* 8.4.5.3.21 table 286s */
    ti = proto_tree_add_text(diuc_tree, tvb, BITHI(bit, 1), "MIMO DL STC HARQ sub-burst IE");
    tree = proto_item_add_subtree(ti, ett_286s);

    XBIT(nsub, 4, "N sub burst[ISI]");
    XBIT(data, 6, "N ACK channel");

    nsub += 1;
    for (j = 0; j < nsub; j++) {
        XBIT(txc, 2, "TX Count");
        XBIT(data, 10, "Duration");
        XBIT(sbi, 1, "Sub-burst offset indication");
        XBIT(data, 3, "Reserved");
        if (sbi == 1) {
            XBIT(data, 8, "Sub-burst offset");
        }
        bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
        XBIT(akd, 1, "ACK Disable");
        if (txc == 0) {
            XBIT(dmci, 1, "Dedicated MIMO DL Control Indicator");
            if (dmci == 1) {
                bit += Dedicated_MIMO_DL_Control_IE(tree, bufptr, bit, length, tvb);
            }
            XBIT(data, 4, "DIUC");
            XBIT(data, 2, "Repetition coding Indication");
        }
        if (akd == 0) {
            XBIT(data, 4, "ACID");
        }
    }

    if (include_cor2_changes)
    {
        /* CRC-16 is always appended */
        data = BIT_BITS(bit, bufptr, 16);
        generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
        /* calculate the CRC */
        calculated_crc = wimax_mac_calc_crc16(tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
        if (data != calculated_crc)
        {
            proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
        }
        bit += 16;
    }

    return (BIT_TO_NIB(bit) - offset);
}

/********************************************************************
 * DL-MAP Extended-2 IEs
 *******************************************************************/

gint MBS_MAP_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended-2 IE = 0 */
    /* 8.4.5.3.12 MBS_MAP_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint mde, dci, s3i;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "MBS_MAP_IE");
    tree = proto_item_add_subtree(ti, ett_286a);

    XBIT(data,  4, "Extended-2 DIUC");
    XBIT(data,  8, "Length");

    XBIT(data, 7, "MBS Zone identifier");
    XBIT(mde, 1, "Macro diversity enhanced");
    if (mde == 1)
    {
        XBIT(data, 2, "Permutation");
        XBIT(data, 5, "DL_PermBase");
        XBIT(data, 2, "PRBS_ID");
        XBIT(data, 7, "OFDMA_Symbol_Offset");
        XBIT(dci, 1, "DIUC_change_indication");
        XBIT(data, 3, "Reserved");
        if (dci == 1) {
            XBIT(data, 3, "Reserved");
            XBIT(data, 3, "Boosting");
            XBIT(data, 4, "DIUC");
            XBIT(data, 6, "No. Subchannels");
            XBIT(data, 6, "No. OFDMA Symbols");
            XBIT(data, 2, "Repetition Coding Indication");
        }
    } else {
        XBIT(data, 4, "DIUC");
        XBIT(data, 16, "CID");
        XBIT(data, 8, "OFDMA Symbols Offset");
        XBIT(data, 6, "Subchannel offset");
        XBIT(data, 3, "Boosting");
        XBIT(s3i, 1, "SLC_3_indication");
        XBIT(data, 6, "No. OFDMA Symbols");
        XBIT(data, 6, "No. Subchannels");
        XBIT(data, 2, "Repetition Coding Indication");
        if (s3i == 1) {
            XBIT(data, 8, "Next MBS_MAP_IE frame offset");
        }
    }
    data = BIT_PADDING(bit, 4);
    if (data) {
        proto_tree_add_text(tree, tvb, BITHI(bit,data), "Padding: %d bits", data);
        bit += data;
    }
    return BIT_TO_NIB(bit);
}

gint HO_Anchor_Active_DL_MAP_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended-2 IE = 1 */
    /* 8.4.5.3.14 [2] HO_Anchor_Active_DL-MAP_IE TODO 1.1 */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "HO_Anchor_Active_DL_MAP_IE");
    tree = proto_item_add_subtree(ti, ett_286c);

    XNIB(data,  1, "Extended-2 DIUC");
    XNIB(data,  2, "Length");
    proto_tree_add_text(diuc_tree, tvb, NIBHI(nib, length-3), "(not implemented)");
    return nib;
}

gint HO_Active_Anchor_DL_MAP_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended-2 IE = 2 */
    /* 8.4.5.3.15 HO_Active_Anchor_DL_MAP_IE TODO 1.1 */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "HO_Active_Anchor_DL_MAP_IE");
    tree = proto_item_add_subtree(ti, ett_286d);

    XNIB(data,  1, "Extended-2 DIUC");
    XNIB(data,  2, "Length");
    proto_tree_add_text(diuc_tree, tvb, NIBHI(nib, length-3), "(not implemented)");
    return nib;
}

gint HO_CID_Translation_MAP_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended-2 IE = 3 */
    /* 8.4.5.3.16 HO_CID_Translation_MAP_IE TODO 1.1 */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "CID_Translation_MAP_IE");
    tree = proto_item_add_subtree(ti, ett_286e);

    XNIB(data,  1, "Extended-2 DIUC");
    XNIB(data,  2, "Length");
    proto_tree_add_text(diuc_tree, tvb, NIBHI(nib, length-3), "(not implemented)");
    return nib;
}

gint MIMO_in_another_BS_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended-2 IE = 4 */
    /* 8.4.5.3.17 [2] MIMO_in_another_BS_IE (not implemented)*/
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "MIMO_in_another_BS_IE");
    tree = proto_item_add_subtree(ti, ett_286f);

    XNIB(data,  1, "Extended-2 DIUC");
    XNIB(data,  2, "Length");
    proto_tree_add_text(diuc_tree, tvb, NIBHI(nib, length-3), "(not implemented)");
    return nib;
}

gint Macro_MIMO_DL_Basic_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* dl-map extended-2 ie = 5 */
    /* 8.4.5.3.18 [2] Macro-MIMO_DL_Basic_IE (not implemented) */
    /* offset of tlv in nibbles, length of tlv in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "Macro_MIMO_DL_Basic_IE");
    tree = proto_item_add_subtree(ti, ett_286g);

    XNIB(data,  1, "Extended-2 DIUC");
    XNIB(data,  2, "Length");
    proto_tree_add_text(diuc_tree, tvb, NIBHI(nib, length-3), "(not implemented)");
    return nib;
}

gint Skip_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended-2 IE = 6 */
    /* 8.4.5.3.20.2 Skip_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "Skip_IE");
    tree = proto_item_add_subtree(ti, ett_286k);

    XBIT(data,  4, "Extended-2 DIUC");
    XBIT(data,  8, "Length");

    XBIT(data,  1, "Mode");
    XBIT(data,  7, "Reserved");

    return BIT_TO_NIB(bit);
}

gint HARQ_DL_MAP_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended-2 IE = 7 */
    /* 8.4.5.3.21 [2] HARQ_DL_MAP_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint len, lastbit, rui, mode, sub_len, pad;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "HARQ_DL_MAP_IE");
    tree = proto_item_add_subtree(ti, ett_286l);

    XBIT(data,  4, "Extended-2 DIUC");
    XBIT(len,  8, "Length");

    XBIT(RCID_Type,  2, "RCID_Type");
    XBIT(data,  2, "Reserved");

    /* while data remains */
    length = NIB_TO_BIT(length);
    /* Subtract extra nibble to be sure to stop in time. */
    lastbit = bit + BYTE_TO_BIT(len) - 14 - 4;
    while (bit < lastbit) {
        XBIT(data,  3, "Boosting");
        XBIT(rui,  1, "Region_ID use indicator");

        if (rui == 0) {
            XBIT(data,  8, "OFDMA symbol offset");
            XBIT(data,  7, "Subchannel offset");
            XBIT(data,  7, "Number of OFDMA symbols");
            XBIT(data,  7, "Number of subchannels");
            if (include_cor2_changes)
            {
                XBIT(data,  1, "Rectangular Sub-Burst Indicator"); /* Implemented: "Rectangular Sub-Burst Indicator" field added */
                XBIT(data,  2, "Reserved");   /* and "Reserved" field resized from 3 bits to 2 bits         */
            }
            else
            {
                XBIT(data,  3, "Reserved");
            }
        } else {
            XBIT(data,  8, "Region_ID");
        }
        XBIT(mode,  4, "Mode");
        XBIT(sub_len,  8, "Sub-burst IE Length");

        /* 8.4.5.3.21 */
        /* length of these are variable, each returns length in nibbles */
        if (mode == 0) {
            DL_HARQ_Chase_sub_burst_IE(tree, bufptr, BIT_TO_NIB(bit), length, tvb);
        } else if (mode == 1) {
            DL_HARQ_IR_CTC_sub_burst_IE(tree, bufptr, BIT_TO_NIB(bit), length, tvb);
        } else if (mode == 2) {
            DL_HARQ_IR_CC_sub_burst_IE(tree, bufptr, BIT_TO_NIB(bit), length, tvb);
        } else if (mode == 3) {
            MIMO_DL_Chase_HARQ_sub_burst_IE(tree, bufptr, BIT_TO_NIB(bit), length, tvb);
        } else if (mode == 4) {
            MIMO_DL_IR_HARQ_sub_burst_IE(tree, bufptr, BIT_TO_NIB(bit), length, tvb);
        } else if (mode == 5) {
            MIMO_DL_IR_HARQ_for_CC_sub_burst_IE(tree, bufptr, BIT_TO_NIB(bit), length, tvb);
        } else if (mode == 6) {
            MIMO_DL_STC_HARQ_sub_burst_IE(tree, bufptr, BIT_TO_NIB(bit), length, tvb);
        } else {
            proto_tree_add_text(tree, tvb, BITHI(bit,1), "(reserved Mode)");
            break; /* cannot continue */
        }
        bit += NIB_TO_BIT(sub_len);
    }

    pad = NIB_TO_BIT(offset) + length - bit;
    if (pad) {
        proto_tree_add_text(tree, tvb, BITHI(bit,pad), "Padding: %d bits",pad);
        bit += pad;
    }
    
    return BIT_TO_NIB(bit);
}

gint HARQ_ACK_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended-2 IE = 8 */
    /* 8.4.5.3.22 HARQ_ACK IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint data;
    gint nib;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "HARQ_ACK_IE");
    tree = proto_item_add_subtree(ti, ett_286u);

    XNIB(data,  1, "Extended-2 DIUC");
    XNIB(data,  2, "Length");

    proto_tree_add_text(diuc_tree, tvb, NIBHI(nib,length-3), "(bitmap data)");

    return nib;
}

gint Enhanced_DL_MAP_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended-2 IE = 9 */
    /* 8.4.5.3.23 Enhanced DL MAP IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint numass, n_cid;
    gint i, n;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "Enhanced_DL-MAP_IE");
    tree = proto_item_add_subtree(ti, ett_286v);

    XBIT(data,  4, "Extended-2 DIUC");
    XBIT(data,  8, "Length");

    XBIT(numass, 4, "Num_Assignment");
    for (i = 0; i < numass; i++) {
        if (INC_CID == 1) {
            XBIT(n_cid, 8, "N_CID");
            for (n = 0; n < n_cid; n++) {
                XBIT(data, 16, "CID");
            }
        }
        XBIT(data, 4, "DIUC");
        XBIT(data, 3, "Boosting");
        XBIT(data, 2, "Repetition Coding Indication");
        XBIT(data, 8, "Region_ID");
        XBIT(data, 3, "Reserved");
    }
    return BIT_TO_NIB(bit);
}

gint Closed_loop_MIMO_DL_Enhanced_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended-2 IE = 0xA */
    /* 8.4.5.3.24 Closed-loop MIMO DL Enhanced IE (not implemented) */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "CL_MIMO_DL_Enhanced_IE");
    tree = proto_item_add_subtree(ti, ett_286w);

    XNIB(data,  1, "Extended-2 DIUC");
    XNIB(data,  2, "Length");
    proto_tree_add_text(diuc_tree, tvb, NIBHI(nib, length-3), "(not implemented)");
    return nib;
}

gint AAS_SDMA_DL_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended-2 IE = 0xE */
    /* 8.4.5.3.26 AAS_SDMA_DL_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint num_region, num_users, pilot_pattern, encoding_mode, ackch_alloc, cqich_alloc;
    gint aas_preamble = 1;
    gint zone_permut = 0; /* TODO */
    gint i, j;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "AAS_SDMA_DL_IE");
    tree = proto_item_add_subtree(ti, ett_286y);

    XBIT(data,  4, "Extended-2 DIUC");
    XBIT(data,  8, "Length");

    XBIT(RCID_Type,  2, "RCID_Type");
    XBIT(num_region,  4, "Num_Burst_Region");
    XBIT(data,  2, "Reserved");
    for (i = 0; i < num_region; i++) {
        XBIT(data,  8, "OFDMA Symbol Offset");
        if (zone_permut == 0) {
            XBIT(data,  8, "Subchannel offset");
            XBIT(data,  5, "No. OFDMA triple symbols");
            XBIT(data,  6, "No. subchannels");
        } else {
            XBIT(data,  6, "Subchannel offset");
            XBIT(data,  7, "No. OFDMA triple symbols");
            XBIT(data,  6, "No. subchannels");
        }
        XBIT(num_users,  3, "Number of Users");
        XBIT(data,  2, "Reserved");
        for (j = 0; j < num_users; j++) {
            bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
            XBIT(encoding_mode,  2, "Encoding Mode");
            XBIT(cqich_alloc,  1, "CQICH Allocation");
            XBIT(ackch_alloc,  1, "ACKCH Allocation");
            XBIT(pilot_pattern,  1, "Pilot Pattern Modifier");
            if (aas_preamble) {
                XBIT(data,  4, "Preamble Modifier Index");
            }
            if (pilot_pattern) {
                XBIT(data,  2, "Pilot Pattern");
                XBIT(data,  1, "Reserved");
            } else {
                XBIT(data,  3, "Reserved");
            }
            if (encoding_mode == 0x0) {
                XBIT(data,  4, "DIUC");
                XBIT(data,  2, "Repetition Coding Indication");
                XBIT(data,  2, "Reserved");
            }
            if (encoding_mode == 0x1) {
                if (ackch_alloc) {
                    XBIT(data,  5, "ACK CH Index");
                } else {
                    XBIT(data,  1, "Reserved");
                }
                XBIT(data,  4, "DIUC");
                XBIT(data,  2, "Repetition Coding Indication");
                XBIT(data,  4, "ACID");
                XBIT(data,  1, "AI_SN");
            }
            if (encoding_mode == 0x2) {
                if (ackch_alloc) {
                    XBIT(data,  5, "ACK CH Index");
                } else {
                    XBIT(data,  1, "Reserved");
                }
                XBIT(data,  4, "N(EP)");
                XBIT(data,  4, "N(SCH)");
                XBIT(data,  2, "SPID");
                XBIT(data,  4, "ACID");
                XBIT(data,  1, "AI_SN");
            }
            if (encoding_mode == 0x3) {
                if (ackch_alloc) {
                    XBIT(data,  5, "ACK CH Index");
                    XBIT(data,  2, "Reserved");
                } else {
                    XBIT(data,  3, "Reserved");
                }
                XBIT(data,  4, "DIUC");
                XBIT(data,  2, "Repetition Coding Indication");
                XBIT(data,  2, "SPID");
                XBIT(data,  4, "ACID");
                XBIT(data,  1, "AI_SN");
            }
            if (cqich_alloc) {
                XBIT(data,  6, "Allocation Index");
                XBIT(data,  3, "Period (p)");
                XBIT(data,  3, "Frame offset");
                XBIT(data,  4, "Duration (d)");
            }
        }
    }
    data = BIT_PADDING(bit,4);
    /* Should this be an optional field? Or do we want it, even if it has a length of zero? */
    proto_tree_add_text(tree, tvb, BITHI(bit,data), "Padding: %d bits", data);
    bit += data;

    return BIT_TO_NIB(bit);
}



/********************************************************************
 * DL-MAP Extended IEs
 *******************************************************************/

gint Channel_Measurement_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 0 */
    /* 8.4.5.3.5 [1] Channel_Measurement_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "Channel_Measurement_IE");
    tree = proto_item_add_subtree(ti, ett_280);

    XNIB(data,  1, "Extended DIUC");
    XNIB(data,  1, "Length");

    XNIB(data, 2, "Channel Nr");
    XNIB(data, 2, "OFDMA Symbol Offset");
    data = NIB_WORD(nib, bufptr);
    proto_tree_add_text(tree, tvb, NIBHI(nib,4), "CID: %d", data);
    nib += 4;
    return nib;
}

gint STC_Zone_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 1 */
    /* 8.4.5.3.4 STC_Zone_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    /* set globals: STC_Zone_Dedicated_Pilots, STC_Zone_Matrix
     * used in 8.4.5.3.21.1 Dedicated MIMO Control IE 286t */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "STC_Zone_IE");
    tree = proto_item_add_subtree(ti, ett_279);

    XBIT(data,  4, "Extended DIUC");
    XBIT(data,  4, "Length");

    XBIT(data, 8, "OFDMA Symbol Offset");
    XBIT(data, 2, "Permutations");
    XBIT(data, 1, "Use All SC indicator");
    XBIT(data, 2, "STC");
    XBIT(STC_Zone_Matrix, 2, "Matrix indicator");
    XBIT(data, 5, "DL_PermBase");
    XBIT(data, 2, "PRBS_ID");
    XBIT(data, 2, "AMC type");
    XBIT(data, 1, "Midamble Presence");
    XBIT(data, 1, "Midamble Boosting");
    XBIT(data, 1, "2/3 antenna select");
    XBIT(STC_Zone_Dedicated_Pilots, 1, "Dedicated Pilots");
    XBIT(data, 4, "Reserved");

    return BIT_TO_NIB(bit);
}

gint AAS_DL_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 2 */
    /* 8.4.5.3.3 AAS_DL_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "AAS_DL_IE");
    tree = proto_item_add_subtree(ti, ett_278);

    XBIT(data,  4, "Extended DIUC");
    XBIT(data,  4, "Length");

    XBIT(data, 8, "OFDMA Symbol Offset");
    XBIT(data, 3, "Permutation");
    XBIT(data, 6, "DL_PermBase");
    XBIT(data, 2, "Downlink_preamble_config");
    XBIT(data, 1, "Preamble type");
    XBIT(data, 2, "PRBS_ID");
    XBIT(data, 1, "Diversity Map");
    XBIT(data, 1, "Reserved");

    return BIT_TO_NIB(bit);
}

gint Data_location_in_another_BS_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 3 */
    /* 8.4.5.3.6 Data_location_in_another_BS_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "Data location in another BS IE");
    tree = proto_item_add_subtree(ti, ett_281);

    XBIT(data,  4, "Extended DIUC");
    XBIT(data,  4, "Length");

    XBIT(data, 2, "Segment");
    XBIT(data, 6, "Used subchannels");
    XBIT(data, 4, "DIUC");
    XBIT(data, 3, "Frame Advance");
    XBIT(data, 1, "Reserved");
    XBIT(data, 8, "OFDMA Symbol Offset");
    XBIT(data, 6, "Subchannel Offset");
    XBIT(data, 3, "Boosting");
    XBIT(data, 7, "Preamble Index");
    XBIT(data, 8, "No. OFDMA Symbols");
    XBIT(data, 6, "No. Subchannels");
    XBIT(data, 2, "Repetition Coding Indication");
    XBIT(data, 16, "CID");

    return BIT_TO_NIB(bit);
}

gint CID_Switch_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 4 */
    /* 8.4.5.3.7 [1] CID_Switch_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    nib = offset;

    INC_CID = INC_CID ? 0 : 1;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "CID_Switch_IE");
    proto_item_append_text(ti, " (INC_CID = %d)",INC_CID);
    tree = proto_item_add_subtree(ti, ett_282);

    XNIB(data,  1, "Extended DIUC");
    XNIB(data,  1, "Length");

    return nib;
}

gint MIMO_DL_Basic_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 5 */
    /* 8.4.5.3.8 MIMO_DL_Basic_IE (not implemented) */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "MIMO_DL_Basic_IE");
    tree = proto_item_add_subtree(ti, ett_283);

    XNIB(data,  1, "Extended-2 DIUC");
    XNIB(data,  2, "Length");
    proto_tree_add_text(diuc_tree, tvb, NIBHI(nib, length-2), "(not implemented)");
    return nib;
}

gint MIMO_DL_Enhanced_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 6 */
    /* 8.4.5.3.9 MIMO_DL_Enhanced_IE (not implemented) */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "MIMO_DL_Enhanced_IE");
    tree = proto_item_add_subtree(ti, ett_284);

    XNIB(data,  1, "Extended-2 DIUC");
    XNIB(data,  2, "Length");
    proto_tree_add_text(diuc_tree, tvb, NIBHI(nib, length-2), "(not implemented)");
    return nib;
}

gint HARQ_Map_Pointer_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 7 */
    /* 8.4.5.3.10 [2] HARQ_Map_Pointer_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint length_in_bits, rep, map, diuc, slots, idle, sleep, mask_len;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "HARQ_Map_Pointer_IE");
    tree = proto_item_add_subtree(ti, ett_285);

    XBIT(data,  4, "Extended DIUC");
    XBIT(data,  4, "Length");

    length_in_bits = NIB_TO_BIT(length-1);
    while (bit < length_in_bits) {
        XBIT(diuc, 4, "DIUC");
        XBIT(slots, 8, "No. Slots");
        XBIT(rep, 2, "Repetition Coding Indication");
        XBIT(map, 2, "Map Version");
        if (map == 2) {
            XBIT(idle, 1, "Idle users");
            XBIT(sleep, 1, "Sleep users");
            XBIT(mask_len, 2, "CID Mask Length");
            if (mask_len == 0) {
                /* 12 bits */
                proto_tree_add_text(diuc_tree, tvb, BITHI(bit,12), "CID Mask: 12 bits");
                bit += 12;
            } else if (mask_len == 1) {
                /* 20 bits */
                proto_tree_add_text(diuc_tree, tvb, BITHI(bit,20), "CID Mask: 20 bits");
                bit += 20;
            } else if (mask_len == 2) {
                /* 36 bits */
                proto_tree_add_text(diuc_tree, tvb, BITHI(bit,36), "CID Mask: 36 bits");
                bit += 36;
            } else if (mask_len == 3) {
                /* 52 bits */
                proto_tree_add_text(diuc_tree, tvb, BITHI(bit,52), "CID Mask: 52 bits");
                bit += 52;
            }
        }
    }
    return BIT_TO_NIB(bit);
}

gint PHYMOD_DL_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 8 */
    /* 8.4.5.3.11 PHYMOD_DL_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint pmt;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "PHYMOD_DL_IE");
    tree = proto_item_add_subtree(ti, ett_286);

    XBIT(data,  4, "Extended DIUC");
    XBIT(data,  4, "Length");

    XBIT(pmt, 1, "Preamble Modifier Type");
    if (pmt == 0) {
        XBIT(data, 4, "Preamble frequency shift index");
    } else {
        XBIT(data, 4, "Preamble Time Shift Index");
    }
    XBIT(data, 1, "Pilot Pattern Modifier");
    XBIT(data, 2, "Pilot Pattern Index");

    return BIT_TO_NIB(bit);
}

gint Broadcast_Control_Pointer_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 0xA */
    /* 8.4.5.3.25 Broadcast Control Pointer IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint skip;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "Broadcast Control Pointer IE");
    tree = proto_item_add_subtree(ti, ett_286x);

    XBIT(data,  4, "Extended DIUC");
    XBIT(data,  4, "Length");

    XBIT(data,  7, "DCD_UCD Transmission Frame");
    XBIT(skip,  1, "Skip Broadcast_System_Update");
    if (skip == 0) {
        XBIT(data,  1, "Broadcast_System_Update_Type");
        XBIT(data,  7, "Broadcast_System_Update_Transmission_Frame");
    }
    return BIT_TO_NIB(bit);
}

gint DL_PUSC_Burst_Allocation_in_Other_Segment_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 0xB */
    /* 8.4.5.3.13 DL PUSC Burst Allocation in Other Segment IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "DL_PUSC_Burst_Allocation_in_Other_Segment_IE");
    tree = proto_item_add_subtree(ti, ett_286b);

    XBIT(data,  4, "Extended DIUC");
    XBIT(data,  4, "Length");

    XBIT(data, 16, "CID");
    XBIT(data,  4, "DIUC");
    XBIT(data,  2, "Segment");
    XBIT(data,  3, "Boosting");
    XBIT(data,  5, "IDcell");
    XBIT(data,  5, "DL_PermBase");
    XBIT(data,  2, "PRBS_ID");
    XBIT(data,  2, "Repetition coding indication");
    XBIT(data,  6, "Used Subchannels");
    XBIT(data,  8, "OFDMA symbol offset");
    XBIT(data,  1, "Reserved");
    XBIT(data,  7, "# OFDMA symbols");
    XBIT(data,  6, "Subchannel offset");
    XBIT(data,  6, "# subchannels");
    XBIT(data,  7, "Reserved");
    return BIT_TO_NIB(bit);
}

gint PUSC_ASCA_Alloc_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 0xC */
    /* 8.4.5.3.27 PUSC_ASCA_Alloc_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "PUSC_ASCA_Alloc_IE");
    tree = proto_item_add_subtree(ti, ett_286z);

    XBIT(data,  4, "Extended DIUC");
    XBIT(data,  4, "Length");
    XBIT(data,  4, "DIUC");
    XBIT(data, 12, "Short Basic CID");
    XBIT(data,  8, "OFDMA Symbol offset");
    XBIT(data,  6, "Subchannel offset");
    XBIT(data,  7, "# OFDMA Symbols");
    XBIT(data,  6, "# Symbols");
    XBIT(data,  2, "Repetition Coding Information");
    XBIT(data,  4, "Permutation ID");
    XBIT(data,  7, "Reserved");

    return BIT_TO_NIB(bit);
}

gint UL_interference_and_noise_level_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* DL-MAP Extended IE = 0xF */
    /* 8.4.5.3.19 UL_interference_and_noise_level_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint bitmap;

    nib = offset;

    ti = proto_tree_add_text(diuc_tree, tvb, NIBHI(offset, length), "UL_interference_and_noise_level_IE");
    tree = proto_item_add_subtree(ti, ett_286h);

    XNIB(data,  1, "Extended DIUC");
    XNIB(data,  1, "Length");

    XNIB(bitmap,  2, "Bitmap");

    if (bitmap & 0x01) {
        XNIB(data, 2, "CQI/ACK/Periodic Ranging region NI");
    }
    if (bitmap & 0x02) {
        XNIB(data, 2, "PUSC region NI");
    }
    if (bitmap & 0x04) {
        XNIB(data, 2, "Optional PUSC region NI");
    }
    if (bitmap & 0x08) {
        XNIB(data, 2, "AMC region NI");
    }
    if (bitmap & 0x10) {
        XNIB(data, 2, "AAS region NI");
    }
    if (bitmap & 0x20) {
        XNIB(data, 2, "Periodic Ranging region NI");
    }
    if (bitmap & 0x40) {
        XNIB(data, 2, "Sounding region NI");
    }
    if (bitmap & 0x80) {
        XNIB(data, 2, "MIMO region NI");
    }

    return nib;
}

/********************************************************************
 * DL-MAP Plugin
 *******************************************************************/

extern gint wimax_decode_ulmapc(proto_tree *base_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb);


gint dissect_dlmap_ie(proto_tree *ie_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* decode a single DL-MAP IE and return the
     * length of the IE in nibbles
     * offset = start of IE (nibbles)
     * length = total length of bufptr (nibbles) */
    proto_item *ti = NULL;
    proto_tree *tree = NULL;

    gint nibble = offset;
    gint diuc;
    gint ext2_diuc;
    gint len;
    gint ext_diuc;

    gint alt_format = 0;
    guint data = 0;
    gint i;
    gint papr = 0;
    gint ie_len = 9;

    gint n_cid;

    /* 8.4.5.3 DL-MAP IE format - table 275 */
    diuc = NIB_NIBBLE(nibble, bufptr);
    if (diuc == 14)
    {
        /* 8.4.5.3.2.2 [2] Extended-2 DIUC dependent IE table 277b */
        ext2_diuc = NIB_NIBBLE(1+nibble, bufptr);
        len = NIB_BYTE(1+nibble+1, bufptr);

        ti = proto_tree_add_uint(ie_tree, hf_dlmap_ie_diuc, tvb, NIBHI(nibble, 1+3+len*2), diuc);
        proto_item_append_text(ti, " (Extended-2)");
        tree = proto_item_add_subtree(ti, ett_277b);
        nibble++;

        len = 3 + BYTE_TO_NIB(len);

        /* table 277c [2] */
        switch (ext2_diuc)
        {
            case 0x00:
                /* 8.4.5.3.12 MBS_MAP_IE */
                nibble = MBS_MAP_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x01:
                /* 8.4.5.3.14 HO_Anchor_Active_DL-MAP_IE */
                nibble = HO_Anchor_Active_DL_MAP_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x02:
                /* 8.4.5.3.15 HO_Active_Anchor_DL_MAP_IE */
                nibble = HO_Active_Anchor_DL_MAP_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x03:
                /* 8.4.5.3.16 HO_CID_Translation_MAP_IE */
                nibble = HO_CID_Translation_MAP_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x04:
                /* 8.4.5.3.17 MIMO_in_another_BS_IE */
                nibble = MIMO_in_another_BS_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x05:
                /* 8.4.5.3.18 Macro-MIMO_DL_Basic_IE */
                nibble = Macro_MIMO_DL_Basic_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x06:
                /* 8.4.5.3.20.2 Skip_IE */
                nibble = Skip_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x07:
                /* 8.4.5.3.21 HARQ_DL_MAP_IE */
                nibble = HARQ_DL_MAP_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x08:
                /* 8.4.5.3.22 HARQ_ACK IE */
                nibble = HARQ_ACK_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x09:
                /* 8.4.5.3.23 Enhanced DL MAP IE */
                nibble = Enhanced_DL_MAP_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x0a:
                /* 8.4.5.3.24 Closed-loop MIMO DL Enhanced IE */
                nibble = Closed_loop_MIMO_DL_Enhanced_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x0b:
                nibble = MIMO_DL_Basic_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x0c:
                nibble = MIMO_DL_Enhanced_IE(tree, bufptr, nibble, len, tvb);
                break;

            case 0x0e:
                nibble = AAS_SDMA_DL_IE(tree, bufptr, nibble, len, tvb);
                break;

            default:
                proto_tree_add_text(tree, tvb, NIBHI(nibble,len), "(reserved Extended-2 DIUC: %d)", ext2_diuc);
                nibble += len;
                break;

        }
    }
    else if (diuc == 15)
    {
        /* 8.4.5.3.2.1 [1] Extended DIUC dependent IE - table 277 */
        ext_diuc = NIB_NIBBLE(1+nibble, bufptr);
        len = NIB_NIBBLE(1+nibble+1, bufptr);

        ti = proto_tree_add_uint(ie_tree, hf_dlmap_ie_diuc,  tvb, NIBHI(nibble, 1+2+len*2), diuc);
        proto_item_append_text(ti, " (Extended)");
        tree = proto_item_add_subtree(ti, ett_277);
        nibble++;

        len = 2 + BYTE_TO_NIB(len);

        /* TODO 8.4.5.3.27 PUSC_ASCA_IE -- unspecified ExtDIUC? */

        /* 8.4.5.3.2.1 table 277a */
        switch (ext_diuc)
        {
            case 0x00:
                /* 8.4.5.3.? Channel_Measurement_IE */
                nibble = Channel_Measurement_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x01:
                /* 8.4.5.3.4 STC_Zone_IE */
                nibble = STC_Zone_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x02:
                /* 8.4.5.3.3 AAS_DL_IE */
                nibble = AAS_DL_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x03:
                /* 8.4.5.3.6 Data_location_in_another_BS_IE */
                nibble = Data_location_in_another_BS_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x04:
                /* 8.4.5.3.7 CID_Switch_IE */
                nibble = CID_Switch_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x07:
                /* 8.4.5.3.10 HARQ_Map_Pointer_IE */
                nibble = HARQ_Map_Pointer_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x08:
                /* 8.4.5.3.11 PHYMOD_DL_IE */
                nibble = PHYMOD_DL_IE(tree, bufptr, nibble, len, tvb);
                break;

            case 0x0b:
                /* 8.4.5.3.13 DL PUSC Burst Allocation in Other Segment IE */
                nibble = DL_PUSC_Burst_Allocation_in_Other_Segment_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x0c:
                nibble = PUSC_ASCA_Alloc_IE(tree, bufptr, nibble, len, tvb);
                break;

            case 0x0f:
                /* 8.4.5.3.19 UL_interference_and_noise_level_IE */
                nibble = UL_interference_and_noise_level_IE(tree, bufptr, nibble, len, tvb);
                break;

            default:
                proto_tree_add_text(tree, tvb, NIBHI(nibble,len), "(reserved Extended DIUC: %d)", ext_diuc);
                nibble += len;
                break;
        }
    }
    else
    {
        /* Downlink IE */
        alt_format = 0;
        data = 0;
        papr = 0;
        ie_len = 9;

        /* TODO: alt_format = 1 if (Permutation == 0x11) and (AMC type is 2x3 or 1x6) */

        /* precalculate IE len for correct highlighting */
        if (INC_CID && !sub_dl_ul_map) {
            ie_len += 2 + (NIB_BYTE(nibble+1, bufptr) * 4);
        }

        /* DL-MAP_IE */
        ti = proto_tree_add_uint(ie_tree, hf_dlmap_ie_diuc,  tvb, NIBHI(nibble, ie_len), diuc);
        tree = proto_item_add_subtree(ti, ett_275_1);
        nibble += 1;

        if (diuc == 13) {
            /* 8.4.5.3.1 [1] Gap/PAPR Reduction */
            papr = 1;
            proto_item_append_text(ti, " (Gap/PAPR Reduction)");
        }


        if (INC_CID)
        {
            n_cid = NIB_BYTE(nibble, bufptr);
            proto_tree_add_uint(tree, hf_dlmap_ie_ncid, tvb, NIBHI(nibble, 2), n_cid);
            nibble += 2;

            for (i = 0; i < n_cid; i++)
            {
                if (sub_dl_ul_map) {
                    /* RCID_IE 8.4.5.3 and 8.4.5.3.20.1, only part of SUB-DL-UL-MAP */
                    /* RCID_Type comes from 6.3.2.3.43.2 [2] Format_configuration_IE in Compact_DL-MAP_IE */
                    nibble += RCID_IE(tree, bufptr, nibble*4, length, tvb, RCID_Type) / 4;
                } else {
                    data = NIB_WORD(nibble, bufptr);
                    proto_tree_add_uint(tree, hf_dlmap_ie_cid, tvb, NIBHI(nibble, 4), data);
                    nibble += 4;
                }
            }
        }

        data = NIB_LONG(nibble, bufptr);
        if (alt_format) {
            proto_tree_add_uint(tree, hf_dlmap_ie_offsym2,   tvb, NIBHI(nibble, 8), data);
            proto_tree_add_uint(tree, hf_dlmap_ie_offsub2,   tvb, NIBHI(nibble, 8), data);
            proto_tree_add_uint(tree, hf_dlmap_ie_boosting2, tvb, NIBHI(nibble, 8), data);
            proto_tree_add_uint(tree, hf_dlmap_ie_numsym2,   tvb, NIBHI(nibble, 8), data);
            proto_tree_add_uint(tree, hf_dlmap_ie_numsub2,   tvb, NIBHI(nibble, 8), data);
            proto_tree_add_uint(tree, hf_dlmap_ie_rep2,      tvb, NIBHI(nibble, 8), data);
        } else {
            proto_tree_add_uint(tree, hf_dlmap_ie_offsym,    tvb, NIBHI(nibble, 8), data);
            proto_tree_add_uint(tree, hf_dlmap_ie_offsub,    tvb, NIBHI(nibble, 8), data);
            proto_tree_add_uint(tree, hf_dlmap_ie_boosting,  tvb, NIBHI(nibble, 8), data);
            proto_tree_add_uint(tree, hf_dlmap_ie_numsym,    tvb, NIBHI(nibble, 8), data);
            proto_tree_add_uint(tree, hf_dlmap_ie_numsub,    tvb, NIBHI(nibble, 8), data);
            proto_tree_add_uint(tree, hf_dlmap_ie_rep,       tvb, NIBHI(nibble, 8), data);
        }
        nibble += 8;
    }

    /* length in nibbles */
    return (nibble - offset);
}


void dissect_mac_mgmt_msg_dlmap_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *base_tree)
{
    /* 6.3.2.3.2 [2] DL-MAP table 16 */
    guint offset = 0;
    gint length, nib, pad;
    proto_item *ti         = NULL;
    proto_tree *dlmap_tree = NULL;
    proto_tree *ie_tree    = NULL;
    proto_tree *phy_tree   = NULL;
    gint tvb_len           = tvb_reported_length(tvb);
    /* XXX This should be removed, and regular tvb accessors should be used instead. */
    const guint8 *bufptr   = tvb_get_ptr(tvb, offset, tvb_len);

    INC_CID = 0;

    /* add protocol */
    ti = proto_tree_add_protocol_format(base_tree, proto_mac_mgmt_msg_dlmap_decoder, tvb, offset, tvb_len, "DL-MAP (%u bytes)", tvb_len);
    dlmap_tree = proto_item_add_subtree(ti, ett_dlmap);

    /* Decode and display the DL-MAP */
    proto_tree_add_item(dlmap_tree, hf_dlmap_message_type, tvb, offset, 1, FALSE);
    offset++;
    /* PHY Synchronization Field 8.4.5.1 */
    {
        ti = proto_tree_add_text(dlmap_tree, tvb, offset, 4, "Phy Synchronization Field");
        phy_tree = proto_item_add_subtree(ti, ett_275_phy);
        proto_tree_add_item(phy_tree, hf_dlmap_phy_fdur_ms, tvb, offset, 1, FALSE);
        proto_tree_add_item(phy_tree, hf_dlmap_phy_fdur_per_sec, tvb, offset, 1, FALSE);
        proto_tree_add_item(phy_tree, hf_dlmap_phy_fdur, tvb, offset, 1, FALSE);
        offset++;
        proto_tree_add_item(phy_tree, hf_dlmap_phy_fnum, tvb, offset, 3, FALSE);
        offset += 3;
    }
    proto_tree_add_item(dlmap_tree, hf_dlmap_dcd, tvb, offset, 1, FALSE);
    offset++;
    proto_tree_add_item(dlmap_tree, hf_dlmap_bsid, tvb, offset, 6, FALSE);
    offset += 6;
    proto_tree_add_item(dlmap_tree, hf_dlmap_ofdma_sym, tvb, offset, 1, FALSE);
    offset++;

    /* DL-MAP IEs */
    length = tvb_len - offset; /* remaining length in bytes */
    ti = proto_tree_add_text(dlmap_tree, tvb, offset, length, "DL-MAP IEs (%d bytes)", length);
    ie_tree = proto_item_add_subtree(ti, ett_dlmap_ie);

    length = BYTE_TO_NIB(length); /* convert length to nibbles */

    nib = BYTE_TO_NIB(offset);
    while (nib < ((tvb_len*2)-1)) {
        nib += dissect_dlmap_ie(ie_tree, bufptr, nib, tvb_len * 2, tvb);
    }
    pad = NIB_PADDING(nib);
    if (pad) {
        proto_tree_add_text(dlmap_tree, tvb, NIBHI(nib,1), "Padding nibble");
        nib++;
    }
}

gint wimax_decode_dlmapc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *base_tree)
{
    /* 8.4.5.6.1 [2] Compressed DL-MAP */
    /* decode a compressed dl-map and return the length in bytes; */
    /* if there is a compressed ul-map, also decode that and include in the length */
    guint offset = 0;
    proto_item *ti = NULL;
    proto_item *ti_phy = NULL;
    proto_item *ti_dlmap_ies = NULL;
    proto_item *generic_item = NULL;
    proto_tree *tree = NULL;
    proto_tree *ie_tree = NULL;
    proto_tree *phy_tree = NULL;
    gint ulmap_appended;
    guint length, lennib, pad;
    guint mac_len, dl_ie_count;
    guint           tvb_len = tvb_reported_length(tvb);
    /* XXX This should be removed, and regular tvb accessors should be used instead. */
    const guint8 * bufptr  = tvb_get_ptr(tvb, offset, tvb_len);
    guint          nib     = 0;
    guint32	   mac_crc, calculated_crc;

    /* update the info column */
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Compressed DL-MAP");

    INC_CID = 0;

    length = tvb_get_ntohs(tvb, offset) & 0x07FF; /* compressed map length is 11 bits */
    mac_len = length;
    lennib = BYTE_TO_NIB(length);

    ulmap_appended = (tvb_get_guint8(tvb, offset) >> 4) & 1; /* UL MAP appended? */

    /* display MAC Compressed DL-MAP and create subtree */
    ti = proto_tree_add_protocol_format(base_tree, proto_mac_mgmt_msg_dlmap_decoder, tvb, offset, length, "Compressed DL-MAP (%u bytes)", length);
    tree = proto_item_add_subtree(ti, ett_305);

    /* decode dlmap fields */
    proto_tree_add_item(tree, hf_dlmapc_compr,    tvb, offset,   2, FALSE);
    proto_tree_add_item(tree, hf_dlmapc_ulmap,    tvb, offset,   2, FALSE);
    proto_tree_add_item(tree, hf_dlmapc_rsv,      tvb, offset,   2, FALSE);
    proto_tree_add_item(tree, hf_dlmapc_len,      tvb, offset,   2, FALSE);
    /* PHY Synchronization Field 8.4.5.1 */
    {
        ti_phy = proto_tree_add_text(tree, tvb, offset+2, 4, "Phy Synchronization Field");
        phy_tree = proto_item_add_subtree(ti_phy, ett_275_phy);
        proto_tree_add_item(phy_tree, hf_dlmap_phy_fdur_ms, tvb, offset+2, 1, FALSE);
        proto_tree_add_item(phy_tree, hf_dlmap_phy_fdur_per_sec, tvb, offset+2, 1, FALSE);
        proto_tree_add_item(phy_tree, hf_dlmap_phy_fnum, tvb, offset+3, 3, FALSE);
    }
    proto_tree_add_item(tree, hf_dlmap_dcd,       tvb, offset+6, 1, FALSE);
    proto_tree_add_item(tree, hf_dlmapc_opid,     tvb, offset+7, 1, FALSE);
    proto_tree_add_item(tree, hf_dlmapc_secid,    tvb, offset+8, 1, FALSE);
    proto_tree_add_item(tree, hf_dlmap_ofdma_sym, tvb, offset+9, 1, FALSE); /* 2005 */
    proto_tree_add_item(tree, hf_dlmapc_count,    tvb, offset+10,1, FALSE);
    dl_ie_count = tvb_get_guint8(tvb, offset + 10);
    offset += 11;
    nib = BYTE_TO_NIB(offset);

    /* DL-MAP IEs */
    length -= 15; /* remaining length in bytes (11 bytes above + CRC at end) */
    if (dl_ie_count) {
        ti_dlmap_ies = proto_tree_add_text(tree, tvb, offset, length, "DL-MAP IEs (%d bytes)", length);
        ie_tree = proto_item_add_subtree(ti_dlmap_ies, ett_dlmap_ie);

        length = BYTE_TO_NIB(mac_len - sizeof(mac_crc) - 1); /* convert length to nibbles */

        while (dl_ie_count--) {
            nib += dissect_dlmap_ie(ie_tree, bufptr, nib, tvb_len * 2, tvb);
        }
        pad = NIB_PADDING(nib);
        if (pad) {
            proto_tree_add_text(tree, tvb, NIBHI(nib,1), "Padding nibble");
            nib++;
        }
    }

    if (ulmap_appended) {
        /* Replace the text of items to set the correct length in bytes.*/
        proto_item_set_text(ti, "Compressed DL-MAP (%u bytes)", NIB_ADDR(nib));
        proto_item_set_text(ti_dlmap_ies, "DL-MAP IEs (%u bytes)",NIB_ADDR(nib)- offset);

        /* set the length of items */
        proto_item_set_end(ti_dlmap_ies, tvb, NIB_ADDR(nib));
        proto_item_set_end(ti, tvb, NIB_ADDR(nib));

        /* update the info column */
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Compressed UL-MAP");

        /* subtract 8 from lennib (CRC) */
        nib += wimax_decode_ulmapc(base_tree, bufptr, nib, lennib - 8, tvb);
    }

    /* CRC is always appended */
    /* check the length */
    if (MIN(tvb_len, tvb_reported_length(tvb)) >= mac_len)
    {   /* get the CRC */
        mac_crc = tvb_get_ntohl(tvb, mac_len - sizeof(mac_crc));
        /* calculate the CRC */
        calculated_crc = wimax_mac_calc_crc32(tvb_get_ptr(tvb, 0, mac_len - sizeof(mac_crc)), mac_len - sizeof(mac_crc));
        /* display the CRC */
        generic_item = proto_tree_add_item(base_tree, hf_mac_header_compress_dlmap_crc, tvb, mac_len - sizeof(mac_crc), sizeof(mac_crc), FALSE);
        if (mac_crc != calculated_crc)
        {
            proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
        }
    }
    else
    {   /* display error message */
        proto_tree_add_protocol_format(base_tree, proto_mac_mgmt_msg_dlmap_decoder, tvb, 0, tvb_len, "CRC missing - the frame is too short (%u bytes)", tvb_len);
    }

    return mac_len;
}

extern gint dissect_ulmap_ie(proto_tree *ie_tree,
    const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb);
extern gint wimax_decode_ulmap_reduced_aas(proto_tree *ie_tree,
    const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb);

gint wimax_decode_sub_dl_ul_map(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *base_tree)
{
    /* decode a SUB-DL-UL-MAP message 6.3.2.3.60 and return the length in bytes */
    /* first three bits are 0x7, which following a compressed DL map indicates this message */
    guint offset = 0;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    proto_tree *ie_tree = NULL;
    proto_item *generic_item = NULL;
    gint data;
    gint i, numie;
    guint16 calculated_crc;

    gint           length = tvb_reported_length(tvb);
    /* XXX This should be removed, and regular tvb accessors should be used instead. */
    const guint8 * bufptr = tvb_get_ptr(tvb, offset, length);
    gint           nib = 0;
    gint           lennib = BYTE_TO_NIB(length);

    sub_dl_ul_map = 1; /* set flag */

    ti = proto_tree_add_text(base_tree, tvb, NIBHI(nib,lennib-nib), "SUB-DL-UL-MAP");
    tree = proto_item_add_subtree(ti, ett_109x);

    data = NIB_WORD(nib,bufptr);
    proto_tree_add_uint(tree, hf_109x_cmi,  tvb, NIBHI(nib,4), data);
    proto_tree_add_uint(tree, hf_109x_len,  tvb, NIBHI(nib,4), data);
    proto_tree_add_uint(tree, hf_109x_rcid, tvb, NIBHI(nib,4), data);
    proto_tree_add_uint(tree, hf_109x_haoi, tvb, NIBHI(nib,4), data);
    nib += 4;

    /* HARQ ACK offset indicator */
    if (data & 1) {
        data = NIB_BYTE(nib,bufptr);
        proto_tree_add_uint(tree, hf_109x_dl,  tvb, NIBHI(nib,2), data);
        nib += 2;
        data = NIB_BYTE(nib,bufptr);
        proto_tree_add_uint(tree, hf_109x_ul, tvb, NIBHI(nib,2), data);
        nib += 2;
    }

    numie = NIB_BYTE(nib,bufptr);
    proto_tree_add_uint(tree, hf_109x_dlie,  tvb, NIBHI(nib,2), numie);
    nib += 2;

    /* DL-MAP IEs */
    ti = proto_tree_add_text(tree, tvb, NIBHI(nib,1), "DL-MAP IEs");
    ie_tree = proto_item_add_subtree(ti, ett_109x_dl);
    for (i = 0; i < numie; i++) {
        nib += dissect_dlmap_ie(ie_tree, bufptr, nib, lennib - nib, tvb);
    }

    data = NIB_BYTE(nib,bufptr);
    proto_tree_add_uint(tree, hf_109x_symofs,  tvb, NIBHI(nib,2), data);
    nib += 2;
    data = NIB_BYTE(nib,bufptr);
    proto_tree_add_uint(tree, hf_109x_subofs,  tvb, NIBHI(nib,2), data);
    proto_tree_add_uint(tree, hf_109x_rsv, tvb, NIBHI(nib,2), data);
    nib += 2;

    /* UL-MAP IEs */
    ti = proto_tree_add_text(tree, tvb, NIBHI(nib,lennib-nib), "UL-MAP IEs");
    ie_tree = proto_item_add_subtree(ti, ett_109x_ul);
    for ( ; nib < lennib - 1; ) {
        nib += dissect_ulmap_ie(ie_tree, bufptr, nib, lennib - nib, tvb);
    }

    /* padding */
    if (nib & 1) {
        proto_tree_add_text(tree, tvb, NIBHI(nib,1), "Padding Nibble");
        nib++;
    }

    /* CRC-16 is always appended */
    data = NIB_WORD(nib, bufptr);
    generic_item = proto_tree_add_text(tree, tvb, NIBHI(nib,4), "CRC-16: 0x%04x",data);
    /* calculate the CRC */
    calculated_crc = wimax_mac_calc_crc16(tvb_get_ptr(tvb, 0, NIB_TO_BYTE(nib)), NIB_TO_BYTE(nib));
    if (data != calculated_crc)
    {
        proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
    }
    nib += 4;


    sub_dl_ul_map = 0; /* clear flag */
    /* return length */
    return length;
}

gint wimax_decode_dlmap_reduced_aas(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *base_tree)
{
    /* 8.4.5.8.1 [2] Reduced AAS private DL-MAP */
    /* if there is an appended UL-MAP, also decode that */
    guint offset = 0;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    proto_item *generic_item = NULL;
    gint ulmap_appended;
    gint length;
    gint           tvb_len = tvb_reported_length(tvb);
    /* XXX This should be removed, and regular tvb accessors should be used instead. */
    const guint8 * bufptr  = tvb_get_ptr(tvb, offset, tvb_len);
    gint           bit     = 0;
    guint data, pad, mult;
    gint numie = 1;
    gint i;
    guint16 calculated_crc;
    gint smcs,cidi,dcdi,phyi,cqci;

    length = tvb_len;

    /* display MAC Reduced_AAS_Private_DL-MAP and create subtree */
    ti = proto_tree_add_protocol_format(base_tree, proto_mac_mgmt_msg_dlmap_decoder, tvb, offset, length, "Reduced_AAS_Private_DL-MAP");
    tree = proto_item_add_subtree(ti, ett_308a);

    VBIT(data, 3, hf_308a_cmi);
    VBIT(ulmap_appended, 1, hf_308a_ulmap);
    VBIT(data, 2, hf_308a_type);
    VBIT(mult, 1, hf_308a_mult);
    VBIT(data, 1, hf_308a_rsv);

    if (mult) {
        XBIT(numie, 8, "NUM IE");
    }

    for (i = 0; i < numie; i++) {
        XBIT(data, 2, "Periodicity");
        XBIT(cidi, 1, "CID Included");
        XBIT(dcdi, 1, "DCD Count Included");
        XBIT(phyi, 1, "PHY modification included");
        XBIT(cqci, 1, "CQICH control indicator");
        XBIT(data, 2, "Encoding Mode");
        XBIT(smcs, 1, "Separate MCS Enabled");

        if (smcs) {
            XBIT(data,10, "Duration");
            XBIT(data, 4, "DIUC");
            XBIT(data, 2, "Repetition Coding Indication");
        }
        if (cidi) {
            XBIT(data,16, "CID");
        }
        if (cqci) {
            XBIT(data, 6, "Allocation Index");
            XBIT(data, 3, "Report Period");
            XBIT(data, 3, "Frame Offset");
            XBIT(data, 4, "Report Duration");
            XBIT(data, 2, "CQI Measurement Type");
            XBIT(data, 2, "Reserved");
        }
        if (dcdi) {
            XBIT(data, 8, "DCD Count");
        }
        if (phyi) {
            XBIT(data, 1, "Preamble Select");
            XBIT(data, 4, "Preamble Shift Index");
            XBIT(data, 1, "Pilot Pattern Modifier");
            XBIT(data, 2, "Pilot Pattern Index");
        }
        XBIT(data, 3, "DL Frame Offset");
        if (fusc) {
            XBIT(data, 8, "Zone Symbol Offset");
        }
        XBIT(data, 8, "OFDMA Symbol Offset");
        if (tusc) {
            XBIT(data, 8, "Subchannel Offset");
            XBIT(data, 5, "No. OFDMA triple symbol");
            XBIT(data, 6, "No. subchannels");
        } else {
            XBIT(data, 6, "Subchannel Offset");
            XBIT(data, 7, "No. OFDMA symbols");
            XBIT(data, 6, "No. subchannels");
        }
        XBIT(data, 4, "DIUC/N(EP)");
        if (harq) {
            XBIT(data, 1, "DL HARQ ACK bitmap");
            XBIT(data, 6, "ACK Allocation Index");
            XBIT(data, 4, "ACID");
            XBIT(data, 1, "AI_SN");
            if (ir_type) {
                XBIT(data, 4, "N(SCH)");
                XBIT(data, 2, "SPID");
                XBIT(data, 2, "Reserved");
            }
        }
        XBIT(data, 2, "Repetition Coding Indication");
        if (ulmap_appended) {
            /* offset and length are in bits */
            bit += wimax_decode_ulmap_reduced_aas(tree, bufptr, offset, length*8, tvb);
        }
        XBIT(data, 3, "Reserved");
    }

    /* padding */
    pad = BIT_PADDING(bit,8);
    if (pad) {
        proto_tree_add_text(tree, tvb, BITHI(bit,pad), "Padding: %d bits",pad);
        bit += pad;
    }

    /* CRC-16 is always appended */
    data = BIT_BITS(bit, bufptr, 16);
    generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
    /* calculate the CRC */
    calculated_crc = wimax_mac_calc_crc16(tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
    if (data != calculated_crc)
    {
        proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
    }
    bit += 16;

    return BIT_TO_BYTE(bit) - offset;
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_dlmap(void)
{
	/* DL-MAP fields display */
	static hf_register_info hf[] =
	{
		{
			&hf_dlmap_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.dlmap",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmap_bsid,
			{
				"Base Station ID", "wmx.dlmap.bsid",
				FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmap_dcd,
			{
				"DCD Count", "wmx.dlmap.dcd",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmap_fch_expected,
			{
				"FCH Expected", "wmx.dlmap.fch_expected",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie,
			{
				"DL-MAP IE", "wmx.dlmap.ie",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_boosting,
			{
				"Boosting", "wmx.dlmap.ie.boosting",
				FT_UINT32, BASE_DEC, VALS(boost_msgs), 0x00038000, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_boosting2,
			{
				"Boosting", "wmx.dlmap.ie.boosting",
				FT_UINT32, BASE_DEC, VALS(boost_msgs), 0x0000E000, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_cid,
			{
				"CID", "wmx.dlmap.ie.cid",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_diuc,
			{
				"DIUC", "wmx.dlmap.ie.diuc",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_ncid,
			{
				"N_CID", "wmx.dlmap.ie.ncid",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_numsub,
			{
				"Number of Subchannels", "wmx.dlmap.ie.numsub",
				FT_UINT32, BASE_DEC, NULL, 0x000000FC, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_numsym,
			{
				"Number of OFDMA Symbols", "wmx.dlmap.ie.numsym",
				FT_UINT32, BASE_DEC, NULL, 0x00007F00, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_numsub2,
			{
				"Number of Subchannels", "wmx.dlmap.ie.numsub",
				FT_UINT32, BASE_DEC, NULL, 0x000000FC, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_numsym2,
			{
				"Number of OFDMA Symbols", "wmx.dlmap.ie.numsym",
				FT_UINT32, BASE_DEC, NULL, 0x00001F00, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_offsub,
			{
				"Subchannel Offset", "wmx.dlmap.ie.offsub",
				FT_UINT32, BASE_DEC, NULL, 0x00FC0000, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_offsym,
			{
				"OFDMA Symbol Offset", "wmx.dlmap.ie.offsym",
				FT_UINT32, BASE_DEC, NULL, 0xFF000000, NULL, HFILL
			}
		},
		/* alt ie format */
		{
			&hf_dlmap_ie_offsub2,
			{
				"Subchannel Offset", "wmx.dlmap.ie.offsub",
				FT_UINT32, BASE_DEC, NULL, 0x00FF0000, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_offsym2,
			{
				"OFDMA Symbol Offset", "wmx.dlmap.ie.offsym",
				FT_UINT32, BASE_DEC, NULL, 0xFF000000, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_rep,
			{
				"Repetition Coding Indication", "wmx.dlmap.ie.rep",
				FT_UINT32, BASE_DEC, VALS(rep_msgs), 0x00000003, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ie_rep2,
			{
				"Repetition Coding Indication", "wmx.dlmap.ie.rep",
				FT_UINT32, BASE_DEC, VALS(rep_msgs), 0x00000003, NULL, HFILL
			}
		},
		{
			&hf_dlmap_ofdma_sym,
			{
				"Num OFDMA Symbols", "wmx.dlmap.ofdma_sym",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmap_phy_fdur,
			{
				"Frame Duration Code", "wmx.dlmap.phy_fdur",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_dlmap_phy_fdur_ms,
			{
				"Frame Duration", "wmx.dlmap.phy_fdur",
				FT_UINT8, BASE_HEX, VALS(frame_duration), 0x00, NULL, HFILL
			}
		},
		{
			&hf_dlmap_phy_fdur_per_sec,
			{
				"Frames per second", "wmx.dlmap.phy_fdur",
				FT_UINT8, BASE_HEX, VALS(frames_per_second), 0x00, NULL, HFILL
			}
		},
		{
			&hf_dlmap_phy_fnum,
			{
				"Frame Number", "wmx.dlmap.phy_fnum",
				FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmapc_compr,
			{
				"Compressed map indicator", "wmx.dlmapc.compr",
				FT_UINT16, BASE_DEC, NULL, 0xe000, NULL, HFILL
			}
		},
		{
			&hf_dlmapc_count,
			{
				"DL IE Count", "wmx.dlmapc.count",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmapc_len,
			{
				"Map message length", "wmx.dlmapc.len",
				FT_UINT16, BASE_DEC, NULL, 0x07FF, NULL, HFILL
			}
		},
		{
			&hf_dlmapc_opid,
			{
				"Operator ID", "wmx.dlmapc.opid",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmapc_rsv,
			{
				"Reserved", "wmx.dlmapc.rsv",
				FT_UINT16, BASE_DEC, NULL, 0x0800, NULL, HFILL
			}
		},
		{
			&hf_dlmapc_secid,
			{
				"Sector ID", "wmx.dlmapc.secid",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmapc_sync,
			{
				"PHY Synchronization Field", "wmx.dlmapc.sync",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmapc_ulmap,
			{
				"UL-MAP appended", "wmx.dlmapc.ulmap",
				FT_UINT16, BASE_DEC, NULL, 0x1000, NULL, HFILL
			}
		},
		{
			&hf_dlmap_xie_diuc,
			{
				"Extended DIUC", "wmx.dlmapc.xie_diuc",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dlmap_xie_len,
			{
				"Length", "wmx.dlmapc.xie_len",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_109x_cmi,
			{
				"SUB-DL-UL-MAP map indicator", "wmx.dlul.cmi",
				FT_UINT16, BASE_DEC, NULL, 0xE000, NULL, HFILL
			}
		},
		{
			&hf_109x_dl,
			{
				"DL HARQ ACK offset", "wmx.dlul.dl",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_109x_dlie,
			{
				"DL IE Count", "wmx.dlul.dlie",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_109x_haoi,
			{
				"HARQ ACK offset indicator", "wmx.dlul.haoi",
				FT_UINT16, BASE_DEC, NULL, 0x0001, NULL, HFILL
			}
		},
		{
			&hf_109x_len,
			{
				"Map message length - The length is limited to 735 bytes at most", "wmx.dlul.len",
				FT_UINT16, BASE_DEC, NULL, 0x1FF8, NULL, HFILL
			}
		},
		{
			&hf_109x_rcid,
			{
				"RCID_Type", "wmx.dlul.rcid",
				FT_UINT16, BASE_DEC, NULL, 0x0006, NULL, HFILL
			}
		},
		{
			&hf_109x_subofs,
			{
				"Subchannel offset", "wmx.dlul.subofs",
				FT_UINT8, BASE_DEC, NULL, 0xFE, NULL, HFILL
			}
		},
		{
			&hf_109x_symofs,
			{
				"OFDMA Symbol offset of subsequent sub-bursts "
				"in this Sub-DL-UL-MAP message with reference to "
				"the start of UL sub-frame.", "wmx.dlul.symofs",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_109x_rsv,
			{
				"Reserved", "wmx.dlul.rsv",
				FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_109x_ul,
			{
				"UL HARQ ACK offset", "wmx.dlul.ul",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_308a_cmi,
			{
				"Compressed map indicator", "wmx.dlmap.reduced_aas_private.cmi",
				FT_UINT8, BASE_DEC, NULL, 0xe0, NULL, HFILL
			}
		},
		{
			&hf_308a_mult,
			{
				"Multiple IE", "wmx.dlmap.reduced_aas_private.mult",
				FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL
			}
		},
		{
			&hf_308a_rsv,
			{
				"Reserved", "wmx.dlmap.reduced_aas_private.rsv",
				FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_308a_type,
			{
				"Compressed Map Type", "wmx.dlmap.reduced_aas_private.type",
				FT_UINT8, BASE_DEC, NULL, 0x0d, NULL, HFILL
			}
		},
		{
			&hf_308a_ulmap,
			{
				"UL-MAP appended", "wmx.dlmap.reduced_aas_private.ulmap",
				FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL
			}
		},
		{
			&hf_mac_header_compress_dlmap_crc,
			{
				"CRC", "wmx.compress_dlmap_crc",
				FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_dlmap,
			&ett_dlmap_ie,
			/* &ett_dlmap_c_ie, */
			&ett_109x,
			&ett_109x_dl,
			&ett_109x_ul,
			&ett_275_phy,
			&ett_275_1,
			&ett_277,
			&ett_277b,
			&ett_278,
			&ett_279,
			&ett_280,
			&ett_281,
			&ett_282,
			&ett_283,
			&ett_284,
			&ett_285,
			&ett_286,
			&ett_286a,
			&ett_286b,
			&ett_286c,
			&ett_286d,
			&ett_286e,
			&ett_286f,
			&ett_286g,
			&ett_286h,
			&ett_286i,
			&ett_286j,
			&ett_286k,
			&ett_286l,
			&ett_286m,
			&ett_286n,
			&ett_286o,
			&ett_286p,
			&ett_286q,
			&ett_286r,
			&ett_286s,
			&ett_286t,
			&ett_286u,
			&ett_286v,
			&ett_286w,
			&ett_286x,
			&ett_286y,
			&ett_286z,
			&ett_305,
			/* &ett_305_dl, */
			&ett_308a,
		};

        proto_mac_mgmt_msg_dlmap_decoder = proto_register_protocol (
                "WiMax DLMAP/ULMAP Messages", /* name       */
                "WiMax DLMAP/ULMAP (map)",    /* short name */
                "wmx.map"                     /* abbrev     */
                );

        proto_register_field_array(proto_mac_mgmt_msg_dlmap_decoder, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}
