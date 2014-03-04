/* msg_ulmap.c
 * WiMax MAC Management UL-MAP Message decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Mike Harvey <michael.harvey@intel.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Include files */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include "crc.h"
#include "wimax_mac.h"
#include "wimax_bits.h"

extern	gboolean include_cor2_changes;

void proto_register_mac_mgmt_msg_ulmap(void);
void proto_reg_handoff_mac_mgmt_msg_ulmap(void);

#define MAC_MGMT_MSG_ULMAP 3

#define XBIT(var, bits, desc) \
    do { \
    var = BIT_BITS(bit, bufptr, bits); \
    proto_tree_add_text(tree, tvb, BITHI(bit, bits), desc ": %d", var); \
    bit += bits; \
    } while(0)

#define XNIB(var, nibs, desc) \
    do { \
    var = NIB_NIBS(nib, bufptr, nibs); \
    proto_tree_add_text(tree, tvb, NIBHI(nib, nibs), desc ": %d", var); \
    nib += nibs; \
    } while(0)

/* from msg_ucd.c */
extern guint cqich_id_size;		/* Set for CQICH_Alloc_IE */

/* from msg_dlmap.c */
extern gint harq;
extern gint ir_type;
extern gint N_layer;
extern gint RCID_Type;
extern gint RCID_IE(proto_tree *diuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb, gint RCID_Type);

static gint proto_mac_mgmt_msg_ulmap_decoder = -1;

static gint ett_ulmap = -1;
static gint ett_ulmap_ie = -1;
static gint ett_ulmap_ffb = -1;
/* static gint ett_ulmap_c = -1;    */
/* static gint ett_ulmap_c_ie = -1; */
/* static gint ett_ulmap_s = -1;    */
/* static gint ett_ulmap_s_ie = -1; */
static gint ett_287_1 = -1;
static gint ett_287_2 = -1;
static gint ett_289 = -1;
static gint ett_290 = -1;
static gint ett_290b = -1;
static gint ett_291 = -1;
static gint ett_292 = -1;
static gint ett_293 = -1;
static gint ett_294 = -1;
static gint ett_295 = -1;
static gint ett_299 = -1;
static gint ett_300 = -1;
static gint ett_302 = -1;
static gint ett_302a = -1;
static gint ett_302b = -1;
static gint ett_302c = -1;
static gint ett_302d = -1;
static gint ett_302e = -1;
static gint ett_302f = -1;
static gint ett_302g = -1;
static gint ett_302h = -1;
static gint ett_302i = -1;
static gint ett_302j = -1;
static gint ett_302k = -1;
static gint ett_302l = -1;
static gint ett_302m = -1;
static gint ett_302n = -1;
static gint ett_302o = -1;
static gint ett_302p = -1;
static gint ett_302q = -1;
static gint ett_302r = -1;
static gint ett_302s = -1;
static gint ett_302t = -1;
static gint ett_302u = -1;
static gint ett_302v = -1;
static gint ett_306 = -1;
static gint ett_306_ul = -1;
static gint ett_308b = -1;
static gint ett_315d = -1;

#define DCD_DOWNLINK_BURST_PROFILE        1
#define DCD_BS_EIRP                       2
#define DCD_FRAME_DURATION                3
#define DCD_PHY_TYPE                      4
#define DCD_POWER_ADJUSTMENT              5
#define DCD_CHANNEL_NR                    6
#define DCD_TTG                           7
#define DCD_RTG                           8
#define DCD_RSS                           9
#define DCD_CHANNEL_SWITCH_FRAME_NR      10
#define DCD_FREQUENCY                    12
#define DCD_BS_ID                        13
#define DCD_FRAME_DURATION_CODE          14
#define DCD_FRAME_NR                     15
#define DCD_SIZE_CQICH_ID                16
#define DCD_H_ARQ_ACK_DELAY              17
#define DCD_MAC_VERSION                 148
#define DCD_RESTART_COUNT               154

#define DCD_BURST_FREQUENCY               1
#define DCD_BURST_FEC_CODE_TYPE         150
#define DCD_BURST_DIUC_EXIT_THRESHOLD   151
#define DCD_BURST_DIUC_ENTRY_THRESHOLD  152
#define DCD_BURST_TCS_ENABLE            153

#define DCD_TLV_T_541_TYPE_FUNCTION_ACTION                                1
#define DCD_TLV_T542_TRIGGER_VALUE                                        2
#define DCD_TLV_T_543_TRIGGER_AVERAGING_DURATION                          3
#define DCD_TLV_T_19_PERMUTATION_TYPE_FOR_BROADCAST_REGION_IN_HARQ_ZONE  19
#define DCD_TLV_T_20_MAXIMUM_RETRANSMISSION                              20
#define DCD_TLV_T_21_DEFAULT_RSSI_AND_CINR_AVERAGING_PARAMETER           21
#define DCD_TLV_T_22_DL_AMC_ALLOCATED_PHYSICAL_BANDS_BITMAP              22
#define DCD_TLV_T_31_H_ADD_THRESHOLD                                     31
#define DCD_TLV_T_32_H_DELETE_THRESHOLD                                  32
#define DCD_TLV_T_33_ASR                                                 33
#define DCD_TLV_T_34_DL_REGION_DEFINITION                                34
#define DCD_TLV_T_35_PAGING_GROUP_ID                                     35
#define DCD_TLV_T_36_TUSC1_PERMUTATION_ACTIVE_SUBCHANNELS_BITMAP         36
#define DCD_TLV_T_37_TUSC2_PERMUTATION_ACTIVE_SUBCHANNELS_BITMAP         37
#define DCD_TLV_T_45_PAGING_INTERVAL_LENGTH                              45
#define DCD_TLV_T_50_HO_TYPE_SUPPORT                                     50
#define DCD_TLV_T_51_HYSTERSIS_MARGIN                                    51
#define DCD_TLV_T_52_TIME_TO_TRIGGER_DURATION                            52
#define DCD_TLV_T_54_TRIGGER                                             54
#define DCD_TLV_T_153_DOWNLINK_BURST_PROFILE_FOR_MULTIPLE_FEC_TYPES     153

#define UL_MAP_NCT_PMP  0
#define UL_MAP_NCT_DM   1
#define UL_MAP_NCT_PTP  2

#if 0
/* NCT messages */
static const value_string nct_msgs[] =
{
    { UL_MAP_NCT_PMP, "PMP" },
    { UL_MAP_NCT_PMP, "DM" },
    { UL_MAP_NCT_PMP, "PTP" },
    { 0,  NULL }
};
#endif

#if 0
/* Repetition Coding Indications */
static const value_string rep_msgs[] =
{
    { 0, "No Repetition Coding" },
    { 1, "Repetition Coding of 2 Used" },
    { 2, "Repetition Coding of 4 Used" },
    { 3, "Repetition Coding of 6 Used" },
    { 0,  NULL }
};
#endif

#if 0
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
#endif

/* ul-map fields */
static gint hf_ulmap_reserved = -1;
static gint hf_ulmap_ucd_count = -1;
static gint hf_ulmap_alloc_start_time = -1;
static gint hf_ulmap_ofdma_sym = -1;
/* static gint hf_ulmap_fch_expected = -1; */

/* static gint hf_ulmap_ie = -1; */

static gint hf_ulmap_ie_cid      = -1;
static gint hf_ulmap_ie_uiuc     = -1;
static gint hf_ulmap_uiuc12_symofs = -1;
static gint hf_ulmap_uiuc12_subofs = -1;
static gint hf_ulmap_uiuc12_numsym = -1;
static gint hf_ulmap_uiuc12_numsub = -1;
static gint hf_ulmap_uiuc12_method = -1;
static gint hf_ulmap_uiuc12_dri    = -1;
static gint hf_ulmap_uiuc10_dur    = -1;
static gint hf_ulmap_uiuc10_rep    = -1;

static gint hf_ulmap_uiuc14_dur  = -1;
static gint hf_ulmap_uiuc14_uiuc = -1;
static gint hf_ulmap_uiuc14_rep  = -1;
static gint hf_ulmap_uiuc14_idx  = -1;
static gint hf_ulmap_uiuc14_code = -1;
static gint hf_ulmap_uiuc14_sym  = -1;
static gint hf_ulmap_uiuc14_sub  = -1;
static gint hf_ulmap_uiuc14_bwr  = -1;

/* static gint hf_ulmap_uiuc11_ext = -1; */
/* static gint hf_ulmap_uiuc11_len = -1; */
/* static gint hf_ulmap_uiuc11_data = -1; */
/* static gint hf_ulmap_uiuc15_ext = -1; */
/* static gint hf_ulmap_uiuc15_len = -1; */
/* static gint hf_ulmap_uiuc15_data = -1; */

static gint hf_ulmap_uiuc0_symofs = -1;
static gint hf_ulmap_uiuc0_subofs = -1;
static gint hf_ulmap_uiuc0_numsym = -1;
static gint hf_ulmap_uiuc0_numsub = -1;
static gint hf_ulmap_uiuc0_rsv    = -1;

static gint hf_ulmap_uiuc13_symofs = -1;
static gint hf_ulmap_uiuc13_subofs = -1;
static gint hf_ulmap_uiuc13_numsym = -1;
static gint hf_ulmap_uiuc13_numsub = -1;
static gint hf_ulmap_uiuc13_papr   = -1;
static gint hf_ulmap_uiuc13_zone   = -1;
static gint hf_ulmap_uiuc13_rsv    = -1;

/*  This gets called each time a capture file is loaded. */
void init_wimax_globals(void)
{
    cqich_id_size = 0;
    harq = 0;
    ir_type = 0;
    N_layer = 0;
    RCID_Type = 0;
}

/********************************************************************
 * UL-MAP HARQ Sub-Burst IEs
 * 8.4.5.4.24 table 302j
 * these functions take offset/length in bits
 *******************************************************************/

static gint Dedicated_UL_Control_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24.1 Dedicated_UL_Control_IE -- table 302r */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    gint sdma;

    bit = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "Dedicated_UL_Control_IE");
    tree = proto_item_add_subtree(ti, ett_302r);

    XBIT(data, 4, "Length");
    XBIT(sdma, 4, "Control Header");
    if ((sdma & 1) == 1) {
        XBIT(data, 2, "Num SDMA layers");
        XBIT(data, 2, "Pilot Pattern");
    }
    return (bit - offset); /* length in bits */
}

static gint Dedicated_MIMO_UL_Control_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24.2 Dedicated_MIMO_UL_Control_IE -- table 302s */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    bit = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "Dedicated_MIMO_UL_Control_IE");
    tree = proto_item_add_subtree(ti, ett_302s);

    XBIT(data, 2, "Matrix");
    XBIT(N_layer, 2, "N_layer");

    return (bit - offset); /* length in bits */
}

/* begin Sub-Burst IEs */

static gint UL_HARQ_Chase_Sub_Burst_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 UL_HARQ_Chase_sub_burst_IE -- table 302k */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    /*proto_item *generic_item = NULL;*/
    gint duci;
    /*guint16 calculated_crc;*/

    bit = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, BITHI(offset,length), "UL_HARQ_Chase_Sub_Burst_IE");
    tree = proto_item_add_subtree(ti, ett_302k);

    bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
    XBIT(duci, 1, "Dedicated UL Control Indicator");
    if (duci == 1) {
        bit += Dedicated_UL_Control_IE(tree, bufptr, bit, length, tvb);
    }
    XBIT(data, 4, "UIUC");
    XBIT(data, 2, "Repetition Coding Indication");
    XBIT(data,10, "Duration");
    XBIT(data, 4, "ACID");
    XBIT(data, 1, "AI_SN");
    XBIT(data, 1, "ACK_disable");
    XBIT(data, 1, "Reserved");

#if 0
    if (include_cor2_changes)
    {
	/* CRC-16 is always appended */
	data = BIT_BITS(bit, bufptr, 16);
	generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
	/* calculate the CRC */
	calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
	if (data != calculated_crc)
	{
		proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
	}
	bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint UL_HARQ_IR_CTC_Sub_Burst_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 UL_HARQ_IR_CTC_sub_burst_IE -- table 302l */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    /*proto_item *generic_item = NULL;*/
    gint duci;
    /*guint16 calculated_crc;*/

    bit = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "UL_HARQ_IR_CTC_Sub_Burst_IE");
    tree = proto_item_add_subtree(ti, ett_302l);

    bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
    XBIT(duci, 1, "Dedicated UL Control Indicator");
    if (duci == 1) {
        bit += Dedicated_UL_Control_IE(tree, bufptr, bit, length, tvb);
    }
    XBIT(data, 4, "N(EP)");
    XBIT(data, 4, "N(SCH)");
    XBIT(data, 2, "SPID");
    XBIT(data, 4, "ACIN");
    XBIT(data, 1, "AI_SN");
    XBIT(data, 1, "ACK_disable");
    XBIT(data, 3, "Reserved");

#if 0
    if (include_cor2_changes)
    {
	/* CRC-16 is always appended */
	data = BIT_BITS(bit, bufptr, 16);
	generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
	/* calculate the CRC */
	calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
	if (data != calculated_crc)
	{
		proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
	}
	bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint UL_HARQ_IR_CC_Sub_Burst_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 UL_HARQ_IR_CC_sub_burst_IE -- table 302m */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    /*proto_item *generic_item = NULL;*/
    gint duci;
    /*guint16 calculated_crc;*/

    bit = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "UL_HARQ_IR_CC_Sub_Burst_IE");
    tree = proto_item_add_subtree(ti, ett_302m);

    bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
    XBIT(duci, 1, "Dedicated UL Control Indicator");
    if (duci == 1) {
        bit += Dedicated_UL_Control_IE(tree, bufptr, bit, length, tvb);
    }
    XBIT(data, 4, "UIUC");
    XBIT(data, 2, "Repetition Coding Indication");
    XBIT(data,10, "Duration");
    XBIT(data, 2, "SPID");
    XBIT(data, 4, "ACID");
    XBIT(data, 1, "AI_SN");
    XBIT(data, 1, "ACK_disable");
    XBIT(data, 3, "Reserved");

#if 0
    if (include_cor2_changes)
    {
	/* CRC-16 is always appended */
	data = BIT_BITS(bit, bufptr, 16);
	generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
	/* calculate the CRC */
	calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
	if (data != calculated_crc)
	{
		proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
	}
	bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint MIMO_UL_Chase_HARQ_Sub_Burst_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 MIMO_UL_Chase_HARQ_Sub_Burst_IE -- table 302n */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    /*proto_item *generic_item = NULL;*/
    gint muin,dmci,ackd,i;
    /*guint16 calculated_crc;*/

    bit = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "MIMO_UL_Chase_HARQ_Sub_Burst_IE");
    tree = proto_item_add_subtree(ti, ett_302n);

    XBIT(muin, 1, "MU indicator");
    XBIT(dmci, 1, "Dedicated MIMO ULControl Indicator");
    XBIT(ackd, 1, "ACK Disable");
    if (muin == 0) {
        bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
        if (dmci) {
            bit += Dedicated_MIMO_UL_Control_IE(tree, bufptr, bit, length, tvb);
        }
    } else {
        XBIT(data, 1, "Matrix");
    }
    XBIT(data, 10, "Duration");
    for (i = 0; i < N_layer; i++) {
        if (muin == 1) {
            bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
        }
        XBIT(data, 4, "UIUC");
        XBIT(data, 2, "Repetition Coding Indication");
        if (ackd == 0) {
            XBIT(data, 4, "ACID");
            XBIT(data, 1, "AI_SN");
        }
    }

#if 0
    if (include_cor2_changes)
    {
	/* CRC-16 is always appended */
	data = BIT_BITS(bit, bufptr, 16);
	generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
	/* calculate the CRC */
	calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
	if (data != calculated_crc)
	{
		proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
	}
	bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint MIMO_UL_IR_HARQ__Sub_Burst_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 MIMO_UL_IR_HARQ__Sub_Burst_IE -- table 302o */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    /*proto_item *generic_item = NULL;*/
    gint muin,dmci,ackd,i;
    /*guint16 calculated_crc;*/

    bit = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "MIMO_UL_IR_HARQ__Sub_Burst_IE");
    tree = proto_item_add_subtree(ti, ett_302o);

    XBIT(muin, 1, "MU indicator");
    XBIT(dmci, 1, "Dedicated MIMO UL Control Indicator");
    XBIT(ackd, 1, "ACK Disable");
    if (muin == 0) {
        bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
        if (dmci) {
            bit += Dedicated_MIMO_UL_Control_IE(tree, bufptr, bit, length, tvb);
        }
    } else {
        XBIT(data, 1, "Matrix");
    }
    XBIT(data, 4, "N(SCH)");
    for (i = 0; i < N_layer; i++) {
        if (muin == 1) {
            bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
        }
        XBIT(data, 4, "N(EP)");
        if (ackd == 0) {
            XBIT(data, 2, "SPID");
            XBIT(data, 4, "ACID");
            XBIT(data, 1, "AI_SN");
        }
    }

#if 0
    if (include_cor2_changes)
    {
	/* CRC-16 is always appended */
	data = BIT_BITS(bit, bufptr, 16);
	generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
	/* calculate the CRC */
	calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
	if (data != calculated_crc)
	{
		proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
	}
	bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint MIMO_UL_IR_HARQ_for_CC_Sub_Burst_UIE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 MIMO_UL_IR_HARQ_for_CC_Sub_Burst_UIE -- table 302p */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    /*proto_item *generic_item = NULL;*/
    gint muin,dmci,ackd,i;
    /*guint16 calculated_crc;*/

    bit = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "MIMO_UL_IR_HARQ_for_CC_Sub_Burst_UIE");
    tree = proto_item_add_subtree(ti, ett_302p);

    XBIT(muin, 1, "MU indicator");
    XBIT(dmci, 1, "Dedicated MIMO UL Control Indicator");
    XBIT(ackd, 1, "ACK Disable");
    if (muin == 0) {
        bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
        if (dmci) {
            bit += Dedicated_MIMO_UL_Control_IE(tree, bufptr, bit, length, tvb);
        }
    } else {
        XBIT(data, 1, "Matrix");
    }
    XBIT(data, 10, "Duration");
    for (i = 0; i < N_layer; i++) {
        if (muin == 1) {
            bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
        }
        XBIT(data, 4, "UIUC");
        XBIT(data, 2, "Repetition Coding Indication");
        if (ackd == 0) {
            XBIT(data, 4, "ACID");
            XBIT(data, 1, "AI_SN");
            XBIT(data, 2, "SPID");
        }
    }

#if 0
    if (include_cor2_changes)
    {
	/* CRC-16 is always appended */
	data = BIT_BITS(bit, bufptr, 16);
	generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
	/* calculate the CRC */
	calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
	if (data != calculated_crc)
	{
		proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
	}
	bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

static gint MIMO_UL_STC_HARQ_Sub_Burst_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.4.24 MIMO_UL_STC_HARQ_Sub_Burst_IE -- table 302q */
    /* UL-MAP HARQ Sub-Burst IE * offset/length are in bits */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    /*proto_item *generic_item = NULL;*/
    gint ackd,txct,sboi;
    /*guint16 calculated_crc;*/

    bit = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "MIMO_UL_STC_HARQ_Sub_Burst_IE");
    tree = proto_item_add_subtree(ti, ett_302q);

    XBIT(txct, 2, "Tx count");
    XBIT(data, 10, "Duration");
    XBIT(sboi, 1, "Sub-burst offset indication");
    /*XBIT(muin, 1, "Reserved");*/
    if (sboi == 1) {
        XBIT(data, 8, "Sub-burst offset");
    }
    bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
    XBIT(ackd, 1, "ACK Disable");
    if (txct == 0) {
        XBIT(data, 4, "UIUC");
        XBIT(data, 2, "Repetition Coding Indication");
    }
    if (ackd == 0) {
        XBIT(data, 4, "ACID");
    }

#if 0
    if (include_cor2_changes)
    {
	/* CRC-16 is always appended */
	data = BIT_BITS(bit, bufptr, 16);
	generic_item = proto_tree_add_text(tree, tvb, BITHI(bit,16), "CRC-16: 0x%04x",data);
	/* calculate the CRC */
	calculated_crc = wimax_mac_calc_crc16((guint8 *)tvb_get_ptr(tvb, 0, BIT_TO_BYTE(bit)), BIT_TO_BYTE(bit));
	if (data != calculated_crc)
	{
		proto_item_append_text(generic_item, " - incorrect! (should be: 0x%x)", calculated_crc);
	}
	bit += 16;
    }
#endif

    return (bit - offset); /* length in bits */
}

/********************************************************************
 * UL-MAP Extended IEs
 * table 290a
 *******************************************************************/

static gint Power_Control_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 0 */
    /* 8.4.5.4.5 Power_Control_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "Power_Control_IE");
    tree = proto_item_add_subtree(ti, ett_292);

    XNIB(data, 1, "Extended UIUC");
    XNIB(data, 1, "Length");

    XNIB(data, 2, "Power Control");
    XNIB(data, 2, "Power measurement frame");
    return nib;
}

static gint Mini_Subchannel_allocation_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 1 */
    /* 8.4.5.4.8 [2] Mini-Subchannel_allocation_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    gint j, M;
    const gint m_table[4] = { 2, 2, 3, 6 };

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "Mini_subchannel_allocation_IE");
    tree = proto_item_add_subtree(ti, ett_295);

    XBIT(data, 4, "Extended-2 UIUC");
    XBIT(data, 8, "Length");

    XBIT(data, 2, "Ctype");
    M = m_table[data];
    XBIT(data, 6, "Duration");

    for (j = 0; j < M; j++) {
        data = BIT_BITS(bit, bufptr, 16);
        proto_tree_add_text(tree, tvb, BITHI(bit, 16), "CID(%d): %d", j, data);
        bit += 16;
        data = BIT_BITS(bit, bufptr, 4);
        proto_tree_add_text(tree, tvb, BITHI(bit, 4), "UIUC(%d): %d", j, data);
        bit += 4;
        data = BIT_BITS(bit, bufptr, 2);
        proto_tree_add_text(tree, tvb, BITHI(bit, 2), "Repetition(%d): %d", j, data);
        bit += 2;
    }
    if (M == 3) {
        XBIT(data, 4, "Padding");
    }
    return BIT_TO_NIB(bit);
}

static gint AAS_UL_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 2 */
    /* 8.4.5.4.6 [2] AAS_UL_IE*/
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "AAS_UL_IE");
    tree = proto_item_add_subtree(ti, ett_293);

    XBIT(data, 4, "Extended UIUC");
    XBIT(data, 4, "Length");

    XBIT(data, 2, "Permutation");
    XBIT(data, 7, "UL_PermBase");
    XBIT(data, 8, "OFDMA symbol offset");
    XBIT(data, 8, "AAS zone length");
    XBIT(data, 2, "Uplink preamble config");
    XBIT(data, 1, "Preamble type");
    XBIT(data, 4, "Reserved");
    return BIT_TO_NIB(bit);
}

static gint CQICH_Alloc_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 3 */
    /* 8.4.5.4.12 [2] CQICH_Alloc_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    gint target;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    gint rci, rtype, ftype, zperm, mgi, api, pad;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "CQICH_Alloc_IE");
    tree = proto_item_add_subtree(ti, ett_300);

    XBIT(data, 4, "Extended UIUC");
    XBIT(data, 4, "Length");
    target = bit + BYTE_TO_BIT(data);

    if (cqich_id_size == 0) {
        proto_tree_add_text(tree, tvb, BITHI(bit, 1), "CQICH_ID: n/a (size == 0 bits)");
    } else {
        /* variable from 0-9 bits */
        data = BIT_BITS16(bit, bufptr, cqich_id_size);
        proto_tree_add_text(tree, tvb, BITHI(bit, cqich_id_size), "CQICH_ID: %d (%d bits)", data, cqich_id_size);
        bit += cqich_id_size;
    }

    XBIT(data, 6, "Allocation offset");
    XBIT(data, 2, "Period (p)");
    XBIT(data, 3, "Frame offset");
    XBIT(data, 3, "Duration (d)");
    XBIT(rci,  1, "Report configuration included");
    if (rci)
    {
        XBIT(ftype, 2, "Feedback Type");
        XBIT(rtype, 1, "Report type");
        if (rtype == 0) {
            XBIT(data, 1, "CINR preamble report type");
        }
        else {
            XBIT(zperm, 3, "Zone permutation");
            XBIT(data, 2, "Zone type");
            XBIT(data, 2, "Zone PRBS_ID");
            if (zperm == 0 || zperm == 1) {
                XBIT(mgi, 1, "Major group indication");
                if (mgi == 1) {
                    /* PUSC major group bitmap*/
                    XBIT(data, 6, "PUSC Major group bitmap");
                }
            }
            XBIT(data, 1, "CINR zone measurement type");
        }
        if (ftype == 0) {
            XBIT(api, 1, "Averaging parameter included");
            if (api == 1) {
                XBIT(data, 4, "Averaging parameter");
            }
        }
    }
    XBIT(data, 2, "MIMO_permutation_feedback_cycle");

    pad = target - bit;
    if (pad) {
        proto_tree_add_text(tree, tvb, BITHI(bit, pad), "Padding: %d bits", pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);	/* Return position in nibbles. */
}

static gint UL_Zone_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 4 */
    /* 8.4.5.4.7 [2] UL_Zone_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "UL_Zone_IE");
    tree = proto_item_add_subtree(ti, ett_294);

    XBIT(data, 4, "Extended UIUC");
    XBIT(data, 4, "Length");

    XBIT(data, 7, "OFDMA symbol offset");
    XBIT(data, 2, "Permutation");
    XBIT(data, 7, "UL_PermBase");
    XBIT(data, 2, "AMC type");
    XBIT(data, 1, "Use All SC indicator");
    XBIT(data, 1, "Disable subchannel rotation");
    XBIT(data, 4, "Reserved");
    return BIT_TO_NIB(bit);
}

static gint PHYMOD_UL_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 5 */
    /* 8.4.5.4.14 [2] PHYMOD_UL_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    gint pmt;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "PHYMOD_UL_IE");
    tree = proto_item_add_subtree(ti, ett_302);

    XBIT(data, 4, "Extended UIUC");
    XBIT(data, 4, "Length");

    XBIT(pmt, 1, "Preamble Modifier Type");
    if (pmt == 0) {
        XBIT(data, 4, "Preamble frequency shift index");
    } else {
        XBIT(data, 4, "Preamble Time Shift index");
    }
    XBIT(data, 1, "Pilot Pattern Modifier");
    XBIT(data, 2, "Pilot Pattern Index");
    return BIT_TO_NIB(bit);
}

static gint MIMO_UL_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 6 */
    /* 8.4.5.4.11 MIMO_UL_Basic_IE (not implemented) */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "MIMO_UL_Basic_IE");
    tree = proto_item_add_subtree(ti, ett_299);

    XNIB(data, 1, "Extended UIUC");
    XNIB(data, 1, "Length");
    proto_tree_add_text(tree, tvb, NIBHI(nib,length-2), "(not implemented)");
    return nib;
}

static gint ULMAP_Fast_Tracking_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 7 */
    /* 8.4.5.4.22 [2] ULMAP_Fast_Tracking_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "Fast_Tracking_IE");
    tree = proto_item_add_subtree(ti, ett_302h);

    length = NIB_TO_BIT(length);

    XBIT(data, 4, "Extended UIUC");
    XBIT(data, 4, "Length");

    XBIT(data, 2, "Map Index");
    XBIT(data, 6, "Reserved");
    while (bit < (length-7)) {
        XBIT(data, 3, "Power correction");
        XBIT(data, 3, "Frequency correction");
        XBIT(data, 2, "Time correction");
    }
    return BIT_TO_NIB(bit);
}

static gint UL_PUSC_Burst_Allocation_in_other_segment_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 8 */
    /* 8.4.5.4.17 [2] UL_PUSC_Burst_Allocation_in_other_segment_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "UL_PUSC_Burst_Allocation_in_Other_Segment_IE");
    tree = proto_item_add_subtree(ti, ett_302c);

    XBIT(data, 4, "Extended UIUC");
    XBIT(data, 4, "Length");

    XBIT(data, 4, "UIUC");
    XBIT(data, 2, "Segment");
    XBIT(data, 7, "UL_PermBase");
    XBIT(data, 8, "OFDMA symbol offset");
    XBIT(data, 6, "Subchannel offset");
    XBIT(data,10, "Duration");
    XBIT(data, 2, "Repetition coding indication");
    XBIT(data, 1, "Reserved");
    return BIT_TO_NIB(bit);
}

static gint Fast_Ranging_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 9 */
    /* 8.4.5.4.21 [2] Fast_Ranging_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    gint hidi;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "Fast_Ranging_IE");
    tree = proto_item_add_subtree(ti, ett_302g);

    XBIT(data, 4, "Extended UIUC");
    XBIT(data, 4, "Length");

    XBIT(hidi, 1, "HO_ID indicator");
    XBIT(data, 7, "Reserved");
    if (hidi == 1) {
        XBIT(data,  8, "HO_ID");
        /* XBIT(data, 40, "Reserved"); TODO */
    } else {
        /* XBIT(data, 48, "MAC address"); TODO */
        proto_tree_add_text(tree, tvb, BITHI(bit, 48), "MAC address");
        bit += 48;
    }
    XBIT(data, 4, "UIUC");
    XBIT(data,10, "Duration");
    XBIT(data, 2, "Repetition coding indication");
    return BIT_TO_NIB(bit);
}

static gint UL_Allocation_Start_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended IE = 0xA */
    /* 8.4.5.4.15 [2] UL_Allocation_Start_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "UL_Allocation_start_IE");
    tree = proto_item_add_subtree(ti, ett_302a);

    XBIT(data, 4, "Extended UIUC");
    XBIT(data, 4, "Length");

    XBIT(data, 8, "OFDMA symbol offset");
    XBIT(data, 7, "Subchannel offset");
    XBIT(data, 1, "Reserved");
    return BIT_TO_NIB(bit);
}


/********************************************************************
 * UL-MAP Extended-2 IEs
 * table 290c
 *******************************************************************/

static gint CQICH_Enhanced_Allocation_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 0 */
    /* 8.4.5.4.16 [2] CQICH_Enhanced_Allocation_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    gint i, cnum, bapm;
    guint pad;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "CQICH_Enhanced_Alloc_IE");
    tree = proto_item_add_subtree(ti, ett_302b);

    XBIT(data, 4, "Extended-2 UIUC");
    XBIT(data, 8, "Length");

    if (cqich_id_size == 0) {
        proto_tree_add_text(tree, tvb, BITHI(bit, 1), "CQICH_ID: n/a (size == 0 bits)");
    } else {
        /* variable from 0-9 bits */
        data = BIT_BITS16(bit, bufptr, cqich_id_size);
        proto_tree_add_text(tree, tvb, BITHI(bit, cqich_id_size), "CQICH_ID: %d (%d bits)", data, cqich_id_size);
        bit += cqich_id_size;
    }

    XBIT(data, 3, "Period (p)");
    XBIT(data, 3, "Frame offset");
    XBIT(data, 3, "Duration (d)");
    XBIT(cnum, 4, "CQICH_Num");
    cnum += 1;
    for (i = 0; i < cnum; i++) {
        XBIT(data, 3, "Feedback Type");
        XBIT(data, 6, "Allocation Index");
        XBIT(data, 3, "CQICH Type");
        XBIT(data, 1, "STTD indication");
    }
    XBIT(bapm, 1, "Band_AMC_Precoding_Mode");
    if (bapm == 1) {
        XBIT(data, 3, "Nr_Precoders_Feedback (=N)");
    }

    pad = BIT_PADDING(bit,8);
    if (pad) {
        proto_tree_add_text(tree, tvb, BITHI(bit, pad), "Padding: %d bits", pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);
}

static gint HO_Anchor_Active_UL_MAP_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 1 */
    /* 8.4.5.4.18 [2] HO_Anchor_Active_UL_MAP_IE (not implemented) */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "HO_Anchor_Active_UL_MAP_IE");
    tree = proto_item_add_subtree(ti, ett_302d);

    XNIB(data, 1, "Extended-2 UIUC");
    XNIB(data, 2, "Length");
    proto_tree_add_text(tree, tvb, NIBHI(nib,length-3), "(not implemented)");
    return nib;
}

static gint HO_Active_Anchor_UL_MAP_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 2 */
    /* 8.4.5.4.19 [2] HO_Active_Anchor_UL_MAP_IE (not implemented) */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "HO_Active_Anchor_UL_MAP_IE");
    tree = proto_item_add_subtree(ti, ett_302e);

    XNIB(data, 1, "Extended-2 UIUC");
    XNIB(data, 2, "Length");
    proto_tree_add_text(tree, tvb, NIBHI(nib,length-3), "(not implemented)");
    return nib;
}

static gint Anchor_BS_switch_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 3 */
    /* 8.4.5.4.23 [2] Anchor_BS_switch_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    gint nbss, acod, cqai, pad;
    gint i;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "Anchor_BS_switch_IE");
    tree = proto_item_add_subtree(ti, ett_302i);

    XBIT(data, 4, "Extended-2 UIUC");
    XBIT(data, 8, "Length");

    XBIT(nbss, 4, "N_Anchor_BS_switch");
    for (i = 0; i < nbss; i++) {
        XBIT(data,12, "Reduced CID");
        XBIT(acod, 2, "Action Code");
        if (acod == 1) {
            XBIT(data, 3, "Action Time (A)");
            XBIT(data, 3, "TEMP_BS_ID");
            XBIT(data, 2, "Reserved");
        }
        if (acod == 0 || acod == 1) {
	    XBIT(data, 1, "AK Change Indicator");
            XBIT(cqai, 1, "CQICH Allocation Indicator");
            if (cqai == 1) {
                /* variable bits from 0-9 */
                if (cqich_id_size == 0) {
                    proto_tree_add_text(tree, tvb, BITHI(bit, 1), "CQICH_ID: n/a (size == 0 bits)");
                } else {
                    data = BIT_BITS16(bit, bufptr, cqich_id_size);
                    proto_tree_add_text(tree, tvb, BITHI(bit, cqich_id_size),
                        "CQICH_ID: %d (%d bits)", data, cqich_id_size);
                    bit += cqich_id_size;
                }
                XBIT(data, 6, "Feedback channel offset");
                XBIT(data, 2, "Period (=p)");
                XBIT(data, 3, "Frame offset");
                XBIT(data, 3, "Duration (=d)");
                XBIT(data, 2, "MIMO_permutation_feedback_code");
                pad = BIT_PADDING(bit,8);
                if (pad) {
                    proto_tree_add_text(tree, tvb, BITHI(bit,pad), "Reserved: %d bits", pad);
                }
            }
        } else {
            XBIT(data, 2, "Reserved");
        }
    }
    XBIT(data, 4, "Reserved");
    return BIT_TO_NIB(bit);
}

static gint UL_sounding_command_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 4 */
    /* 8.4.5.4.26 [2] UL_sounding_command_IE */
    /* see 8.4.6.2.7.1 */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    gint stype, ssrf, srlf, iafb, pad, sept, nssym, ncid, amod;
    gint i, j;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "UL_Sounding_Command_IE");
    tree = proto_item_add_subtree(ti, ett_315d);

    XBIT(data, 4, "Extended-2 UIUC");
    XBIT(data, 8, "Length");

    XBIT(stype, 1, "Sounding_Type");
    XBIT(ssrf, 1, "Send Sounding Report Flag");
    XBIT(srlf, 1, "Sounding Relevance Flag");
    if (srlf == 0) {
        XBIT(data, 1, "Sounding_Relevance");
        XBIT(data, 2, "Reserved");
    } else {
        XBIT(data, 3, "Reserved");
    }
    XBIT(iafb, 2, "Include additional feedback");
    if (stype == 0) {
        XBIT(nssym, 3, "Num_Sounding_Symbols");
        XBIT(data, 1, "Reserved");
        for (i = 0; i < nssym; i++) {
	    XBIT(sept, 1, "Separability Type");
            if (sept == 0) {
                XBIT(data, 3, "Max Cyclic Shift Index P");
                XBIT(data, 1, "Reserved");
            } else {
                XBIT(data, 3, "Decimation Value D");
                XBIT(data, 1, "Decimation offset randomization");
            }
            XBIT(data, 3, "Sounding symbol index");
            XBIT(ncid, 7, "Number of CIDs");
            XBIT(data, 1, "Reserved");
            for (j = 0; j < ncid; j++) {
                XBIT(data,12, "Shorted Basic CID");
                XBIT(data, 2, "Power Assignment Method");
                XBIT(data, 1, "Power boost");
                XBIT(data, 1, "Multi-Antenna Flag");
                XBIT(amod, 1, "Allocation Mode");
                if (amod == 1) {
                    XBIT(data,12, "Band bit map");
                    XBIT(data, 2, "Reserved");
                } else {
                    XBIT(data, 7, "Starting frequency band");
                    XBIT(data, 7, "Number of frequency bands");
                }
                if (srlf == 1) {
                    XBIT(data, 1, "Sounding_Relevance");
                } else {
                    XBIT(data, 1, "Reserved");
                }
                if (sept == 0) {
                    XBIT(data, 5, "Cyclic time shift index m");
                } else {
                    XBIT(data, 6, "Decimation offset d");
                    if (iafb == 1) {
                        XBIT(data, 1, "Use same symbol for additional feedback");
                        XBIT(data, 2, "Reserved");
                    } else {
                        XBIT(data, 3, "Reserved");
                    }
                }
                XBIT(data, 3, "Periodicity");
            }
        }
    } else {
        XBIT(data, 3, "Permutation");
        XBIT(data, 6, "DL_PermBase");
        XBIT(nssym, 3, "Num_Sounding_symbols");
        for (i = 0; i < nssym; i++) {
            XBIT(ncid, 7, "Number of CIDs");
            XBIT(data, 1, "Reserved");
            for (j = 0; j < ncid; j++) {
                XBIT(data, 12, "Shortened basic CID");
                if (srlf) {
                    XBIT(data, 1, "Sounding_Relevance");
                    XBIT(data, 3, "Reserved");
                }
                XBIT(data, 7, "Subchannel offset");
                XBIT(data, 1, "Power boost");
                XBIT(data, 3, "Number of subchannels");
                XBIT(data, 3, "Periodicity");
                XBIT(data, 2, "Power assignment method");
            }
        }
    }
    pad = BIT_PADDING(bit,8);
    if (pad) {
        proto_tree_add_text(tree, tvb, BITHI(bit,pad), "Padding: %d bits",pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);
}

static gint MIMO_UL_Enhanced_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 6 */
    /* 8.4.5.4.20 [2] MIMO_UL_Enhanced_IE (not implemented) */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint nib;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    nib = offset;

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "MIMO_UL_Enhanced_IE");
    tree = proto_item_add_subtree(ti, ett_302f);

    XNIB(data, 1, "Extended-2 UIUC");
    XNIB(data, 2, "Length");
    proto_tree_add_text(tree, tvb, NIBHI(nib,length-3), "(not implemented)");
    return nib;
}

static gint HARQ_ULMAP_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 7 */
    /* 8.4.5.4.24 HARQ_ULMAP_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    gint bitlength;
    gint lastbit;
    gint pad, mode, alsi, nsub;
    gint i;

    bit = NIB_TO_BIT(offset);
    bitlength = NIB_TO_BIT(length);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "HARQ_ULMAP_IE");
    tree = proto_item_add_subtree(ti, ett_302j);

    XBIT(data, 4, "Extended-2 UIUC");
    XBIT(data, 8, "Length");

    XBIT(RCID_Type, 2, "RCID_Type");
    XBIT(data, 2, "Reserved");
    lastbit = bit + bitlength -16 - 4;
    while (bit < lastbit) {
        XBIT(mode, 3, "Mode");
        XBIT(alsi, 1, "Allocation Start Indication");
        if (alsi == 1) {
            XBIT(data, 8, "OFDMA Symbol offset");
            XBIT(data, 7, "Subchannel offset");
            XBIT(data, 1, "Reserved");
        }
        XBIT(nsub, 4, "N sub Burst");
        nsub++;
        for (i = 0; i < nsub; i++) {
            if (mode == 0) {
                bit += UL_HARQ_Chase_Sub_Burst_IE(tree, bufptr, bit, bitlength, tvb);
            } else if (mode == 1) {
               bit +=  UL_HARQ_IR_CTC_Sub_Burst_IE(tree, bufptr, bit, bitlength, tvb);
            } else if (mode == 2) {
                bit += UL_HARQ_IR_CC_Sub_Burst_IE(tree, bufptr, bit, bitlength, tvb);
            } else if (mode == 3) {
                bit += MIMO_UL_Chase_HARQ_Sub_Burst_IE(tree, bufptr, bit, bitlength, tvb);
            } else if (mode == 4) {
                bit += MIMO_UL_IR_HARQ__Sub_Burst_IE(tree, bufptr, bit, bitlength, tvb);
            } else if (mode == 5) {
                bit += MIMO_UL_IR_HARQ_for_CC_Sub_Burst_UIE(tree, bufptr, bit, bitlength, tvb);
            } else if (mode == 6) {
                bit += MIMO_UL_STC_HARQ_Sub_Burst_IE(tree, bufptr, bit, bitlength, tvb);
            }
        }
    }

    pad = NIB_TO_BIT(offset) + bitlength - bit;
    if (pad) {
        proto_tree_add_text(tree, tvb, BITHI(bit,pad), "Padding: %d bits",pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);
}

static gint HARQ_ACKCH_Region_Allocation_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 8 */
    /* 8.4.5.4.25 [2] HARQ_ACKCH_Region_Allocation_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "HARQ_ACKCH_Region_IE");
    tree = proto_item_add_subtree(ti, ett_302t);

    XBIT(data, 4, "Extended-2 UIUC");
    XBIT(data, 8, "Length");

    XBIT(data, 8, "OFDMA Symbol Offset");
    XBIT(data, 7, "Subchannel Offset");
    XBIT(data, 5, "No. OFDMA Symbols");
    XBIT(data, 4, "No. Subchannels");
    return BIT_TO_NIB(bit);
}

static gint AAS_SDMA_UL_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 0xE */
    /* 8.4.5.4.27 [2] AAS_SDMA_UL_IE  */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    gint nreg, pad, user, encm, ppmd, padj;
    gint aasp = 0; /* TODO AAS UL preamble used */
    gint ii, jj;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "AAS_SDMA_UL_IE");
    tree = proto_item_add_subtree(ti, ett_302u);

    XBIT(data, 4, "Extended-2 UIUC");
    XBIT(data, 8, "Length");

    XBIT(RCID_Type, 2, "RCID_Type");
    XBIT(nreg, 4, "Num Burst Region");
    XBIT(data, 2, "Reserved");
    for (ii = 0; ii < nreg; ii++) {
        XBIT(data,12, "Slot offset");
        XBIT(data,10, "Slot duration");
        XBIT(user, 3, "Number of users");
        XBIT(data, 3, "Reserved");
        for (jj = 0; jj < user; jj++) {
            bit += RCID_IE(tree, bufptr, bit, length, tvb, RCID_Type);
            XBIT(encm, 2, "Encoding Mode");
            XBIT(padj, 1, "Power Adjust");
            XBIT(ppmd, 1, "Pilot Pattern Modifier");
            if (aasp) {
                XBIT(data, 4, "Preamble Modifier Index");
            }
            if (ppmd) {
                XBIT(data, 2, "Pilot Pattern");
                XBIT(data, 2, "Reserved");
            }
            if (encm == 0) {
                XBIT(data, 4, "DIUC");
                XBIT(data, 2, "Repetition Coding Indication");
                XBIT(data, 2, "Reserved");
            }
            if (encm == 1) {
                XBIT(data, 4, "DIUC");
                XBIT(data, 2, "Repetition Coding Indication");
                XBIT(data, 4, "ACID");
                XBIT(data, 1, "AI_SN");
                XBIT(data, 1, "Reserved");
            }
            if (encm == 2) {
                XBIT(data, 4, "N(EP)");
                XBIT(data, 4, "N(SCH)");
                XBIT(data, 2, "SPID");
                XBIT(data, 4, "ACID");
                XBIT(data, 1, "AI_SN");
                XBIT(data, 1, "Reserved");
            }
            if (encm == 3) {
                XBIT(data, 4, "DIUC");
                XBIT(data, 2, "Repetition Coding Indication");
                XBIT(data, 2, "SPID");
                XBIT(data, 4, "ACID");
                XBIT(data, 1, "AI_SN");
                XBIT(data, 3, "Reserved");
            }
            if (padj) {
                XBIT(data, 8, "Power Adjustment");

            }
        }
    }

    pad = BIT_PADDING(bit,8);
    if (pad) {
        proto_tree_add_text(tree, tvb, BITHI(bit, pad), "Padding: %d bits", pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);
}

static gint Feedback_Polling_IE(proto_tree *uiuc_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* UL-MAP Extended-2 IE = 0xF */
    /* 8.4.5.4.28 [2] Feedback_Polling_IE */
    /* offset of TLV in nibbles, length of TLV in nibbles */
    gint bit;
    gint data;
    proto_item *ti = NULL;
    proto_item *tree = NULL;
    gint nalloc, dula, pad, adur;
    gint i;

    bit = NIB_TO_BIT(offset);

    ti = proto_tree_add_text(uiuc_tree, tvb, NIBHI(offset, length), "Feedback_Polling_IE");
    tree = proto_item_add_subtree(ti, ett_302v);

    XBIT(data, 4, "Extended-2 UIUC");
    XBIT(data, 8, "Length");

    XBIT(nalloc, 4, "Num_Allocation");
    XBIT(dula, 1, "Dedicated UL Allocation included");
    XBIT(data, 3, "Reserved");
    for (i = 0; i < nalloc; i++) {
        XBIT(data,16, "Basic CID");
        XBIT(adur, 3, "Allocation Duration (d)");
        if (adur != 0) {
            XBIT(data, 4, "Feedback type");
            XBIT(data, 3, "Frame Offset");
            XBIT(data, 2, "Period (p)");
            if (dula == 1) {
                XBIT(data, 4, "UIUC");
                XBIT(data, 8, "OFDMA Symbol Offset");
                XBIT(data, 7, "Subchannel offset");
                XBIT(data, 3, "Duration");
                XBIT(data, 2, "Repetition coding indication");
            }
        }
    }
    pad = BIT_PADDING(bit,8);
    if (pad) {
        proto_tree_add_text(tree, tvb, BITHI(bit, pad), "Padding: %d bits", pad);
        bit += pad;
    }
    return BIT_TO_NIB(bit);
}


/********************************************************************
 * UL-MAP Miscellany
 *******************************************************************/

gint dissect_ulmap_ie( proto_tree *ie_tree, const guint8 *bufptr, gint offset, gint length _U_, tvbuff_t *tvb)
{
    /* decode a single UL-MAP IE and return the
     * length of the IE in nibbles
     * offset = start of IE (nibbles)
     * length = total length of bufptr (nibbles) */
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint nibble;
    gint uiuc, ext_uiuc, ext2_uiuc, len, aas_or_amc;
    guint cid;
    guint data;
    guint32 data32;

    nibble = offset;

    /* 8.4.5.4 UL-MAP IE format - table 287 */
    cid = TVB_NIB_WORD(nibble, tvb);
    uiuc = TVB_NIB_NIBBLE(nibble + 4, tvb);

    if (uiuc == 0)
    {
        /* 8.4.5.4.9 FAST-FEEDBACK channel */
        ti = proto_tree_add_text(ie_tree, tvb, NIBHI(nibble, 5+8), "FAST FEEDBACK Allocation IE");
        tree = proto_item_add_subtree(ti, ett_ulmap_ffb);

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

        data = NIB_LONG(nibble, bufptr);
        proto_tree_add_uint(tree, hf_ulmap_uiuc0_symofs, tvb, NIBHI(nibble, 8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc0_subofs, tvb, NIBHI(nibble, 8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc0_numsym, tvb, NIBHI(nibble, 8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc0_numsub, tvb, NIBHI(nibble, 8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc0_rsv,    tvb, NIBHI(nibble, 8), data);
        nibble += 8;
    }
    else if (uiuc == 11)
    {
        /* 8.4.5.4.4.2 [2] extended-2 UIUC IE table 290b */
        ext2_uiuc = NIB_NIBBLE(5+nibble, bufptr);
        len = NIB_BYTE(5+nibble+1, bufptr);

        ti = proto_tree_add_text(ie_tree, tvb, NIBHI(nibble, 5+3+len*2), "UIUC: %d (Extended-2 IE)", uiuc);
        tree = proto_item_add_subtree(ti, ett_290b);

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

#if 0
        proto_tree_add_uint(tree, hf_ulmap_uiuc11_ext, tvb, NIBHI(nibble, 1), ext2_uiuc);
        nibble += 1;
        proto_tree_add_uint(tree, hf_ulmap_uiuc11_len, tvb, NIBHI(nibble, 2), len);
        nibble += 2;
#endif

        len = 3 + BYTE_TO_NIB(len); /* length in nibbles */

        /* data table 290c 8.4.5.4.4.2 */
        switch (ext2_uiuc) {
            case 0x00:
                /* 8.4.5.4.16 CQICH_Enhanced_Allocation_IE */
                nibble = CQICH_Enhanced_Allocation_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x01:
                /* 8.4.5.4.18 HO_Anchor_Active_UL_MAP_IE */
                nibble = HO_Anchor_Active_UL_MAP_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x02:
                /* 8.4.5.4.19 HO_Active_Anchor_UL_MAP_IE */
                nibble = HO_Active_Anchor_UL_MAP_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x03:
                /* 8.4.5.4.23 Anchor_BS_switch_IE */
                nibble = Anchor_BS_switch_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x04:
                /* 8.4.5.4.26 UL_sounding_command_IE */
                nibble = UL_sounding_command_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x06:
                /* 8.4.5.4.20 MIMO_UL_Enhanced_IE */
                nibble = MIMO_UL_Enhanced_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x07:
                /* 8.4.5.4.24 HARQ_ULMAP_IE */
                nibble = HARQ_ULMAP_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x08:
                /* 8.4.5.4.25 HARQ_ACKCH_Region_Allocation_IE */
                nibble = HARQ_ACKCH_Region_Allocation_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x0e:
                /* 8.4.5.4.27 AAS_SDMA_UL_IE */
                nibble = AAS_SDMA_UL_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x0f:
                /* 8.4.5.4.28 Feedback_Polling_IE */
                nibble = Feedback_Polling_IE(tree, bufptr, nibble, len, tvb);
                break;

            default:
                proto_tree_add_text(tree, tvb, NIBHI(nibble, len), "(reserved Extended-2 UIUC: %d)", ext2_uiuc);
		nibble += len;
                break;

        }
    }
    else if (uiuc == 12)
    {
        /* 8.4.5.4 [2] CDMA bandwidth request, CDMA ranging */
        ti = proto_tree_add_text(ie_tree, tvb, NIBHI(nibble, 5+8), "CDMA Bandwidth/Ranging Request IE");
        tree = proto_item_add_subtree(ti, ett_287_1);

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

        data32 = NIB_LONG(nibble, bufptr);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_symofs, tvb, NIBHI(nibble,8), data32);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_subofs, tvb, NIBHI(nibble,8), data32);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_numsym, tvb, NIBHI(nibble,8), data32);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_numsub, tvb, NIBHI(nibble,8), data32);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_method, tvb, NIBHI(nibble,8), data32);
        proto_tree_add_uint(tree, hf_ulmap_uiuc12_dri,    tvb, NIBHI(nibble,8), data32);
        nibble += 8;
    }
    else if (uiuc == 13)
    {
        /* 8.4.5.4.2 [2] PAPR reduction allocation, safety zone - table 289 */
        ti = proto_tree_add_text(ie_tree, tvb, NIBHI(nibble,5+8), "PAPR/Safety/Sounding Zone IE");
        tree = proto_item_add_subtree(ti, ett_289);


        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

        data = NIB_LONG(nibble, bufptr);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_symofs, tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_subofs, tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_numsym, tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_numsub, tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_papr,   tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_zone,   tvb, NIBHI(nibble,8), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc13_rsv,    tvb, NIBHI(nibble,8), data);
        nibble += 8;
    }
    else if (uiuc == 14)
    {
        /* 8.4.5.4.3 [2] CDMA allocation IE */
        ti = proto_tree_add_text(ie_tree, tvb, NIBHI(nibble,5+10), "CDMA allocation IE");
        tree = proto_item_add_subtree(ti, ett_290);

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

        data = NIB_WORD(nibble, bufptr);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_dur,  tvb, NIBHI(nibble,2), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_uiuc, tvb, NIBHI(nibble+1,2), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_rep,  tvb, NIBHI(nibble+2,1), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_idx,  tvb, NIBHI(nibble+3,1), data);
        nibble += 4;

        data = NIB_BYTE(nibble, bufptr);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_code, tvb, NIBHI(nibble,2), data);
        proto_item_append_text(ti, " (0x%02x)", data);
        nibble += 2;

        data = NIB_BYTE(nibble, bufptr);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_sym,  tvb, NIBHI(nibble,2), data);
        proto_item_append_text(ti, " (0x%02x)", data);
        nibble += 2;

        data = NIB_BYTE(nibble, bufptr);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_sub,  tvb, NIBHI(nibble,2), data);
        proto_item_append_text(ti, " (0x%02x)", data >> 1);
        proto_tree_add_uint(tree, hf_ulmap_uiuc14_bwr,  tvb, NIBHI(nibble+1,1), data);
        nibble += 2;
    }
    else if (uiuc == 15)
    {
        /* 8.4.5.4.4 [1] Extended UIUC dependent IE table 291 */
        ext_uiuc = NIB_NIBBLE(5+nibble, bufptr);
        len = NIB_NIBBLE(5+nibble+1, bufptr);

        ti = proto_tree_add_text(ie_tree, tvb, NIBHI(nibble, 5+2+len*2), "UIUC: %d (Extended IE)", uiuc);
        tree = proto_item_add_subtree(ti, ett_291);

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble,4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble,1), uiuc);
        nibble += 1;

#if 0
        ti = proto_tree_add_uint(tree, hf_ulmap_uiuc11_ext, tvb, NIBHI(nibble,1), ext_uiuc);
        nibble += 1;
        proto_tree_add_uint(tree, hf_ulmap_uiuc11_len, tvb, NIBHI(nibble,1), len);
        nibble += 1;
#endif

        len = 2 + BYTE_TO_NIB(len); /* length in nibbles */

        /* data table 290a 8.4.5.4.4.1 */
        switch (ext_uiuc) {
            case 0x00:
                /* 8.4.5.4.5 Power_Control_IE */
                nibble = Power_Control_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x01:
                /* 8.4.5.4.8 Mini-Subchannel_allocation_IE*/
                nibble = Mini_Subchannel_allocation_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x02:
                /* 8.4.5.4.6 AAS_UL_IE*/
                nibble = AAS_UL_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x03:
                /* 8.4.5.4.12 CQICH_Alloc_IE */
                nibble = CQICH_Alloc_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x04:
                /* 8.4.5.4.7 UL_Zone_IE */
                nibble = UL_Zone_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x05:
                /* 8.4.5.4.14 PHYMOD_UL_IE */
                nibble = PHYMOD_UL_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x06:
                /* 8.4.5.4.11 MIMO_UL_IE */
                nibble = MIMO_UL_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x07:
                /* 8.4.5.4.22 ULMAP_Fast_Tracking_IE */
                nibble = ULMAP_Fast_Tracking_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x08:
                /* 8.4.5.4.17 UL_PUSC_Burst_Allocation_in_other_segment_IE */
                nibble = UL_PUSC_Burst_Allocation_in_other_segment_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x09:
                /* 8.4.5.4.21 Fast_Ranging_IE */
                nibble = Fast_Ranging_IE(tree, bufptr, nibble, len, tvb);
                break;
            case 0x0a:
                /* 8.4.5.4.15 UL_Allocation_Start_IE */
                nibble = UL_Allocation_Start_IE(tree, bufptr, nibble, len, tvb);
                break;
            default:
                proto_tree_add_text(tree, tvb, NIBHI(nibble,len), "(reserved Extended UIUC: %d)", ext_uiuc);
		nibble += len;
                break;
        }
    }
    else
    {
        /* 8.4.5.4 [2] regular IE 1-10, data grant burst type */
        aas_or_amc = 0; /* TODO */
        len = 3;

        if (aas_or_amc) len += 3;

        ti = proto_tree_add_text(ie_tree, tvb, NIBHI(nibble, 5+len), "Data Grant Burst Profile");
        tree = proto_item_add_subtree(ti, ett_287_2);

        proto_tree_add_uint(tree, hf_ulmap_ie_cid, tvb, NIBHI(nibble, 4), cid);
        nibble += 4;
        proto_tree_add_uint(tree, hf_ulmap_ie_uiuc, tvb, NIBHI(nibble, 1), uiuc);
        nibble += 1;

        data = NIB_WORD(nibble, bufptr);
        proto_tree_add_uint(tree, hf_ulmap_uiuc10_dur, tvb, NIBHI(nibble,3), data);
        proto_tree_add_uint(tree, hf_ulmap_uiuc10_rep, tvb, NIBHI(nibble+2,1), data);
        nibble += 3;

        if (aas_or_amc) {
            data = NIB_BITS12(nibble, bufptr);
            proto_tree_add_text(tree, tvb, NIBHI(nibble,3), "Slot offset: %d", data);
            nibble += 3;
        }
    }

    /* length in nibbles */
    return (nibble - offset);
}

static void dissect_mac_mgmt_msg_ulmap_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    /* 6.3.2.3.4 [2] UL-MAP table 18 */
    guint offset = 0;
    guint length;
    guint nib, pad;
    proto_item *ti         = NULL;
    proto_tree *ulmap_tree = NULL;
    proto_tree *ie_tree    = NULL;
    guint tvb_len;
    const guint8 *bufptr;

    tvb_len = tvb_reported_length(tvb);
    /* XXX This should be removed, and regular tvb accessors should be used instead. */
    bufptr = tvb_get_ptr(tvb, offset, tvb_len);

    /* display MAC UL-MAP */
    ti = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_ulmap_decoder, tvb, offset, -1, "UL-MAP");
    ulmap_tree = proto_item_add_subtree(ti, ett_ulmap);

    proto_tree_add_item(ulmap_tree, hf_ulmap_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ulmap_tree, hf_ulmap_ucd_count, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ulmap_tree, hf_ulmap_alloc_start_time, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ulmap_tree, hf_ulmap_ofdma_sym, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* UL-MAP IEs */
    length = tvb_len - offset; /* remaining length in bytes */
    ti = proto_tree_add_text(ulmap_tree, tvb, offset, length, "UL-MAP IEs (%u bytes)", length);
    ie_tree = proto_item_add_subtree(ti, ett_ulmap_ie);

    /* length = BYTE_TO_NIB(length); */ /* convert length to nibbles */
    nib = BYTE_TO_NIB(offset);
    while (nib < ((tvb_len*2)-1)) {
        nib += dissect_ulmap_ie(ie_tree, bufptr, nib, tvb_len*2, tvb);
    }
    pad = NIB_PADDING(nib);
    if (pad) {
        proto_tree_add_text(ulmap_tree, tvb, NIBHI(nib,1), "Padding nibble");
        nib++;
    }
}

/*gint wimax_decode_ulmapc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)*/
gint wimax_decode_ulmapc(proto_tree *base_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.6.2 [2] Compressed UL-MAP */
    /* returns length in nibbles */
    gint nib;
    guint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    proto_tree *ie_tree = NULL;

    nib = offset;

    /* display MAC UL-MAP */
    ti = proto_tree_add_protocol_format(base_tree, proto_mac_mgmt_msg_ulmap_decoder, tvb, NIBHI(offset,length-offset), "Compressed UL-MAP (%u bytes)", NIB_ADDR(length-offset));
    tree = proto_item_add_subtree(ti, ett_306);

    /* Decode and display the UL-MAP */
    data = NIB_BYTE(nib, bufptr);
    proto_tree_add_uint(tree, hf_ulmap_ucd_count, tvb, NIBHI(nib,2), data);
    nib += 2;
    data = NIB_LONG(nib, bufptr);
    proto_tree_add_uint(tree, hf_ulmap_alloc_start_time, tvb, NIBHI(nib,8), data);
    nib += 8;
    data = NIB_BYTE(nib, bufptr);
    proto_tree_add_uint(tree, hf_ulmap_ofdma_sym, tvb, NIBHI(nib,2), data); /* added 2005 */
    nib += 2;

    ti = proto_tree_add_text(tree, tvb, NIBHI(nib,length-nib), "UL-MAP IEs (%u bytes)", NIB_ADDR(length-nib));
    ie_tree = proto_item_add_subtree(ti, ett_306_ul);
    while (nib < length-1) {
        nib += dissect_ulmap_ie(ie_tree, bufptr, nib, length-nib, tvb);
    }

    /* padding */
    if (nib & 1) {
        proto_tree_add_text(tree, tvb, NIBHI(nib,1), "Padding Nibble");
        nib++;
    }


    return length;
}


gint wimax_decode_ulmap_reduced_aas(proto_tree *base_tree, const guint8 *bufptr, gint offset, gint length, tvbuff_t *tvb)
{
    /* 8.4.5.8.2 Reduced AAS private UL-MAP */
    /* offset and length are in bits since this is called from within
     * the Reduced AAS private DL-MAP
     * return length in bits */
    gint bit;
    guint data;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    gint azci, azpi, umii, phmi, powi, fbck;

    bit = offset;

    ti = proto_tree_add_text(base_tree, tvb, BITHI(bit,length), "Reduced_AAS_Private_UL_MAP");
    tree = proto_item_add_subtree(ti, ett_308b);

    /* Decode and display the Reduced AAS private UL-MAP */
    XBIT(azci, 1, "AAS zone configuration included");
    XBIT(azpi, 1, "AAS zone position included");
    XBIT(umii, 1, "UL-MAP information included");
    XBIT(phmi, 1, "PHY modification included");
    XBIT(powi, 1, "Power Control included");
    XBIT(fbck, 2, "Include Feedback Header");
    XBIT(data, 2, "Encoding Mode");

    if (azci) {
        XBIT(data, 2, "Permutation");
        XBIT(data, 7, "UL_PermBase");
        XBIT(data, 2, "Preamble Indication");
        XBIT(data, 5, "Padding");
    }
    if (azpi) {
        XBIT(data, 8, "Zone Symbol Offset");
        XBIT(data, 8, "Zone Length");
    }
    if (umii) {
        XBIT(data, 8, "UCD Count");
        data = BIT_BITS64(bit,bufptr,32);
        proto_tree_add_text(tree, tvb, BITHI(bit,32), "Private Map Allocation Start Time: %u",data);
        bit += 32;
    }
    if (phmi) {
        XBIT(data, 1, "Preamble Select");
        XBIT(data, 4, "Preamble Shift Index");
        XBIT(data, 1, "Pilot Pattern Modifier");
        data = BIT_BITS32(bit,bufptr,22);
        proto_tree_add_text(tree, tvb, BITHI(bit,22), "Pilot Pattern Index: %u",data);
        bit += 22;
    }
    if (powi) {
        XBIT(data, 8, "Power Control");
    }
    XBIT(data, 3, "UL Frame Offset");
    XBIT(data,12, "Slot Offset");
    XBIT(data,10, "Slot Duration");
    XBIT(data, 4, "UIUC / N(EP)");
    if (harq) {
        XBIT(data, 4, "ACID");
        XBIT(data, 1, "AI_SN");
        XBIT(data, 3, "Reserved");
        if (ir_type) {
            XBIT(data, 4, "N(SCH)");
            XBIT(data, 2, "SPID");
            XBIT(data, 2, "Reserved");
        }
    }
    XBIT(data, 2, "Repetition Coding Indication");

    return (bit - offset); /* length in bits */
}


/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_ulmap(void)
{
	/* UL-MAP fields display */
	static hf_register_info hf[] =
	{
#if 0
		{
			&hf_ulmap_fch_expected,
			{
				"FCH Expected", "wmx.ulmap.fch.expected",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#endif
#if 0
		{
			&hf_ulmap_ie,
			{
				"UL-MAP IE", "wmx.ulmap.ie",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#endif
		{
			&hf_ulmap_ie_cid,
			{
				"CID", "wmx.ulmap.ie.cid",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_ie_uiuc,
			{
				"UIUC", "wmx.ulmap.ie.uiuc",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_ofdma_sym,
			{
				"Num OFDMA Symbols", "wmx.ulmap.ofdma.sym",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_reserved,
			{
				"Reserved", "wmx.ulmap.rsv",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_alloc_start_time,
			{
				"Uplink Channel ID", "wmx.ulmap.start",
				FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_ucd_count,
			{
				"UCD Count", "wmx.ulmap.ucd",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc0_numsub,
			{
				"No. subchannels", "wmx.ulmap.uiuc0.numsub",
				FT_UINT32,	BASE_DEC, NULL, 0x000003f8, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc0_numsym,
			{
				"No. OFDMA symbols", "wmx.ulmap.uiuc0.numsym",
				FT_UINT32,	BASE_DEC, NULL, 0x0001fc00, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc0_rsv,
			{
				"Reserved", "wmx.ulmap.uiuc0.rsv",
				FT_UINT32,	BASE_DEC, NULL, 0x00000007, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc0_subofs,
			{
				"Subchannel offset", "wmx.ulmap.uiuc0.subofs",
				FT_UINT32,	BASE_DEC, NULL, 0x00fe0000, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc0_symofs,
			{
				"OFDMA symbol offset", "wmx.ulmap.uiuc0.symofs",
				FT_UINT32,	BASE_DEC, NULL, 0xff000000, NULL, HFILL
			}
		},
#if 0
		{
			&hf_ulmap_uiuc11_data,
			{
				"Data", "wmx.ulmap.uiuc11.data",
				FT_BYTES,  BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc11_ext,
			{
				"Extended 2 UIUC", "wmx.ulmap.uiuc11.ext",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc11_len,
			{
				"Length", "wmx.ulmap.uiuc11.len",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#endif
		{
			&hf_ulmap_uiuc12_dri,
			{
				"Dedicated ranging indicator", "wmx.ulmap.uiuc12.dri",
				FT_UINT32, BASE_DEC, NULL, 0x00000001, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc10_dur,
			{
				"Duration", "wmx.ulmap.uiuc12.dur",
				FT_UINT16, BASE_DEC, NULL, 0xFFc0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc12_method,
			{
				"Ranging Method", "wmx.ulmap.uiuc12.method",
				FT_UINT32, BASE_DEC, NULL, 0x00000006, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc12_numsub,
			{
				"No. Subchannels", "wmx.ulmap.uiuc12.numsub",
				FT_UINT32, BASE_DEC, NULL, 0x000003F8, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc12_numsym,
			{
				"No. OFDMA Symbols", "wmx.ulmap.uiuc12.numsym",
				FT_UINT32, BASE_DEC, NULL, 0x0001Fc00, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc10_rep,
			{
				"Repetition Coding indication", "wmx.ulmap.uiuc12.rep",
				FT_UINT16, BASE_DEC, NULL, 0x0030, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc12_subofs,
			{
				"Subchannel Offset", "wmx.ulmap.uiuc12.subofs",
				FT_UINT32, BASE_DEC, NULL, 0x00Fe0000, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc12_symofs,
			{
				"OFDMA Symbol Offset", "wmx.ulmap.uiuc12.symofs",
				FT_UINT32, BASE_DEC, NULL, 0xFF000000, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_numsub,
			{
				"No. Subchannels/SZ Shift Value", "wmx.ulmap.uiuc13.numsub",
				FT_UINT32,	BASE_DEC, NULL, 0x000003f8, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_numsym,
			{
				"No. OFDMA symbols", "wmx.ulmap.uiuc13.numsym",
				FT_UINT32,	BASE_DEC, NULL, 0x0001fc00, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_papr,
			{
				"PAPR Reduction/Safety Zone", "wmx.ulmap.uiuc13.papr",
				FT_UINT32,	BASE_DEC, NULL, 0x00000004, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_rsv,
			{
				"Reserved", "wmx.ulmap.uiuc13.rsv",
				FT_UINT32,	BASE_DEC, NULL, 0x00000001, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_subofs,
			{
				"Subchannel offset", "wmx.ulmap.uiuc13.subofs",
				FT_UINT32,	BASE_DEC, NULL, 0x00fe0000, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_symofs,
			{
				"OFDMA symbol offset", "wmx.ulmap.uiuc13.symofs",
				FT_UINT32,	BASE_DEC, NULL, 0xff000000, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc13_zone,
			{
				"Sounding Zone", "wmx.ulmap.uiuc13.zone",
				FT_UINT32,	BASE_DEC, NULL, 0x00000002, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_bwr,
			{
				"BW request mandatory", "wmx.ulmap.uiuc14.bwr",
				FT_UINT8,  BASE_DEC, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_code,
			{
				"Ranging code", "wmx.ulmap.uiuc14.code",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_dur,
			{
				"Duration", "wmx.ulmap.uiuc14.dur",
				FT_UINT16, BASE_DEC, NULL, 0xfc00, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_idx,
			{
				"Frame Number Index", "wmx.ulmap.uiuc14.idx",
				FT_UINT16, BASE_DEC, NULL, 0x000F, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_rep,
			{
				"Repetition Coding Indication", "wmx.ulmap.uiuc14.rep",
				FT_UINT16, BASE_DEC, NULL, 0x0030, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_sub,
			{
				"Ranging subchannel", "wmx.ulmap.uiuc14.sub",
				FT_UINT8,  BASE_DEC, NULL, 0xfe, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_sym,
			{
				"Ranging symbol", "wmx.ulmap.uiuc14.sym",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc14_uiuc,
			{
				"UIUC", "wmx.ulmap.uiuc14.uiuc",
				FT_UINT16, BASE_DEC, NULL, 0x03c0, NULL, HFILL
			}
		},
#if 0
		{
			&hf_ulmap_uiuc15_data,
			{
				"Data", "wmx.ulmap.uiuc15.data",
				FT_BYTES,  BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc15_ext,
			{
				"Extended UIUC", "wmx.ulmap.uiuc15.ext",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_ulmap_uiuc15_len,
			{
				"Length", "wmx.ulmap.uiuc15.len",
				FT_UINT8,  BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		}
#endif
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_ulmap,
			&ett_ulmap_ie,
			&ett_ulmap_ffb,
			/* &ett_ulmap_c,    */
			/* &ett_ulmap_c_ie, */
			/* &ett_ulmap_s,    */
			/* &ett_ulmap_s_ie, */
			&ett_287_1,
			&ett_287_2,
			&ett_289,
			&ett_290,
			&ett_290b,
			&ett_291,
			&ett_292,
			&ett_293,
			&ett_294,
			&ett_295,
			&ett_299,
			&ett_300,
			&ett_302,
			&ett_302a,
			&ett_302b,
			&ett_302c,
			&ett_302d,
			&ett_302e,
			&ett_302f,
			&ett_302h,
			&ett_302g,
			&ett_302i,
			&ett_302j,
			&ett_302k,
			&ett_302l,
			&ett_302m,
			&ett_302n,
			&ett_302o,
			&ett_302p,
			&ett_302q,
			&ett_302r,
			&ett_302s,
			&ett_302t,
			&ett_302u,
			&ett_302v,
			&ett_306,
			&ett_306_ul,
			&ett_308b,
			&ett_315d,
		};

	proto_mac_mgmt_msg_ulmap_decoder = proto_register_protocol (
                "WiMax ULMAP Messages", /* name       */
                "WiMax ULMAP",    /* short name */
                "wmx.ulmap"       /* abbrev     */
                );

	proto_register_field_array(proto_mac_mgmt_msg_ulmap_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_mac_mgmt_msg_ulmap(void)
{
	dissector_handle_t ulmap_handle;

	ulmap_handle = create_dissector_handle(dissect_mac_mgmt_msg_ulmap_decoder, proto_mac_mgmt_msg_ulmap_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_UL_MAP, ulmap_handle);
}
