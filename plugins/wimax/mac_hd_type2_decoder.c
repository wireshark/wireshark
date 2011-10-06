/* mac_hd_type2_decoder.c
 * WiMax MAC Type II Signaling Header decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
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

/* TODO:  Add FT_UINT24 and FT_INT24 cases to gtk_widget_get_toplevel()
 * to prevent having to make all the changes from BASE_DEC to BASE_HEX
 * made to this file today: 10/20/06.
 */

/*
#define DEBUG
*/

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

extern gint proto_mac_header_generic_decoder;

static gint proto_mac_header_type_2_decoder = -1;
static gint ett_mac_header_type_2_decoder = -1;
static gint hf_mac_header_type_2_value_bytes = -1;

#define WIMAX_MAC_HEADER_SIZE  6

/* WiMax MAC Header Type II Feedback Types */
enum
{
	CQI_MIMO_FB,         /* 0 */
	DL_AVG_CINR,         /* 1 */
	MIMO_COEF_FB,        /* 2 */
	PREF_DL_CHAN_DIUC_FB,/* 3 */
	UL_TX_PWR,           /* 4 */
	PHY_CHAN_FB,         /* 5 */
	AMC_BAND_BITMAP,     /* 6 */
	SHORT_PRECODE_FB,    /* 7 */
	MULTI_TYPES_FB,      /* 8 */
	LONG_PRECODE_FB,     /* 9 */
	COMB_DL_AVG_CINR,    /* 10 */
	MIMO_CHAN_FB,        /* 11 */
	CINR_FB,             /* 12 */
	CL_MIMO_FB,          /* 13 */
	TYPE_II_FB_TYPE_MAX
} TYPE_II_FB_TYPE;

static char *type2_fb_type_abbrv[TYPE_II_FB_TYPE_MAX] =
{
	"CQI and MIMO Feedback",
	"DL average CINR",
	"MIMO Coefficients Feedback",
	"Preferred DL Channel DIUC Feedback",
	"UL Transmission Power",
	"PHY Channel Feedback",
	"AMC Band Indication Bitmap",
	"Life Span of Short-term Precoding Feedback",
	"Multiple Types of Feedback",
	"Long-term Precoding Feedback",
	"Combined DL Average CINR of Active BSs",
	"MIMO Channel Feedback",
	"CINR Feedback",
	"Close-loop MIMO Feedback"
};

/* WIMAX MAC HEADER TYPE II FILEDS */
/* first byte */
#define WIMAX_MAC_HEADER_TYPE_2_HT           0x80
#define WIMAX_MAC_HEADER_TYPE_2_EC           0x40
#define WIMAX_MAC_HEADER_TYPE_2_TYPE         0x20
#define WIMAX_MAC_HEADER_TYPE_2_CII          0x10
#define WIMAX_MAC_HEADER_TYPE_2_FB_TYPE      0x0F
static int hf_mac_header_type_2_ht = -1;
static int hf_mac_header_type_2_ec = -1;
static int hf_mac_header_type_2_type = -1;
static int hf_mac_header_type_2_cii = -1;
static int hf_mac_header_type_2_fb_type = -1;

/* 2nd to 5th bytes (varies by different fb types) */
static int hf_mac_header_type_2_cid = -1;
static int hf_mac_header_type_2_no_cid = -1;
/* CQI and MIMO Feedback */
/* 2nd & 3rd bytes */
#define WIMAX_MAC_HEADER_TYPE_2_CQI_FB_TYPE  0xE000
#define WIMAX_MAC_HEADER_TYPE_2_CQI_PAYLOAD  0x1F80
#define WIMAX_MAC_HEADER_TYPE_2_CQI_RSV      0x007F
static int hf_mac_header_type_2_cqi_fb_type = -1;
static int hf_mac_header_type_2_cqi_payload = -1;
static int hf_mac_header_type_2_cqi_rsv = -1;
/* 4th & 5th without CID */
/*#define WIMAX_MAC_HEADER_TYPE_2_NO_CID       0xFFFF*/

/* DL average CINR */
/* 2nd byte */
#define WIMAX_MAC_HEADER_TYPE_2_DL_AVE_CINR  0xF800
#define WIMAX_MAC_HEADER_TYPE_2_DL_AVE_RSV   0x07FF
static int hf_mac_header_type_2_dl_ave_cinr = -1;
static int hf_mac_header_type_2_dl_ave_rsv = -1;

/* MIMO Coefficients Feedback */
/* 2nd & 3rd bytes */
#define WIMAX_MAC_HEADER_TYPE_2_MIMO_COEF_NI   0xC000
#define WIMAX_MAC_HEADER_TYPE_2_MIMO_COEF_AI   0x3000
#define WIMAX_MAC_HEADER_TYPE_2_MIMO_COEF      0x0F80
#define WIMAX_MAC_HEADER_TYPE_2_MIMO_COEF_RSV  0x007F
static int hf_mac_header_type_2_mimo_coef_ni = -1;
static int hf_mac_header_type_2_mimo_coef_ai = -1;
static int hf_mac_header_type_2_mimo_coef = -1;
static int hf_mac_header_type_2_mimo_coef_rsv = -1;

/* Preferred DL Channel DIUC Feedback */
/* 2nd byte */
#define WIMAX_MAC_HEADER_TYPE_2_DL_CHAN_DIUC  0xF000
#define WIMAX_MAC_HEADER_TYPE_2_DL_CHAN_DCD   0x0F00
#define WIMAX_MAC_HEADER_TYPE_2_DL_CHAN_RSV   0x00FF
static int hf_mac_header_type_2_dl_chan_diuc = -1;
static int hf_mac_header_type_2_dl_chan_dcd = -1;
static int hf_mac_header_type_2_dl_chan_rsv = -1;

/* UL Transmission Power */
/* 2nd byte */
#define WIMAX_MAC_HEADER_TYPE_2_UL_TX_PWR     0xFF00
#define WIMAX_MAC_HEADER_TYPE_2_UL_TX_PWR_RSV 0x00FF
static int hf_mac_header_type_2_ul_tx_pwr = -1;
static int hf_mac_header_type_2_ul_tx_pwr_rsv = -1;

/* PHY Channel Feedback */
/* 2nd to 4th bytes */
#define WIMAX_MAC_HEADER_TYPE_2_PHY_DIUC      0xF00000
#define WIMAX_MAC_HEADER_TYPE_2_PHY_UL_TX_PWR 0x0FF000
#define WIMAX_MAC_HEADER_TYPE_2_PHY_UL_HDRM   0x000FC0
#define WIMAX_MAC_HEADER_TYPE_2_PHY_RSV       0x00003F
static int hf_mac_header_type_2_phy_diuc = -1;
static int hf_mac_header_type_2_phy_ul_tx_pwr = -1;
static int hf_mac_header_type_2_phy_ul_hdrm = -1;
static int hf_mac_header_type_2_phy_rsv = -1;

/* AMC Band Indication Bitmap */
/* 2nd to 5th bytes */
#define WIMAX_MAC_HEADER_TYPE_2_AMC_BITMAP   0xFFF00000
#define WIMAX_MAC_HEADER_TYPE_2_AMC_CQI_1    0x000F8000
#define WIMAX_MAC_HEADER_TYPE_2_AMC_CQI_2    0x00007C00
#define WIMAX_MAC_HEADER_TYPE_2_AMC_CQI_3    0x000003E0
#define WIMAX_MAC_HEADER_TYPE_2_AMC_CQI_4    0x0000001F
static int hf_mac_header_type_2_amc_bitmap = -1;
static int hf_mac_header_type_2_amc_cqi_1 = -1;
static int hf_mac_header_type_2_amc_cqi_2 = -1;
static int hf_mac_header_type_2_amc_cqi_3 = -1;
static int hf_mac_header_type_2_amc_cqi_4 = -1;

/* Life Span of Short-term Precoding Feedback */
/* 2nd byte */
#define WIMAX_MAC_HEADER_TYPE_2_LIFE_SPAN  0xF000
#define WIMAX_MAC_HEADER_TYPE_2_LIFE_SPAN_RSV 0x0FFF
static int hf_mac_header_type_2_life_span = -1;
static int hf_mac_header_type_2_life_span_rsv = -1;

/* Multiple Types of Feedback */
/* 2nd to 5th bytes ??? */
#define WIMAX_MAC_HEADER_TYPE_2_MT_NUM_FB_TYPES 0xC0000000
#define WIMAX_MAC_HEADER_TYPE_2_MT_OCCU_FB_TYPE 0x3C000000
#define WIMAX_MAC_HEADER_TYPE_2_MT_FB_CONTENTS  0x03FFFFFF
static int hf_mac_header_type_2_mt_num_fb_types = -1;
static int hf_mac_header_type_2_mt_occu_fb_type = -1;
static int hf_mac_header_type_2_mt_fb_contents = -1;

/* Long-term Precoding Feedback */
/* 2nd & 3rd bytes */
#define WIMAX_MAC_HEADER_TYPE_2_LT_ID_FB     0xFC00
#define WIMAX_MAC_HEADER_TYPE_2_LT_RANK      0x0300
#define WIMAX_MAC_HEADER_TYPE_2_LT_FEC_QAM   0x00FC
#define WIMAX_MAC_HEADER_TYPE_2_LT_RSV       0x0003
static int hf_mac_header_type_2_lt_id_fb = -1;
static int hf_mac_header_type_2_lt_rank = -1;
static int hf_mac_header_type_2_lt_fec_qam = -1;
static int hf_mac_header_type_2_lt_rsv = -1;

/* Combined DL Average CINR of Active BSs */
/* 2nd & 3rd bytes */
#define WIMAX_MAC_HEADER_TYPE_2_COMB_DL_AVE  0xF800
#define WIMAX_MAC_HEADER_TYPE_2_COMB_DL_RSV  0x0EFF
static int hf_mac_header_type_2_comb_dl_ave = -1;
static int hf_mac_header_type_2_comb_dl_rsv = -1;

/* MIMO Channel Feedback */
/* 2nd byte */
#define WIMAX_MAC_HEADER_TYPE_2_DIUC         0xF0
#define WIMAX_MAC_HEADER_TYPE_2_PBWI         0x0F
/* 3rd to 5th bytes with CID */
#define WIMAX_MAC_HEADER_TYPE_2_SLPB         0xFE0000
#define WIMAX_MAC_HEADER_TYPE_2_PBRI_CID     0x010000
#define WIMAX_MAC_HEADER_TYPE_2_CID          0x00FFFF
/* 3rd to 5th bytes without CID */
#define WIMAX_MAC_HEADER_TYPE_2_PBRI         0x018000
#define WIMAX_MAC_HEADER_TYPE_2_CTI          0x007000
#define WIMAX_MAC_HEADER_TYPE_2_AI_0         0x000800
#define WIMAX_MAC_HEADER_TYPE_2_AI_1         0x000400
#define WIMAX_MAC_HEADER_TYPE_2_AI_2         0x000200
#define WIMAX_MAC_HEADER_TYPE_2_AI_3         0x000100
#define WIMAX_MAC_HEADER_TYPE_2_MI           0x0000C0
#define WIMAX_MAC_HEADER_TYPE_2_CT           0x000020
#define WIMAX_MAC_HEADER_TYPE_2_CQI          0x00001F
static int hf_mac_header_type_2_mimo_diuc = -1;
static int hf_mac_header_type_2_mimo_pbwi = -1;
static int hf_mac_header_type_2_mimo_slpb = -1;
static int hf_mac_header_type_2_mimo_bpri = -1;
static int hf_mac_header_type_2_mimo_bpri_cid = -1;
static int hf_mac_header_type_2_mimo_cid = -1;
static int hf_mac_header_type_2_mimo_cti = -1;
static int hf_mac_header_type_2_mimo_ai_0 = -1;
static int hf_mac_header_type_2_mimo_ai_1 = -1;
static int hf_mac_header_type_2_mimo_ai_2 = -1;
static int hf_mac_header_type_2_mimo_ai_3 = -1;
static int hf_mac_header_type_2_mimo_mi = -1;
static int hf_mac_header_type_2_mimo_ct = -1;
static int hf_mac_header_type_2_mimo_cqi = -1;

/* CINR Feedback */
/* 2nd byte */
/*#define WIMAX_MAC_HEADER_TYPE_2_CINR_MEAN    0xFF*/
/* 3rd byte */
/*#define WIMAX_MAC_HEADER_TYPE_2_CINR_DEVI    0xFF*/
static int hf_mac_header_type_2_cinr_mean = -1;
static int hf_mac_header_type_2_cinr_devi = -1;

/* Close-loop MIMO Feedback */
/* 2nd & 3rd bytes */
#define WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_TYPE        0xC000
#define WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_ANT_ID      0x3C00
#define WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_CQI         0x03E0
#define WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_RSV         0x008F
#define WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_STREAMS     0x3000
#define WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_ANT_SEL     0x0E00
#define WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_CQI_1       0x01F0
#define WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_RSV_1       0x000F
#define WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_CODEBOOK_ID 0x3F00
#define WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_CQI_2       0x00F8
#define WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_RSV_2       0x000E
static int hf_mac_header_type_2_cl_mimo_type = -1;
static int hf_mac_header_type_2_cl_mimo_ant_id = -1;
static int hf_mac_header_type_2_cl_mimo_cqi = -1;
static int hf_mac_header_type_2_cl_mimo_cqi_1 = -1;
static int hf_mac_header_type_2_cl_mimo_cqi_2 = -1;
static int hf_mac_header_type_2_cl_mimo_rsv = -1;
static int hf_mac_header_type_2_cl_mimo_rsv_1 = -1;
static int hf_mac_header_type_2_cl_mimo_rsv_2 = -1;
static int hf_mac_header_type_2_cl_mimo_streams = -1;
static int hf_mac_header_type_2_cl_mimo_ant_sel = -1;
static int hf_mac_header_type_2_cl_mimo_codebook_id = -1;

/* last byte */
/*#define WIMAX_MAC_HEADER_TYPE_2_HCS          0xFF*/
static int hf_mac_header_type_2_hcs = -1;

/* CID Inclusion Indication messages */
static const value_string cii_msgs[] =
{
	{ 0, "without CID" },
	{ 1, "with CID" },
	{ 0,  NULL}
};

/* Feedback Types */
static const value_string fb_types[] =
{
	{ 0, "CQI and MIMO Feedback" },
	{ 1, "DL average CINR" },
	{ 2, "MIMO Coefficients Feedback" },
	{ 3, "Preferred DL Channel DIUC Feedback" },
	{ 4, "UL Transmission Power" },
	{ 5, "PHY Channel Feedback" },
	{ 6, "AMC Band Indication Bitmap" },
	{ 7, "Life Span of Short-term Precoding Feedback" },
	{ 8, "Multiple Types of Feedback" },
	{ 9, "Long-term Precoding Feedback" },
	{ 10, "Combined DL Average CINR of Active BSs" },
	{ 11, "MIMO Channel Feedback" },
	{ 12, "CINR Feedback" },
	{ 13, "Close-loop MIMO Feedback" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{ 0,  NULL}
};

/* Table of the Preferred Bandwidth Ratio of bandwidth over used channel bandwidth */
static const value_string pbwi_table[] =
{
	{ 0, "1" },
	{ 1, "3/4" },
	{ 2, "2/3" },
	{ 3, "1/2" },
	{ 4, "1/3" },
	{ 5, "1/4" },
	{ 6, "1/5" },
	{ 7, "1/6" },
	{ 8, "1/8" },
	{ 9, "1/10" },
	{ 10, "1/12" },
	{ 11, "1/16" },
	{ 12, "1/24" },
	{ 13, "1/32" },
	{ 14, "1/48" },
	{ 15, "1/64" },
	{ 0,  NULL}
};

/* Burst Profile Ranking Indicator table */
static const value_string bpri_table[] =
{
	{ 0, "1st preferred burst profile" },
	{ 1, "2nd preferred burst profile" },
	{ 2, "3rd preferred burst profile" },
	{ 3, "4th preferred burst profile" },
	{ 0,  NULL}
};

/* Coherent Time Index Table */
static const value_string cti_table[] =
{
	{ 0, "Infinite" },
	{ 1, "1 frame" },
	{ 2, "2 frames" },
	{ 3, "3 frames" },
	{ 4, "4 frames" },
	{ 5, "8 frames" },
	{ 6, "14 frames" },
	{ 7, "24 frames" },
	{ 0,  NULL}
};

/* The MS Matrix Index Table */
static const value_string mi_table[] =
{
	{ 0, "No STC" },
	{ 1, "Matrix A" },
	{ 2, "Matrix B" },
	{ 3, "Matrix C" },
	{ 0,  NULL}
};

/* CQI Feedback Types */
static const value_string ct_msgs[] =
{
	{ 0, "DL average feedback" },
	{ 1, "CQI feedback" },
	{ 0,  NULL}
};

/* Antenna Indication messages */
static const value_string ai_msgs[] =
{
	{ 0, "Not applicable" },
	{ 1, "Applicable" },
	{ 0,  NULL}
};


void dissect_mac_header_type_2_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint tvb_len, offset = 0;
	guint cii_bit, first_byte, fb_type, mimo_type;
	proto_item *parent_item = NULL;
	proto_item *ti = NULL;
	proto_tree *ti_tree = NULL;

	if (tree)
	{	/* we are being asked for details */
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display the MAC Type II Header message */
		ti = proto_tree_add_protocol_format(tree, proto_mac_header_type_2_decoder, tvb, offset, tvb_len, "Mac Type II Header (6 bytes)");
		/* add subtree */
		ti_tree = proto_item_add_subtree(ti, ett_mac_header_type_2_decoder);
		if(tvb_len < WIMAX_MAC_HEADER_SIZE)
		{
			/* display the error message */
			proto_tree_add_protocol_format(ti_tree, proto_mac_header_type_2_decoder, tvb, offset, tvb_len, "Error: the size of Mac Header Type II tvb is too small! (%u bytes)", tvb_len);
			/* display the MAC Type II Header in Hex */
			proto_tree_add_item(ti_tree, hf_mac_header_type_2_value_bytes, tvb, offset, tvb_len, ENC_NA);
			return;
		}
#ifdef DEBUG
		/* update the info column */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "MAC Signaling Header Type II");
#endif
		/* get the parent */
		parent_item = proto_tree_get_parent(tree);
		/* Decode and display the first byte of the header */
		/* header type */
		proto_tree_add_item(ti_tree, hf_mac_header_type_2_ht, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* encryption control */
		proto_tree_add_item(ti_tree, hf_mac_header_type_2_ec, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* sub-type */
		proto_tree_add_item(ti_tree, hf_mac_header_type_2_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* CID inclusion indication */
		proto_tree_add_item(ti_tree, hf_mac_header_type_2_cii, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* feedback type */
		proto_tree_add_item(ti_tree, hf_mac_header_type_2_fb_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* Get the first byte */
		first_byte = tvb_get_guint8(tvb, offset);
		/* get the CII field */
		cii_bit = ((first_byte & WIMAX_MAC_HEADER_TYPE_2_CII)?1:0);
		/* check the Type field */
		if(!(first_byte & WIMAX_MAC_HEADER_TYPE_2_TYPE))
		{
			/* Get the feedback type */
			fb_type = (first_byte & WIMAX_MAC_HEADER_TYPE_2_FB_TYPE);
			if(fb_type < TYPE_II_FB_TYPE_MAX)
			{
				/* update the info column */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, type2_fb_type_abbrv[fb_type]);
			}
			else
			{
				/* update the info column */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Unknown type 2 fb type");
				/* display the MAC Type I Header in Hex */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_value_bytes, tvb, offset, tvb_len, ENC_NA);
				return;
			}
			/* move to the second byte */
			offset++;
			/* add the MAC header info */
			proto_item_append_text(parent_item, "%s", type2_fb_type_abbrv[fb_type]);
			/* process the feedback header based on the fb type */
			switch (fb_type)
			{
			case CQI_MIMO_FB:
				/* Decode and display the CQI and MIMO feedback */
				/* CQI feedback type */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_cqi_fb_type, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* CQI payload */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_cqi_payload, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* reserved */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_cqi_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
			break;
			case DL_AVG_CINR:
				/* Decode and display the DL average CINR feedback */
				/* DL average CINR payload */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_dl_ave_cinr, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* reserved */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_dl_ave_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
			break;
			case MIMO_COEF_FB:
				/* Decode and display the MIMO coefficients feedback */
				/* number of index */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_coef_ni, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* occurrences of antenna index */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_coef_ai, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* MIMO coefficients */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_coef, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* reserved */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_coef_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* Decode and display the CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
			break;
			case PREF_DL_CHAN_DIUC_FB:
				/* Decode and display the Preffed DL Channel DIUC feedback */
				/* Preferred DIUC */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_dl_chan_diuc, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* DCD Change Count */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_dl_chan_dcd, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* reserved */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_dl_chan_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
			break;
			case UL_TX_PWR:
				/* Decode and display the UL TX Power feedback */
				/* UL TX Power */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_ul_tx_pwr, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* reserved */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_ul_tx_pwr_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
			break;
			case PHY_CHAN_FB:
				/* Decode and display the PHY Channel feedback */
				/* Preffed DIUC */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_phy_diuc, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* UL TX Power */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_phy_ul_tx_pwr, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* UL Headroom */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_phy_ul_hdrm, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* reserved */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_phy_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
			break;
			case AMC_BAND_BITMAP:
				/* Decode and display the AMC Band CQIs feedback */
				/* AMC Band Indication Bitmap */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_amc_bitmap, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* AMC CQI 1 */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_amc_cqi_1, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* AMC CQI 2 */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_amc_cqi_2, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* AMC CQI 3 */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_amc_cqi_3, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* AMC CQI 4 */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_amc_cqi_4, tvb, offset, 2, ENC_BIG_ENDIAN);
#if 0
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
#endif
			break;
			case SHORT_PRECODE_FB:
				/* Decode and display the Life Span of Short-term precoding feedback */
				/* Life Span */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_life_span, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* reserved */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_life_span_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
			break;
			case MULTI_TYPES_FB:
				/* Decode and display the Multi types of feedback */
				/* Number of feedback types */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_mt_num_fb_types, tvb, offset, 4, ENC_BIG_ENDIAN);
				/* Occurrences of feedback type */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_mt_occu_fb_type, tvb, offset, 4, ENC_BIG_ENDIAN);
				/* feedback contents */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_mt_fb_contents, tvb, offset, 4, ENC_BIG_ENDIAN);
#if 0
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
#endif
			break;
			case LONG_PRECODE_FB:
				/* Decode and display the Long-term precoding feedback */
				/* Feedback of index */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_lt_id_fb, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* rank of prrecoding codebook */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_lt_rank, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* EFC and QAM feedback */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_lt_fec_qam, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* reserved */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_lt_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
			break;
			case COMB_DL_AVG_CINR:
				/* Decode and display the Combined DL Average CINR feedback */
				/* Combined DL average CINR of Active BSs */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_comb_dl_ave, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* reserved */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_comb_dl_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
			break;
			case MIMO_CHAN_FB:
				/* Decode and display the second byte of the header */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_diuc, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_pbwi, tvb, (offset+1), 1, ENC_BIG_ENDIAN);
				/* Decode and display the 3rd to 5th bytes of the header */
				/* Decode and display the SLPB */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_slpb, tvb, offset, 3, ENC_BIG_ENDIAN);
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* Decode and display the BPRI */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_bpri_cid, tvb, offset, 3, ENC_BIG_ENDIAN);
					/* Decode and display the CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_cid, tvb, offset, 3, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* Decode and display the BPRI */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_bpri, tvb, offset, 3, ENC_BIG_ENDIAN);
					/* Decode and display the CTI */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_cti, tvb, offset, 3, ENC_BIG_ENDIAN);
					/* Decode and display the AI */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_ai_0, tvb, offset, 3, ENC_BIG_ENDIAN);
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_ai_1, tvb, offset, 3, ENC_BIG_ENDIAN);
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_ai_2, tvb, offset, 3, ENC_BIG_ENDIAN);
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_ai_3, tvb, offset, 3, ENC_BIG_ENDIAN);
					/* Decode and display the MI */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_mi, tvb, offset, 3, ENC_BIG_ENDIAN);
					/* Decode and display the CT */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_ct, tvb, offset, 3, ENC_BIG_ENDIAN);
					/* Decode and display the CQI */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_mimo_cqi, tvb, offset, 3, ENC_BIG_ENDIAN);
				}
			break;
			case CINR_FB:
				/* Decode and display the CINRC feedback */
				/* CINR Mean */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_cinr_mean, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* CINR Standard Deviation */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_cinr_devi, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* Decode and display the CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
			break;
			case CL_MIMO_FB:
				/* Get the MIMO type */
				mimo_type = ((tvb_get_guint8(tvb, offset) & 0xC0) >> 6);
				/* Decode and display the MIMO type */
				proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_type, tvb, offset, 2, ENC_BIG_ENDIAN);
				if(mimo_type == 1)
				{
					/* Decode and display the umber of streams */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_streams, tvb, offset, 2, ENC_BIG_ENDIAN);
					/* Decode and display the antenna selection option index */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_ant_sel, tvb, offset, 2, ENC_BIG_ENDIAN);
					/* Decode and display the average CQI */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_cqi_1, tvb, offset, 2, ENC_BIG_ENDIAN);
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_rsv_1, tvb, offset, 2, ENC_BIG_ENDIAN);
				}
				else if(mimo_type == 2)
				{
					/* Decode and display the umber of streams */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_streams, tvb, offset, 2, ENC_BIG_ENDIAN);
					/* Decode and display the antenna selection option index */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_codebook_id, tvb, offset, 2, ENC_BIG_ENDIAN);
					/* Decode and display the average CQI */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_cqi_2, tvb, offset, 2, ENC_BIG_ENDIAN);
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_rsv_2, tvb, offset, 2, ENC_BIG_ENDIAN);
				}
				else
				{
					/* Decode and display the antenna grouping index */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_ant_id, tvb, offset, 2, ENC_BIG_ENDIAN);
					/* Decode and display the average CQI */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_cqi, tvb, offset, 2, ENC_BIG_ENDIAN);
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cl_mimo_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
				}
				/* check the CII field */
				if(cii_bit)
				{	/* with CID */
					/* Decode and display the CID */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
				else
				{	/* without CID */
					/* reserved */
					proto_tree_add_item(ti_tree, hf_mac_header_type_2_no_cid, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
				}
			break;
			default:
			break;
			}
			/* Decode and display the HCS */
			proto_tree_add_item(ti_tree, hf_mac_header_type_2_hcs, tvb, (offset+4), 1, ENC_BIG_ENDIAN);
		}
		else
		{
			/* update the info column */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Error - Undefined Type");
		}
	}
}

/* Register Wimax Mac Header Type II Protocol and Dissector */
void proto_register_mac_header_type_2(void)
{
	/* MAC HEADER TYPE II display */
	static hf_register_info hf[] =
	{
		{
			&hf_mac_header_type_2_value_bytes,
			{
				"Values", "wmx.type2ValueBytes",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_ht,
			{
				"MAC Header Type", "wmx.type2Ht",
				FT_UINT8, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_HT,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_ec,
			{
				"MAC Encryption Control", "wmx.type2Ec",
				FT_UINT8, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_EC,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_type,
			{
				"MAC Sub-Type", "wmx.type2Type",
				FT_UINT8, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_TYPE,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cii,
			{
				"CID Inclusion Indication", "wmx.type2Cii",
				FT_UINT8, BASE_DEC, VALS(cii_msgs), WIMAX_MAC_HEADER_TYPE_2_CII,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_fb_type,
			{
				"Feedback Type", "wmx.type2FbType",
				FT_UINT8, BASE_DEC, VALS(fb_types), WIMAX_MAC_HEADER_TYPE_2_FB_TYPE,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cqi_fb_type,
			{
				"Mimo Feedback Type", "wmx.type2MimoFbType",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CQI_FB_TYPE,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cqi_payload,
			{
				"CQI and Mimo Feedback Payload", "wmx.type2MimoFbPayload",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CQI_PAYLOAD,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cqi_rsv,
			{
				"Reserved", "wmx.type2MimoFbRsv",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CQI_RSV,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_dl_ave_cinr,
			{
				"DL Average CINR", "wmx.type2DlAveCinr",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_DL_AVE_CINR,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_dl_ave_rsv,
			{
				"Reserved", "wmx.type2DlAveRsv",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_DL_AVE_RSV,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_coef_ni,
			{
				"Number of Index", "wmx.type2MimoCoefNi",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_MIMO_COEF_NI,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_coef_ai,
			{
				"Occurrences of Antenna Index", "wmx.type2MimoCoefAi",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_MIMO_COEF_AI,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_coef,
			{
				"MIMO Coefficients", "wmx.type2MimoCoef",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_MIMO_COEF,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_coef_rsv,
			{
				"Reserved", "wmx.type2MimoCoefRsv",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_MIMO_COEF_RSV,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_dl_chan_diuc,
			{
				"Preferred DIUC", "wmx.type2DlChanDiuc",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_DL_CHAN_DIUC,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_dl_chan_dcd,
			{
				"DCD Change Count", "wmx.type2DlChanDcd",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_DL_CHAN_DCD,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_dl_chan_rsv,
			{
				"Reserved", "wmx.type2DlChanRsv",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_DL_CHAN_RSV,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_ul_tx_pwr,
			{
				"UL TX Power", "wmx.type2UlTxPwr",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_UL_TX_PWR,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_ul_tx_pwr_rsv,
			{
				"Reserved", "wmx.type2UlTxPwrRsv",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_UL_TX_PWR_RSV,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_phy_diuc,
			{
				"Preferred DIUC Index", "wmx.type2PhyDiuc",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_PHY_DIUC,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_phy_ul_tx_pwr,
			{
				"UL TX Power", "wmx.type2PhyUlTxPwr",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_PHY_UL_TX_PWR,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_phy_ul_hdrm,
			{
				"UL Headroom", "wmx.type2PhyHdRm",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_PHY_UL_HDRM,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_phy_rsv,
			{
				"Reserved", "wmx.type2PhyRsv",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_PHY_RSV,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_amc_bitmap,
			{
				"AMC Band Indication Bitmap", "wmx.type2AmcBitmap",
				FT_UINT32, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_AMC_BITMAP,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_amc_cqi_1,
			{
				"CQI 1", "wmx.type2AmcCqi1",
				FT_UINT32, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_AMC_CQI_1,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_amc_cqi_2,
			{
				"CQI 2", "wmx.type2AmcCqi2",
				FT_UINT32, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_AMC_CQI_2,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_amc_cqi_3,
			{
				"CQI 3", "wmx.type2AmcCqi3",
				FT_UINT32, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_AMC_CQI_3,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_amc_cqi_4,
			{
				"CQI 4", "wmx.type2AmcCqi4",
				FT_UINT32, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_AMC_CQI_4,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_life_span,
			{
				"Life Span of Short-term", "wmx.type2LifeSpan",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_LIFE_SPAN,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_life_span_rsv,
			{
				"Reserved", "wmx.type2LifeSpanRsv",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_LIFE_SPAN_RSV,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mt_num_fb_types,
			{
				"Number of Feedback Types", "wmx.type2MtNumFbTypes",
				FT_UINT32, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_MT_NUM_FB_TYPES,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mt_occu_fb_type,
			{
				"Occurrences of Feedback Type", "wmx.type2MtOccuFbType",
				FT_UINT32, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_MT_OCCU_FB_TYPE,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mt_fb_contents,
			{
				"Number of Feedback Types", "wmx.type2MtNumFbTypes",
				FT_UINT32, BASE_HEX, NULL, WIMAX_MAC_HEADER_TYPE_2_MT_FB_CONTENTS,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_lt_id_fb,
			{
				"Long-term Feedback Index", "wmx.type2LtFbId",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_LT_ID_FB,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_lt_rank,
			{
				"Rank of Precoding Codebook", "wmx.type2LtRank",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_LT_RANK,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_lt_fec_qam,
			{
				"FEC and QAM", "wmx.type2LtFecQam",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_LT_FEC_QAM,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_lt_rsv,
			{
				"Reserved", "wmx.type2LtFbId",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_LT_RSV,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_comb_dl_ave,
			{
				"Combined DL Average CINR of Active BSs", "wmx.type2CombDlAve",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_COMB_DL_AVE,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_comb_dl_rsv,
			{
				"Reserved", "wmx.type2CombDlRsv",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_COMB_DL_RSV,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_diuc,
			{
				"Preferred DIUC Index", "wmx.type2MimoDiuc",
				FT_UINT8, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_DIUC,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_pbwi,
			{
				"Preferred Bandwidth Index", "wmx.type2MimoPbwi",
				FT_UINT8, BASE_DEC, VALS(pbwi_table), WIMAX_MAC_HEADER_TYPE_2_PBWI,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_slpb,
			{
				"Starting Location of Preferred Bandwidth", "wmx.type2MimoSlpb",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_SLPB,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_bpri_cid,
			{
				"Burst Profile Ranking Indicator with CID", "wmx.type2MimoBpriCid",
				FT_UINT24, BASE_HEX, VALS(bpri_table), WIMAX_MAC_HEADER_TYPE_2_PBRI_CID,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_cid,
			{
				"Connection ID", "wmx.type2MimoCid",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CID,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_bpri,
			{
				"Burst Profile Ranking Indicator without CID", "wmx.type2MimoBpri",
				FT_UINT24, BASE_HEX, VALS(bpri_table), WIMAX_MAC_HEADER_TYPE_2_PBRI,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_cti,
			{
				"Coherent Time Index", "wmx.type2MimoCti",
				FT_UINT24, BASE_HEX, VALS(cti_table), WIMAX_MAC_HEADER_TYPE_2_CTI,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_ai_0,
			{
				"Antenna 0 Indication", "wmx.type2MimoAi",
				FT_UINT24, BASE_HEX, VALS(ai_msgs), WIMAX_MAC_HEADER_TYPE_2_AI_0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_ai_1,
			{
				"Antenna 1 Indication", "wmx.type2MimoAi",
				FT_UINT24, BASE_HEX, VALS(ai_msgs), WIMAX_MAC_HEADER_TYPE_2_AI_1,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_ai_2,
			{
				"Antenna 2 Indication", "wmx.type2MimoAi",
				FT_UINT24, BASE_HEX, VALS(ai_msgs), WIMAX_MAC_HEADER_TYPE_2_AI_2,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_ai_3,
			{
				"Antenna 3 Indication", "wmx.type2MimoAi",
				FT_UINT24, BASE_HEX, VALS(ai_msgs), WIMAX_MAC_HEADER_TYPE_2_AI_3,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_mi,
			{
				"MS Matrix Indicator", "wmx.type2MimoMi",
				FT_UINT24, BASE_HEX, VALS(mi_table), WIMAX_MAC_HEADER_TYPE_2_MI,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_ct,
			{
				"CQI Type", "wmx.type2MimoCt",
				FT_UINT24, BASE_HEX, VALS(ct_msgs), WIMAX_MAC_HEADER_TYPE_2_CT,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_mimo_cqi,
			{
				"CQI Feedback", "wmx.type2MimoCqi",
				FT_UINT24, BASE_HEX, NULL, WIMAX_MAC_HEADER_TYPE_2_CQI,
				NULL, HFILL
			}
		},
		{	&hf_mac_header_type_2_cinr_mean,
			{
				"CINR Mean", "wmx.type2CinrMean",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cinr_devi,
			{
				"CINR Standard Deviation", "wmx.type2CinrDevi",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cl_mimo_type,
			{
				"Closed-Loop MIMO Type", "wmx.type2ClMimoType",
				FT_UINT16, BASE_HEX, NULL, WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_TYPE,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cl_mimo_ant_id,
			{
				"Antenna Grouping Index", "wmx.type2ClMimoAntId",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_ANT_ID,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cl_mimo_cqi,
			{
				"Average CQI", "wmx.type2ClMimoCqi",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_CQI,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cl_mimo_cqi_1,
			{
				"Average CQI", "wmx.type2ClMimoCqi",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_CQI_1,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cl_mimo_cqi_2,
			{
				"Average CQI", "wmx.type2ClMimoCqi",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_CQI_2,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cl_mimo_rsv,
			{
				"Reserved", "wmx.type2ClMimoRsv",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_RSV,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cl_mimo_rsv_1,
			{
				"Reserved", "wmx.type2ClMimoRsv",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_RSV_1,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cl_mimo_rsv_2,
			{
				"Reserved", "wmx.type2ClMimoRsv",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_RSV_2,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cl_mimo_streams,
			{
				"Number of Streams", "wmx.type2ClMimoStreams",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_STREAMS,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cl_mimo_ant_sel,
			{
				"Antenna Selection Option Index", "wmx.type2ClMimoAntSel",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_ANT_SEL,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cl_mimo_codebook_id,
			{
				"Codebook Index", "wmx.type2ClMimoCodeBkId",
				FT_UINT16, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_2_CL_MIMO_CODEBOOK_ID,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_cid,
			{
				"Connection ID", "wmx.type2Cid",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_no_cid,
			{
				"Reserved", "wmx.type2NoCid",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_2_hcs,
			{
				"Header Check Sequence", "wmx.type2Hcs",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_header_type_2_decoder,
		};

	proto_mac_header_type_2_decoder = proto_mac_header_generic_decoder;

	proto_register_field_array(proto_mac_header_type_2_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("mac_header_type_2_handler", dissect_mac_header_type_2_decoder, -1);
}
