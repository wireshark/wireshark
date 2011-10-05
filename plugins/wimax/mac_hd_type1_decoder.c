/* mac_hd_type1_decoder.c
 * WiMax MAC Type I Signaling Header decoder
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
#define DEBUG
*/

#include <glib.h>
#include <epan/packet.h>

extern gint proto_mac_header_generic_decoder;

static gint proto_mac_header_type_1_decoder = -1;
static gint ett_mac_header_type_1_decoder = -1;
static gint hf_mac_header_type_1_value_bytes = -1;

#define WIMAX_MAC_HEADER_SIZE  6

/* WiMax MAC Header Type I Sub Types */
enum
{
	BR_INCREMENTAL,            /* 0 */
	BR_AGGREGATE,              /* 1 */
	PHY_CHANNEL_REPORT,        /* 2 */
	BR_WITH_UL_TX_POWER_REPORT,/* 3 */
	BR_AND_CINR_REPORT,        /* 4 */
	BR_WITH_UL_SLEEP_CONTROL,  /* 5 */
	SN_REPORT,                 /* 6 */
	CQICH_ALLOCATION_REQUEST,  /* 7 */
	TYPE_I_SUBTYPE_MAX
} TYPE_I_SUBTYPE;

static char *type1_subtype_abbrv[TYPE_I_SUBTYPE_MAX] =
{
	"BR INCREMENTAL",            /* 0 */
	"BR AGGREGATE",              /* 1 */
	"PHY CHANNEL_REPORT",        /* 2 */
	"BR WITH UL TX POWER_REPORT",/* 3 */
	"BR AND CINR REPORT",        /* 4 */
	"BR WITH UL SLEEP CONTROL",  /* 5 */
	"SN REPORT",                 /* 6 */
	"CQICH ALLOCATION REQUEST"   /* 7 */
};

#define WIMAX_MAC_HEADER_TYPE_1_SUB_TYPE_MASK 0x38

/* WIMAX MAC HEADER TYPE I FILEDS */
/* 1st to 3rd bytes */
/* Common Fields */
#define WIMAX_MAC_HEADER_TYPE_1_HT           0x800000
#define WIMAX_MAC_HEADER_TYPE_1_EC           0x400000
#define WIMAX_MAC_HEADER_TYPE_1_TYPE         0x380000
/* Bandwidth Request Incremental Header (type 0) &
   Bandwidth Request Aggregate Header (type 1) only */
#define WIMAX_MAC_HEADER_TYPE_1_BR           0x07FFFF
/* PHY Channel Report Header (type 2) only */
#define WIMAX_MAC_HEADER_TYPE_1_DIUC         0x078000
#define WIMAX_MAC_HEADER_TYPE_1_UL_TX_PWR    0x007F80
#define WIMAX_MAC_HEADER_TYPE_1_UL_HDRM      0x00007E
#define WIMAX_MAC_HEADER_TYPE_1_RSV_2        0x000001
/* Bandwidth Request and UL TX Power Report Header (type 3),
   Bandwidth Request and CINR Report Header (type 4), &
   Bandwidth Request and Uplink Sleep Control Header (type 5) only */
#define WIMAX_MAC_HEADER_TYPE_1_BR_3         0x07FF00
/* Bandwidth Request and UL TX Power Report Header (type 3) only */
#define WIMAX_MAC_HEADER_TYPE_1_UL_TX_PWR_3  0x0000FF
/* Bandwidth Request and CINR Report Header (type 4) only */
#define WIMAX_MAC_HEADER_TYPE_1_CINR         0x0000FE
#define WIMAX_MAC_HEADER_TYPE_1_DCI          0x000001
/* Bandwidth Request and Uplink Sleep Control Header (type 5) only */
#define WIMAX_MAC_HEADER_TYPE_1_PSCID        0x0000FC
#define WIMAX_MAC_HEADER_TYPE_1_OP           0x000002
#define WIMAX_MAC_HEADER_TYPE_1_RSV_5        0x000001
/* SN Report Header (type 6) only */
#define WIMAX_MAC_HEADER_TYPE_1_LAST         0x040000
#define WIMAX_MAC_HEADER_TYPE_1_SDU_SN1      0x03F000
#define WIMAX_MAC_HEADER_TYPE_1_SDU_SN2      0x000FC0
#define WIMAX_MAC_HEADER_TYPE_1_SDU_SN3      0x00003F
/* CQICH Allocation Request (type 7) only */
#define WIMAX_MAC_HEADER_TYPE_1_FB_TYPE      0x070000
#define WIMAX_MAC_HEADER_TYPE_1_FBSSI        0x008000
#define WIMAX_MAC_HEADER_TYPE_1_PERIOD       0x007000
#define WIMAX_MAC_HEADER_TYPE_1_RSV_7        0x000FFF
/* 4th to 6th bytes */
/*#define WIMAX_MAC_HEADER_TYPE_1_CID          0xFFFF
*#define WIMAX_MAC_HEADER_TYPE_1_HCS          0xFF
*/
/* Common Fields */
static int hf_mac_header_type_1_ht = -1;
static int hf_mac_header_type_1_ec = -1;
static int hf_mac_header_type_1_type = -1;
/* type 0 & type 1 only */
static int hf_mac_header_type_1_br = -1;
/* type 3, type 4, & type 5 only */
static int hf_mac_header_type_1_br_3 = -1;
/* type 2 only */
static int hf_mac_header_type_1_diuc = -1;
static int hf_mac_header_type_1_ultxpwr = -1;
static int hf_mac_header_type_1_ulhdrm = -1;
static int hf_mac_header_type_1_rsv_2 = -1;
/* type 3 only */
static int hf_mac_header_type_1_ultxpwr_3 = -1;
/* type 4 only */
static int hf_mac_header_type_1_cinr = -1;
static int hf_mac_header_type_1_dci = -1;
/* type 5 only */
static int hf_mac_header_type_1_pscid = -1;
static int hf_mac_header_type_1_op = -1;
static int hf_mac_header_type_1_rsv_5 = -1;
/* type 6 only */
static int hf_mac_header_type_1_last = -1;
static int hf_mac_header_type_1_sdu_sn1 = -1;
static int hf_mac_header_type_1_sdu_sn2 = -1;
static int hf_mac_header_type_1_sdu_sn3 = -1;
/* type 7 only */
static int hf_mac_header_type_1_fb_type = -1;
static int hf_mac_header_type_1_fbssi = -1;
static int hf_mac_header_type_1_period = -1;
static int hf_mac_header_type_1_rsv_7 = -1;
/* Common Fields */
static int hf_mac_header_type_1_cid = -1;
static int hf_mac_header_type_1_hcs = -1;

/* MAC Header Type I Sub-Types */
static const value_string sub_types[] =
{
	{ BR_INCREMENTAL, "Bandwidth Request Incremental" },
	{ BR_AGGREGATE, "Bandwidth Request Aggregate" },
	{ PHY_CHANNEL_REPORT, "PHY Channel Report" },
	{ BR_WITH_UL_TX_POWER_REPORT, "Bandwidth Request with UL TX Power Report" },
	{ BR_AND_CINR_REPORT, "Bandwidth Request and CINR Report" },
	{ BR_WITH_UL_SLEEP_CONTROL, "Bandwidth Request with Sleep Control" },
	{ SN_REPORT, "SN Report" },
	{ CQICH_ALLOCATION_REQUEST, "CQICH Allocation Request" },
	{ 0,				NULL}
};

/* Feedback Types (need to be changed for type I) */
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
	{ 0,				NULL}
};

/* DCD Change Indication messages */
static const value_string dci_msgs[] =
{
	{ 0, "Match DCD Change Count" },
	{ 1, "Mismatch DCD Change Count" },
	{ 0,				NULL}
};

/* Operation messages */
static const value_string op_msgs[] =
{
	{ 0, "Deactivate Power Saving Class" },
	{ 1, "Activate Power Saving Class" },
	{ 0,				NULL}
};

/* Last ARQ BSN or SDU SN Indication messages */
static const value_string last_msgs[] =
{
	{ 0, "First three connections" },
	{ 1, "Last three connections" },
	{ 0,				NULL}
};

void dissect_mac_header_type_1_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint tvb_len, offset = 0;
	guint first_byte, sub_type;
	proto_item *parent_item = NULL;
	proto_item *ti = NULL;
	proto_tree *ti_tree = NULL;

	if (tree)
	{	/* we are being asked for details */
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display the MAC Type I Header message */
		ti = proto_tree_add_protocol_format(tree, proto_mac_header_type_1_decoder, tvb, offset, tvb_len, "Mac Type I Header (%u bytes)", WIMAX_MAC_HEADER_SIZE);
		/* add subtree */
		ti_tree = proto_item_add_subtree(ti, ett_mac_header_type_1_decoder);
		if(tvb_len < WIMAX_MAC_HEADER_SIZE)
		{
			/* display the MAC Type I Header in Hex */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_value_bytes, tvb, offset, tvb_len, ENC_NA);
			return;
		}
#ifdef DEBUG
		/* update the info column */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, type1_subtype_abbrv[]);
#endif
		/* get the parent */
		parent_item = proto_tree_get_parent(tree);
		/* Decode and display the first 3 bytes of the header */
		proto_tree_add_item(ti_tree, hf_mac_header_type_1_ht, tvb, offset, 3, FALSE);
		proto_tree_add_item(ti_tree, hf_mac_header_type_1_ec, tvb, offset, 3, FALSE);
		proto_tree_add_item(ti_tree, hf_mac_header_type_1_type, tvb, offset, 3, FALSE);
		/* Get the first byte */
		first_byte = tvb_get_guint8(tvb, offset);
		/* get the sub Type */
		sub_type = ((first_byte & WIMAX_MAC_HEADER_TYPE_1_SUB_TYPE_MASK)>>3);
		if(sub_type < TYPE_I_SUBTYPE_MAX)
		{
			/* update the info column */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, type1_subtype_abbrv[sub_type]);
		}
		else
		{
			/* update the info column */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Unknown type 1 subtype");
			/* display MAC Header Type I Subtype */
			proto_tree_add_protocol_format(ti_tree, proto_mac_header_type_1_decoder, tvb, offset, tvb_len, "Unknown type 1 subtype: %u", sub_type);
			/* display the MAC Type I Header in Hex */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_value_bytes, tvb, offset, tvb_len, ENC_NA);
			return;
		}
		/* add the MAC header info */
		proto_item_append_text(parent_item, "%s", type1_subtype_abbrv[sub_type]);
		switch (sub_type)
		{
		case BR_INCREMENTAL:
		case BR_AGGREGATE:
			/* Decode and display the Bandwidth Request */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_br, tvb, offset, 3, FALSE);
		break;
		case PHY_CHANNEL_REPORT:
			/* Decode and display the Preferred-DIUC */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_diuc, tvb, offset, 3, FALSE);
			/* Decode and display the UL TX Power */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_ultxpwr, tvb, offset, 3, FALSE);
			/* Decode and display the UL Headroom */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_ulhdrm, tvb, offset, 3, FALSE);
			/* Decode and display the reserved filed */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_rsv_2, tvb, offset, 3, FALSE);
		break;
		case BR_WITH_UL_TX_POWER_REPORT:
			/* Decode and display the Bandwidth Request */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_br_3, tvb, offset, 3, FALSE);
			/* Decode and display the UL TX Power */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_ultxpwr_3, tvb, offset, 3, FALSE);
		break;
		case BR_AND_CINR_REPORT:
			/* Decode and display the Bandwidth Request */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_br_3, tvb, offset, 3, FALSE);
			/* Decode and display the CINR */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_cinr, tvb, offset, 3, FALSE);
			/* Decode and display the DCD Change Indication */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_dci, tvb, offset, 3, FALSE);
		break;
		case BR_WITH_UL_SLEEP_CONTROL:
			/* Decode and display the Bandwidth Request */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_br_3, tvb, offset, 3, FALSE);
			/* Decode and display the Power Saving Class ID */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_pscid, tvb, offset, 3, FALSE);
			/* Decode and display the Operation */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_op, tvb, offset, 3, FALSE);
			/* Decode and display the reserved filed */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_rsv_5, tvb, offset, 3, FALSE);
		break;
		case SN_REPORT:
			/* Decode and display the Last field */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_last, tvb, offset, 3, FALSE);
			/* Decode and display the SDU SN1 */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_sdu_sn1, tvb, offset, 3, FALSE);
			/* Decode and display the SDU SN2 */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_sdu_sn2, tvb, offset, 3, FALSE);
			/* Decode and display the SDU SN3 */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_sdu_sn3, tvb, offset, 3, FALSE);
		break;
		case CQICH_ALLOCATION_REQUEST:
			/* Decode and display the Feedback Type */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_fb_type, tvb, offset, 3, FALSE);
			/* Decode and display the FBSSI */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_fbssi, tvb, offset, 3, FALSE);
			/* Decode and display the Prreferred-period */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_period, tvb, offset, 3, FALSE);
			/* Decode and display the reserved filed */
			proto_tree_add_item(ti_tree, hf_mac_header_type_1_rsv_7, tvb, offset, 3, FALSE);
		break;
		}
		/* Decode and display the CID */
		proto_tree_add_item(ti_tree, hf_mac_header_type_1_cid, tvb, (offset+3), 2, FALSE);
		/* Decode and display the HCS */
		proto_tree_add_item(ti_tree, hf_mac_header_type_1_hcs, tvb, (offset+5), 1, FALSE);
	}
}

/* Register Wimax Mac Header Type II Protocol and Dissector */
void proto_register_mac_header_type_1(void)
{
	/* TLV display */
	static hf_register_info hf[] =
	{
		{
			&hf_mac_header_type_1_value_bytes,
			{
				"Values", "wmx.type1ValueBytes",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_ht,
			{
				"MAC Header Type", "wmx.type1Ht",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_HT,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_ec,
			{
				"MAC Encryption Control", "wmx.type1Ec",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_EC,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_type,
			{
				"MAC Sub-Type", "wmx.type1Type",
				FT_UINT24, BASE_HEX, VALS(sub_types), WIMAX_MAC_HEADER_TYPE_1_TYPE,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_br,
			{
				"Bandwidth Request", "wmx.type1Br",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_BR,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_br_3,
			{
				"Bandwidth Request", "wmx.type1Br3",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_BR_3,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_fb_type,
			{
				"Feedback Type", "wmx.type1FbType",
				FT_UINT24, BASE_HEX, VALS(fb_types), WIMAX_MAC_HEADER_TYPE_1_FB_TYPE,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_diuc,
			{
				"Preferred DIUC Index", "wmx.type1Diuc",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_DIUC,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_ultxpwr,
			{
				"UL TX Power", "wmx.type1UlTxPwr",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_UL_TX_PWR,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_ultxpwr_3,
			{
				"UL TX Power", "wmx.type1UlTxPwr3",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_UL_TX_PWR_3,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_ulhdrm,
			{
				"Headroom to UL Max Power Level", "wmx.type1HdRm",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_UL_HDRM,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_cinr,
			{
				"CINR Value", "wmx.type1Cinr",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_CINR,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_dci,
			{
				"DCD Change Indication", "wmx.type1Dci",
				FT_UINT24, BASE_HEX, VALS(dci_msgs), WIMAX_MAC_HEADER_TYPE_1_DCI,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_pscid,
			{
				"Power Saving Class ID", "wmx.type1PsCid",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_PSCID,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_op,
			{
				"Operation", "wmx.type1Op",
				FT_UINT24, BASE_HEX, VALS(op_msgs), WIMAX_MAC_HEADER_TYPE_1_OP,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_last,
			{
				"Last ARQ BSN or SDU SN", "wmx.type1Last",
				FT_UINT24, BASE_HEX, VALS(last_msgs), WIMAX_MAC_HEADER_TYPE_1_LAST,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_sdu_sn1,
			{
				"ARQ BSN or MAC SDU SN (1)", "wmx.type1SduSn1",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_SDU_SN1,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_sdu_sn2,
			{
				"ARQ BSN or MAC SDU SN (2)", "wmx.type1SduSn2",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_SDU_SN2,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_sdu_sn3,
			{
				"ARQ BSN or MAC SDU SN (3)", "wmx.type1SduSn3",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_SDU_SN3,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_fbssi,
			{
				"FBSS Indicator", "wmx.type1Fbssi",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_FBSSI,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_period,
			{
				"Preferred CQICH Allocation Period", "wmx.type1Period",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_PERIOD,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_rsv_2,
			{
				"Reserved", "wmx.type1Rsv2",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_RSV_2,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_rsv_5,
			{
				"Reserved", "wmx.type1Rsv5",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_RSV_5,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_rsv_7,
			{
				"Reserved", "wmx.type1Rsv7",
				FT_UINT24, BASE_DEC, NULL, WIMAX_MAC_HEADER_TYPE_1_RSV_7,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_cid,
			{
				"Connection ID", "wmx.type1Cid",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_mac_header_type_1_hcs,
			{
				"Header Check Sequence", "wmx.type1Hcs",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_header_type_1_decoder,
		};

	proto_mac_header_type_1_decoder = proto_mac_header_generic_decoder;

	proto_register_field_array(proto_mac_header_type_1_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("mac_header_type_1_handler", dissect_mac_header_type_1_decoder, -1);
}
