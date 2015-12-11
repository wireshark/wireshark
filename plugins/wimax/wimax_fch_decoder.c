/* wimax_fch_decoder.c
 * WiMax FCH Burst decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
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

#include <string.h>

#include <epan/packet.h>

extern gint proto_wimax;

extern address bs_address;	/* declared in packet-wmx.c */

void proto_register_wimax_fch(void);

static int proto_wimax_fch_decoder = -1;
static gint ett_wimax_fch_decoder = -1;

#define FCH_BURST_LENGTH 3
/* FCH Burst bits */
#define USED_SUB_CHANNEL_GROUP_0     0x800000
#define USED_SUB_CHANNEL_GROUP_1     0x400000
#define USED_SUB_CHANNEL_GROUP_2     0x200000
#define USED_SUB_CHANNEL_GROUP_3     0x100000
#define USED_SUB_CHANNEL_GROUP_4     0x080000
#define USED_SUB_CHANNEL_GROUP_5     0x040000
#define FCH_RESERVED_1		     0x020000
#define REPETITION_CODING_INDICATION 0x018000
#define CODING_INDICATION            0x007000
#define DL_MAP_LENGTH                0x000FF0
#define FCH_RESERVED_2		     0x00000F

static int hf_fch_used_subchannel_group0 = -1;
static int hf_fch_used_subchannel_group1 = -1;
static int hf_fch_used_subchannel_group2 = -1;
static int hf_fch_used_subchannel_group3 = -1;
static int hf_fch_used_subchannel_group4 = -1;
static int hf_fch_used_subchannel_group5 = -1;
static int hf_fch_reserved_1 = -1;
static int hf_fch_repetition_coding_indication = -1;
static int hf_fch_coding_indication = -1;
static int hf_fch_dlmap_length = -1;
static int hf_fch_reserved_2 = -1;

static const value_string used_or_not_used[] =
{
	{ 0, "Is Not Used" },
	{ 1, "Is Used" },
	{ 0,  NULL }
};

/* DL Frame Prefix Repetition Coding Indications */
static const value_string repetition_coding_indications[] =
{
	{ 0, "No Repetition Coding" },
	{ 1, "Repetition Coding of 2 Used" },
	{ 2, "Repetition Coding of 4 Used" },
	{ 3, "Repetition Coding of 6 Used" },
	{ 0, NULL }
};

/* DL Frame Prefix Coding Indications */
static const value_string coding_indications[] =
{
	{ 0, "CC Encoding Used" },
	{ 1, "BTC Encoding Used" },
	{ 2, "CTC Encoding Used" },
	{ 3, "ZT CC Encoding Used" },
	{ 4, "CC Encoding with optional interleaver" },
	{ 5, "LDPC Encoding Used" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0,  NULL }
};

static int dissect_wimax_fch_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	gint offset = 0;
	proto_item *fch_item = NULL;
	proto_tree *fch_tree = NULL;

	/* save the base station address (once) */
	if(!bs_address.len)
		copy_address(&bs_address, &(pinfo->src));
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "FCH");
	if (tree)
	{	/* we are being asked for details */
		/* display FCH dissector info */
		fch_item = proto_tree_add_protocol_format(tree, proto_wimax_fch_decoder, tvb, offset, 3, "DL Frame Prefix (24 bits)");
		/* add FCH subtree */
		fch_tree = proto_item_add_subtree(fch_item, ett_wimax_fch_decoder);
		/* Decode and display the used sub-channel groups */
		proto_tree_add_item(fch_tree, hf_fch_used_subchannel_group0, tvb, offset, FCH_BURST_LENGTH, ENC_BIG_ENDIAN);
		proto_tree_add_item(fch_tree, hf_fch_used_subchannel_group1, tvb, offset, FCH_BURST_LENGTH, ENC_BIG_ENDIAN);
		proto_tree_add_item(fch_tree, hf_fch_used_subchannel_group2, tvb, offset, FCH_BURST_LENGTH, ENC_BIG_ENDIAN);
		proto_tree_add_item(fch_tree, hf_fch_used_subchannel_group3, tvb, offset, FCH_BURST_LENGTH, ENC_BIG_ENDIAN);
		proto_tree_add_item(fch_tree, hf_fch_used_subchannel_group4, tvb, offset, FCH_BURST_LENGTH, ENC_BIG_ENDIAN);
		proto_tree_add_item(fch_tree, hf_fch_used_subchannel_group5, tvb, offset, FCH_BURST_LENGTH, ENC_BIG_ENDIAN);
		proto_tree_add_item(fch_tree, hf_fch_reserved_1, tvb, offset, FCH_BURST_LENGTH, ENC_BIG_ENDIAN);
		/* Decode and display the repetition coding indication */
		proto_tree_add_item(fch_tree, hf_fch_repetition_coding_indication, tvb, offset, FCH_BURST_LENGTH, ENC_BIG_ENDIAN);
		/* Decode and display the coding indication */
		proto_tree_add_item(fch_tree, hf_fch_coding_indication, tvb, offset, FCH_BURST_LENGTH, ENC_BIG_ENDIAN);
		/* Decode and display the DL MAP length */
		proto_tree_add_item(fch_tree, hf_fch_dlmap_length, tvb, offset, FCH_BURST_LENGTH, ENC_BIG_ENDIAN);
		proto_tree_add_item(fch_tree, hf_fch_reserved_2, tvb, offset, FCH_BURST_LENGTH, ENC_BIG_ENDIAN);
	}
	return tvb_captured_length(tvb);
}

/* Register Wimax FCH Protocol */
void proto_register_wimax_fch(void)
{
	/* TLV display */
	static hf_register_info hf[] =
	{
		{
			&hf_fch_used_subchannel_group0,
			{
				"Sub-Channel Group 0", "wmx.fch.subchannel_group0",
				FT_UINT24, BASE_DEC, VALS(used_or_not_used), USED_SUB_CHANNEL_GROUP_0,
				NULL, HFILL
			}
		},
		{
			&hf_fch_used_subchannel_group1,
			{
				"Sub-Channel Group 1", "wmx.fch.subchannel_group1",
				FT_UINT24, BASE_DEC, VALS(used_or_not_used), USED_SUB_CHANNEL_GROUP_1,
				NULL, HFILL
			}
		},
		{
			&hf_fch_used_subchannel_group2,
			{
				"Sub-Channel Group 2", "wmx.fch.subchannel_group2",
				FT_UINT24, BASE_DEC, VALS(used_or_not_used), USED_SUB_CHANNEL_GROUP_2,
				NULL, HFILL
			}
		},
		{
			&hf_fch_used_subchannel_group3,
			{
				"Sub-Channel Group 3", "wmx.fch.subchannel_group3",
				FT_UINT24, BASE_DEC, VALS(used_or_not_used), USED_SUB_CHANNEL_GROUP_3,
				NULL, HFILL
			}
		},
		{
			&hf_fch_used_subchannel_group4,
			{
				"Sub-Channel Group 4", "wmx.fch.subchannel_group4",
				FT_UINT24, BASE_DEC, VALS(used_or_not_used), USED_SUB_CHANNEL_GROUP_4,
				NULL, HFILL
			}
		},
		{
			&hf_fch_used_subchannel_group5,
			{
				"Sub-Channel Group 5", "wmx.fch.subchannel_group5",
				FT_UINT24, BASE_DEC, VALS(used_or_not_used), USED_SUB_CHANNEL_GROUP_5,
				NULL, HFILL
			}
		},
		{
			&hf_fch_reserved_1,
			{
				"Reserved", "wmx.fch.reserved1",
				FT_UINT24, BASE_DEC, NULL, FCH_RESERVED_1,
				NULL, HFILL
			}
		},
		{
			&hf_fch_repetition_coding_indication,
			{
				"Repetition Coding Indication", "wmx.fch.repetition_coding_indication",
				FT_UINT24, BASE_DEC, VALS(repetition_coding_indications), REPETITION_CODING_INDICATION,
				NULL, HFILL
			}
		},
		{
			&hf_fch_coding_indication,
			{
				"Coding Indication", "wmx.fch.coding_indication",
				FT_UINT24, BASE_DEC, VALS(coding_indications), CODING_INDICATION,
				NULL, HFILL
			}
		},
		{
			&hf_fch_dlmap_length,
			{
				"DL Map Length", "wmx.fch.dl_map_length",
				FT_UINT24, BASE_DEC, NULL, DL_MAP_LENGTH,
				NULL, HFILL
			}
		},
		{
			&hf_fch_reserved_2,
			{
				"Reserved", "wmx.fch.reserved2",
				FT_UINT24, BASE_DEC, NULL, FCH_RESERVED_2,
				NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_wimax_fch_decoder,
		};

	proto_wimax_fch_decoder = proto_wimax;

	/* register the field display messages */
	proto_register_field_array(proto_wimax_fch_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("wimax_fch_burst_handler", dissect_wimax_fch_decoder, -1);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
