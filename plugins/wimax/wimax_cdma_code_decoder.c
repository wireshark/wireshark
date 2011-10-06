/* wimax_cdma_code_decoder.c
 * WiMax CDMA CODE Attribute decoder
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

extern gint proto_wimax;

static int proto_wimax_cdma_code_decoder = -1;
static gint ett_wimax_cdma_code_decoder = -1;

static int hf_wimax_ranging_code = -1;
static int hf_wimax_ranging_symbol_offset = -1;
static int hf_wimax_ranging_subchannel_offset = -1;

static void dissect_wimax_cdma_code_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	guint length;
	proto_item *cdma_item = NULL;

	proto_tree *cdma_tree = NULL;

	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "CDMA Code Attribute");
	if (tree)
	{	/* we are being asked for details */
		/* get the tvb reported length */
		length = tvb_reported_length(tvb);
		/* display CDMA dissector info */
		cdma_item = proto_tree_add_protocol_format(tree, proto_wimax_cdma_code_decoder, tvb, offset, length, "CDMA Code Attribute (%u bytes)", length);
		/* add CDMA Code subtree */
		cdma_tree = proto_item_add_subtree(cdma_item, ett_wimax_cdma_code_decoder);
		/* display the first CDMA Code */
		proto_tree_add_item(cdma_tree, hf_wimax_ranging_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the 2nd CDMA Code */
		proto_tree_add_item(cdma_tree, hf_wimax_ranging_symbol_offset, tvb, offset+1, 1, ENC_BIG_ENDIAN);
		/* display the 3rd CDMA Code */
		proto_tree_add_item(cdma_tree, hf_wimax_ranging_subchannel_offset, tvb, offset+2, 1, ENC_BIG_ENDIAN);
	}
}

/* Register Wimax CDMA Protocol */
void proto_register_wimax_cdma(void)
{
	/* TLV display */
	static hf_register_info hf[] =
	{
		{
			&hf_wimax_ranging_code,
			{
				"Ranging Code", "wmx.cdma.ranging_code",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_wimax_ranging_symbol_offset,
			{
				"Ranging Symbol Offset", "wmx.cdma.ranging_symbol_offset",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_wimax_ranging_subchannel_offset,
			{
				"Ranging Sub-Channel Offset", "wmx.cdma.ranging_subchannel_offset",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		}
	};

        /* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_wimax_cdma_code_decoder,
		};

	proto_wimax_cdma_code_decoder = proto_wimax;

	/* register the field display messages */
	proto_register_field_array(proto_wimax_cdma_code_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("wimax_cdma_code_burst_handler", dissect_wimax_cdma_code_decoder, -1);
}

