/* packet-h261.c
 *
 * Routines for ITU-T Recommendation H.261 dissection
 *
 * $Id$
 *
 * Copyright 2000, Philips Electronics N.V.
 * Andreas Sikkema <h323@ramdyne.nl>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * This dissector tries to dissect the H.261 protocol according to Annex C
 * of ITU-T Recommendation H.225.0 (02/98)
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include <epan/rtp_pt.h>

/* H.261 header fields             */
static int proto_h261          = -1;
static int hf_h261_sbit        = -1;
static int hf_h261_ebit        = -1;
static int hf_h261_ibit        = -1;
static int hf_h261_vbit        = -1;
static int hf_h261_gobn        = -1;
static int hf_h261_mbap        = -1;
static int hf_h261_quant       = -1;
static int hf_h261_hmvd        = -1; /* Mislabeled in a figure in section C.3.1 as HMDV */
static int hf_h261_vmvd        = -1;
static int hf_h261_data        = -1;

/* H.261 fields defining a sub tree */
static gint ett_h261           = -1;

static void
dissect_h261( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti            = NULL;
	proto_tree *h261_tree     = NULL;
	unsigned int offset       = 0;

	if ( check_col( pinfo->cinfo, COL_PROTOCOL ) )   {
		col_set_str( pinfo->cinfo, COL_PROTOCOL, "H.261" );
	}

	if ( check_col( pinfo->cinfo, COL_INFO) ) {
		col_set_str( pinfo->cinfo, COL_INFO, "H.261 message");
	}

	if ( tree ) {
		ti = proto_tree_add_item( tree, proto_h261, tvb, offset, -1, FALSE );
		h261_tree = proto_item_add_subtree( ti, ett_h261 );
		/* SBIT 1st octet, 3 bits */
		proto_tree_add_uint( h261_tree, hf_h261_sbit, tvb, offset, 1, tvb_get_guint8( tvb, offset ) >> 5 );
		/* EBIT 1st octet, 3 bits */
		proto_tree_add_uint( h261_tree, hf_h261_ebit, tvb, offset, 1, ( tvb_get_guint8( tvb, offset )  << 3 ) >> 5 );
		/* I flag, 1 bit */
		proto_tree_add_boolean( h261_tree, hf_h261_ibit, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 2 );
		/* V flag, 1 bit */
		proto_tree_add_boolean( h261_tree, hf_h261_vbit, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 1 );
		offset++;

		/* GOBN 2nd octet, 4 bits */
		proto_tree_add_uint( h261_tree, hf_h261_gobn, tvb, offset, 1, tvb_get_guint8( tvb, offset ) >> 4 );
		/* MBAP 2nd octet, 4 bits, 3rd octet 1 bit */
		proto_tree_add_uint( h261_tree, hf_h261_mbap, tvb, offset, 1,
		    ( tvb_get_guint8( tvb, offset ) & 15 )
		    + ( tvb_get_guint8( tvb, offset + 1 ) >> 7 ) );
		offset++;

		/* QUANT 3rd octet, 5 bits (starting at bit 2!) */
		proto_tree_add_uint( h261_tree, hf_h261_quant, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 124 );

		/* HMVD 3rd octet 2 bits, 4th octet 3 bits */
		proto_tree_add_uint( h261_tree, hf_h261_hmvd, tvb, offset, 2,
		    ( ( tvb_get_guint8( tvb, offset ) & 0x03 ) << 3 )
		     + ( tvb_get_guint8( tvb, offset+1 ) >> 5 ) );
		offset++;

		/* VMVD 4th octet, last 5 bits */
		proto_tree_add_uint( h261_tree, hf_h261_vmvd, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 31 );
		offset++;

		/* The rest of the packet is the H.261 stream */
		proto_tree_add_item( h261_tree, hf_h261_data, tvb, offset, -1, FALSE );
	}
}

void
proto_register_h261(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_h261_sbit,
			{
				"Start bit position",
				"h261.sbit",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_h261_ebit,
			{
				"End bit position",
				"h261.ebit",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_h261_ibit,
			{
				"Intra frame encoded data flag",
				"h261.i",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_h261_vbit,
			{
				"Motion vector flag",
				"h261.v",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_h261_gobn,
			{
				"GOB Number",
				"h261.gobn",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_h261_mbap,
			{
				"Macroblock address predictor",
				"h261.mbap",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_h261_quant,
			{
				"Quantizer",
				"h261.quant",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_h261_hmvd,
			{
				"Horizontal motion vector data",
				"h261.hmvd",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_h261_vmvd,
			{
				"Vertical motion vector data",
				"h261.vmvd",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_h261_data,
			{
				"H.261 stream",
				"h261.stream",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x0,
				"", HFILL
			}
		},
};

	static gint *ett[] =
	{
		&ett_h261,
	};


	proto_h261 = proto_register_protocol("ITU-T Recommendation H.261",
	    "H.261", "h261");
	proto_register_field_array(proto_h261, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_h261(void)
{
	dissector_handle_t h261_handle;

	h261_handle = create_dissector_handle(dissect_h261, proto_h261);
	dissector_add("rtp.pt", PT_H261, h261_handle);
}
