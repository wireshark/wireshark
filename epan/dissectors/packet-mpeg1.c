/* packet-mpeg1.c
 *
 * Routines for RFC 2250 MPEG-1 dissection
 *
 * $Id$
 *
 * Copyright 2001,
 * Francisco Javier Cabello Torres, <fjcabello@vtools.es>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * This dissector tries to dissect the MPEG-1 video streams.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/rtp_pt.h>

#define RTP_MPG_MBZ(word) ( word >> 11)
#define RTP_MPG_T(word)   ( (word >> 10) & 1 )
#define RTP_MPG_TR(word)   ( word & 0x3ff )

#define RTP_MPG_AN(octet) ( octet >> 7)
#define RTP_MPG_N(octet)  ( (octet >> 6) & 1 )
#define RTP_MPG_S(octet)  ( (octet >> 5) & 1 )
#define RTP_MPG_B(octet)  ( (octet >> 4) & 1 )
#define RTP_MPG_E(octet)  ( (octet >> 3) & 1 )
#define RTP_MPG_P(octet)  ( octet & 7 )

#define RTP_MPG_FBV(octet) ( (octet >> 7) & 1 )
#define RTP_MPG_BFC(octet) ( (octet >> 4) & 7 )
#define RTP_MPG_FFV(octet) ( (octet >> 3) & 1 )
#define RTP_MPG_FFC(octet) (  octet & 7 )


/* MPEG1 header fields             */


static int proto_mpg          = -1;

static int hf_rtp_mpg_mbz     = -1;
static int hf_rtp_mpg_T       = -1;
static int hf_rtp_mpg_tr      = -1;
static int hf_rtp_mpg_an      = -1;
static int hf_rtp_mpg_n       = -1;
static int hf_rtp_mpg_s       = -1;
static int hf_rtp_mpg_b       = -1;
static int hf_rtp_mpg_e       = -1;
static int hf_rtp_mpg_p       = -1;


static int hf_rtp_mpg_fbv     = -1;
static int hf_rtp_mpg_bfc     = -1;
static int hf_rtp_mpg_ffv     = -1;
static int hf_rtp_mpg_ffc     = -1;
static int hf_rtp_mpg_data    = -1;



/* MPEG-1 fields defining a sub tree */
static gint ett_mpg           = -1;

static const value_string rtp_mpg_picture_types_vals[] =
{
	{ 0, "Forbidden" },
	{ 1, "I-Picture" },
	{ 2, "P-Picture" },
	{ 3, "B-Picture" },
	{ 4, "D-Picture" },
	{ 5, "reserved" },
	{ 6, "reserved" },
	{ 7, "reserved" },
	{ 0, NULL },
};

static void
dissect_mpeg1( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti            = NULL;
	proto_tree *mpg_tree     = NULL;
	unsigned int offset       = 0;

	guint8      octet;
	guint16     word;


	guint16     mpg_mbz;
	guint16     mpg_T;
	guint16     mpg_tr;
	guint16     mpg_an;
	guint16     mpg_n;
	gboolean    mpg_s;
	gboolean    mpg_b;
	gboolean    mpg_e;
	guint16     mpg_p;
	guint16     mpg_fbv;
	guint16     mpg_bfc;
	guint16     mpg_ffv;
	guint16     mpg_ffc;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPEG-1");

	col_set_str(pinfo->cinfo, COL_INFO, "MPEG-1 message");

	/* Get MPEG-1  fields */

	word  =   tvb_get_guint8( tvb, offset  );
	word  = (word << 8) | tvb_get_guint8( tvb, offset +1 );
	mpg_mbz = RTP_MPG_MBZ(word);
	mpg_T   = RTP_MPG_T(word);
	mpg_tr  = RTP_MPG_TR(word);

	octet = tvb_get_guint8( tvb, offset + 2 );
	mpg_an  = RTP_MPG_AN(octet);
	mpg_n   = RTP_MPG_N(octet);
	mpg_s   = RTP_MPG_S(octet);
	mpg_b   = RTP_MPG_B(octet);
	mpg_e   = RTP_MPG_E(octet);
	mpg_p   = RTP_MPG_P(octet);

	octet = tvb_get_guint8( tvb, offset + 3 );

	mpg_fbv   = RTP_MPG_FBV(octet);
	mpg_bfc   = RTP_MPG_BFC(octet);
	mpg_ffv   = RTP_MPG_FFV(octet);
	mpg_ffc   = RTP_MPG_FFC(octet);


	if ( tree )
	  {
	    ti = proto_tree_add_item( tree, proto_mpg, tvb, offset, -1, ENC_NA );
	    mpg_tree = proto_item_add_subtree( ti, ett_mpg );

	    proto_tree_add_uint( mpg_tree, hf_rtp_mpg_mbz, tvb, offset, 1, mpg_mbz );
	    proto_tree_add_uint( mpg_tree, hf_rtp_mpg_T  , tvb, offset, 1, mpg_T );
	    proto_tree_add_uint( mpg_tree, hf_rtp_mpg_tr , tvb, offset, 2, mpg_tr );
	    offset += 2;
	    proto_tree_add_uint( mpg_tree, hf_rtp_mpg_an, tvb, offset, 1, mpg_an );
	    proto_tree_add_uint( mpg_tree, hf_rtp_mpg_n , tvb, offset, 1, mpg_n );
	    proto_tree_add_boolean( mpg_tree, hf_rtp_mpg_s , tvb, offset, 1, mpg_s );
	    proto_tree_add_boolean( mpg_tree, hf_rtp_mpg_b , tvb, offset, 1, mpg_b );
	    proto_tree_add_boolean( mpg_tree, hf_rtp_mpg_e , tvb, offset, 1, mpg_e );

	    proto_tree_add_uint( mpg_tree, hf_rtp_mpg_p, tvb , offset, 1, mpg_p );
	    offset += 1;

	    proto_tree_add_uint( mpg_tree, hf_rtp_mpg_fbv, tvb, offset, 1, mpg_fbv );
	    proto_tree_add_uint( mpg_tree, hf_rtp_mpg_bfc, tvb, offset, 1, mpg_bfc );
	    proto_tree_add_uint( mpg_tree, hf_rtp_mpg_ffv, tvb, offset, 1, mpg_ffv );
	    proto_tree_add_uint( mpg_tree, hf_rtp_mpg_ffc, tvb, offset, 1, mpg_ffc );
	    offset += 1;

	    /* The rest of the packet is the MPEG-1 stream */
	    proto_tree_add_item( mpg_tree, hf_rtp_mpg_data, tvb, offset, -1, ENC_NA );

	  }
}

void
proto_register_mpeg1(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_rtp_mpg_mbz,
			{
				"MBZ",
				"rtp.payload_mpeg_mbz",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_mpg_T,
			{
				"T",
				"rtp.payload_mpeg_T",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_mpg_tr,
			{
				"Temporal Reference",
				"rtp.payload_mpeg_tr",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_mpg_an,
			{
				"AN",
				"rtp.payload_mpeg_an",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_mpg_n,
			{
				"New Picture Header",
				"rtp.payload_mpeg_n",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_mpg_s,
			{
				"Sequence Header",
				"rtp.payload_mpeg_s",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_mpg_b,
			{
				"Beginning-of-slice",
				"rtp.payload_mpeg_b",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_mpg_e,
			{
				"End-of-slice",
				"rtp.payload_mpeg_an",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_mpg_p,
			{
				"Picture type",
				"rtp.payload_mpeg_p",
				FT_UINT16,
				BASE_DEC,
				VALS(rtp_mpg_picture_types_vals),
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_mpg_fbv,
			{
				"FBV",
				"rtp.payload_mpeg_fbv",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_mpg_bfc,
			{
				"BFC",
				"rtp.payload_mpeg_bfc",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_mpg_ffv,
			{
				"FFV",
				"rtp.payload_mpeg_ffv",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

		{
			&hf_rtp_mpg_ffc,
			{
				"FFC",
				"rtp.payload_mpeg_ffc",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_mpg_data,
			{
				"MPEG-1 stream",
				"mpeg1.stream",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

	};

	static gint *ett[] =
	{
		&ett_mpg,
	};


	proto_mpg = proto_register_protocol("RFC 2250 MPEG1","MPEG1","mpeg1");
	proto_register_field_array(proto_mpg, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mpeg1(void)
{
	dissector_handle_t mpeg1_handle;

	mpeg1_handle = create_dissector_handle(dissect_mpeg1, proto_mpg);
	dissector_add_uint("rtp.pt", PT_MPV, mpeg1_handle);
}
