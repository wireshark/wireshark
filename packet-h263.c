/* packet-h263.c
 *
 * Routines for ITU-T Recommendation H.263 dissection
 *
 * Copyright 2003 Niklas Ögren <niklas.ogren@7l.se>
 * Seven Levels Consultants AB
 *
 * $Id: packet-h263.c,v 1.4 2003/08/25 21:48:44 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied structure from packet-h261.c
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
 * This dissector tries to dissect the H.263 protocol according to
 * ITU-T Recommendations and RFC 2190
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include "rtp_pt.h"

/* H.263 header fields             */
static int proto_h263          = -1;

/* Mode A header */
static int hf_h263_ftype = -1;
static int hf_h263_pbframes = -1;
static int hf_h263_sbit = -1;
static int hf_h263_ebit = -1;
static int hf_h263_srcformat = -1;
static int hf_h263_picture_coding_type = -1;	
static int hf_h263_unrestricted_motion_vector = -1;
static int hf_h263_syntax_based_arithmetic = -1;
static int hf_h263_advanced_prediction = -1;
static int hf_h263_r = -1;
static int hf_h263_rr = -1;
static int hf_h263_dbq = -1;
static int hf_h263_trb = -1;
static int hf_h263_tr = -1;
/* Additional fields for Mode B or C header */
static int hf_h263_quant = -1;
static int hf_h263_gobn = -1;
static int hf_h263_mba = -1;
static int hf_h263_hmv1 = -1;
static int hf_h263_vmv1 = -1;
static int hf_h263_hmv2 = -1;
static int hf_h263_vmv2 = -1;

static int hf_h263_data        = -1;

/* Source format types */
#define SRCFORMAT_FORB   0  /* forbidden */
#define SRCFORMAT_SQCIF  1
#define SRCFORMAT_QCIF   2
#define SRCFORMAT_CIF    3
#define SRCFORMAT_4CIF   4
#define SRCFORMAT_16CIF  5

static const value_string srcformat_vals[] =
{
  { SRCFORMAT_FORB,	"forbidden" },
  { SRCFORMAT_SQCIF,	"sub-QCIF 128x96" },
  { SRCFORMAT_QCIF,	"QCIF 176x144" },
  { SRCFORMAT_CIF,	"CIF 352x288" },
  { SRCFORMAT_4CIF,	"4CIF 704x576" },
  { SRCFORMAT_16CIF,	"16CIF 1408x1152" },
  { 0,		NULL },
};

/* H.263 fields defining a sub tree */
static gint ett_h263           = -1;

static void
dissect_h263( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti            = NULL;
	proto_tree *h263_tree     = NULL;
	unsigned int offset       = 0;
	unsigned int h263_version = 0;

	h263_version = (tvb_get_guint8( tvb, offset ) & 0xc0 ) >> 6;

	if ( check_col( pinfo->cinfo, COL_PROTOCOL ) )   {
		col_set_str( pinfo->cinfo, COL_PROTOCOL, "H.263" );
	}

	if( h263_version == 0x00) {
	  if ( check_col( pinfo->cinfo, COL_INFO) ) {
	    col_append_str( pinfo->cinfo, COL_INFO, " MODE A");
	  }
	}
	else if( h263_version == 0x02) {
	  if ( check_col( pinfo->cinfo, COL_INFO) ) {
	    col_append_str( pinfo->cinfo, COL_INFO, " MODE B");
	  }
	}
	else if( h263_version == 0x03) {
	  if ( check_col( pinfo->cinfo, COL_INFO) ) {
	    col_append_str( pinfo->cinfo, COL_INFO, " MODE C");
	  }
	}

	if ( tree ) {
	  ti = proto_tree_add_item( tree, proto_h263, tvb, offset, -1, FALSE );
	  h263_tree = proto_item_add_subtree( ti, ett_h263 );

	  /* FBIT 1st octet, 1 bit */
	  proto_tree_add_boolean( h263_tree, hf_h263_ftype, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x80 );
	  /* PBIT 1st octet, 1 bit */
	  proto_tree_add_boolean( h263_tree, hf_h263_pbframes, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x40 );
	  /* SBIT 1st octet, 3 bits */
	  proto_tree_add_uint( h263_tree, hf_h263_sbit, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0x38 ) >> 3 );
	  /* EBIT 1st octet, 3 bits */
	  proto_tree_add_uint( h263_tree, hf_h263_ebit, tvb, offset, 1, tvb_get_guint8( tvb, offset )  & 0x7 );

	  offset++;

	  /* SRC 2nd octet, 3 bits */
	  proto_tree_add_uint( h263_tree, hf_h263_srcformat, tvb, offset, 1, tvb_get_guint8( tvb, offset ) >> 5 );

	  if(h263_version == 0x00) { /* MODE A */
	    /* I flag, 1 bit */
	    proto_tree_add_boolean( h263_tree, hf_h263_picture_coding_type, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x10 );
	    /* U flag, 1 bit */
	    proto_tree_add_boolean( h263_tree, hf_h263_unrestricted_motion_vector, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x08 );
	    /* S flag, 1 bit */
	    proto_tree_add_boolean( h263_tree, hf_h263_syntax_based_arithmetic, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x04 );
	    /* A flag, 1 bit */
	    proto_tree_add_boolean( h263_tree, hf_h263_advanced_prediction, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x02 );

	    /* Reserved 2nd octect, 1 bit + 3rd octect 3 bits */
	    proto_tree_add_uint( h263_tree, hf_h263_r, tvb, offset, 2, ( ( tvb_get_guint8( tvb, offset ) & 0x1 ) << 3 ) + ( ( tvb_get_guint8( tvb, offset + 1 ) & 0xe0 ) >> 5 ) );

	    offset++;

	    /* DBQ 3 octect, 2 bits */
	    proto_tree_add_uint( h263_tree, hf_h263_dbq, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0x18 ) >> 3 );
	    /* TRB 3 octect, 3 bits */
	    proto_tree_add_uint( h263_tree, hf_h263_trb, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0x07 ) );

	    offset++;
	    
	    /* TR 4 octect, 8 bits */
	    proto_tree_add_uint( h263_tree, hf_h263_tr, tvb, offset, 1, tvb_get_guint8( tvb, offset ) );
	    
	    offset++;

	  } else { /* MODE B or MODE C */

	    /* QUANT 2 octect, 5 bits */
	    proto_tree_add_uint( h263_tree, hf_h263_quant, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x1f );

	    offset++;

	    /* GOBN 3 octect, 5 bits */
	    proto_tree_add_uint( h263_tree, hf_h263_gobn, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0xf8 ) >> 3);
	    /* MBA 3 octect, 3 bits + 4 octect 6 bits */
	    proto_tree_add_uint( h263_tree, hf_h263_mba, tvb, offset, 2, ( ( tvb_get_guint8( tvb, offset ) & 0x7 ) << 6 ) + ( ( tvb_get_guint8( tvb, offset + 1 ) & 0xfc ) >> 2 ) );
	    
	    offset++;

	    /* Reserved 4th octect, 2 bits */
	    proto_tree_add_uint( h263_tree, hf_h263_r, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0x3 ) );

	    offset++;

	    /* I flag, 1 bit */
	    proto_tree_add_boolean( h263_tree, hf_h263_picture_coding_type, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x80 );
	    /* U flag, 1 bit */
	    proto_tree_add_boolean( h263_tree, hf_h263_unrestricted_motion_vector, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x40 );
	    /* S flag, 1 bit */
	    proto_tree_add_boolean( h263_tree, hf_h263_syntax_based_arithmetic, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x20 );
	    /* A flag, 1 bit */
	    proto_tree_add_boolean( h263_tree, hf_h263_advanced_prediction, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x10 );

	    /* HMV1 5th octect, 4 bits + 6th octect 3 bits*/
	    proto_tree_add_uint( h263_tree, hf_h263_hmv1, tvb, offset, 2,( ( tvb_get_guint8( tvb, offset ) & 0xf ) << 3 ) + ( ( tvb_get_guint8( tvb, offset+1 ) & 0xe0 ) >> 5) );

	    offset++;
	    
	    /* VMV1 6th octect, 5 bits + 7th octect 2 bits*/
	    proto_tree_add_uint( h263_tree, hf_h263_vmv1, tvb, offset, 2,( ( tvb_get_guint8( tvb, offset ) & 0x1f ) << 2 ) + ( ( tvb_get_guint8( tvb, offset+1 ) & 0xc0 ) >> 6) );
	    
	    offset++;

	    /* HMV2 7th octect, 6 bits + 8th octect 1 bit*/
	    proto_tree_add_uint( h263_tree, hf_h263_hmv2, tvb, offset, 2,( ( tvb_get_guint8( tvb, offset ) & 0x3f ) << 1 ) + ( ( tvb_get_guint8( tvb, offset+1 ) & 0xf0 ) >> 7) );
	    
	    offset++;

	    /* VMV2 8th octect, 7 bits*/
	    proto_tree_add_uint( h263_tree, hf_h263_vmv2, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x7f );
		  
	    offset++;

	    if(h263_version == 0x03) { /* MODE C */
	      /* Reserved 9th to 11th octect, 8 + 8 + 3 bits */
	      proto_tree_add_uint( h263_tree, hf_h263_rr, tvb, offset, 3, ( tvb_get_guint8( tvb, offset ) << 11 ) + ( tvb_get_guint8( tvb, offset + 1 ) << 3 ) + ( ( tvb_get_guint8( tvb, offset + 2 ) & 0xe0 ) >> 5 ) );

	      offset+=2;

	      /* DBQ 11th octect, 2 bits */
	      proto_tree_add_uint( h263_tree, hf_h263_dbq, tvb, offset, 1, ( tvb_get_guint8( tvb, offset ) & 0x18 ) >>3 );
	      /* TRB 11th octect, 3 bits */
	      proto_tree_add_uint( h263_tree, hf_h263_trb, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 0x07 );
	      
	      offset++;
	      
	      /* TR 12th octect, 8 bits */
	      proto_tree_add_uint( h263_tree, hf_h263_tr, tvb, offset, 1, tvb_get_guint8( tvb, offset ) );
	      
	      offset++;
	    } /* end mode c */
	  } /* end not mode a */

	  /* The rest of the packet is the H.263 stream */
	  proto_tree_add_item( h263_tree, hf_h263_data, tvb, offset, -1, FALSE );
	}
}

void
proto_register_h263(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_h263_ftype,
			{
				"F",
				"h263.sbit",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Indicates the mode of the payload header (MODE A or B/C)", HFILL
			}
		},
		{
			&hf_h263_pbframes,
			{
				"p/b frame",
				"h263.pbframes",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Optional PB-frames mode as defined by H.263 (MODE C)", HFILL
			}
		},
		{
			&hf_h263_sbit,
			{
				"Start bit position",
				"h263.sbit",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Start bit position specifies number of most significant bits that shall be ignored in the first data byte.", HFILL
			}
		},
		{
			&hf_h263_ebit,
			{
				"End bit position",
				"h263.ebit",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"End bit position specifies number of least significant bits that shall be ignored in the last data byte.", HFILL
			}
		},
		{
			&hf_h263_srcformat,
			{
				"SRC format",
				"h263.srcformat",
				FT_UINT8,
				BASE_DEC,
				VALS(srcformat_vals),
				0x0,
				"Source format specifies the resolution of the current picture.", HFILL
			}
		},
		{
			&hf_h263_picture_coding_type,
			{
				"Inter-coded frame",
				"h263.picture_coding_type",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Picture coding type, intra-coded (false) or inter-coded (true)", HFILL
			}
		},
		{
			&hf_h263_unrestricted_motion_vector,
			{
				"Motion vector",
				"h263.unrestricted_motion_vector",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Unrestricted Motion Vector option for current picture", HFILL
			}
		},
		{
			&hf_h263_syntax_based_arithmetic,
			{
				"Syntax-based arithmetic coding",
				"h263.syntax_based_arithmetic",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Syntax-based Arithmetic Coding option for current picture", HFILL
			}
		},
		{
			&hf_h263_advanced_prediction,
			{
				"Advanced prediction option",
				"h263.advanced_prediction",
				FT_BOOLEAN,
				BASE_NONE,
				NULL,
				0x0,
				"Advanced Prediction option for current picture", HFILL
			}
		},
		{
			&hf_h263_dbq,
			{
				"Differential quantization parameter",
				"h263.dbq",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Differential quantization parameter used to calculate quantizer for the B frame based on quantizer for the P frame, when PB-frames option is used.", HFILL
			}
		},
		{
			&hf_h263_trb,
			{
				"Temporal Reference for B frames",
				"h263.trb",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Temporal Reference for the B frame as defined by H.263", HFILL
			}
		},
		{
			&hf_h263_tr,
			{
				"Temporal Reference for P frames",
				"h263.tr",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Temporal Reference for the P frame as defined by H.263", HFILL
			}
		},
		{
			&hf_h263_quant,
			{
				"Quantizer",
				"h263.quant",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Quantization value for the first MB coded at the starting of the packet.", HFILL
			}
		},
		{
			&hf_h263_gobn,
			{
				"GOB Number",
				"h263.gobn",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"GOB number in effect at the start of the packet.", HFILL
			}
		},
		{
			&hf_h263_mba,
			{
				"Macroblock address",
				"h263.mba",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"The address within the GOB of the first MB in the packet, counting from zero in scan order.", HFILL
			}
		},
		{
			&hf_h263_hmv1,
			{
				"Horizontal motion vector 1",
				"h263.hmv1",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Horizontal motion vector predictor for the first MB in this packet ", HFILL
			}
		},
		{
			&hf_h263_vmv1,
			{
				"Vertical motion vector 1",
				"h263.vmv1",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Vertical motion vector predictor for the first MB in this packet ", HFILL
			}
		},
		{
			&hf_h263_hmv2,
			{
				"Horizontal motion vector 2",
				"h263.hmv2",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Horizontal motion vector predictor for block number 3 in the first MB in this packet when four motion vectors are used with the advanced prediction option.", HFILL
			}
		},
		{
			&hf_h263_vmv2,
			{
				"Vertical motion vector 2",
				"h263.vmv2",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Vertical motion vector predictor for block number 3 in the first MB in this packet when four motion vectors are used with the advanced prediction option.", HFILL
			}
		},
		{
			&hf_h263_r,
			{
				"Reserved field",
				"h263.r",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Reserved field that houls contain zeroes", HFILL
			}
		},
		{
			&hf_h263_rr,
			{
				"Reserved field 2",
				"h263.rr",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"Reserved field that should contain zeroes", HFILL
			}
		},
		{
			&hf_h263_data,
			{
				"H.263 stream",
				"h263.stream",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x0,
				"The H.263 stream including its Picture, GOB or Macro block start code.", HFILL
			}
		},
};

	static gint *ett[] =
	{
		&ett_h263,
	};


	proto_h263 = proto_register_protocol("ITU-T Recommendation H.263 RTP Payload header (RFC2190)",
	    "H.263", "h263");
	proto_register_field_array(proto_h263, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_h263(void)
{
	dissector_handle_t h263_handle;

	h263_handle = create_dissector_handle(dissect_h263, proto_h263);
	dissector_add("rtp.pt", PT_H263, h263_handle);
}
