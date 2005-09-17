/* packet-h263.c
 *
 * Routines for ITU-T Recommendation H.263 dissection
 *
 * Copyright 2003 Niklas Ögren <niklas.ogren@7l.se>
 * Seven Levels Consultants AB
 *
 * $Id$
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

#include <epan/rtp_pt.h>
#include <epan/iax2_codec_type.h>

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
/* Fields for the data section */
static int hf_h263_psc = -1;
static int hf_h263_gbsc = -1;
static int hf_h263_TR =-1;
static int hf_h263_split_screen_indicator = -1;
static int hf_h263_document_camera_indicator = -1;
static int hf_h263_full_picture_freeze_release = -1;
static int hf_h263_source_format = -1;
static int hf_h263_payload_picture_coding_type = -1;
static int hf_h263_opt_unres_motion_vector_mode = -1;
static int hf_h263_syntax_based_arithmetic_coding_mode = -1;
static int hf_h263_optional_advanced_prediction_mode = -1;
static int hf_h263_PB_frames_mode = -1;
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

static const true_false_string on_off_flg = {
  "On",
  "Off"
};
static const true_false_string picture_coding_type_flg = {
  "INTER (P-picture)",
  "INTRA (I-picture)"
};

static const true_false_string PB_frames_mode_flg = {
  "PB-frame",
  "Normal I- or P-picture"
};

/* H.263 fields defining a sub tree */
static gint ett_h263			= -1;
static gint ett_h263_payload	= -1;
static void
dissect_h263( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti					= NULL;
	proto_item *h263_payload_item	= NULL;
	proto_tree *h263_tree			= NULL;
	proto_tree *h263_payload_tree	= NULL;
	unsigned int offset				= 0;
	unsigned int h263_version		= 0;
	guint32 data;
	guint8 octet;

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
	  h263_payload_item = proto_tree_add_text(h263_tree,tvb,offset,-1,"H263 Payload");
	  h263_payload_tree = proto_item_add_subtree( h263_payload_item, ett_h263_payload );

	  /* Check for PSC, PSC is a word of 22 bits. Its value is 0000 0000 0000 0000' 1000 00xx xxxx xxxx. */
	  data = tvb_get_ntohl(tvb, offset);
	  
	  if (( data & 0xffff8000) == 0x00008000 ) { /* PSC or Group of Block Start Code (GBSC) found */
		  if (( data & 0xfffffc00) == 0x00008000 ) { /* PSC found */
			  proto_tree_add_uint(h263_payload_tree, hf_h263_psc,tvb, offset,3,data);
			  offset = offset + 2;
			  proto_tree_add_uint(h263_payload_tree, hf_h263_TR,tvb, offset,2,data);
			  /* Last two bits in the 32 bits fetched
			   * Bit 1: Always "1", in order to avoid start code emulation. 
			   * Bit 2: Always "0", for distinction with Recommendation H.261.
			   */
			  offset = offset + 2;
			  /* Bit 3: Split screen indicator, "0" off, "1" on. */
			  proto_tree_add_item( h263_payload_tree, hf_h263_split_screen_indicator, tvb, offset, 1, FALSE );
			  /* Bit 4: Document camera indicator, */
			  proto_tree_add_item( h263_payload_tree, hf_h263_document_camera_indicator, tvb, offset, 1, FALSE );
			  /* Bit 5: Full Picture Freeze Release, "0" off, "1" on. */
			  proto_tree_add_item( h263_payload_tree, hf_h263_full_picture_freeze_release, tvb, offset, 1, FALSE );
			  /* Bits 6-8: Source Format, "000" forbidden, "001" sub-QCIF, "010" QCIF, "011" CIF,
			   * "100" 4CIF, "101" 16CIF, "110" reserved, "111" extended PTYPE.
			   */
			  proto_tree_add_item( h263_payload_tree, hf_h263_source_format, tvb, offset, 1, TRUE );
			  octet = tvb_get_guint8(tvb,offset);
			  if (( octet & 0x1c) != 0x1c){
				  /* Not extended PTYPE */
				  /* Bit 9: Picture Coding Type, "0" INTRA (I-picture), "1" INTER (P-picture). */
				  proto_tree_add_item( h263_payload_tree, hf_h263_payload_picture_coding_type, tvb, offset, 1, FALSE );
				  /* Bit 10: Optional Unrestricted Motion Vector mode (see Annex D), "0" off, "1" on. */
				  proto_tree_add_item( h263_payload_tree, hf_h263_opt_unres_motion_vector_mode, tvb, offset, 1, FALSE );
				  offset++;
				  /* Bit 11: Optional Syntax-based Arithmetic Coding mode (see Annex E), "0" off, "1" on.*/
				  proto_tree_add_item( h263_payload_tree, hf_h263_syntax_based_arithmetic_coding_mode, tvb, offset, 1, FALSE );
				  /* Bit 12: Optional Advanced Prediction mode (see Annex F), "0" off, "1" on.*/
				  proto_tree_add_item( h263_payload_tree, hf_h263_optional_advanced_prediction_mode, tvb, offset, 1, FALSE );
				  /* Bit 13: Optional PB-frames mode (see Annex G), "0" normal I- or P-picture, "1" PB-frame.*/
				  proto_tree_add_item( h263_payload_tree, hf_h263_PB_frames_mode, tvb, offset, 1, FALSE );
			  }
		  }else{ 
			  if ((data & 0x00007c00)!= 0) { /* GBSC found */

				/* Group of Block Start Code (GBSC) (17 bits)
				 * A word of 17 bits. Its value is 0000 0000 0000 0000 1. GOB start codes may be byte aligned. This
				 * can be achieved by inserting GSTUF before the start code such that the first bit of the start code is
				 * the first (most significant) bit of a byte.
				 *
				 */
				proto_tree_add_uint(h263_payload_tree, hf_h263_gbsc,tvb, offset,3,data);
				offset = offset + 2;
			  }
		  }
	  }
	  proto_tree_add_item( h263_payload_tree, hf_h263_data, tvb, offset, -1, FALSE );
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
		{
			&hf_h263_psc,
			{
				"H.263 Picture start Code",
				"h263.psc",
				FT_UINT32,
				BASE_HEX,
				NULL,
				0xfffffc00,
				"Picture start Code, PSC", HFILL
			}
		},
		{ &hf_h263_gbsc,
			{
				"H.263 Group of Block Start Code",
				"h263.gbsc",
				FT_UINT32,
				BASE_HEX,
				NULL,
				0xffff8000,
				"Group of Block Start Code", HFILL
			}
		},
		{
			&hf_h263_TR,
			{
				"H.263 Temporal Reference",
				"h263.tr2",
				FT_UINT32,
				BASE_HEX,
				NULL,
				0x000003fc,
				"Temporal Reference, TR", HFILL
			}
		},
		{
			&hf_h263_split_screen_indicator,
			{
				"H.263 Split screen indicator",
				"h263.split_screen_indicator",
				FT_BOOLEAN,
				8,
				TFS(&on_off_flg),
				0x80,
				"Split screen indicator", HFILL
			}
		},
		{
			&hf_h263_document_camera_indicator,
			{
				"H.263 Document camera indicator",
				"h263.document_camera_indicator",
				FT_BOOLEAN,
				8,
				TFS(&on_off_flg),
				0x40,
				"Document camera indicator", HFILL
			}
		},
		{
			&hf_h263_full_picture_freeze_release,
			{
				"H.263 Full Picture Freeze Release",
				"h263.split_screen_indicator",
				FT_BOOLEAN,
				8,
				TFS(&on_off_flg),
				0x20,
				"Full Picture Freeze Release", HFILL
			}
		},
		{
			&hf_h263_source_format,
			{
				"H.263 Source Format",
				"h263.split_screen_indicator",
				FT_UINT8,
				BASE_HEX,
				VALS(srcformat_vals),
				0x1c,
				"Source Format", HFILL
			}
		},
		{
			&hf_h263_payload_picture_coding_type,
			{
				"H.263 Picture Coding Type",
				"h263.picture_coding_type",
				FT_BOOLEAN,
				8,
				TFS(&picture_coding_type_flg),
				0x02,
				"Picture Coding Typet", HFILL
			}
		},
		{
			&hf_h263_opt_unres_motion_vector_mode,
			{
				"H.263 Optional Unrestricted Motion Vector mode",
				"h263.opt_unres_motion_vector_mode",
				FT_BOOLEAN,
				8,
				TFS(&on_off_flg),
				0x01,
				"Optional Unrestricted Motion Vector mode", HFILL
			}
		},
		{
			&hf_h263_syntax_based_arithmetic_coding_mode,
			{
				"H.263 Optional Syntax-based Arithmetic Coding mode",
				"h263.syntax_based_arithmetic_coding_mode",
				FT_BOOLEAN,
				8,
				TFS(&on_off_flg),
				0x80,
				"Optional Syntax-based Arithmetic Coding mode", HFILL
			}
		},
		{
			&hf_h263_optional_advanced_prediction_mode,
			{
				"H.263 Optional Advanced Prediction mode",
				"h263.optional_advanced_prediction_mode",
				FT_BOOLEAN,
				8,
				TFS(&on_off_flg),
				0x40,
				"Optional Advanced Prediction mode", HFILL
			}
		},
		{
			&hf_h263_PB_frames_mode,
			{
				"H.263 Optional PB-frames mode",
				"h263.PB_frames_mode",
				FT_BOOLEAN,
				8,
				TFS(&PB_frames_mode_flg),
				0x20,
				"Optional PB-frames mode", HFILL
			}
		},

};

	static gint *ett[] =
	{
		&ett_h263,
		&ett_h263_payload,
	};


	proto_h263 = proto_register_protocol("ITU-T Recommendation H.263 RTP Payload header (RFC2190)",
	    "H.263", "h263");
	proto_register_field_array(proto_h263, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("h263", dissect_h263, proto_h263);
}

void
proto_reg_handoff_h263(void)
{
	dissector_handle_t h263_handle;

	h263_handle = find_dissector("h263");
	dissector_add("rtp.pt", PT_H263, h263_handle);
	dissector_add("iax2.codec", AST_FORMAT_H263, h263_handle);
}
