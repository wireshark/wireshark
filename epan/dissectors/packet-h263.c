/* packet-h263.c
 *
 * Routines for ITU-T Recommendation H.263 dissection
 *
 * Copyright 2003 Niklas Ögren <niklas.ogren@7l.se>
 * Seven Levels Consultants AB
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * ITU-T Recommendations and RFC 2190 and
 * http://www.ietf.org/rfc/rfc4629.txt?number=4629
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include <epan/emem.h>
#include <epan/rtp_pt.h>
#include <epan/iax2_codec_type.h>

static void dissect_h263_data( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree );

/* H.263 header fields             */
static int proto_h263			= -1;
static int proto_h263P			= -1;
static int proto_h263_data		= -1;

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
static int hf_h263_data			= -1;
static int hf_h263_payload		= -1;
static int hf_h263_GN			= -1;
static int hf_h263_UFEP			= -1;
static int hf_h263_opptype		= -1;


/* H.263 RFC 4629 fields */
static int hf_h263P_payload = -1;
static int hf_h263P_rr = -1;
static int hf_h263P_pbit = -1;
static int hf_h263P_vbit = -1;
static int hf_h263P_plen = -1;
static int hf_h263P_pebit = -1;
static int hf_h263P_tid = -1;
static int hf_h263P_trun = -1;
static int hf_h263P_s = -1;
static int hf_h263P_extra_hdr = -1;
static int hf_h263P_PSC = -1;
static int hf_h263P_TR = -1;

/* Source format types */
#define H263_SRCFORMAT_FORB		0  /* forbidden */
#define H263_SRCFORMAT_SQCIF	1
#define H263_SRCFORMAT_QCIF		2
#define H263_SRCFORMAT_CIF		3
#define H263_SRCFORMAT_4CIF		4
#define H263_SRCFORMAT_16CIF	5
#define H263_PLUSPTYPE			7

static const value_string srcformat_vals[] =
{
  { H263_SRCFORMAT_FORB,		"forbidden" },
  { H263_SRCFORMAT_SQCIF,		"sub-QCIF 128x96" },
  { H263_SRCFORMAT_QCIF,		"QCIF 176x144" },
  { H263_SRCFORMAT_CIF,			"CIF 352x288" },
  { H263_SRCFORMAT_4CIF,		"4CIF 704x576" },
  { H263_SRCFORMAT_16CIF,		"16CIF 1408x1152" },
  { 6,							"Reserved",},
  { H263_PLUSPTYPE,				"extended PTYPE" },
  { 0,		NULL },
};

static const value_string h263_ufep_vals[] =
{
  { 0,		"Only MPPTYPE included" },
  { 1,		"All extended PTYPE fields are included" },
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

static const value_string picture_coding_type_vals[] =
{
  { 0,		"I-Frame" },
  { 1,		"P-frame" },
  { 0,		NULL },
};

static const true_false_string PB_frames_mode_flg = {
  "PB-frame",
  "Normal I- or P-picture"
};

/* H.263 fields defining a sub tree */
static gint ett_h263			= -1;
static gint ett_h263_payload	= -1;
static gint ett_h263_optype		= -1;

/* H.263-1998 fields defining a sub tree */
static gint ett_h263P			= -1;
static gint ett_h263P_extra_hdr = -1;
static gint ett_h263P_payload	= -1;
static gint ett_h263P_data = -1;

static void
dissect_h263( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti					= NULL;
	proto_tree *h263_tree			= NULL;
	unsigned int offset				= 0;
	unsigned int h263_version		= 0;
	tvbuff_t *next_tvb;

	h263_version = (tvb_get_guint8( tvb, offset ) & 0xc0 ) >> 6;

	if ( check_col( pinfo->cinfo, COL_PROTOCOL ) )   {
		col_set_str( pinfo->cinfo, COL_PROTOCOL, "H.263 " );
	}

	if( h263_version == 0x00) {
	  if ( check_col( pinfo->cinfo, COL_INFO) ) {
	    col_append_str( pinfo->cinfo, COL_INFO, "MODE A ");
	  }
	}
	else if( h263_version == 0x02) {
	  if ( check_col( pinfo->cinfo, COL_INFO) ) {
	    col_append_str( pinfo->cinfo, COL_INFO, "MODE B ");
	  }
	}
	else if( h263_version == 0x03) {
	  if ( check_col( pinfo->cinfo, COL_INFO) ) {
	    col_append_str( pinfo->cinfo, COL_INFO, "MODE C ");
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
	  next_tvb = tvb_new_subset( tvb, offset, tvb_length(tvb) - offset, tvb_reported_length(tvb) - offset);
	  dissect_h263_data( next_tvb, pinfo, h263_tree );

	}
}

#define cVALS(x) (const value_string*)(x)

static proto_item *
h263_proto_tree_add_bits(proto_tree *tree, int hf_index, tvbuff_t *tvb, gint bit_offset, gint no_of_bits)
{
	gint offset;
	guint length;
	char *str;
	header_field_info *hfinfo;
	guint32 value = 0;
	int bit;
	guint32 mask = 0, tmp;
	gboolean is_bytealigned = FALSE;
	guint8 mask8	= 0xff;
	guint16 mask16	= 0xffff;
	guint32 mask24	= 0xffffff;
	guint32 mask32	= 0xffffffff;
	guint8 shift;
	int i;

	if((bit_offset&0x7)==0)
		is_bytealigned = TRUE;

	hfinfo = proto_registrar_get_nth(hf_index);

	offset = bit_offset>>3;
	length = ((bit_offset&0x7)+no_of_bits)>>3;
	length = length +1;

	if (no_of_bits < 2){
		/* Single bit */
		mask8 = mask8 >>(bit_offset&0x7);
		value = tvb_get_guint8(tvb,offset) & mask8;
		mask = 0x80;
		shift = 8-((bit_offset + no_of_bits)&0x7);
		value = value >> shift;
		mask = mask >> shift;
	}else if(no_of_bits < 9){
		/* One or 2 bytes */
		if(length == 1){
			/* Spans 1 byte */
			mask8 = mask8>>(bit_offset&0x7);
			value = tvb_get_guint8(tvb,offset)&mask8;
			mask = 0x80;
		}else{
			/* Spans 2 bytes */	
			mask16 = mask16>>(bit_offset&0x7);
			value = tvb_get_ntohs(tvb,offset) & mask16;
			mask = 0x8000;
		}
		shift = 8-((bit_offset + no_of_bits)&0x7);
		value = value >> shift;
		mask = mask >> shift;
		
	}else if (no_of_bits < 17){
		/* 2 or 3 bytes */
		if(length == 2){
			/* Spans 2 bytes */
			mask16 = mask16>>(bit_offset&0x7);
			value = tvb_get_ntohs(tvb,offset) & mask16;
			mask = 0x8000;
		}else{
			/* Spans 3 bytes */	
			mask24 = mask24>>(bit_offset&0x7);
			value = tvb_get_ntoh24(tvb,offset) & mask24;
			mask = 0x800000;
		}
		shift = 8-((bit_offset + no_of_bits)&0x7);

		value = value >> shift;
		mask = mask >> shift;

	}else if (no_of_bits < 25){
		/* 3 or 4 bytes */
		if(length == 3){
			/* Spans 3 bytes */
			mask24 = mask24>>(bit_offset&0x7);
			value = tvb_get_ntoh24(tvb,offset) & mask24;
			mask = 0x800000;
		}else{
			/* Spans 4 bytes */	
			mask32 = mask32>>(bit_offset&0x7);
			value = tvb_get_ntohl(tvb,offset) & mask32;
			mask = 0x80000000;
		}
		shift = 8-((bit_offset + no_of_bits)&0x7);

		value = value >> shift;
		mask = mask >> shift;

	}else if (no_of_bits < 33){
		/* 4 or 5 bytes */
		if(length == 4){
			/* Spans 4 bytes */	
			mask32 = mask32>>(bit_offset&0x7);
			value = tvb_get_ntohl(tvb,offset) & mask32;
			mask = 0x80000000;
		}else{
			/* Spans 5 bytes
			 * Does not handle unaligned bits over 24
			 */
			DISSECTOR_ASSERT_NOT_REACHED();
		}
		shift = 8-((bit_offset + no_of_bits)&0x7);

		value = value >> shift;
		mask = mask >> shift;

	}else{
		g_assert_not_reached();
	}

	/* prepare the string */
	str=ep_alloc(256);
	str[0]='0';
	for(bit=0;bit<((int)(bit_offset&0x07));bit++){
		if(bit&&(!(bit%4))){
			strcat(str, " ");
		}
		strcat(str,".");
		mask = mask>>1;
	}
	/* read the bits for the int */
	for(i=0;i<no_of_bits;i++){
		if(bit&&(!(bit%4))){
			strcat(str, " ");
		}
		if(bit&&(!(bit%8))){
			strcat(str, " ");
		}
		bit++;
		tmp = value & mask;
		if(tmp != 0){
			strcat(str, "1");
		} else {
			strcat(str, "0");
		}
		mask = mask>>1;
	}
	for(;bit%8;bit++){
		if(bit&&(!(bit%4))){
			strcat(str, " ");
		}
		strcat(str,".");
	}


	strcat(str," = ");
	strcat(str,hfinfo->name);
	if (no_of_bits== 1){
		/* Boolean field */
		if (hfinfo->strings) {
			const true_false_string		*tfstring = &tfs_true_false;
			tfstring = (const struct true_false_string*) hfinfo->strings;

			return proto_tree_add_boolean_format(tree, hf_index, tvb, offset, length, value,
				"%s: %s",
				str,
				value ? tfstring->true_string : tfstring->false_string);
		}

	}
	/* 2 - 32 bits field */

	if (hfinfo->strings) {
		return proto_tree_add_uint_format(tree, hf_index, tvb, offset, length, value,
                      "%s: %s",
					  str,
					  val_to_str(value, cVALS(hfinfo->strings), "Unknown"));
	}
	switch(hfinfo->display){
	case BASE_DEC:
		return proto_tree_add_uint_format(tree, hf_index, tvb, offset, length, value,
	                 "%s: %u",
					  str,
					  value);
		break;
	case BASE_HEX:
		return proto_tree_add_uint_format(tree, hf_index, tvb, offset, length, value,
	                 "%s: %x",
					  str,
					  value);
		break;
	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		return NULL;
		;
	}

}

/*
 * Length is used for the "Extra header" otherwise set to -1.
 */
static int
dissect_h263_picture_layer( tvbuff_t *tvb, proto_tree *tree, gint offset, gint length _U_, gboolean is_rfc4626)
{
	proto_tree *h263_opptype_tree	= NULL;
	proto_item *opptype_item		= NULL;
	unsigned int offset_in_bits		= offset << 3;
	guint8 source_format;
	guint16 ufep;

	if(is_rfc4626){
		/* PC 1000 00xx */ 
		h263_proto_tree_add_bits(tree, hf_h263_psc, tvb, offset_in_bits, 6);
		offset_in_bits = offset_in_bits +6;

	}else{
	/* Check for PSC, PSC is a word of 22 bits. 
	 * Its value is 0000 0000 0000 0000' 1000 00xx xxxx xxxx.
	 */
		h263_proto_tree_add_bits(tree, hf_h263_psc, tvb, offset_in_bits, 22);
		offset_in_bits = offset_in_bits +22;

	}
	h263_proto_tree_add_bits(tree, hf_h263_TR, tvb, offset_in_bits, 8);
	offset_in_bits = offset_in_bits +8;
	/*
	 * Bit 1: Always "1", in order to avoid start code emulation. 
	 * Bit 2: Always "0", for distinction with Recommendation H.261.
	 */
	offset_in_bits = offset_in_bits +2;
	/* Bit 3: Split screen indicator, "0" off, "1" on. */
	h263_proto_tree_add_bits( tree, hf_h263_split_screen_indicator, tvb, offset_in_bits, 1);
	offset_in_bits++;
	/* Bit 4: Document camera indicator, */
	h263_proto_tree_add_bits( tree, hf_h263_document_camera_indicator, tvb, offset_in_bits, 1);
	offset_in_bits++;
	/* Bit 5: Full Picture Freeze Release, "0" off, "1" on. */
	h263_proto_tree_add_bits( tree, hf_h263_full_picture_freeze_release, tvb, offset_in_bits, 1);
	offset_in_bits++;
	/* Bits 6-8: Source Format, "000" forbidden, "001" sub-QCIF, "010" QCIF, "011" CIF,
	 * "100" 4CIF, "101" 16CIF, "110" reserved, "111" extended PTYPE.
	 */
	h263_proto_tree_add_bits( tree, hf_h263_source_format, tvb, offset_in_bits, 3);
	offset_in_bits = offset_in_bits +3;
	source_format = (tvb_get_guint8(tvb,(offset_in_bits>>3)& 0x1c)>>2);
	if (source_format != H263_PLUSPTYPE){
		/* Not extended PTYPE */
		/* Bit 9: Picture Coding Type, "0" INTRA (I-picture), "1" INTER (P-picture). */
		h263_proto_tree_add_bits( tree, hf_h263_payload_picture_coding_type, tvb, offset_in_bits, 1);
		offset_in_bits++;
		/* Bit 10: Optional Unrestricted Motion Vector mode (see Annex D), "0" off, "1" on. */
		h263_proto_tree_add_bits( tree, hf_h263_opt_unres_motion_vector_mode, tvb, offset_in_bits, 1);
		offset_in_bits++;
		/* Bit 11: Optional Syntax-based Arithmetic Coding mode (see Annex E), "0" off, "1" on.*/
		h263_proto_tree_add_bits( tree, hf_h263_syntax_based_arithmetic_coding_mode, tvb, offset_in_bits, 1);
		offset_in_bits++;
		/* Bit 12: Optional Advanced Prediction mode (see Annex F), "0" off, "1" on.*/
		h263_proto_tree_add_bits( tree, hf_h263_optional_advanced_prediction_mode, tvb, offset_in_bits, 1);
		offset_in_bits++;
		/* Bit 13: Optional PB-frames mode (see Annex G), "0" normal I- or P-picture, "1" PB-frame.*/
		h263_proto_tree_add_bits( tree, hf_h263_PB_frames_mode, tvb, offset_in_bits, 1);
		offset_in_bits++;
	}else{
		/* Extended PTYPE 
		 * Update Full Extended PTYPE (UFEP) (3 bits)
		 */
		ufep = (tvb_get_ntohs(tvb,offset)&0x0380)>>7;
		/* .... ..xx x... .... */
		h263_proto_tree_add_bits( tree, hf_h263_UFEP, tvb, offset_in_bits, 3);
		offset_in_bits = offset_in_bits +3;
		if(ufep==1){
			/* The Optional Part of PLUSPTYPE (OPPTYPE) (18 bits) 
			 */
			 /*  .xxx xxxx  xxxx xxxx  xxx. .... */
			opptype_item = h263_proto_tree_add_bits( tree, hf_h263_opptype, tvb, offset_in_bits, 18);
			h263_opptype_tree = proto_item_add_subtree( opptype_item, ett_h263_optype );
			/*
			 * If UFEP is "001", then the following bits are present in PLUSPTYPE:
			 *  Bits 1-3 Source Format, "000" reserved, "001" sub-QCIF, "010" QCIF, "011" CIF,
			 * "100" 4CIF, "101" 16CIF, "110" custom source format, "111" reserved;
			 */
			h263_proto_tree_add_bits( h263_opptype_tree, hf_h263_source_format, tvb, offset_in_bits, 3);
			offset_in_bits = offset_in_bits +3;
			offset_in_bits = offset_in_bits +15;/* 18-3 */
			/*
			 *  Bit 4 Optional Custom PCF, "0" CIF PCF, "1" custom PCF;
			 *  Bit 5 Optional Unrestricted Motion Vector (UMV) mode (see Annex D), "0" off, "1" on;
			 *  Bit 6 Optional Syntax-based Arithmetic Coding (SAC) mode (see Annex E), "0" off, "1" on;
			 *  Bit 7 Optional Advanced Prediction (AP) mode (see Annex F), "0" off, "1" on;
			 *  Bit 8 Optional Advanced INTRA Coding (AIC) mode (see Annex I), "0" off, "1" on;
			 *  Bit 9 Optional Deblocking Filter (DF) mode (see Annex J), "0" off, "1" on;
			 *  Bit 10 Optional Slice Structured (SS) mode (see Annex K), "0" off, "1" on;
			 *  Bit 11 Optional Reference Picture Selection (RPS) mode (see Annex N), "0" off, "1" on;
			 *  Bit 12 Optional Independent Segment Decoding (ISD) mode (see Annex R), "0" off,"1" on;
			 *  Bit 13 Optional Alternative INTER VLC (AIV) mode (see Annex S), "0" off, "1" on;
			 *  Bit 14 Optional Modified Quantization (MQ) mode (see Annex T), "0" off, "1" on;
			 *  Bit 15 Equal to "1" to prevent start code emulation;
			 *  Bit 16 Reserved, shall be equal to "0";
			 *  Bit 17 Reserved, shall be equal to "0";
			 *  Bit 18 Reserved, shall be equal to "0".
			 */
		}
		/*
		 * 5.1.4.3 The mandatory part of PLUSPTYPE when PLUSPTYPE present (MPPTYPE) (9 bits)
		 * Regardless of the value of UFEP, the following 9 bits are also present in PLUSPTYPE:
		 * – Bits 1-3 Picture Type Code:
		 * "000" I-picture (INTRA);
		 * "001" P-picture (INTER);
		 * "010" Improved PB-frame (see Annex M);
		 * "011" B-picture (see Annex O);
		 * "100" EI-picture (see Annex O);
		 * "101" EP-picture (see Annex O);
		 * "110" Reserved;
		 * "111" Reserved;
		 * – Bit 4 Optional Reference Picture Resampling (RPR) mode (see Annex P), "0" off, "1" on;
		 * – Bit 5 Optional Reduced-Resolution Update (RRU) mode (see Annex Q), "0" off, "1" on;
		 * – Bit 6 Rounding Type (RTYPE) (see 6.1.2);
		 * – Bit 7 Reserved, shall be equal to "0";
		 * – Bit 8 Reserved, shall be equal to "0";
		 * – Bit 9 Equal to "1" to prevent start code emulation.
		 */
		offset_in_bits = offset_in_bits +9;
	}

	return offset_in_bits>>3;

}

/* RFC 4629 */
static void
dissect_h263P( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti					= NULL;
	proto_item *data_item			= NULL;
	proto_item *extra_hdr_item		= NULL;
	proto_tree *h263P_tree			= NULL;
	proto_tree *h263P_extr_hdr_tree	= NULL;
	proto_tree *h263P_data_tree		= NULL;
	unsigned int offset				= 0;
	unsigned int start_offset		= 0;
	guint16 data16, plen;
	guint8 octet;

	/*
	tvbuff_t *next_tvb;
	*/

	if ( check_col( pinfo->cinfo, COL_PROTOCOL ) )   {
		col_set_str( pinfo->cinfo, COL_PROTOCOL, "H.263 RFC4629 " );
	}

	if ( tree ) {
	  ti = proto_tree_add_item( tree, proto_h263P, tvb, offset, -1, FALSE );
	  h263P_tree = proto_item_add_subtree( ti, ett_h263P );
	  /* Add it as hidden to make a filter of h263 possible here as well */
	  proto_tree_add_item_hidden( tree, proto_h263, tvb, offset, -1, FALSE );

	  data16 = tvb_get_ntohs(tvb,offset);
	  proto_tree_add_item( h263P_tree, hf_h263P_rr, tvb, offset, 2, FALSE );
	  proto_tree_add_item( h263P_tree, hf_h263P_pbit, tvb, offset, 2, FALSE );
	  proto_tree_add_item( h263P_tree, hf_h263P_vbit, tvb, offset, 2, FALSE );
	  proto_tree_add_item( h263P_tree, hf_h263P_plen, tvb, offset, 2, FALSE );
	  proto_tree_add_item( h263P_tree, hf_h263P_pebit, tvb, offset, 2, FALSE );
	  offset = offset +2;
	  /*
	   *   V: 1 bit
	   *
	   *      Indicates the presence of an 8-bit field containing information
	   *      for Video Redundancy Coding (VRC), which follows immediately after
	   *      the initial 16 bits of the payload header, if present.  For syntax
	   *      and semantics of that 8-bit VRC field, see Section 5.2.
	   */

	  if ((data16&0x0200)==0x0200){
		  /* V bit = 1 
		   *   The format of the VRC header extension is as follows:
		   *
		   *         0 1 2 3 4 5 6 7
		   *        +-+-+-+-+-+-+-+-+
		   *        | TID | Trun  |S|
		   *        +-+-+-+-+-+-+-+-+
		   *
		   *   TID: 3 bits
		   *
		   *   Thread ID.  Up to 7 threads are allowed.  Each frame of H.263+ VRC
		   *   data will use as reference information only sync frames or frames
		   *   within the same thread.  By convention, thread 0 is expected to be
		   *   the "canonical" thread, which is the thread from which the sync frame
		   *   should ideally be used.  In the case of corruption or loss of the
		   *   thread 0 representation, a representation of the sync frame with a
		   *   higher thread number can be used by the decoder.  Lower thread
		   *   numbers are expected to contain representations of the sync frames
		   *   equal to or better than higher thread numbers in the absence of data
		   *   corruption or loss.  See [Vredun] for a detailed discussion of VRC.
		   *
		   *   Trun: 4 bits
		   *
		   *   Monotonically increasing (modulo 16) 4-bit number counting the packet
		   *   number within each thread.
		   *
		   *   S: 1 bit
		   *
		   *   A bit that indicates that the packet content is for a sync frame.  
		   *   :
		   */
		  proto_tree_add_item( h263P_tree, hf_h263P_tid, tvb, offset, 1, FALSE );
		  proto_tree_add_item( h263P_tree, hf_h263P_trun, tvb, offset, 1, FALSE );
		  proto_tree_add_item( h263P_tree, hf_h263P_s, tvb, offset, 1, FALSE );
		  offset++;
	  }

	  /* Length, in bytes, of the extra picture header. */
	  plen = (data16 & 0x01f8) >> 3;
	  if (plen != 0){
		  start_offset = offset;
		  extra_hdr_item = proto_tree_add_item( h263P_tree, hf_h263P_extra_hdr, tvb, offset, plen, FALSE );
		  h263P_extr_hdr_tree = proto_item_add_subtree( extra_hdr_item, ett_h263P_extra_hdr );
		  
		  dissect_h263_picture_layer( tvb, h263P_extr_hdr_tree, offset, plen, TRUE);

		  offset = start_offset + plen;		
	  }
	  if ((data16&0x0400)!=0){
		  /* P bit = 1 */
		  data_item = proto_tree_add_item( h263P_tree, hf_h263P_payload, tvb, offset, -1, FALSE );
		  h263P_data_tree = proto_item_add_subtree( data_item, ett_h263P_data );
		  octet = tvb_get_guint8(tvb,offset);
		  if((octet&0xfc)==0x80){
			  /* Check for PSC, PSC is a word of 22 bits. Its value is 0000 0000 0000 0000' 1000 00xx xxxx xxxx.
			   * Here without the first two 0 bytes of the PSC
			   */
			if ( check_col( pinfo->cinfo, COL_INFO) )
				col_append_str( pinfo->cinfo, COL_INFO, "(PSC) ");

			offset = dissect_h263_picture_layer( tvb, h263P_data_tree, offset, -1, TRUE);
			return;
		  }else{
			  /*
			if ( check_col( pinfo->cinfo, COL_INFO) )
			  col_append_str( pinfo->cinfo, COL_INFO, "(GBSC) ");
			  */
			  return;
		  }
	  }
	  proto_tree_add_item( h263P_tree, hf_h263P_payload, tvb, offset, -1, FALSE );
	}
}
/*
TODO: Add these?
	End Of Sequence (EOS) (22 bits)
	A codeword of 22 bits. Its value is 0000 0000 0000 0000 1 11111.

	Group of Block Start Code (GBSC) (17 bits)
	A word of 17 bits. Its value is 0000 0000 0000 0000 1.

	End Of Sub-Bitstream code (EOSBS) (23 bits)
	The EOSBS code is a codeword of 23 bits. Its value is 0000 0000 0000 0000 1 11110 0.

	Slice Start Code (SSC) (17 bits)
	A word of 17 bits. Its value is 0000 0000 0000 0000 1.
  */
static void dissect_h263_data( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	guint offset = 0;
	proto_item *h263_payload_item	= NULL;
	proto_tree *h263_payload_tree	= NULL;
	guint32 data;

	if ( check_col( pinfo->cinfo, COL_INFO) ) {
	  col_append_str( pinfo->cinfo, COL_INFO, "H263 payload ");
	}

	if( tree ) {
	  h263_payload_item = proto_tree_add_item( tree, hf_h263_payload, tvb, offset, -1, FALSE );
	  h263_payload_tree = proto_item_add_subtree( h263_payload_item, ett_h263_payload );
	}

	/* Check for PSC, PSC is a word of 22 bits. Its value is 0000 0000 0000 0000' 1000 00xx xxxx xxxx. */
	data = tvb_get_ntohl(tvb, offset);
	
	if (( data & 0xffff8000) == 0x00008000 ) { /* PSC or Group of Block Start Code (GBSC) found */
		if (( data & 0x00007c00) == 0 ) { /* PSC found */
			if ( check_col( pinfo->cinfo, COL_INFO) )
			  col_append_str( pinfo->cinfo, COL_INFO, "(PSC) ");
			if( tree ) {
				offset = dissect_h263_picture_layer( tvb, h263_payload_tree, offset, -1, FALSE);
			}
		} else { /* GBSC found */
			if ( check_col( pinfo->cinfo, COL_INFO) )
			  col_append_str( pinfo->cinfo, COL_INFO, "(GBSC) ");
			if( tree ) {
				/* Group of Block Start Code (GBSC) (17 bits)
				 * A word of 17 bits. Its value is 0000 0000 0000 0000 1. GOB start codes may be byte aligned. This
				 * can be achieved by inserting GSTUF before the start code such that the first bit of the start code is
				 * the first (most significant) bit of a byte.
				 *
				 */
				proto_tree_add_uint(h263_payload_tree, hf_h263_gbsc,tvb, offset,3,data);
 				proto_tree_add_uint(h263_payload_tree, hf_h263_GN, tvb, offset,3,data);
				/* GN is followed by (optionally) GBSI, then
				 * GFID and GQUANT, but decoding them requires
				 * knowing the value of CPM in the picture
				 * header */
				offset = offset + 2;
			}
		}
	}
	if( tree )
		proto_tree_add_item( h263_payload_tree, hf_h263_data, tvb, offset, -1, FALSE );
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
				"h263.ftype",
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
			&hf_h263_payload,
			{
				"H.263 payload",
				"h263.payload",
				FT_NONE,
				BASE_NONE,
				NULL,
				0x0,
				"The actual H.263 data", HFILL
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
			&hf_h263_UFEP,
			{
				"H.263 Update Full Extended PTYPE",
				"h263.ufep",
				FT_UINT16,
				BASE_DEC,
				VALS(h263_ufep_vals),
				0x0380,
				"Update Full Extended PTYPE", HFILL
			}
		},
		{
			&hf_h263_opptype,
			{
				"H.263 Optional Part of PLUSPTYPE",
				"h263.opptype",
				FT_UINT24,
				BASE_DEC,
				NULL,
				0x7fffe0,
				"Optional Part of PLUSPTYPE", HFILL
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
		{
			&hf_h263_GN,
			{
				"H.263 Group Number",
				"h263.gn",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x00007c00,
				"Group Number, GN", HFILL
			}
		},
};

	static gint *ett[] =
	{
		&ett_h263,
		&ett_h263_payload,
		&ett_h263_optype,
	};


	proto_h263 = proto_register_protocol("ITU-T Recommendation H.263 RTP Payload header (RFC2190)",
	    "H.263", "h263");
	proto_h263_data = proto_register_protocol("ITU-T Recommendation H.263",
	    "H.263 data", "h263data");
	proto_register_field_array(proto_h263, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("h263", dissect_h263, proto_h263);
	register_dissector("h263data", dissect_h263_data, proto_h263_data);
}

void
proto_register_h263P(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_h263P_payload,
			{
				"H.263 RFC4629 payload",
				"h263P.payload",
				FT_NONE,
				BASE_NONE,
				NULL,
				0x0,
				"The actual H.263 RFC4629 data", HFILL
			}
		},
		{
			&hf_h263P_rr,
			{
				"Reserved",
				"h263P.rr",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0xf800,
				"Reserved SHALL be zero", HFILL
			}
		},
		{
			&hf_h263P_pbit,
			{
				"P",
				"h263P.p",
				FT_BOOLEAN,
				16,
				NULL,
				0x0400,
				"Indicates (GOB/Slice) start or (EOS or EOSBS)", HFILL
			}
		},
		{
			&hf_h263P_vbit,
			{
				"V",
				"h263P.v",
				FT_BOOLEAN,
				16,
				NULL,
				0x0200,
				"presence of Video Redundancy Coding (VRC) field", HFILL
			}
		},
		{
			&hf_h263P_plen,
			{
				"PLEN",
				"h263P.plen",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x01f8,
				"Length, in bytes, of the extra picture header", HFILL
			}
		},
		{
			&hf_h263P_pebit,
			{
				"PEBIT",
				"h263P.pebit",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0003,
				"number of bits that shall be ignored in the last byte of the picture header", HFILL
			}
		},


		{
			&hf_h263P_tid,
			{
				"Thread ID",
				"h263P.tid",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0xe0,
				"Thread ID", HFILL
			}
		},
		{
			&hf_h263P_trun,
			{
				"Trun",
				"h263P.trun",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x1e,
				"Monotonically increasing (modulo 16) 4-bit number counting the packet number within each thread", HFILL
			}
		},
		{
			&hf_h263P_s,
			{
				"S",
				"h263P.s",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x01,
				"Indicates that the packet content is for a sync frame", HFILL
			}
		},
		{
			&hf_h263P_extra_hdr,
			{
				"Extra picture header",
				"h263P.extra_hdr",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x0,
				"Extra picture header", HFILL
			}
		},
		{
			&hf_h263P_PSC,
			{
				"H.263 PSC",
				"h263P.PSC",
				FT_UINT16,
				BASE_HEX,
				NULL,
				0xfc00,
				"Picture Start Code(PSC)", HFILL
			}
		},
		{
			&hf_h263P_TR,
			{
				"H.263 Temporal Reference",
				"h263P.tr",
				FT_UINT16,
				BASE_HEX,
				NULL,
				0x03fc,
				"Temporal Reference, TR", HFILL
			}
		},

	};

	static gint *ett[] =
	{
		&ett_h263P,
		&ett_h263P_extra_hdr,
		&ett_h263P_payload,
		&ett_h263P_data,
	};


	proto_h263P = proto_register_protocol("ITU-T Recommendation H.263 RTP Payload header (RFC4629)",
	    "H263P", "h263p");

	proto_register_field_array(proto_h263P, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("h263P", dissect_h263P, proto_h263P);

}

void
proto_reg_handoff_h263(void)
{
	dissector_handle_t h263_handle;

	h263_handle = find_dissector("h263");
	dissector_add("rtp.pt", PT_H263, h263_handle);
	dissector_add("iax2.codec", AST_FORMAT_H263, h263_handle);
}

void
proto_reg_handoff_h263P(void)
{
	dissector_handle_t h263P_handle;

	h263P_handle = find_dissector("h263P");
	dissector_add_string("rtp_dyn_payload_type","H263-1998", h263P_handle);
	dissector_add_string("rtp_dyn_payload_type","H263-2000", h263P_handle);
}
