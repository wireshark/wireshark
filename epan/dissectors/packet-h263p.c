/* packet-h263p.c
 *
 * Routines for RFC-4629-encapsulated H.263 dissection
 *
 * Copyright 2003 Niklas Ogren <niklas.ogren@7l.se>
 * Seven Levels Consultants AB
 *
 * Copyright 2008 Richard van der Hoff, MX Telecom
 * <richardv@mxtelecom.com>
 *
 * $Id$
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/prefs.h>

#include "packet-h263.h"

static int proto_h263P			= -1;

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


/* H.263-1998 fields defining a sub tree */
static gint ett_h263P			= -1;
static gint ett_h263P_extra_hdr = -1;
static gint ett_h263P_payload	= -1;
static gint ett_h263P_data = -1;

/* The dynamic payload type which will be dissected as H.263-1998/H263-2000 */

static guint temp_dynamic_payload_type = 0;

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
	guint16 data16, plen;
	guint8 startcode;

	/*
	tvbuff_t *next_tvb;
	*/

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "H.263 RFC4629 ");

	if ( tree ) {
	  ti = proto_tree_add_item( tree, proto_h263P, tvb, offset, -1, FALSE );
	  h263P_tree = proto_item_add_subtree( ti, ett_h263P );
          
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
		  extra_hdr_item = proto_tree_add_item( h263P_tree, hf_h263P_extra_hdr, tvb, offset, plen, ENC_NA );
		  h263P_extr_hdr_tree = proto_item_add_subtree( extra_hdr_item, ett_h263P_extra_hdr );
		  dissect_h263_picture_layer( tvb, pinfo, h263P_extr_hdr_tree, offset, plen, TRUE);
		  offset += plen;		
	  }
	  if ((data16&0x0400)!=0){
		  /* P bit = 1 */
		  data_item = proto_tree_add_item( h263P_tree, hf_h263P_payload, tvb, offset, -1, ENC_NA );
		  h263P_data_tree = proto_item_add_subtree( data_item, ett_h263P_data );
		  /* Startc code holds bit 17 -23 of the codeword */
		  startcode = tvb_get_guint8(tvb,offset)&0xfe;
		  if (startcode & 0x80){
			  /* All picture, slice, and EOSBS start codes
			   * shall be byte aligned, and GOB and EOS start codes may be byte aligned.
			   */
			  switch(startcode){
			  case 0xf8:
				  /* End Of Sub-Bitstream code (EOSBS) 
				   * EOSBS codes shall be byte aligned
				   * ( 1111 100. )
				   */
				  break;
			  case 0x80:
			  case 0x82:
				  /* Picture Start Code (PSC)
				   * ( 1000 00x.)
				   */
				  col_append_str( pinfo->cinfo, COL_INFO, "(PSC) ");
				  offset = dissect_h263_picture_layer( tvb, pinfo, h263P_data_tree, offset, -1, TRUE);
				  break;
			  case 0xfc:
			  case 0xfe:
				  /* End Of Sequence (EOS)
				   * ( 1111 11x. )
				   */
			  default:
				  /* Group of Block Start Code (GBSC) or
				   * Slice Start Code (SSC)
				   */
				  col_append_str( pinfo->cinfo, COL_INFO, "(GBSC) ");
				  dissect_h263_group_of_blocks_layer( tvb, h263P_data_tree, offset,TRUE);
				  break;
			  }
		  }else{
			  /* Error */
		  }
		  return;
	  }
	  proto_tree_add_item( h263P_tree, hf_h263P_payload, tvb, offset, -1, ENC_NA );
	}
}

void
proto_reg_handoff_h263P(void)
{
	static dissector_handle_t h263P_handle;
	static guint dynamic_payload_type;
	static gboolean h263P_prefs_initialized = FALSE;

	if (!h263P_prefs_initialized) {
		h263P_handle = find_dissector("h263P");
		dissector_add_string("rtp_dyn_payload_type","H263-1998", h263P_handle);
		dissector_add_string("rtp_dyn_payload_type","H263-2000", h263P_handle);
		h263P_prefs_initialized = TRUE;
	  }
	else {
		if ( dynamic_payload_type > 95 )
			dissector_delete_uint("rtp.pt", dynamic_payload_type, h263P_handle);
	}
	dynamic_payload_type = temp_dynamic_payload_type;

	if ( dynamic_payload_type > 95 ){
		dissector_add_uint("rtp.pt", dynamic_payload_type, h263P_handle);
	}
}


void
proto_register_h263P(void)
{
	module_t *h263P_module;

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
				NULL, HFILL
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
				NULL, HFILL
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

	h263P_module = prefs_register_protocol(proto_h263P, proto_reg_handoff_h263P);

	prefs_register_uint_preference(h263P_module, "dynamic.payload.type",
                                                     "H263-1998 and H263-2000 dynamic payload type",
                                                     "The dynamic payload type which will be interpreted as H264"
                                                     "; The value must be greater than 95",
                                                     10,
                                                     &temp_dynamic_payload_type);

	register_dissector("h263P", dissect_h263P, proto_h263P);

}
