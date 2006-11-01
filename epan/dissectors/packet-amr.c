/* packet-amr.c
 * Routines for AMR dissection
 * Copyright 2005, Anders Broman <anders.broman[at]ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * References:
 * RFC 3267  http://www.ietf.org/rfc/rfc3267.txt?number=3267
 * 3GPP TS 26.101
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/proto.h>

#include "prefs.h"

#define AMR_SID 8
#define AMR_NO_TRANS 15

/* Initialize the protocol and registered fields */
static int proto_amr		= -1;
static int hf_amr_cmr		= -1;
static int hf_amr_reserved	= -1;
static int hf_amr_toc_f		= -1;
static int hf_amr_toc_ft	= -1;
static int hf_amr_toc_q		= -1;

static int hf_amr_if1_ft = -1;
static int hf_amr_if1_fqi = -1;
static int hf_amr_if1_mode_req = -1;
static int hf_amr_if1_sti = -1;
static int hf_amr_if1_mode_ind = -1;
static int hf_amr_if1_sti_mode_ind = -1;
static int hf_amr_sti = -1;

static int hf_amr_if2_ft = -1;

static int hf_amr_be_reserved = -1;
static int hf_amr_be_ft = -1;
static int hf_amr_be_reserved2 = -1;


/* Initialize the subtree pointers */
static int ett_amr = -1;
static int ett_amr_toc = -1;

/* The dynamic payload type which will be dissected as AMR */

static guint dynamic_payload_type = 0;
static guint temp_dynamic_payload_type = 0;
gint amr_encoding_type = 0;

/* Currently only octet aligned works */
/* static gboolean octet_aligned = TRUE; */

static const value_string amr_encoding_type_value[] = {
	{0,			"RFC 3267"}, 
	{1,			"RFC 3267 bandwidth-efficient mode"}, 
	{2,			"AMR IF 1"},
	{3,			"AMR IF 2"},
	{ 0,	NULL }
};

static const value_string amr_codec_mode_vals[] = {
	{0,			"AMR 4,75 kbit/s"}, 
	{1,			"AMR 5,15 kbit/s"},
	{2,			"AMR 5,90 kbit/s"},
	{3,			"AMR 6,70 kbit/s (PDC-EFR)"},
	{4,			"AMR 7,40 kbit/s (TDMA-EFR)"},
	{5,			"AMR 7,95 kbit/s"},
	{6,			"AMR 10,2 kbit/s"},
	{7,			"AMR 12,2 kbit/s (GSM-EFR)"},
	{ 0,	NULL }
};

/* Ref 3GPP TS 26.101 table 1a */
static const value_string amr_codec_mode_request_vals[] = {
	{0,			"AMR 4,75 kbit/s"}, 
	{1,			"AMR 5,15 kbit/s"},
	{2,			"AMR 5,90 kbit/s"},
	{3,			"AMR 6,70 kbit/s (PDC-EFR)"},
	{4,			"AMR 7,40 kbit/s (TDMA-EFR)"},
	{5,			"AMR 7,95 kbit/s"},
	{6,			"AMR 10,2 kbit/s"},
	{7,			"AMR 12,2 kbit/s (GSM-EFR)"},
	{AMR_SID,	"AMR SID"},
	{9,			"GSM-EFR SID"},
	{10,		"TDMA-EFR SID"},
	{11,		"PDC-EFR SID"},
	/*
	{12-14	-	-	For future use
	*/
	{AMR_NO_TRANS,	"No Data (No transmission/No reception)"}, 
	{ 0,	NULL }
};

static const true_false_string toc_f_bit_vals = {
  "Followed by another speech frame",
  "Last frame in this payload"
};

static const true_false_string toc_q_bit_vals = {
  "Ok",
  "Severely damaged frame"
};

static const true_false_string amr_sti_vals = {
  "SID_UPDATE",
  "SID_FIRST"
};
static void
dissect_amr_if1(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree){
	int offset =0;
	guint8 octet;

	proto_tree_add_item(tree, hf_amr_if1_ft, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_amr_if1_fqi, tvb, offset, 1, FALSE);
	octet = tvb_get_guint8(tvb,offset) & 0x0f;
	if (octet == AMR_SID){
		proto_tree_add_item(tree, hf_amr_if1_mode_req, tvb, offset+1, 1, FALSE);
		proto_tree_add_text(tree, tvb, offset+2, 4, "Speech data");
		proto_tree_add_item(tree, hf_amr_if1_sti, tvb, offset+7, 1, FALSE);
		proto_tree_add_item(tree, hf_amr_if1_sti_mode_ind, tvb, offset+7, 1, FALSE);
		return;
	}

	proto_tree_add_item(tree, hf_amr_if1_mode_ind, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(tree, hf_amr_if1_mode_req, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_text(tree, tvb, offset, -1, "Speech data");

}

static void
dissect_amr_if2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset =0;
	guint8 octet;

	proto_tree_add_item(tree, hf_amr_if2_ft, tvb, offset, 1, FALSE);
	octet = tvb_get_guint8(tvb,offset) & 0x0f;
	if (octet == AMR_SID){
		proto_tree_add_text(tree, tvb, offset+1, 3, "Speech data");
		proto_tree_add_item(tree, hf_amr_sti, tvb, offset+4, 1, FALSE);
		proto_tree_add_item(tree, hf_amr_if2_ft, tvb, offset+5, 1, FALSE);
		return;
	}
	if (octet == AMR_NO_TRANS)
		return;
	proto_tree_add_text(tree, tvb, offset+1, -1, "Speech data");

	if(check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(octet, amr_codec_mode_request_vals, "Unknown (%d)" ));
}
/*
 * 4.3.5.1. Single Channel Payload Carrying a Single Frame
 * 
 *    The following diagram shows a bandwidth-efficient AMR payload from a
 *    single channel session carrying a single speech frame-block.
 * 
 *    In the payload, no specific mode is requested (CMR=15), the speech
 *    frame is not damaged at the IP origin (Q=1), and the coding mode is
 *    AMR 7.4 kbps (FT=4).  The encoded speech bits, d(0) to d(147), are
 *    arranged in descending sensitivity order according to [2].  Finally,
 *    two zero bits are added to the end as padding to make the payload
 *    octet aligned.
 * 
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | CMR=15|0| FT=4  |1|d(0)                                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void
dissect_amr_be(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	proto_item *item;
	guint8 octet;
	int offset =0;

	proto_tree_add_item(tree, hf_amr_cmr, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_amr_be_reserved, tvb, offset, 1, FALSE);
	octet = tvb_get_guint8(tvb,offset) & 0x08;
	if ( octet != 0  ){
		item = proto_tree_add_text(tree, tvb, offset, -1, "Reserved != 0, wrongly encoded or not bandwidth-efficient.");
		PROTO_ITEM_SET_GENERATED(item);
		return;
	}
	proto_tree_add_item(tree, hf_amr_be_ft, tvb, offset, 2, FALSE);
	proto_tree_add_item(tree, hf_amr_be_reserved2, tvb, offset, 2, FALSE);
	offset++;
	octet = tvb_get_guint8(tvb,offset) & 0x40;
	if ( octet != 0x40  ){
		item = proto_tree_add_text(tree, tvb, offset, -1, "Reserved != 1, wrongly encoded or not bandwidth-efficient.");
		PROTO_ITEM_SET_GENERATED(item);
		return;
	}
	
}
/* Code to actually dissect the packets */
static void
dissect_amr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	int toc_offset = 0;
	guint8 octet;
	proto_item *item;
	gboolean first_time;

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti,*toc_item;
	proto_tree *amr_tree, *toc_tree;

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "AMR");
	if (tree) {

		ti = proto_tree_add_item(tree, proto_amr, tvb, 0, -1, FALSE);
		amr_tree = proto_item_add_subtree(ti, ett_amr);

		proto_tree_add_text(amr_tree, tvb, offset, -1, "Payload decoded as %s",val_to_str(amr_encoding_type, amr_encoding_type_value, "Unknown value - Error"));

		switch (amr_encoding_type){
		case 0: /* RFC 3267 Byte aligned */
			break;
		case 1: /* RFC 3267 Bandwidth-efficient */
			dissect_amr_be(tvb, pinfo, amr_tree);
			return;
		case 2: /* AMR IF1 */
			dissect_amr_if1(tvb, pinfo, amr_tree);
			return;
		case 3: /* AMR IF2 */
			dissect_amr_if2(tvb, pinfo, amr_tree);
			return;
		default:
			break;
		}



		proto_tree_add_item(amr_tree, hf_amr_cmr, tvb, offset, 1, FALSE);
		octet = tvb_get_guint8(tvb,offset) & 0x0f;
		if ( octet != 0  ){
			item = proto_tree_add_text(amr_tree, tvb, offset, -1, "Reserved != 0, wrongly encoded or not octet aligned. Decoding as bandwidth-efficient mode");
			PROTO_ITEM_SET_GENERATED(item);
			return;

		}

		proto_tree_add_item(amr_tree, hf_amr_reserved, tvb, offset, 1, FALSE);
		offset++;
		toc_offset = offset;
		/*
		 *  A ToC entry takes the following format in octet-aligned mode:
		 *
		 *    0 1 2 3 4 5 6 7
		 *   +-+-+-+-+-+-+-+-+
		 *   |F|  FT   |Q|P|P|
		 *   +-+-+-+-+-+-+-+-+
		 *
		 *   F (1 bit): see definition in Section 4.3.2.
		 *
		 *   FT (4 bits unsigned integer): see definition in Section 4.3.2.
		 *
		 *   Q (1 bit): see definition in Section 4.3.2.
		 *
		 *   P bits: padding bits, MUST be set to zero.
		 */
		octet = tvb_get_guint8(tvb,offset);
		toc_item = proto_tree_add_text(amr_tree, tvb, offset, -1, "Payload Table of Contents");
		toc_tree = proto_item_add_subtree(toc_item, ett_amr_toc);
		
		first_time = TRUE;
		while ((( octet& 0x80 ) == 0x80)||(first_time == TRUE)){
			first_time = FALSE;
			octet = tvb_get_guint8(tvb,offset);	
			proto_tree_add_item(amr_tree, hf_amr_toc_f, tvb, offset, 1, FALSE);
			proto_tree_add_item(amr_tree, hf_amr_toc_ft, tvb, offset, 1, FALSE);
			proto_tree_add_item(amr_tree, hf_amr_toc_q, tvb, offset, 1, FALSE);
			offset++;
		}

	}/* if tree */

}


/* Register the protocol with Wireshark */
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_amr(void)
{
	dissector_handle_t amr_handle;
	static int amr_prefs_initialized = FALSE;
	
	amr_handle = create_dissector_handle(dissect_amr, proto_amr);

	if (!amr_prefs_initialized) {
		amr_prefs_initialized = TRUE;
	  }
	else {
			if ( dynamic_payload_type > 95 )
				dissector_delete("rtp.pt", dynamic_payload_type, amr_handle);
	}
	dynamic_payload_type = temp_dynamic_payload_type;

	if ( dynamic_payload_type > 95 ){
		dissector_add("rtp.pt", dynamic_payload_type, amr_handle);
	}
	dissector_add_string("rtp_dyn_payload_type","AMR", amr_handle);

}

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_amr(void)
{                 

	module_t *amr_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_amr_cmr,
			{ "CMR",           "amr.cmr",
			FT_UINT8, BASE_DEC, VALS(amr_codec_mode_request_vals), 0xf0,          
			"codec mode request", HFILL }
		},
		{ &hf_amr_reserved,
			{ "Reserved",           "amr.reserved",
			FT_UINT8, BASE_DEC, NULL, 0x0f,          
			"Reserved bits", HFILL }
		},
		{ &hf_amr_toc_f,
			{ "F bit",           "amr.toc.f",
			FT_BOOLEAN, 8, TFS(&toc_f_bit_vals), 0x80,          
			"F bit", HFILL }
		},
		{ &hf_amr_toc_ft,
			{ "FT bits",           "amr.toc.ft",
			FT_UINT8, BASE_DEC, VALS(amr_codec_mode_request_vals), 0x78,          
			"Frame type index", HFILL }
		},
		{ &hf_amr_toc_q,
			{ "Q bit",           "amr.toc.q",
			FT_BOOLEAN, 8, TFS(&toc_q_bit_vals), 0x04,          
			"Frame quality indicator bit", HFILL }
		},
		{ &hf_amr_if1_ft,
			{ "Frame Type",           "amr.if1.ft",
			FT_UINT8, BASE_DEC, VALS(amr_codec_mode_request_vals), 0xf0,          
			"Frame Type", HFILL }
		},
		{ &hf_amr_if1_mode_req,
			{ "Mode Type request",           "amr.if1.modereq",
			FT_UINT8, BASE_DEC, VALS(amr_codec_mode_vals), 0xe0,          
			"Mode Type request", HFILL }
		},
		{ &hf_amr_if1_sti,
			{ "SID Type Indicator",           "amr.if1.sti",
			FT_BOOLEAN, 8, TFS(&amr_sti_vals), 0x10,          
			"SID Type Indicator", HFILL }
		},
		{ &hf_amr_if1_sti_mode_ind,
			{ "Mode Type indication",           "amr.if1.modereq",
			FT_UINT8, BASE_DEC, VALS(amr_codec_mode_vals), 0x0e,          
			"Mode Type indication", HFILL }
		},
		{ &hf_amr_if1_mode_ind,
			{ "Mode Type indication",           "amr.if1.modereq",
			FT_UINT8, BASE_DEC, VALS(amr_codec_mode_vals), 0x07,          
			"Mode Type indication", HFILL }
		},
		{ &hf_amr_if2_ft,
			{ "Frame Type",           "amr.if2.ft",
			FT_UINT8, BASE_DEC, VALS(amr_codec_mode_request_vals), 0x0f,          
			"Frame Type", HFILL }
		},
		{ &hf_amr_sti,
			{ "SID Type Indicator",           "amr.sti",
			FT_BOOLEAN, 8, TFS(&amr_sti_vals), 0x80,          
			"SID Type Indicator", HFILL }
		},
		{ &hf_amr_if1_fqi,
			{ "FQI",           "amr.fqi",
			FT_BOOLEAN, 8, TFS(&toc_q_bit_vals), 0x08,          
			"Frame quality indicator bit", HFILL }
		},
		{ &hf_amr_be_reserved,
			{ "Reserved",           "amr.be.reserved",
			FT_UINT8, BASE_DEC, NULL, 0x08,          
			"Reserved", HFILL }
		},
		{ &hf_amr_be_ft,
			{ "Frame Type",           "amr.be.ft",
			FT_UINT16, BASE_DEC, VALS(amr_codec_mode_request_vals), 0x0780,          
			"Frame Type", HFILL }
		},
		{ &hf_amr_be_reserved2,
			{ "Reserved",           "amr.be.reserved2",
			FT_UINT16, BASE_DEC, NULL, 0x0040,          
			"Reserved", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_amr,
		&ett_amr_toc,
	};
    static enum_val_t encoding_types[] = {
	{"RFC 3267 Byte aligned", "RFC 3267 octet aligned", 0},
	{"RFC 3267 Bandwidth-efficient", "RFC 3267 BW-efficient", 1}, 
	{"AMR IF1", "AMR IF1", 2},
	{"AMR IF2", "AMR IF2", 3},
	{NULL, NULL, -1}
    };

/* Register the protocol name and description */
	proto_amr = proto_register_protocol("Adaptive Multi-Rate","AMR", "amr");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_amr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	/* Register a configuration option for port */

	
	amr_module = prefs_register_protocol(proto_amr, proto_reg_handoff_amr);

	prefs_register_uint_preference(amr_module, "dynamic.payload.type",
								   "AMR dynamic payload type",
								   "The dynamic payload type which will be interpreted as AMR",
								   10,
								   &temp_dynamic_payload_type);

    prefs_register_enum_preference(amr_module, "encoding.version",
      "Type of AMR encoding of the payload",
      "Type of AMR encoding of the payload",
      &amr_encoding_type, encoding_types, FALSE);
	
	register_dissector("amr", dissect_amr, proto_amr);
	register_dissector("amr_if1", dissect_amr_if1, proto_amr);
	register_dissector("amr_if2", dissect_amr_if2, proto_amr);
}


