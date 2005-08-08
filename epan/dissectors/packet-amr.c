/* packet-amr.c
 * Routines for AMR dissection
 * Copyright 2005, Anders Broman <anders.broman[at]ericsson.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * References:
 * RFC 3267 
 * http://www.ietf.org/rfc/rfc3267.txt?number=3267
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include "prefs.h"


/* Initialize the protocol and registered fields */
static int proto_amr		= -1;
static int hf_amr_cmr		= -1;
static int hf_amr_reserved	= -1;
static int hf_amr_toc_f		= -1;
static int hf_amr_toc_ft	= -1;
static int hf_amr_toc_q		= -1;

/* Initialize the subtree pointers */
static int ett_amr = -1;
static int ett_amr_toc = -1;

/* The dynamic payload type which will be dissected as AMR */

static guint dynamic_payload_type = 0;
static guint temp_dynamic_payload_type = 0;

/* Currently only octet aligned works */
static gboolean octet_aligned = TRUE;

static const value_string amr_codec_mode_request_vals[] = {
	{0,		"AMR 4,75 kbit/s"}, 
	{1,		"AMR 5,15 kbit/s"},
	{2,		"AMR 5,90 kbit/s"},
	{3,		"AMR 6,70 kbit/s (PDC-EFR)"},
	{4,		"AMR 7,40 kbit/s (TDMA-EFR)"},
	{5,		"AMR 7,95 kbit/s"},
	{6,		"AMR 10,2 kbit/s"},
	{7,		"AMR 12,2 kbit/s (GSM-EFR)"},
	{8,		"AMR SID"},
	{9,		"GSM-EFR SID"},
	{10,	"TDMA-EFR SID"},
	{11,	"PDC-EFR SID"},
	/*
	{12-14	-	-	For future use
	*/
	{15,	"No Data (No transmission/No reception)"}, 
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

/* Code to actually dissect the packets */
static void
dissect_amr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	int toc_offset = 0;
	guint octet;

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti,*toc_item;
	proto_tree *amr_tree, *toc_tree;

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "AMR");
	if (tree) {
		ti = proto_tree_add_item(tree, proto_amr, tvb, 0, -1, FALSE);

		amr_tree = proto_item_add_subtree(ti, ett_amr);

/* add an item to the subtree, see section 1.6 for more information */
		proto_tree_add_item(amr_tree, hf_amr_cmr, tvb, offset, 1, FALSE);
		if ( !octet_aligned )
			return; /* only handle octet aligned for now */

		proto_tree_add_item(amr_tree, hf_amr_reserved, tvb, offset, 1, FALSE);
		offset++;
		toc_offset = offset;
		/* If interleaced ILL and ILP follows here */

		/* Payload Table of Contents 
		 * A ToC entry takes the following format in octet-aligned mode:
		 *
		 *  0 1 2 3 4 5 6 7
		 * +-+-+-+-+-+-+-+-+
		 * |F|  FT   |Q|P|P|
		 * +-+-+-+-+-+-+-+-+
		 */
		octet = tvb_get_guint8(tvb,offset);
		toc_item = proto_tree_add_text(amr_tree, tvb, offset, -1, "Payload Table of Contents");
		toc_tree = proto_item_add_subtree(toc_item, ett_amr_toc);

		while ( ( octet& 0x80 ) == 0x80 ){
			octet = tvb_get_guint8(tvb,offset);	
			proto_tree_add_item(amr_tree, hf_amr_toc_f, tvb, offset, 1, FALSE);
			proto_tree_add_item(amr_tree, hf_amr_toc_ft, tvb, offset, 1, FALSE);
			proto_tree_add_item(amr_tree, hf_amr_toc_q, tvb, offset, 1, FALSE);
			offset++;
		}


/* Continue adding tree items to process the packet here */


	}/* if tree */

/* If this protocol has a sub-dissector call it here, see section 1.8 */
}


/* Register the protocol with Ethereal */
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
	dissector_add_string("rtp_dyn_payload_type","amr", amr_handle);

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
			"FT bits", HFILL }
		},
		{ &hf_amr_toc_q,
			{ "Q bit",           "amr.toc.q",
			FT_BOOLEAN, 8, TFS(&toc_q_bit_vals), 0x04,          
			"Frame quality indicator bit", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_amr,
		&ett_amr_toc,
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
								   "The dynamic payload type which will be interpretyed as AMR",
								   10,
								   &temp_dynamic_payload_type);

}


