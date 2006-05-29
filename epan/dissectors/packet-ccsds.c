/* packet-ccsds.c
 * Routines for CCSDS dissection
 * Copyright 2000, Scott Hovis scott.hovis@ums.msfc.nasa.gov
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

/*
 * See
 *
 *	http://stationpayloads.jsc.nasa.gov/J-reference/documents/ssp57002B.pdf
 */

/* Initialize the protocol and registered fields */
static int proto_ccsds = -1;
static int hf_ccsds_apid = -1;
static int hf_ccsds_version = -1;
static int hf_ccsds_secheader = -1;
static int hf_ccsds_type = -1;
static int hf_ccsds_seqnum = -1;
static int hf_ccsds_seqflag = -1;
static int hf_ccsds_length = -1;
static int hf_ccsds_time = -1;
static int hf_ccsds_timeid = -1;
static int hf_ccsds_checkword = -1;
static int hf_ccsds_zoe = -1;
static int hf_ccsds_packtype = -1;
static int hf_ccsds_vid = -1;
static int hf_ccsds_dcc = -1;

/* Initialize the subtree pointers */
static gint ett_ccsds = -1;
static gint ett_header = -1;
static gint ett_header2 = -1;

/*
 * Bits in the first 16-bit header word
 */
#define HDR_VERSION	0xe000
#define HDR_TYPE	0x1000
#define HDR_SECHDR	0x0800
#define HDR_APID	0x07ff

/* Code to actually dissect the packets */
static void
dissect_ccsds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_item *ti;
	proto_tree *ccsds_tree;
	proto_item *header;
	proto_tree *header_tree;
	guint16 first_word;
	proto_item *header2;
	proto_tree *header2_tree;
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CCSDS");
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_set_str(pinfo->cinfo, COL_INFO, "CCSDS Packet");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ccsds, tvb, 0, -1, FALSE);
		ccsds_tree = proto_item_add_subtree(ti, ett_ccsds);

		header=proto_tree_add_text(ccsds_tree, tvb, 0, -1,
		    "Primary CCSDS Header");
		header_tree=proto_item_add_subtree(header, ett_header);
		
		first_word=tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(header_tree, hf_ccsds_version, tvb, offset, 2, first_word);
		proto_tree_add_uint(header_tree, hf_ccsds_type, tvb, offset, 2, first_word);
		proto_tree_add_boolean(header_tree, hf_ccsds_secheader, tvb, offset, 2, first_word);
		proto_tree_add_uint(header_tree, hf_ccsds_apid, tvb, offset, 2, first_word);
		offset += 2;

		proto_tree_add_item(header_tree, hf_ccsds_seqflag, tvb, offset, 2, FALSE);
		proto_tree_add_item(header_tree, hf_ccsds_seqnum, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(header_tree, hf_ccsds_length, tvb, offset, 2, FALSE);
		offset += 2;
		proto_item_set_end(header, tvb, offset);

		if(first_word&HDR_SECHDR)
		{
			header2=proto_tree_add_text(ccsds_tree, tvb, offset, -1,
			    "Secondary CCSDS Header");
			header2_tree=proto_item_add_subtree(header2, ett_header2);

			proto_tree_add_item(header2_tree, hf_ccsds_time, tvb, offset, 5, FALSE);
			offset += 5;

			proto_tree_add_item(header2_tree, hf_ccsds_timeid, tvb, offset, 1, FALSE);
			proto_tree_add_item(header2_tree, hf_ccsds_checkword, tvb, offset, 1, FALSE);
			proto_tree_add_item(header2_tree, hf_ccsds_zoe, tvb, offset, 1, FALSE);
			proto_tree_add_item(header2_tree, hf_ccsds_packtype, tvb, offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(header2_tree, hf_ccsds_vid, tvb, offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(header2_tree, hf_ccsds_dcc, tvb, offset, 2, FALSE);
			offset += 2;
			proto_item_set_end(header2, tvb, offset);
		}

		proto_tree_add_text(ccsds_tree, tvb, offset, -1,
		    "Data");
	}
}


/* Register the protocol with Wireshark */
/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/
void
proto_register_ccsds(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_ccsds_version,
			{ "version",           "ccsds.version",
			FT_UINT16, BASE_DEC, NULL, HDR_VERSION,
			"version", HFILL }
		},
		{ &hf_ccsds_type,
			{ "type",           "ccsds.type",
			FT_UINT16, BASE_DEC, NULL, HDR_TYPE,          
			"type", HFILL }
		},
		{ &hf_ccsds_secheader,
			{ "secondary header",           "ccsds.secheader",
			FT_BOOLEAN, 16, NULL, HDR_SECHDR,
			"secondary header present", HFILL }
		},
		{ &hf_ccsds_apid,
			{ "APID",           "ccsds.apid",
			FT_UINT16, BASE_DEC, NULL, HDR_APID,
			"Represents APID", HFILL }
		},
		{ &hf_ccsds_seqflag,
			{ "sequence flags",           "ccsds.seqflag",
			FT_UINT16, BASE_DEC, NULL, 0xc000,
			"sequence flags", HFILL }
		},
		{ &hf_ccsds_seqnum,
			{ "sequence number",           "ccsds.seqnum",
			FT_UINT16, BASE_DEC, NULL, 0x3fff,          
			"sequence number", HFILL }
		},
		{ &hf_ccsds_length,
			{ "packet length",           "ccsds.length",
			FT_UINT16, BASE_DEC, NULL, 0xffff,          
			"packet length", HFILL }
		},
		{ &hf_ccsds_time,
			{ "time",           "ccsds.time",
			FT_BYTES, BASE_HEX, NULL, 0x0,          
			"time", HFILL }
		},
		{ &hf_ccsds_timeid,
			{ "time identifier",           "ccsds.timeid",
			FT_UINT8, BASE_DEC, NULL, 0xC0,
			"time identifier", HFILL }
		},
		{ &hf_ccsds_checkword,
			{ "checkword indicator",           "ccsds.checkword",
			FT_UINT8, BASE_DEC, NULL, 0x20,          
			"checkword indicator", HFILL }
		},
		{ &hf_ccsds_zoe,
			{ "ZOE TLM",           "ccsds.zoe",
			FT_UINT8, BASE_DEC, NULL, 0x10,          
			"CONTAINS S-BAND ZOE PACKETS", HFILL }
		},
		{ &hf_ccsds_packtype,
			{ "packet type",           "ccsds.packtype",
			FT_UINT8, BASE_DEC, NULL, 0x0f,          
			"Packet Type - Unused in Ku-Band", HFILL }
		},
		{ &hf_ccsds_vid,
			{ "version identifier",           "ccsds.vid",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"version identifier", HFILL }
		},
		{ &hf_ccsds_dcc,
			{ "Data Cycle Counter",           "ccsds.dcc",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Data Cycle Counter", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ccsds,
		&ett_header,
		&ett_header2,
	};

/* Register the protocol name and description */
	proto_ccsds = proto_register_protocol("CCSDS", "CCSDS", "ccsds");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_ccsds, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_ccsds(void)
{
	dissector_handle_t ccsds_handle;

	ccsds_handle = create_dissector_handle(dissect_ccsds,
	    proto_ccsds);
	dissector_add_handle("udp.port", ccsds_handle);
}
