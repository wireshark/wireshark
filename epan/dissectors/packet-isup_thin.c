/* packet-isup_thin.c
 * Routines for ISUP Thin dissection
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/conversation.h>

#include <epan/packet.h>
#include "prefs.h"

static int ISUP_thinTCPPort = 0;
static int tcp_port = 0;

/* Initialize the protocol and registered fields */
static int proto_isup_thin		= -1;

/* Initialize the subtree pointers */
static int ett_isup_thin					= -1;

static int hf_isup_thin_count_type		= -1;
static int hf_isup_thin_count			= -1;
static int hf_isup_thin_message_class	= -1;
static int hf_isup_thin_version			= -1;
static int hf_isup_thin_message_type	= -1;
static int hf_isup_thin_serv_ind		= -1;
static int hf_isup_thin_subservind		= -1;
static int hf_isup_thin_priority		= -1;
static int hf_isup_thin_sls				= -1;
static int hf_isup_thin_opc				= -1;
static int hf_isup_thin_dpc				= -1;
static int hf_isup_thin_oam_message_name_code = -1;
static int hf_isup_thin_mtp_primitive_message_name_code = -1;
static int hf_isup_thin_isup_length		= -1;



static const value_string isup_thin_count_type_vals[] = {
	{0,		"64 octet count (Not used by t-ISUP)"}, 
	{1,		"4 octet count"},
	{ 0,	NULL }
};

static const value_string isup_thin_message_type_vals[] = {
	{0,		"OAM Message"}, 
	{1,		"MTP Primitive"},
	{2,		"Encapsulated ISUP Message format according to the used ISUP protocol"},
	{ 0,	NULL }
};

static const value_string isup_thin_oam_message_name_code_vals[] = {
	{1,		"Heartbeat"},
	{ 0,	NULL }
};
static const value_string isup_thin_mtp_message_name_code_vals[] = {
	{1,		"MTP_Pause"},
	{2,		"MTP_Resume"},
	{3,		"MTP_UP_Unavailable"},
	{4,		"MTP_Cong"},
	{6,		"MTP_Rest"},
	{7,		"MTP_Rest_End"},
	{ 0,	NULL }
};

static dissector_handle_t isup_thin_handle;
static dissector_handle_t isup_handle;


static int dissect_isup_thin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);





/* Code to actually dissect the packets */
static int
dissect_isup_thin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *isup_thin_tree;
	tvbuff_t *next_tvb;
	gint offset = 0;
	gint octet;
	gint message_type;
	gint16 isup_message_length;


	/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "isup_thin");

	/* Find the end line to be able to process the headers
	 * Note that in case of [content-stuff] headers and [content-stuff] is separated by CRLF
	 */



	if (tree) {
		ti = proto_tree_add_item(tree, proto_isup_thin, tvb, 0, -1, FALSE);
		isup_thin_tree = proto_item_add_subtree(ti, ett_isup_thin);

		octet = tvb_get_guint8(tvb,offset);
		proto_tree_add_item(isup_thin_tree, hf_isup_thin_count_type, tvb, offset, 1, FALSE);
		proto_tree_add_item(isup_thin_tree, hf_isup_thin_count, tvb, offset, 2, FALSE);
		offset = offset + 2;
		proto_tree_add_item(isup_thin_tree, hf_isup_thin_message_class, tvb, offset, 1, FALSE);
		proto_tree_add_item(isup_thin_tree, hf_isup_thin_version, tvb, offset, 2, FALSE);
		offset++;
		message_type = tvb_get_guint8(tvb,offset) & 0x7f ;
		proto_tree_add_item(isup_thin_tree, hf_isup_thin_message_type, tvb, offset, 1, FALSE);
		offset++;
		proto_tree_add_item(isup_thin_tree, hf_isup_thin_serv_ind, tvb, offset, 1, FALSE);
		/* SubServInd	*/
		proto_tree_add_item(isup_thin_tree, hf_isup_thin_subservind, tvb, offset, 1, FALSE);
		/* Priority		*/
		proto_tree_add_item(isup_thin_tree, hf_isup_thin_priority, tvb, offset, 1, FALSE);
		offset++;
		proto_tree_add_item(isup_thin_tree, hf_isup_thin_sls, tvb, offset, 1, FALSE);
		offset++;
		proto_tree_add_item(isup_thin_tree, hf_isup_thin_opc, tvb, offset, 3, FALSE);
		offset = offset +3;
		proto_tree_add_item(isup_thin_tree, hf_isup_thin_dpc, tvb, offset, 3, FALSE);
		offset = offset +3;

		/* 12 Bytes off measage header done */
		switch (message_type) {
			case 0:
				/* OAM message */
				proto_tree_add_item(isup_thin_tree, hf_isup_thin_oam_message_name_code, tvb, offset, 1, FALSE);
				offset++;
				break;
			case 1:
				/* MTP Primitive */
				proto_tree_add_item(isup_thin_tree, hf_isup_thin_mtp_primitive_message_name_code, tvb, offset, 1, FALSE);
				offset++;
				break;
			case 2:
				/*Encapsulated ISUP Message format according to the used ISUP protocol */
				isup_message_length = tvb_get_ntohs(tvb,offset);
				proto_tree_add_item(isup_thin_tree, hf_isup_thin_isup_length, tvb, offset, 2, FALSE);
				offset = offset +2;
				next_tvb = tvb_new_subset(tvb, offset, isup_message_length, isup_message_length);
				call_dissector(isup_handle, next_tvb, pinfo, tree);
				break;
			default:
				/* Unknown */
				return 0;
		}



	}/* if tree */
	return tvb_length(tvb); 

/* If this protocol has a sub-dissector call it here, see section 1.8 */
}


/* Register the protocol with Wireshark */
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_isup_thin(void)
{
	static int Initialized=FALSE;
	
	if (!Initialized) {
		isup_thin_handle = new_create_dissector_handle(dissect_isup_thin, proto_isup_thin);
		Initialized=TRUE;
	}else{
		dissector_delete("tcp.port", tcp_port, isup_thin_handle);
	}

	tcp_port = ISUP_thinTCPPort;

	dissector_add("tcp.port", tcp_port, isup_thin_handle);
	isup_handle = find_dissector("isup");
}

void
proto_register_isup_thin(void)
{                 

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_isup_thin,
	};

        /* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_isup_thin_count_type,
			{ "Count Type", 		"isup_thin.count.type",
			FT_UINT8, BASE_DEC,VALS(isup_thin_count_type_vals), 0x80,
			"Count Type", HFILL }
		},
		{ &hf_isup_thin_count,
			{ "Message length (counted according to bit 0) including the Message Header","isup_thin.count",
			FT_UINT16, BASE_DEC,NULL, 0x7fff,
			"Message length", HFILL }
		},
		{ &hf_isup_thin_message_class,
			{ "Message Class","isup_thin.message.class",
			FT_UINT8, BASE_DEC,NULL, 0xfc,
			"Message Class", HFILL }
		},
		{ &hf_isup_thin_version,
			{ "Version","isup_thin.count.version",
			FT_UINT16, BASE_DEC,NULL, 0x0380,
			"Version", HFILL }
		},
		{ &hf_isup_thin_message_type,
			{ "Message Type", 		"isup_thin.messaget.type",
			FT_UINT8, BASE_DEC,VALS(isup_thin_message_type_vals), 0x7f,
			"Message Type", HFILL }
		},
		{ &hf_isup_thin_serv_ind,
			{ "Service Indicator","isup_thin.servind",
			FT_UINT8, BASE_DEC,NULL, 0xf0,
			"Service Indicator", HFILL }
		},
		{ &hf_isup_thin_subservind,
			{ "Sub Service Field (Network Indicator)","isup_thin.subservind",
			FT_UINT8, BASE_DEC,NULL, 0x0c,
			"Sub Service Field (Network Indicator)", HFILL }
		},
		{ &hf_isup_thin_priority,
			{ "Priority","isup_thin.priority",
			FT_UINT8, BASE_DEC,NULL, 0x03,
			"Priority", HFILL }
		},
		{ &hf_isup_thin_sls,
			{ "Signalling Link Selection","isup_thin.sls",
			FT_UINT8, BASE_DEC,NULL, 0x0,
			"Signalling Link Selection", HFILL }
		},
		{ &hf_isup_thin_opc,
			{ "Originating Point Code","isup_thin.opc",
			FT_UINT32, BASE_DEC,NULL, 0x0,
			"Originating Point Code", HFILL }
		},
		{ &hf_isup_thin_dpc,
			{ "Destination Point Code","isup_thin.dpc",
			FT_UINT32, BASE_DEC,NULL, 0x0,
			"Destination Point Code", HFILL }
		},
		{ &hf_isup_thin_oam_message_name_code,
			{ "Message Name Code","isup_thin.oam.message.name",
			FT_UINT8, BASE_DEC,VALS(isup_thin_oam_message_name_code_vals), 0x0,
			"Message Name", HFILL }
		},
		{ &hf_isup_thin_mtp_primitive_message_name_code,
			{ "Message Name Code","isup_thin.mtp.message.name",
			FT_UINT8, BASE_DEC,VALS(isup_thin_mtp_message_name_code_vals), 0x0,
			"Message Name", HFILL }
		},
		{ &hf_isup_thin_isup_length,
			{ "ISUP message length","isup_thin.isup.message.length",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"ISUP message length", HFILL }
		},
	};

	module_t *isup_thin_module;
/* Register the protocol name and description */
	proto_isup_thin = proto_register_protocol("ISUP Thin Protocol","isup_thin", "isup_thin");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_isup_thin, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));


	isup_thin_module = prefs_register_protocol(proto_isup_thin, NULL);

	prefs_register_uint_preference(isup_thin_module, "tcp.port",
								   "ISUP Thin TCP Port",
								   "Set TCP port for ISUP Thin messages",
								   10,
								   &ISUP_thinTCPPort);
		
  /*
   * Register the dissector by name, so other dissectors can
   * grab it by name rather than just referring to it directly.
   */
  new_register_dissector("isup_thin", dissect_isup_thin, proto_isup_thin);

}


