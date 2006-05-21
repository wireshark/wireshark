/* packet-rlm.c
 * Routines for RLM dissection
 * Copyright 2004, Duncan Sargeant <dunc-ethereal@rcpt.to>
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
 
/*
 * RLM is a proprietary Cisco protocol used for centralling managing
 * many redundant NASes.  I don't know much about the format, but you
 * can read about the feature here:
 * 
 * http://www.cisco.com/univercd/cc/td/doc/product/software/ios120/120newft/120t/120t3/rlm_123.htm
 *
 * RLM runs on a UDP port (default 3000) between the MGC and the NAS.
 * On port N+1 (default 3001), a Q.931/LAPD/UDP connection is maintained.
 * Both sides use the same local port number for the connection, so source
 * and dest port are always the same.
 * 
 * In large networks, the links are typically split onto higher ports,
 * so anything up to 3015 (or higher) could either be RLM or Q.931 traffic,
 * although always the RLM has the one lower port number for that RLM group.
 *
 * Multiple RLM groups are possible on a single NAS.
 * 
 * I haven't been able to find the protocol documented, so I've
 * guessed some of the fields based on the output of debug commands on
 * cisco NASes.
 * 
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>

/* Initialize the protocol and registered fields */
static int proto_rlm = -1;

static int hf_rlm_version = -1;
static int hf_rlm_type = -1;
static int hf_rlm_unknown = -1;
static int hf_rlm_tid = -1;
static int hf_rlm_unknown2 = -1;

/* Initialize the subtree pointers */
static gint ett_rlm = -1;


/* RLM definitions - missing some! */

#define RLM_START_REQUEST	1
#define RLM_START_ACK		2
/* #define ???	3 */
/* #define ???	4 */
#define RLM_ECHO_REQUEST	5
#define RLM_ECHO_REPLY		6
/* #define ???	?? */


/* 
  Maybe this isn't the best place for it, but RLM goes hand in hand
  with Q.931 traffic on a higher port.
*/

static gboolean
dissect_udp_lapd(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree) {

	if (pinfo->srcport < 3001 || pinfo->srcport > 3015
		|| pinfo->destport < 3001 || pinfo->destport > 3015
		|| pinfo->destport != pinfo->srcport)
			return FALSE;

	call_dissector(find_dissector("lapd"), tvb, pinfo, tree);
	return TRUE;
}


/* Code to actually dissect the packets */
static gboolean
dissect_rlm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *rlm_tree;
	guint8 rlm_type, version;
	const char *type_str = NULL;

	if (pinfo->srcport < 3000 || pinfo->srcport > 3015
			|| pinfo->destport < 3000 || pinfo->destport > 3015
			|| pinfo->destport != pinfo->srcport)
		return FALSE;

	version = tvb_get_guint8(tvb, 0);
	rlm_type = tvb_get_guint8(tvb, 1);

	/* we only know about version 2, and I've only seen 8 byte packets */
	if (tvb_length(tvb) != 8 || version != 2) {
		return FALSE;
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLM");

	switch (rlm_type) {
		case RLM_START_REQUEST:
			type_str = "Start request";
			break;;

		case RLM_START_ACK:
			type_str = "Start acknowledgement";
			break;;

		case RLM_ECHO_REQUEST:
			type_str = "Echo request";
			break;;

		case RLM_ECHO_REPLY:
			type_str = "Echo reply";
			break;;

		default:
			type_str = "Unknown type";
			break;;
	}

	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_set_str(pinfo->cinfo, COL_INFO, type_str);

	if (tree) {
		/* proto_tree_add_protocol_format(tree, proto_rlm, tvb, 0,
			16, "Cisco Session Management"); */
		ti = proto_tree_add_item(tree, proto_rlm, tvb, 0, 8, FALSE);
		rlm_tree = proto_item_add_subtree(ti, ett_rlm);
		ti = proto_tree_add_item(rlm_tree, hf_rlm_version, tvb, 0, 1, FALSE);
		proto_tree_add_uint_format(rlm_tree, hf_rlm_type, tvb, 1, 1, rlm_type, "Type: %u (%s)", rlm_type, type_str);
		ti = proto_tree_add_item(rlm_tree, hf_rlm_unknown, tvb, 2, 2, FALSE);
		ti = proto_tree_add_item(rlm_tree, hf_rlm_tid, tvb, 4, 2, FALSE);
		ti = proto_tree_add_item(rlm_tree, hf_rlm_unknown2, tvb, 6, 2, FALSE);
	}

	return TRUE;
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_reg_handoff_rlm(void)
{
	heur_dissector_add("udp", dissect_rlm, proto_rlm);
	heur_dissector_add("udp", dissect_udp_lapd, proto_get_id_by_filter_name("lapd"));
}

void
proto_register_rlm(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_rlm_version,
			{ "Version",           "rlm.version",
			FT_UINT8, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_rlm_type,
			{ "Type",           "rlm.type",
			FT_UINT8, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_rlm_unknown,
			{ "Unknown",           "rlm.unknown",
			FT_UINT16, BASE_HEX, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_rlm_tid,
			{ "Transaction ID",           "rlm.tid",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_rlm_unknown2,
			{ "Unknown",           "rlm.unknown2",
			FT_UINT16, BASE_HEX, NULL, 0x0,          
			"", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_rlm,
	};

/* Register the protocol name and description */
	proto_rlm = proto_register_protocol("Redundant Link Management Protocol",
	    "RLM", "rlm");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_rlm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
