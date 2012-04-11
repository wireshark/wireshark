/* packet-bfcp.c
 * Routines for Binary Floor Control Protocol(BFCP) dissection
 * Copyright 2012, Nitinkumar Yemul <nitinkumaryemul@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * BFCP Message structure is defined in RFC 4582.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

/* Initialize protocol and registered fields */
static int proto_bfcp = -1;
static gboolean  bfcp_enable_heuristic_dissection = FALSE; 
static dissector_handle_t bfcp_handle;

static int hf_bfcp_primitive = -1;
static int hf_bfcp_payload_length = -1;
static int hf_bfcp_conference_id = -1;
static int hf_bfcp_transaction_id = -1;
static int hf_bfcp_user_id = -1;
static int hf_bfcp_payload = -1;

/* Initialize subtree pointers */
static gint ett_bfcp = -1;

/* Initialize BFCP primitives */
static const value_string map_bfcp_primitive[] = {
	{ 0,  "<Invalid Primitive>"},
	{ 1,  "FloorRequest"},
	{ 2,  "FloorRelease"},
	{ 3,  "FloorRequestQuery"},
	{ 4,  "FloorRequestStatus"},
	{ 5,  "UserQuery"},
	{ 6,  "UserStatus"},
	{ 7,  "FloorQuery"},
	{ 8,  "FloorStatus"},
	{ 9,  "ChairAction"},
	{ 10, "ChairActionAck"},
	{ 11, "Hello"},
	{ 12, "HelloAck"},
	{ 13, "Error"},
	{ 0,  NULL},
};

/*Define offset for fields in BFCP packet */
#define BFCP_OFFSET_PRIMITIVE 1
#define BFCP_OFFSET_PAYLOAD_LENGTH 2
#define BFCP_OFFSET_CONFERENCE_ID 4
#define BFCP_OFFSET_TRANSACTION_ID 8
#define BFCP_OFFSET_USER_ID 10
#define BFCP_OFFSET_PAYLOAD 12

/* Code to actually dissect BFCP packets */
static gboolean dissect_bfcp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
	guint8 first_byte = 0;
	guint8 primitive = 0;
	const gchar *str = NULL;
	guint idx = 0;
	gint bfcp_payload_length = 0;
	
	/* Size of smallest BFCP packet 12-octets */
	if (tvb_length(tvb) < 12)
		return FALSE;

	/* Check version and reserved bits in first byte */
	first_byte = tvb_get_guint8 (tvb, 0);

	/* If first_byte of bfcp_packet is not 0x20 then 
 	 * this can not be a BFCP. Return FALSE give another 
 	 * dissector a chance to dissect it.
 	 */
	if (first_byte != 0x20)
		return FALSE;
	
	primitive = tvb_get_guint8 (tvb, 1);

	if (primitive < 1 || primitive > 13)
		return FALSE;

	str = match_strval_idx(primitive, map_bfcp_primitive, &idx);
	if(NULL == str)
		return FALSE;
	
	/* Make entries in Protocol column and Info column on summary display*/
	col_set_str (pinfo->cinfo, COL_PROTOCOL, "BFCP");
	col_add_str (pinfo->cinfo, COL_INFO, str);
	
	if (tree) {

		proto_item *ti = NULL;
		proto_tree *bfcp_tree = NULL;

		ti = proto_tree_add_item(tree, proto_bfcp, tvb, 0, -1, ENC_NA);
		bfcp_tree = proto_item_add_subtree(ti, ett_bfcp);
		
		/* Add items to BFCP tree */
		proto_tree_add_item(bfcp_tree, hf_bfcp_primitive, tvb, 
			BFCP_OFFSET_PRIMITIVE, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(bfcp_tree, hf_bfcp_payload_length, tvb, 
			BFCP_OFFSET_PAYLOAD_LENGTH, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(bfcp_tree, hf_bfcp_conference_id, tvb, 
			BFCP_OFFSET_CONFERENCE_ID, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(bfcp_tree, hf_bfcp_transaction_id, tvb, 
			BFCP_OFFSET_TRANSACTION_ID, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(bfcp_tree, hf_bfcp_user_id, tvb, 
			BFCP_OFFSET_USER_ID, 2, ENC_BIG_ENDIAN);

		bfcp_payload_length = tvb_get_ntohs(tvb, 
					BFCP_OFFSET_PAYLOAD_LENGTH); 

		if (tvb_length_remaining(tvb, BFCP_OFFSET_PAYLOAD) > 0)
        		proto_tree_add_item(bfcp_tree, hf_bfcp_payload, tvb, 
				BFCP_OFFSET_PAYLOAD, bfcp_payload_length, 
				ENC_NA);
	}
	return TRUE;	
}

void proto_reg_handoff_bfcp(void)
{
	static gboolean prefs_initialized = FALSE;

  	/* "Decode As" is always available;
   	 *  Heuristic dissection in disabled by default since 
	 *  the heuristic is quite weak.
         */
  	if (!prefs_initialized) {
		heur_dissector_add ("tcp", dissect_bfcp_tcp, proto_bfcp);
		bfcp_handle = new_create_dissector_handle(dissect_bfcp_tcp, 
					proto_bfcp);
    		dissector_add_handle("tcp.port", bfcp_handle);

	    	prefs_initialized = TRUE;
	}

	heur_dissector_set_enabled("tcp", dissect_bfcp_tcp, proto_bfcp, 
				   bfcp_enable_heuristic_dissection);
}

void proto_register_bfcp(void)
{
	module_t *bfcp_module;

	static hf_register_info hf[] = {
		{
			&hf_bfcp_primitive,
			{ "Primitive", "bfcp.primitive",
			  FT_UINT8, BASE_DEC,
			  VALS(map_bfcp_primitive), 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_payload_length,
			{ "Payload Length", "bfcp.payload_length",
			  FT_UINT16, BASE_DEC,
			  NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_conference_id,
			{ "Conference ID", "bfcp.conference_id",
			  FT_UINT32, BASE_DEC,
			  NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_transaction_id,
			{ "Transaction ID", "bfcp.transaction_id",
			  FT_UINT16, BASE_DEC,
			  NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_user_id,
			{ "User ID", "bfcp.user_id",
			  FT_UINT16, BASE_DEC,
			  NULL, 0x0,
			  NULL, HFILL }
		},
		{	
			&hf_bfcp_payload,
          		{ "Payload", "bfcp.payload", 
			  FT_BYTES, BASE_NONE, 
			  NULL, 0x0, NULL,
			  HFILL }
		}
	};	

 	static gint *ett[] = {
		&ett_bfcp
	};	

	/* Register protocol name and description */
	proto_bfcp = proto_register_protocol("Binary Floor Control Protocol", 
				"BFCP", "bfcp");

  	bfcp_module = prefs_register_protocol(proto_bfcp, 
				proto_reg_handoff_bfcp);
	
  	prefs_register_bool_preference(bfcp_module, "enable", 
		      "Enable BFCP heuristic dissection",
                      "Enable BFCP heuristic dissection (default is disabled)",
                      &bfcp_enable_heuristic_dissection);

	/* Register field and subtree array */
	proto_register_field_array(proto_bfcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
