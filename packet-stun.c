/* packet-stun.c
 * Routines for Simple Traversal of UDP Through NAT dissection
 * Copyright 2003, Shiang-Ming Huang <smhuang@pcs.csie.nctu.edu.tw>
 *
 * $Id: packet-stun.c,v 1.1 2003/08/17 00:54:24 guy Exp $
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
 * Please refer to RFC 3489 for protocol detail.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>

/* Initialize the protocol and registered fields */
static int proto_stun = -1;

static int hf_stun_type = -1;		/* STUN message header */
static int hf_stun_length = -1;
static int hf_stun_id = -1;
static int hf_stun_att = -1;

static int stun_att_type = -1;		/* STUN attribute fields */
static int stun_att_length = -1;
static int stun_att_value = -1;
static int stun_att_family = -1;
static int stun_att_ip = -1;
static int stun_att_port = -1;
static int stun_att_change_ip = -1;
static int stun_att_change_port = -1;
static int stun_att_unknown = -1;
static int stun_att_error_class = -1;
static int stun_att_error_number = -1;
static int stun_att_error_reason = -1;



/* Message Types */
#define BINDING_REQUEST			0x0001
#define BINDING_RESPONSE		0x0101
#define BINDING_ERROR_RESPONSE		0x0111
#define SHARED_SECRET_REQUEST		0x0002
#define SHARED_SECRET_RESPONSE		0x0102
#define SHARED_SECRET_ERROR_RESPONSE	0x1112

/* Attribute Types */
#define MAPPED_ADDRESS		0x0001
#define RESPONSE_ADDRESS	0x0002
#define CHANGE_REQUEST		0x0003
#define SOURCE_ADDRESS		0x0004
#define CHANGED_ADDRESS		0x0005
#define USERNAME		0x0006
#define PASSWORD		0x0007
#define MESSAGE_INTEGRITY	0x0008
#define ERROR_CODE		0x0009
#define UNKNOWN_ATTRIBUTES	0x000a
#define REFLECTED_FROM		0x000b



/* Initialize the subtree pointers */
static gint ett_stun = -1;
static gint ett_stun_att = -1;


#define UDP_PORT_STUN 	3478
#define TCP_PORT_STUN	3478


#define STUN_HDR_LEN	20	/* STUN message header length */
#define ATTR_HDR_LEN	4	/* STUN attribute header length */


static const true_false_string set_flag = {
	"SET",
	"NOT SET"
};

static const value_string messages[] = {
	{BINDING_REQUEST, "Binding Request"},
	{BINDING_RESPONSE, "Binding Response"},
	{BINDING_ERROR_RESPONSE, "Binding Error Response"},
	{SHARED_SECRET_REQUEST, "Shared Secret Request"},
	{SHARED_SECRET_RESPONSE, "Shared Secret Response"},
	{SHARED_SECRET_ERROR_RESPONSE, "Shared Secret Error Response"},
	{0x00, NULL}
};

static const value_string attributes[] = {
	{MAPPED_ADDRESS, "MAPPED-ADDRESS"},
	{RESPONSE_ADDRESS, "RESPONSE-ADDRESS"},
	{CHANGE_REQUEST, "CHANGE-REQUEST"},
	{SOURCE_ADDRESS, "SOURCE-ADDRESS"},
	{CHANGED_ADDRESS, "CHANGED-ADDRESS"},
	{USERNAME, "USERNAME"},
	{PASSWORD, "PASSWORD"},
	{MESSAGE_INTEGRITY, "MESSAGE-INTEGRITY"},
	{ERROR_CODE, "ERROR-CODE"},
	{REFLECTED_FROM, "REFLECTED-FROM"},
	{0x00, NULL}
};

static const value_string attributes_family[] = {
	{0x0001, "IPv4"},
	{0x00, NULL}
};

static void
dissect_stun(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	proto_item *ti;
	proto_item *ta;
	proto_tree *stun_tree;
	proto_tree *att_tree;

	
	guint16 message_type;

	
	guint16 att_type;
	guint16 att_length;
	guint16 offset;


	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "STUN");
    
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		
		message_type = tvb_get_ntohs(tvb, 0);

		    
		col_add_fstr(pinfo->cinfo, COL_INFO, "Message : %s",
				(message_type==BINDING_REQUEST)?"Binding Request":
				(message_type==BINDING_RESPONSE)?"Binding Response":
				(message_type==BINDING_ERROR_RESPONSE)?"Binding Error Response":
				(message_type==SHARED_SECRET_REQUEST)?"Shared Secret Request":
				(message_type==SHARED_SECRET_RESPONSE)?"Shared Secret Response":
				(message_type==SHARED_SECRET_ERROR_RESPONSE)?"Shared Secret Error Response":"UNKNOWN"
			);
			    
	}


	if (tree) {


		ti = proto_tree_add_item(tree, proto_stun, tvb, 0, -1, FALSE);
			    
		stun_tree = proto_item_add_subtree(ti, ett_stun);




		proto_tree_add_item(stun_tree, hf_stun_type, tvb, 0, 2, FALSE);
		proto_tree_add_item(stun_tree, hf_stun_length, tvb, 2, 2, FALSE);
		proto_tree_add_item(stun_tree, hf_stun_id, tvb, 4, 16, FALSE);

		ta = proto_tree_add_item(stun_tree, hf_stun_att, tvb, STUN_HDR_LEN, -1, FALSE);
		att_tree = proto_item_add_subtree(ta, ett_stun_att);

		offset = STUN_HDR_LEN;

		while(1){
			if( !tvb_bytes_exist(tvb, offset, ATTR_HDR_LEN) ) /* no data anymore */
			    break;
			    
			att_type = tvb_get_ntohs(tvb, offset); /* Type field in attribute header */
			att_length = tvb_get_ntohs(tvb, offset+2); /* Length field in attribute header */
			
			
			switch( att_type ){
				case MAPPED_ADDRESS:
				case RESPONSE_ADDRESS:
				case SOURCE_ADDRESS:
				case CHANGED_ADDRESS:
				case REFLECTED_FROM:
					proto_tree_add_item(att_tree, stun_att_type, tvb, offset, 2, FALSE);
					proto_tree_add_item(att_tree, stun_att_length, tvb, offset+2, 2, FALSE);
					proto_tree_add_item(att_tree, stun_att_family, tvb, offset+5, 1, FALSE);
					proto_tree_add_item(att_tree, stun_att_port, tvb, offset+6, 2, FALSE);
					proto_tree_add_item(att_tree, stun_att_ip, tvb, offset+8, 4, FALSE);

					offset = offset+(ATTR_HDR_LEN+att_length);
					
					break;
					
				case CHANGE_REQUEST:
					proto_tree_add_item(att_tree, stun_att_type, tvb, offset, 2, FALSE);
					proto_tree_add_item(att_tree, stun_att_length, tvb, offset+2, 2, FALSE);
					proto_tree_add_item(att_tree, stun_att_change_ip, tvb, offset+4, 4, FALSE);
					proto_tree_add_item(att_tree, stun_att_change_port, tvb, offset+4, 4, FALSE);

					offset = offset+(ATTR_HDR_LEN+att_length);
					
					break;					
					
				case USERNAME:
				case PASSWORD:
				case MESSAGE_INTEGRITY:
					proto_tree_add_item(att_tree, stun_att_type, tvb, offset, 2, FALSE);
					proto_tree_add_item(att_tree, stun_att_length, tvb, offset+2, 2, FALSE);
					proto_tree_add_item(att_tree, stun_att_length, tvb, offset+2, att_length, FALSE);
					
					offset = offset+(ATTR_HDR_LEN+att_length);
					
					break;
					
				case ERROR_CODE:
					proto_tree_add_item(att_tree, stun_att_type, tvb, offset, 2, FALSE);
					proto_tree_add_item(att_tree, stun_att_length, tvb, offset+2, 2, FALSE);
					
					proto_tree_add_item(att_tree, stun_att_error_class, tvb, offset+6, 1, FALSE);
					proto_tree_add_item(att_tree, stun_att_error_number, tvb, offset+7, 1, FALSE);
					proto_tree_add_item(att_tree, stun_att_error_reason, tvb, offset+8, (att_length-4), FALSE);
					
					offset = offset+(ATTR_HDR_LEN+att_length);
					
					break;				
				
				
				case UNKNOWN_ATTRIBUTES:
					proto_tree_add_item(att_tree, stun_att_type, tvb, offset, 2, FALSE);
					proto_tree_add_item(att_tree, stun_att_length, tvb, offset+2, 2, FALSE);

					offset = offset + ATTR_HDR_LEN;
					while(tvb_bytes_exist(tvb, offset, 4)){	/* UNKNOWN-ATTRIBUTES is 4 bytes aligned */
						proto_tree_add_item(att_tree, stun_att_unknown, tvb, offset, 2, FALSE);
						proto_tree_add_item(att_tree, stun_att_unknown, tvb, offset+2, 2, FALSE);
						offset = offset + 4;
					}
							
					break;
					
				default:
					return;
				
			}
			
		}
	}
}


static gboolean
dissect_stun_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        guint16 type, length;

        /*
         * This is a heuristic dissector, which means we get all the
         * UDP and TCP traffic not sent to a known dissector and not
         * claimed by a heuristic dissector called before us!
         * So we first check if the frame is really meant for us.
         */

        /* First, make sure we have enough data to do the check. */
        if (!tvb_bytes_exist(tvb, 0, STUN_HDR_LEN))
                return FALSE;
        
	type = tvb_get_ntohs(tvb, 0);
	
	/* check if message type is correct */
        if( 	(type != BINDING_REQUEST) &&
        	(type != BINDING_RESPONSE) &&
        	(type != BINDING_ERROR_RESPONSE) &&
            	(type != SHARED_SECRET_REQUEST) &&
            	(type != SHARED_SECRET_RESPONSE) &&
            	(type != SHARED_SECRET_ERROR_RESPONSE)
          )
        	return FALSE;
        
        
        length = tvb_get_ntohs(tvb, 2);
        
        /* check if payload enough */
        if (!tvb_bytes_exist(tvb, 0, STUN_HDR_LEN+length))
        	return FALSE;

	if(tvb_bytes_exist(tvb, 0, STUN_HDR_LEN+length+1))
		return FALSE;

        
        /* The message seems to be a valid STUN message! */
        dissect_stun(tvb, pinfo, tree);

        return TRUE;
}




void
proto_register_stun(void)
{                 

	static hf_register_info hf[] = {
		{ &hf_stun_type,
			{ "Message Type",	"stun.type", 	FT_UINT16, 
			BASE_HEX, 	VALS(messages),	0x0, 	"", 	HFILL }
		},
		{ &hf_stun_length,
			{ "Message Length",	"stun.length",	FT_UINT16, 
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &hf_stun_id,
			{ "Message Transaction ID",	"stun.id",	FT_BYTES,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &hf_stun_att,
			{ "Attributes",		"stun.att",	FT_NONE,
			0, 		NULL, 	0x0, 	"",	HFILL }
		},
		/* ////////////////////////////////////// */
		{ &stun_att_type,
			{ "Attribute Type",	"stun.att.type",	FT_UINT16,
			BASE_HEX,	VALS(attributes),	0x0, 	"",	HFILL }
		},
		{ &stun_att_length,
			{ "Attribute Length",	"stun.att.length",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_value,
			{ "Value",	"stun.att.value",	FT_BYTES,
			BASE_HEX,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_family,
			{ "Protocol Family",	"stun.att.family",	FT_UINT16,
			BASE_HEX,	VALS(attributes_family),	0x0, 	"",	HFILL }
		},
		{ &stun_att_ip,
			{ "IP",		"stun.att.ip",	FT_IPv4,
			BASE_NONE,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_port,
			{ "Port",	"stun.att.port",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	"",	HFILL }
		},
		{ &stun_att_change_ip,
			{ "Change IP","stun.att.change.ip",	FT_BOOLEAN,
			16, 	TFS(&set_flag),	0x0004,	"",	HFILL}
		},
		{ &stun_att_change_port,
			{ "Change Port","stun.att.change.port",	FT_BOOLEAN,
			16, 	TFS(&set_flag),	0x0002,	"",	HFILL}
		},		
		{ &stun_att_unknown,
			{ "Unknown Attribute","stun.att.unknown",	FT_UINT16,
			BASE_HEX, 	NULL,	0x0,	NULL,	HFILL}
		},
		{ &stun_att_error_class,
			{ "Error Class","stun.att.error.class",	FT_UINT8,
			BASE_DEC, 	NULL,	0x07,	"",	HFILL}
		},
		{ &stun_att_error_number,
			{ "Error Code","stun.att.error",	FT_UINT8,
			BASE_DEC, 	NULL,	0x0,	"",	HFILL}
		},
		{ &stun_att_error_reason,
			{ "Error Reason Phase","stun.att.error.reason",	FT_STRING,
			BASE_NONE, 	NULL,	0x0,	"",	HFILL}
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_stun,
		&ett_stun_att,
	};

/* Register the protocol name and description */
	proto_stun = proto_register_protocol("Simple Traversal of UDP Through NAT",
	    "STUN", "stun");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_stun, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_stun(void)
{
	dissector_handle_t stun_handle;

	stun_handle = create_dissector_handle(dissect_stun, proto_stun);
	dissector_add("tcp.port", TCP_PORT_STUN, stun_handle);
	dissector_add("udp.port", UDP_PORT_STUN, stun_handle);

        heur_dissector_add( "udp", dissect_stun_heur, proto_stun );
        heur_dissector_add( "tcp", dissect_stun_heur, proto_stun );
}
