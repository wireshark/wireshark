/* packet-tipc.c
 * Routines for Transparent Inter Process Communication packet dissection
 *
 * $Id$
 *
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * Protocol ref:
 * http://tipc.sourceforge.net/
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <epan/prefs.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/emem.h>

static int proto_tipc = -1;
static int hf_tipc_ver = -1;
static int hf_tipc_usr = -1;
static int hf_tipc_hdr_size = -1;
static int hf_tipc_unused = -1;
static int hf_tipc_msg_size = -1;
static int hf_tipc_ack_link_lev_seq = -1;
static int hf_tipc_link_lev_seq = -1;
static int hf_tipc_prev_proc = -1;
static int hf_tipc_org_port = -1;
static int hf_tipc_dst_port = -1;
static int hf_tipc_data_msg_type = -1;
static int hf_tipc_err_code = -1;
static int hf_tipc_reroute_cnt = -1;
static int hf_tipc_act_id = -1;
static int hf_tipc_org_proc = -1;
static int hf_tipc_dst_proc = -1;
static int hf_tipc_unused2 = -1;
static int hf_tipc_importance = -1;
static int hf_tipc_link_selector = -1;
static int hf_tipc_msg_cnt = -1;
static int hf_tipc_probe = -1;
static int hf_tipc_bearer_id = -1;
static int hf_tipc_link_selector2 = -1;
static int hf_tipc_remote_addr = -1;
static int hf_tipc_rm_msg_type = -1;
static int hf_tipc_nd_msg_type = -1;
static int hf_tipc_cm_msg_type = -1;
static int hf_tipc_lp_msg_type = -1;
static int hf_tipc_sm_msg_type = -1;
static int hf_tipc_ma_msg_type = -1;
static int hf_tipc_unknown_msg_type = -1;
static int hf_tipc_seq_gap = -1;
static int hf_tipc_nxt_snt_pkg = -1;
static int hf_tipc_unused3 = -1;
static int hf_tipc_bearer_name = -1;

static int hf_tipc_name_dist_type = -1;
static int hf_tipc_name_dist_lower = -1;
static int hf_tipc_name_dist_upper = -1;
static int hf_tipc_name_dist_port = -1;
static int hf_tipc_name_dist_key = -1;

/* Initialize the subtree pointer */
static gint ett_tipc = -1;
static gint ett_tipc_data = -1;

#define MAX_TIPC_ADDRESS_STR_LEN	15

/* Users */
#define TIPC_DATA_PRIO_0			0
#define TIPC_DATA_PRIO_1			1
#define TIPC_DATA_PRIO_2			2
#define TIPC_DATA_NON_REJECTABLE	3

#define TIPC_ROUTING_MANAGER		8
#define TIPC_NAME_DISTRIBUTOR		9
#define TIPC_CONNECTION_MANAGER		10
#define TIPC_LINK_PROTOCOL			11
#define TIPC_CHANGEOVER_PROTOCOL	13
#define TIPC_SEGMENTATION_MANAGER	14
#define TIPC_MSG_BUNDLER			15

#define TIPC_LINK_PROTOCO_STATE_MSG 0

const value_string tipc_user_values[] = {
	{ 0,	"DATA_PRIO_0"},
	{ 1,	"DATA_PRIO_1"},
	{ 2,	"DATA_PRIO_2"},
	{ 3,	"DATA_NON_REJECTABLE"},
	{ TIPC_ROUTING_MANAGER,			"ROUTING_MANAGER"},
	{ TIPC_NAME_DISTRIBUTOR,		"NAME_DISTRIBUTOR"},
	{ TIPC_CONNECTION_MANAGER,		"CONNECTION_MANAGER"},
	{ TIPC_LINK_PROTOCOL,			"LINK_PROTOCOL"},
	{ TIPC_CHANGEOVER_PROTOCOL,		"CHANGEOVER_PROTOCOL"},
	{ TIPC_SEGMENTATION_MANAGER,	"SEGMENTATION_MANAGER"},
	{ TIPC_MSG_BUNDLER,				"MSG_BUNDLER"},
	{ 0,	NULL},
};
const value_string tipc_data_msg_type_values[] = {
	{ 0,	"CONNECTED_MSG"},
	{ 2,	"NAMED_MSG"},
	{ 3,	"DIRECT_MSG"},
	{ 4,	"OVERLOAD_W_MSG"},
	{ 0,	NULL},
};
const value_string tipc_error_code_values[] = {
	{ 0,	"MSG_OK"},
	{ 1,	"NO_PORT_NAME"},
	{ 2,	"NO_REMOTE_PORT"},
	{ 3,	"NO_REMOTE_PROCESSOR"},
	{ 4,	"DEST_OVERLOADED"},
	{ 6,	"NO_CONNECTION"},
	{ 7,	"COMMUNICATION_ERROR"},
	{ 0,	NULL},
};
const value_string tipc_routing_mgr_msg_type_values[] = {
	{ 0,	"EXT_ROUTING_TABLE"},
	{ 1,	"LOCAL_ROUTING_TABLE"},
	{ 2,	"DP_ROUTING_TABLE"},
	{ 3,	"ROUTE_ADDITION"},
	{ 4,	"ROUTE_REMOVAL"},
	{ 0,	NULL},
};
const value_string tipc_name_dist_msg_type_values[] = {
	{ 0,	"PUBLICATION"},
	{ 1,	"WITHDRAWAL"},
	{ 0,	NULL},
};
const value_string tipc_cm_msg_type_values[] = {
	{ 0,	"CONNECTION_PROBE"},
	{ 1,	"CONNECTION_PROBE_REPLY"},
	{ 0,	NULL},
};
const value_string tipc_link_prot_msg_type_values[] = {
	{ 10,	"RESET_MSG"},
	{ 11,	"ACTIVATE_MSG"},
	{ 12,	"STATE_MSG"},
	{ 0,	NULL},
};
const value_string tipc_sm_msg_type_values[] = {
	{ 1,	"FIRST_SEGMENT"},
	{ 2,	"SEGMENT"},
	{ 0,	NULL},
};

static gchar*
tipc_addr_to_str(guint tipc_address)
{
	guint8 zone;
	guint16 subnetwork;
	guint16 processor;
	gchar *buff;

	buff=ep_alloc(MAX_TIPC_ADDRESS_STR_LEN);

	processor = tipc_address & 0x0fff;

	tipc_address = tipc_address >> 12;
	subnetwork = tipc_address & 0x0fff;

	tipc_address = tipc_address >> 12;
	zone = tipc_address & 0xff;

	g_snprintf(buff,MAX_TIPC_ADDRESS_STR_LEN,"%u.%u.%u",zone,subnetwork,processor);

	return buff;
}

/*
All name distributor messages have a data part containing one or more table elements with
the following five-word structure:
struct DistributionItem{
	unsigned int type; / Published port name type /
	unsigned int lower; / Lower bound of published sequence /
	unsigned int upper; / Upper bound of published sequence /
	unsigned int port; / Random number part of port identity /
	unsigned int key; / Use for verification at withdrawal /
};
*/
static void
dissect_tipc_name_dist_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
 
	while ( tvb_length_remaining(tvb,offset) > 0){
		 proto_tree_add_item(tree, hf_tipc_name_dist_type, tvb, offset, 4, FALSE);
		 offset = offset+4;
		 proto_tree_add_item(tree, hf_tipc_name_dist_lower, tvb, offset, 4, FALSE);
		 offset = offset+4;
		 proto_tree_add_item(tree, hf_tipc_name_dist_upper, tvb, offset, 4, FALSE);
		 offset = offset+4;
		 proto_tree_add_item(tree, hf_tipc_name_dist_port, tvb, offset, 4, FALSE);
		 offset = offset+4;
		 proto_tree_add_item(tree, hf_tipc_name_dist_key, tvb, offset, 4, FALSE);
		 offset = offset+4;
	}
}
/*  From message.h (http://cvs.sourceforge.net/viewcvs.py/tipc/source/stable_ericsson/TIPC_SCC/src/Message.h?rev=1.2&view=markup)
	////////////////////////////////////////////////////////////////////
                TIPC internal header format, version 1:

   :                                                               :
   |                 Word 0-2: common to all users                 |
   |                                                               |
   +-------+-------+-------+-------+-------+-------+-------+-------+
   |netw-|imp|link |                               | |p|bea- |link |
w3:|ork  |ort|sel- |        message count          | |r|rer  |sel- | 
   |id   |anc|ector|                               | |b|id   |ector| 
   +-------+-------+-------+-------+-------+-------+-------+-------+
   |                                                               |
w4:|                        remote address                         |
   |                                                               |
   +-------+-------+-------+-------+-------+-------+-------+-------+
   | msg   |                       |                               |
w5:| type  |           gap         |           next sent           |
   |       |                       |                               |
   +-------+-------+-------+-------+-------+-------+-------+-------+
   |                       | link    |                             |
w6:|        reserve        | prio-   |        link tolerance       |
   |                       | ity     |                             |
   +-------+-------+-------+-------+-------+-------+-------+-------+
   |                                                               |
w7:|                                                               |
   |                                                               |
   +-------+-------+                               +-------+-------+
   |                                                               |
w8:|                                                               |
   |                                                               |
   +-------+-------+       bearer name             +-------+-------+
   |                                                               |
w9:|                                                               |
   |                                                               |
   +-------+-------+                               +-------+-------+
   |                                                               |
wa:|                                                               |
   |                                                               |
   +-------+-------+-------+-------+-------+-------+-------+-------+

 NB: Connection Manager and Name Distributor use data message format.
   
*/

static void
dissect_tipc_int_prot_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tipc_tree,int offset,guint8 user, guint32 msg_size)
{	
	guint8 msg_type;
	/* Internal Protocol Header */
	/* Unused */
	msg_type = tvb_get_guint8(tvb,offset + 11);
	/* W3 */
	proto_tree_add_item(tipc_tree, hf_tipc_unused2, tvb, offset, 4, FALSE);
	/* Importance */
	if ( user == TIPC_SEGMENTATION_MANAGER)
		proto_tree_add_item(tipc_tree, hf_tipc_importance, tvb, offset, 4, FALSE);
	/* Link selector */
	if ( user == TIPC_SEGMENTATION_MANAGER || user == TIPC_NAME_DISTRIBUTOR || user == TIPC_CHANGEOVER_PROTOCOL )
		proto_tree_add_item(tipc_tree, hf_tipc_link_selector, tvb, offset, 4, FALSE);
	/* Message count */
	if ( user == TIPC_MSG_BUNDLER || user == TIPC_CHANGEOVER_PROTOCOL )
		proto_tree_add_item(tipc_tree, hf_tipc_msg_cnt, tvb, offset, 4, FALSE);
	/* Unused */
	/* Probe */
	if ( user == TIPC_LINK_PROTOCOL )
		proto_tree_add_item(tipc_tree, hf_tipc_probe, tvb, offset, 4, FALSE);
	/* Bearer identity */
	if ( user == TIPC_LINK_PROTOCOL || user == TIPC_CHANGEOVER_PROTOCOL )
		proto_tree_add_item(tipc_tree, hf_tipc_bearer_id, tvb, offset, 4, FALSE);
	/* Link selector */
	if ( user == TIPC_SEGMENTATION_MANAGER || user == TIPC_NAME_DISTRIBUTOR || user == TIPC_CHANGEOVER_PROTOCOL )
		proto_tree_add_item(tipc_tree, hf_tipc_link_selector2, tvb, offset, 4, FALSE);
	
	offset = offset + 4;

	/* W4 */
	/* Remote address */
	if ( user == TIPC_ROUTING_MANAGER )
		proto_tree_add_item(tipc_tree, hf_tipc_remote_addr, tvb, offset, 4, FALSE);
	offset = offset + 4;
	
	/* W5 */
	/* Message type */
	switch (user){
	case TIPC_ROUTING_MANAGER:
		proto_tree_add_item(tipc_tree, hf_tipc_rm_msg_type, tvb, offset, 4, FALSE);
		break;
	case TIPC_NAME_DISTRIBUTOR:
		proto_tree_add_item(tipc_tree, hf_tipc_nd_msg_type, tvb, offset, 4, FALSE);
		break;
	case TIPC_CONNECTION_MANAGER:
		break;
	case TIPC_LINK_PROTOCOL:
		proto_tree_add_item(tipc_tree, hf_tipc_lp_msg_type, tvb, offset, 4, FALSE);
		break;
	case TIPC_SEGMENTATION_MANAGER:
		proto_tree_add_item(tipc_tree, hf_tipc_sm_msg_type, tvb, offset, 4, FALSE);
		break;
	default:
		proto_tree_add_item(tipc_tree, hf_tipc_unknown_msg_type, tvb, offset, 4, FALSE);
		break;
	}
	/* Sequence gap */
	if ( user == TIPC_LINK_PROTOCOL && msg_type == TIPC_LINK_PROTOCO_STATE_MSG )
		proto_tree_add_item(tipc_tree, hf_tipc_seq_gap, tvb, offset, 4, FALSE);
	/* Next sent packet */
	proto_tree_add_item(tipc_tree, hf_tipc_nxt_snt_pkg, tvb, offset, 4, FALSE);

	offset = offset + 4;
	/* W6 */
	/* Unused */
	proto_tree_add_item(tipc_tree, hf_tipc_unused3, tvb, offset, 4, FALSE);
	offset = offset + 4;
	switch (user){
		case TIPC_CONNECTION_MANAGER:
		case TIPC_NAME_DISTRIBUTOR:
			proto_tree_add_text(tipc_tree, tvb, offset, -1,"%u bytes Data",(msg_size - 28));
			break;
		case TIPC_LINK_PROTOCOL:
			proto_tree_add_item(tipc_tree, hf_tipc_bearer_name, tvb, offset, -1, FALSE);
			break;
		default:
			proto_tree_add_text(tipc_tree, tvb, offset, -1,"%u bytes Data",(msg_size - 28));
			break;
	}
	return;
}




static void
dissect_tipc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	proto_item *ti, *tipc_data_item;
	proto_tree *tipc_tree, *tipc_data_tree;
	int offset = 0;
	guint32 dword;
	guint32 msg_size;
	guint8 hdr_size;
	guint8 user;
	gchar *addr_str_ptr;
	const guchar		*src_addr, *dst_addr;
	tvbuff_t *data_tvb;

		/* Make entry in Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TIPC");

	dword = tvb_get_ntohl(tvb,offset);
	hdr_size = (dword >>21) & 0xf;
	user = (dword>>25) & 0xf;
	msg_size = dword & 0x1ffff;

	/* 
	 * src and dest address will be found at different location depending on User ad hdr_size
	 */
	switch (user){
		case TIPC_DATA_PRIO_0: 	
		case TIPC_DATA_PRIO_1:
		case TIPC_DATA_PRIO_2:
		case TIPC_DATA_NON_REJECTABLE:
		case TIPC_NAME_DISTRIBUTOR:
		case TIPC_CONNECTION_MANAGER:
			/* Data type header */
			if ( hdr_size > 5 && user <4){
				src_addr = tvb_get_ptr(tvb, offset + 24, 4);
				SET_ADDRESS(&pinfo->src, AT_TIPC, 4, src_addr);
	
				dst_addr = tvb_get_ptr(tvb, offset + 28, 4);
				SET_ADDRESS(&pinfo->dst, AT_TIPC, 4, dst_addr);
			}else{
				/* Short data hdr */
				src_addr = tvb_get_ptr(tvb, offset + 8, 4);
				SET_ADDRESS(&pinfo->src, AT_TIPC, 4, src_addr);
			}
			break;
		case TIPC_ROUTING_MANAGER:
		case TIPC_LINK_PROTOCOL:
		case TIPC_CHANGEOVER_PROTOCOL:
		case TIPC_SEGMENTATION_MANAGER:
		case TIPC_MSG_BUNDLER:
			src_addr = tvb_get_ptr(tvb, offset + 8, 4);
			SET_ADDRESS(&pinfo->src, AT_TIPC, 4, src_addr);
		default:
			break;		 
	}


	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "User: %s(%u)", val_to_str(user, tipc_user_values, "unknown"),user);

	/* If "tree" is NULL, not necessary to generate protocol tree items. */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_tipc, tvb, offset, -1, FALSE);
		tipc_tree = proto_item_add_subtree(ti, ett_tipc);
		/* Word 0-2 common for all messages
		 * Word 0
		 */

		proto_tree_add_item(tipc_tree, hf_tipc_ver, tvb, offset, 4, FALSE);
		proto_tree_add_item(tipc_tree, hf_tipc_usr, tvb, offset, 4, FALSE);
		proto_tree_add_item(tipc_tree, hf_tipc_hdr_size, tvb, offset, 4, FALSE);
		proto_tree_add_item(tipc_tree, hf_tipc_unused, tvb, offset, 4, FALSE);
		proto_tree_add_item(tipc_tree, hf_tipc_msg_size, tvb, offset, 4, FALSE);
		offset = offset + 4;
		
		/* Word 1 */
		proto_tree_add_item(tipc_tree, hf_tipc_ack_link_lev_seq, tvb, offset, 4, FALSE);
		proto_tree_add_item(tipc_tree, hf_tipc_link_lev_seq, tvb, offset, 4, FALSE);
		offset = offset + 4;
		
		/* Word 2 */
		dword = tvb_get_ntohl(tvb,offset);
		addr_str_ptr = tipc_addr_to_str(dword);
		proto_tree_add_string(tipc_tree, hf_tipc_prev_proc, tvb, offset, 4,	addr_str_ptr);

		offset = offset + 4;
		switch (user){
			case TIPC_ROUTING_MANAGER:
			case TIPC_LINK_PROTOCOL:
			case TIPC_CHANGEOVER_PROTOCOL:
			case TIPC_SEGMENTATION_MANAGER:
			case TIPC_MSG_BUNDLER:
				dissect_tipc_int_prot_msg(tvb, pinfo, tipc_tree, offset, user, msg_size);
				return;
				break;
			default:
			break;		 
		}

		dword = tvb_get_ntohl(tvb,offset);
		pinfo->ptype = PT_TIPC;
		pinfo->srcport = dword;
		proto_tree_add_item(tipc_tree, hf_tipc_org_port, tvb, offset, 4, FALSE);
		offset = offset + 4;
		if(user != TIPC_NAME_DISTRIBUTOR){
			dword = tvb_get_ntohl(tvb,offset);
			pinfo->destport = dword;
			proto_tree_add_item(tipc_tree, hf_tipc_dst_port, tvb, offset, 4, FALSE);
		}
			offset = offset + 4;
		/* 20 - 24 Bytes 
			20 bytes: Used in subnetwork local, connection oriented messages, where error code, reroute
			counter and activity identity are zero. A recipient finding that the header size field is 20 does
			by default know both user (DATA), message type (CONNECTED_MSG), error code
			(MSG_OK), reroute counter (0), and activity identity (undefined). Since no more testing for
			this is needed these fields can be left out in the header. Furthermore, since such messages
			only will do zero or one inter-processor hop, we know that previous processor is the real
			origin of the message. Hence the field originating processor can be omitted. For the same
			reason, the recipient processor will know that it is identical to destination processor, so even
			this field can be skipped. Finally, because the link layer guarantees delivery and sequence
			order for this single hop, even the connection sequence number is redundant. So the message
			can just be passed directly on to the destination port. Since this type of message statistically
			should be by far the most frequent one this small optimization pays off.
		*/
		if ( hdr_size <= 5 ){
				proto_tree_add_text(tipc_tree, tvb, offset, -1,"%u bytes Data",(msg_size - hdr_size *4));
		}else{
			switch (user){
			case TIPC_NAME_DISTRIBUTOR:
				proto_tree_add_item(tipc_tree, hf_tipc_nd_msg_type, tvb, offset, 4, FALSE);
				break;
			case TIPC_CONNECTION_MANAGER:
				proto_tree_add_item(tipc_tree, hf_tipc_cm_msg_type, tvb, offset, 4, FALSE);
				break;
			default:
				proto_tree_add_item(tipc_tree, hf_tipc_data_msg_type, tvb, offset, 4, FALSE);
				break;
			}
			proto_tree_add_item(tipc_tree, hf_tipc_err_code, tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipc_reroute_cnt, tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipc_act_id, tvb, offset, 4, FALSE);
			offset = offset + 4;

			dword = tvb_get_ntohl(tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);

			proto_tree_add_string(tipc_tree, hf_tipc_org_proc, tvb, offset, 4,	addr_str_ptr);
			offset = offset + 4;

			dword = tvb_get_ntohl(tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);

			proto_tree_add_string(tipc_tree, hf_tipc_dst_proc, tvb, offset, 4,	addr_str_ptr);
			offset = offset + 4;
				/* 32 bytes 
				32 bytes: The size of all data messages containing an explicit port identity as destination
				address.
				*/
			if ( hdr_size > 8){
				if (user == TIPC_NAME_DISTRIBUTOR ){
					/*
						Although an internal service, the name distributor uses the full 40-byte “external” data header
						format when updating the naming table instances. This is because its messages may need
						routing, - all system processor must contain the publications from all device processors and
						vice versa, whether they are directly linked or not. The fields name type, name instance, and
						destination port of that header have no meaning for such messages
						*/
					offset = offset + 8;
				}else{
					/* TODO Add to protocol tree */
					/* Port name type / Connection level sequence number */
					offset = offset + 4;
					/* Port name instance */
					offset = offset + 4;
				}
			}
		}
			switch (user){
			case TIPC_NAME_DISTRIBUTOR:
				tipc_data_item = proto_tree_add_text(tipc_tree, tvb, offset, -1,"TIPC_NAME_DISTRIBUTOR %u bytes User Data",(msg_size - hdr_size *4));
				tipc_data_tree = proto_item_add_subtree(tipc_data_item , ett_tipc_data);
				data_tvb = tvb_new_subset(tvb, offset, -1, -1);
				dissect_tipc_name_dist_data(data_tvb, pinfo, tipc_data_tree);
				break;
			default:
				proto_tree_add_text(tipc_tree, tvb, offset, -1,"%u bytes Data",(msg_size - hdr_size *4));
			break;		 
		}
	}/* if tree */
}





/* Register TIPC with Ethereal */
void
proto_register_tipc(void)
{                 

	static hf_register_info hf[] = {

		{ &hf_tipc_ver,
			{ "Version",           "tipc.ver",
			FT_UINT32, BASE_DEC, NULL, 0xe0000000,          
			"TIPC protocol version", HFILL }
		},
		{ &hf_tipc_usr,
			{ "User",           "tipc.usr",
			FT_UINT32, BASE_DEC, VALS(tipc_user_values), 0x1e000000,          
			"TIPC User", HFILL }
		},
		{ &hf_tipc_hdr_size,
			{ "Header size",           "tipc.hdr_size",
			FT_UINT32, BASE_DEC, NULL, 0x01e00000,          
			"TIPC Header size", HFILL }
		},
		{ &hf_tipc_unused,
			{ "Unused",           "tipc.hdr_unused",
			FT_UINT32, BASE_DEC, NULL, 0x001e0000,          
			"TIPC Unused", HFILL }
		},
		{ &hf_tipc_msg_size,
			{ "Message size",           "tipc.msg_size",
			FT_UINT32, BASE_DEC, NULL, 0x0001ffff,          
			"TIPC Message size", HFILL }
		},
		{ &hf_tipc_ack_link_lev_seq,
			{ "Acknowledged link level sequence number",           "tipc.ack_link_lev_seq",
			FT_UINT32, BASE_DEC, NULL, 0xffff0000,          
			"TIPC Acknowledged link level sequence number", HFILL }
		},
		{ &hf_tipc_link_lev_seq,
			{ "Link level sequence number",           "tipc.link_lev_seq",
			FT_UINT32, BASE_DEC, NULL, 0x0000ffff,          
			"TIPC Link level sequence number", HFILL }
		},
		{ &hf_tipc_prev_proc,
			{ "Previous processor",           "tipc.prev_proc",
			FT_STRING, BASE_NONE, NULL, 0x0,          
			"TIPC Previous processor", HFILL }
		},
		{ &hf_tipc_org_port,
			{ "Originating port",           "tipc.org_port",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"TIPC Oiginating port", HFILL }
		},
		{ &hf_tipc_dst_port,
			{ "Destination port",           "tipc.dst_port",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"TIPC Destination port", HFILL }
		},
		{ &hf_tipc_data_msg_type,
			{ "Message type",           "tipc.msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_data_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_err_code,
			{ "Error code",           "tipc.err_code",
			FT_UINT32, BASE_DEC, VALS(tipc_error_code_values), 0x0f000000,          
			"TIPC Error code", HFILL }
		},
		{ &hf_tipc_reroute_cnt,
			{ "Reroute counter",           "tipc.route_cnt",
			FT_UINT32, BASE_DEC, NULL, 0x00f00000,          
			"TIPC Reroute counter", HFILL }
		},
		{ &hf_tipc_act_id,
			{ "Activity identity",           "tipc.act_id",
			FT_UINT32, BASE_DEC, NULL, 0x000fffff,          
			"TIPC Activity identity", HFILL }
		},		
		{ &hf_tipc_org_proc,
			{ "Originating processor",           "tipc.org_proc",
			FT_STRING, BASE_NONE, NULL, 0x0,          
			"TIPC Originating processor", HFILL }
		},
		{ &hf_tipc_dst_proc,
			{ "Destination processor",           "tipc.dst_proc",
			FT_STRING, BASE_NONE, NULL, 0x0,          
			"TIPC Destination processor", HFILL }
		},
		{ &hf_tipc_unused2,
			{ "Unused",           "tipc.unused2",
			FT_UINT32, BASE_DEC, NULL, 0xe0000000,          
			"TIPC Unused", HFILL }
		},
		{ &hf_tipc_importance,
			{ "Importance",           "tipc.importance",
			FT_UINT32, BASE_DEC, NULL, 0x18000000,          
			"TIPC Importance", HFILL }
		},
		{ &hf_tipc_link_selector,
			{ "Link selector",           "tipc.link_selector",
			FT_UINT32, BASE_DEC, NULL, 0x07000000,          
			"TIPC Link selector", HFILL }
		},
		{ &hf_tipc_msg_cnt,
			{ "Message count",           "tipc.imsg_cnt",
			FT_UINT32, BASE_DEC, NULL, 0x00ffff00,          
			"TIPC Message count", HFILL }
		},
		{ &hf_tipc_probe,
			{ "Probe",           "tipc.probe",
			FT_UINT32, BASE_DEC, NULL, 0x00000040,          
			"TIPC Probe", HFILL }
		},
		{ &hf_tipc_bearer_id,
			{ "Bearer identity",           "tipc.bearer_id",
			FT_UINT32, BASE_DEC, NULL, 0x00000038,          
			"TIPC Bearer identity", HFILL }
		},
		{ &hf_tipc_link_selector2,
			{ "Link selector",           "tipc.link_selector",
			FT_UINT32, BASE_DEC, NULL, 0x00000003,          
			"TIPC Link selector", HFILL }
		},
		{ &hf_tipc_remote_addr,
			{ "Remote address",           "tipc.remote_addr",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"TIPC Remote address", HFILL }
		},
		{ &hf_tipc_rm_msg_type,
			{ "Message type",           "tipc.rm_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_routing_mgr_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_nd_msg_type,
			{ "Message type",           "tipc.nd_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_name_dist_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_cm_msg_type,
			{ "Message type",           "tipc.nd_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_cm_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_lp_msg_type,
			{ "Message type",           "tipc.lp_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_link_prot_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_sm_msg_type,
			{ "Message type",           "tipc.sm_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_sm_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_unknown_msg_type,
			{ "Message type",           "tipc.unknown_msg_type",
			FT_UINT32, BASE_DEC, NULL, 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_seq_gap,
			{ "Sequence gap",           "tipc.seq_gap",
			FT_UINT32, BASE_DEC, NULL, 0x0fff0000,          
			"TIPC Sequence gap", HFILL }
		},
		{ &hf_tipc_nxt_snt_pkg,
			{ "Next sent packet",           "tipc.nxt_snt_pkg",
			FT_UINT32, BASE_DEC, NULL, 0x0000ffff,          
			"TIPC Next sent packet", HFILL }
		},
		{ &hf_tipc_unused3,
			{ "Unused",           "tipc.unused3",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"TIPC Unused", HFILL }
		},
		{ &hf_tipc_bearer_name,
			{ "Bearer name",           "tipc.bearer_name",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,          
			"TIPC Bearer name", HFILL }
		},
		{ &hf_tipc_name_dist_type,
			{ "Published port name type", "tipc.name_dist_type",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"TIPC Published port name type", HFILL }
		},
		{ &hf_tipc_name_dist_lower,
			{ "Lower bound of published sequence",  "tipc.ame_dist_lower",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"TIPC Lower bound of published sequence", HFILL }
		},
		{ &hf_tipc_name_dist_upper,
			{ "Upper bound of published sequence",  "tipc.name_dist_upper",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"TIPC Upper bound of published sequence", HFILL }
		},
		{ &hf_tipc_name_dist_port,
			{ "Random number part of port identity", "tipc.dist_port",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"TIPC Random number part of port identity", HFILL }
		},
		{ &hf_tipc_name_dist_key,
			{ "Key (Use for verification at withdrawal)",  "tipc.dist_key",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"TIPC key", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_tipc,
		&ett_tipc_data,
	};

/* Register the protocol name and description */
	proto_tipc = proto_register_protocol("Transparent Inter Process Communication(TIPC)",
	    "TIPC", "tipc");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_tipc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_tipc(void)
{
	dissector_handle_t tipc_handle;

	tipc_handle = create_dissector_handle(dissect_tipc, proto_tipc);
	dissector_add("ethertype", ETHERTYPE_TIPC,     tipc_handle);
}
