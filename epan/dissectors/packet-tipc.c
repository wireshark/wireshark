/* packet-tipc.c
 * Routines for Transparent Inter Process Communication packet dissection
 *
 * $Id$
 *
 * Copyright 2005-2006, Anders Broman <anders.broman@ericsson.com>
 * 
 * TIPCv2 protocol updates
 * Copyright 2006, Martin Peylo <martin.peylo@siemens.com>
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
#include <epan/reassemble.h>

static int proto_tipc = -1;

static int hf_tipc_msg_fragments = -1;
static int hf_tipc_msg_fragment = -1;
static int hf_tipc_msg_fragment_overlap = -1;
static int hf_tipc_msg_fragment_overlap_conflicts = -1;
static int hf_tipc_msg_fragment_multiple_tails = -1;
static int hf_tipc_msg_fragment_too_long_fragment = -1;
static int hf_tipc_msg_fragment_error = -1;
static int hf_tipc_msg_reassembled_in = -1;

static int hf_tipc_ver = -1;
static int hf_tipc_usr = -1;
static int hf_tipcv2_usr = -1;
static int hf_tipc_hdr_size = -1;
static int hf_tipc_nonsequenced = -1;
static int hf_tipc_destdrop;
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
static int hf_tipc_cng_prot_msg_type = -1;
static int hf_tipc_sm_msg_type = -1;
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

static int hf_tipcv2_srcdrop;
static int hf_tipcv2_data_msg_type = -1;
static int hf_tipcv2_bcast_mtype = -1;
static int hf_tipcv2_link_mtype = -1;
static int hf_tipcv2_connmgr_mtype = -1;
static int hf_tipcv2_route_mtype = -1;
static int hf_tipcv2_changeover_mtype = -1;
static int hf_tipcv2_naming_mtype = -1;
static int hf_tipcv2_fragmenter_mtype = -1;
static int hf_tipcv2_neighbour_mtype = -1;
static int hf_tipcv2_errorcode = -1;
static int hf_tipcv2_rer_cnt = -1;
static int hf_tipcv2_lookup_scope = -1;
static int hf_tipcv2_opt_p = -1;
static int hf_tipcv2_broadcast_ack_no = -1;
static int hf_tipcv2_link_level_ack_no = -1;
static int hf_tipcv2_link_level_seq_no = -1;
static int hf_tipcv2_bcast_seq_no = -1;
static int hf_tipcv2_prev_node = -1;
static int hf_tipcv2_orig_node = -1;
static int hf_tipcv2_dest_node = -1;
static int hf_tipcv2_port_name_type = -1;
static int hf_tipcv2_port_name_instance = -1;

static int hf_tipcv2_bcast_seq_gap = -1;
static int hf_tipcv2_sequence_gap = -1;
static int hf_tipcv2_next_sent_broadcast = -1;
static int hf_tipcv2_fragment_number = -1;
static int hf_tipcv2_fragment_msg_number = -1;
static int hf_tipcv2_next_sent_packet = -1;
static int hf_tipcv2_session_no = -1;
static int hf_tipcv2_link_prio = -1;
static int hf_tipcv2_network_plane = -1;
static int hf_tipcv2_probe = -1;
static int hf_tipcv2_link_tolerance = -1;
static int hf_tipcv2_bearer_instance = -1;
static int hf_tipcv2_bearer_level_orig_addr = -1;
static int hf_tipcv2_cluster_address = -1;
static int hf_tipcv2_bitmap = -1;
static int hf_tipcv2_node_address = -1;
static int hf_tipcv2_destination_domain = -1;
static int hf_tipcv2_network_id = -1;

static int hf_tipcv2_bcast_tag = -1;
static int hf_tipcv2_msg_count = -1;
static int hf_tipcv2_max_packet = -1;
static int hf_tipcv2_transport_seq_no = -1;
static int hf_tipcv2_redundant_link = -1;
static int hf_tipcv2_bearer_id = -1;
static int hf_tipcv2_conn_mgr_msg_ack = -1;
static int hf_tipcv2_req_links = -1;

static gint ett_tipc_msg_fragment = -1;
static gint ett_tipc_msg_fragments = -1;

/* Initialize the subtree pointer */
static gint ett_tipc = -1;
static gint ett_tipc_data = -1;

static gboolean tipc_defragment = TRUE;
static gboolean dissect_tipc_data = FALSE;

static gboolean extra_ethertype = FALSE;

#define ETHERTYPE_TIPC2  0x0807

dissector_handle_t ip_handle;

static proto_tree *top_tree;

static const fragment_items tipc_msg_frag_items = {
	/* Fragment subtrees */
	&ett_tipc_msg_fragment,
	&ett_tipc_msg_fragments,
	/* Fragment fields */
	&hf_tipc_msg_fragments,
	&hf_tipc_msg_fragment,
	&hf_tipc_msg_fragment_overlap,
	&hf_tipc_msg_fragment_overlap_conflicts,
	&hf_tipc_msg_fragment_multiple_tails,
	&hf_tipc_msg_fragment_too_long_fragment,
	&hf_tipc_msg_fragment_error,
	/* Reassembled in field */
	&hf_tipc_msg_reassembled_in,
	/* Tag */
	"TIPC Message fragments"
};


#define MAX_TIPC_ADDRESS_STR_LEN   15
#define TIPCv1 1
#define TIPCv2 2
/* Users */
#define TIPC_DATA_PRIO_0            0
#define TIPC_DATA_PRIO_1            1
#define TIPC_DATA_PRIO_2            2
#define TIPC_DATA_NON_REJECTABLE    3

#define TIPC_ROUTING_MANAGER        8
#define TIPC_NAME_DISTRIBUTOR       9
#define TIPC_CONNECTION_MANAGER    10
#define TIPC_LINK_PROTOCOL         11
#define TIPC_CHANGEOVER_PROTOCOL   13
#define TIPC_SEGMENTATION_MANAGER  14
#define TIPC_MSG_BUNDLER           15

#define TIPC_LINK_PROTOCO_STATE_MSG 0

const value_string tipc_user_values[] = {
	{ TIPC_DATA_PRIO_0,          "DATA_PRIO_0"},
	{ TIPC_DATA_PRIO_1,          "DATA_PRIO_1"},
	{ TIPC_DATA_PRIO_2,          "DATA_PRIO_2"},
	{ TIPC_DATA_NON_REJECTABLE,  "DATA_NON_REJECTABLE"},
	{ TIPC_ROUTING_MANAGER,      "ROUTING_MANAGER"},
	{ TIPC_NAME_DISTRIBUTOR,     "NAME_DISTRIBUTOR"},
	{ TIPC_CONNECTION_MANAGER,   "CONNECTION_MANAGER"},
	{ TIPC_LINK_PROTOCOL,        "LINK_PROTOCOL"},
	{ TIPC_CHANGEOVER_PROTOCOL,  "CHANGEOVER_PROTOCOL"},
	{ TIPC_SEGMENTATION_MANAGER, "SEGMENTATION_MANAGER"},
	{ TIPC_MSG_BUNDLER,          "MSG_BUNDLER"},
	{ 0, NULL}
};

#define TIPCv2_DATA_LOW             0
#define TIPCv2_DATA_NORMAL          1
#define TIPCv2_DATA_HIGH            2
#define TIPCv2_DATA_NON_REJECTABLE  3

#define TIPCv2_BCAST_PROTOCOL       5
#define TIPCv2_MSG_BUNDLER          6
#define TIPCv2_LINK_PROTOCOL        7
#define TIPCv2_CONN_MANAGER         8
#define TIPCv2_ROUTE_DISTRIBUTOR    9
#define TIPCv2_CHANGEOVER_PROTOCOL 10
#define TIPCv2_NAME_DISTRIBUTOR    11
#define TIPCv2_MSG_FRAGMENTER      12
#define TIPCv2_NEIGHBOUR_DISCOVERY  13

const value_string tipcv2_user_values[] = {
	{ TIPCv2_DATA_LOW,            "Low Priority Payload Data"},
	{ TIPCv2_DATA_NORMAL,         "Normal Priority Payload Data"},
	{ TIPCv2_DATA_HIGH,           "High Priority Payload Data"},
	{ TIPCv2_DATA_NON_REJECTABLE, "Non-Rejectable Payload Data"},
	{ TIPCv2_BCAST_PROTOCOL,      "Broadcast Maintenance Protocol"},
	{ TIPCv2_MSG_BUNDLER,         "Message Bundler Protocol"},
	{ TIPCv2_LINK_PROTOCOL,       "Link State Maintenance Protocol"},
	{ TIPCv2_CONN_MANAGER,        "Connection Manager"},
	{ TIPCv2_ROUTE_DISTRIBUTOR,   "Routing Table Update Protocol"},
	{ TIPCv2_CHANGEOVER_PROTOCOL, "Link Changeover Protocol"},
	{ TIPCv2_NAME_DISTRIBUTOR,    "Name Table Update Protocol"},
	{ TIPCv2_MSG_FRAGMENTER,      "Message Fragmentation Protocol"},
	{ TIPCv2_NEIGHBOUR_DISCOVERY,  "Neighbour Discovery Protocol"},
	{ 0, NULL}
};

const value_string tipcv2_user_short_str_vals[] = {
	{ TIPCv2_DATA_LOW,            "Payld:Low"},
	{ TIPCv2_DATA_NORMAL,         "Payld:Normal"},
	{ TIPCv2_DATA_HIGH,           "Payld:High"},
	{ TIPCv2_DATA_NON_REJECTABLE, "Payld:NoRej"},
	{ TIPCv2_BCAST_PROTOCOL,      "Broadcast"},
	{ TIPCv2_MSG_BUNDLER,         "Bundler"},
	{ TIPCv2_LINK_PROTOCOL,       "Link State"},
	{ TIPCv2_CONN_MANAGER,        "Conn Mgr"},
	{ TIPCv2_ROUTE_DISTRIBUTOR,   "Route Dist"},
	{ TIPCv2_CHANGEOVER_PROTOCOL, "Changeover"},
	{ TIPCv2_NAME_DISTRIBUTOR,    "Name Dist"},
	{ TIPCv2_MSG_FRAGMENTER,      "Fragmenter"},
	{ TIPCv2_NEIGHBOUR_DISCOVERY,  "Ngbr Disc"},
	{ 0, NULL}
};

#define TIPC_CONNECTED_MSG  0
#define TIPC_NAMED_MSG      2
#define TIPC_DIRECT_MSG     3
#define TIPC_OVERLOAD_W_MSG 4

static const value_string tipc_data_msg_type_values[] = {
	{ 0, "CONN_MSG"},
	{ 2, "NAMED_MSG"},
	{ 3, "DIRECT_MSG"},
	{ 4, "OVERLOAD_W_MSG"},
	{ 0, NULL}
};

static const value_string tipcv2_data_msg_type_defines[] = {
	{ 0, "ConnMsg"},
	{ 1, "McastMsg"},
	{ 2, "NamedMsg"},
	{ 3, "DirectMsg"},
	{ 0, NULL}
};
static const value_string tipcv2_data_msg_type_values[] = {
	{ 0, "Sent on connection (CONN_MSG)"},
	{ 1, "Logical multicast (MCAST_MSG)"},
	{ 2, "Port name destination address (NAMED_MSG)"},
	{ 3, "Port identity destination address (DIRECT_MSG)"},
	{ 0, NULL}
};
static const value_string tipc_error_code_values[] = {
	{ 0, "MSG_OK"},
	{ 1, "NO_PORT_NAME"},
	{ 2, "NO_REMOTE_PORT"},
	{ 3, "NO_REMOTE_PROCESSOR"},
	{ 4, "DEST_OVERLOADED"},
	{ 6, "NO_CONNECTION"},
	{ 7, "COMMUNICATION_ERROR"},
	{ 0, NULL}
};

static const value_string tipcv2_error_code_strings[]={
	{ 0, "No error (TIPC_OK)"},
	{ 1, "Destination port name unknown (TIPC_ERR_NO_NAME)"}, 
	{ 2, "Destination port does not exist (TIPC_ERR_NO_PORT)"},
	{ 3, "Destination node unavailable (TIPC_ERR_NO_NODE)"},
	{ 4, "Destination node overloaded (TIPC_ERR_OVERLOAD)"},
	{ 5, "Connection Shutdown (No error) (TIPC_CONN_SHUTDOWN)"},
	{ 6, "Communication Error (TIPC_CONN_ERROR)"},
	{ 0, NULL}
};

static const value_string tipcv2_error_code_short_strings[]={
	{ 0, "OK"},
	{ 1, "ErrNoName"}, 
	{ 2, "ErrNoPort"},
	{ 3, "ErrNoNode"},
	{ 4, "ErrOverload"},
	{ 5, "ConnShutdown"},
	{ 6, "ConnError"},
	{ 0, NULL}
};

static const value_string tipcv2_lookup_scope_strings[]={
	{ 0, "Zone Scope"},
	{ 1, "Cluster Scope"},
	{ 2, "Node Scope"},
	{ 0, NULL}
};
static const value_string tipc_routing_mgr_msg_type_values[] = {
	{ 0, "EXT_ROUTING_TABLE"},
	{ 1, "LOCAL_ROUTING_TABLE"},
	{ 2, "DP_ROUTING_TABLE"},
	{ 3, "ROUTE_ADDITION"},
	{ 4, "ROUTE_REMOVAL"},
	{ 0, NULL}
};
static const value_string tipc_name_dist_msg_type_values[] = {
	{ 0, "PUBLICATION"},
	{ 1, "WITHDRAWAL"},
	{ 0, NULL}
};
/* CONNECTION_MANAGER */
static const value_string tipc_cm_msg_type_values[] = {
	{ 0, "CONNECTION_PROBE"},
	{ 1, "CONNECTION_PROBE_REPLY"},
	{ 0, NULL}
};
static const value_string tipc_link_prot_msg_type_values[] = {
	{ 10, "RESET_MSG"},
	{ 11, "ACTIVATE_MSG"},
	{ 12, "STATE_MSG"},
	{ 0, NULL}
};
/* CHANGEOVER_PROTOCOL */
static const value_string tipc_cng_prot_msg_type_values[] = {
	{ 0, "DUPLICATE_MSG"},
	{ 1, "ORIGINAL_MSG"},
	{ 2, "INFO_MSG"},
	{ 0, NULL}
};
/* SEGMENTATION_MANAGER */
#define TIPC_FIRST_SEGMENT	1
#define TIPC_SEGMENT		2
const value_string tipc_sm_msg_type_values[] = {
	{ 1, "FIRST_SEGMENT"},
	{ 2, "SEGMENT"},
	{ 0, NULL}
};

/* TIPCv2_BCAST_PROTOCOL - Broadcast Maintenance Protocol */
static const value_string tipcv2_bcast_mtype_strings[]={
	{ 0, "Bcast"},
	{ 0, NULL}
};

/* TIPCv2_MSG_BUNDLER - Message Bundler Protocol */

/* No message types */

/* TIPCv2_LINK_PROTOCOL - Link State Maintenance Protocol */
#define TIPCv2_STATE_MSG 0
#define TIPCv2_RESET_MSG 1
#define TIPCv2_ACTIV_MSG 2

static const value_string tipcv2_link_mtype_strings[]={
	{ TIPCv2_STATE_MSG, "State"},
	{ TIPCv2_RESET_MSG, "Reset"},
	{ TIPCv2_ACTIV_MSG, "Activate"},
	{ 0, NULL}
};
/* TIPCv2_CONN_MANAGER - Connection Manager */
#define TIPCv2_CONMGR_CONN_PROBE	0
#define TIPCv2_CONMGR_CONN_PROBE_REPLY  1
#define TIPCv2_CONMGR_MSG_ACK		2
static const value_string tipcv2_connmgr_mtype_strings[]={
	{ TIPCv2_CONMGR_CONN_PROBE       ,"Probe"},
	{ TIPCv2_CONMGR_CONN_PROBE_REPLY ,"ProbeReply"},
	{ TIPCv2_CONMGR_MSG_ACK          ,"Ack"},
	{ 0, NULL}
};
/* TIPCv2_ROUTE_DISTRIBUTOR - Routing Table Update Protocol */

#define TIPCv2_EXT_ROUTING_TABLE   0
#define TIPCv2_LOCAL_ROUTING_TABLE 1
#define TIPCv2_SEC_ROUTING_TABLE   2
#define TIPCv2_ROUTE_ADDITION      3
#define TIPCv2_ROUTE_REMOVAL       4
static const value_string tipcv2_route_mtype_strings[]={
	{ 0, "ExtRoutingTab"},
	{ 1, "LocalRoutingTab"},
	{ 2, "SecRoutingTab"},
	{ 3, "RouteAddition"},
	{ 4, "RouteRemoval"},
	{ 0, NULL}
};
/* TIPCv2_CHANGEOVER_PROTOCOL - Link Changeover Protocol */
static const value_string tipcv2_changeover_mtype_strings[]={
	{ 0, "Duplicate"},
	{ 1, "Original"},
	{ 0, NULL}
};
/* TIPCv2_NAME_DISTRIBUTOR - Name Table Update Protocol */
static const value_string tipcv2_naming_mtype_strings[]={
	{ 0, "Publication"},
	{ 1, "Withdrawal"},
	{ 0, NULL}
};
/* TIPCv2_MSG_FRAGMENTER - Message Fragmentation Protocol" */
static const value_string tipcv2_fragmenter_mtype_strings[]={
	{ 0, "First"},
	{ 1, "Fragment"},
	{ 2, "Last"},
	{ 0, NULL}
};

/* TIPCv2_NEIGHBOUR_DISCOVERY 
 * 4.3.9 Neighbour Detection Protocol
 */

static const value_string tipcv2_neighbour_mtype_strings[]={
	{ 0, "Request"},
	{ 1, "Response"},
	{ 0, NULL}
};


static const value_string tipcv2_networkplane_strings[]={
	{ 0, "A"},
	{ 1, "B"},
	{ 2, "C"},
	{ 3, "D"},
	{ 4, "E"},
	{ 5, "F"},
	{ 0, NULL}
};


static void dissect_tipc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


static GHashTable *tipc_msg_fragment_table    = NULL;
static GHashTable *tipc_msg_reassembled_table = NULL;


static void
tipc_defragment_init(void)
{
	fragment_table_init (&tipc_msg_fragment_table);
	reassembled_table_init(&tipc_msg_reassembled_table);
}


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
dissect_tipc_name_dist_data(tvbuff_t *tvb, proto_tree *tree){
	int offset = 0;
 
	while ( tvb_reported_length_remaining(tvb,offset) > 0){
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

/* Set message type in COL INFO and return type of message ( data or Internal message type */
static void
tipc_v2_set_info_col(tvbuff_t *tvb, packet_info *pinfo, guint8 user, guint8 msg_type, guint8 hdr_size){

	guint32 portNameInst, dword;
	guint32 portNameType, portNameInstLow, portNameInstHigh;
	guint8 error;

	switch (user){
		case TIPCv2_DATA_LOW:
		case TIPCv2_DATA_NORMAL:
		case TIPCv2_DATA_HIGH:
		case TIPCv2_DATA_NON_REJECTABLE:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(msg_type, tipcv2_data_msg_type_defines, "unknown"));

			/* Display Error!=0 in Info Column */
			dword = tvb_get_ntohl(tvb, 4);
			error = (dword>>25) & 0xf;
			if (error > 0)
				col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(error, tipcv2_error_code_short_strings, "unknown"));
			if (hdr_size > 8 ){
				/* Port Name Type: 32 bits */
				portNameType = tvb_get_ntohl(tvb, 32);
				col_append_fstr(pinfo->cinfo, COL_INFO, " type:%d", portNameType);
				if (hdr_size > 9 ){
					/* W9 name instance/multicast lower bound  */
					portNameInst = tvb_get_ntohl(tvb, 36);
					col_append_fstr(pinfo->cinfo, COL_INFO, " inst:%d", portNameInst);
					/*  Port Name Sequence Lower: 32 bits */
					if (hdr_size > 10 ){
						portNameInst = tvb_get_ntohl(tvb, 40);
						col_append_fstr(pinfo->cinfo, COL_INFO, "-%d", portNameInst);
					}						
				}
			}
			break;
		case TIPCv2_BCAST_PROTOCOL:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(msg_type, tipcv2_bcast_mtype_strings, "unknown"));
			break;
		case TIPCv2_MSG_BUNDLER:
			/* No message types */
			break;
		case TIPCv2_LINK_PROTOCOL:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(msg_type, tipcv2_link_mtype_strings, "unknown"));
			break;
		case TIPCv2_CONN_MANAGER:
			dword = tvb_get_ntohl(tvb, 4);
			/* Display Error!=0 in Info Column */
			error = (dword>>25) & 0xf;
			if (error > 0)
				col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(error, tipcv2_error_code_short_strings, "unknown"));
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(msg_type, tipcv2_connmgr_mtype_strings, "unknown"));
			break;
		case TIPCv2_ROUTE_DISTRIBUTOR:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(msg_type, tipcv2_route_mtype_strings, "unknown"));
			break;
		case TIPCv2_CHANGEOVER_PROTOCOL:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(msg_type, tipcv2_changeover_mtype_strings, "unknown"));
			break;
		case TIPCv2_NAME_DISTRIBUTOR:
			portNameType     = tvb_get_ntohl(tvb, 40);
			portNameInstLow  = tvb_get_ntohl(tvb, 44);
			portNameInstHigh = tvb_get_ntohl(tvb, 48);

			if( portNameInstLow == portNameInstHigh) {
				col_append_fstr(pinfo->cinfo, COL_INFO, " %s type:%d inst:%d", val_to_str(msg_type, tipcv2_naming_mtype_strings, "unknown"), portNameType, portNameInstLow);
			} else {
				/* sequence */
				col_append_fstr(pinfo->cinfo, COL_INFO, " %s type:%d seq:%d-%d", val_to_str(msg_type, tipcv2_naming_mtype_strings, "unknown"), portNameType, portNameInstLow, portNameInstHigh);
			}
			break;
		case TIPCv2_MSG_FRAGMENTER:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(msg_type, tipcv2_fragmenter_mtype_strings, "unknown"));
			break;
		case TIPCv2_NEIGHBOUR_DISCOVERY:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(msg_type, tipcv2_neighbour_mtype_strings, "unknown"));
			break;
		default:
			break;		 
	}
}

/* Set message type in COL INFO and return type of message ( data or Internal message type */
static gboolean
tipc_v1_set_col_msgtype(packet_info *pinfo, guint8 user,guint8 msg_type){

	gboolean datatype_hdr = FALSE;

	switch (user){
		case TIPC_DATA_PRIO_0: 	
		case TIPC_DATA_PRIO_1:
		case TIPC_DATA_PRIO_2:
		case TIPC_DATA_NON_REJECTABLE:
			/* 
			 * src and dest address will be found at different location depending on User ad hdr_size
			 */
			datatype_hdr = TRUE;
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%u) ", val_to_str(msg_type, tipc_data_msg_type_values, "unknown"),msg_type);
			break;
		case TIPC_NAME_DISTRIBUTOR:
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%u) ", val_to_str(msg_type, tipc_name_dist_msg_type_values, "unknown"),msg_type);
			break;
		case TIPC_CONNECTION_MANAGER:
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%u) ", val_to_str(msg_type, tipc_cm_msg_type_values, "unknown"),msg_type);
			break;
		case TIPC_ROUTING_MANAGER:
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%u) ", val_to_str(msg_type, tipc_routing_mgr_msg_type_values, "unknown"),msg_type);
			break;
		case TIPC_LINK_PROTOCOL:
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%u) ", val_to_str(msg_type, tipc_link_prot_msg_type_values, "unknown"),msg_type);
			break;
		case TIPC_CHANGEOVER_PROTOCOL:
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%u) ", val_to_str(msg_type, tipc_cng_prot_msg_type_values, "unknown"),msg_type);
			break;
		case TIPC_SEGMENTATION_MANAGER:
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%u) ", val_to_str(msg_type, tipc_sm_msg_type_values, "unknown"),msg_type);
			break;
		case TIPC_MSG_BUNDLER:
			break;
		default:
			break;		 
	}
	return datatype_hdr;
}


/*
	  Version 2(draft-maloy-tipc-01.txt):

4.2.1 Internal Message Header Format



       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w0:|vers |msg usr|hdr sz |n|resrv|            packet size          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w1:|m typ|bcstsqgap| sequence gap  |       broadcast ack no        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w2:|        link level ack no      |   broadcast/link level seq no |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w3:|                       previous node                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w4:|  next sent broadcast/fragm no | next sent pkt/ fragm msg no   |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w5:|          session no           | res |r|berid|link prio|netpl|p|
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w6:|                      originating node                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w7:|                      destination node                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w8:|                  transport sequence number                    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w9:|          msg count            |       link tolerance          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      \                                                               \
      /                     User Specific Data                        /
      \                                                               \
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  */
static void
dissect_tipc_v2_internal_msg(tvbuff_t *tipc_tvb, proto_tree *tipc_tree, int offset, guint8 user, guint32 msg_size, guint8 orig_hdr_size)
{

	guint32 dword;
	gchar *addr_str_ptr;
	tvbuff_t *data_tvb;
	guint8 message_type;

	dword = tvb_get_ntohl(tipc_tvb,offset+8);
	addr_str_ptr = tipc_addr_to_str(dword);
	message_type = (tvb_get_guint8(tipc_tvb,offset) >>5) & 0x7;  

	switch (user){
		case TIPCv2_BCAST_PROTOCOL:
			/* W1 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_bcast_mtype, tipc_tvb, offset, 4, FALSE);
			/* NO bcstsqgap */
			/* NO sequence gap */
			proto_tree_add_item(tipc_tree, hf_tipcv2_broadcast_ack_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W2 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_ack_no, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_seq_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W3 */
			proto_tree_add_string(tipc_tree, hf_tipcv2_prev_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;
			/* W4 */
			proto_tree_add_text(tipc_tree, tipc_tvb, offset, 20,"Words 4-8 Unused for this user");
			offset = offset + 20;
			/* W9 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_bcast_tag, tipc_tvb, offset, 4, FALSE);
			/* NO link tolerance */
			offset = offset + 4;
			break;
		case TIPCv2_MSG_BUNDLER:
			/* W1+W2 */
			/* No message types */
			proto_tree_add_text(tipc_tree, tipc_tvb, offset, 8,"Words 1+2 Unused for this user");
			offset = offset + 8;
			/* W3 */
			proto_tree_add_string(tipc_tree, hf_tipcv2_prev_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;
			/* W4 */
			proto_tree_add_text(tipc_tree, tipc_tvb, offset, 20,"Word 4-8 Unused for this user");
			offset = offset + 20;
			/* W9 */
			/* Message Count: 16 bits. */
			proto_tree_add_item(tipc_tree, hf_tipcv2_msg_count, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			break;
		case TIPCv2_LINK_PROTOCOL:
			/* W1 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_mtype, tipc_tvb, offset, 4, FALSE);
			/*  Broadcast Sequence Gap: 5 bits. */
			proto_tree_add_item(tipc_tree, hf_tipcv2_bcast_seq_gap, tipc_tvb, offset, 4, FALSE);
			/* Sequence Gap:  8 bits. */
			proto_tree_add_item(tipc_tree, hf_tipcv2_sequence_gap, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_broadcast_ack_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W2 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_ack_no, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_seq_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W3 */
			proto_tree_add_string(tipc_tree, hf_tipcv2_prev_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;
			/* W4 */
			/* Next Sent Broadcast: 16 bits */
			proto_tree_add_item(tipc_tree, hf_tipcv2_next_sent_broadcast, tipc_tvb, offset, 4, FALSE);
			/* Next Sent Packet:  16 bits. */
			proto_tree_add_item(tipc_tree, hf_tipcv2_next_sent_packet, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W5 */
			/* Session Number: 16 bits. */
			proto_tree_add_item(tipc_tree, hf_tipcv2_session_no, tipc_tvb, offset, 4, FALSE);
			/* Reserved: 3 bits Must be set to zero. */
			/* the following two fields appear in this user according to */
			/* Jon Malloy on the tipc-discussion mailing list */
			/* Redundant Link: 1 bit */
			proto_tree_add_item(tipc_tree, hf_tipcv2_redundant_link, tipc_tvb, offset, 4, FALSE);
			/* Bearer Identity: 3 bits */
			proto_tree_add_item(tipc_tree, hf_tipcv2_bearer_id, tipc_tvb, offset, 4, FALSE);
			/* Link Priority: 5 bits. */
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_prio, tipc_tvb, offset, 4, FALSE);
			/* Network Plane: 3 bits. */
			proto_tree_add_item(tipc_tree, hf_tipcv2_network_plane, tipc_tvb, offset, 4, FALSE);
			/* Probe: 1 bit. */
			proto_tree_add_item(tipc_tree, hf_tipcv2_probe, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W6 */
			proto_tree_add_text(tipc_tree, tipc_tvb, offset, 12,"Words 6-8 Unused for this user");
			offset = offset + 12;
			/* W9 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_max_packet, tipc_tvb, offset, 4, FALSE);
			/* Link Tolerance:  16 bits */
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_tolerance, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			
			if ((message_type == TIPCv2_RESET_MSG) 
				|| ((message_type == TIPCv2_STATE_MSG) && ((msg_size-(orig_hdr_size*4))  !=0))) /* is allowed */
				proto_tree_add_item(tipc_tree, hf_tipcv2_bearer_instance, tipc_tvb, offset, -1, FALSE);
			break;
		case TIPCv2_CONN_MANAGER:
			/* CONN_MANAGER uses the 36-byte header format of CONN_MSG payload messages */
			/* W1 */ 
			proto_tree_add_item(tipc_tree, hf_tipcv2_connmgr_mtype, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_errorcode, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_rer_cnt, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_lookup_scope, tipc_tvb, offset, 4, FALSE);

			/* Options Position: 3 bits */
			/* is this not used by this user according to Jon Maloy in tipc-discussion mailing list 
			opt_p = tvb_get_guint8(tipc_tvb, offset+1) & 0x7;
			proto_tree_add_item(tipc_tree, hf_tipcv2_opt_p , tipc_tvb, offset, 4, FALSE);
			if (opt_p != 0){
				hdr_size = hdr_size - (opt_p << 2);	
			}
			*/
			proto_tree_add_item(tipc_tree, hf_tipcv2_broadcast_ack_no , tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;

			/* W2 */	
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_ack_no , tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_seq_no , tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;

			/* W3 */
			dword = tvb_get_ntohl(tipc_tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);
			proto_tree_add_string(tipc_tree, hf_tipcv2_prev_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;

			/* W4 */
			proto_tree_add_item(tipc_tree, hf_tipc_org_port , tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;

			/* W5 */
			proto_tree_add_item(tipc_tree, hf_tipc_dst_port , tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;

			/* W6 */
			dword = tvb_get_ntohl(tipc_tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);
			proto_tree_add_string(tipc_tree, hf_tipcv2_orig_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;

			/* W7 */
			dword = tvb_get_ntohl(tipc_tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);
			proto_tree_add_string(tipc_tree, hf_tipcv2_dest_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;

			/* W8  */
			proto_tree_add_item(tipc_tree, hf_tipcv2_transport_seq_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;

			/* is this not used here according to Jon Maloy in tipc-discussion mailing list 
			 * Options

			if (opt_p != 0){
				proto_tree_add_text(tipc_tree, tipc_tvb, offset,(opt_p >> 2),"Options");
				offset = offset + (opt_p << 2);
			}
			  */

			/* Dissect if MSG_ACK */
			/* TIPCv2 data */
			if ( message_type == TIPCv2_CONMGR_MSG_ACK) 
			{
				proto_tree_add_item(tipc_tree, hf_tipcv2_conn_mgr_msg_ack, tipc_tvb, offset, 4, FALSE);
				/* what are the next 2 bytes for? --> so far unused */
				offset += 2;
			}
			break;
		case TIPCv2_ROUTE_DISTRIBUTOR:
			/* W1 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_route_mtype,      tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_broadcast_ack_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W2 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_ack_no, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_seq_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W3 */
			proto_tree_add_string(tipc_tree, hf_tipcv2_prev_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;
			/* W4 */
			proto_tree_add_text(tipc_tree, tipc_tvb, offset, 24,"Words 4-9 Unused for this user");
			offset = offset + 24;
			/* W10 */
			switch (message_type){
				case TIPCv2_EXT_ROUTING_TABLE:		/* 0  */
				case TIPCv2_LOCAL_ROUTING_TABLE:	/* 1  */
				case TIPCv2_SEC_ROUTING_TABLE:		/* 2  */
					/* Cluster Address */
					dword = tvb_get_ntohl(tipc_tvb,offset+8);
					addr_str_ptr = tipc_addr_to_str(dword);
					proto_tree_add_string(tipc_tree, hf_tipcv2_cluster_address, tipc_tvb, offset, 4, addr_str_ptr);
					offset = offset + 4;
					/* bitmap */
					proto_tree_add_item(tipc_tree, hf_tipcv2_bitmap, tipc_tvb, offset, -1, FALSE);
					break;
				case TIPCv2_ROUTE_ADDITION:			/* 3  */
				case TIPCv2_ROUTE_REMOVAL:			/* 4  */
					/* Node Address */
					dword = tvb_get_ntohl(tipc_tvb,offset+8);
					addr_str_ptr = tipc_addr_to_str(dword);
					proto_tree_add_string(tipc_tree, hf_tipcv2_node_address, tipc_tvb, offset, 4, addr_str_ptr);
					offset = offset + 4;
				default:
					break;
			}
			break;
		case TIPCv2_CHANGEOVER_PROTOCOL:
			/* W1 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_changeover_mtype, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_broadcast_ack_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W2 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_ack_no, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_seq_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W3 */
			proto_tree_add_string(tipc_tree, hf_tipcv2_prev_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;
			/* W4 */
			proto_tree_add_text(tipc_tree, tipc_tvb, offset, 4,"Word 4 Unused for this user");
			offset = offset + 4;
			/* W5 */
			/* the following two fields appear in this user according to */
			/* Jon Malloy on the tipc-discussion mailing list */
			/* Redundant Link: 1 bit */
			proto_tree_add_item(tipc_tree, hf_tipcv2_redundant_link, tipc_tvb, offset, 4, FALSE);
			/* Bearer Identity: 3 bits */
			proto_tree_add_item(tipc_tree, hf_tipcv2_bearer_id, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W6-W8 */
			proto_tree_add_text(tipc_tree, tipc_tvb, offset, 12,"Words 6-8 Unused for this user");
			offset = offset + 12;
			/* W9 */
			switch (message_type)
			{
				case 0:
					/* DUPLICATE_MSG */
					proto_tree_add_text(tipc_tree, tipc_tvb, offset, 4,"Word 9 Unused for this message type");
					break;
				case 1:
					/* ORIGINAL_MSG */
					/* Message Count: 16 bits. */
					proto_tree_add_item(tipc_tree, hf_tipcv2_msg_count, tipc_tvb, offset, 4, FALSE);
					break;
				default:
					break;
			}
			offset = offset + 4;
			break;
		case TIPCv2_NAME_DISTRIBUTOR:
			/* W1 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_naming_mtype, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_broadcast_ack_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W2 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_ack_no, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_seq_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W3 */
			proto_tree_add_string(tipc_tree, hf_tipcv2_prev_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;
			/* W4+W5 */
			proto_tree_add_text(tipc_tree, tipc_tvb, offset, 8,"Words 4+5 Unused for this user");
			offset = offset + 8;
			/* W6 */
			/* Originating Node: 32 bits. */
			dword = tvb_get_ntohl(tipc_tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);
			proto_tree_add_string(tipc_tree, hf_tipcv2_dest_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;
			/* W7 */
			/* Destination Node: 32 bits.  */
			dword = tvb_get_ntohl(tipc_tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);
			proto_tree_add_string(tipc_tree, hf_tipcv2_orig_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;
			/* W8 */
			/* Transport Level Sequence Number: 32 bits */
			proto_tree_add_item(tipc_tree, hf_tipcv2_transport_seq_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W9 */
			proto_tree_add_text(tipc_tree, tipc_tvb, offset, 4,"Word 9 Unused for this user");
			offset = offset + 4;
			/* W10 */
			/* dissect the (one or more) Publications */
			data_tvb = tvb_new_subset(tipc_tvb, offset, -1, -1);
			dissect_tipc_name_dist_data(data_tvb, tipc_tree);
			break;
		case TIPCv2_MSG_FRAGMENTER:
			/* W1 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_fragmenter_mtype, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_broadcast_ack_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W2 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_ack_no, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_seq_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W3 */
			proto_tree_add_string(tipc_tree, hf_tipcv2_prev_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;
			/* W4 */
			/* Fragment Number: 16 Bits. */
			proto_tree_add_item(tipc_tree, hf_tipcv2_fragment_number, tipc_tvb, offset, 4, FALSE);
			/* Fragment msg Number: 16 bits */
			proto_tree_add_item(tipc_tree, hf_tipcv2_fragment_msg_number, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W5-W9 */
			proto_tree_add_text(tipc_tree, tipc_tvb, offset, 20,"Words 5-9 Unused for this user");
			offset = offset + 20;
			break;
		case TIPCv2_NEIGHBOUR_DISCOVERY:
/*
The protocol for neighbour detection
   uses a special message format, with the following generic structure:

        0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w0:|vers |msg usr|hdr sz |n|resrv|            packet size          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w1:|m typ|0| requested links       |       broadcast ack no        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w2:|                      destination domain                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w3:|                       previous node                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w4:|                      network identity                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   w5:|                                                               |
      +-+-+-+-+-+-+-                                    +-+-+-+-+-+-+-+
   w6:|                                                               |
      +-+-+-+-+-+-+-  bearer level originating address  +-+-+-+-+-+-+-+
   w7:|                                                               |
      +-+-+-+-+-+-+-                                    +-+-+-+-+-+-+-+
   w8:|                                                               |
      +-+-+-+-+-+-+-                                    +-+-+-+-+-+-+-+
   w9:|                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      \                                                               \
      /                 vendor specific data  (optional)              /
      \                                                               \
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  */
			/* W1 */
			proto_tree_add_item(tipc_tree, hf_tipcv2_neighbour_mtype, tipc_tvb, offset, 4, FALSE);
			/* Requested Links (12 bits) */
			proto_tree_add_item(tipc_tree, hf_tipcv2_req_links, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipcv2_broadcast_ack_no, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W2 */
			/* Destination Domain */
			dword = tvb_get_ntohl(tipc_tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);
			proto_tree_add_string(tipc_tree, hf_tipcv2_destination_domain, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;
			/* W3 */
			dword = tvb_get_ntohl(tipc_tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);
			proto_tree_add_string(tipc_tree, hf_tipcv2_prev_node, tipc_tvb, offset, 4, addr_str_ptr);
			offset = offset + 4;
			/* W4 */
			/* Network Identity: */
			dword = tvb_get_ntohl(tipc_tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);
			proto_tree_add_item(tipc_tree, hf_tipcv2_network_id, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			/* W5 - W9 Bearer Level Originating Address: */
			proto_tree_add_item(tipc_tree, hf_tipcv2_bearer_level_orig_addr, tipc_tvb, offset, 20, FALSE);
			offset = offset + 20;
			if(msg_size-(orig_hdr_size*4) !=0) {
				proto_tree_add_text(tipc_tree, tipc_tvb, offset, -1,"Vendor specific data");
			}
			break;
		default:
			break;		 
	}

}

/* Version 2 Header 
http://tipc.sourceforge.net/doc/draft-spec-tipc-02.html#sec:TIPC_Pkt_Format
3.1.1. Payload Message Header Format



    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
w0:|vers | user  |hdr sz |n|d|s|r|          message size           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
w1:|mstyp| error |rer cnt|lsc|opt p|      broadcast ack no         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
w2:|        link level ack no      |   broadcast/link level seq no |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
w3:|                       previous node                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
w4:|                      originating port                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
w5:|                      destination port                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
w6:|                      originating node                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
w7:|                      destination node                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
w8:|             name type / transport sequence number             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
w9:|              name instance/multicast lower bound              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
wA:|                    multicast upper bound                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                                                               /
   \                           options                             \
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


  */

static void
dissect_tipc_v2(tvbuff_t *tipc_tvb, proto_tree *tipc_tree, int offset, guint8 user, guint32 msg_size, guint8 hdr_size, gboolean datatype_hdr)
{
	guint32 dword;
	gchar *addr_str_ptr;
	guint8 opt_p;
	/* The unit used is 32 bit words */
	guint8 orig_hdr_size;

	orig_hdr_size = hdr_size;

	/*
	 * Word 0
	 */
	/* Version: 3 bits */
	proto_tree_add_item(tipc_tree, hf_tipc_ver, tipc_tvb, offset, 4, FALSE);
	/* User: 4 bits */
	proto_tree_add_item(tipc_tree, hf_tipcv2_usr, tipc_tvb, offset, 4, FALSE);
	/* Header Size: 4 bits */
	proto_tree_add_item(tipc_tree, hf_tipc_hdr_size, tipc_tvb, offset, 4, FALSE);
	/* Non-sequenced: 1 bit */
	proto_tree_add_item(tipc_tree,hf_tipc_nonsequenced, tipc_tvb,offset,4, FALSE);
	if (datatype_hdr){
		/* Destination Droppable: 1 bit */
		proto_tree_add_item(tipc_tree,hf_tipc_destdrop, tipc_tvb,offset,4, FALSE);
		/* Source Droppable: 1 bit */
		proto_tree_add_item(tipc_tree,hf_tipcv2_srcdrop, tipc_tvb,offset,4, FALSE);
	}
	/* Reserved: 1 bits */

	/* Message Size: 17 bits */
	proto_tree_add_item(tipc_tree, hf_tipc_msg_size, tipc_tvb, offset, 4, FALSE);
	offset = offset + 4;
	
	if (!datatype_hdr){
		dissect_tipc_v2_internal_msg(tipc_tvb, tipc_tree, offset, user, msg_size, orig_hdr_size);
		return;
	}

	/* Word 1 */ 
	/* Message Type: 3 bits */
	proto_tree_add_item(tipc_tree, hf_tipcv2_data_msg_type, tipc_tvb, offset, 4, FALSE);
	/* Error Code: 4 bits */
	proto_tree_add_item(tipc_tree, hf_tipcv2_errorcode, tipc_tvb, offset, 4, FALSE);

	/* Reroute Counter: 4 bits */
	proto_tree_add_item(tipc_tree, hf_tipcv2_rer_cnt, tipc_tvb, offset, 4, FALSE);
	/* Lookup Scope: 2 bits */
	proto_tree_add_item(tipc_tree, hf_tipcv2_lookup_scope, tipc_tvb, offset, 4, FALSE);

	/* Options Position: 3 bits */
	opt_p = tvb_get_guint8(tipc_tvb, offset+1) & 0x7;
	proto_tree_add_item(tipc_tree, hf_tipcv2_opt_p, tipc_tvb, offset, 4, FALSE);
	if (opt_p != 0){
		hdr_size = hdr_size - (opt_p << 2);	
	}
	/* Broadcast Acknowledge Number: 16 bits */
	proto_tree_add_item(tipc_tree, hf_tipcv2_broadcast_ack_no, tipc_tvb, offset, 4, FALSE);
	offset = offset + 4;

	/* W2 */	
	/* Link Level Acknowledge Number: 16 bits */
	proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_ack_no, tipc_tvb, offset, 4, FALSE);
	/* broadcast/link level seq no */
	proto_tree_add_item(tipc_tree, hf_tipcv2_link_level_seq_no, tipc_tvb, offset, 4, FALSE);
	offset = offset + 4;
	/* W3 previous node */
	dword = tvb_get_ntohl(tipc_tvb,offset);
	addr_str_ptr = tipc_addr_to_str(dword);
	proto_tree_add_string(tipc_tree, hf_tipcv2_prev_node, tipc_tvb, offset, 4, addr_str_ptr);
	offset = offset + 4;

	/* W4 Originating Port: 32 bits */
	proto_tree_add_item(tipc_tree, hf_tipc_org_port, tipc_tvb, offset, 4, FALSE);
	offset = offset + 4;

	/* W5 Destination Port: 32 bits */
	proto_tree_add_item(tipc_tree, hf_tipc_dst_port, tipc_tvb, offset, 4, FALSE);
	offset = offset + 4;
	if (hdr_size > 6 ){

		/* W6 Originating Node: 32 bits */
		dword = tvb_get_ntohl(tipc_tvb,offset);
		addr_str_ptr = tipc_addr_to_str(dword);
		proto_tree_add_string(tipc_tree, hf_tipcv2_orig_node, tipc_tvb, offset, 4, addr_str_ptr);
		offset = offset + 4;
		/* W7 Destination Node: 32 bits */
		dword = tvb_get_ntohl(tipc_tvb,offset);
		addr_str_ptr = tipc_addr_to_str(dword);
		proto_tree_add_string(tipc_tree, hf_tipcv2_dest_node, tipc_tvb, offset, 4, addr_str_ptr);
		offset = offset + 4;
		if (hdr_size > 8 ){
			/* W8 name type / transport sequence number */
			/* Transport Level Sequence Number: 32 bits */
			/* Port Name Type: 32 bits */
			proto_tree_add_item(tipc_tree, hf_tipcv2_port_name_type, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;
			
			if (hdr_size > 9 ){
				/* W9 name instance/multicast lower bound  */
				/*  Port Name Instance: 32 bits */
				proto_tree_add_item(tipc_tree, hf_tipcv2_port_name_instance, tipc_tvb, offset, 4, FALSE);
				/*  Port Name Sequence Lower: 32 bits */
				offset = offset + 4;
				if (hdr_size > 10 ){

					/* W10 multicast upper bound */
					/* Port Name Sequence Upper: 32 bits */
					offset = offset + 4;
				}						
			}
		}
	}
	/* Options */
	if (opt_p != 0){
		proto_tree_add_text(tipc_tree, tipc_tvb, offset,(opt_p >> 2),"Options");
		offset = offset + (opt_p << 2);
	}
	/* TIPCv2 data */
        if ( msg_size > (orig_hdr_size<<2))
		proto_tree_add_text(tipc_tree, tipc_tvb, offset, -1,"TIPCv2 data: %u bytes", (msg_size - (orig_hdr_size<<2)));

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
	tvbuff_t *data_tvb;
	guint16 message_count;
	guint32 msg_in_bundle_size;
	guint32 dword;
	guint msg_no = 0;
	guint8 link_sel;
	guint16 link_lev_seq_no;
	guint32 reassembled_msg_length = 0;
	guint32 no_of_segments = 0;

	gboolean   save_fragmented;
	tvbuff_t* new_tvb = NULL;
	tvbuff_t* next_tvb = NULL;
	fragment_data *frag_msg = NULL;
	proto_item *item;
	
	link_lev_seq_no = tvb_get_ntohl(tvb,4) & 0xffff;
	/* Internal Protocol Header */
	/* Unused */

	msg_type = tvb_get_guint8(tvb,20)>>4;
	/* W3 */
	dword = tvb_get_ntohl(tvb,offset);
	link_sel = dword & 0x7;
	proto_tree_add_item(tipc_tree, hf_tipc_unused2, tvb, offset, 4, FALSE);
	/* Importance */
	if ( user == TIPC_SEGMENTATION_MANAGER)
		proto_tree_add_item(tipc_tree, hf_tipc_importance, tvb, offset, 4, FALSE);
	/* Link selector */
	if ( user == TIPC_SEGMENTATION_MANAGER || user == TIPC_NAME_DISTRIBUTOR || user == TIPC_CHANGEOVER_PROTOCOL )
		proto_tree_add_item(tipc_tree, hf_tipc_link_selector, tvb, offset, 4, FALSE);
	/* Message count */
	if ( user == TIPC_MSG_BUNDLER || user == TIPC_CHANGEOVER_PROTOCOL ){
		message_count = tvb_get_ntohs(tvb,offset+2);
		proto_tree_add_item(tipc_tree, hf_tipc_msg_cnt, tvb, offset, 4, FALSE);
	}
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
	case TIPC_CHANGEOVER_PROTOCOL:
		proto_tree_add_item(tipc_tree, hf_tipc_cng_prot_msg_type, tvb, offset, 4, FALSE);
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
	/*W7 */
	if (msg_size == 28) /* No data */
		return;

	switch (user){
		case TIPC_LINK_PROTOCOL:
			proto_tree_add_item(tipc_tree, hf_tipc_bearer_name, tvb, offset, -1, FALSE);
			break;
		case TIPC_CHANGEOVER_PROTOCOL:
			switch (msg_type){
			case 0: /* DUPLICATE_MSG */
			case 1: /* ORIGINAL_MSG */
				proto_tree_add_text(tipc_tree, tvb, offset, -1,"TIPC_CHANGEOVER_PROTOCOL %s (%u)",val_to_str(msg_type, tipc_cng_prot_msg_type_values, "unknown"),msg_type);
				data_tvb = tvb_new_subset(tvb, offset, -1, -1);
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_fence(pinfo->cinfo, COL_INFO);
				dissect_tipc(data_tvb, pinfo, tipc_tree);
				break;
			default:
				/*	INFO_MSG: Even when there are no packets in the send queue of a removed link, the other
					endpoint must be informed about this fact, so it can be unblocked when it has terminated its
					part of the changeover procedure. This message type may be regarded as an empty
					ORIGINAL_MSG, where message count is zero, and no packet is wrapped inside.
				*/
				proto_tree_add_text(tipc_tree, tvb, offset, -1,"TIPC_CHANGEOVER_PROTOCOL Protol/dissection Error");
				return;
				break;
			}
			break;
		case TIPC_SEGMENTATION_MANAGER:
			save_fragmented = pinfo->fragmented;
			if (tipc_defragment){
				pinfo->fragmented = TRUE;
			
				frag_msg = fragment_add_seq_next(tvb, offset, pinfo,
						link_sel,							/* ID for fragments belonging together - NEEDS IMPROVING? */  
						tipc_msg_fragment_table,			/* list of message fragments */
						tipc_msg_reassembled_table,			/* list of reassembled messages */
						tvb_length_remaining(tvb, offset),	/* fragment length - to the end */
						TRUE);								/* More fragments? */
				if (msg_type == TIPC_FIRST_SEGMENT ){
					reassembled_msg_length = tvb_get_ntohl(tvb,offset) & 0x1ffff;
					/* The number of segments needed fot he complete message (Including header) will be
					 * The size of the data section of the first message, divided by the complete message size
					 * + one segment for the remainder (if any).
					 */
					no_of_segments = reassembled_msg_length/(msg_size - 28);
					if (reassembled_msg_length > (no_of_segments * (msg_size - 28)))
						no_of_segments++;
					fragment_set_tot_len(pinfo, link_sel, tipc_msg_fragment_table, no_of_segments-1);
					item = proto_tree_add_text(tipc_tree, tvb, offset, -1,"Segmented message size %u bytes -> No segments = %i",reassembled_msg_length,no_of_segments);
					PROTO_ITEM_SET_GENERATED(item);
				}

				new_tvb = process_reassembled_data(tvb, offset, pinfo,
					"Reassembled Message", frag_msg, &tipc_msg_frag_items,
					NULL, tipc_tree);

				if (frag_msg) { /* Reassembled */
					if (check_col(pinfo->cinfo, COL_INFO))
						col_append_str(pinfo->cinfo, COL_INFO, 
						" (Message Reassembled)");
				} else { /* Not last packet of reassembled Short Message */
					if (check_col(pinfo->cinfo, COL_INFO))
						col_append_fstr(pinfo->cinfo, COL_INFO,
						" (Message fragment %u)", link_lev_seq_no);
				}
			}

			if (new_tvb) { /* take it all */
				next_tvb = new_tvb;
			} else { /* make a new subset */
			 	next_tvb = tvb_new_subset(tvb, offset, -1, -1);
			}
			pinfo->fragmented = save_fragmented;
			if (new_tvb){
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_fence(pinfo->cinfo, COL_INFO);
				dissect_tipc(next_tvb, pinfo, tipc_tree);
				return;
			}
		
			proto_tree_add_text(tipc_tree, next_tvb, 0, -1,"%u bytes Data Fragment",(msg_size - 28));
			return;
			break;
		case TIPC_MSG_BUNDLER:
			proto_tree_add_text(tipc_tree, tvb, offset, -1,"Message Bundle");
			while ((guint32)offset < msg_size ){
				msg_no++;
				msg_in_bundle_size = tvb_get_ntohl(tvb,offset);
				proto_tree_add_text(tipc_tree, tvb, offset, msg_in_bundle_size,"%u Message in Bundle",msg_no);
				data_tvb = tvb_new_subset(tvb, offset, msg_in_bundle_size, msg_in_bundle_size);
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_fence(pinfo->cinfo, COL_INFO);
				dissect_tipc(data_tvb, pinfo, tipc_tree);
				offset = offset + msg_in_bundle_size;
			}
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
	int previous_offset;
	guint32 dword;
	guint8  version;
	guint32 msg_size;
	guint8  hdr_size;
	guint8  user;
	gchar  *addr_str_ptr;
	const guchar		*src_addr, *dst_addr;
	tvbuff_t *data_tvb, *tipc_tvb;
	gboolean datatype_hdr = FALSE;
	guint8   msg_type = 0;

		/* Make entry in Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TIPC");

	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_clear(pinfo->cinfo, COL_INFO);

	top_tree = tree;
	dword = tvb_get_ntohl(tvb, offset);
	version = (dword >>29) & 0xf;
	hdr_size = (dword >>21) & 0xf;
	user = (dword>>25) & 0xf;
	msg_size = dword & 0x1ffff;

	if ( (guint32)tvb_length_remaining(tvb, offset) < msg_size){
		tipc_tvb = tvb;
	}else{
		tipc_tvb = tvb_new_subset(tvb, offset, msg_size, msg_size);
	}
	/* Set User values in COL INFO different in V1 and V2 */
	switch (version){
	case 0:
	case TIPCv1:
		msg_type = tvb_get_guint8(tipc_tvb, offset + 20)>>4;
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s(%u) ", val_to_str(user, tipc_user_values, "unknown"),user);
		}
		/* Set msg type in info col and find out if its a data hdr or not */
		datatype_hdr = tipc_v1_set_col_msgtype(pinfo, user, msg_type);
		if ( datatype_hdr ){
			/* Data type header */
			if ( hdr_size > 5 && user <4){
				/* W6 Originating Processor */
				src_addr = tvb_get_ptr(tipc_tvb, offset + 24, 4);
				SET_ADDRESS(&pinfo->src, AT_TIPC, 4, src_addr);
	
				/* W7 Destination Processor */
				dst_addr = tvb_get_ptr(tipc_tvb, offset + 28, 4);
				SET_ADDRESS(&pinfo->dst, AT_TIPC, 4, dst_addr);
			}else{
				/* Short data hdr */
				/* W2 Previous Processor */
				src_addr = tvb_get_ptr(tipc_tvb, offset + 8, 4);
				SET_ADDRESS(&pinfo->src, AT_TIPC, 4, src_addr);
			}
		}else{
			/* W2 Previous Processor */
			src_addr = tvb_get_ptr(tipc_tvb, offset + 8, 4);
			SET_ADDRESS(&pinfo->src, AT_TIPC, 4, src_addr);
		}
		break;
	case TIPCv2:
		msg_type = tvb_get_guint8(tipc_tvb,offset + 4)>>5;
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, "%-12s", val_to_str(user, tipcv2_user_short_str_vals, "unknown"));
		}
		/* Set msg type in info col */
		if (check_col(pinfo->cinfo, COL_INFO))
			tipc_v2_set_info_col(tvb, pinfo, user, msg_type, hdr_size);

		/* find out if its a data hdr or not */
		switch (user){
			case TIPCv2_DATA_LOW:
			case TIPCv2_DATA_NORMAL:
			case TIPCv2_DATA_HIGH:
			case TIPCv2_DATA_NON_REJECTABLE:
				datatype_hdr = TRUE;
				break;
			default:
				datatype_hdr = FALSE;
				break;
		}

		if ( datatype_hdr ){
			if (hdr_size > 6){
				/* W6 Originating Processor */
				src_addr = tvb_get_ptr(tipc_tvb, offset + 24, 4);
				SET_ADDRESS(&pinfo->src, AT_TIPC, 4, src_addr);
	
				/* W7 Destination Processor */
				dst_addr = tvb_get_ptr(tipc_tvb, offset + 28, 4);
				SET_ADDRESS(&pinfo->dst, AT_TIPC, 4, dst_addr);
			}else{
				/* W3 Previous Processor */
				src_addr = tvb_get_ptr(tipc_tvb, offset + 12, 4);
				SET_ADDRESS(&pinfo->src, AT_TIPC, 4, src_addr);
			}

		}else{
			if (user != TIPCv2_NEIGHBOUR_DISCOVERY){
				/* W6 Originating Processor */
				src_addr = tvb_get_ptr(tipc_tvb, offset + 24, 4);
				SET_ADDRESS(&pinfo->src, AT_TIPC, 4, src_addr);
	
				/* W7 Destination Processor */
				dst_addr = tvb_get_ptr(tipc_tvb, offset + 28, 4);
				SET_ADDRESS(&pinfo->dst, AT_TIPC, 4, dst_addr);
			}else{
				/* W2 Destination Domain */
				dst_addr = tvb_get_ptr(tipc_tvb, offset + 8, 4);
				SET_ADDRESS(&pinfo->dst, AT_TIPC, 4, dst_addr);
	
				/* W3 Previous Node */
				src_addr = tvb_get_ptr(tipc_tvb, offset + 12, 4);
				SET_ADDRESS(&pinfo->src, AT_TIPC, 4, src_addr);
			}
		}
		break;
	default:
		break;
	}

	ti = proto_tree_add_item(tree, proto_tipc, tipc_tvb, offset, -1, FALSE);
	tipc_tree = proto_item_add_subtree(ti, ett_tipc);
	if ( version == TIPCv2){
		dissect_tipc_v2(tipc_tvb, tipc_tree, offset, user, msg_size, hdr_size, datatype_hdr);
		return;
	}
	/* Word 0-2 common for all messages
	 * Word 0
	 */


	proto_tree_add_item(tipc_tree, hf_tipc_ver, tipc_tvb, offset, 4, FALSE);
	proto_tree_add_item(tipc_tree, hf_tipc_usr, tipc_tvb, offset, 4, FALSE);
	proto_tree_add_item(tipc_tree, hf_tipc_hdr_size, tipc_tvb, offset, 4, FALSE);
	proto_tree_add_item(tipc_tree,hf_tipc_nonsequenced, tipc_tvb,offset,4, FALSE);
	proto_tree_add_item(tipc_tree, hf_tipc_unused, tipc_tvb, offset, 4, FALSE);
	if (datatype_hdr){
		proto_tree_add_item(tipc_tree,hf_tipc_destdrop, tipc_tvb,offset,4, FALSE);
		proto_tree_add_item(tipc_tree,hf_tipcv2_srcdrop, tipc_tvb,offset,4, FALSE);
	}

	proto_tree_add_item(tipc_tree, hf_tipc_msg_size, tipc_tvb, offset, 4, FALSE);
	offset = offset + 4;
		
	/* Word 1 */
	proto_tree_add_item(tipc_tree, hf_tipc_ack_link_lev_seq, tipc_tvb, offset, 4, FALSE);
	proto_tree_add_item(tipc_tree, hf_tipc_link_lev_seq, tipc_tvb, offset, 4, FALSE);
	offset = offset + 4;
		
	/* Word 2 */
	dword = tvb_get_ntohl(tipc_tvb,offset);
	addr_str_ptr = tipc_addr_to_str(dword);
	proto_tree_add_string(tipc_tree, hf_tipc_prev_proc, tipc_tvb, offset, 4, addr_str_ptr);

	offset = offset + 4;
	switch (user){
		case TIPC_ROUTING_MANAGER:
		case TIPC_LINK_PROTOCOL:
		case TIPC_CHANGEOVER_PROTOCOL:
		case TIPC_SEGMENTATION_MANAGER:
		case TIPC_MSG_BUNDLER:
			dissect_tipc_int_prot_msg(tipc_tvb, pinfo, tipc_tree, offset, user, msg_size);
			return;
			break;
		default:
		break;		 
	}

	dword = tvb_get_ntohl(tipc_tvb,offset);
	pinfo->ptype = PT_TIPC;
	pinfo->srcport = dword;
	proto_tree_add_item(tipc_tree, hf_tipc_org_port, tipc_tvb, offset, 4, FALSE);
	offset = offset + 4;
	if(user != TIPC_NAME_DISTRIBUTOR){
		dword = tvb_get_ntohl(tipc_tvb,offset);
		pinfo->destport = dword;
		proto_tree_add_item(tipc_tree, hf_tipc_dst_port, tipc_tvb, offset, 4, FALSE);
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
	if ( hdr_size <= 6 ){
		proto_tree_add_text(tipc_tree, tipc_tvb, offset, -1, "%u bytes Data", (msg_size - hdr_size *4));
	}else{
		switch (user){
			case TIPC_NAME_DISTRIBUTOR:
				proto_tree_add_item(tipc_tree, hf_tipc_nd_msg_type, tipc_tvb, offset, 4, FALSE);
				break;
			case TIPC_CONNECTION_MANAGER:
				proto_tree_add_item(tipc_tree, hf_tipc_cm_msg_type, tipc_tvb, offset, 4, FALSE);
				break;
			default:
				proto_tree_add_item(tipc_tree, hf_tipc_data_msg_type, tipc_tvb, offset, 4, FALSE);
				break;
			}
			proto_tree_add_item(tipc_tree, hf_tipc_err_code, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipc_reroute_cnt, tipc_tvb, offset, 4, FALSE);
			proto_tree_add_item(tipc_tree, hf_tipc_act_id, tipc_tvb, offset, 4, FALSE);
			offset = offset + 4;

			dword = tvb_get_ntohl(tipc_tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);

			proto_tree_add_string(tipc_tree, hf_tipc_org_proc, tipc_tvb, offset, 4,	addr_str_ptr);
			offset = offset + 4;

			dword = tvb_get_ntohl(tipc_tvb,offset);
			addr_str_ptr = tipc_addr_to_str(dword);

			proto_tree_add_string(tipc_tree, hf_tipc_dst_proc, tipc_tvb, offset, 4,	addr_str_ptr);
			offset = offset + 4;
				/* 32 bytes 
				32 bytes: The size of all data messages containing an explicit port identity as destination
				address.
				*/
			if ( hdr_size > 8){
				if (user == TIPC_NAME_DISTRIBUTOR ){
					/*
						Although an internal service, the name distributor uses the full 40-byte "external" data header
						format when updating the naming table instances. This is because its messages may need
						routing, - all system processor must contain the publications from all device processors and
						vice versa, whether they are directly linked or not. The fields name type, name instance, and
						destination port of that header have no meaning for such messages
						*/
					offset = offset + 8;
					tipc_data_item = proto_tree_add_text(tipc_tree, tvb, offset, -1, "TIPC_NAME_DISTRIBUTOR %u bytes User Data", (msg_size - hdr_size *4));
					tipc_data_tree = proto_item_add_subtree(tipc_data_item , ett_tipc_data);
					data_tvb = tvb_new_subset(tipc_tvb, offset, -1, -1);
					dissect_tipc_name_dist_data(data_tvb, tipc_data_tree);
					return;
				}else{
					/* Port name type / Connection level sequence number */
					proto_tree_add_text(tipc_tree, tipc_tvb, offset, 4, "Port name type / Connection level sequence number");
					offset = offset + 4;
					/* Port name instance */
					proto_tree_add_text(tipc_tree, tipc_tvb, offset, 4, "Port name instance");
					offset = offset + 4;
				}
			}

 			if (user < 4 && dissect_tipc_data){ /* DATA type user */
				switch (msg_type){
				case TIPC_CONNECTED_MSG:
					proto_tree_add_text(tipc_tree, tipc_tvb, offset, -1, "%u bytes Data", (msg_size - hdr_size *4));
					break;
				case TIPC_NAMED_MSG:
					data_tvb = tvb_new_subset(tipc_tvb, offset+14, -1, -1);
					proto_tree_add_text(tipc_tree, tipc_tvb, offset, 14, "TIPC_NAMED_MSG Hdr");
					proto_tree_add_text(tipc_tree, data_tvb,0, -1, "%u bytes Data", (msg_size - hdr_size *4));
					return;
					break;
				case TIPC_DIRECT_MSG:
					previous_offset = offset;
					while (tvb_reported_length_remaining(tipc_tvb,offset) > 0){
						dword = tvb_get_ntohl(tipc_tvb,offset);
						if ((dword & 0xff000000) == 0x45000000){ /* && ((dword & 0x0000ffff)== tvb_reported_length_remaining(tvb,offset+2)))*/
							data_tvb = tvb_new_subset(tipc_tvb, offset, -1, -1);
							call_dissector(ip_handle, data_tvb, pinfo, top_tree);
							return;
						}
						offset = offset+4;
					}
					proto_tree_add_text(tipc_tree, tipc_tvb, previous_offset, -1,"%u bytes Data", (msg_size - hdr_size *4));
					return;
					break;
				default:
					proto_tree_add_text(tipc_tree, tipc_tvb, offset, -1,"%u bytes Data", (msg_size - hdr_size *4));
					break;
				}
			}			
			
		}/*if ( hdr_size <= 5 ) */
	/*}if tree */

}




/* Register TIPC with Wireshark */
void
proto_register_tipc(void)
{                 

	static hf_register_info hf[] = {

		{&hf_tipc_msg_fragments,
			{"Message fragments", "tipc.msg.fragments",
			FT_NONE, BASE_NONE, NULL, 0x00,	NULL, HFILL } 
		},
		{&hf_tipc_msg_fragment,
			{"Message fragment", "tipc.msg.fragment",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } 
		},
		{&hf_tipc_msg_fragment_overlap,
			{"Message fragment overlap", "tipc.msg.fragment.overlap",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } 
		},
		{&hf_tipc_msg_fragment_overlap_conflicts,
			{"Message fragment overlapping with conflicting data", "tipc.msg.fragment.overlap.conflicts",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } 
		},
		{&hf_tipc_msg_fragment_multiple_tails,
			{"Message has multiple tail fragments", "tipc.msg.fragment.multiple_tails", 
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } 
		},
		{&hf_tipc_msg_fragment_too_long_fragment,
			{"Message fragment too long", "tipc.msg.fragment.too_long_fragment",
			FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } 
		},
		{&hf_tipc_msg_fragment_error,
			{"Message defragmentation error", "tipc.msg.fragment.error",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } 
		},
		{&hf_tipc_msg_reassembled_in,
			{"Reassembled in", "tipc.msg.reassembled.in",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } 
		},
		{ &hf_tipc_ver,
			{ "Version", "tipc.ver",
			FT_UINT32, BASE_DEC, NULL, 0xe0000000,          
			"TIPC protocol version", HFILL }
		},
		{ &hf_tipc_usr,
			{ "User", "tipc.usr",
			FT_UINT32, BASE_DEC, VALS(tipc_user_values), 0x1e000000,          
			"TIPC User", HFILL }
		},
		{ &hf_tipcv2_usr,
			{ "User", "tipc.usr",
			FT_UINT32, BASE_DEC, VALS(tipcv2_user_values), 0x1e000000,          
			"TIPC User", HFILL }
		},
		{ &hf_tipc_hdr_size,
			{ "Header size", "tipc.hdr_size",
			FT_UINT32, BASE_DEC, NULL, 0x01e00000,          
			"TIPC Header size", HFILL }
		},
		{ &hf_tipc_nonsequenced,
			{ "Non-sequenced", "tipc.non_sequenced",
			FT_UINT32,BASE_DEC,NULL,0x00100000,
			"Non-sequenced Bit",HFILL }
		},
		{ &hf_tipc_destdrop,
			{ "Destination Droppable", "tipc.destdrop",
			FT_UINT32,BASE_DEC,NULL,0x00080000,
			"Destination Droppable Bit",HFILL }
		},
		{ &hf_tipc_unused,
			{ "Unused", "tipc.hdr_unused",
			FT_UINT32, BASE_DEC, NULL, 0x000e0000,          
			"TIPC Unused", HFILL }
		},
		{ &hf_tipc_msg_size,
			{ "Message size", "tipc.msg_size",
			FT_UINT32, BASE_DEC, NULL, 0x0001ffff,          
			"TIPC Message size", HFILL }
		},
		{ &hf_tipc_ack_link_lev_seq,
			{ "Acknowledged link level sequence number", "tipc.ack_link_lev_seq",
			FT_UINT32, BASE_DEC, NULL, 0xffff0000,          
			"TIPC Acknowledged link level sequence number", HFILL }
		},
		{ &hf_tipc_link_lev_seq,
			{ "Link level sequence number", "tipc.link_lev_seq",
			FT_UINT32, BASE_DEC, NULL, 0x0000ffff,          
			"TIPC Link level sequence number", HFILL }
		},
		{ &hf_tipc_prev_proc,
			{ "Previous processor", "tipc.prev_proc",
			FT_STRING, BASE_NONE, NULL, 0xffffffff,          
			"TIPC Previous processor", HFILL }
		},
		{ &hf_tipc_org_port,
			{ "Originating port", "tipc.org_port",
			FT_UINT32, BASE_DEC, NULL, 0xffffffff,          
			"TIPC Oiginating port", HFILL }
		},
		{ &hf_tipc_dst_port,
			{ "Destination port", "tipc.dst_port",
			FT_UINT32, BASE_DEC, NULL, 0xffffffff,          
			"TIPC Destination port", HFILL }
		},
		{ &hf_tipc_data_msg_type,
			{ "Message type", "tipc.msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_data_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_err_code,
			{ "Error code", "tipc.err_code",
			FT_UINT32, BASE_DEC, VALS(tipc_error_code_values), 0x0f000000,          
			"TIPC Error code", HFILL }
		},
		{ &hf_tipc_reroute_cnt,
			{ "Reroute counter", "tipc.route_cnt",
			FT_UINT32, BASE_DEC, NULL, 0x00f00000,          
			"TIPC Reroute counter", HFILL }
		},
		{ &hf_tipc_act_id,
			{ "Activity identity", "tipc.act_id",
			FT_UINT32, BASE_DEC, NULL, 0x000fffff,          
			"TIPC Activity identity", HFILL }
		},		
		{ &hf_tipc_org_proc,
			{ "Originating processor", "tipc.org_proc",
			FT_STRING, BASE_NONE, NULL, 0x0,          
			"TIPC Originating processor", HFILL }
		},
		{ &hf_tipc_dst_proc,
			{ "Destination processor", "tipc.dst_proc",
			FT_STRING, BASE_NONE, NULL, 0x0,          
			"TIPC Destination processor", HFILL }
		},
		{ &hf_tipc_unused2,
			{ "Unused", "tipc.unused2",
			FT_UINT32, BASE_DEC, NULL, 0xe0000000,          
			"TIPC Unused", HFILL }
		},
		{ &hf_tipc_importance,
			{ "Importance", "tipc.importance",
			FT_UINT32, BASE_DEC, NULL, 0x18000000,          
			"TIPC Importance", HFILL }
		},
		{ &hf_tipc_link_selector,
			{ "Link selector", "tipc.link_selector",
			FT_UINT32, BASE_DEC, NULL, 0x07000000,          
			"TIPC Link selector", HFILL }
		},
		{ &hf_tipc_msg_cnt,
			{ "Message count", "tipc.imsg_cnt",
			FT_UINT32, BASE_DEC, NULL, 0x00ffff00,          
			"TIPC Message count", HFILL }
		},
		{ &hf_tipc_probe,
			{ "Probe", "tipc.probe",
			FT_UINT32, BASE_DEC, NULL, 0x00000040,          
			"TIPC Probe", HFILL }
		},
		{ &hf_tipc_bearer_id,
			{ "Bearer identity", "tipc.bearer_id",
			FT_UINT32, BASE_DEC, NULL, 0x00000038,          
			"TIPC Bearer identity", HFILL }
		},
		{ &hf_tipc_link_selector2,
			{ "Link selector", "tipc.link_selector",
			FT_UINT32, BASE_DEC, NULL, 0x00000007,          
			"TIPC Link selector", HFILL }
		},
		{ &hf_tipc_remote_addr,
			{ "Remote address", "tipc.remote_addr",
			FT_UINT32, BASE_DEC, NULL, 0xffffffff,          
			"TIPC Remote address", HFILL }
		},
		{ &hf_tipc_rm_msg_type,
			{ "Message type", "tipc.rm_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_routing_mgr_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_nd_msg_type,
			{ "Message type", "tipc.nd_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_name_dist_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_cm_msg_type,
			{ "Message type", "tipc.nd_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_cm_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_lp_msg_type,
			{ "Message type", "tipc.lp_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_link_prot_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_cng_prot_msg_type,
			{ "Message type", "tipc.cng_prot_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_cng_prot_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_sm_msg_type,
			{ "Message type", "tipc.sm_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipc_sm_msg_type_values), 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_unknown_msg_type,
			{ "Message type", "tipc.unknown_msg_type",
			FT_UINT32, BASE_DEC, NULL, 0xf0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipc_seq_gap,
			{ "Sequence gap", "tipc.seq_gap",
			FT_UINT32, BASE_DEC, NULL, 0x0fff0000,          
			"TIPC Sequence gap", HFILL }
		},
		{ &hf_tipc_nxt_snt_pkg,
			{ "Next sent packet", "tipc.nxt_snt_pkg",
			FT_UINT32, BASE_DEC, NULL, 0x0000ffff,          
			"TIPC Next sent packet", HFILL }
		},
		{ &hf_tipc_unused3,
			{ "Unused", "tipc.unused3",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"TIPC Unused", HFILL }
		},
		{ &hf_tipc_bearer_name,
			{ "Bearer name", "tipc.bearer_name",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,          
			"TIPC Bearer name", HFILL }
		},
		{ &hf_tipc_name_dist_type,
			{ "Published port name type", "tipc.name_dist_type",
			FT_UINT32, BASE_DEC, NULL, 0xffffffff,          
			"TIPC Published port name type", HFILL }
		},
		{ &hf_tipc_name_dist_lower,
			{ "Lower bound of published sequence", "tipc.name_dist_lower",
			FT_UINT32, BASE_DEC, NULL, 0xffffffff,          
			"TIPC Lower bound of published sequence", HFILL }
		},
		{ &hf_tipc_name_dist_upper,
			{ "Upper bound of published sequence", "tipc.name_dist_upper",
			FT_UINT32, BASE_DEC, NULL, 0xffffffff,          
			"TIPC Upper bound of published sequence", HFILL }
		},
		{ &hf_tipc_name_dist_port,
			{ "Random number part of port identity", "tipc.dist_port",
			FT_UINT32, BASE_DEC, NULL, 0xffffffff,          
			"TIPC Random number part of port identity", HFILL }
		},
		{ &hf_tipc_name_dist_key,
			{ "Key (Use for verification at withdrawal)", "tipc.dist_key",
			FT_UINT32, BASE_DEC, NULL, 0xffffffff,          
			"TIPC key", HFILL }
		},
		{ &hf_tipcv2_srcdrop,
			{ "Source Droppable", "tipc.srcdrop",
			FT_UINT32, BASE_DEC, NULL, 0x00040000,
			"Destination Droppable Bit", HFILL }
		},
		{ &hf_tipcv2_data_msg_type ,
			{ "Message type", "tipc.data_type",
			FT_UINT32, BASE_DEC, VALS(tipc_data_msg_type_values), 0xe0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipcv2_bcast_mtype ,
			{ "Message type", "tipcv2.bcast_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipcv2_bcast_mtype_strings), 0xe0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipcv2_link_mtype ,
			{ "Message type", "tipcv2.link_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipcv2_link_mtype_strings), 0xe0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipcv2_connmgr_mtype ,
			{ "Message type", "tipcv2.connmgr_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipcv2_connmgr_mtype_strings), 0xe0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipcv2_route_mtype ,
			{ "Message type", "tipcv2.route_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipcv2_route_mtype_strings), 0xe0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipcv2_changeover_mtype ,
			{ "Message type", "tipcv2.changeover_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipcv2_changeover_mtype_strings), 0xe0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipcv2_naming_mtype ,
			{ "Message type", "tipcv2.naming_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipcv2_naming_mtype_strings), 0xe0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipcv2_fragmenter_mtype ,
			{ "Message type", "tipcv2.fragmenter_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipcv2_fragmenter_mtype_strings), 0xe0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipcv2_neighbour_mtype ,
			{ "Message type", "tipcv2.data_msg_type",
			FT_UINT32, BASE_DEC, VALS(tipcv2_neighbour_mtype_strings), 0xe0000000,          
			"TIPC Message type", HFILL }
		},
		{ &hf_tipcv2_errorcode ,
			{ "Error code", "tipcv2.errorcode",
			FT_UINT32, BASE_DEC, VALS(tipcv2_error_code_strings), 0x1e000000,          
			"Error code", HFILL }
		},
		{ &hf_tipcv2_rer_cnt,
			{ "Reroute Counter", "tipcv2.rer_cnt",
			FT_UINT32, BASE_DEC, NULL, 0x01e00000,          
			"Reroute Counter", HFILL }
		},
		{ &hf_tipcv2_lookup_scope,
			{ "Lookup Scope", "tipcv2.lookup_scope",
			FT_UINT32, BASE_DEC, VALS(tipcv2_lookup_scope_strings), 0x00180000,          
			"Lookup Scope", HFILL }
		},
		{ &hf_tipcv2_opt_p,
			{ "Options Position", "tipcv2.opt_p",
			FT_UINT32, BASE_DEC, NULL, 0x00070000,          
			"Options Position", HFILL }
		},
		{ &hf_tipcv2_broadcast_ack_no,
			{ "Broadcast Acknowledge Number", "tipcv2.broadcast_ack_no",
			FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,          
			"Broadcast Acknowledge Number", HFILL }
		},

		{ &hf_tipcv2_link_level_ack_no,
			{ "Link Level Acknowledge Number", "tipcv2.link_level_ack_no",
			FT_UINT32, BASE_DEC, NULL, 0xFFFF0000,          
			"Link Level Acknowledge Number", HFILL }
		},
		{ &hf_tipcv2_link_level_seq_no,
			{ "Link Level Sequence Number", "tipcv2.link_level_seq_no",
			FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,          
			"Link Level Sequence Number", HFILL }
		},
		{ &hf_tipcv2_bcast_seq_no,
			{ "Broadcast Sequence Number", "tipcv2.bcast_seq_no",
			FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,          
			"Broadcast Sequence Number", HFILL }
		},
		{ &hf_tipcv2_prev_node,
			{ "Previous Node", "tipcv2.prev_node",
			FT_STRING, BASE_NONE, NULL, 0xffffffff,          
			"TIPC Previous Node", HFILL }
		},
		{ &hf_tipcv2_orig_node,
			{ "Originating Node", "tipcv2.orig_node",
			FT_STRING, BASE_NONE, NULL, 0xffffffff,          
			"TIPC Originating Node", HFILL }
		},
		{ &hf_tipcv2_dest_node,
			{ "Destination Node", "tipcv2.dest_node",
			FT_STRING, BASE_NONE, NULL, 0xffffffff,          
			"TIPC Destination Node", HFILL }
		},
		{ &hf_tipcv2_port_name_type,
			{ "Port name type", "tipcv2.port_name_type",
			FT_UINT32, BASE_DEC, NULL, 0xffffffff,          
			"Port name type", HFILL }
		},
		{ &hf_tipcv2_port_name_instance,
			{ "Port name instance", "tipcv2.port_name_instance",
			FT_UINT32, BASE_DEC, NULL, 0xffffffff,          
			"Port name instance", HFILL }
		},
		{ &hf_tipcv2_bcast_seq_gap,
			{ "Broadcast Sequence Gap", "tipcv2.bcast_seq_gap",
			FT_UINT32, BASE_DEC, NULL, 0x1F000000,          
			"Broadcast Sequence Gap", HFILL }
		},
		{ &hf_tipcv2_sequence_gap,
			{ "Sequence Gap", "tipcv2.seq_gap",
			FT_UINT32, BASE_DEC, NULL, 0x00FF0000,          
			"Sequence Gap", HFILL }
		},
		{ &hf_tipcv2_next_sent_broadcast,
			{ "Next Sent Broadcast", "tipcv2.next_sent_broadcast",
			FT_UINT32, BASE_DEC, NULL, 0xFFFF0000,          
			"Next Sent Broadcast", HFILL }
		},
		{ &hf_tipcv2_fragment_number,
			{ "Fragment Number", "tipcv2.fragment_number",
			FT_UINT32, BASE_DEC, NULL, 0xFFFF0000,          
			"Fragment Number", HFILL }
		},
		{ &hf_tipcv2_fragment_msg_number,
			{ "Fragment Message Number", "tipcv2.fragment_msg_number",
			FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,          
			"Fragment Message Number", HFILL }
		},
		{ &hf_tipcv2_next_sent_packet,
			{ "Next Sent Packet", "tipcv2.next_sent_packet",
			FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,          
			"Next Sent Packet", HFILL }
		},
		{ &hf_tipcv2_session_no,
			{ "Session Number", "tipcv2.session_no",
			FT_UINT32, BASE_DEC, NULL, 0xFFFF0000,          
			"Session Number", HFILL }
		},
		{ &hf_tipcv2_link_prio,
			{ "Link Priority", "tipcv2.link_prio",
			FT_UINT32, BASE_DEC, NULL, 0x000001F0,          
			"Link Priority", HFILL }
		},
		{ &hf_tipcv2_network_plane,
			{ "Network Plane", "tipcv2.network_plane",
			FT_UINT32, BASE_DEC, VALS(tipcv2_networkplane_strings), 0x0000000E,          
			"Network Plane", HFILL }
		},
		{ &hf_tipcv2_probe,
			{ "Probe", "tipcv2.probe",
			FT_UINT32, BASE_DEC, NULL, 0x00000001,          
			"probe", HFILL }
		},
		{ &hf_tipcv2_link_tolerance,
			{ "Link Tolerance (ms)", "tipcv2.link_tolerance",
			FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,          
			"Link Tolerance in ms", HFILL }
		},
		{ &hf_tipcv2_bearer_instance,
			{ "Bearer Instance", "tipcv2.bearer_instance",
			FT_STRINGZ, BASE_NONE, NULL, 0,          
			"Bearer instance used by the sender node for this link", HFILL }
		},
		{ &hf_tipcv2_bearer_level_orig_addr,
			{ "Bearer Level Originating Address", "tipcv2.bearer_level_orig_addr",
			FT_BYTES, BASE_HEX, NULL, 0,          
			"Bearer Level Originating Address", HFILL }
		},
		{ &hf_tipcv2_cluster_address,
			{ "Cluster Address", "tipcv2.cluster_address",
			FT_STRING, BASE_NONE, NULL, 0xffffffff,          
			"The remote cluster concerned by the table", HFILL }
		},
		{ &hf_tipcv2_bitmap,
			{ "Bitmap", "tipcv2.bitmap",
			FT_BYTES, BASE_HEX, NULL, 0,          
			"Bitmap, indicating to which nodes within that cluster the sending node has direct links", HFILL }
		},
		{ &hf_tipcv2_node_address,
			{ "Node Address", "tipcv2.node_address",
			FT_STRING, BASE_NONE, NULL, 0xffffffff,
			"Which node the route addition/loss concern", HFILL }
		},
		{ &hf_tipcv2_destination_domain,
			{ "Destination Domain", "tipcv2.destination_domain",
			FT_STRING, BASE_NONE, NULL, 0xffffffff,
			"The domain to which the link request is directed", HFILL }
		},
		{ &hf_tipcv2_network_id,
			{ "Network Identity", "tipcv2.network_id",
			FT_UINT32, BASE_DEC, NULL, 0xFFFFFFFF,
			"The sender node's network identity", HFILL }
		},
		{ &hf_tipcv2_bcast_tag,
			{ "Broadcast Tag", "tipcv2.bcast_tag",
			FT_UINT32, BASE_DEC, NULL, 0xFFFF0000,          
			"Broadcast Tag", HFILL }
		},
		{ &hf_tipcv2_msg_count,
			{ "Message Count", "tipcv2.msg_count",
			FT_UINT32, BASE_DEC, NULL, 0xFFFF0000,          
			"Message Count", HFILL }
		},
		{ &hf_tipcv2_max_packet,
			{ "Max Packet", "tipcv2.max_packet",
			FT_UINT32, BASE_DEC, NULL, 0xFFFF0000,          
			"Max Packet", HFILL }
		},
		{ &hf_tipcv2_transport_seq_no,
			{ "Transport Sequence No", "tipcv2.tseq_no",
			FT_UINT32, BASE_DEC, NULL, 0xFFFFFFFF,          
			"Transport Level Sequence Number", HFILL }
		},
		{ &hf_tipcv2_redundant_link,
			{ "Redundant Link", "tipcv2.redundant_link",
			FT_UINT32, BASE_DEC, NULL, 0x00001000,          
			"Redundant Link", HFILL }
		},
		{ &hf_tipcv2_bearer_id,
			{ "Bearer identity", "tipcv2.bearer_id",
			FT_UINT32, BASE_DEC, NULL, 0x00000e00,          
			"Bearer identity", HFILL }
		},
		{ &hf_tipcv2_conn_mgr_msg_ack, /* special CONN_MANAGER payload */
			{ "Number of Messages Acknowledged", "tipcv2.conn_mgr_msg_ack",
			FT_UINT32, BASE_DEC, NULL, 0xffff0000,          
			"Number of Messages Acknowledged", HFILL }
		},
		{ &hf_tipcv2_req_links,
			{ "Requested Links", "tipcv2.req_links",
			FT_UINT32, BASE_DEC, NULL, 0x0fff0000,          
			"Requested Links", HFILL }
		}
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_tipc,
		&ett_tipc_data,
		&ett_tipc_msg_fragment,
		&ett_tipc_msg_fragments
	};

	module_t *tipc_module;

/* Register the protocol name and description */
	proto_tipc = proto_register_protocol("Transparent Inter Process Communication(TIPC)",
	    "TIPC", "tipc");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_tipc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_init_routine(tipc_defragment_init);

	/* Register configuration options */
	tipc_module = prefs_register_protocol(proto_tipc, NULL);

	prefs_register_bool_preference(tipc_module, "defragment",
		"Reassemble TIPCv1 SEGMENTATION_MANAGER datagrams",
		"Whether TIPCv1 SEGMENTATION_MANAGER datagrams should be reassembled",
		&tipc_defragment);

 	prefs_register_bool_preference(tipc_module, "dissect_tipc_data",
 		"Dissect TIPC data",
 		"Whether to try to dissect TIPC data or not",
 		&dissect_tipc_data);
}

void
proto_reg_handoff_tipc(void)
{
	dissector_handle_t tipc_handle;

	tipc_handle = create_dissector_handle(dissect_tipc, proto_tipc);
	dissector_add("ethertype", ETHERTYPE_TIPC, tipc_handle);
	if (extra_ethertype)
		dissector_add("ethertype", ETHERTYPE_TIPC2, tipc_handle);
	
	ip_handle = find_dissector("ip");
}
