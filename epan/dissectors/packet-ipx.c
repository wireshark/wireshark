/* packet-ipx.c
 * Routines for NetWare's IPX
 * Gilbert Ramirez <gram@alumni.rice.edu>
 * NDPS support added by Greg Morris (gmorris@novell.com)
 *
 * Portions Copyright (c) 2000-2002 by Gilbert Ramirez.
 * Portions Copyright (c) Novell, Inc. 2002-2003
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include "packet-ipx.h"
#include "packet-sll.h"
#include <epan/addr_resolv.h>
#include <epan/etypes.h>
#include <epan/ppptypes.h>
#include <epan/llcsaps.h>
#include <epan/aftypes.h>
#include <epan/arcnet_pids.h>
#include <epan/conversation.h>
#include <epan/conversation_table.h>
#include <epan/proto_data.h>

void proto_register_ipx(void);
void proto_reg_handoff_ipx(void);

static int ipx_tap = -1;

/* The information in this module (IPX, SPX, NCP) comes from:
	NetWare LAN Analysis, Second Edition
	Laura A. Chappell and Dan E. Hakes
	(c) 1994 Novell, Inc.
	Novell Press, San Jose.
	ISBN: 0-7821-1362-1

  And from the ncpfs source code by Volker Lendecke

*/

static int proto_ipx = -1;
static int hf_ipx_checksum = -1;
static int hf_ipx_len = -1;
static int hf_ipx_src = -1;
static int hf_ipx_dst = -1;
static int hf_ipx_addr = -1;
static int hf_ipx_hops = -1;
static int hf_ipx_packet_type = -1;
static int hf_ipx_dnet = -1;
static int hf_ipx_dnode = -1;
static int hf_ipx_dsocket = -1;
static int hf_ipx_snet = -1;
static int hf_ipx_snode = -1;
static int hf_ipx_ssocket = -1;
static int hf_ipx_net = -1;
static int hf_ipx_node = -1;
static int hf_ipx_socket = -1;

static gint ett_ipx = -1;

static dissector_table_t ipx_type_dissector_table;
static dissector_table_t ipx_socket_dissector_table;
static dissector_table_t spx_socket_dissector_table;
static dissector_handle_t ipx_handle;
static dissector_handle_t ipxsap_handle;

static int proto_spx = -1;
static int hf_spx_connection_control = -1;
static int hf_spx_connection_control_sys = -1;
static int hf_spx_connection_control_send_ack = -1;
static int hf_spx_connection_control_attn = -1;
static int hf_spx_connection_control_eom = -1;
static int hf_spx_connection_control_v2 = -1;
static int hf_spx_connection_control_neg_size = -1;
static int hf_spx_connection_control_reserved = -1;
static int hf_spx_connection_control_ext_header = -1;
static int hf_spx_datastream_type = -1;
static int hf_spx_src_id = -1;
static int hf_spx_dst_id = -1;
static int hf_spx_seq_nr = -1;
static int hf_spx_ack_nr = -1;
static int hf_spx_all_nr = -1;
static int hf_spx_neg_size = -1;
static int hf_spx_rexmt_frame = -1;
static int hf_spx_rexmt_data = -1;

static gint ett_spx = -1;
static gint ett_spx_connctrl = -1;

static int proto_ipxrip = -1;
static int hf_ipxrip_request = -1;
static int hf_ipxrip_response = -1;
static int hf_ipxrip_packet_type = -1;
static int hf_ipxrip_route_vector = -1;
static int hf_ipxrip_hops = -1;
static int hf_ipxrip_ticks = -1;

static gint ett_ipxrip = -1;

static int proto_serialization = -1;
static int hf_serial_number = -1;
static gint ett_serialization = -1;

static int proto_sap = -1;
static int hf_sap_request = -1;
static int hf_sap_response = -1;
static int hf_sap_packet_type = -1;
static int hf_sap_server = -1;
static int hf_sap_server_type = -1;
static int hf_sap_server_name = -1;
static int hf_sap_server_network = -1;
static int hf_sap_server_node = -1;
static int hf_sap_server_socket = -1;
static int hf_sap_server_intermediate_networks = -1;

static gint ett_ipxsap = -1;
static gint ett_ipxsap_server = -1;

static gint ett_ipxmsg = -1;
static int proto_ipxmsg = -1;
static int hf_msg_conn = -1;
static int hf_msg_sigchar = -1;

#define UDP_PORT_IPX    213		/* RFC 1234 */

#define IPX_HEADER_LEN	30		/* It's *always* 30 bytes */

static const char* ipx_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
	if ((filter == CONV_FT_SRC_ADDRESS) && (conv->src_address.type == AT_IPX))
		return "ipx.src";

	if ((filter == CONV_FT_DST_ADDRESS) && (conv->dst_address.type == AT_IPX))
		return "ipx.dst";

	if ((filter == CONV_FT_ANY_ADDRESS) && (conv->src_address.type == AT_IPX))
		return "ipx.addr";

	return CONV_FILTER_INVALID;
}

static ct_dissector_info_t ipx_ct_dissector_info = {&ipx_conv_get_filter_type};

static tap_packet_status
ipx_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
	conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;

	const ipxhdr_t *ipxh=(const ipxhdr_t *)vip;

	add_conversation_table_data(hash, &ipxh->ipx_src, &ipxh->ipx_dst, 0, 0, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts, &ipx_ct_dissector_info, CONVERSATION_NONE);

	return TAP_PACKET_REDRAW;
}

static const char* ipx_endpoint_get_filter_type(endpoint_item_t* endpoint, conv_filter_type_e filter)
{
	if ((filter == CONV_FT_ANY_ADDRESS) && (endpoint->myaddress.type == AT_IPX))
		return "ipx.addr";

	return CONV_FILTER_INVALID;
}

static et_dissector_info_t ipx_endpoint_dissector_info = {&ipx_endpoint_get_filter_type};

static tap_packet_status
ipx_endpoint_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
	conv_hash_t *hash = (conv_hash_t*) pit;
    hash->flags = flags;

	const ipxhdr_t *ipxh=(const ipxhdr_t *)vip;

	/* Take two "add" passes per packet, adding for each direction, ensures that all
	packets are counted properly (even if address is sending to itself)
	XXX - this could probably be done more efficiently inside endpoint_table */
	add_endpoint_table_data(hash, &ipxh->ipx_src, 0, TRUE, 1, pinfo->fd->pkt_len, &ipx_endpoint_dissector_info, ENDPOINT_NONE);
	add_endpoint_table_data(hash, &ipxh->ipx_dst, 0, FALSE, 1, pinfo->fd->pkt_len, &ipx_endpoint_dissector_info, ENDPOINT_NONE);

	return TAP_PACKET_REDRAW;
}

/* ================================================================= */
/* IPX                                                               */
/* ================================================================= */
static const value_string ipx_socket_vals[] = {
	{ IPX_SOCKET_PING_CISCO,		"CISCO PING" },
	{ IPX_SOCKET_NCP,			"NCP" },
	{ IPX_SOCKET_SAP,			"SAP" },
	{ IPX_SOCKET_IPXRIP,			"RIP" },
	{ IPX_SOCKET_NETBIOS,			"NetBIOS" },
	{ IPX_SOCKET_DIAGNOSTIC,		"Diagnostic" },
	{ IPX_SOCKET_SERIALIZATION,		"Serialization" },
	{ IPX_SOCKET_NWLINK_SMB_SERVER,		"NWLink SMB Server" },
	{ IPX_SOCKET_NWLINK_SMB_NAMEQUERY,	"NWLink SMB Name Query" },
	{ IPX_SOCKET_NWLINK_SMB_REDIR,		"NWLink SMB Redirector" },
	{ IPX_SOCKET_NWLINK_SMB_MAILSLOT,	"NWLink SMB Mailslot Datagram" },
	{ IPX_SOCKET_NWLINK_SMB_MESSENGER,	"NWLink SMB Messenger" },
	{ IPX_SOCKET_NWLINK_SMB_BROWSE,		"NWLink SMB Browse" },
	{ IPX_SOCKET_ATTACHMATE_GW,		"Attachmate Gateway" },
	{ IPX_SOCKET_IPX_MESSAGE,		"IPX Message" },
	{ IPX_SOCKET_IPX_MESSAGE1,		"IPX Message" },
	{ 0x4006,				"NetWare Directory Server" },
	{ 0x400C,				"HP LaserJet/QuickSilver" },
	{ 0x8104,				"NetWare 386" },
	{ IPX_SOCKET_ADSM,			"ADSM" },
	{ IPX_SOCKET_EIGRP,			"Cisco EIGRP for IPX" },
	{ 0x8F83,				"Powerchute UPS Monitoring" },
	{ IPX_SOCKET_NLSP,			"NetWare Link Services Protocol" },
	{ IPX_SOCKET_IPXWAN,			"IPX WAN" },
	{ IPX_SOCKET_SNMP_AGENT,		"SNMP Agent" },
	{ IPX_SOCKET_SNMP_SINK,			"SNMP Sink" },
	{ 0x907B,				"SMS Testing and Development" },
	{ IPX_SOCKET_PING_NOVELL,		"Novell PING" },
	{ IPX_SOCKET_TCP_TUNNEL,		"TCP Tunnel" },
	{ IPX_SOCKET_UDP_TUNNEL,		"UDP Tunnel" },
	{ SPX_SOCKET_PA,			"NDPS Printer Agent/PSM" },
	{ SPX_SOCKET_BROKER,			"NDPS Broker" },
	{ SPX_SOCKET_SRS,			"NDPS Service Registry Service" },
	{ SPX_SOCKET_ENS,			"NDPS Event Notification Service" },
	{ SPX_SOCKET_RMS,			"NDPS Remote Management Service" },
	{ SPX_SOCKET_NOTIFY_LISTENER,		"NDPS Notify Listener" },
	{ 0xE885,				"NT Server-RPC/GW" },
	{ 0x0000,				NULL }
};

value_string_ext ipx_socket_vals_ext = VALUE_STRING_EXT_INIT(ipx_socket_vals);

static const value_string ipx_packet_type_vals[] = {
	{ IPX_PACKET_TYPE_IPX,		"IPX" },
	{ IPX_PACKET_TYPE_RIP,		"RIP" },
	{ IPX_PACKET_TYPE_ECHO,		"Echo" },
	{ IPX_PACKET_TYPE_ERROR,	"Error" },
	{ IPX_PACKET_TYPE_PEP,		"PEP" }, /* Packet Exchange Packet */
	{ IPX_PACKET_TYPE_SPX,		"SPX" },
	{ 16,				"Experimental Protocol" },
	{ IPX_PACKET_TYPE_NCP,		"NCP" },
	{ 18,				"Experimental Protocol" },
	{ 19,				"Experimental Protocol" },
	{ IPX_PACKET_TYPE_WANBCAST,	"NetBIOS Broadcast" },
	{ 21,				"Experimental Protocol" },
	{ 22,				"Experimental Protocol" },
	{ 23,				"Experimental Protocol" },
	{ 24,				"Experimental Protocol" },
	{ 25,				"Experimental Protocol" },
	{ 26,				"Experimental Protocol" },
	{ 27,				"Experimental Protocol" },
	{ 28,				"Experimental Protocol" },
	{ 29,				"Experimental Protocol" },
	{ 30,				"Experimental Protocol" },
	{ 31,				"Experimental Protocol" },
	{ 0,				NULL }
};

static const value_string ipxmsg_sigchar_vals[] = {
	{ '?', "Poll inactive station" },
	{ 'Y', "Station is still using the connection" },
	{ '!', "Broadcast message waiting" },
	{ 0, NULL }
};

static gboolean
capture_ipx(const guchar *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
	capture_dissector_increment_count(cpinfo, proto_ipx);
	return TRUE;
}

static int
dissect_ipx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	tvbuff_t	*next_tvb;

	proto_tree	*ipx_tree = NULL;
	proto_item	*ti = NULL, *hidden_item;

	guint8		ipx_hops;
	char 		*str;
	guint16		first_socket, second_socket;
	guint32		ipx_snet, ipx_dnet;
	static ipxhdr_t ipxh_arr[4];
	static int ipx_current=0;
	ipxhdr_t *ipxh;

	ipx_current++;
	if(ipx_current==4){
		ipx_current=0;
	}
	ipxh=&ipxh_arr[ipx_current];


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPX");
	col_clear(pinfo->cinfo, COL_INFO);

	/* Calculate here for use in pinfo and in tree */
	ipxh->ipx_dsocket = tvb_get_ntohs(tvb, 16);
	ipxh->ipx_ssocket = tvb_get_ntohs(tvb, 28);
	ipxh->ipx_type    = tvb_get_guint8(tvb, 5);
	ipxh->ipx_length  = tvb_get_ntohs(tvb, 2);

	pinfo->ptype = PT_IPX;
	pinfo->srcport = ipxh->ipx_ssocket;
	pinfo->destport = ipxh->ipx_dsocket;

	/* Adjust the tvbuff length to include only the IPX datagram. */
	set_actual_length(tvb, ipxh->ipx_length);

	set_address_tvb(&pinfo->net_src, AT_IPX, 10, tvb, 18);
    copy_address_shallow(&pinfo->src, &pinfo->net_src);
    copy_address_shallow(&ipxh->ipx_src, &pinfo->net_src);
	set_address_tvb(&pinfo->net_dst, AT_IPX, 10, tvb, 6);
    copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
    copy_address_shallow(&ipxh->ipx_dst, &pinfo->net_dst);

	col_add_str(pinfo->cinfo, COL_INFO, val_to_str_ext(ipxh->ipx_dsocket, &ipx_socket_vals_ext, "Unknown (0x%04x)"));

	if (tree) {

		ti = proto_tree_add_item(tree, proto_ipx, tvb, 0, IPX_HEADER_LEN, ENC_NA);
		ipx_tree = proto_item_add_subtree(ti, ett_ipx);
	}

	str=address_to_str(pinfo->pool, &pinfo->net_src);
	hidden_item = proto_tree_add_string(ipx_tree, hf_ipx_src, tvb, 0, 0, str);
	proto_item_set_hidden(hidden_item);
	hidden_item = proto_tree_add_string(ipx_tree, hf_ipx_addr, tvb, 0, 0, str);
	proto_item_set_hidden(hidden_item);
	str=address_to_str(pinfo->pool, &pinfo->net_dst);
	hidden_item = proto_tree_add_string(ipx_tree, hf_ipx_dst, tvb, 0, 0, str);
	proto_item_set_hidden(hidden_item);
	hidden_item = proto_tree_add_string(ipx_tree, hf_ipx_addr, tvb, 0, 0, str);
	proto_item_set_hidden(hidden_item);

	proto_tree_add_checksum(ipx_tree, tvb, 0, hf_ipx_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
	proto_tree_add_uint(ipx_tree, hf_ipx_len, tvb, 2, 2, ipxh->ipx_length);
	ipx_hops = tvb_get_guint8(tvb, 4);
	proto_tree_add_uint_format(ipx_tree, hf_ipx_hops, tvb, 4, 1, ipx_hops,
		"Transport Control: %d hops", ipx_hops);
	proto_tree_add_uint(ipx_tree, hf_ipx_packet_type, tvb, 5, 1, ipxh->ipx_type);

	/* Destination */
	ipx_dnet = tvb_get_ntohl(tvb, 6);
	proto_tree_add_ipxnet(ipx_tree, hf_ipx_dnet, tvb, 6, 4,
		ipx_dnet);
	hidden_item = proto_tree_add_ipxnet(ipx_tree, hf_ipx_net, tvb, 6, 4,
		ipx_dnet);
	proto_item_set_hidden(hidden_item);
	proto_tree_add_item(ipx_tree, hf_ipx_dnode, tvb, 10, 6, ENC_NA);
	hidden_item = proto_tree_add_item(ipx_tree, hf_ipx_node, tvb, 10, 6, ENC_NA);
	proto_item_set_hidden(hidden_item);
	proto_tree_add_uint(ipx_tree, hf_ipx_dsocket, tvb, 16, 2,
		ipxh->ipx_dsocket);
	hidden_item = proto_tree_add_uint(ipx_tree, hf_ipx_socket, tvb, 16, 2,
		ipxh->ipx_dsocket);
	proto_item_set_hidden(hidden_item);

	/* Source */
	ipx_snet = tvb_get_ntohl(tvb, 18);
	proto_tree_add_ipxnet(ipx_tree, hf_ipx_snet, tvb, 18, 4,
		ipx_snet);
	hidden_item = proto_tree_add_ipxnet(ipx_tree, hf_ipx_net, tvb, 18, 4,
		ipx_snet);
	proto_item_set_hidden(hidden_item);
	proto_tree_add_item(ipx_tree, hf_ipx_snode, tvb, 22, 6, ENC_NA);
	hidden_item = proto_tree_add_item(ipx_tree, hf_ipx_node, tvb, 22, 6, ENC_NA);
	proto_item_set_hidden(hidden_item);
	proto_tree_add_uint(ipx_tree, hf_ipx_ssocket, tvb, 28, 2,
		ipxh->ipx_ssocket);
	hidden_item = proto_tree_add_uint(ipx_tree, hf_ipx_socket, tvb, 28, 2,
		ipxh->ipx_ssocket);
	proto_item_set_hidden(hidden_item);

	/* Make the next tvbuff */
	next_tvb = tvb_new_subset_remaining(tvb, IPX_HEADER_LEN);

	/*
	 * Check the socket numbers before we check the packet type;
	 * we've seen non-NCP packets with a type of NCP and a
	 * destination socket of IPX_SOCKET_IPX_MESSAGE, and SAP
	 * packets with a type of NCP and a destination socket of
	 * IPX_SOCKET_SAP.
	 *
	 * We've seen NCP packets with a type of NCP, a source socket of
	 * IPX_SOCKET_NCP, and a destination socket of IPX_SOCKET_IPX_MESSAGE,
	 * and we've seen NCP packets with a type of NCP, a source socket of
	 * IPX_SOCKET_IPX_MESSAGE, and a destination socket of
	 * IPX_SOCKET_NCP, so testing the destination socket first doesn't
	 * always give the right answer.  We've also seen SAP packets with
	 * a source socket of IPX_SOCKET_SAP and a destination socket of
	 * IPX_SOCKET_IPX_MESSAGE.
	 *
	 * Unfortunately, we've also seen packets with a source socket
	 * of IPX_SOCKET_NWLINK_SMB_SERVER and a destination socket
	 * of IPX_SOCKET_NWLINK_SMB_NAMEQUERY that were NMPI packets,
	 * not SMB packets, so testing the lower-valued socket first
	 * also doesn't always give the right answer.
	 *
	 * So we start out assuming we should test the lower-numbered
	 * socket number first, but, if the higher-numbered socket is
	 * IPX_SOCKET_NWLINK_SMB_NAMEQUERY, we assume that it's a
	 * NMPI query, and test only that socket.
	 */
	if (ipxh->ipx_ssocket > ipxh->ipx_dsocket) {
		first_socket = ipxh->ipx_dsocket;
		second_socket = ipxh->ipx_ssocket;
	} else {
		first_socket = ipxh->ipx_ssocket;
		second_socket = ipxh->ipx_dsocket;
	}

	tap_queue_packet(ipx_tap, pinfo, ipxh);

	if (second_socket != IPX_SOCKET_NWLINK_SMB_NAMEQUERY) {
		if (dissector_try_uint_new(ipx_socket_dissector_table, first_socket,
			next_tvb, pinfo, tree, FALSE, ipxh))
			return tvb_captured_length(tvb);
	}
	if (dissector_try_uint_new(ipx_socket_dissector_table, second_socket,
		next_tvb, pinfo, tree, FALSE, ipxh))
		return tvb_captured_length(tvb);

	/*
	 * Neither of them are known; try the packet type, which will
	 * at least let us, for example, dissect SPX packets as SPX.
	 */
	if (dissector_try_uint_new(ipx_type_dissector_table, ipxh->ipx_type, next_tvb,
		pinfo, tree, FALSE, ipxh))
		return tvb_captured_length(tvb);

	call_data_dissector(next_tvb, pinfo, tree);
	return tvb_captured_length(tvb);
}
/* ================================================================= */
/* SPX Hash Functions                                                */
/* ================================================================= */

typedef struct {
	conversation_t	*conversation;
	guint32         spx_src;
	guint16         spx_seq;
} spx_hash_key;

typedef struct {
	guint16             spx_ack;
	guint16             spx_all;
	guint32             num;
} spx_hash_value;

/*
 * Structure attached to retransmitted SPX frames; it contains the
 * frame number of the original transmission.
 */
typedef struct {
	guint32             num;
} spx_rexmit_info;

static wmem_map_t *spx_hash = NULL;

/* Hash Functions */
static gint
spx_equal(gconstpointer v, gconstpointer v2)
{
	const spx_hash_key	*val1 = (const spx_hash_key*)v;
	const spx_hash_key	*val2 = (const spx_hash_key*)v2;

	if (val1->conversation == val2->conversation &&
	    val1->spx_src == val2->spx_src &&
	    val1->spx_seq == val2->spx_seq) {
		return 1;
	}
	return 0;
}

static guint
spx_hash_func(gconstpointer v)
{
	const spx_hash_key	*spx_key = (const spx_hash_key*)v;
	return GPOINTER_TO_UINT(spx_key->conversation) + spx_key->spx_src;
}

static spx_hash_value*
spx_hash_insert(conversation_t *conversation, guint32 spx_src, guint16 spx_seq)
{
	spx_hash_key		*key;
	spx_hash_value		*value;

	/* Now remember the packet, so we can find it if we later. */
	key = wmem_new(wmem_file_scope(), spx_hash_key);
	key->conversation = conversation;
	key->spx_src = spx_src;
	key->spx_seq = spx_seq;

	value = wmem_new0(wmem_file_scope(), spx_hash_value);

	wmem_map_insert(spx_hash, key, value);

	return value;
}

/* Returns the spx_hash_value*, or NULL if not found. */
static spx_hash_value*
spx_hash_lookup(conversation_t *conversation, guint32 spx_src, guint32 spx_seq)
{
	spx_hash_key		key;

	key.conversation = conversation;
	key.spx_src = spx_src;
	key.spx_seq = spx_seq;

	return (spx_hash_value *)wmem_map_lookup(spx_hash, &key);
}

/* ================================================================= */
/* SPX                                                               */
/* ================================================================= */

#define SPX_SYS_PACKET	0x80
#define SPX_SEND_ACK	0x40
#define SPX_ATTN	0x20
#define SPX_EOM		0x10
#define SPX_VII_PACKET	0x08
#define SPX_NEG_SIZE	0x04
#define SPX_RESERVED	0x02
#define SPX_EXT_HEADER	0x01

static const value_string conn_vals[] = {
	{ 0x00,                        "Data, No Ack Required" },
	{ SPX_EOM,                     "End-of-Message" },
	{ SPX_ATTN,                    "Attention" },
	{ SPX_SEND_ACK,                "Acknowledgment Required"},
	{ SPX_SEND_ACK|SPX_EOM,        "Send Ack: End Message"},
	{ SPX_SYS_PACKET,              "System Packet"},
	{ SPX_SYS_PACKET|SPX_SEND_ACK, "System Packet: Send Ack"},
	{ 0x00,                        NULL }
};

static const char*
spx_datastream(guint8 type)
{
	switch (type) {
		case 0xfe:
			return "End-of-Connection";
		case 0xff:
			return "End-of-Connection Acknowledgment";
		default:
			return NULL;
	}
}

#define SPX_HEADER_LEN	12
#define SPX2_HEADER_LEN	14

static int
dissect_spx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*spx_tree;
	proto_item	*ti;
	tvbuff_t	*next_tvb;
	guint8		conn_ctrl;
	guint8		hdr_len = SPX_HEADER_LEN;
	guint8		datastream_type;
	const char	*datastream_type_string;
	guint16         spx_seq;
	const char	*spx_msg_string;
	guint16		low_socket, high_socket;
	guint32		src;
	conversation_t	*conversation;
	spx_hash_value	*pkt_value;
	spx_rexmit_info	*spx_rexmit_info_p;
	spx_info	spx_infox;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SPX");
	col_set_str(pinfo->cinfo, COL_INFO, "SPX");

	conn_ctrl = tvb_get_guint8(tvb, 0);
	if ((conn_ctrl & SPX_VII_PACKET) && tvb_get_ntohs(tvb, 4) != 0xffff) {
		/* SPX2 packets have an extra two-byte field, unless they have
		 * a dest-ID of 0xffff... */
		hdr_len = SPX2_HEADER_LEN;
	}

	ti = proto_tree_add_item(tree, proto_spx, tvb, 0, hdr_len, ENC_NA);
	spx_tree = proto_item_add_subtree(ti, ett_spx);

	spx_msg_string = val_to_str_const((conn_ctrl & 0xf0), conn_vals, "Unknown" );
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", spx_msg_string);
	if (tree) {
		static int * const spx_flags[] = {
			&hf_spx_connection_control_sys,
			&hf_spx_connection_control_send_ack,
			&hf_spx_connection_control_attn,
			&hf_spx_connection_control_eom,
			NULL
		};

		static int * const spx_vii_flags[] = {
			&hf_spx_connection_control_sys,
			&hf_spx_connection_control_send_ack,
			&hf_spx_connection_control_attn,
			&hf_spx_connection_control_eom,
			&hf_spx_connection_control_v2,
			&hf_spx_connection_control_neg_size,
			&hf_spx_connection_control_reserved,
			&hf_spx_connection_control_ext_header,
			NULL
		};

		if (conn_ctrl & SPX_VII_PACKET) {
			proto_tree_add_bitmask_with_flags(spx_tree, tvb, 0, hf_spx_connection_control,
											ett_spx_connctrl, spx_vii_flags, ENC_NA, BMT_NO_APPEND);
		} else {
			proto_tree_add_bitmask_with_flags(spx_tree, tvb, 0, hf_spx_connection_control,
											ett_spx_connctrl, spx_flags, ENC_NA, BMT_NO_APPEND);
		}
	}

	datastream_type = tvb_get_guint8(tvb, 1);
	datastream_type_string = spx_datastream(datastream_type);
	if (datastream_type_string != NULL) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
			    datastream_type_string);
	}
	if (tree) {
		if (datastream_type_string != NULL) {
			proto_tree_add_uint_format_value(spx_tree, hf_spx_datastream_type, tvb,
						   1, 1, datastream_type,
						   "%s (0x%02X)",
						   datastream_type_string,
						   datastream_type);
		} else {
			proto_tree_add_uint_format_value(spx_tree, hf_spx_datastream_type, tvb,
						   1, 1, datastream_type,
						   "0x%02X",
						   datastream_type);
		}
		proto_tree_add_item(spx_tree, hf_spx_src_id, tvb,  2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(spx_tree, hf_spx_dst_id, tvb,  4, 2, ENC_BIG_ENDIAN);
	}
	spx_seq = tvb_get_ntohs(tvb, 6);
	if (tree) {
		proto_tree_add_uint(spx_tree, hf_spx_seq_nr, tvb,  6, 2, spx_seq);
		proto_tree_add_item(spx_tree, hf_spx_ack_nr, tvb,  8, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(spx_tree, hf_spx_all_nr, tvb, 10, 2, ENC_BIG_ENDIAN);
		/*  field exists on ALL SPXII packets EXCEPT the first packet of
		 *  the session.  The first packet can be determined by checking
		 *  the destination ID field for a value of 0xffff (65535) and
		 *  that the SPXII bit is set in Connection Control.
		 */
		if ((conn_ctrl & SPX_VII_PACKET) && tvb_get_ntohs(tvb, 4) != 0xffff) {
			proto_tree_add_item(spx_tree, hf_spx_neg_size, tvb, 12, 2, ENC_BIG_ENDIAN);
		}
	}

	/*
	 * SPX is Connection Oriented and Delivery Guaranteed.
	 * On the first pass, we need to flag retransmissions by the SPX
	 * protocol, so that subdissectors know whether a packet was
	 * retransmitted.
	 *
	 * We start out by creating a conversation for this direction of the
	 * IPX session; we use "pinfo->srcport" twice, so that we have
	 * separate conversations for the two directions.
	 *
	 * XXX - that might not work correctly if there's more than one
	 * SPX session using that source port; can that happen?  If so,
	 * we should probably use the direction, as well as the conversation,
	 * as part of the hash key; if we do that, we can probably just
	 * use CONVERSATION_IPX as the port type, and possibly get rid of CONVERSATION_NCP.
	 *
	 * According to
	 *
	 *	http://developer.novell.com/research/appnotes/1995/december/03/apv.htm
	 *
	 * the sequence number is not incremented for system packets, so
	 * presumably that means there is no notion of a system packet
	 * being retransmitted; that document also says that system
	 * packets are used as "I'm still here" keepalives and as
	 * acknowledgements (presumably meaning ACK-only packets), which
	 * suggests that they might not be ACKed and thus might not
	 * be retransmitted.
	 */
	if (conn_ctrl & SPX_SYS_PACKET) {
		/*
		 * It's a system packet, so it isn't a retransmission.
		 */
		spx_rexmit_info_p = NULL;
	} else {
		/*
		 * Not a system packet - check for retransmissions.
		 */
		if (!pinfo->fd->visited) {
			conversation = find_conversation(pinfo->num, &pinfo->src,
			    &pinfo->dst, CONVERSATION_NCP, pinfo->srcport,
			    pinfo->srcport, 0);
			if (conversation == NULL) {
				/*
				 * It's not part of any conversation - create
				 * a new one.
				 */
				conversation = conversation_new(pinfo->num, &pinfo->src,
				    &pinfo->dst, CONVERSATION_NCP, pinfo->srcport,
				    pinfo->srcport, 0);
			}

			/*
			 * Now we'll hash the SPX header and use the result
			 * of that, plus the conversation, as a hash key to
			 * identify this packet.
			 *
			 * If we don't find it in the hash table, it's not a
			 * retransmission, otherwise it is.  If we don't find
			 * it, we enter it into the hash table, with the
			 * frame number.
			 * If we do, we attach to this frame a structure giving
			 * the frame number of the original transmission, so
			 * that we, and subdissectors, know it's a
			 * retransmission.
			 */
			src = tvb_get_ntohs(tvb, 0)+tvb_get_ntohs(tvb, 2)+tvb_get_ntohs(tvb, 4)+tvb_get_ntohs(tvb, 6)+tvb_get_ntohs(tvb, 8);
			pkt_value = spx_hash_lookup(conversation, src, spx_seq);
			if (pkt_value == NULL) {
				/*
				 * Not found in the hash table.
				 * Enter it into the hash table.
				 */
				pkt_value = spx_hash_insert(conversation, src,
				    spx_seq);
				pkt_value->spx_ack = tvb_get_ntohs(tvb, 8);
				pkt_value->spx_all = tvb_get_ntohs(tvb, 10);
				pkt_value->num = pinfo->num;

				/*
				 * This is not a retransmission, so we shouldn't
				 * have any retransmission indicator.
				 */
				spx_rexmit_info_p = NULL;
			} else {
				/*
				 * Found in the hash table.  Mark this frame as
				 * a retransmission.
				 */
				spx_rexmit_info_p = wmem_new(wmem_file_scope(), spx_rexmit_info);
				spx_rexmit_info_p->num = pkt_value->num;
				p_add_proto_data(wmem_file_scope(), pinfo, proto_spx, 0,
				    spx_rexmit_info_p);
			}
		} else {
			/*
			 * Do we have per-packet SPX data for this frame?
			 * If so, it's a retransmission, and the per-packet
			 * data indicates which frame had the original
			 * transmission.
			 */
			spx_rexmit_info_p = (spx_rexmit_info *)p_get_proto_data(wmem_file_scope(), pinfo,
			    proto_spx, 0);
		}
	}

	/*
	 * It's a retransmission if we have a retransmission indicator.
	 * Flag this as a retransmission, but don't pass it to the
	 * subdissector.
	 */
	if (spx_rexmit_info_p != NULL) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
			    "[Retransmission] Original Packet %u",
			    spx_rexmit_info_p->num);

		if (tree) {
			proto_tree_add_uint_format(spx_tree, hf_spx_rexmt_frame,
			    tvb, 0, 0, spx_rexmit_info_p->num,
			    "This is a retransmission of frame %u",
			    spx_rexmit_info_p->num);
			if (tvb_reported_length_remaining(tvb, hdr_len) > 0) {
				proto_tree_add_item(spx_tree, hf_spx_rexmt_data, tvb, hdr_len, -1, ENC_NA);
			}
		}
		return tvb_captured_length(tvb);
	}

	if (tvb_reported_length_remaining(tvb, hdr_len) > 0) {
		/*
		 * Call subdissectors based on the IPX socket numbers; a
		 * subdissector might have registered with our IPX socket
		 * dissector table rather than the IPX dissector's socket
		 * dissector table.
		 *
		 * Assume the lower-numbered socket number is more likely
		 * to be the right one, along the lines of what we do for
		 * TCP and UDP.  We've seen NCP packets with a type of NCP,
		 * a source socket of IPX_SOCKET_NCP, and a destination
		 * socket of IPX_SOCKET_IPX_MESSAGE, and we've seen NCP
		 * packets with a type of NCP, a source socket of
		 * IPX_SOCKET_IPX_MESSAGE, and a destination socket of
		 * IPX_SOCKET_NCP.
		 */
		if (pinfo->srcport > pinfo->destport) {
			low_socket = pinfo->destport;
			high_socket = pinfo->srcport;
		} else {
			low_socket = pinfo->srcport;
			high_socket = pinfo->destport;
		}

		/*
		 * Pass information to subdissectors.
		 */
		spx_infox.eom = conn_ctrl & SPX_EOM;
		spx_infox.datastream_type = datastream_type;

		next_tvb = tvb_new_subset_remaining(tvb, hdr_len);
		if (dissector_try_uint_new(spx_socket_dissector_table, low_socket,
		    next_tvb, pinfo, tree, FALSE, &spx_infox))
		{
			return tvb_captured_length(tvb);
		}
		if (dissector_try_uint_new(spx_socket_dissector_table, high_socket,
		    next_tvb, pinfo, tree, FALSE, &spx_infox))
		{
			return tvb_captured_length(tvb);
		}
		call_data_dissector(next_tvb, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

/* ================================================================= */
/* IPX Message                                                       */
/* ================================================================= */
static int
dissect_ipxmsg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*msg_tree;
	proto_item	*ti;
	guint8		conn_number, sig_char;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPX MSG");
	col_clear(pinfo->cinfo, COL_INFO);

	conn_number = tvb_get_guint8(tvb, 0);
	sig_char = tvb_get_guint8(tvb, 1);

	col_add_fstr(pinfo->cinfo, COL_INFO,
			"%s, Connection %d",
			val_to_str_const(sig_char, ipxmsg_sigchar_vals, "Unknown Signature Character"), conn_number);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ipxmsg, tvb, 0, -1, ENC_NA);
		msg_tree = proto_item_add_subtree(ti, ett_ipxmsg);

		proto_tree_add_uint(msg_tree, hf_msg_conn, tvb, 0, 1, conn_number);
		proto_tree_add_uint(msg_tree, hf_msg_sigchar, tvb, 1, 1, sig_char);
	}
	return tvb_captured_length(tvb);
}


/* ================================================================= */
/* IPX RIP                                                           */
/* ================================================================= */
static const value_string ipxrip_packet_vals[] = {
	{ IPX_RIP_REQUEST,    "Request"},
	{ IPX_RIP_RESPONSE,   "Response"},
	{ 0,            NULL}
};

static int
dissect_ipxrip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*rip_tree;
	proto_item	*ti, *hidden_item;
	guint16		operation, ticks;
	guint		cursor;
	guint		available_length;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPX RIP");
	col_clear(pinfo->cinfo, COL_INFO);

	operation = tvb_get_ntohs(tvb, 0);

	/* rip_types 0 and 1 are valid, anything else becomes 2 or "Unknown" */
	col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(operation, ipxrip_packet_vals, "Unknown"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ipxrip, tvb, 0, -1, ENC_NA);
		rip_tree = proto_item_add_subtree(ti, ett_ipxrip);

		proto_tree_add_item(rip_tree, hf_ipxrip_packet_type, tvb, 0, 2, ENC_BIG_ENDIAN);

		switch(operation)
		{
		case IPX_RIP_REQUEST:
			hidden_item = proto_tree_add_boolean(rip_tree,
						     hf_ipxrip_request,
						     tvb, 0, 2, 1);
			proto_item_set_hidden(hidden_item);
			break;
		case IPX_RIP_RESPONSE:
			hidden_item = proto_tree_add_boolean(rip_tree,
						     hf_ipxrip_response,
						     tvb, 0, 2, 1);
			proto_item_set_hidden(hidden_item);
			break;
		}

		available_length = tvb_reported_length(tvb);
		for (cursor =  2; cursor < available_length; cursor += 8) {
			ticks = tvb_get_ntohs(tvb, cursor+6);

			proto_tree_add_item(rip_tree, hf_ipxrip_route_vector, tvb, cursor, 4, ENC_NA);
			proto_tree_add_item(rip_tree, hf_ipxrip_hops, tvb, cursor+4, 2, ENC_BIG_ENDIAN);
			if (operation == IPX_RIP_REQUEST - 1) {
				proto_tree_add_item(rip_tree, hf_ipxrip_ticks, tvb, cursor+6, 2, ENC_BIG_ENDIAN);
			}
			else {
				proto_tree_add_uint_format_value(rip_tree, hf_ipxrip_ticks, tvb, cursor+6, 2, ticks,
					"%d ms", ticks * 1000 / 18);
			}
		}
	}
	return tvb_captured_length(tvb);
}

/* ================================================================= */
/* IPX Serialization                                                 */
/* ================================================================= */
static int
dissect_serialization(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*ser_tree = NULL;
	proto_item	*ti;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NW_SERIAL");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_serialization, tvb, 0, -1,
		    ENC_NA);
		ser_tree = proto_item_add_subtree(ti, ett_serialization);
	}

	col_add_fstr(pinfo->cinfo, COL_INFO, "Serial number %s",
		    tvb_bytes_to_str(pinfo->pool, tvb, 0, 6));

	proto_tree_add_item(ser_tree, hf_serial_number, tvb, 0, 6, ENC_NA);
	return tvb_captured_length(tvb);
}

/*
 * Some of these are from ncpfs, others are from the book,
 * others are from the page at
 *
 *	http://www.iana.org/assignments/novell-sap-numbers
 *
 * and some from the page at
 *
 *	http://www.rware.demon.co.uk/ipxsap.htm
 *
 * (see also the page at
 *
 *	http://developer.novell.com/research/appnotes/1998/february/03/06.htm
 *
 * which has a huge list - but many of the entries list only the
 * organization owning the SAP type, not what the type is for).
 */
static const value_string novell_server_vals[] = {
	{ 0x0000,	"Unknown" },
	{ 0x0001,	"User" },
	{ 0x0002,	"User Group" },
	{ 0x0003,	"Print Queue or Print Group" },
	{ 0x0004,	"File Server (SLIST source)" },
	{ 0x0005,	"Job Server" },
	{ 0x0006,	"Gateway" },
	{ 0x0007,	"Print Server or Silent Print Server" },
	{ 0x0008,	"Archive Queue" },
	{ 0x0009,	"Archive Server" },
	{ 0x000a,	"Job Queue" },
	{ 0x000b,	"Administration" },
	{ 0x000F,	"Novell TI-RPC" },
	{ 0x0017,	"Diagnostics" },
	{ 0x0020,	"NetBIOS" },
	{ 0x0021,	"NAS SNA Gateway" },
	{ 0x0023,	"NACS Async Gateway or Asynchronous Gateway" },
	{ 0x0024,	"Remote Bridge or Routing Service" },
	{ 0x0026,	"Bridge Server or Asynchronous Bridge Server" },
	{ 0x0027,	"TCP/IP Gateway Server" },
	{ 0x0028,	"Point to Point (Eicon) X.25 Bridge Server" },
	{ 0x0029,	"Eicon 3270 Gateway" },
	{ 0x002a,	"CHI Corp" },
	{ 0x002c,	"PC Chalkboard" },
	{ 0x002d,	"Time Synchronization Server or Asynchronous Timer" },
	{ 0x002e,	"ARCserve 5.0 / Palindrome Backup Director 4.x (PDB4)" },
	{ 0x0045,	"DI3270 Gateway" },
	{ 0x0047,	"Advertising Print Server" },
	{ 0x004a,	"NetBlazer Modems" },
	{ 0x004b,	"Btrieve VAP/NLM 5.0" },
	{ 0x004c,	"NetWare SQL VAP/NLM Server" },
	{ 0x004d,	"Xtree Network Version/NetWare XTree" },
	{ 0x0050,	"Btrieve VAP 4.11" },
	{ 0x0052,	"QuickLink (Cubix)" },
	{ 0x0053,	"Print Queue User" },
	{ 0x0058,	"Multipoint X.25 Eicon Router" },
	{ 0x0060,	"STLB/NLM" },
	{ 0x0064,	"ARCserve" },
	{ 0x0066,	"ARCserve 3.0" },
	{ 0x0072,	"WAN Copy Utility" },
	{ 0x007a,	"TES-NetWare for VMS" },
	{ 0x0092,	"WATCOM Debugger or Emerald Tape Backup Server" },
	{ 0x0095,	"DDA OBGYN" },
	{ 0x0098,	"NetWare Access Server (Asynchronous gateway)" },
	{ 0x009a,	"NetWare for VMS II or Named Pipe Server" },
	{ 0x009b,	"NetWare Access Server" },
	{ 0x009e,	"Portable NetWare Server or SunLink NVT" },
	{ 0x00a1,	"Powerchute APC UPS NLM" },
	{ 0x00aa,	"LAWserve" },
	{ 0x00ac,	"Compaq IDA Status Monitor" },
	{ 0x0100,	"PIPE STAIL" },
	{ 0x0102,	"LAN Protect Bindery" },
	{ 0x0103,	"Oracle DataBase Server" },
	{ 0x0107,	"NetWare 386 or RSPX Remote Console" },
	{ 0x010f,	"Novell SNA Gateway" },
	{ 0x0111,	"Test Server" },
	{ 0x0112,	"Print Server (HP)" },
	{ 0x0114,	"CSA MUX (f/Communications Executive)" },
	{ 0x0115,	"CSA LCA (f/Communications Executive)" },
	{ 0x0116,	"CSA CM (f/Communications Executive)" },
	{ 0x0117,	"CSA SMA (f/Communications Executive)" },
	{ 0x0118,	"CSA DBA (f/Communications Executive)" },
	{ 0x0119,	"CSA NMA (f/Communications Executive)" },
	{ 0x011a,	"CSA SSA (f/Communications Executive)" },
	{ 0x011b,	"CSA STATUS (f/Communications Executive)" },
	{ 0x011e,	"CSA APPC (f/Communications Executive)" },
	{ 0x0126,	"SNA TEST SSA Profile" },
	{ 0x012a,	"CSA TRACE (f/Communications Executive)" },
	{ 0x012b,	"NetWare for SAA" },
	{ 0x012e,	"IKARUS virus scan utility" },
	{ 0x0130,	"Communications Executive" },
	{ 0x0133,	"NNS Domain Server or NetWare Naming Services Domain" },
	{ 0x0135,	"NetWare Naming Services Profile" },
	{ 0x0137,	"NetWare 386 Print Queue or NNS Print Queue" },
	{ 0x0141,	"LAN Spool Server (Vap, Intel)" },
	{ 0x0152,	"IRMALAN Gateway" },
	{ 0x0154,	"Named Pipe Server" },
	{ 0x0166,	"NetWare Management" },
	{ 0x0168,	"Intel PICKIT Comm Server or Intel CAS Talk Server" },
	{ 0x0173,	"Compaq" },
	{ 0x0174,	"Compaq SNMP Agent" },
	{ 0x0175,	"Compaq" },
	{ 0x0180,	"XTree Server or XTree Tools" },
	{ 0x018A,	"NASI services broadcast server (Novell)" },
	{ 0x01b0,	"GARP Gateway (net research)" },
	{ 0x01b1,	"Binfview (Lan Support Group)" },
	{ 0x01bf,	"Intel LanDesk Manager" },
	{ 0x01ca,	"AXTEC" },
	{ 0x01cb,	"Shiva NetModem/E" },
	{ 0x01cc,	"Shiva LanRover/E" },
	{ 0x01cd,	"Shiva LanRover/T" },
	{ 0x01ce,	"Shiva Universal" },
	{ 0x01d8,	"Castelle FAXPress Server" },
	{ 0x01da,	"Castelle LANPress Print Server" },
	{ 0x01dc,	"Castelle FAX/Xerox 7033 Fax Server/Excel Lan Fax" },
	{ 0x01f0,	"LEGATO" },
	{ 0x01f5,	"LEGATO" },
	{ 0x0233,	"NMS Agent or NetWare Management Agent" },
	{ 0x0237,	"NMS IPX Discovery or LANtern Read/Write Channel" },
	{ 0x0238,	"NMS IP Discovery or LANtern Trap/Alarm Channel" },
	{ 0x023a,	"LANtern" },
	{ 0x023c,	"MAVERICK" },
	{ 0x023f,	"SMS Testing and Development" },
	{ 0x024e,	"NetWare Connect" },
	{ 0x024f,	"NASI server broadcast (Cisco)" },
	{ 0x026a,	"Network Management (NMS) Service Console" },
	{ 0x026b,	"Time Synchronization Server (NetWare 4.x)" },
	{ 0x0278,	"Directory Server (NetWare 4.x)" },
	{ 0x027b,	"NetWare Management Agent" },
	{ 0x0280,	"Novell File and Printer Sharing Service for PC" },
	{ 0x0304,	"Novell SAA Gateway" },
	{ 0x0308,	"COM or VERMED 1" },
	{ 0x030a,	"Galacticomm's Worldgroup Server" },
	{ 0x030c,	"Intel Netport 2 or HP JetDirect or HP Quicksilver" },
	{ 0x0320,	"Attachmate Gateway" },
	{ 0x0327,	"Microsoft Diagnostics" },
	{ 0x0328,	"WATCOM SQL server" },
	{ 0x0335,	"MultiTech Systems Multisynch Comm Server" },
	{ 0x0343,	"Xylogics Remote Access Server or LAN Modem" },
	{ 0x0355,	"Arcada Backup Exec" },
	{ 0x0358,	"MSLCD1" },
	{ 0x0361,	"NETINELO" },
	{ 0x037e,	"Powerchute UPS Monitoring" },
	{ 0x037f,	"ViruSafe Notify" },
	{ 0x0386,	"HP Bridge" },
	{ 0x0387,	"HP Hub" },
	{ 0x0394,	"NetWare SAA Gateway" },
	{ 0x039b,	"Lotus Notes" },
	{ 0x03b7,	"Certus Anti Virus NLM" },
	{ 0x03c4,	"ARCserve 4.0 (Cheyenne)" },
	{ 0x03c7,	"LANspool 3.5 (Intel)" },
	{ 0x03d7,	"Lexmark printer server (type 4033-011)" },
	{ 0x03d8,	"Lexmark XLE printer server (type 4033-301)" },
	{ 0x03dd,	"Banyan ENS for NetWare Client NLM" },
	{ 0x03de,	"Gupta Sequel Base Server or NetWare SQL" },
	{ 0x03e1,	"Univel Unixware" },
	{ 0x03e4,	"Univel Unixware" },
	{ 0x03fc,	"Intel Netport" },
	{ 0x03fd,	"Intel Print Server Queue" },
	{ 0x040A,	"ipnServer" },
	{ 0x040D,	"LVERRMAN" },
	{ 0x040E,	"LVLIC" },
	{ 0x0414,	"NET Silicon (DPI)/Kyocera" },
	{ 0x0429,	"Site Lock Virus (Brightworks)" },
	{ 0x0432,	"UFHELP R" },
	{ 0x0433,	"Synoptics 281x Advanced SNMP Agent" },
	{ 0x0444,	"Microsoft NT SNA Server" },
	{ 0x0448,	"Oracle" },
	{ 0x044c,	"ARCserve 5.01" },
	{ 0x0457,	"Canon GP55 Running on a Canon GP55 network printer" },
	{ 0x045a,	"QMS Printers" },
	{ 0x045b,	"Dell SCSI Array (DSA) Monitor" },
	{ 0x0491,	"NetBlazer Modems" },
	{ 0x04ac,	"On-Time Scheduler NLM" },
	{ 0x04b0,	"CD-Net (Meridian)" },
	{ 0x0513,	"Emulex NQA" },
	{ 0x0520,	"Site Lock Checks" },
	{ 0x0529,	"Site Lock Checks (Brightworks)" },
	{ 0x052d,	"Citrix OS/2 App Server" },
	{ 0x0535,	"Tektronix" },
	{ 0x0536,	"Milan" },
	{ 0x055d,	"Attachmate SNA gateway" },
	{ 0x056b,	"IBM 8235 modem server" },
	{ 0x056c,	"Shiva LanRover/E PLUS" },
	{ 0x056d,	"Shiva LanRover/T PLUS" },
	{ 0x0580,	"McAfee's NetShield anti-virus" },
	{ 0x05B8,	"NLM to workstation communication (Revelation Software)" },
	{ 0x05BA,	"Compatible Systems Routers" },
	{ 0x05BE,	"Cheyenne Hierarchical Storage Manager" },
	{ 0x0606,	"JCWatermark Imaging" },
	{ 0x060c,	"AXIS Network Printer" },
	{ 0x0610,	"Adaptec SCSI Management" },
	{ 0x0621,	"IBM AntiVirus NLM" },
	{ 0x0640,	"Microsoft Gateway Services for NetWare" },
/*	{ 0x0640,	"NT Server-RPC/GW for NW/Win95 User Level Sec" }, */
	{ 0x064e,	"Microsoft Internet Information Server" },
	{ 0x067b,	"Microsoft Win95/98 File and Print Sharing for NetWare" },
	{ 0x067c,	"Microsoft Win95/98 File and Print Sharing for NetWare" },
	{ 0x076C,	"Xerox" },
	{ 0x079b,	"Shiva LanRover/E 115" },
	{ 0x079c,	"Shiva LanRover/T 115" },
	{ 0x07B4,	"Cubix WorldDesk" },
	{ 0x07c1,	"Quarterdeck IWare Connect V3.x NLM" },
	{ 0x07c2,	"Quarterdeck IWare Connect V2.x NLM" },
	{ 0x0810,	"ELAN License Server Demo" },
	{ 0x0824,	"Shiva LanRover Access Switch/E" },
	{ 0x086a,	"ISSC collector NLMs" },
	{ 0x087f,	"ISSC DAS agent for AIX" },
	{ 0x0880,	"Intel Netport PRO" },
	{ 0x0881,	"Intel Netport PRO" },
	{ 0x0b29,	"Site Lock" },
	{ 0x0c29,	"Site Lock Applications" },
	{ 0x0c2c,	"Licensing Server" },
	{ 0x2101,	"Performance Technology Instant Internet" },
	{ 0x2380,	"LAI Site Lock" },
	{ 0x238c,	"Meeting Maker" },
	{ 0x4808,	"Site Lock Server or Site Lock Metering VAP/NLM" },
	{ 0x5555,	"Site Lock User" },
	{ 0x6312,	"Tapeware" },
	{ 0x6f00,	"Rabbit Gateway (3270)" },
	{ 0x7703,	"MODEM" },
	{ 0x8002,	"NetPort Printers (Intel) or LANport" },
	{ 0x8003,	"SEH InterCon Printserver" },
	{ 0x8008,	"WordPerfect Network Version" },
	{ 0x85BE,	"Cisco Enhanced Interior Routing Protocol (EIGRP)" },
	{ 0x8888,	"WordPerfect Network Version or Quick Network Management" },
	{ 0x9000,	"McAfee's NetShield anti-virus" },
	{ 0x9604,	"CSA-NT_MON" },
	{ 0xb6a8,	"Ocean Isle Reachout Remote Control" },
	{ 0xf11f,	"Site Lock Metering VAP/NLM" },
	{ 0xf1ff,	"Site Lock" },
	{ 0xf503,	"Microsoft SQL Server" },
	{ 0xf905,	"IBM Time and Place/2 application" },
	{ 0xfbfb,	"TopCall III fax server" },
	{ 0xffff,	"Any Service or Wildcard" },
	{ 0x0000,	NULL }
};

value_string_ext novell_server_vals_ext = VALUE_STRING_EXT_INIT(novell_server_vals);

static const value_string ipxsap_packet_vals[] = {
	{ IPX_SAP_GENERAL_QUERY,       "General Query"},
	{ IPX_SAP_GENERAL_RESPONSE,    "General Response"},
	{ IPX_SAP_NEAREST_QUERY,       "Nearest Query"},
	{ IPX_SAP_NEAREST_RESPONSE,    "Nearest Response"},
	{ 0,            NULL}
};

static int
dissect_ipxsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree	*sap_tree, *s_tree;
	proto_item	*ti, *hidden_item;
	guint		cursor;
	struct sap_query query;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPX SAP");
	col_clear(pinfo->cinfo, COL_INFO);

	query.query_type = tvb_get_ntohs(tvb, 0);
	query.server_type = tvb_get_ntohs(tvb, 2);

	col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(query.query_type, ipxsap_packet_vals, "Unknown Packet Type"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_sap, tvb, 0, -1, ENC_NA);
		sap_tree = proto_item_add_subtree(ti, ett_ipxsap);

		proto_tree_add_item(sap_tree, hf_sap_packet_type, tvb, 0, 2, ENC_BIG_ENDIAN);

		switch(query.query_type)
		{
		case IPX_SAP_GENERAL_QUERY:
		case IPX_SAP_NEAREST_QUERY:
			hidden_item = proto_tree_add_boolean(sap_tree,
						     hf_sap_response,
						     tvb, 0, 2, 1);
			proto_item_set_hidden(hidden_item);
			break;
		case IPX_SAP_GENERAL_RESPONSE:
		case IPX_SAP_NEAREST_RESPONSE:
			hidden_item = proto_tree_add_boolean(sap_tree,
						     hf_sap_request,
						     tvb, 0, 2, 1);
			proto_item_set_hidden(hidden_item);
			break;
		}

		if (query.query_type == IPX_SAP_GENERAL_RESPONSE ||
				query.query_type == IPX_SAP_NEAREST_RESPONSE) { /* responses */

			guint available_length = tvb_reported_length(tvb);
			for (cursor =  2; cursor < available_length; cursor += 64) {
				const guint8 *server_name;

				ti = proto_tree_add_item(sap_tree, hf_sap_server, tvb, cursor, 64, ENC_NA);
				s_tree = proto_item_add_subtree(ti, ett_ipxsap_server);

				proto_tree_add_item(s_tree, hf_sap_server_type, tvb, cursor, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item_ret_string(s_tree, hf_sap_server_name, tvb, cursor+2, 48, ENC_ASCII|ENC_NA, pinfo->pool, &server_name);
				proto_item_append_text(ti, ": %s", server_name);
				proto_tree_add_item(s_tree, hf_sap_server_network, tvb, cursor+50, 4, ENC_NA);
				proto_tree_add_item(s_tree, hf_sap_server_node, tvb, cursor+54, 6, ENC_NA);
				proto_tree_add_item(s_tree, hf_sap_server_socket, tvb, cursor+60, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(s_tree, hf_sap_server_intermediate_networks, tvb, cursor+62, 2, ENC_BIG_ENDIAN);
			}
		}
		else {  /* queries */
			proto_tree_add_item(sap_tree, hf_sap_server_type, tvb, 2, 2, ENC_BIG_ENDIAN);
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_register_ipx(void)
{
	static hf_register_info hf_ipx[] = {
		{ &hf_ipx_checksum,
		{ "Checksum",		"ipx.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ipx_src,
		{ "Source Address",	"ipx.src", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Source IPX Address  \"network.node\"", HFILL }},

		{ &hf_ipx_dst,
		{ "Destination Address",	"ipx.dst", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Destination IPX Address  \"network.node\"", HFILL }},
		{ &hf_ipx_addr,
		{ "Src/Dst Address",	"ipx.addr", FT_STRING, BASE_NONE, NULL, 0x0,
		  "Source or Destination IPX Address  \"network.node\"", HFILL }},

		{ &hf_ipx_len,
		{ "Length",		"ipx.len", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
			NULL, HFILL }},

		{ &hf_ipx_hops,
		{ "Transport Control (Hops)", "ipx.hops", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ipx_packet_type,
		{ "Packet Type",	"ipx.packet_type", FT_UINT8, BASE_HEX, VALS(ipx_packet_type_vals),
			0x0,
			NULL, HFILL }},

		{ &hf_ipx_dnet,
		{ "Destination Network","ipx.dst.net", FT_IPXNET, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ipx_dnode,
		{ "Destination Node",	"ipx.dst.node", FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ipx_dsocket,
		{ "Destination Socket",	"ipx.dst.socket", FT_UINT16, BASE_HEX|BASE_EXT_STRING,
			&ipx_socket_vals_ext, 0x0,
			NULL, HFILL }},

		{ &hf_ipx_snet,
		{ "Source Network","ipx.src.net", FT_IPXNET, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ipx_snode,
		{ "Source Node",	"ipx.src.node", FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ipx_ssocket,
		{ "Source Socket",	"ipx.src.socket", FT_UINT16, BASE_HEX|BASE_EXT_STRING,
			&ipx_socket_vals_ext, 0x0,
			NULL, HFILL }},

		{ &hf_ipx_net,
		{ "Source or Destination Network","ipx.net", FT_IPXNET, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ipx_node,
		{ "Source or Destination Node", "ipx.node", FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ipx_socket,
		{ "Source or Destination Socket", "ipx.socket", FT_UINT16, BASE_HEX|BASE_EXT_STRING,
			&ipx_socket_vals_ext, 0x0,
			NULL, HFILL }},
	};

	static hf_register_info hf_spx[] = {
		{ &hf_spx_connection_control,
		{ "Connection Control",	"spx.ctl",
		  FT_UINT8,	BASE_HEX,	VALS(conn_vals),	0xF0,
		  NULL, HFILL }},

		{ &hf_spx_connection_control_sys,
		{ "System Packet",	"spx.ctl.sys",
		  FT_BOOLEAN,	8,	NULL,	SPX_SYS_PACKET,
		  NULL, HFILL }},

		{ &hf_spx_connection_control_send_ack,
		{ "Send Ack",		"spx.ctl.send_ack",
		  FT_BOOLEAN,	8,	NULL,	SPX_SEND_ACK,
		  NULL, HFILL }},

		{ &hf_spx_connection_control_attn,
		{ "Attention",		"spx.ctl.attn",
		  FT_BOOLEAN,	8,	NULL,	SPX_ATTN,
		  NULL, HFILL }},

		{ &hf_spx_connection_control_eom,
		{ "End of Message",	"spx.ctl.eom",
		  FT_BOOLEAN,	8,	NULL,	SPX_EOM,
		  NULL, HFILL }},

		{ &hf_spx_connection_control_v2,
		{ "SPXII Packet",	"spx.ctl.v2",
		  FT_BOOLEAN,	8,	NULL,	SPX_VII_PACKET,
		  NULL, HFILL }},

		{ &hf_spx_connection_control_neg_size,
		{ "Negotiate Size",	"spx.ctl.neg_size",
		  FT_BOOLEAN,	8,	NULL,	SPX_NEG_SIZE,
		  NULL, HFILL }},

		{ &hf_spx_connection_control_reserved,
		{ "Reserved",		"spx.ctl.reserved",
		  FT_BOOLEAN,	8,	NULL,	SPX_RESERVED,
		  NULL, HFILL }},

		{ &hf_spx_connection_control_ext_header,
		{ "Extended Header",	"spx.ctl.ext_header",
		  FT_BOOLEAN,	8,	NULL,	SPX_EXT_HEADER,
		  NULL, HFILL }},

		{ &hf_spx_datastream_type,
		{ "Datastream Type",	       	"spx.type",
		  FT_UINT8,	BASE_HEX,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_spx_src_id,
		{ "Source Connection ID",	"spx.src",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_spx_dst_id,
		{ "Destination Connection ID",	"spx.dst",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_spx_seq_nr,
		{ "Sequence Number",		"spx.seq",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_spx_ack_nr,
		{ "Acknowledgment Number",	"spx.ack",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_spx_all_nr,
		{ "Allocation Number",		"spx.alloc",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_spx_neg_size,
		{ "Negotiation Size",		"spx.neg_size",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_spx_rexmt_frame,
		{ "Retransmitted Frame Number",	"spx.rexmt_frame",
		  FT_FRAMENUM,	BASE_NONE,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_spx_rexmt_data,
		{ "Retransmitted data",	"spx.rexmt_data",
		  FT_BYTES,	BASE_NONE,	NULL,	0x0,
		  NULL, HFILL }},
	};

	static hf_register_info hf_ipxrip[] = {
		{ &hf_ipxrip_request,
		{ "Request",			"ipxrip.request",
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if IPX RIP request", HFILL }},

		{ &hf_ipxrip_response,
		{ "Response",			"ipxrip.response",
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if IPX RIP response", HFILL }},

		{ &hf_ipxrip_packet_type,
		{ "RIP packet type",			"ipxrip.packet_type",
		  FT_UINT16,	BASE_DEC,	VALS(ipxrip_packet_vals),	0x0,
		  NULL, HFILL }},

		{ &hf_ipxrip_route_vector,
		{ "Route Vector",			"ipxrip.route_vector",
		  FT_IPXNET,	BASE_NONE,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_ipxrip_hops,
		{ "Hops",			"ipxrip.hops",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_ipxrip_ticks,
		{ "Ticks",			"ipxrip.ticks",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  NULL, HFILL }},
	};

	static hf_register_info hf_sap[] = {
		{ &hf_sap_request,
		{ "Request",			"ipxsap.request",
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if SAP request", HFILL }},

		{ &hf_sap_response,
		{ "Response",			"ipxsap.response",
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if SAP response", HFILL }},

		{ &hf_sap_packet_type,
		{ "SAP packet type",		"ipxsap.packet_type",
		  FT_UINT16,	BASE_DEC,	VALS(ipxsap_packet_vals), 0x0,
		  NULL, HFILL }},

		{ &hf_sap_server,
		{ "Server",			"ipxsap.server",
		  FT_NONE,	BASE_NONE,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_sap_server_type,
		{ "Server Type",		"ipxsap.server.type",
		  FT_UINT16,	BASE_HEX|BASE_EXT_STRING, &novell_server_vals_ext, 0x0,
		  NULL, HFILL }},

		{ &hf_sap_server_name,
		{ "Server Name",		"ipxsap.server.name",
		  FT_STRINGZTRUNC,	BASE_NONE,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_sap_server_network,
		{ "Network",			"ipxsap.server.network",
		  FT_IPXNET,	BASE_NONE,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_sap_server_node,
		{ "Node",			"ipxsap.server.node",
		  FT_ETHER,	BASE_NONE,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_sap_server_socket,
		{ "Socket",			"ipxsap.server.socket",
		  FT_UINT16,	BASE_HEX|BASE_EXT_STRING, &ipx_socket_vals_ext, 0x0,
		  NULL, HFILL }},

		{ &hf_sap_server_intermediate_networks,
		{ "Intermediate Networks",	"ipxsap.server.intermediate_networks",
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  NULL, HFILL }},
	};

	static hf_register_info hf_ipxmsg[] = {
		{ &hf_msg_conn,
		{ "Connection Number",			"ipxmsg.conn",
		  FT_UINT8,	BASE_DEC,	NULL,	0x0,
		  NULL, HFILL }},

		{ &hf_msg_sigchar,
		{ "Signature Character",		"ipxmsg.sigchar",
		  FT_CHAR,	BASE_HEX,	VALS(ipxmsg_sigchar_vals),	0x0,
		  NULL, HFILL }}
	};

	static hf_register_info hf_serial[] = {
		{ &hf_serial_number,
		{ "Serial number",			"nw_serial.serial_number",
		  FT_BYTES,	BASE_NONE,	NULL,	0x0,
		  NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_ipx,
		&ett_spx,
		&ett_spx_connctrl,
		&ett_ipxmsg,
		&ett_ipxrip,
		&ett_serialization,
		&ett_ipxsap,
		&ett_ipxsap_server,
	};

	proto_ipx = proto_register_protocol("Internetwork Packet eXchange",
	    "IPX", "ipx");
	proto_register_field_array(proto_ipx, hf_ipx, array_length(hf_ipx));

	ipx_handle = register_dissector("ipx", dissect_ipx, proto_ipx);

	proto_spx = proto_register_protocol("Sequenced Packet eXchange",
	    "SPX", "spx");
	proto_register_field_array(proto_spx, hf_spx, array_length(hf_spx));

	proto_ipxrip = proto_register_protocol("IPX Routing Information Protocol",
	    "IPX RIP", "ipxrip");
	proto_register_field_array(proto_ipxrip, hf_ipxrip, array_length(hf_ipxrip));

	proto_serialization = proto_register_protocol("NetWare Serialization Protocol",
	    "NW_SERIAL", "nw_serial");
	proto_register_field_array(proto_serialization, hf_serial, array_length(hf_serial));

	proto_ipxmsg = proto_register_protocol("IPX Message", "IPX MSG",
	    "ipxmsg");
	proto_register_field_array(proto_ipxmsg, hf_ipxmsg, array_length(hf_ipxmsg));

	proto_sap = proto_register_protocol("Service Advertisement Protocol",
	    "IPX SAP", "ipxsap");
	ipxsap_handle = register_dissector("ipxsap", dissect_ipxsap, proto_sap);

	proto_register_field_array(proto_sap, hf_sap, array_length(hf_sap));

	proto_register_subtree_array(ett, array_length(ett));

	ipx_type_dissector_table = register_dissector_table("ipx.packet_type",
	    "IPX packet type", proto_ipx, FT_UINT8, BASE_HEX);
	ipx_socket_dissector_table = register_dissector_table("ipx.socket",
	    "IPX socket", proto_ipx, FT_UINT16, BASE_HEX);
	spx_socket_dissector_table = register_dissector_table("spx.socket",
	    "SPX socket", proto_spx, FT_UINT16, BASE_HEX);

	spx_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), spx_hash_func, spx_equal);
	ipx_tap=register_tap("ipx");

	register_conversation_table(proto_ipx, TRUE, ipx_conversation_packet, ipx_endpoint_packet);

	register_capture_dissector("ipx", capture_ipx, proto_ipx);
}

void
proto_reg_handoff_ipx(void)
{
	dissector_handle_t spx_handle;
	dissector_handle_t ipxrip_handle;
	dissector_handle_t serialization_handle, ipxmsg_handle;
	capture_dissector_handle_t ipx_cap_handle;

	dissector_add_uint_with_preference("udp.port", UDP_PORT_IPX, ipx_handle);
	dissector_add_uint("ethertype", ETHERTYPE_IPX, ipx_handle);
	dissector_add_uint("chdlc.protocol", ETHERTYPE_IPX, ipx_handle);
	dissector_add_uint("ppp.protocol", PPP_IPX, ipx_handle);
	dissector_add_uint("llc.dsap", SAP_NETWARE1, ipx_handle);
	dissector_add_uint("llc.dsap", SAP_NETWARE2, ipx_handle);
	dissector_add_uint("sll.ltype", LINUX_SLL_P_802_3, ipx_handle);
	dissector_add_uint("null.type", BSD_AF_IPX, ipx_handle);
	dissector_add_uint("gre.proto", ETHERTYPE_IPX, ipx_handle);
	dissector_add_uint("arcnet.protocol_id", ARCNET_PROTO_IPX, ipx_handle);
	dissector_add_uint("arcnet.protocol_id", ARCNET_PROTO_NOVELL_EC, ipx_handle);

	spx_handle = create_dissector_handle(dissect_spx, proto_spx);
	dissector_add_uint("ipx.packet_type", IPX_PACKET_TYPE_SPX, spx_handle);

	dissector_add_uint("ipx.socket", IPX_SOCKET_SAP, ipxsap_handle);

	ipxrip_handle = create_dissector_handle(dissect_ipxrip, proto_ipxrip);
	dissector_add_uint("ipx.socket", IPX_SOCKET_IPXRIP, ipxrip_handle);

	serialization_handle = create_dissector_handle(dissect_serialization,
	    proto_serialization);
	dissector_add_uint("ipx.socket", IPX_SOCKET_SERIALIZATION,
	    serialization_handle);

	ipxmsg_handle = create_dissector_handle(dissect_ipxmsg, proto_ipxmsg);
	dissector_add_uint("ipx.socket", IPX_SOCKET_IPX_MESSAGE, ipxmsg_handle);
	dissector_add_uint("ipx.socket", IPX_SOCKET_IPX_MESSAGE1, ipxmsg_handle);

	ipx_cap_handle = find_capture_dissector("ipx");
	capture_dissector_add_uint("ethertype", ETHERTYPE_IPX, ipx_cap_handle);
	capture_dissector_add_uint("ppp_hdlc", PPP_IPX, ipx_cap_handle);
	capture_dissector_add_uint("sll.ltype", LINUX_SLL_P_802_3, ipx_cap_handle);
	capture_dissector_add_uint("llc.dsap", SAP_NETWARE1, ipx_cap_handle);
	capture_dissector_add_uint("llc.dsap", SAP_NETWARE2, ipx_cap_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
