/* packet-ipx.c
 * Routines for NetWare's IPX
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-ipx.c,v 1.69 2000/11/17 21:00:35 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "etypes.h"
#include "ppptypes.h"
#include "llcsaps.h"
#include "aftypes.h"
#include "packet.h"
#include "packet-ipx.h"
#include "packet-nbipx.h"
#include "resolv.h"

#include "packet-snmp.h"

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
static int hf_ipx_hops = -1;
static int hf_ipx_packet_type = -1;
static int hf_ipx_dnet = -1;
static int hf_ipx_dnode = -1;
static int hf_ipx_dsocket = -1;
static int hf_ipx_snet = -1;
static int hf_ipx_snode = -1;
static int hf_ipx_ssocket = -1;

static gint ett_ipx = -1;

static dissector_table_t ipx_type_dissector_table;
static dissector_table_t ipx_socket_dissector_table;

static int proto_spx = -1;
static int hf_spx_connection_control = -1;
static int hf_spx_datastream_type = -1;
static int hf_spx_src_id = -1;
static int hf_spx_dst_id = -1;
static int hf_spx_seq_nr = -1;
static int hf_spx_ack_nr = -1;
static int hf_spx_all_nr = -1;

static gint ett_spx = -1;

static int proto_ipxrip = -1;
static int hf_ipxrip_request = -1;
static int hf_ipxrip_response = -1;

static gint ett_ipxrip = -1;

static int proto_sap = -1;
static int hf_sap_request = -1;
static int hf_sap_response = -1;

static gint ett_ipxsap = -1;
static gint ett_ipxsap_server = -1;

static gint ett_ipxmsg = -1;
static int proto_ipxmsg = -1;
static int hf_msg_conn = -1;
static int hf_msg_sigchar = -1;

static void
dissect_spx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_ipxrip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_ipxsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_ipxmsg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#define UDP_PORT_IPX    213		/* RFC 1234 */

#define IPX_HEADER_LEN	30		/* It's *always* 30 bytes */

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
	{ IPX_SOCKET_NWLINK_SMB_NAMEQUERY,	"NWLink SMB Name Query" },
	{ IPX_SOCKET_NWLINK_SMB_DGRAM,		"NWLink SMB Datagram" },
	{ IPX_SOCKET_NWLINK_SMB_BROWSE,		"NWLink SMB Browse" },
	{ IPX_SOCKET_ATTACHMATE_GW,		"Attachmate Gateway" },
	{ IPX_SOCKET_IPX_MESSAGE,		"IPX Message" },
	{ IPX_SOCKET_SNMP_AGENT,		"SNMP Agent" },
	{ IPX_SOCKET_SNMP_SINK,			"SNMP Sink" },
	{ IPX_SOCKET_PING_NOVELL,		"Novell PING" },
	{ IPX_SOCKET_UDP_TUNNEL,		"UDP Tunnel" },
	{ IPX_SOCKET_TCP_TUNNEL,		"TCP Tunnel" },
	{ IPX_SOCKET_TCP_TUNNEL,		"TCP Tunnel" },
	{ IPX_SOCKET_ADSM,			"ADSM" },
	{ IPX_SOCKET_EIGRP,			"Cisco EIGRP for IPX" },
	{ IPX_SOCKET_WIDE_AREA_ROUTER,		"Wide Area Router" },
	{ 0x0000,				NULL }
};

static const char*
socket_text(guint16 socket)
{
	const char	*p;

	p = match_strval(socket, ipx_socket_vals);
	if (p) {
		return p;
	}
	else {
		return "Unknown";
	}
}

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
	{ 0, NULL }
};

gchar*
ipxnet_to_string(const guint8 *ad)
{
	guint32	addr = pntohl(ad);
	return ipxnet_to_str_punct(addr, ' ');
}

/* We use a different representation of hardware addresses
 * than ether_to_str(); we don't put punctuation between the hex
 * digits.
 */

gchar*
ipx_addr_to_str(guint32 net, const guint8 *ad)
{
	static gchar	str[3][8+1+MAXNAMELEN+1]; /* 8 digits, 1 period, NAME, 1 null */
	static gchar	*cur;
	char		*name;

	if (cur == &str[0][0]) {
		cur = &str[1][0];
	} else if (cur == &str[1][0]) {
		cur = &str[2][0];
	} else {
		cur = &str[0][0];
	}

	name = get_ether_name_if_known(ad);

	if (name) {
		sprintf(cur, "%s.%s", get_ipxnet_name(net), name);
	}
	else {
		sprintf(cur, "%s.%s", get_ipxnet_name(net), ether_to_str_punct(ad, '\0'));
	}
	return cur;
}

gchar *
ipxnet_to_str_punct(const guint32 ad, char punct)
{
  static gchar  str[3][12];
  static gchar *cur;
  gchar        *p;
  int          i;
  guint32      octet;
  static const gchar hex_digits[16] = "0123456789ABCDEF";
  static const guint32  octet_mask[4] =
	  { 0xff000000 , 0x00ff0000, 0x0000ff00, 0x000000ff };

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  p = &cur[12];
  *--p = '\0';
  i = 3;
  for (;;) {
    octet = (ad & octet_mask[i]) >> ((3 - i) * 8);
    *--p = hex_digits[octet&0xF];
    octet >>= 4;
    *--p = hex_digits[octet&0xF];
    if (i == 0)
      break;
    if (punct)
      *--p = punct;
    i--;
  }
  return p;
}

void
capture_ipx(const u_char *pd, int offset, packet_counts *ld)
{
	ld->ipx++;
}

void
dissect_ipx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t	*next_tvb;
	const guint8	*this_pd;
	int		this_offset, len;
	const guint8	*next_pd;
	int		next_offset;

	proto_tree	*ipx_tree;
	proto_item	*ti;

	guint8		*src_net_node, *dst_net_node;

	guint8		ipx_type, ipx_hops;
	guint16		ipx_length;
	int		reported_length, available_length;

	guint16		ipx_dsocket, ipx_ssocket;

	CHECK_DISPLAY_AS_DATA(proto_ipx, tvb, pinfo, tree);

	pinfo->current_proto = "IPX";

	/* Calculate here for use in pinfo and in tree */
	ipx_dsocket	= tvb_get_ntohs(tvb, 16);
	ipx_ssocket	= tvb_get_ntohs(tvb, 28);
	ipx_type	= tvb_get_guint8(tvb, 5);
	ipx_length	= tvb_get_ntohs(tvb, 2);

	/* Set the payload and captured-payload lengths to the minima of
	   (the IPX length plus the length of the headers above it) and
	   the frame lengths. XXX - remove once all dissectors use tvbuffs */
	tvb_compat(tvb, &this_pd, &this_offset);
	len = ipx_length + this_offset;
	if (pi.len > len)
		pi.len = len;
	if (pi.captured_len > len)
		pi.captured_len = len;

	src_net_node = tvb_get_ptr(tvb, 18, 10);
	dst_net_node = tvb_get_ptr(tvb, 6,  10);

	SET_ADDRESS(&pi.net_src,	AT_IPX, 10, src_net_node);
	SET_ADDRESS(&pi.src,		AT_IPX, 10, src_net_node);
	SET_ADDRESS(&pi.net_dst,	AT_IPX, 10, dst_net_node);
	SET_ADDRESS(&pi.dst,		AT_IPX, 10, dst_net_node);

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_add_str(pinfo->fd, COL_PROTOCOL, "IPX");
	if (check_col(pinfo->fd, COL_INFO))
		col_add_fstr(pinfo->fd, COL_INFO, "%s (0x%04X)",
				socket_text(ipx_dsocket), ipx_dsocket);

	if (tree) {

		ti = proto_tree_add_item(tree, proto_ipx, tvb, 0, IPX_HEADER_LEN, FALSE);
		ipx_tree = proto_item_add_subtree(ti, ett_ipx);

		proto_tree_add_item(ipx_tree, hf_ipx_checksum, tvb, 0, 2, FALSE);
		proto_tree_add_uint_format(ipx_tree, hf_ipx_len, tvb, 2, 2, ipx_length,
			"Length: %d bytes", ipx_length);
		ipx_hops = tvb_get_guint8(tvb, 4);
		proto_tree_add_uint_format(ipx_tree, hf_ipx_hops, tvb, 4, 1, ipx_hops,
			"Transport Control: %d hops", ipx_hops);
		proto_tree_add_uint(ipx_tree, hf_ipx_packet_type, tvb, 5, 1, ipx_type);

		/* Destination */
		proto_tree_add_item(ipx_tree, hf_ipx_dnet, tvb, 6, 4, FALSE);
		proto_tree_add_item(ipx_tree, hf_ipx_dnode, tvb, 10, 6, FALSE);
		proto_tree_add_uint_format(ipx_tree, hf_ipx_dsocket, tvb, 16, 2,
			ipx_dsocket, "Destination Socket: %s (0x%04X)",
			socket_text(ipx_dsocket), ipx_dsocket);

		/* Source */
		proto_tree_add_item(ipx_tree, hf_ipx_snet, tvb, 18, 4, FALSE);
		proto_tree_add_item(ipx_tree, hf_ipx_snode, tvb, 22, 6, FALSE);
		proto_tree_add_uint_format(ipx_tree, hf_ipx_ssocket, tvb, 28, 2,
			ipx_ssocket, "Source Socket: %s (0x%04X)", socket_text(ipx_ssocket),
			ipx_ssocket);
	}

	/* Make the next tvbuff */
	reported_length = ipx_length - IPX_HEADER_LEN;
	available_length = tvb_length(tvb) - IPX_HEADER_LEN;
	next_tvb = tvb_new_subset(tvb, IPX_HEADER_LEN,
			MIN(available_length, reported_length),
			reported_length);

	tvb_compat(next_tvb, &next_pd, &next_offset);

	if (dissector_try_port(ipx_type_dissector_table, ipx_type, next_tvb,
	    pinfo, tree))
		return;

	switch (ipx_type) {
		case IPX_PACKET_TYPE_WANBCAST:
		case IPX_PACKET_TYPE_PEP:
			if (ipx_dsocket == IPX_SOCKET_NETBIOS) {
				dissect_nbipx(next_tvb, pinfo, tree);
				return;
			}
			/* else fall through */

		case 0: /* IPX, fall through to default */
			/* XXX - should type 0's be dissected as NBIPX
			   if they're aimed at the NetBIOS socket? */
			break;
	}

	if (dissector_try_port(ipx_socket_dissector_table, ipx_dsocket,
	    next_tvb, pinfo, tree))
		return;
	if (dissector_try_port(ipx_socket_dissector_table, ipx_ssocket,
	    next_tvb, pinfo, tree))
		return;
	dissect_data(next_tvb, 0, pinfo, tree);
}


/* ================================================================= */
/* SPX                                                               */
/* ================================================================= */
static const char*
spx_conn_ctrl(guint8 ctrl)
{
	const char *p;

	static const value_string conn_vals[] = {
		{ 0x10, "End-of-Message" },
		{ 0x20, "Attention" },
		{ 0x40, "Acknowledgment Required"},
		{ 0x80, "System Packet"},
		{ 0x00, NULL }
	};

	p = match_strval(ctrl, conn_vals);

	if (p) {
		return p;
	}
	else {
		return "Unknown";
	}
}

static const char*
spx_datastream(guint8 type)
{
	switch (type) {
		case 0xfe:
			return "End-of-Connection";
		case 0xff:
			return "End-of-Connection Acknowledgment";
		default:
			return "Client-Defined";
	}
}

#define SPX_HEADER_LEN	12

static void
dissect_spx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*spx_tree;
	proto_item	*ti;
	tvbuff_t	*next_tvb;

	guint8		conn_ctrl;
	guint8		datastream_type;

	CHECK_DISPLAY_AS_DATA(proto_spx, tvb, pinfo, tree);

	pinfo->current_proto = "SPX";
	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_add_str(pinfo->fd, COL_PROTOCOL, "SPX");
	if (check_col(pinfo->fd, COL_INFO))
		col_add_str(pinfo->fd, COL_INFO, "SPX");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_spx, tvb, 0, SPX_HEADER_LEN, FALSE);
		spx_tree = proto_item_add_subtree(ti, ett_spx);

		conn_ctrl = tvb_get_guint8(tvb, 0);
		proto_tree_add_uint_format(spx_tree, hf_spx_connection_control, tvb,
					   0, 1, conn_ctrl,
					   "Connection Control: %s (0x%02X)",
					   spx_conn_ctrl(conn_ctrl), conn_ctrl);

		datastream_type = tvb_get_guint8(tvb, 1);
		proto_tree_add_uint_format(spx_tree, hf_spx_datastream_type, tvb,
					   1, 1, datastream_type,
					   "Datastream Type: %s (0x%02X)",
					   spx_datastream(datastream_type), datastream_type);

		proto_tree_add_item(spx_tree, hf_spx_src_id, tvb,  2, 2, FALSE);
		proto_tree_add_item(spx_tree, hf_spx_dst_id, tvb,  4, 2, FALSE);
		proto_tree_add_item(spx_tree, hf_spx_seq_nr, tvb,  6, 2, FALSE);
		proto_tree_add_item(spx_tree, hf_spx_ack_nr, tvb,  8, 2, FALSE);
		proto_tree_add_item(spx_tree, hf_spx_all_nr, tvb, 10, 2, FALSE);

		next_tvb = tvb_new_subset(tvb, SPX_HEADER_LEN, -1, -1);
		dissect_data(next_tvb, 0, pinfo, tree);
	}
}

/* ================================================================= */
/* IPX Message                                                       */
/* ================================================================= */
static void
dissect_ipxmsg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*msg_tree;
	proto_item	*ti;
	guint8		conn_number, sig_char;

	CHECK_DISPLAY_AS_DATA(proto_ipxmsg, tvb, pinfo, tree);

	pinfo->current_proto = "IPX MSG";

	if (check_col(pinfo->fd, COL_PROTOCOL))
	 col_add_str(pinfo->fd, COL_PROTOCOL, "IPX MSG");

	conn_number = tvb_get_guint8(tvb, 0);
	sig_char = tvb_get_guint8(tvb, 1);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_add_fstr(pinfo->fd, COL_INFO, 
			"%s, Connection %d", 
			val_to_str(sig_char, ipxmsg_sigchar_vals, "Unknown Signature Char"), conn_number);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ipxmsg, tvb, 0, tvb_length(tvb), FALSE);
		msg_tree = proto_item_add_subtree(ti, ett_ipxmsg);

		proto_tree_add_uint(msg_tree, hf_msg_conn, tvb, 0, 1, conn_number);
		proto_tree_add_uint(msg_tree, hf_msg_sigchar, tvb, 1, 1, sig_char);
	}
}


/* ================================================================= */
/* IPX RIP                                                           */
/* ================================================================= */
static void
dissect_ipxrip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*rip_tree;
	proto_item	*ti;
	guint16		operation;
	struct ipx_rt_def route;
	int		cursor;
	int		available_length;

	char		*rip_type[3] = { "Request", "Response", "Unknown" };

	CHECK_DISPLAY_AS_DATA(proto_ipxrip, tvb, pinfo, tree);

	pinfo->current_proto = "IPX RIP";
	if (check_col(pinfo->fd, COL_PROTOCOL))
	 col_add_str(pinfo->fd, COL_PROTOCOL, "IPX RIP");

	operation = tvb_get_ntohs(tvb, 0) - 1;

	if (check_col(pinfo->fd, COL_INFO)) {
		/* rip_types 0 and 1 are valid, anything else becomes 2 or "Unknown" */
		col_add_str(pinfo->fd, COL_INFO, rip_type[MIN(operation, 2)]);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ipxrip, tvb, 0, tvb_length(tvb), FALSE);
		rip_tree = proto_item_add_subtree(ti, ett_ipxrip);

		if (operation < 2) {
			proto_tree_add_text(rip_tree, tvb, 0, 2,
			"RIP packet type: %s", rip_type[operation]);

			if (operation == 0) {
			  proto_tree_add_boolean_hidden(rip_tree, 
						     hf_ipxrip_request, 
						     tvb, 0, 2, 1);
			} else {
			  proto_tree_add_boolean_hidden(rip_tree, 
						     hf_ipxrip_response, 
						     tvb, 0, 2, 1);
			}

		}
		else {
			proto_tree_add_text(rip_tree, tvb, 0, 2, "Unknown RIP packet type");
		}

		available_length = tvb_length(tvb);
		for (cursor =  2; cursor < available_length; cursor += 8) {
			memcpy(&route.network, tvb_get_ptr(tvb, cursor, 4), 4);
			route.hops = tvb_get_ntohs(tvb, cursor+4);
			route.ticks = tvb_get_ntohs(tvb, cursor+6);

			if (operation == IPX_RIP_REQUEST - 1) {
				proto_tree_add_text(rip_tree, tvb, cursor,      8,
					"Route Vector: %s, %d hop%s, %d tick%s",
					ipxnet_to_string((guint8*)&route.network),
					route.hops,  route.hops  == 1 ? "" : "s",
					route.ticks, route.ticks == 1 ? "" : "s");
			}
			else {
				proto_tree_add_text(rip_tree, tvb, cursor,      8,
					"Route Vector: %s, %d hop%s, %d tick%s (%d ms)",
					ipxnet_to_string((guint8*)&route.network),
					route.hops,  route.hops  == 1 ? "" : "s",
					route.ticks, route.ticks == 1 ? "" : "s",
					route.ticks * 1000 / 18);
			}
		}
	}
}



/* ================================================================= */
/* SAP	        							 */
/* ================================================================= */
static const char*
server_type(guint16 type)
{
	const char *p;

	/* some of these are from ncpfs, others are from the book */
	static const value_string server_vals[] = {
		{ 0x0001,	"User" },
		{ 0x0002,	"User Group" },
		{ 0x0003,	"Print Queue" },
		{ 0x0004,	"File server" },
		{ 0x0005,	"Job server" },
		{ 0x0007,	"Print server" },
		{ 0x0008,	"Archive server" },
		{ 0x0009,	"Archive server" },
		{ 0x000a,	"Job queue" },
		{ 0x000b,	"Administration" },
		{ 0x0021,	"NAS SNA gateway" },
		{ 0x0024,	"Remote bridge" },
		{ 0x0026,	"Bridge server" },
		{ 0x0027,	"TCP/IP gateway" },
		{ 0x002d,	"Time Synchronization VAP" },
		{ 0x002e,	"Archive Server Dynamic SAP" },
		{ 0x0047,	"Advertising print server" },
		{ 0x004b,	"Btrieve VAP 5.0" },
		{ 0x004c,	"SQL VAP" },
		{ 0x0050,	"Btrieve VAP" },
		{ 0x0053,	"Print Queue VAP" },
		{ 0x007a,	"TES NetWare for VMS" },
		{ 0x0098,	"NetWare access server" },
		{ 0x009a,	"Named Pipes server" },
		{ 0x009e,	"Portable NetWare Unix" },
		{ 0x0107,	"NetWare 386" },
		{ 0x0111,	"Test server" },
		{ 0x0133,	"NetWare Name Service" },
		{ 0x0166,	"NetWare management" },
		{ 0x023f,	"SMS Testing and Development" },
		{ 0x026a,	"NetWare management" },
		{ 0x026b,	"Time synchronization" },
		{ 0x027b,	"NetWare Management Agent" },
		{ 0x0278,	"NetWare Directory server" },
		{ 0x030c,	"HP LaserJet / Quick Silver" },
		{ 0x0355,	"Arcada Software" },
		{ 0x0361,	"NETINELO" },
		{ 0x037e,	"Powerchute UPS Monitoring" },
		{ 0x03e1,	"UnixWare Application Server" },
		{ 0x044c,	"Archive" },
		{ 0x055d,	"Attachmate SNA gateway" },
		{ 0x0610,	"Adaptec SCSI Management" },
		{ 0x0640,	"NT Server-RPC/GW for NW/Win95 User Level Sec" },
		{ 0x064e,	"NT Server-IIS" },
		{ 0x0810,	"ELAN License Server Demo" },
		{ 0x8002,	"Intel NetPort Print Server" },

/* For any unidentified ones, I found a really big list of them at: */
/*    http://www.inpnet.org/cnpweb/saplist.txt */
/*    http://www.isi.edu/in-notes/iana/assignments/novell-sap-numbers */

		{ 0x0000,	NULL }
	};

	p = match_strval(type, server_vals);
	if (p) {
		return p;
	}
	else {
		return "Unknown";
	}
}

static void
dissect_ipxsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*sap_tree, *s_tree;
	proto_item	*ti;
	int		cursor;
	struct sap_query query;
	struct sap_server_ident server;

	char		*sap_type[4] = { "General Query", "General Response",
		"Nearest Query", "Nearest Response" };

	CHECK_DISPLAY_AS_DATA(proto_sap, tvb, pinfo, tree);

	pinfo->current_proto = "IPX SAP";
	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_add_str(pinfo->fd, COL_PROTOCOL, "IPX SAP");

	query.query_type = tvb_get_ntohs(tvb, 0);
	query.server_type = tvb_get_ntohs(tvb, 2);

	if (check_col(pinfo->fd, COL_INFO)) {
		if (query.query_type >= 1 && query.query_type <= 4) {
			col_add_str(pinfo->fd, COL_INFO, sap_type[query.query_type - 1]);
		}
		else {
			col_add_str(pinfo->fd, COL_INFO, "Unknown Packet Type");
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_sap, tvb, 0, tvb_length(tvb), FALSE);
		sap_tree = proto_item_add_subtree(ti, ett_ipxsap);

		if (query.query_type >= 1 && query.query_type <= 4) {
			proto_tree_add_text(sap_tree, tvb, 0, 2, sap_type[query.query_type - 1]);
			if ((query.query_type - 1) % 2) {
			  proto_tree_add_boolean_hidden(sap_tree, 
						     hf_sap_response, 
						     tvb, 0, 2, 1);
			} else {
			  proto_tree_add_boolean_hidden(sap_tree, 
						     hf_sap_request, 
						     tvb, 0, 2, 1);
			}
		}
		else {
			proto_tree_add_text(sap_tree, tvb, 0, 2,
					"Unknown SAP Packet Type %d", query.query_type);
		}

		if (query.query_type == IPX_SAP_GENERAL_RESPONSE ||
				query.query_type == IPX_SAP_NEAREST_RESPONSE) { /* responses */

			int available_length = tvb_length(tvb);
			for (cursor =  2; (cursor + 64) <= available_length; cursor += 64) {
				server.server_type = tvb_get_ntohs(tvb, cursor);
				memcpy(server.server_name, tvb_get_ptr(tvb, cursor+2, 48), 48);
				memcpy(&server.server_network, tvb_get_ptr(tvb, cursor+50, 4), 4);
				memcpy(&server.server_node, tvb_get_ptr(tvb, cursor+54, 6), 6);
				server.server_port = tvb_get_ntohs(tvb, cursor+60);
				server.intermediate_network = tvb_get_ntohs(tvb, cursor+62);

				ti = proto_tree_add_text(sap_tree, tvb, cursor+2, 48,
					"Server Name: %s", server.server_name);
				s_tree = proto_item_add_subtree(ti, ett_ipxsap_server);

				proto_tree_add_text(s_tree, tvb, cursor, 2, "Server Type: %s (0x%04X)",
						server_type(server.server_type), server.server_type);
				proto_tree_add_text(s_tree, tvb, cursor+50, 4, "Network: %s",
						ipxnet_to_string((guint8*)tvb_get_ptr(tvb, cursor+50, 4)));
				proto_tree_add_text(s_tree, tvb, cursor+54, 6, "Node: %s",
						ether_to_str((guint8*)tvb_get_ptr(tvb, cursor+54, 6)));
				proto_tree_add_text(s_tree, tvb, cursor+60, 2, "Socket: %s (0x%04X)",
						socket_text(server.server_port), server.server_port);
				proto_tree_add_text(s_tree, tvb, cursor+62, 2,
						"Intermediate Networks: %d",
						server.intermediate_network);
			}
		}
		else {  /* queries */
			proto_tree_add_text(sap_tree, tvb, 2, 2, "Server Type: %s (0x%04X)",
					server_type(query.server_type), query.server_type);
		}
	}
}

void
proto_register_ipx(void)
{
	static hf_register_info hf_ipx[] = {
		{ &hf_ipx_checksum,
		{ "Checksum",		"ipx.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_ipx_len,
		{ "Length",		"ipx.len", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_ipx_hops,
		{ "Transport Control (Hops)", "ipx.hops", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_ipx_packet_type,
		{ "Packet Type",	"ipx.packet_type", FT_UINT8, BASE_HEX, VALS(ipx_packet_type_vals),
			0x0,
			"" }},

		{ &hf_ipx_dnet,
		{ "Destination Network","ipx.dst.net", FT_IPXNET, BASE_NONE, NULL, 0x0,
			"" }},

		{ &hf_ipx_dnode,
		{ "Destination Node",	"ipx.dst.node", FT_ETHER, BASE_NONE, NULL, 0x0,
			"" }},

		{ &hf_ipx_dsocket,
		{ "Destination Socket",	"ipx.dst.socket", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_ipx_snet,
		{ "Source Network","ipx.src.net", FT_IPXNET, BASE_NONE, NULL, 0x0,
			"" }},

		{ &hf_ipx_snode,
		{ "Source Node",	"ipx.src.node", FT_ETHER, BASE_NONE, NULL, 0x0,
			"" }},

		{ &hf_ipx_ssocket,
		{ "Source Socket",	"ipx.src.socket", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},
	};

	static hf_register_info hf_spx[] = {
		{ &hf_spx_connection_control,
		{ "Connection Control",		"spx.ctl", 
		  FT_UINT8,	BASE_HEX,	NULL,	0x0,
		  "" }},

		{ &hf_spx_datastream_type,
		{ "Datastream type",	       	"spx.type", 
		  FT_UINT8,	BASE_HEX,	NULL,	0x0,
		  "" }},

		{ &hf_spx_src_id,
		{ "Source Connection ID",	"spx.src", 
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "" }},

		{ &hf_spx_dst_id,
		{ "Destination Connection ID",	"spx.dst", 
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "" }},

		{ &hf_spx_seq_nr,
		{ "Sequence Number",		"spx.seq", 
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "" }},

		{ &hf_spx_ack_nr,
		{ "Acknowledgment Number",	"spx.ack", 
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "" }},

		{ &hf_spx_all_nr,
		{ "Allocation Number",		"spx.alloc", 
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "" }}
	};

	static hf_register_info hf_ipxrip[] = {
		{ &hf_ipxrip_request,
		{ "Request",			"ipxrip.request", 
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if IPX RIP request" }},

		{ &hf_ipxrip_response,
		{ "Response",			"ipxrip.response", 
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if IPX RIP response" }}
	};

	static hf_register_info hf_sap[] = {
		{ &hf_sap_request,
		{ "Request",			"ipxsap.request", 
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if SAP request" }},

		{ &hf_sap_response,
		{ "Response",			"ipxsap.response", 
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if SAP response" }}
	};

	static hf_register_info hf_ipxmsg[] = {
		{ &hf_msg_conn,
		{ "Connection Number",			"ipxmsg.conn", 
		  FT_UINT8,	BASE_NONE,	NULL,	0x0,
		  "Connection Number" }},

		{ &hf_msg_sigchar,
		{ "Signature Char",			"ipxmsg.sigchar", 
		  FT_UINT8,	BASE_NONE,	VALS(ipxmsg_sigchar_vals),	0x0,
		  "Signature Char" }}
	};

	static gint *ett[] = {
		&ett_ipx,
		&ett_spx,
		&ett_ipxmsg,
		&ett_ipxrip,
		&ett_ipxsap,
		&ett_ipxsap_server,
	};

	proto_ipx = proto_register_protocol ("Internetwork Packet eXchange", "ipx");
	proto_register_field_array(proto_ipx, hf_ipx, array_length(hf_ipx));

	proto_spx = proto_register_protocol ("Sequenced Packet eXchange", "spx");
	proto_register_field_array(proto_spx, hf_spx, array_length(hf_spx));

	proto_ipxrip = proto_register_protocol ("IPX Routing Information Protocol", "ipxrip");
	proto_register_field_array(proto_ipxrip, hf_ipxrip, array_length(hf_ipxrip));

	proto_ipxmsg = proto_register_protocol ("IPX Message", "ipxmsg");
	proto_register_field_array(proto_ipxmsg, hf_ipxmsg, array_length(hf_ipxmsg));

	proto_sap = proto_register_protocol ("Service Advertisement Protocol", "ipxsap");
	proto_register_field_array(proto_sap, hf_sap, array_length(hf_sap));

	proto_register_subtree_array(ett, array_length(ett));

	ipx_type_dissector_table = register_dissector_table("ipx.packet_type");
	ipx_socket_dissector_table = register_dissector_table("ipx.socket");
}

void
proto_reg_handoff_ipx(void)
{
	dissector_add("udp.port", UDP_PORT_IPX, dissect_ipx);
	dissector_add("ethertype", ETHERTYPE_IPX, dissect_ipx);
	dissector_add("ppp.protocol", PPP_IPX, dissect_ipx);
	dissector_add("llc.dsap", SAP_NETWARE, dissect_ipx);
	dissector_add("null.type", BSD_AF_IPX, dissect_ipx);
	dissector_add("ipx.packet_type", IPX_PACKET_TYPE_SPX, dissect_spx);
	dissector_add("ipx.socket", IPX_SOCKET_SAP, dissect_ipxsap);
	dissector_add("ipx.socket", IPX_SOCKET_IPXRIP, dissect_ipxrip);
	dissector_add("ipx.socket", IPX_SOCKET_IPX_MESSAGE, dissect_ipxmsg);
}
