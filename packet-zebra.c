/* packet-zebra.c
 * Routines for zebra packet disassembly
 *
 * Jochen Friedrich <jochen@scram.de>
 *
 * $Id: packet-zebra.c,v 1.5 2000/12/02 08:41:08 guy Exp $
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
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include "packet.h"

static int proto_zebra = -1;
static int hf_zebra_len = -1;
static int hf_zebra_command = -1;
static int hf_zebra_request = -1;
static int hf_zebra_interface = -1;
static int hf_zebra_index = -1;
static int hf_zebra_indexnum = -1;
static int hf_zebra_type = -1;
static int hf_zebra_intflags = -1;
static int hf_zebra_rtflags = -1;
static int hf_zebra_distance = -1;
static int hf_zebra_metric = -1;
static int hf_zebra_mtu = -1;
static int hf_zebra_bandwidth = -1;
static int hf_zebra_family = -1;
static int hf_zebra_message = -1;
static int hf_zebra_msg_nexthop = -1;
static int hf_zebra_msg_index = -1;
static int hf_zebra_msg_distance = -1;
static int hf_zebra_msg_metric = -1;
static int hf_zebra_nexthopnum = -1;
static int hf_zebra_nexthop4 = -1;
static int hf_zebra_nexthop6 = -1;
static int hf_zebra_dest4 = -1;
static int hf_zebra_dest6 = -1;
static int hf_zebra_prefixlen = -1;
static int hf_zebra_prefix4 = -1;
static int hf_zebra_prefix6 = -1;

static gint ett_zebra = -1;
static gint ett_zebra_request = -1;
static gint ett_message = -1;

#define TCP_PORT_ZEBRA			2600

/* Zebra message types. */
#define ZEBRA_INTERFACE_ADD                1
#define ZEBRA_INTERFACE_DELETE             2
#define ZEBRA_INTERFACE_ADDRESS_ADD        3
#define ZEBRA_INTERFACE_ADDRESS_DELETE     4
#define ZEBRA_INTERFACE_UP                 5
#define ZEBRA_INTERFACE_DOWN               6
#define ZEBRA_IPV4_ROUTE_ADD               7
#define ZEBRA_IPV4_ROUTE_DELETE            8
#define ZEBRA_IPV6_ROUTE_ADD               9
#define ZEBRA_IPV6_ROUTE_DELETE           10
#define ZEBRA_REDISTRIBUTE_ADD            11
#define ZEBRA_REDISTRIBUTE_DELETE         12
#define ZEBRA_REDISTRIBUTE_DEFAULT_ADD    13
#define ZEBRA_REDISTRIBUTE_DEFAULT_DELETE 14
#define ZEBRA_IPV4_NEXTHOP_LOOKUP         15
#define ZEBRA_IPV6_NEXTHOP_LOOKUP         16

static const value_string messages[] = {
	{ ZEBRA_INTERFACE_ADD,			"Add Interface" },
	{ ZEBRA_INTERFACE_DELETE,		"Delete Interface" },
	{ ZEBRA_INTERFACE_ADDRESS_ADD,		"Add Interface Address" },
	{ ZEBRA_INTERFACE_ADDRESS_DELETE,	"Delete Interface Address" },
	{ ZEBRA_INTERFACE_UP,			"Interface Up" },
	{ ZEBRA_INTERFACE_DOWN,			"Interface Down" },
	{ ZEBRA_IPV4_ROUTE_ADD,			"Add IPv4 Route" },
	{ ZEBRA_IPV4_ROUTE_DELETE,		"Delete IPv4 Route" },
	{ ZEBRA_IPV6_ROUTE_ADD,			"Add IPv6 Route" },
	{ ZEBRA_IPV6_ROUTE_DELETE,		"Delete IPv6 Route" },
	{ ZEBRA_REDISTRIBUTE_ADD,		"Add Redistribute" },
	{ ZEBRA_REDISTRIBUTE_DELETE,		"Delete Redistribute" },
	{ ZEBRA_REDISTRIBUTE_DEFAULT_ADD,	"Add Default Redistribute" },
	{ ZEBRA_REDISTRIBUTE_DEFAULT_DELETE,	"Delete Default Redistribute" },
	{ ZEBRA_IPV4_NEXTHOP_LOOKUP,		"IPv4 Nexthop Lookup" },
	{ ZEBRA_IPV6_NEXTHOP_LOOKUP,		"IPv6 Nexthop Lookup" },
	{ 0,					NULL },
};

/* Zebra route's types. */
#define ZEBRA_ROUTE_SYSTEM               0
#define ZEBRA_ROUTE_KERNEL               1
#define ZEBRA_ROUTE_CONNECT              2
#define ZEBRA_ROUTE_STATIC               3
#define ZEBRA_ROUTE_RIP                  4
#define ZEBRA_ROUTE_RIPNG                5
#define ZEBRA_ROUTE_OSPF                 6
#define ZEBRA_ROUTE_OSPF6                7
#define ZEBRA_ROUTE_BGP                  8

static const value_string routes[] = {
	{ ZEBRA_ROUTE_SYSTEM,			"System Route" },
	{ ZEBRA_ROUTE_KERNEL,			"Kernel Route" },
	{ ZEBRA_ROUTE_CONNECT,			"Connected Route" },
	{ ZEBRA_ROUTE_STATIC,			"Static Route" },
	{ ZEBRA_ROUTE_RIP,			"RIP Route" },
	{ ZEBRA_ROUTE_RIPNG,			"RIPnG Route" },
	{ ZEBRA_ROUTE_OSPF,			"OSPF Route" },
	{ ZEBRA_ROUTE_OSPF6,			"OSPF6 Route" },
	{ ZEBRA_ROUTE_BGP,			"BGP Route" },
	{ 0,					NULL },
};

/* Zebra's family types. */
#define ZEBRA_FAMILY_IPV4                1
#define ZEBRA_FAMILY_IPV6                2

static const value_string families[] = {
	{ ZEBRA_FAMILY_IPV4,			"IPv4" },
	{ ZEBRA_FAMILY_IPV6,			"IPv6" },
	{ 0,					NULL },
};

/* Error codes of zebra. */
#define ZEBRA_ERR_RTEXIST                1
#define ZEBRA_ERR_RTUNREACH              2
#define ZEBRA_ERR_EPERM                  3
#define ZEBRA_ERR_RTNOEXIST              4

static const value_string errors[] = {
	{ ZEBRA_ERR_RTEXIST,			"Route Exists" },
	{ ZEBRA_ERR_RTUNREACH,			"Route Unreachable" },
	{ ZEBRA_ERR_EPERM,			"Permission Denied" },
	{ ZEBRA_ERR_RTNOEXIST,			"Route Does Not Exist" },
	{ 0,					NULL },
};

/* Zebra message flags */
#define ZEBRA_FLAG_INTERNAL           0x01
#define ZEBRA_FLAG_SELFROUTE          0x02
#define ZEBRA_FLAG_BLACKHOLE          0x04

/* Subsequent Address Family Identifier. */
#define ZEBRA_SAFI_UNICAST               1
#define ZEBRA_SAFI_MULTICAST             2
#define ZEBRA_SAFI_UNICAST_MULTICAST     3
#define ZEBRA_SAFI_MPLS_VPN              4

static const value_string safis[] = {
	{ ZEBRA_SAFI_UNICAST,			"Unicast" },
	{ ZEBRA_SAFI_MULTICAST,			"Multicast" },
	{ ZEBRA_SAFI_UNICAST_MULTICAST,		"Unicast And Multicast" },
	{ ZEBRA_SAFI_MPLS_VPN,			"MPLS VPN" },
	{ 0,					NULL },
};

/* Zebra API message flag. */
#define ZEBRA_ZAPI_MESSAGE_NEXTHOP    0x01
#define ZEBRA_ZAPI_MESSAGE_IFINDEX    0x02
#define ZEBRA_ZAPI_MESSAGE_DISTANCE   0x04
#define ZEBRA_ZAPI_MESSAGE_METRIC     0x08

#define INTERFACE_NAMSIZ      20

#define PSIZE(a) (((a) + 7) / (8))

void
dissect_zebra_request(proto_tree *tree, gboolean request, tvbuff_t *tvb,
	int offset, guint16 len, guint8 command)
{
	guint32	prefix4;
	guint16 i;
	guint8  buffer6[16], prefixlen, message;
	guint8 *prefix;
	proto_item *ti;
	proto_tree *msg_tree;

	proto_tree_add_uint(tree, hf_zebra_len, tvb, offset, 2, len);
	offset += 2;
	proto_tree_add_uint(tree, hf_zebra_command, tvb, offset, 1,
		command);
	offset += 1;
	switch(command) {
		case ZEBRA_INTERFACE_ADD:
		case ZEBRA_INTERFACE_UP:
		case ZEBRA_INTERFACE_DOWN:
			if (request) break;
			/* Request just subscribes to messages */

			proto_tree_add_string(tree, hf_zebra_interface, 
				tvb, offset, INTERFACE_NAMSIZ, 
				tvb_get_ptr(tvb, offset, INTERFACE_NAMSIZ));
			offset += INTERFACE_NAMSIZ;

			proto_tree_add_item(tree, hf_zebra_index, tvb,
				 offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(tree, hf_zebra_intflags, tvb,
				 offset, 4, FALSE);
			offset += 4;
			
			proto_tree_add_item(tree, hf_zebra_metric, tvb,
				 offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(tree, hf_zebra_mtu, tvb,
				 offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(tree, hf_zebra_bandwidth, tvb,
				 offset, 4, FALSE);
			offset += 4;

			break;
		case ZEBRA_INTERFACE_DELETE:
			proto_tree_add_string(tree, hf_zebra_interface,
				tvb, offset, INTERFACE_NAMSIZ,
				tvb_get_ptr(tvb, offset, INTERFACE_NAMSIZ));
			offset += INTERFACE_NAMSIZ;

			proto_tree_add_item(tree, hf_zebra_index, tvb,
				 offset, 4, FALSE);
			offset += 4;
			break;
		case ZEBRA_INTERFACE_ADDRESS_ADD:
		case ZEBRA_INTERFACE_ADDRESS_DELETE:
			proto_tree_add_item(tree, hf_zebra_index, tvb,
				 offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(tree, hf_zebra_family, tvb,
				 offset, 1, FALSE);
			offset += 1;

			if (len == 17) { /* IPv4 */
				proto_tree_add_item(tree, hf_zebra_prefix4,
					tvb, offset, 4, FALSE);
				offset += 4;
			}
			else if (len == 41) { /* IPv6 */
				proto_tree_add_item(tree, hf_zebra_prefix6,
					tvb, offset, 16, FALSE);
				offset += 16;
			}
			else break;

			proto_tree_add_item(tree, hf_zebra_prefixlen, tvb,
				 offset, 1, FALSE);
			offset += 1;

			if (len == 17) { /* IPv4 */
				proto_tree_add_item(tree, hf_zebra_dest4,
					tvb, offset, 4, FALSE);
				offset += 4;
			}
			else if (len == 41) { /* IPv6 */
				proto_tree_add_item(tree, hf_zebra_dest6,
					tvb, offset, 16, FALSE);
				offset += 16;
			}
			break;

		case ZEBRA_IPV4_ROUTE_ADD:
		case ZEBRA_IPV4_ROUTE_DELETE:
			proto_tree_add_item(tree, hf_zebra_type, tvb,
				 offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(tree, hf_zebra_rtflags, tvb,
				 offset, 1, FALSE);
			offset += 1;

			message = tvb_get_guint8(tvb, offset);
			ti = proto_tree_add_uint(tree, hf_zebra_message, tvb,
				 offset, 1, message);
			msg_tree = proto_item_add_subtree(ti, ett_message);
			proto_tree_add_boolean(msg_tree, hf_zebra_msg_nexthop,
				tvb, offset, 1, message);
			proto_tree_add_boolean(msg_tree, hf_zebra_msg_index,
				tvb, offset, 1, message);
			proto_tree_add_boolean(msg_tree, hf_zebra_msg_distance,
				tvb, offset, 1, message);
			proto_tree_add_boolean(msg_tree, hf_zebra_msg_metric,
				tvb, offset, 1, message);
			offset += 1;

			prefixlen = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint(tree, hf_zebra_prefixlen, tvb,
				 offset, 1, prefixlen);
			offset += 1;

			prefix = tvb_get_ptr(tvb, offset, PSIZE(prefixlen));
			prefix4 = 0;
			memcpy(&prefix4, prefix,
			    MIN(PSIZE(prefixlen), sizeof prefix4));
			proto_tree_add_ipv4(tree, hf_zebra_prefix4,
				tvb, offset, PSIZE(prefixlen), prefix4);
			offset += PSIZE(prefixlen);

			if (message & ZEBRA_ZAPI_MESSAGE_NEXTHOP) {
				i = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(tree, hf_zebra_nexthopnum,
					tvb, offset, 1, i);
				offset += 1;

				if (i>len) break; /* Sanity */

				while (i--) {
					proto_tree_add_item(tree,
						hf_zebra_nexthop4, tvb,
						offset, 4, FALSE);
					offset += 4;
				}
			}
			if (message & ZEBRA_ZAPI_MESSAGE_IFINDEX) {
				i = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(tree, hf_zebra_indexnum,
					tvb, offset, 1, i);
				offset += 1;

				if (i>len) break; /* Sanity */

				while (i--) {
					proto_tree_add_item(tree,
						hf_zebra_index, tvb,
						offset, 4, FALSE);
					offset += 4;
				}
			}
			if (message & ZEBRA_ZAPI_MESSAGE_DISTANCE) {
				proto_tree_add_item(tree, hf_zebra_distance,
					tvb, offset, 1, FALSE);
				offset += 1;
			}
			if (message & ZEBRA_ZAPI_MESSAGE_METRIC) {
				proto_tree_add_item(tree, hf_zebra_metric,
					tvb, offset, 4, FALSE);
				offset += 4;
			}
			break;
		case ZEBRA_IPV6_ROUTE_ADD:
		case ZEBRA_IPV6_ROUTE_DELETE:
			proto_tree_add_item(tree, hf_zebra_type, tvb,
				 offset, 1, FALSE);
			offset += 1;

			proto_tree_add_item(tree, hf_zebra_rtflags, tvb,
				 offset, 1, FALSE);
			offset += 1;

			message = tvb_get_guint8(tvb, offset);
			ti = proto_tree_add_uint(tree, hf_zebra_message, tvb,
				 offset, 1, message);
			msg_tree = proto_item_add_subtree(ti, ett_message);
			proto_tree_add_boolean(msg_tree, hf_zebra_msg_nexthop,
				tvb, offset, 1, message);
			proto_tree_add_boolean(msg_tree, hf_zebra_msg_index,
				tvb, offset, 1, message);
			proto_tree_add_boolean(msg_tree, hf_zebra_msg_distance,
				tvb, offset, 1, message);
			proto_tree_add_boolean(msg_tree, hf_zebra_msg_metric,
				tvb, offset, 1, message);
			offset += 1;

			prefixlen = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint(tree, hf_zebra_prefixlen, tvb,
				 offset, 1, prefixlen);
			offset += 1;

			prefix = tvb_get_ptr(tvb, offset, PSIZE(prefixlen));
			memset(buffer6, '\0', sizeof buffer6);
			memcpy(buffer6, prefix,
			    MIN(PSIZE(prefixlen), sizeof buffer6));
			proto_tree_add_ipv6(tree, hf_zebra_prefix6,
				tvb, offset, PSIZE(prefixlen), buffer6);
			offset += PSIZE(prefixlen);

			if (message & ZEBRA_ZAPI_MESSAGE_NEXTHOP) {
				i = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(tree, hf_zebra_nexthopnum,
					tvb, offset, 1, i);
				offset += 1;

				if (i>len) break; /* Sanity */

				while (i--) {
					proto_tree_add_item(tree,
						hf_zebra_nexthop6, tvb,
						offset, 16, FALSE);
					offset += 16;
				}
			}
			if (message & ZEBRA_ZAPI_MESSAGE_IFINDEX) {
				i = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(tree, hf_zebra_indexnum,
					tvb, offset, 1, i);
				offset += 1;

				if (i>len) break; /* Sanity */

				while (i--) {
					proto_tree_add_item(tree,
						hf_zebra_index, tvb,
						offset, 4, FALSE);
					offset += 4;
				}
			}
			if (message & ZEBRA_ZAPI_MESSAGE_DISTANCE) {
				proto_tree_add_item(tree, hf_zebra_distance,
					tvb, offset, 1, FALSE);
				offset += 1;
			}
			if (message & ZEBRA_ZAPI_MESSAGE_METRIC) {
				proto_tree_add_item(tree, hf_zebra_metric,
					tvb, offset, 4, FALSE);
				offset += 4;
			}
			break;
		case ZEBRA_REDISTRIBUTE_ADD:
		case ZEBRA_REDISTRIBUTE_DELETE:
			proto_tree_add_item(tree, hf_zebra_type, tvb,
				 offset, 1, FALSE);
			offset += 1;
			break;
		case ZEBRA_REDISTRIBUTE_DEFAULT_ADD:
		case ZEBRA_REDISTRIBUTE_DEFAULT_DELETE:
			break;
		case ZEBRA_IPV4_NEXTHOP_LOOKUP:
			proto_tree_add_item(tree, hf_zebra_nexthop4,
				tvb, offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(tree, hf_zebra_metric,
				tvb, offset, 4, FALSE);
			offset += 4;
			break;
		case ZEBRA_IPV6_NEXTHOP_LOOKUP:
			/* Not yet implemeted in ZEBRA */
			break;
	}
}
		
void
dissect_zebra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*ti;
	proto_tree	*zebra_tree;
	gboolean	request;
	int		left, offset;

	CHECK_DISPLAY_AS_DATA(proto_zebra, tvb, pinfo, tree);

	pinfo->current_proto = "ZEBRA";

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "ZEBRA");

	request = (pi.destport == TCP_PORT_ZEBRA);
	left = tvb_reported_length(tvb);
	offset = 0;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_add_str(pinfo->fd, COL_INFO, 
			request? "ZEBRA Request" : "ZEBRA Reply");
	}
	if (tree) {
		ti = proto_tree_add_item(tree, proto_zebra, tvb, offset,
			END_OF_FRAME, FALSE);
		zebra_tree = proto_item_add_subtree(ti, ett_zebra);
		proto_tree_add_boolean_hidden(zebra_tree, hf_zebra_request,
			tvb, offset, END_OF_FRAME, request);

		for (;;) {
			guint8		command;
			guint16		len;
			proto_tree	*zebra_request_tree;
			
			if (left < 3) break;

			len = tvb_get_ntohs(tvb, offset);
			if (len < 3) break;

			command = tvb_get_guint8(tvb, offset+2);

			ti = proto_tree_add_uint(zebra_tree,
				hf_zebra_command, tvb, offset, len,
				command);
			zebra_request_tree = proto_item_add_subtree(ti,
				ett_zebra_request);
			dissect_zebra_request(zebra_request_tree, request, tvb,
				offset, len, command);

			offset += len;
			left -= len;
		}
	}
}

void
proto_register_zebra(void)
{

  static hf_register_info hf[] = {
    { &hf_zebra_len,
      { "Length",		"zebra.len",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Length of ZEBRA request" }},
    { &hf_zebra_request,
      { "Request",		"zebra.request",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"TRUE if ZEBRA request" }},
    { &hf_zebra_command,
      { "Command",		"zebra.command",
	FT_UINT8, BASE_DEC, VALS(messages), 0x0,
	"ZEBRA command" }},
    { &hf_zebra_interface,
      { "Interface",		"zebra.interface",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"Interface name of ZEBRA request" }},
    { &hf_zebra_index,
      { "Index",		"zebra.index",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Index of interface" }},
    { &hf_zebra_indexnum,
      { "Index Number",		"zebra.indexnum",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Number of indices for route" }},
    { &hf_zebra_intflags,
      { "Flags",		"zebra.intflags",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Flags of interface" }},
    { &hf_zebra_rtflags,
      { "Flags",		"zebra.rtflags",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Flags of route" }},
    { &hf_zebra_message,
      { "Message",		"zebra.message",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Message type of route" }},
    { &hf_zebra_msg_nexthop,
      { "Message Nexthop",	"zebra.message.nexthop",
	FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_NEXTHOP,
	"Message contains nexthop" }},
    { &hf_zebra_msg_index,
      { "Message Index",	"zebra.message.index",
	FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_IFINDEX,
	"Message contains index" }},
    { &hf_zebra_msg_distance,
      { "Message Distance",	"zebra.message.distance",
	FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_DISTANCE,
	"Message contains distance" }},
    { &hf_zebra_msg_metric,
      { "Message Metric",	"zebra.message.metric",
	FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_METRIC,
	"Message contains metric" }},
    { &hf_zebra_type,
      { "Type",			"zebra.type",
	FT_UINT8, BASE_DEC, VALS(routes), 0x0,
	"Type of route" }},
    { &hf_zebra_distance,
      { "Distance",		"zebra.distance",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Distance of route" }},
    { &hf_zebra_metric,
      { "Metric",		"zebra.metric",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Metric of interface or route" }},
    { &hf_zebra_mtu,
      { "MTU",			"zebra.mtu",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"MTU of interface" }},
    { &hf_zebra_bandwidth,
      { "Bandwidth",		"zebra.bandwidth",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Bandwidth of interface" }},
    { &hf_zebra_family,
      { "Family",		"zebra.family",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Family of IP address" }},
    { &hf_zebra_dest4,
      { "Destination",		"zebra.dest4",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"Destination IPv4 field" }},
    { &hf_zebra_dest6,
      { "Destination",		"zebra.dest6",
	FT_IPv6, BASE_NONE, NULL, 0x0,
	"Destination IPv6 field" }},
    { &hf_zebra_nexthopnum,
      { "Nexthop Number",	"zebra.nexthopnum",
	FT_UINT8, BASE_NONE, NULL, 0x0,
	"Number of nexthops in route" }},
    { &hf_zebra_nexthop4,
      { "Nexthop",		"zebra.nexthop4",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"Nethop IPv4 field of route" }},
    { &hf_zebra_nexthop6,
      { "Nexthop",		"zebra.nexthop6",
	FT_IPv6, BASE_NONE, NULL, 0x0,
	"Nethop IPv6 field of route" }},
    { &hf_zebra_prefixlen,
      { "Prefix length",	"zebra.prefixlen",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Prefix length" }},
    { &hf_zebra_prefix4,
      { "Prefix",		"zebra.prefix4",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"Prefix IPv4" }},
    { &hf_zebra_prefix6,
      { "Prefix",		"zebra.prefix6",
	FT_IPv6, BASE_NONE, NULL, 0x0,
	"Prefix IPv6" }},
  };

  static gint *ett[] = {
    &ett_zebra,
    &ett_zebra_request,
    &ett_message,
  };

  proto_zebra = proto_register_protocol("Zebra Protocol", "zebra");
  proto_register_field_array(proto_zebra, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_zebra(void)
{
  dissector_add("tcp.port", TCP_PORT_ZEBRA, dissect_zebra);
}
