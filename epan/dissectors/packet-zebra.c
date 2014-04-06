/* packet-zebra.c
 * Routines for zebra packet disassembly
 *
 * Jochen Friedrich <jochen@scram.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <epan/packet.h>

/*  Function declarations */
void proto_reg_handoff_zebra(void);
void proto_register_zebra(void);

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
static int hf_zebra_mtu6 = -1;
static int hf_zebra_bandwidth = -1;
static int hf_zebra_family = -1;
static int hf_zebra_flags = -1;
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
static int hf_zebra_version = -1;
static int hf_zebra_intstatus = -1;
static int hf_zebra_routeridaddress = -1;
static int hf_zebra_routeridmask = -1;
static int hf_zebra_mac = -1;

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
#define ZEBRA_IPV4_IMPORT_LOOKUP          17
#define ZEBRA_IPV6_IMPORT_LOOKUP          18
#define ZEBRA_INTERFACE_RENAME            19
#define ZEBRA_ROUTER_ID_ADD               20
#define ZEBRA_ROUTER_ID_DELETE            21
#define ZEBRA_ROUTER_ID_UPDATE            22


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
	{ ZEBRA_IPV4_IMPORT_LOOKUP,		"IPv4 Import Lookup" },
	{ ZEBRA_IPV6_IMPORT_LOOKUP,		"IPv6 Import Lookup" },
	{ ZEBRA_INTERFACE_RENAME,		"Rename Interface" },
	{ ZEBRA_ROUTER_ID_ADD,			"Router ID Add" },
	{ ZEBRA_ROUTER_ID_DELETE,		"Router ID Delete" },
	{ ZEBRA_ROUTER_ID_UPDATE,		"Router ID Update" },
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
#define ZEBRA_FAMILY_IPV4                2
#define ZEBRA_FAMILY_IPV6                10

static const value_string families[] = {
	{ ZEBRA_FAMILY_IPV4,			"IPv4" },
	{ ZEBRA_FAMILY_IPV6,			"IPv6" },
	{ 0,					NULL },
};

/* Zebra message flags */
#define ZEBRA_FLAG_INTERNAL              0x01
#define ZEBRA_FLAG_SELFROUTE             0x02
#define ZEBRA_FLAG_BLACKHOLE             0x04

/* Zebra API message flag. */
#define ZEBRA_ZAPI_MESSAGE_NEXTHOP       0x01
#define ZEBRA_ZAPI_MESSAGE_IFINDEX       0x02
#define ZEBRA_ZAPI_MESSAGE_DISTANCE      0x04
#define ZEBRA_ZAPI_MESSAGE_METRIC        0x08

/* Zebra NextHop Types */
#define ZEBRA_NEXTHOP_TYPE_IFINDEX       0x01
#define ZEBRA_NEXTHOP_TYPE_IFNAME        0x02
#define ZEBRA_NEXTHOP_TYPE_IPV4          0x03
#define ZEBRA_NEXTHOP_TYPE_IPV4_IFINDEX  0x04
#define ZEBRA_NEXTHOP_TYPE_IPV4_IFNAME   0x05
#define ZEBRA_NEXTHOP_TYPE_IPV6          0x06
#define ZEBRA_NEXTHOP_TYPE_IPV6_IFINDEX  0x07
#define ZEBRA_NEXTHOP_TYPE_IPV6_IFNAME   0x08


#define INTERFACE_NAMSIZ      20

#define PSIZE(a) (((a) + 7) / (8))

static int
zebra_route_nexthop(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 len)
{
	guint8 nexthoptype, nexthopcount, interfacenamelength;
	nexthopcount = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_zebra_nexthopnum,
			    tvb, offset, 1, nexthopcount);
	offset += 1;

	if (nexthopcount > len)
		return offset; /* Sanity */

	while (nexthopcount--) {
		nexthoptype = tvb_get_guint8(tvb, offset);
		offset += 1;
		if (nexthoptype == ZEBRA_NEXTHOP_TYPE_IFINDEX      ||
		    nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFINDEX ||
		    nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFINDEX){
			proto_tree_add_item(tree,hf_zebra_index, tvb,
					    offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		if (nexthoptype == ZEBRA_NEXTHOP_TYPE_IFNAME       ||
		    nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFNAME  ||
		    nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFNAME) {
			interfacenamelength = tvb_get_guint8(tvb, offset);
			offset += 1;
			proto_tree_add_item(tree, hf_zebra_interface,
					    tvb, offset, interfacenamelength,
					    ENC_ASCII|ENC_NA);
			offset += interfacenamelength;
		}
		if (nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6         ||
		    nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFINDEX ||
		    nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV6_IFNAME) {
			proto_tree_add_item(tree, hf_zebra_nexthop6,
					    tvb, offset, 16, ENC_NA);
			offset += 16;
		}
		if (nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4         ||
		    nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFINDEX ||
		    nexthoptype == ZEBRA_NEXTHOP_TYPE_IPV4_IFNAME) {
			proto_tree_add_item(tree, hf_zebra_nexthop4,
					    tvb, offset, 4, ENC_NA);
			offset += 4;
		}

	}
	return offset;
}

static int
zebra_route_ifindex(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 len)
{
	guint16 indexcount = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_zebra_indexnum,
			    tvb, offset, 1, indexcount);
	offset += 1;
	if (indexcount > len)
		return offset; /* Sanity */

	while (indexcount--) {
		proto_tree_add_item(tree, hf_zebra_index, tvb, offset, 4,
				ENC_BIG_ENDIAN);
		offset += 4;
	}
	return offset;
}

static guint8
zebra_route_message(proto_tree *tree, tvbuff_t *tvb, int offset, guint8 message)
{
	proto_item *ti;
	proto_tree *msg_tree;

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

	return offset;
}

static int
zebra_route(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 len,
	    guint8 family)
{
	guint32	prefix4;
	guint8 message, prefixlen, buffer6[16];

	proto_tree_add_item(tree, hf_zebra_type, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_zebra_rtflags, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	message = tvb_get_guint8(tvb, offset);
	offset = zebra_route_message(tree, tvb, offset, message);

	prefixlen = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_zebra_prefixlen, tvb,
			    offset, 1, prefixlen);
	offset += 1;

	if (family == ZEBRA_FAMILY_IPV6) {
		memset(buffer6, '\0', sizeof buffer6);
		tvb_memcpy(tvb, buffer6, offset,
			   MIN((unsigned) PSIZE(prefixlen), sizeof buffer6));
		proto_tree_add_ipv6(tree, hf_zebra_prefix6,
				    tvb, offset, PSIZE(prefixlen), buffer6);
	}else {
		prefix4 = 0;
		tvb_memcpy(tvb, (guint8 *)&prefix4, offset,
			   MIN((unsigned) PSIZE(prefixlen), sizeof prefix4));
		proto_tree_add_ipv4(tree, hf_zebra_prefix4,
				    tvb, offset, PSIZE(prefixlen), prefix4);
	}
	offset += PSIZE(prefixlen);

	if (message & ZEBRA_ZAPI_MESSAGE_NEXTHOP) {
		offset = zebra_route_nexthop(tree, tvb, offset, len);
	}
	if (message & ZEBRA_ZAPI_MESSAGE_IFINDEX) {
		offset = zebra_route_ifindex(tree, tvb, offset, len);
	}
	if (message & ZEBRA_ZAPI_MESSAGE_DISTANCE) {
		proto_tree_add_item(tree, hf_zebra_distance,
				    tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
	}
	if (message & ZEBRA_ZAPI_MESSAGE_METRIC) {
		proto_tree_add_item(tree, hf_zebra_metric,
				    tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	return offset;
}

static int
zebra_interface_address(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint8 family;
	proto_tree_add_item(tree, hf_zebra_index, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_zebra_flags, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_zebra_family, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	family = tvb_get_guint8(tvb, offset);
	offset += 1;
	if (family == ZEBRA_FAMILY_IPV4) {
		proto_tree_add_item(tree, hf_zebra_prefix4,
				    tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	else if (family == ZEBRA_FAMILY_IPV6) {
		proto_tree_add_item(tree, hf_zebra_prefix6,
				    tvb, offset, 16, ENC_NA);
		offset += 16;
	}
	else
		return offset;

	proto_tree_add_item(tree, hf_zebra_prefixlen, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	if (family == ZEBRA_FAMILY_IPV4) {
		proto_tree_add_item(tree, hf_zebra_dest4,
				    tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	else if (family == ZEBRA_FAMILY_IPV6) {
		proto_tree_add_item(tree, hf_zebra_dest6,
				    tvb, offset, 16, ENC_NA);
		offset += 16;
	}
	return offset;
}

static int
zebra_interface_del(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item(tree, hf_zebra_interface,
			    tvb, offset, INTERFACE_NAMSIZ, ENC_ASCII|ENC_NA);
	offset += INTERFACE_NAMSIZ;
	proto_tree_add_item(tree, hf_zebra_index, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	return offset;
}

static int
zebra_interface(proto_tree *tree, tvbuff_t *tvb, int offset, guint8 version)
{
	gint maclen;
	proto_tree_add_item(tree, hf_zebra_interface,
			    tvb, offset, INTERFACE_NAMSIZ, ENC_ASCII|ENC_NA);
	offset += INTERFACE_NAMSIZ;
	proto_tree_add_item(tree, hf_zebra_index, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_zebra_intstatus, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	if (version != 0) {
		proto_tree_add_item(tree, hf_zebra_intflags, tvb,
				    offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
	} else {
		proto_tree_add_item(tree, hf_zebra_intflags, tvb,
				    offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	proto_tree_add_item(tree, hf_zebra_metric, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_zebra_mtu, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	if (version != 0) {
		proto_tree_add_item(tree, hf_zebra_mtu6, tvb,
				    offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	proto_tree_add_item(tree, hf_zebra_bandwidth, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	if (version != 0) {
		maclen = (gint)tvb_get_ntohl(tvb, offset);
		offset += 4;
		if (maclen > 0)
			proto_tree_add_item(tree, hf_zebra_mac, tvb,
					    offset, maclen, ENC_NA);
		offset += maclen;
	}
	return offset;
}

static int
zebra_nexthop_lookup(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 len,
		     guint8 family)
{
	if (family == ZEBRA_FAMILY_IPV6) {
		proto_tree_add_item(tree, hf_zebra_dest6, tvb, offset, 16,
				    ENC_NA);
		offset += 16;
	}else {
		proto_tree_add_item(tree, hf_zebra_dest4, tvb, offset, 4,
				    ENC_BIG_ENDIAN);
		offset += 4;
	}
	proto_tree_add_item(tree, hf_zebra_metric,tvb, offset, 4, ENC_NA);
	offset += 4;
	offset = zebra_route_nexthop(tree, tvb, offset, len);
	return offset;
}

static int
zerba_router_update(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset += 1;
	proto_tree_add_item(tree, hf_zebra_routeridaddress, tvb,
			    offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_zebra_routeridmask, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	return offset;
}

static int
dissect_zebra_request(proto_tree *tree, gboolean request, tvbuff_t *tvb,
		      int offset, guint16 len, guint16 command, guint8 version)
{
	proto_tree_add_uint(tree, hf_zebra_len, tvb, offset, 2, len);
	offset += 2;
	if (version != 0) {
		proto_tree_add_uint(tree, hf_zebra_version, tvb, offset, 1,
				    version);
		offset += 2;
		proto_tree_add_uint(tree, hf_zebra_command, tvb, offset, 2,
				    command);
		offset += 2;
	} else {
		proto_tree_add_uint(tree, hf_zebra_command, tvb, offset, 1,
				    command);
		offset += 1;
	}

	switch(command) {
		case ZEBRA_INTERFACE_ADD:
		case ZEBRA_INTERFACE_UP:
		case ZEBRA_INTERFACE_DOWN:
			if (request)
				break; /* Request just subscribes to messages */
			offset = zebra_interface(tree, tvb, offset, version);
			break;
		case ZEBRA_INTERFACE_DELETE:
			offset = zebra_interface_del(tree, tvb, offset);
			break;
		case ZEBRA_INTERFACE_ADDRESS_ADD:
		case ZEBRA_INTERFACE_ADDRESS_DELETE:
			offset = zebra_interface_address(tree, tvb, offset);
			break;
		case ZEBRA_IPV4_ROUTE_ADD:
		case ZEBRA_IPV4_ROUTE_DELETE:
			offset = zebra_route(tree, tvb, offset, len,
					     ZEBRA_FAMILY_IPV4);
			break;
		case ZEBRA_IPV6_ROUTE_ADD:
		case ZEBRA_IPV6_ROUTE_DELETE:
			offset = zebra_route(tree, tvb, offset, len,
					     ZEBRA_FAMILY_IPV6);
			break;
		case ZEBRA_REDISTRIBUTE_ADD:
		case ZEBRA_REDISTRIBUTE_DEFAULT_ADD:
			proto_tree_add_item(tree, hf_zebra_type, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			offset = 1;
			break;
		case ZEBRA_IPV4_IMPORT_LOOKUP:
		case ZEBRA_IPV4_NEXTHOP_LOOKUP:
			offset = zebra_nexthop_lookup(tree, tvb, offset, len,
						      ZEBRA_FAMILY_IPV4);
			break;
		case ZEBRA_IPV6_IMPORT_LOOKUP:
		case ZEBRA_IPV6_NEXTHOP_LOOKUP:
			offset = zebra_nexthop_lookup(tree, tvb, offset, len,
						      ZEBRA_FAMILY_IPV6);
			break;
		case ZEBRA_ROUTER_ID_UPDATE:
			offset = zerba_router_update(tree, tvb, offset);
			break;
		case ZEBRA_REDISTRIBUTE_DEFAULT_DELETE:
		case ZEBRA_REDISTRIBUTE_DELETE:
			/* nothing to do */
			break;
	}
return offset;
}

static void
dissect_zebra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*ti;
	proto_tree	*zebra_tree;
	gboolean	request;
	int		left, offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZEBRA");

	request = (pinfo->destport == pinfo->match_uint);
	left = tvb_reported_length(tvb);
	offset = 0;

	col_set_str(pinfo->cinfo, COL_INFO,
		    request? "ZEBRA Request" : "ZEBRA Reply");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_zebra, tvb, offset, -1,
					 ENC_NA);
		zebra_tree = proto_item_add_subtree(ti, ett_zebra);
		ti = proto_tree_add_boolean(zebra_tree, hf_zebra_request,
					    tvb, offset, 0, request);
		PROTO_ITEM_SET_HIDDEN(ti);

		for (;;) {
			guint8 		headermarker, version;
			guint16		command, len;
			proto_tree	*zebra_request_tree;

			if (left < 3)
				break;
			len = tvb_get_ntohs(tvb, offset);
			if (len < 3)
				break;

			headermarker = tvb_get_guint8(tvb,offset+2);
			if (headermarker != 0xFF) {
				command = headermarker;
				version = 0;
			} else {
				version = tvb_get_guint8(tvb, offset+3);
				command = tvb_get_ntohs(tvb, offset+4);
			}
			ti = proto_tree_add_uint(zebra_tree,
						 hf_zebra_command, tvb,
						 offset, len, command);
			zebra_request_tree = proto_item_add_subtree(ti,
							ett_zebra_request);
			dissect_zebra_request(zebra_request_tree, request, tvb,
					      offset, len, command, version);
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
	"Length of ZEBRA request", HFILL }},
    { &hf_zebra_version,
      { "Version", 		"zebra.version",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Zerbra srv version", HFILL }},
    { &hf_zebra_request,
      { "Request",		"zebra.request",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"TRUE if ZEBRA request", HFILL }},
    { &hf_zebra_command,
      { "Command",		"zebra.command",
	FT_UINT8, BASE_DEC, VALS(messages), 0x0,
	"ZEBRA command", HFILL }},
    { &hf_zebra_interface,
      { "Interface",		"zebra.interface",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"Interface name of ZEBRA request", HFILL }},
    { &hf_zebra_index,
      { "Index",		"zebra.index",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Index of interface", HFILL }},
    { &hf_zebra_intstatus,
      { "Status",		"zebra.intstatus",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Status of interface", HFILL}},
    { &hf_zebra_indexnum,
      { "Index Number",		"zebra.indexnum",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Number of indices for route", HFILL }},
    { &hf_zebra_intflags,
      { "Flags",		"zebra.intflags",
	FT_UINT64, BASE_DEC, NULL, 0x0,
	"Flags of interface", HFILL }},
    { &hf_zebra_rtflags,
      { "Flags",		"zebra.rtflags",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Flags of route", HFILL }},
    { &hf_zebra_message,
      { "Message",		"zebra.message",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Message type of route", HFILL }},
    { &hf_zebra_msg_nexthop,
      { "Message Nexthop",	"zebra.message.nexthop",
	FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_NEXTHOP,
	"Message contains nexthop", HFILL }},
    { &hf_zebra_msg_index,
      { "Message Index",	"zebra.message.index",
	FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_IFINDEX,
	"Message contains index", HFILL }},
    { &hf_zebra_msg_distance,
      { "Message Distance",	"zebra.message.distance",
	FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_DISTANCE,
	"Message contains distance", HFILL }},
    { &hf_zebra_msg_metric,
      { "Message Metric",	"zebra.message.metric",
	FT_BOOLEAN, 8, NULL, ZEBRA_ZAPI_MESSAGE_METRIC,
	"Message contains metric", HFILL }},
    { &hf_zebra_type,
      { "Type",			"zebra.type",
	FT_UINT8, BASE_DEC, VALS(routes), 0x0,
	"Type of route", HFILL }},
    { &hf_zebra_distance,
      { "Distance",		"zebra.distance",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Distance of route", HFILL }},
    { &hf_zebra_metric,
      { "Metric",		"zebra.metric",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Metric of interface or route", HFILL }},
    { &hf_zebra_mtu,
      { "MTU",			"zebra.mtu",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"MTU of interface", HFILL }},
    { &hf_zebra_mtu6,
      { "MTUv6",		"zebra.mtu6",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"MTUv6 of interface", HFILL }},
    { &hf_zebra_bandwidth,
      { "Bandwidth",		"zebra.bandwidth",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Bandwidth of interface", HFILL }},
    { &hf_zebra_family,
      { "Family",		"zebra.family",
	FT_UINT8, BASE_DEC, VALS(families), 0x0,
	"Family of IP address", HFILL }},
    { &hf_zebra_flags,
      { "Flags",		"zebra.flags",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Flags of Address Info", HFILL }},
    { &hf_zebra_dest4,
      { "Destination",		"zebra.dest4",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"Destination IPv4 field", HFILL }},
    { &hf_zebra_dest6,
      { "Destination",		"zebra.dest6",
	FT_IPv6, BASE_NONE, NULL, 0x0,
	"Destination IPv6 field", HFILL }},
    { &hf_zebra_nexthopnum,
      { "Nexthop Number",	"zebra.nexthopnum",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Number of nexthops in route", HFILL }},
    { &hf_zebra_nexthop4,
      { "Nexthop",		"zebra.nexthop4",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"Nethop IPv4 field of route", HFILL }},
    { &hf_zebra_nexthop6,
      { "Nexthop",		"zebra.nexthop6",
	FT_IPv6, BASE_NONE, NULL, 0x0,
	"Nethop IPv6 field of route", HFILL }},
    { &hf_zebra_prefixlen,
      { "Prefix length",	"zebra.prefixlen",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	NULL, HFILL }},
    { &hf_zebra_prefix4,
      { "Prefix",		"zebra.prefix4",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"Prefix IPv4", HFILL }},
    { &hf_zebra_prefix6,
      { "Prefix",		"zebra.prefix6",
	FT_IPv6, BASE_NONE, NULL, 0x0,
	"Prefix IPv6", HFILL }},
    { &hf_zebra_routeridaddress,
      { "Router ID address",	"zebra.routerIDAddress",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "Router ID", HFILL }},
    { &hf_zebra_routeridmask,
      { "Router ID mask",	"zebra.routerIDMask",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"netmask of Router ID", HFILL }},
    { &hf_zebra_mac,
      { "MAC address",	"zebra.macaddress",
	FT_ETHER, BASE_NONE, NULL, 0x0,
	"MAC address of interface", HFILL }},
  };

  static gint *ett[] = {
    &ett_zebra,
    &ett_zebra_request,
    &ett_message,
  };

  proto_zebra = proto_register_protocol("Zebra Protocol", "ZEBRA", "zebra");
  proto_register_field_array(proto_zebra, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_zebra(void)
{
  dissector_handle_t zebra_handle;

  zebra_handle = create_dissector_handle(dissect_zebra, proto_zebra);
  dissector_add_uint("tcp.port", TCP_PORT_ZEBRA, zebra_handle);
}
