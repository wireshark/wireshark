/* packet-rip.c
 * Routines for RIPv1 and RIPv2 packet disassembly
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-rip.c,v 1.26 2001/09/14 06:34:36 guy Exp $
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
 */
 
#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"

#define UDP_PORT_RIP    520

#define	RIPv1	1
#define	RIPv2	2

static const value_string version_vals[] = {
	{ RIPv1, "RIPv1" },
	{ RIPv2, "RIPv2" },
	{ 0,     NULL }
};

static const value_string command_vals[] = {
	{ 1, "Request" },
	{ 2, "Response" },
	{ 3, "Traceon" },
	{ 4, "Traceoff" },
	{ 5, "Vendor specific (Sun)" },
	{ 0, NULL }
};

static const value_string family_vals[] = {
	{ 2,	"IP" },
	{ 0,	NULL }
};

#define RIP_HEADER_LENGTH 4
#define RIP_ENTRY_LENGTH 20

static int proto_rip = -1;
static int hf_rip_command = -1;
static int hf_rip_version = -1;
static int hf_rip_routing_domain = -1;
static int hf_rip_ip = -1;
static int hf_rip_netmask = -1;
static int hf_rip_next_hop = -1;
static int hf_rip_metric = -1;
static int hf_rip_auth = -1;
static int hf_rip_auth_passwd = -1;
static int hf_rip_family = -1;
static int hf_rip_route_tag = -1;

static gint ett_rip = -1;
static gint ett_rip_vec = -1;

static void dissect_ip_rip_vektor(tvbuff_t *tvb, int offset, guint8 version,
    proto_tree *tree);
static void dissect_rip_authentication(tvbuff_t *tvb, int offset,
    proto_tree *tree);

static void 
dissect_rip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    proto_tree *rip_tree = NULL;
    proto_item *ti;
    guint8 command;
    guint8 version;
    guint16 family;

    if (check_col(pinfo->fd, COL_PROTOCOL))
        col_set_str(pinfo->fd, COL_PROTOCOL, "RIP");
    if (check_col(pinfo->fd, COL_INFO))
        col_clear(pinfo->fd, COL_INFO);

    command = tvb_get_guint8(tvb, 0);
    version = tvb_get_guint8(tvb, 1);
  
    if (check_col(pinfo->fd, COL_PROTOCOL))
        col_add_str(pinfo->fd, COL_PROTOCOL,
		    val_to_str(version, version_vals, "RIP"));
    if (check_col(pinfo->fd, COL_INFO))
        col_add_str(pinfo->fd, COL_INFO,
		    val_to_str(command, command_vals, "Unknown command (%u)"));

    if (tree) {
	ti = proto_tree_add_item(tree, proto_rip, tvb, 0, tvb_length(tvb), FALSE);
	rip_tree = proto_item_add_subtree(ti, ett_rip);

	proto_tree_add_uint(rip_tree, hf_rip_command, tvb, 0, 1, command);
	proto_tree_add_uint(rip_tree, hf_rip_version, tvb, 1, 1, version);
	if (version == RIPv2)
	    proto_tree_add_uint(rip_tree, hf_rip_routing_domain, tvb, 2, 2,
			tvb_get_ntohs(tvb, 2));

	/* skip header */
	offset = RIP_HEADER_LENGTH;

        /* zero or more entries */
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
	    family = tvb_get_ntohs(tvb, offset);
	    switch (family) {
	    case 2: /* IP */
		dissect_ip_rip_vektor(tvb, offset, version, rip_tree);
		break;
	    case 0xFFFF:
		dissect_rip_authentication(tvb, offset, rip_tree);
		break;
	    default:
	        proto_tree_add_text(rip_tree, tvb, offset,
				RIP_ENTRY_LENGTH, "Unknown address family %u",
				family);
		break;
	    }

            offset += RIP_ENTRY_LENGTH;
        }
    }
}

static void
dissect_ip_rip_vektor(tvbuff_t *tvb, int offset, guint8 version,
		      proto_tree *tree)
{
    proto_item *ti;
    proto_tree *rip_vektor_tree;
    guint32 metric;

    metric = tvb_get_ntohl(tvb, offset+16);
    ti = proto_tree_add_text(tree, tvb, offset,
			     RIP_ENTRY_LENGTH, "IP Address: %s, Metric: %u",
			     ip_to_str(tvb_get_ptr(tvb, offset+4, 4)), metric);
    rip_vektor_tree = proto_item_add_subtree(ti, ett_rip_vec);
	   

    proto_tree_add_uint(rip_vektor_tree, hf_rip_family, tvb, offset, 2, 
			tvb_get_ntohs(tvb, offset));
    if (version == RIPv2) {
	proto_tree_add_uint(rip_vektor_tree, hf_rip_route_tag, tvb, offset+2, 2,
			tvb_get_ntohs(tvb, offset+2));
    }

    proto_tree_add_item(rip_vektor_tree, hf_rip_ip, tvb, offset+4, 4, FALSE);

    if (version == RIPv2) {
	proto_tree_add_item(rip_vektor_tree, hf_rip_netmask, tvb, offset+8, 4,
			    FALSE);
	proto_tree_add_item(rip_vektor_tree, hf_rip_next_hop, tvb, offset+12, 4,
			    FALSE);
    }
    proto_tree_add_uint(rip_vektor_tree, hf_rip_metric, tvb, 
			offset+16, 4, metric);
}

static void
dissect_rip_authentication(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *rip_authentication_tree;
    guint16 authtype;

    ti = proto_tree_add_text(tree, tvb, offset, RIP_ENTRY_LENGTH,
			     "Authentication");
    rip_authentication_tree = proto_item_add_subtree(ti, ett_rip_vec);

    authtype = tvb_get_ntohs(tvb, offset + 2);
    proto_tree_add_uint(rip_authentication_tree, hf_rip_auth, tvb, offset+2, 2,
		authtype);
    if (authtype == 2) {
	proto_tree_add_item(rip_authentication_tree, hf_rip_auth_passwd,
			tvb, offset+4, 16, TRUE);
    }
}

void
proto_register_rip(void)
{
	static hf_register_info hf[] = {
		{ &hf_rip_command,
			{ "Command", "rip.command", FT_UINT8, BASE_DEC,
			VALS(command_vals), 0, "What type of RIP Command is this", HFILL }},

		{ &hf_rip_version,
			{ "Version", "rip.version", FT_UINT8, BASE_DEC,
			VALS(version_vals), 0, "Version of the RIP protocol", HFILL }},

		{ &hf_rip_family,
			{ "Address Family", "rip.family", FT_UINT16, BASE_DEC,
			VALS(family_vals), 0, "Address family", HFILL }},

		{ &hf_rip_routing_domain,
			{ "Routing Domain", "rip.routing_domain", FT_UINT16, BASE_DEC,
			NULL, 0, "RIPv2 Routing Domain", HFILL }},

		{ &hf_rip_ip,
			{ "IP Address", "rip.ip", FT_IPv4, BASE_NONE,
			NULL, 0, "IP Address", HFILL}},

		{ &hf_rip_netmask,
			{ "Netmask", "rip.netmask", FT_IPv4, BASE_NONE,
			NULL, 0, "Netmask", HFILL}},

		{ &hf_rip_next_hop,
			{ "Next Hop", "rip.next_hop", FT_IPv4, BASE_NONE,
			NULL, 0, "Next Hop router for this route", HFILL}},

		{ &hf_rip_metric,
			{ "Metric", "rip.metric", FT_UINT16, BASE_DEC,
			NULL, 0, "Metric for this route", HFILL }},

		{ &hf_rip_auth,
			{ "Authentication type", "rip.auth.type", FT_UINT16, BASE_DEC,
			NULL, 0, "Type of authentication", HFILL }},

		{ &hf_rip_auth_passwd,
			{ "Password", "rip.auth.passwd", FT_STRING, BASE_DEC,
			NULL, 0, "Authentication password", HFILL }},

		{ &hf_rip_route_tag,
			{ "Route Tag", "rip.route_tag", FT_UINT16, BASE_DEC,
			NULL, 0, "Route Tag", HFILL }},

	};
	static gint *ett[] = {
		&ett_rip,
		&ett_rip_vec,
	};

	proto_rip = proto_register_protocol("Routing Information Protocol",
				"RIP", "rip");
	proto_register_field_array(proto_rip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rip(void)
{
	dissector_add("udp.port", UDP_PORT_RIP, dissect_rip, proto_rip);
}
