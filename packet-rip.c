/* packet-rip.c
 * Routines for RIPv1 and RIPv2 packet disassembly
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-rip.c,v 1.23 2001/01/22 08:03:45 guy Exp $
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

#define RIP_HEADER_LENGTH 4
#define RIP_ENTRY_LENGTH 20

static int proto_rip = -1;

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
    guint reported_length;

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

	proto_tree_add_text(rip_tree, tvb, 0, 1, "Command: %u (%s)", command,
		val_to_str(command, command_vals, "Unknown"));
	proto_tree_add_text(rip_tree, tvb, 1, 1, "Version: %u", version);
	if (version == RIPv2)
	    proto_tree_add_text(rip_tree, tvb, 2, 2, "Routing Domain: %u",
				tvb_get_ntohs(tvb, 2));

	/* skip header */
	offset = RIP_HEADER_LENGTH;

        /* zero or more entries */
	reported_length = tvb_reported_length(tvb);
	while (offset < reported_length) {
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
    guint8 *ip;
    guint32 metric;

    ip = tvb_get_ptr(tvb, offset+4, 4);
    metric = tvb_get_ntohl(tvb, offset+16);
    ti = proto_tree_add_text(tree, tvb, offset,
			     RIP_ENTRY_LENGTH, "IP Address: %s, Metric: %u",
			     ip_to_str(ip), metric);
    rip_vektor_tree = proto_item_add_subtree(ti, ett_rip_vec);
	   
    proto_tree_add_text(rip_vektor_tree, tvb, offset, 2,
			"Address Family ID: IP"); 
    if (version == RIPv2)
	proto_tree_add_text(rip_vektor_tree, tvb, offset + 2, 2,
			    "Route Tag: %u", tvb_get_ntohs(tvb, offset+2));
    proto_tree_add_text(rip_vektor_tree, tvb, offset + 4, 4, "IP Address: %s",
    				ip_to_str(ip));
    if (version == RIPv2) {
	proto_tree_add_text(rip_vektor_tree, tvb, offset + 8, 4,
			    "Netmask: %s", 
			    ip_to_str(tvb_get_ptr(tvb, offset + 8, 4))); 
	proto_tree_add_text(rip_vektor_tree, tvb, offset + 12, 4,
			    "Next Hop: %s", 
			     ip_to_str(tvb_get_ptr(tvb, offset+12, 4))); 
    }
    proto_tree_add_text(rip_vektor_tree, tvb, offset + 16, 4, "Metric: %u",
			metric);
}

static void
dissect_rip_authentication(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *rip_authentication_tree;
    guint16 authtype;
    char authentication[16];

    ti = proto_tree_add_text(tree, tvb, offset, RIP_ENTRY_LENGTH,
			     "Authentication");
    rip_authentication_tree = proto_item_add_subtree(ti, ett_rip_vec);

    authtype = tvb_get_ntohs(tvb, offset + 2);
    proto_tree_add_text(rip_authentication_tree, tvb, offset + 2, 2,
    				"Authentication type: %u", authtype);
    if (authtype == 2) {
	tvb_get_nstringz0(tvb, offset + 4, 16, authentication);
	proto_tree_add_text(rip_authentication_tree, tvb, offset + 4, 16,
				"Password: %s", authentication);
    }
}

void
proto_register_rip(void)
{
/*  static hf_register_info hf[] = {
	{ &variable,
	{ "Name",           "rip.abbreviation", TYPE, VALS_POINTER }},
    };*/
    static gint *ett[] = {
	&ett_rip,
	&ett_rip_vec,
    };

    proto_rip = proto_register_protocol("Routing Information Protocol",
					"RIP", "rip");
/*  proto_register_field_array(proto_rip, hf, array_length(hf));*/
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rip(void)
{
    dissector_add("udp.port", UDP_PORT_RIP, dissect_rip, proto_rip);
}
