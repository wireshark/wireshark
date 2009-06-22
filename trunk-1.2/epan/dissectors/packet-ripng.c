/* packet-ripng.c
 * Routines for RIPng disassembly
 * (c) Copyright Jun-ichiro itojun Hagino <itojun@itojun.org>
 * derived from packet-rip.c
 *
 * $Id$
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
 */

#include "config.h"

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-ripng.h"

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

static int proto_ripng = -1;
static int hf_ripng_cmd = -1;
static int hf_ripng_version = -1;

static gint ett_ripng = -1;
static gint ett_ripng_addr = -1;

#define UDP_PORT_RIPNG  521

static const value_string cmdvals[] = {
    { RIP6_REQUEST, "Request" },
    { RIP6_RESPONSE, "Response" },
    { 0, NULL },
};

static void
dissect_ripng(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    int offset = 0;
    struct rip6 rip6;
    struct netinfo6 ni6;
    proto_tree *ripng_tree = NULL;
    proto_tree *subtree = NULL;
    proto_item *ti;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RIPng");
    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

    /* avoid alignment problem */
    tvb_memcpy(tvb, (guint8 *)&rip6, offset, sizeof(rip6));

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "RIPng version %u", rip6.rip6_vers);
    if (check_col(pinfo->cinfo, COL_INFO))
	col_add_str(pinfo->cinfo, COL_INFO,
	    val_to_str(rip6.rip6_cmd, cmdvals, "Unknown command (%u)"));

    if (tree) {
	ti = proto_tree_add_item(tree, proto_ripng, tvb, offset, -1, FALSE);
	ripng_tree = proto_item_add_subtree(ti, ett_ripng);

	proto_tree_add_uint(ripng_tree, hf_ripng_cmd, tvb, offset, 1,
	    rip6.rip6_cmd);
	proto_tree_add_uint(ripng_tree, hf_ripng_version, tvb, offset + 1, 1,
	    rip6.rip6_vers);

	offset += 4;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		    tvb_memcpy(tvb, (guint8 *)&ni6, offset, sizeof(ni6));
		    if (ni6.rip6_tag) {
			ti = proto_tree_add_text(ripng_tree, tvb, offset,
					sizeof(ni6), "IP Address: %s/%u, Metric: %u, tag: 0x%04x",
					ip6_to_str(&ni6.rip6_dest),
					ni6.rip6_plen,
					ni6.rip6_metric,
					g_ntohs(ni6.rip6_tag));
		    } else {
			ti = proto_tree_add_text(ripng_tree, tvb, offset,
					sizeof(ni6), "IP Address: %s/%u, Metric: %u",
					ip6_to_str(&ni6.rip6_dest),
					ni6.rip6_plen,
					ni6.rip6_metric);
		    }
		    subtree = proto_item_add_subtree(ti, ett_ripng_addr);
		    proto_tree_add_text(subtree, tvb,
				offset + offsetof(struct netinfo6, rip6_dest),
				sizeof(ni6.rip6_dest), "IP Address: %s",
				ip6_to_str(&ni6.rip6_dest));
		    proto_tree_add_text(subtree, tvb,
				offset + offsetof(struct netinfo6, rip6_tag),
				sizeof(ni6.rip6_tag), "Tag: 0x%04x",
				g_ntohs(ni6.rip6_tag));
		    proto_tree_add_text(subtree, tvb,
				offset + offsetof(struct netinfo6, rip6_plen),
				sizeof(ni6.rip6_plen), "Prefix length: %u",
				ni6.rip6_plen);
		    proto_tree_add_text(subtree, tvb,
				offset + offsetof(struct netinfo6, rip6_metric),
				sizeof(ni6.rip6_metric), "Metric: %u",
				ni6.rip6_metric);

		    offset += sizeof(ni6);
	}
    }
}

void
proto_register_ripng(void)
{
    static hf_register_info hf[] = {
      { &hf_ripng_cmd,
	{ "Command",		"ripng.cmd",
				FT_UINT8, BASE_DEC, VALS(cmdvals),
				0x0, "", HFILL }},
      { &hf_ripng_version,
	{ "Version",		"ripng.version",
				FT_UINT8, BASE_DEC, NULL,
				0x0, "", HFILL }},
    };
    static gint *ett[] = {
      &ett_ripng,
      &ett_ripng_addr,
    };

    proto_ripng = proto_register_protocol("RIPng", "RIPng", "ripng");
    proto_register_field_array(proto_ripng, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ripng(void)
{
    dissector_handle_t ripng_handle;

    ripng_handle = create_dissector_handle(dissect_ripng, proto_ripng);
    dissector_add("udp.port", UDP_PORT_RIPNG, ripng_handle);
}
