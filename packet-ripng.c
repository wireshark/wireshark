/* packet-ripng.c
 * Routines for RIPng disassembly
 * (c) Copyright Jun-ichiro itojun Hagino <itojun@itojun.org>
 * derived from packet-rip.c
 *
 * $Id: packet-ripng.c,v 1.6 1999/11/16 11:42:51 guy Exp $
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

#include <glib.h>
#include "packet.h"
#include "packet-ipv6.h"
#include "packet-ripng.h"

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

static int proto_ripng = -1;
static int hf_ripng_cmd = -1;
static int hf_ripng_version = -1;

static gint ett_ripng = -1;
static gint ett_ripng_addr = -1;

void 
dissect_ripng(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    struct rip6 rip6;
    struct netinfo6 ni6;
    proto_tree *ripng_tree = NULL;
    proto_tree *subtree = NULL;
    proto_item *ti; 
    static const value_string cmdvals[] = {
	{ RIP6_REQUEST, "Request" },
	{ RIP6_RESPONSE, "Response" },
	{ 0, NULL },
    };
    const char *cmd;

    /* avoid alignment problem */
    memcpy(&rip6, &pd[offset], sizeof(rip6));
  
    cmd = val_to_str(rip6.rip6_cmd, cmdvals, "Unknown");

    if (check_col(fd, COL_PROTOCOL))
        col_add_fstr(fd, COL_PROTOCOL, "RIPng version %d", rip6.rip6_vers);
    if (check_col(fd, COL_INFO))
	col_add_fstr(fd, COL_INFO, "%s", cmd); 

    if (tree) {
	ti = proto_tree_add_item(tree, proto_ripng, offset, END_OF_FRAME, NULL);
	ripng_tree = proto_item_add_subtree(ti, ett_ripng);

	proto_tree_add_item_format(ripng_tree, hf_ripng_cmd, offset, 1,
	    rip6.rip6_cmd,
	    "Command: %s (%u)", cmd, rip6.rip6_cmd); 
	proto_tree_add_item(ripng_tree, hf_ripng_version, offset + 1, 1,
	    rip6.rip6_vers);

	offset += 4;
	while ((pi.captured_len - offset) >= sizeof(struct netinfo6)){
	    memcpy(&ni6, &pd[offset], sizeof(ni6));
	    if (ni6.rip6_tag) {
		ti = proto_tree_add_text(ripng_tree, offset,
				sizeof(ni6), "IP Address: %s/%d, Metric: %ld, tag: 0x%04x",
				ip6_to_str(&ni6.rip6_dest),
				ni6.rip6_plen,
				ni6.rip6_metric,
				ntohs(ni6.rip6_tag));
	    } else {
		ti = proto_tree_add_text(ripng_tree, offset,
				sizeof(ni6), "IP Address: %s/%d, Metric: %ld",
				ip6_to_str(&ni6.rip6_dest),
				ni6.rip6_plen,
				ni6.rip6_metric);
	    }
	    subtree = proto_item_add_subtree(ti, ett_ripng_addr);
	    proto_tree_add_text(subtree,
			offset + offsetof(struct netinfo6, rip6_dest),
			sizeof(ni6.rip6_dest), "IP Address: %s",
			ip6_to_str(&ni6.rip6_dest));
	    proto_tree_add_text(subtree,
			offset + offsetof(struct netinfo6, rip6_tag),
			sizeof(ni6.rip6_tag), "Tag: 0x%04x",
			ntohs(ni6.rip6_tag));
	    proto_tree_add_text(subtree,
			offset + offsetof(struct netinfo6, rip6_plen),
			sizeof(ni6.rip6_plen), "Prefix length: %d",
			ni6.rip6_plen);
	    proto_tree_add_text(subtree,
			offset + offsetof(struct netinfo6, rip6_metric),
			sizeof(ni6.rip6_metric), "Metric: %d",
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
				FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
      { &hf_ripng_version,
	{ "Version",		"ripng.version",
				FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
    };
    static gint *ett[] = {
      &ett_ripng,
      &ett_ripng_addr,
    };

    proto_ripng = proto_register_protocol("RIPng", "ripng");
    proto_register_field_array(proto_ripng, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}
