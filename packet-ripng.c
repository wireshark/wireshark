/* packet-ripng.c
 * Routines for RIPng disassembly
 * (c) Copyright Jun-ichiro itojun Hagino <itojun@itojun.org>
 * derived from packet-rip.c
 *
 * $Id: packet-ripng.c,v 1.1 1999/10/12 23:12:06 guy Exp $
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

static int proto_ripng = -1;

void 
dissect_ripng(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    struct rip6 rip6;
    struct netinfo6 ni6;
    proto_tree *ripng_tree = NULL;
	proto_item *ti; 
    char *packet_type[] = { "*invalid*", "Request", "Response" };
    char *cmd;

    /* avoid alignment problem */
    memcpy(&rip6, &pd[offset], sizeof(rip6));
  
    switch (rip6.rip6_cmd) {
    case RIP6_REQUEST:
    case RIP6_RESPONSE:
	cmd = packet_type[rip6.rip6_cmd];
	break;
    default:
	cmd = packet_type[0];
	break;
    }

    if (check_col(fd, COL_PROTOCOL))
        col_add_fstr(fd, COL_PROTOCOL, "RIPng version %d", rip6.rip6_vers);
    if (check_col(fd, COL_INFO))
	col_add_str(fd, COL_INFO, cmd); 

    if (tree) {
	ti = proto_tree_add_item(tree, proto_ripng, offset, END_OF_FRAME, NULL);
	ripng_tree = proto_item_add_subtree(ti, ETT_RIP);

	proto_tree_add_text(ripng_tree, offset, 1,
	    "Command: %d (%s)", rip6.rip6_cmd, cmd); 
	proto_tree_add_text(ripng_tree, offset + 1, 1,
	    "Version: %d", rip6.rip6_vers);

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

            offset += sizeof(ni6);
        }
    }
}

void
proto_register_ripng(void)
{
        proto_ripng = proto_register_protocol("RIPng", "ripng");
}
