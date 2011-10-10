/* packet-rgmp.c
 * Routines for IGMP/RGMP packet disassembly
 * Copyright 2006 Jaap Keuter
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

/* 
 Based on RFC3488 

 This is a setup for RGMP dissection, a simple protocol bolted on IGMP.
 The trick is to have IGMP dissector call this function (which by itself is not
 registered as dissector). IGAP and other do the same.

 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include "packet-igmp.h"
#include "packet-rgmp.h"


static int proto_rgmp      = -1;
static int hf_type         = -1;
static int hf_checksum     = -1;
static int hf_checksum_bad = -1;
static int hf_maddr        = -1;

static int ett_rgmp = -1;

static const value_string rgmp_types[] = {
    {IGMP_RGMP_LEAVE, "Leave"},
    {IGMP_RGMP_JOIN,  "Join"},
    {IGMP_RGMP_BYE,   "Bye"},
    {IGMP_RGMP_HELLO, "Hello"},
    {0, NULL}
};

/* This function is only called from the IGMP dissector */
int
dissect_rgmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
    proto_tree *tree;
    proto_item *item;
    guint8 type;

    if (!proto_is_protocol_enabled(find_protocol_by_id(proto_rgmp))) {
	/* we are not enabled, skip entire packet to be nice
	   to the igmp layer. (so clicking on IGMP will display the data)
	   */
	return offset + tvb_length_remaining(tvb, offset);
    }

    item = proto_tree_add_item(parent_tree, proto_rgmp, tvb, offset, -1, FALSE);
    tree = proto_item_add_subtree(item, ett_rgmp);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RGMP");
    col_clear(pinfo->cinfo, COL_INFO);

    type = tvb_get_guint8(tvb, offset);
    if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_str(pinfo->cinfo, COL_INFO, 
		     val_to_str(type, rgmp_types, "Unknown Type: 0x%02x"));
    }
    proto_tree_add_uint(tree, hf_type, tvb, offset, 1, type);
    offset += 1;

    /* reserved */

    offset += 1;

    igmp_checksum(tree, tvb, hf_checksum, hf_checksum_bad, pinfo, 0);
    offset += 2;

    proto_tree_add_item(tree, hf_maddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}


void
proto_register_rgmp(void)
{
    static hf_register_info hf[] = {
	{ &hf_type,
	  { "Type", "rgmp.type", FT_UINT8, BASE_HEX,
	    VALS(rgmp_types), 0, "RGMP Packet Type", HFILL }
	},

	{ &hf_checksum,
	  { "Checksum", "rgmp.checksum", FT_UINT16, BASE_HEX,
	    NULL, 0, NULL, HFILL }
	},

	{ &hf_checksum_bad,
	  { "Bad Checksum", "rgmp.checksum_bad", FT_BOOLEAN, BASE_NONE,
	    NULL, 0x0, NULL, HFILL }
	},

	{ &hf_maddr,
	  { "Multicast group address", "rgmp.maddr", FT_IPv4, BASE_NONE,
	    NULL, 0, NULL, HFILL }
	}
    };

    static gint *ett[] = {
	&ett_rgmp
    };

    proto_rgmp = proto_register_protocol
	("Router-port Group Management Protocol", "RGMP", "rgmp");
    proto_register_field_array(proto_rgmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}
