/* packet-mpls.c
 * Routines for MPLS data packet disassembly
 * 
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id: packet-mpls.c,v 1.5 2000/04/16 22:59:37 guy Exp $
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

/*
 * NOTES
 *
 * This module defines routines to handle Ethernet-encapsulated MPLS IP packets.
 * It should implement all the functionality in <draft-ietf-mpls-label-encaps-07.txt>
 * Multicast MPLS support is not tested yet
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include "etypes.h"
#include "packet.h"
#include "packet-ip.h"

static gint proto_mpls = -1;

static gint ett_mpls = -1;

/* Special labels in MPLS */
enum {
    IP4_EXPLICIT_NULL = 0,
    ROUTER_ALERT,
    IP6_EXPLICIT_NULL,
    IMPLICIT_NULL,

    MAX_RESERVED = 15
};

static const value_string special_labels[] = {
    {IP4_EXPLICIT_NULL, "IPv4 Explicit-Null"},
    {ROUTER_ALERT, "Router Alert"},
    {IP6_EXPLICIT_NULL, "IPv6 Explicit-Null"},
    {IMPLICIT_NULL, "Implicit-Null"},
    {0, NULL }
};

/* MPLS filter values */
enum mpls_filter_keys {

    /* Is the packet MPLS-encapsulated? */
/*    MPLSF_PACKET,*/

    /* MPLS encap properties */
    MPLSF_LABEL,
    MPLSF_EXP,
    MPLSF_BOTTOM_OF_STACK,
    MPLSF_TTL,

    MPLSF_MAX
};

static int mpls_filter[MPLSF_MAX];
static hf_register_info mplsf_info[] = {

/*    {&mpls_filter[MPLSF_PACKET], 
     {"MPLS Label Switched Packet", "mpls", FT_UINT8, BASE_NONE, NULL, 0x0, 
      "" }},*/

    {&mpls_filter[MPLSF_LABEL], 
     {"MPLS Label", "mpls.label", FT_UINT32, BASE_DEC, VALS(special_labels), 0x0, 
      "" }},

    {&mpls_filter[MPLSF_EXP], 
     {"MPLS Experimental Bits", "mpls.exp", FT_UINT8, BASE_DEC, NULL, 0x0, 
      "" }},

    {&mpls_filter[MPLSF_BOTTOM_OF_STACK], 
     {"MPLS Bottom Of Label Stack", "mpls.bottom", FT_UINT8, BASE_DEC, NULL, 0x0, 
      "" }},

    {&mpls_filter[MPLSF_TTL], 
     {"MPLS TTL", "mpls.ttl", FT_UINT8, BASE_DEC, NULL, 0x0, 
      "" }},
};

/*
 * Given a 4-byte MPLS label starting at "start", decode this.
 * Return the label in "label", EXP bits in "exp",
 * bottom_of_stack in "bos", and TTL in "ttl"
 */
void decode_mpls_label(const unsigned char *start,  
		       guint32 *label, guint8 *exp,
		       guint8 *bos, guint8 *ttl)
{
    *label = (start[0] << 12) + (start[1] << 4) + ((start[2] >> 4) & 0xff);
    *exp = (start[2] >> 1) & 0x7;
    *bos = (start[2] & 0x1);
    *ttl = start[3];
}

static void
dissect_mpls(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
    guint32 label;
    guint8 exp;
    guint8 bos;
    guint8 ttl;

    proto_tree  *mpls_tree;
    proto_item  *ti;

    if (check_col(fd, COL_PROTOCOL)) {
	col_add_str(fd,COL_PROTOCOL, "MPLS");
    }
    
    if (check_col(fd,COL_INFO)) {
	col_add_fstr(fd,COL_INFO,"MPLS Label Switched Packet");
    }

    /* Start Decoding Here. */
    while (1) {
	if (!BYTES_ARE_IN_FRAME(offset, 4)) {
	    dissect_data(pd, offset, fd, tree);
	    return;
	}

	decode_mpls_label(pd+offset, &label, &exp, &bos, &ttl);

	if (tree) {

	    ti = proto_tree_add_item(tree, proto_mpls, offset, 4, NULL);
	    mpls_tree = proto_item_add_subtree(ti, ett_mpls);

	    if (label <= MAX_RESERVED)
		proto_tree_add_uint_format(mpls_tree, mpls_filter[MPLSF_LABEL],
				    offset, 3, label, "Label: %d (%s)", 
				    label, val_to_str(label, special_labels, 
						      "Reserved - Unknown"));
	    else
		proto_tree_add_item(mpls_tree, mpls_filter[MPLSF_LABEL],
				    offset, 3, label);

	    proto_tree_add_item(mpls_tree,mpls_filter[MPLSF_EXP], 
				offset+2,1, exp);
	    proto_tree_add_item(mpls_tree,mpls_filter[MPLSF_BOTTOM_OF_STACK], 
				offset+2,1, bos);
	    proto_tree_add_item(mpls_tree,mpls_filter[MPLSF_TTL], 
				offset+3,1, ttl);
	}
	offset += 4;
	if (bos) break;
    }
    dissect_ip(pd, offset, fd, tree);
}

void
proto_register_mpls(void)
{
	static gint *ett[] = {
		&ett_mpls,
	};

	proto_mpls = proto_register_protocol("MultiProtocol Label Switching Header", "mpls");
	proto_register_field_array(proto_mpls, mplsf_info, array_length(mplsf_info));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mpls(void)
{
	dissector_add("ethertype", ETHERTYPE_MPLS, dissect_mpls);
}
