/* packet-mpls.c
 * Routines for MPLS data packet disassembly
 * 
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id: packet-mpls.c,v 1.17 2001/01/25 06:14:14 guy Exp $
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
#include "ppptypes.h"
#include "packet-ppp.h"

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

static dissector_handle_t ip_handle;

/*
 * Given a 4-byte MPLS label starting at offset "offset", in tvbuff "tvb",
 * decode it.
 * Return the label in "label", EXP bits in "exp",
 * bottom_of_stack in "bos", and TTL in "ttl"
 */
void decode_mpls_label(tvbuff_t *tvb, int offset,
		       guint32 *label, guint8 *exp,
		       guint8 *bos, guint8 *ttl)
{
    guint8 octet0 = tvb_get_guint8(tvb, offset+0);
    guint8 octet1 = tvb_get_guint8(tvb, offset+1);
    guint8 octet2 = tvb_get_guint8(tvb, offset+2);

    *label = (octet0 << 12) + (octet1 << 4) + ((octet2 >> 4) & 0xff);
    *exp = (octet2 >> 1) & 0x7;
    *bos = (octet2 & 0x1);
    *ttl = tvb_get_guint8(tvb, offset+3);
}

static void
dissect_mpls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
    int offset = 0;
    guint32 label;
    guint8 exp;
    guint8 bos;
    guint8 ttl;

    proto_tree  *mpls_tree;
    proto_item  *ti;
    tvbuff_t *next_tvb;

    if (check_col(pinfo->fd, COL_PROTOCOL)) {
	col_set_str(pinfo->fd,COL_PROTOCOL, "MPLS");
    }
    
    if (check_col(pinfo->fd,COL_INFO)) {
	col_add_fstr(pinfo->fd,COL_INFO,"MPLS Label Switched Packet");
    }

    /* Start Decoding Here. */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
	decode_mpls_label(tvb, offset, &label, &exp, &bos, &ttl);

	if (tree) {

	    ti = proto_tree_add_item(tree, proto_mpls, tvb, offset, 4, FALSE);
	    mpls_tree = proto_item_add_subtree(ti, ett_mpls);

	    if (label <= MAX_RESERVED)
		proto_tree_add_uint_format(mpls_tree, mpls_filter[MPLSF_LABEL], tvb,
				    offset, 3, label, "Label: %u (%s)", 
				    label, val_to_str(label, special_labels, 
						      "Reserved - Unknown"));
	    else
		proto_tree_add_uint(mpls_tree, mpls_filter[MPLSF_LABEL], tvb,
				    offset, 3, label);

	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_EXP], tvb, 
				offset+2,1, exp);
	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_BOTTOM_OF_STACK], tvb, 
				offset+2,1, bos);
	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_TTL], tvb, 
				offset+3,1, ttl);
	}
	offset += 4;
	if (bos) break;
    }
    next_tvb = tvb_new_subset(tvb, offset, -1, -1);
    call_dissector(ip_handle, next_tvb, pinfo, tree);
}

void
proto_register_mpls(void)
{
	static gint *ett[] = {
		&ett_mpls,
	};

	proto_mpls = proto_register_protocol("MultiProtocol Label Switching Header",
	    "MPLS", "mpls");
	proto_register_field_array(proto_mpls, mplsf_info, array_length(mplsf_info));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mpls(void)
{
	/*
	 * Get a handle for the IP dissector.
	 */
	ip_handle = find_dissector("ip");

	dissector_add("ethertype", ETHERTYPE_MPLS, dissect_mpls, proto_mpls);
	dissector_add("ppp.protocol", PPP_MPLS_UNI, dissect_mpls, proto_mpls);
}
