/* packet-mpls.c
 * Routines for MPLS data packet disassembly
 * RFC 3032
 *
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id$
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/ppptypes.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include "packet-ppp.h"
#include "packet-mpls.h"

static gint proto_mpls = -1;

static gint ett_mpls = -1;
static gint ett_mpls_control = -1;

const value_string special_labels[] = {
    {LABEL_IP4_EXPLICIT_NULL,	"IPv4 Explicit-Null"},
    {LABEL_ROUTER_ALERT,	"Router Alert"},
    {LABEL_IP6_EXPLICIT_NULL,	"IPv6 Explicit-Null"},
    {LABEL_IMPLICIT_NULL,	"Implicit-Null"},
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
static int hf_mpls_control_control = -1;
static int hf_mpls_control_res = -1;

static hf_register_info mplsf_info[] = {

/*    {&mpls_filter[MPLSF_PACKET],
     {"MPLS Label Switched Packet", "mpls", FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }},*/

    {&mpls_filter[MPLSF_LABEL],
     {"MPLS Label", "mpls.label", FT_UINT32, BASE_DEC, VALS(special_labels), 0x0,
      "", HFILL }},

    {&mpls_filter[MPLSF_EXP],
     {"MPLS Experimental Bits", "mpls.exp", FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }},

    {&mpls_filter[MPLSF_BOTTOM_OF_STACK],
     {"MPLS Bottom Of Label Stack", "mpls.bottom", FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }},

    {&mpls_filter[MPLSF_TTL],
     {"MPLS TTL", "mpls.ttl", FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }},

    {&hf_mpls_control_control,
     {"MPLS Control Channel", "mpls.cw.control", FT_UINT8, BASE_DEC, NULL, 0xF0,
      "First nibble", HFILL }},

    {&hf_mpls_control_res,
     {"Reserved", "mpls.cw.res", FT_UINT16, BASE_HEX, NULL, 0xFFF, 
      "Reserved", HFILL }},
};

static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t data_handle;
static dissector_table_t ppp_subdissector_table;

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
dissect_mpls_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *mpls_control_tree = NULL;
    proto_item  *ti;
    tvbuff_t    *next_tvb;
    guint8      ctrl;
    guint16     res, ppp_proto;

    if (tvb_reported_length_remaining(tvb, 0) < 4){
        if(tree)
            proto_tree_add_text(tree, tvb, 0, -1, "Error processing Message");
        return;
    }
    ctrl = (tvb_get_guint8(tvb, 0) & 0xF0) >> 4;
    res = tvb_get_ntohs(tvb, 0) & 0x0FFF;
    ppp_proto = tvb_get_ntohs(tvb, 2);
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, 4, "MPLS PW Control Channel Header");
        mpls_control_tree = proto_item_add_subtree(ti, ett_mpls_control);
        if(mpls_control_tree == NULL) return;

        proto_tree_add_uint_format(mpls_control_tree, hf_mpls_control_control, tvb, 0, 1,
            ctrl, "Control Channel: 0x%1x", ctrl);
        proto_tree_add_uint_format(mpls_control_tree, hf_mpls_control_res, tvb, 0, 2,
            res, "Reserved: 0x%03x", res);
        proto_tree_add_text(mpls_control_tree, tvb, 2, 2,
            "PPP DLL Protocol Number: %s (0x%04X)", 
                val_to_str(ppp_proto, ppp_vals, "Unknown"), ppp_proto);
    }
    next_tvb = tvb_new_subset(tvb, 4, -1, -1);
    if (!dissector_try_port(ppp_subdissector_table, ppp_proto, 
        next_tvb, pinfo, tree)) {
            call_dissector(data_handle, next_tvb, pinfo, tree);
    }


}

static void
dissect_mpls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint32 label;
    guint8 exp;
    guint8 bos;
    guint8 ttl;
    guint8 ipvers;

    proto_tree  *mpls_tree;
    proto_item  *ti;
    tvbuff_t *next_tvb;

    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
	col_set_str(pinfo->cinfo,COL_PROTOCOL, "MPLS");
    }

    if (check_col(pinfo->cinfo,COL_INFO)) {
	col_add_fstr(pinfo->cinfo,COL_INFO,"MPLS Label Switched Packet");
    }

    /* Start Decoding Here. */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
	decode_mpls_label(tvb, offset, &label, &exp, &bos, &ttl);

	if (tree) {

	    ti = proto_tree_add_item(tree, proto_mpls, tvb, offset, 4, FALSE);
	    mpls_tree = proto_item_add_subtree(ti, ett_mpls);

	    proto_item_append_text(ti, ", Label: %u", label);
	    if (label <= LABEL_MAX_RESERVED){
		proto_tree_add_uint_format(mpls_tree, mpls_filter[MPLSF_LABEL], tvb,
				    offset, 3, label, "MPLS Label: %u (%s)",
				    label, val_to_str(label, special_labels,
						      "Reserved - Unknown"));
		proto_item_append_text(ti, " (%s)", val_to_str(label, special_labels,
					"Reserved - Unknown"));
	    } else {
		proto_tree_add_uint_format(mpls_tree, mpls_filter[MPLSF_LABEL], tvb,
				    offset, 3, label, "MPLS Label: %u", label);
	    }

	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_EXP], tvb,
				offset+2,1, exp);
	    proto_item_append_text(ti, ", Exp: %u", exp);

	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_BOTTOM_OF_STACK], tvb,
				offset+2,1, bos);
	    proto_item_append_text(ti, ", S: %u", bos);

	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_TTL], tvb,
				offset+3,1, ttl);
	    proto_item_append_text(ti, ", TTL: %u", ttl);
	}
	offset += 4;
	if (bos) break;
    }
    next_tvb = tvb_new_subset(tvb, offset, -1, -1);

    ipvers = (tvb_get_guint8(tvb, offset) >> 4) & 0x0F;
    if (ipvers == 6) {
      call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    } else if (ipvers == 4) {
      call_dissector(ipv4_handle, next_tvb, pinfo, tree);
    } else if (ipvers == 1) {
      dissect_mpls_control(next_tvb, pinfo, tree);
    } else {
      call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
    }
}

void
proto_register_mpls(void)
{
	static gint *ett[] = {
		&ett_mpls,
                &ett_mpls_control,
	};

	proto_mpls = proto_register_protocol("MultiProtocol Label Switching Header",
	    "MPLS", "mpls");
	proto_register_field_array(proto_mpls, mplsf_info, array_length(mplsf_info));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("mpls", dissect_mpls, proto_mpls);
}

void
proto_reg_handoff_mpls(void)
{
	dissector_handle_t mpls_handle;

	/*
	 * Get a handle for the IPv4 and IPv6 dissectors and PPP protocol dissector table.
	 */
	ipv4_handle = find_dissector("ip");
	ipv6_handle = find_dissector("ipv6");
	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
        data_handle = find_dissector("data");
        ppp_subdissector_table = find_dissector_table("ppp.protocol");


	mpls_handle = create_dissector_handle(dissect_mpls, proto_mpls);
	dissector_add("ethertype", ETHERTYPE_MPLS, mpls_handle);
	dissector_add("ethertype", ETHERTYPE_MPLS_MULTI, mpls_handle);
	dissector_add("ppp.protocol", PPP_MPLS_UNI, mpls_handle);
	dissector_add("ppp.protocol", PPP_MPLS_MULTI, mpls_handle);
	dissector_add("chdlctype", ETHERTYPE_MPLS, mpls_handle);
	dissector_add("chdlctype", ETHERTYPE_MPLS_MULTI, mpls_handle);
	dissector_add("gre.proto", ETHERTYPE_MPLS, mpls_handle);
	dissector_add("gre.proto", ETHERTYPE_MPLS_MULTI, mpls_handle);
}
