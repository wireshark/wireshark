/* packet-ieee8021ah.c
 * Routines for 802.1ah ethernet header disassembly
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include "packet-ieee8023.h"
#include "packet-ieee8021ah.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include "packet-vlan.h"
#include <epan/etypes.h>
#include <epan/prefs.h>

void proto_reg_handoff_ieee8021ah(void);
void dissect_ieee8021ah_common(tvbuff_t *tvb, packet_info *pinfo,
			       proto_tree *tree, proto_tree *parent, int tree_index);

/* GLOBALS ************************************************************/

/* ethertype for 802.1ah tag - encapsulating an Ethernet packet */
static unsigned int ieee8021ah_ethertype = ETHERTYPE_IEEE_802_1AH;

static int proto_ieee8021ah = -1;
static int proto_ieee8021ad = -1;

/* dot1ad B-tag fields */
static int hf_ieee8021ad_priority = -1;
static int hf_ieee8021ad_cfi = -1;
static int hf_ieee8021ad_id = -1;
static int hf_ieee8021ad_svid = -1;
static int hf_ieee8021ad_cvid = -1;

/* dot1ah C-tag fields */
static int hf_ieee8021ah_priority = -1;
static int hf_ieee8021ah_drop = -1;   /* drop eligibility */
static int hf_ieee8021ah_nca = -1;    /* no customer addresses (c_daddr & c_saddr are 0) */
static int hf_ieee8021ah_res1 = -1;   /* 2 bits reserved; ignored on receive */
static int hf_ieee8021ah_res2 = -1;   /* 2 bits reserved; delete frame if non-zero */
static int hf_ieee8021ah_isid = -1;     /* I-SID */
static int hf_ieee8021ah_c_daddr = -1;  /* encapsulated customer dest addr */
static int hf_ieee8021ah_c_saddr = -1;  /* encapsulated customer src addr */

static int hf_ieee8021ah_etype = -1;
static int hf_ieee8021ah_len = -1;
static int hf_ieee8021ah_trailer = -1;

static gint ett_ieee8021ah = -1;
static gint ett_ieee8021ad = -1;

/* FUNCTIONS ************************************************************/


void
capture_ieee8021ah(const guchar *pd, int offset, int len, packet_counts *ld)
{
    guint16 encap_proto;

    if (!BYTES_ARE_IN_FRAME(offset, len, IEEE8021AH_LEN + 1)) {
	ld->other++;
	return;
    }
    encap_proto = pntohs( &pd[offset + IEEE8021AH_LEN - 2] );
    if (encap_proto <= IEEE_802_3_MAX_LEN) {
	if ( pd[offset + IEEE8021AH_LEN] == 0xff
	     && pd[offset + IEEE8021AH_LEN + 1] == 0xff ) {
	    capture_ipx(ld);
	}
	else {
	    capture_llc(pd, offset + IEEE8021AH_LEN,len,ld);
	}
    }
    else {
	capture_ethertype(encap_proto, pd, offset + IEEE8021AH_LEN, len, ld);
    }
}

/* Dissector *************************************************************/
static
void
dissect_ieee8021ad(tvbuff_t *tvb, packet_info *pinfo,
		   proto_tree *tree)
{
    proto_tree *ptree = NULL;
    proto_tree *tagtree = NULL;
    guint32 tci, ctci;
    guint16 encap_proto;
    proto_tree *volatile ieee8021ad_tree;
    proto_tree *volatile ieee8021ad_tag_tree;
    int proto_tree_index;
    tvbuff_t *volatile next_tvb = NULL;

    /* set tree index */
    proto_tree_index = proto_ieee8021ad;

    /* add info to column display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "802.1ad");
    col_clear(pinfo->cinfo, COL_INFO);

    tci = tvb_get_ntohs( tvb, 0 );

    if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO,
		     "PRI: %d  DROP: %d ID: %d",
		     (tci >> 13), ((tci >> 12) & 1), (tci & 0xFFF));
    }

    /* create the protocol tree */
    ieee8021ad_tree = NULL;

    if (tree) {
	ptree = proto_tree_add_item(tree, proto_tree_index, tvb, 0, IEEE8021AD_LEN, FALSE);
	ieee8021ad_tree = proto_item_add_subtree(ptree, ett_ieee8021ad);
    }

    encap_proto = tvb_get_ntohs(tvb, IEEE8021AD_LEN - 2);

    /* If it's a 1ah frame, create subtree for B-Tag, rename overall
       tree to 802.1ah, pass to 1ah dissector */
    if (encap_proto == ETHERTYPE_IEEE_802_1AH) {
	if (tree) {
	    tagtree = proto_tree_add_item(ptree, proto_tree_index, tvb, 0, 2, FALSE);
	    ieee8021ad_tag_tree = proto_item_add_subtree(tagtree, ett_ieee8021ad);

	    /* add fields */
	    proto_tree_add_uint(ieee8021ad_tag_tree, hf_ieee8021ad_priority, tvb,
				0, 1, tci);
	    proto_tree_add_uint(ieee8021ad_tag_tree, hf_ieee8021ad_cfi, tvb, 0, 1, tci);
	    proto_tree_add_uint(ieee8021ad_tag_tree, hf_ieee8021ad_id, tvb, 0, 2, tci);

	    /* set label of B-tag subtree */
	    proto_item_set_text(ieee8021ad_tag_tree, "B-Tag, B-VID: %d", tci & 0x0FFF);
	}

	next_tvb = tvb_new_subset_remaining(tvb, IEEE8021AD_LEN);

	if (ptree) {
	    /* add bvid to label */
	    proto_item_set_text(ptree, "IEEE 802.1ah, B-VID: %d", tci & 0x0FFF);

	    dissect_ieee8021ah_common(next_tvb, pinfo, ptree, tree, proto_tree_index);
	}
	else {
	    dissect_ieee8021ah_common(next_tvb, pinfo, tree, NULL, proto_tree_index);
	}

	return;
    } else if (encap_proto == ETHERTYPE_IEEE_802_1AD) {
	/* two VLAN tags (i.e. Q-in-Q) */
	ctci = tvb_get_ntohs(tvb, IEEE8021AD_LEN);

	if (tree) {
	    /* add fields */
	    proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_priority, tvb,
				0, 1, tci);
	    proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_cfi, tvb, 0, 1, tci);
	    proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_svid, tvb, 0, 2, tci);
	    proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_priority, tvb,
				IEEE8021AD_LEN, 1, ctci);
	    proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_cfi, tvb,
				IEEE8021AD_LEN, 1, ctci);
	    proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_cvid, tvb, IEEE8021AD_LEN,
				2, ctci);
	}

	proto_item_set_text(ptree, "IEEE 802.1ad, S-VID: %d, C-VID: %d", tci & 0x0FFF,
			    ctci & 0x0FFF);

	/* 802.1ad tags are always followed by an ethertype; call next
	   dissector based on ethertype */
	encap_proto = tvb_get_ntohs(tvb, IEEE8021AD_LEN * 2 - 2);
	ethertype(encap_proto, tvb, IEEE8021AD_LEN * 2, pinfo, tree, ieee8021ad_tree,
		  hf_ieee8021ah_etype, hf_ieee8021ah_trailer, 0);
    } else {
	/* Something else (shouldn't really happen, but we'll support it anyways) */
	if (tree) {
	    /* add fields */
	    proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_priority, tvb,
				0, 1, tci);
	    proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_cfi, tvb, 0, 1, tci);
	    proto_tree_add_uint(ieee8021ad_tree, hf_ieee8021ad_id, tvb, 0, 2, tci);
	}

	/* label should be 802.1ad not .1ah */
	proto_item_set_text(ptree, "IEEE 802.1ad, ID: %d", tci & 0x0FFF);

	/* 802.1ad tags are always followed by an ethertype; call next
	   dissector based on ethertype */
	ethertype(encap_proto, tvb, IEEE8021AD_LEN, pinfo, tree, ieee8021ad_tree,
		  hf_ieee8021ah_etype, hf_ieee8021ah_trailer, 0);
    }
}

void
dissect_ieee8021ah_common(tvbuff_t *tvb, packet_info *pinfo,
			  proto_tree *tree, proto_tree *parent, int tree_index) {
    guint32 tci;
    guint16 encap_proto;
    proto_tree *ptree;
    proto_tree *volatile ieee8021ah_tag_tree;

    /* for parsing out ethernet addrs */
    const guint8 *src_addr, *dst_addr;

    tci = tvb_get_ntohl( tvb, 0 );

    if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO,
		     "PRI: %d  Drop: %d  NCA: %d  Res1: %d  Res2: %d  I-SID: %d",
		     (tci >> 29), ((tci >> 28) & 1), ((tci >> 27) & 1),
		     ((tci >> 26) & 1), ((tci >> 24) & 3), tci & IEEE8021AH_ISIDMASK);
    }

    /* create the protocol tree */
    ptree = NULL;
    ieee8021ah_tag_tree = NULL;

    if (tree) {
	/* 802.1ah I-Tag */
	ptree = proto_tree_add_item(tree, tree_index, tvb, 0, 4, FALSE);
	ieee8021ah_tag_tree = proto_item_add_subtree(ptree, ett_ieee8021ah);

	/* add fields */
	proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_priority, tvb,
			    0, 1, tci);
	proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_drop, tvb, 0, 1, tci);
	proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_nca, tvb, 0, 1, tci);
	proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_res1, tvb, 0, 1, tci);
	proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_res2, tvb, 0, 1, tci);
	proto_tree_add_uint(ieee8021ah_tag_tree, hf_ieee8021ah_isid, tvb, 1, 3, tci);

	proto_item_set_text(ieee8021ah_tag_tree, "I-Tag, I-SID: %d",
			    tci & IEEE8021AH_ISIDMASK);

	/* ensure size of tag */
	tvb_ensure_bytes_exist(tvb, 4, 12);

	/* parse out IP addrs */
	dst_addr = tvb_get_ptr(tvb, 4, 6); /* safe to use this function? */
	src_addr = tvb_get_ptr(tvb, 10, 6);

	proto_tree_add_ether(tree, hf_ieee8021ah_c_daddr,
					 tvb, 4, 6, dst_addr);

	proto_tree_add_ether(tree, hf_ieee8021ah_c_saddr,
					 tvb, 10, 6, src_addr);

	/* add text to 802.1ad label */
	if (parent) {
	    proto_item_append_text(tree, ", I-SID: %d, C-Src: %s (%s), C-Dst: %s (%s)",
				   tci & IEEE8021AH_ISIDMASK, get_ether_name(src_addr),
				   ether_to_str(src_addr), get_ether_name(dst_addr),
				   ether_to_str(dst_addr));
	}
    }

    encap_proto = tvb_get_ntohs(tvb, IEEE8021AH_LEN - 2);

    /* 802.1ah I-tags are always followed by an ethertype; call next
       dissector based on ethertype */

    /* If this was preceded by a 802.1ad tag, must pass original tree
       to next dissector, not 802.1ad tree */
    if (parent) {
	ethertype(encap_proto, tvb, IEEE8021AH_LEN, pinfo, parent, tree,
		  hf_ieee8021ah_etype, hf_ieee8021ah_trailer, 0);
    }
    else {
	ethertype(encap_proto, tvb, IEEE8021AH_LEN, pinfo, tree, tree,
		  hf_ieee8021ah_etype, hf_ieee8021ah_trailer, 0);
    }
}

static
void
dissect_ieee8021ah(tvbuff_t *tvb, packet_info *pinfo,
		   proto_tree *tree)
{
    proto_tree *ptree;
    guint32 tci;
    proto_tree *volatile ieee8021ah_tree;
    int proto_tree_index;

    /* set tree index */
    proto_tree_index = proto_ieee8021ah;

    /* add info to column display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "802.1ah");
    col_clear(pinfo->cinfo, COL_INFO);

    tci = tvb_get_ntohl( tvb, 0 );

    if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO,
		     "PRI: %d  Drop: %d  NCA: %d  Res1: %d  Res2: %d  I-SID: %d",
		     (tci >> 29), ((tci >> 28) & 1), ((tci >> 27) & 1),
		     ((tci >> 26) & 1), ((tci >> 24) & 3), (tci & 0x00FFFFFF));
    }

    /* create the protocol tree */
    ieee8021ah_tree = NULL;

    if (tree) {
	ptree = proto_tree_add_item(tree, proto_tree_index, tvb, 0, IEEE8021AH_LEN, FALSE);
	ieee8021ah_tree = proto_item_add_subtree(ptree, ett_ieee8021ah);

	dissect_ieee8021ah_common(tvb, pinfo, ieee8021ah_tree, tree, proto_tree_index);
    }
}

/* Protocol Registration **************************************************/

void
proto_register_ieee8021ah(void)
{
    static hf_register_info hf[] = {
	{ &hf_ieee8021ah_priority, {
	    "Priority", "ieee8021ah.priority", FT_UINT32, BASE_DEC,
	    0, 0xE0000000, NULL, HFILL }},
	{ &hf_ieee8021ah_drop, {
	    "DROP", "ieee8021ah.drop", FT_UINT32, BASE_DEC,
	    0, 0x10000000, NULL, HFILL }},
	{ &hf_ieee8021ah_nca, {
	    "NCA", "ieee8021ah.nca", FT_UINT32, BASE_DEC,
	    0, 0x08000000, "No Customer Addresses", HFILL }},
	{ &hf_ieee8021ah_res1, {
	    "RES1", "ieee8021ah.res1", FT_UINT32, BASE_DEC,
	    0, 0x04000000, "Reserved1", HFILL }},
	{ &hf_ieee8021ah_res2, {
	    "RES2", "ieee8021ah.res2", FT_UINT32, BASE_DEC,
	    0, 0x03000000, "Reserved2", HFILL }},
	{ &hf_ieee8021ah_isid, {
	    "I-SID", "ieee8021ah.isid", FT_UINT32, BASE_DEC,
	    0, 0x00FFFFFF, NULL, HFILL }},
	{ &hf_ieee8021ah_c_daddr, {
	    "C-Destination", "ieee8021ah.cdst", FT_ETHER, BASE_NONE,
	    NULL, 0x0, "Customer Destination Address", HFILL }},
	{ &hf_ieee8021ah_c_saddr, {
	    "C-Source", "ieee8021ah.csrc", FT_ETHER, BASE_NONE,
	    NULL, 0x0, "Customer Source Address", HFILL }},
	{ &hf_ieee8021ah_etype, {
		"Type", "ieee8021ah.etype", FT_UINT16, BASE_HEX,
		VALS(etype_vals), 0x0, NULL, HFILL }},
	{ &hf_ieee8021ah_len, {
		"Length", "ieee8021ah.len", FT_UINT16, BASE_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_ieee8021ah_trailer, {
		"Trailer", "ieee8021ah.trailer", FT_BYTES, BASE_NONE,
		NULL, 0x0, "802.1ah Trailer", HFILL }}
    };

    static hf_register_info hf_1ad[] = {
	{ &hf_ieee8021ad_priority, {
		"Priority", "ieee8021ad.priority", FT_UINT16, BASE_DEC,
		0, 0xE000, NULL, HFILL }},
	{ &hf_ieee8021ad_cfi, {
		"DEI", "ieee8021ad.dei", FT_UINT16, BASE_DEC,
		0, 0x1000, "Drop Eligibility", HFILL }},
	{ &hf_ieee8021ad_id, {
		"ID", "ieee8021ad.id", FT_UINT16, BASE_DEC,
		0, 0x0FFF, "Vlan ID", HFILL }},
	{ &hf_ieee8021ad_svid, {
		"ID", "ieee8021ad.svid", FT_UINT16, BASE_DEC,
		0, 0x0FFF, "S-Vlan ID", HFILL }},
	{ &hf_ieee8021ad_cvid, {
		"ID", "ieee8021ad.cvid", FT_UINT16, BASE_DEC,
		0, 0x0FFF, "C-Vlan ID", HFILL }},
    };

    static gint *ett[] = {
	&ett_ieee8021ah,
	&ett_ieee8021ad
    };


    module_t *ieee8021ah_module;

    /* registration */
    /* dot1ah */
    proto_ieee8021ah = proto_register_protocol("IEEE 802.1ah", "IEEE 802.1AH",
					       "ieee8021ah");
    proto_register_field_array(proto_ieee8021ah, hf, array_length(hf));

    proto_ieee8021ad = proto_register_protocol("IEEE 802.1ad", "IEEE 802.1AD",
					       "ieee8021ad");
    proto_register_field_array(proto_ieee8021ad, hf_1ad, array_length(hf_1ad));

    /* register subtree array for both */
    proto_register_subtree_array(ett, array_length(ett));

    /* add a user preference to set the 802.1ah ethertype */
    ieee8021ah_module = prefs_register_protocol(proto_ieee8021ah,
						proto_reg_handoff_ieee8021ah);
    prefs_register_uint_preference(ieee8021ah_module, "8021ah_ethertype",
				   "802.1ah Ethertype (in hex)",
				   "(Hexadecimal) Ethertype used to indicate IEEE 802.1ah tag.",
				   16, &ieee8021ah_ethertype);
}

void
proto_reg_handoff_ieee8021ah(void)
{
    static gboolean prefs_initialized = FALSE;
    static dissector_handle_t ieee8021ah_handle;
    static unsigned int old_ieee8021ah_ethertype;

    if (!prefs_initialized){
	dissector_handle_t ieee8021ad_handle;
	ieee8021ah_handle = create_dissector_handle(dissect_ieee8021ah,
						    proto_ieee8021ah);
	ieee8021ad_handle = create_dissector_handle(dissect_ieee8021ad,
						    proto_ieee8021ad);
	dissector_add_uint("ethertype", ETHERTYPE_IEEE_802_1AD, ieee8021ad_handle);
	prefs_initialized = TRUE;
    }
    else {
	dissector_delete_uint("ethertype", old_ieee8021ah_ethertype, ieee8021ah_handle);
    }

    old_ieee8021ah_ethertype = ieee8021ah_ethertype;
    dissector_add_uint("ethertype", ieee8021ah_ethertype, ieee8021ah_handle);

}
