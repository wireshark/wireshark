/* packet-pw-eth.c
 * Routines for ethernet PW dissection:
 * it should be conformance to RFC 4448.
 *
 * Copyright 2008 _FF_
 *
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-mpls.h"

static gint proto_pw_eth = -1;
static gint proto_pw_eth_nocw = -1;

static gint ett_pw_eth = -1;

static int hf_pw_eth = -1;
static int hf_pw_eth_cw = -1;
static int hf_pw_eth_cw_sequence_number = -1;

static hf_register_info hf[] = {
	{
		&hf_pw_eth,
		{
			"PW (ethernet)", 
			"pweth", FT_BOOLEAN, 
			0, NULL, 0x0, NULL, HFILL
		}
	},
	{
		&hf_pw_eth_cw,
		{
			"PW Control Word (ethernet)", 
			"pweth.cw", FT_BOOLEAN, 
			0, NULL, 0x0, NULL, HFILL
		}
	},
	{
		&hf_pw_eth_cw_sequence_number,
		{
			"PW sequence number (ethernet)", 
			"pweth.cw.sequence_number", FT_UINT16, 
			BASE_DEC, NULL, 0x0, NULL, HFILL
		}
	}
};

static gint *ett[] = {
	&ett_pw_eth
};

static dissector_handle_t eth_withoutfcs_handle;

static void
dissect_pw_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *pw_eth_tree = NULL;
	proto_item *ti = NULL;
	tvbuff_t *next_tvb = NULL;
	guint16 sequence_number = 0;
	
	if (tvb_reported_length_remaining(tvb, 0) < 4) {
		if (tree)
			proto_tree_add_text(tree, tvb, 0, -1, 
					    "Error processing Message");
		return;
	}
	sequence_number = tvb_get_ntohs(tvb, 2);
	if (tree) {
		ti = proto_tree_add_boolean(tree, hf_pw_eth_cw, tvb, 0, 0, TRUE);
		PROTO_ITEM_SET_HIDDEN(ti);
		ti = proto_tree_add_item(tree, proto_pw_eth, tvb, 0, 4, FALSE);
		pw_eth_tree = proto_item_add_subtree(ti, ett_pw_eth);
		if (pw_eth_tree == NULL)
			return;
		proto_tree_add_uint_format(pw_eth_tree, 
					   hf_pw_eth_cw_sequence_number,
					   tvb, 2, 2, sequence_number,
					   "Sequence Number: %d", 
					   sequence_number);
	}
	next_tvb = tvb_new_subset(tvb, 4, -1, -1);
	call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
}

static void
dissect_pw_eth_nocw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb = NULL;
	proto_item *ti = NULL;

	if (tree) {
		ti = proto_tree_add_boolean(tree, hf_pw_eth, tvb, 0, 0, TRUE);
		PROTO_ITEM_SET_HIDDEN(ti);
	}
	next_tvb = tvb_new_subset(tvb, 0, -1, -1);
	call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
}

void
proto_register_pw_eth(void)
{
	proto_pw_eth = proto_register_protocol("PW Control Word (ethernet)",
                                               "PWETH", "pweth");
	proto_pw_eth_nocw = proto_register_protocol("PW (ethernet)",
						    "PWETH (no CW)", 
						    "");
	proto_register_field_array(proto_pw_eth, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("pw_eth", dissect_pw_eth, proto_pw_eth);
	register_dissector("pw_eth_nocw", dissect_pw_eth_nocw, 
			   proto_pw_eth_nocw);
}

void
proto_reg_handoff_pw_eth(void)
{
	dissector_handle_t pw_eth_handle;
	dissector_handle_t pw_eth_handle_nocw;

	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");

	pw_eth_handle = create_dissector_handle(dissect_pw_eth, proto_pw_eth);
	dissector_add("mpls.label", LABEL_INVALID, pw_eth_handle);
	pw_eth_handle_nocw = create_dissector_handle(dissect_pw_eth_nocw, 
						     proto_pw_eth_nocw);
	dissector_add("mpls.label", LABEL_INVALID, pw_eth_handle_nocw);
}
