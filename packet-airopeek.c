/* packet-airopeek.c
 * Routines for AiroPeek capture file dissection
 *
 * $Id: packet-airopeek.c,v 1.1 2002/01/29 09:45:55 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include "packet-ieee80211.h"

/* protocol */
static int proto_airopeek = -1;

/* header fields */
static int hf_airopeek_data_rate = -1;
static int hf_airopeek_channel = -1;
static int hf_airopeek_signal_strength = -1;

static gint ett_airopeek = -1;

static dissector_handle_t ieee80211_fixed_handle;

static void
dissect_airopeek(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *airopeek_tree;
	proto_item *ti;
	guint8 data_rate;
	guint8 signal_strength;
	tvbuff_t *next_tvb;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "AiroPeek");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_airopeek,
			tvb, 0, 3, "AiroPeek Radio Information");
		airopeek_tree = proto_item_add_subtree(ti, ett_airopeek);

		data_rate = tvb_get_guint8(tvb, 0);
		proto_tree_add_uint_format(airopeek_tree, hf_airopeek_data_rate,
		    tvb, 0, 1, data_rate,
		    "Data Rate: %g kb/s", .5*data_rate);

		proto_tree_add_item(airopeek_tree, hf_airopeek_channel,
		    tvb, 1, 1, FALSE);

		signal_strength = tvb_get_guint8(tvb, 2);
		proto_tree_add_uint_format(airopeek_tree, hf_airopeek_data_rate,
		    tvb, 2, 1, data_rate,
		    "Signal Strength: %u%%", signal_strength);
	}

	/* dissect the 802.11 header next */
	next_tvb = tvb_new_subset(tvb, 4, -1, -1);
	call_dissector(ieee80211_fixed_handle, next_tvb, pinfo, tree);
}

void
proto_register_airopeek(void)
{
	static hf_register_info hf[] = {
	    { &hf_airopeek_data_rate,
	      { "Data Rate", "airopeek.data_rate", FT_UINT8, BASE_DEC, NULL,
	        0x0, "", HFILL}},
	    { &hf_airopeek_channel,
	      { "Channel", "airopeek.channel", FT_UINT8, BASE_DEC, NULL,
	        0x0, "", HFILL}},
	    { &hf_airopeek_signal_strength,
	      { "Signal Strength", "airopeek.signal_strength", FT_UINT8, BASE_DEC, NULL,
	        0x0, "", HFILL}},
	}; 
	static gint *ett[] = {
		&ett_airopeek
	};

	proto_airopeek = proto_register_protocol("AiroPeek radio information",
	    "AiroPeek", "airopeek");
	proto_register_field_array(proto_airopeek, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_airopeek(void)
{
	dissector_handle_t airopeek_handle;

	/* handle for 802.11 dissector for fixed-length 802.11 headers */
	ieee80211_fixed_handle = find_dissector("wlan_fixed");

	airopeek_handle = create_dissector_handle(dissect_airopeek,
	    proto_airopeek);
	dissector_add("wtap_encap", WTAP_ENCAP_AIROPEEK, airopeek_handle);
}
