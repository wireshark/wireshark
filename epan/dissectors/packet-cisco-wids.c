/* packet-cwids.c
 * Routines for dissecting wireless ids packets sent from a Cisco 
 * access point to the WLSE (or whatever)
 *
 * $Id$
 *
 * Copyright 2006 Joerg Mayer (see AUTHORS file)
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

/* With current IOS, you can use Cisco wireless Bridges/APs as a
 * wireless sniffers and configure them with the "monitor ..."
 * command to * send the data to some central IDS.
 * This dissector tries to decode those frames.
 */

/* 2do:
 *	- Find out more about the contents of the capture header
 *	- Protect the address fields etc (all columns?)
 *	- Create subelements and put each header and packet into it
 *	- fuzz-test the dissector
 *	- Find some heuristic do detect the packet automagically and
 *	  convert dissector into a heuristic dissector
 *	- Is the TRY/CATCH stuff OK?
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/prefs.h>

static guint udp_port = 0;
void proto_reg_handoff_cwids(void);


static int proto_cwids = -1;
static int hf_cwids_version = -1;
static int hf_cwids_unknown1 = -1;
static int hf_cwids_reallength = -1;
static int hf_cwids_capturelen = -1;
static int hf_cwids_unknown2 = -1;
static int hf_cwids_trailer = -1;

static gint ett_cwids = -1;

static dissector_handle_t ieee80211_handle;

static void
dissect_cwids(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *wlan_tvb;
	proto_tree *ti, *cwids_tree;
	int offset = 0;
	guint16 capturelen;
	guint remain;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CWIDS");
	if (check_col(pinfo->cinfo, COL_INFO))
	  col_clear(pinfo->cinfo, COL_INFO);

	if (check_col(pinfo->cinfo, COL_INFO)) {
	  col_add_fstr(pinfo->cinfo, COL_INFO, "Cwids: ");
	}
	/* FIXME: col_set_fence(pinfo->cinfo, all-cols, only addr-cols?); */

	cwids_tree = NULL;

	while((remain = tvb_length_remaining(tvb, offset)) >= 28) {
		ti = proto_tree_add_item(tree, proto_cwids, tvb, offset, 28, FALSE);
		cwids_tree = proto_item_add_subtree(ti, ett_cwids);
	
		proto_tree_add_item(cwids_tree, hf_cwids_version, tvb, offset, 2, FALSE);
		offset += 2;
		proto_tree_add_item(cwids_tree, hf_cwids_unknown1, tvb, offset, 14, FALSE);
		offset += 14;
		proto_tree_add_item(cwids_tree, hf_cwids_reallength, tvb, offset, 2, FALSE);
		offset += 2;
		capturelen = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(cwids_tree, hf_cwids_capturelen, tvb, offset, 2, FALSE);
		offset += 2;
		proto_tree_add_item(cwids_tree, hf_cwids_unknown2, tvb, offset, 8, FALSE);
		offset += 8;
	
		wlan_tvb = tvb_new_subset(tvb, offset, capturelen, capturelen);
		/* Continue after ieee80211 dissection errors */
		TRY {
			call_dissector(ieee80211_handle, wlan_tvb, pinfo, tree);
		} CATCH2(BoundsError, ReportedBoundsError) {

			expert_add_info_format(pinfo, NULL,
				PI_MALFORMED, PI_ERROR,
				"Malformed or short IEEE80211 subpacket");

			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_str(pinfo->cinfo, COL_INFO,
					" [Malformed or short IEEE80211 subpacket] " );
				col_set_fence(pinfo->cinfo, COL_INFO);
			}

	wlan_tvb = tvb_new_subset(tvb, offset, capturelen, capturelen);
#if 0
			/* FIXME: Why does this throw an exception? */
			proto_tree_add_text(cwids_tree, wlan_tvb, offset, capturelen, 
				"[Malformed or short IEEE80211 subpacket]");
#endif
	;
		} ENDTRY;

		offset += capturelen;
	}
	if (remain > 0) { /* FIXME: Shouldn't happen? */
		ti = proto_tree_add_item(tree, proto_cwids, tvb, offset, remain, FALSE);
		cwids_tree = proto_item_add_subtree(ti, ett_cwids);

		proto_tree_add_item(cwids_tree, hf_cwids_trailer, tvb, offset, remain, FALSE);
	}
}

void
proto_register_cwids(void)
{
	static hf_register_info hf[] = {
		{ &hf_cwids_version,
		{ "Capture Version", "cwids.version", FT_UINT16, BASE_DEC, NULL,
			0x0, "Version or format of record", HFILL }},

		{ &hf_cwids_unknown1,
		{ "Unknown1", "cwids.unknown1", FT_BYTES, BASE_NONE, NULL,
			0x0, "1st Unknown block", HFILL }},

		{ &hf_cwids_reallength,
		{ "Original length", "cwids.reallen", FT_UINT16, BASE_DEC, NULL,
			0x0, "Original num bytes in frame", HFILL }},

		{ &hf_cwids_capturelen,
		{ "Capture length", "cwids.caplen", FT_UINT16, BASE_DEC, NULL,
			0x0, "Captured bytes in record", HFILL }},

		{ &hf_cwids_unknown2,
		{ "Unknown2", "cwids.unknown2", FT_BYTES, BASE_NONE, NULL,
			0x0, "2nd Unknown block", HFILL }},

		{ &hf_cwids_trailer,
		{ "Trailer", "cwids.trailer", FT_BYTES, BASE_NONE, NULL,
			0x0, "CWIDS trailer", HFILL }},
	};
	static gint *ett[] = {
		&ett_cwids,
	};

	module_t *cwids_module;

	proto_cwids = proto_register_protocol("Cisco Wireless IDS Captures", "CWIDS", "cwids");
	proto_register_field_array(proto_cwids, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	cwids_module = prefs_register_protocol(proto_cwids, proto_reg_handoff_cwids);
	prefs_register_uint_preference(cwids_module, "udp.port",
		"CWIDS port",
		"Set the destination UDP port Cisco wireless IDS messages",
		10, &udp_port);

}

void
proto_reg_handoff_cwids(void)
{
	dissector_handle_t cwids_handle;

	ieee80211_handle = find_dissector("wlan");

	cwids_handle = create_dissector_handle(dissect_cwids, proto_cwids);
	dissector_add("udp.port", udp_port, cwids_handle);
}

