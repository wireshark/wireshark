/* packet-hpteam.c
 * Routines for HP Teaming heartbeat dissection
 * Copyright 2009, Nathan Hartwell <nhartwell@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/oui.h>
#include <string.h>
#include <packet-llc.h>


static int proto_hpteam = -1;

/* Handle of the "data" subdissector */
static dissector_handle_t data_handle;

/* Known HP NIC teaming PID values */
static const value_string hpteam_pid_vals[] = {
	{ 0x0002,	"HP Teaming heartbeat" },
	{ 0,		NULL }
};

static gint hf_hpteam = -1;
static gint hf_llc_hpteam_pid = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_hpteam = -1;

/*
 * According to the HP document at
 *
 *	http://www.hp.com/sbso/bus_protect/teaming.pdf
 *
 * the heartbeats are sent to 03-00-C7-00-00-EE in SNAP frames
 * in unnumbered TEST frames.  It says that the LLC header is
 * followed by 63 bytes of "Insignificant data" and the FCS.
 * This means that the SNAP header is part of the "Insignificant
 * data".
 *
 * The SNAP specification (section 10.3 "Subnetwork Access Protocol"
 * of IEEE Std 802-2001) says that *all* SNAP PDUs have an LLC
 * payload that starts with the 5-octet Protocol Identification
 * field, i.e. the OUI and PID.
 *
 * At least some Teaming heartbeat packets have an OUI of 00-80-5F,
 * which belongs to HP, and a protocol ID of 0x0002.
 *
 * If all heartbeat packets have that OUI/PID combination, and no other
 * packets have it, the right way to recognize them is by registering
 * the PID of 0x0002 in the dissector table for that OUI; there is no
 * need to check the destination MAC address.
 *
 * If not all heartbeat packets have that OUI/PID combination and/or other
 * packets have it, the only way to recognize them would be to add
 * support for heuristic dissectors to the SNAP dissector, register this
 * as a heuristic dissector for that table, and have it compare pinfo->dl_dst
 * against an address structure with a type of AT_ETHER, a length of 6,
 * and data of 03-00-C7-00-00-EE.  It is *not* sufficient to just check
 * pinfo->dl_dst.data, as there is no guarantee that it will be a MAC
 * address - SNAP frames can also be captured with "Linux cooked mode"
 * headers, e.g. on the "any" device, and those only have a destination
 * address for packets sent by the machine capturing the traffic, not for
 * packets received by the machine.
 */

static void
dissect_hpteam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *hpteam_item;
	proto_tree *hpteam_tree;
	guint32 offset = 0;

	/*
	 * No need to show the source MAC address; there's no 100%
	 * guarantee that it's there, and it should show up in
	 * the source address column by default.
	 */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HP NIC Team");
	col_set_str(pinfo->cinfo, COL_INFO, "HP NIC Teaming Heartbeat");

	if (tree) { /* we are being asked for details */
		hpteam_item = proto_tree_add_item(tree, proto_hpteam, tvb, 0, -1, ENC_NA);
		hpteam_tree = proto_item_add_subtree(hpteam_item, ett_hpteam);
		proto_tree_add_item(hpteam_tree, hf_hpteam, tvb, offset, -1, ENC_NA);
	}
}

void proto_register_hpteam(void)
{
	static hf_register_info hf_pid = {
		&hf_llc_hpteam_pid,
		{ "PID", "llc.hpteam_pid", FT_UINT16, BASE_HEX,
		  VALS(hpteam_pid_vals), 0x0, NULL, HFILL }
	};

	static hf_register_info hf_data[] = {
		{&hf_hpteam,
		{ "Proprietary Data", "hpteam.data", FT_BYTES, BASE_NONE,
		  NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_hpteam
	};

	proto_hpteam = proto_register_protocol ("HP NIC Teaming Heartbeat", "HPTEAM", "hpteam");

	/*Tied into the LLC dissector so register the OUI with LLC*/
	llc_add_oui(OUI_HP_2, "llc.hpteam_pid", "Hewlett Packard OUI PID", &hf_pid);
	proto_register_field_array(proto_hpteam, hf_data, array_length(hf_data));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("hpteam", dissect_hpteam, proto_hpteam);
}

void proto_reg_handoff_hpteam(void)
{
	dissector_handle_t hpteam_handle;

	data_handle   = find_dissector("data");
	hpteam_handle = find_dissector("hpteam");
	/* Register dissector to key off of known PID / OUI combination */
	dissector_add_uint("llc.hpteam_pid", 0x0002, hpteam_handle);
}
