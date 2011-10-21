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
	{ 0x0002,	"Hewlett-Packard" },
	{ 0,		NULL }
};

static gint hf_hpteam = -1;
static gint hf_llc_hpteam_pid = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_hpteam = -1;

static void
dissect_hpteam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *hpteam_item;
	proto_tree *hpteam_tree;
	guint32 offset = 0;
	const char   *strPtr, *HP_Mac;
	const guint8 *mac_addr;

	mac_addr = pinfo->dl_dst.data;
	strPtr = ether_to_str(mac_addr);
	HP_Mac = "03:00:c7:00:00:ee";
	/*
	 * Check to see if SNAP frame is a HP Teaming frame or
	 * if it is really just SNAP
	 */
	if (memcmp(strPtr, HP_Mac, 17) == 0) {
		mac_addr = pinfo->dl_src.data;
		strPtr = ether_to_str(mac_addr);
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "HP NIC Team");
		/* Clear out stuff in the info column */
		col_set_str(pinfo->cinfo, COL_INFO, "HP NIC Teaming Heartbeat; ");
		col_append_fstr(pinfo->cinfo, COL_INFO, "Port MAC = %s ", strPtr);

		if (tree) { /* we are being asked for details */
			hpteam_item = proto_tree_add_item(tree, proto_hpteam, tvb, 0, -1, ENC_NA);
			hpteam_tree = proto_item_add_subtree(hpteam_item, ett_hpteam);
			proto_tree_add_item(hpteam_tree, hf_hpteam, tvb, offset, 58, ENC_NA);
		}
	}
	else {
		call_dissector(data_handle, tvb, pinfo, tree);
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
