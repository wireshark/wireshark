/* packet-cgmp.c
 * Routines for the disassembly of the Cisco Group Management Protocol
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

/*
 * See
 *
 * http://www.barnett.sk/software/bbooks/cisco_multicasting_routing/chap04.html
 *
 * for some information on CGMP.
 */

static int proto_cgmp = -1;
static int hf_cgmp_version = -1;
static int hf_cgmp_type = -1;
static int hf_cgmp_count = -1;
static int hf_cgmp_gda = -1;
static int hf_cgmp_usa = -1;

static gint ett_cgmp = -1;

static const value_string type_vals[] = {
	{ 0, "Join" },
	{ 1, "Leave" },
	{ 0, NULL },
};

static void
dissect_cgmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *cgmp_tree = NULL;
	int offset = 0;
	guint8 count;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CGMP");
	col_set_str(pinfo->cinfo, COL_INFO, "Cisco Group Management Protocol");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_cgmp, tvb, offset, -1,
		    ENC_NA);
		cgmp_tree = proto_item_add_subtree(ti, ett_cgmp);

		proto_tree_add_item(cgmp_tree, hf_cgmp_version, tvb, offset, 1,
		    ENC_BIG_ENDIAN);
		proto_tree_add_item(cgmp_tree, hf_cgmp_type, tvb, offset, 1,
		    ENC_BIG_ENDIAN);
		offset += 1;

		offset += 2;	/* skip reserved field */

		count = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(cgmp_tree, hf_cgmp_count, tvb, offset, 1,
		    count);
		offset += 1;

		while (count != 0) {
			proto_tree_add_item(cgmp_tree, hf_cgmp_gda, tvb, offset, 6,
			    ENC_NA);
			offset += 6;

			proto_tree_add_item(cgmp_tree, hf_cgmp_usa, tvb, offset, 6,
			    ENC_NA);
			offset += 6;

			count--;
		}
	}
}

void
proto_register_cgmp(void)
{
	static hf_register_info hf[] = {
		{ &hf_cgmp_version,
		{ "Version",	"cgmp.version",	FT_UINT8, BASE_DEC, NULL, 0xF0,
			NULL, HFILL }},

		{ &hf_cgmp_type,
		{ "Type",	"cgmp.type",	FT_UINT8, BASE_DEC, VALS(type_vals), 0x0F,
			NULL, HFILL }},

		{ &hf_cgmp_count,
		{ "Count",	"cgmp.count", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_cgmp_gda,
		{ "Group Destination Address",	"cgmp.gda", FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_cgmp_usa,
		{ "Unicast Source Address",	"cgmp.usa", FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
        };
	static gint *ett[] = {
		&ett_cgmp,
	};

        proto_cgmp = proto_register_protocol("Cisco Group Management Protocol",
	    "CGMP", "cgmp");
        proto_register_field_array(proto_cgmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cgmp(void)
{
	dissector_handle_t cgmp_handle;

	cgmp_handle = create_dissector_handle(dissect_cgmp, proto_cgmp);
	dissector_add_uint("llc.cisco_pid", 0x2001, cgmp_handle);
	dissector_add_uint("ethertype", 0x2001, cgmp_handle);
}
