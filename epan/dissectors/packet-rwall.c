/* packet-rwall.c
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



#include "packet-rpc.h"
#include "packet-rwall.h"

static int proto_rwall = -1;
static int hf_rwall_procedure_v1 = -1;
static int hf_rwall_message = -1;

static gint ett_rwall = -1;

static int
dissect_rwall_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree, hf_rwall_message, offset, NULL);

	return offset;
}

static const vsff rwall1_proc[] = {
	{ RWALL_WALL,	"RWALL",
		dissect_rwall_call,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string rwall1_proc_vals[] = {
	{ RWALL_WALL,	"RWALL" },
	{ 0,	NULL }
};


void
proto_register_rwall(void)
{
	static hf_register_info hf[] = {
		{ &hf_rwall_procedure_v1, {
			"V1 Procedure", "rwall.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(rwall1_proc_vals), 0, NULL, HFILL }},
		{ &hf_rwall_message, {
			"Message", "rwall.message", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_rwall,
	};

	proto_rwall = proto_register_protocol("Remote Wall protocol",
	    "RWALL", "rwall");
	proto_register_field_array(proto_rwall, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rwall(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_rwall, RWALL_PROGRAM, ett_rwall);
	/* Register the procedure tables */
	rpc_init_proc_table(RWALL_PROGRAM, 1, rwall1_proc, hf_rwall_procedure_v1);
}


