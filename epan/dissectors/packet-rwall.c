/* packet-rwall.c
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

#define NEW_PROTO_TREE_API

#include "config.h"

#include "packet-rpc.h"
#include "packet-rwall.h"

void proto_register_rwall(void);
void proto_reg_handoff_rwall(void);

static header_field_info *hfi_rwall = NULL;

#define RWALL_HFI_INIT HFI_INIT(proto_rwall)

static const value_string rwall1_proc_vals[] = {
	{ RWALL_WALL,	"RWALL" },
	{ 0,	NULL }
};

static header_field_info hfi_rwall_procedure_v1 RWALL_HFI_INIT = {
	"V1 Procedure", "rwall.procedure_v1", FT_UINT32, BASE_DEC,
	VALS(rwall1_proc_vals), 0, NULL, HFILL };

static header_field_info hfi_rwall_message RWALL_HFI_INIT = {
	"Message", "rwall.message", FT_STRING, BASE_NONE,
	NULL, 0, NULL, HFILL };

static gint ett_rwall = -1;

static int
dissect_rwall_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = dissect_rpc_string(tvb, tree, hfi_rwall_message.id, offset, NULL);

	return offset;
}

static const vsff rwall1_proc[] = {
	{ RWALL_WALL,	"RWALL", dissect_rwall_call,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};

void
proto_register_rwall(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
		&hfi_rwall_procedure_v1,
		&hfi_rwall_message,
	};
#endif

	static gint *ett[] = {
		&ett_rwall,
	};

	int proto_rwall;

	proto_rwall = proto_register_protocol("Remote Wall protocol", "RWALL", "rwall");
	hfi_rwall = proto_registrar_get_nth(proto_rwall);

	proto_register_fields(proto_rwall, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rwall(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(hfi_rwall->id, RWALL_PROGRAM, ett_rwall);
	/* Register the procedure tables */
	rpc_init_proc_table(RWALL_PROGRAM, 1, rwall1_proc, hfi_rwall_procedure_v1.id);
}


