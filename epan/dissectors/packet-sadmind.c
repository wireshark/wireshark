/* packet-sadmind.c
 * Stubs for the Solstice admin daemon RPC service
 *
 * Guy Harris <guy@alum.mit.edu>
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

static int proto_sadmind = -1;
static int hf_sadmind_procedure_v1 = -1;
static int hf_sadmind_procedure_v2 = -1;
static int hf_sadmind_procedure_v3 = -1;

static gint ett_sadmind = -1;

#define SADMIND_PROGRAM	100232

#define SADMINDPROC_NULL		0

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff sadmind1_proc[] = {
	{ SADMINDPROC_NULL,	"NULL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string sadmind1_proc_vals[] = {
	{ SADMINDPROC_NULL,	"NULL" },
	{ 0,	NULL }
};

static const vsff sadmind2_proc[] = {
	{ SADMINDPROC_NULL,	"NULL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string sadmind2_proc_vals[] = {
	{ SADMINDPROC_NULL,	"NULL" },
	{ 0,	NULL }
};

static const vsff sadmind3_proc[] = {
	{ SADMINDPROC_NULL,	"NULL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string sadmind3_proc_vals[] = {
	{ SADMINDPROC_NULL,	"NULL" },
	{ 0,	NULL }
};

void
proto_register_sadmind(void)
{
	static hf_register_info hf[] = {
		{ &hf_sadmind_procedure_v1, {
			"V1 Procedure", "sadmind.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(sadmind1_proc_vals), 0, NULL, HFILL }},
		{ &hf_sadmind_procedure_v2, {
			"V2 Procedure", "sadmind.procedure_v2", FT_UINT32, BASE_DEC,
			VALS(sadmind2_proc_vals), 0, NULL, HFILL }},
		{ &hf_sadmind_procedure_v3, {
			"V3 Procedure", "sadmind.procedure_v3", FT_UINT32, BASE_DEC,
			VALS(sadmind3_proc_vals), 0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_sadmind,
	};

	proto_sadmind = proto_register_protocol("SADMIND", "SADMIND", "sadmind");
	proto_register_field_array(proto_sadmind, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_sadmind(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_sadmind, SADMIND_PROGRAM, ett_sadmind);
	/* Register the procedure tables */
	rpc_init_proc_table(SADMIND_PROGRAM, 1, sadmind1_proc, hf_sadmind_procedure_v1);
	rpc_init_proc_table(SADMIND_PROGRAM, 2, sadmind2_proc, hf_sadmind_procedure_v2);
	rpc_init_proc_table(SADMIND_PROGRAM, 3, sadmind3_proc, hf_sadmind_procedure_v3);
}
