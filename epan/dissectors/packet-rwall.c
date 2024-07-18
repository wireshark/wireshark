/* packet-rwall.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include "packet-rpc.h"

void proto_register_rwall(void);
void proto_reg_handoff_rwall(void);

/* there is no procedure 1 */
#define RWALL_WALL 2

#define RWALL_PROGRAM 100008

static const value_string rwall1_proc_vals[] = {
	{ RWALL_WALL,	"RWALL" },
	{ 0,	NULL }
};

static int proto_rwall;

static int hf_rwall_message;
static int hf_rwall_procedure_v1;

static int ett_rwall;

static int
dissect_rwall_call(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	return dissect_rpc_string(tvb, tree, hf_rwall_message, 0, NULL);
}

static const vsff rwall1_proc[] = {
	{ RWALL_WALL,	"RWALL", dissect_rwall_call,	dissect_rpc_void },
	{ 0,	NULL,	NULL,	NULL }
};

static const rpc_prog_vers_info rwall_vers_info[] = {
	{ 1, rwall1_proc, &hf_rwall_procedure_v1 },
};

void
proto_register_rwall(void)
{
	static hf_register_info hf[] = {
		{ &hf_rwall_procedure_v1,
			{ "V1 Procedure", "rwall.procedure_v1",
			  FT_UINT32, BASE_DEC, VALS(rwall1_proc_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_rwall_message,
			{ "Message", "rwall.message",
			  FT_STRING, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_rwall,
	};

	proto_rwall = proto_register_protocol("Remote Wall protocol", "RWALL", "rwall");
	proto_register_field_array(proto_rwall, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rwall(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_rwall, RWALL_PROGRAM, ett_rwall,
	    G_N_ELEMENTS(rwall_vers_info), rwall_vers_info);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
