/* packet-romon.c
 * Routines for Mikrotik RoMON dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2003 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>

void proto_register_romon(void);
void proto_reg_handoff_romon(void);

static dissector_handle_t romon_handle;

/* Initialize the protocol and registered fields */
static int proto_romon;

/* Initialize the subtree pointers */
static int ett_romon;

/* Code to actually dissect the packets */
static int
dissect_romon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RoMON");
	col_clear(pinfo->cinfo, COL_INFO);

	proto_tree_add_item(tree, proto_romon, tvb, 0, -1, ENC_NA);

	return tvb_captured_length(tvb);
}


void
proto_register_romon(void)
{
	static int *ett[] = {
		&ett_romon,
	};

	proto_romon = proto_register_protocol("Mikrotik RoMON", "RoMON", "romon");
	proto_register_subtree_array(ett, array_length(ett));

	romon_handle = register_dissector("romon", dissect_romon, proto_romon);
}


void
proto_reg_handoff_romon(void)
{
	dissector_add_uint("ethertype", 0x88bf, romon_handle);
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
