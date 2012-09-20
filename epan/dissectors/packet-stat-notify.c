/* packet-stat.c
 * Routines for async NSM stat callback dissection
 * 2001 Ronnie Sahlberg <See AUTHORS for email>
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
#include "packet-stat-notify.h"

static int proto_statnotify = -1;
static int hf_statnotify_procedure_v1 = -1;
static int hf_statnotify_name = -1;
static int hf_statnotify_state = -1;
static int hf_statnotify_priv = -1;

static gint ett_statnotify = -1;


static int
dissect_statnotify_mon(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{

	offset = dissect_rpc_string(tvb,tree,hf_statnotify_name,offset,NULL);

	offset = dissect_rpc_uint32(tvb,tree,hf_statnotify_state,offset);

	proto_tree_add_item(tree,hf_statnotify_priv,tvb,offset,16,ENC_NA);
	offset += 16;

	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */

static const vsff statnotify1_proc[] = {
    { 0, "NULL", NULL, NULL },
    { STATNOTIFYPROC_MON,   "MON-CALLBACK",
		dissect_statnotify_mon, NULL },
    { 0, NULL, NULL, NULL }
};
static const value_string statnotify1_proc_vals[] = {
    { 0, "NULL" },
    { STATNOTIFYPROC_MON,   "MON-CALLBACK" },
    { 0, NULL }
};
/* end of stat-notify version 1 */


void
proto_register_statnotify(void)
{
	static hf_register_info hf[] = {
		{ &hf_statnotify_procedure_v1, {
			"V1 Procedure", "statnotify.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(statnotify1_proc_vals), 0, NULL, HFILL }},
		{ &hf_statnotify_name, {
			"Name", "statnotify.name", FT_STRING, BASE_NONE,
			NULL, 0, "Name of client that changed", HFILL }},
		{ &hf_statnotify_state, {
			"State", "statnotify.state", FT_UINT32, BASE_DEC,
			NULL, 0, "New state of client that changed", HFILL }},
		{ &hf_statnotify_priv, {
			"Priv", "statnotify.priv", FT_BYTES, BASE_NONE,
			NULL, 0, "Client supplied opaque data", HFILL }},
	};

	static gint *ett[] = {
		&ett_statnotify,
	};

	proto_statnotify = proto_register_protocol("Network Status Monitor CallBack Protocol", "STAT-CB", "statnotify");
	proto_register_field_array(proto_statnotify, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_statnotify(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_statnotify, STATNOTIFY_PROGRAM, ett_statnotify);
	/* Register the procedure tables */
	rpc_init_proc_table(STATNOTIFY_PROGRAM, 1, statnotify1_proc, hf_statnotify_procedure_v1);
}
