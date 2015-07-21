/* packet-clearcase.c
 * Routines for ClearCase NFS dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-ypxfr.c
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

#include <epan/packet.h>

#include "packet-rpc.h"
#include "packet-clearcase.h"

void proto_register_clearcase(void);
void proto_reg_handoff_clearcase(void);

static int proto_clearcase = -1;
static int hf_clearcase_procedure_v3 = -1;

static gint ett_clearcase = -1;

/* proc number, "proc name", dissect_request, dissect_reply */
static const vsff clearcase3_proc[] = {
	{ CLEARCASEPROC_NULL,	"NULL",	dissect_rpc_void,	dissect_rpc_void },
	{ 0,			NULL,	NULL,			NULL }
};
static const value_string clearcase3_proc_vals[] = {
	{ CLEARCASEPROC_NULL,	"NULL" },
	{ 0,			NULL }
};
/* end of Clearcase version 3 */

static const rpc_prog_vers_info clearcase_vers_info[] = {
	{ 3, clearcase3_proc, &hf_clearcase_procedure_v3 }
};

void
proto_register_clearcase(void)
{
	static hf_register_info hf[] = {
		{ &hf_clearcase_procedure_v3, {
			"V3 Procedure", "clearcase.procedure_v3", FT_UINT32, BASE_DEC,
			VALS(clearcase3_proc_vals), 0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_clearcase
	};

	proto_clearcase = proto_register_protocol("Clearcase NFS",
	    "CLEARCASE", "clearcase");
	proto_register_field_array(proto_clearcase, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_clearcase(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_clearcase, CLEARCASE_PROGRAM, ett_clearcase,
	    G_N_ELEMENTS(clearcase_vers_info), clearcase_vers_info);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
