/* packet-nfsauth.c
 * Stubs for Sun's NFS AUTH RPC service
 *
 * Ronnie Sahlberg
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

static int proto_nfsauth = -1;
static int hf_nfsauth_procedure_v1 = -1;

static gint ett_nfsauth = -1;

#define NFSAUTH_PROGRAM	100231

#define NFSAUTHPROC_NULL		0
#define NFSAUTH1_ACCESS			1
/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff nfsauth1_proc[] = {
	{ NFSAUTHPROC_NULL,	"NULL",
		NULL,	NULL },
	{ NFSAUTH1_ACCESS,	"ACCESS",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string nfsauth1_proc_vals[] = {
	{ NFSAUTHPROC_NULL,	"NULL" },
	{ NFSAUTH1_ACCESS,	"ACCESS" },
	{ 0,	NULL }
};


void
proto_register_nfsauth(void)
{
	static hf_register_info hf[] = {
		{ &hf_nfsauth_procedure_v1, {
			"V1 Procedure", "nfsauth.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(nfsauth1_proc_vals), 0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_nfsauth,
	};

	proto_nfsauth = proto_register_protocol("NFSAUTH", "NFSAUTH", "nfsauth");
	proto_register_field_array(proto_nfsauth, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nfsauth(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfsauth, NFSAUTH_PROGRAM, ett_nfsauth);
	/* Register the procedure tables */
	rpc_init_proc_table(NFSAUTH_PROGRAM, 1, nfsauth1_proc, hf_nfsauth_procedure_v1);
}
