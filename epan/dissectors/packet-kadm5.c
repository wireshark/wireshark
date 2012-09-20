/* packet-kadm5.c
 * Routines for kadm5 dissection
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

/*
 * The kadm5 RPC protocol is used to administer Kerberos principals
 * and policies.  It is not officially documented anywhere.  The
 * information for this dissector came from the MIT kadmin source.
 */

#include "config.h"

#include "packet-rpc.h"

#define KADM5_PROGRAM			2112
#define KADM5PROC_NULL			0
#define KADM5PROC_CREATE_PRINCIPAL	1
#define KADM5PROC_DELETE_PRINCIPAL	2
#define KADM5PROC_MODIFY_PRINCIPAL	3
#define KADM5PROC_RENAME_PRINCIPAL	4
#define KADM5PROC_GET_PRINCIPAL		5
#define KADM5PROC_CHPASS_PRINCIPAL	6
#define KADM5PROC_CHRAND_PRINCIPAL	7
#define KADM5PROC_CREATE_POLICY		8
#define KADM5PROC_DELETE_POLICY		9
#define KADM5PROC_MODIFY_POLICY		10
#define KADM5PROC_GET_POLICY		11
#define KADM5PROC_GET_PRIVS		12
#define KADM5PROC_INIT			13
#define KADM5PROC_GET_PRINCS		14
#define KADM5PROC_GET_POLS		15
#define KADM5PROC_SETKEY_PRINCIPAL	16
#define KADM5PROC_SETV4KEY_PRINCIPAL	17
#define KADM5PROC_CREATE_PRINCIPAL3	18
#define KADM5PROC_CHPASS_PRINCIPAL3	19
#define KADM5PROC_CHRAND_PRINCIPAL3	20
#define KADM5PROC_SETKEY_PRINCIPAL3	21

static int proto_kadm5 = -1;
static int hf_kadm5_procedure_v2 = -1;
static gint ett_kadm5 = -1;

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff kadm5_v2_proc[] = {
	{ KADM5PROC_NULL,	 	"NULL",			NULL,	NULL },
	{ KADM5PROC_CREATE_PRINCIPAL,	"CREATE_PRINCIPAL",	NULL,	NULL },
	{ KADM5PROC_DELETE_PRINCIPAL,	"DELETE_PRINCIPAL",	NULL,	NULL },
	{ KADM5PROC_MODIFY_PRINCIPAL,	"MODIFY_PRINCIPAL",	NULL,	NULL },
	{ KADM5PROC_RENAME_PRINCIPAL,	"RENAME_PRINCIPAL",	NULL,	NULL },
	{ KADM5PROC_GET_PRINCIPAL,	"GET_PRINCIPAL",	NULL,	NULL },
	{ KADM5PROC_CHPASS_PRINCIPAL,	"CHPASS_PRINCIPAL",	NULL,	NULL },
	{ KADM5PROC_CHRAND_PRINCIPAL,	"CHRAND_PRINCIPAL",	NULL,	NULL },
	{ KADM5PROC_CREATE_POLICY,	"CREATE_POLICY",	NULL,	NULL },
	{ KADM5PROC_DELETE_POLICY,	"DELETE_POLICY",	NULL,	NULL },
	{ KADM5PROC_MODIFY_POLICY,	"MODIFY_POLICY",	NULL,	NULL },
	{ KADM5PROC_GET_POLICY,		"GET_POLICY",		NULL,	NULL },
	{ KADM5PROC_GET_PRIVS,		"GET_PRIVS",		NULL,	NULL },
	{ KADM5PROC_INIT,		"INIT",			NULL,	NULL },
	{ KADM5PROC_GET_PRINCS,		"GET_PRINCS",		NULL,	NULL },
	{ KADM5PROC_GET_POLS,		"GET_POLS",		NULL,	NULL },
	{ KADM5PROC_SETKEY_PRINCIPAL,	"SETKEY_PRINCIPAL",	NULL,	NULL },
	{ KADM5PROC_SETV4KEY_PRINCIPAL,	"SETV4KEY_PRINCIPAL",	NULL,	NULL },
	{ KADM5PROC_CREATE_PRINCIPAL3,	"CREATE_PRINCIPAL3",	NULL,	NULL },
	{ KADM5PROC_CHPASS_PRINCIPAL3,	"CHPASS_PRINCIPAL3",	NULL,	NULL },
	{ KADM5PROC_CHRAND_PRINCIPAL3,	"CHRAND_PRINCIPAL3",	NULL,	NULL },
	{ KADM5PROC_SETKEY_PRINCIPAL3,	"SETKEY_PRINCIPAL3",	NULL,	NULL },
	{ 0,				 NULL,			NULL,	NULL }
};

static const value_string kadm5_v2_proc_vals[] = {
	{ KADM5PROC_NULL,	 	"NULL" },
	{ KADM5PROC_CREATE_PRINCIPAL,	"CREATE_PRINCIPAL" },
	{ KADM5PROC_DELETE_PRINCIPAL,	"DELETE_PRINCIPAL" },
	{ KADM5PROC_MODIFY_PRINCIPAL,	"MODIFY_PRINCIPAL" },
	{ KADM5PROC_RENAME_PRINCIPAL,	"RENAME_PRINCIPAL" },
	{ KADM5PROC_GET_PRINCIPAL,	"GET_PRINCIPAL" },
	{ KADM5PROC_CHPASS_PRINCIPAL,	"CHPASS_PRINCIPAL" },
	{ KADM5PROC_CHRAND_PRINCIPAL,	"CHRAND_PRINCIPAL" },
	{ KADM5PROC_CREATE_POLICY,	"CREATE_POLICY" },
	{ KADM5PROC_DELETE_POLICY,	"DELETE_POLICY" },
	{ KADM5PROC_MODIFY_POLICY,	"MODIFY_POLICY" },
	{ KADM5PROC_GET_POLICY,		"GET_POLICY" },
	{ KADM5PROC_GET_PRIVS,		"GET_PRIVS" },
	{ KADM5PROC_INIT,		"INIT" },
	{ KADM5PROC_GET_PRINCS,		"GET_PRINCS" },
	{ KADM5PROC_GET_POLS,		"GET_POLS" },
	{ KADM5PROC_SETKEY_PRINCIPAL,	"SETKEY_PRINCIPAL" },
	{ KADM5PROC_SETV4KEY_PRINCIPAL,	"SETV4KEY_PRINCIPAL" },
	{ KADM5PROC_CREATE_PRINCIPAL3,	"CREATE_PRINCIPAL3" },
	{ KADM5PROC_CHPASS_PRINCIPAL3,	"CHPASS_PRINCIPAL3" },
	{ KADM5PROC_CHRAND_PRINCIPAL3,	"CHRAND_PRINCIPAL3" },
	{ KADM5PROC_SETKEY_PRINCIPAL3,	"SETKEY_PRINCIPAL3" },
	{ 0,				 NULL }
};

void
proto_register_kadm5(void)
{
	static hf_register_info hf[] = {
		{ &hf_kadm5_procedure_v2, {
		    "V2 Procedure", "kadm5.procedure_v2", FT_UINT32, BASE_DEC,
		    VALS(kadm5_v2_proc_vals), 0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_kadm5,
	};

	proto_kadm5 = proto_register_protocol("Kerberos Administration",
	    "KADM5", "kadm5");
	proto_register_field_array(proto_kadm5, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_kadm5(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_kadm5, KADM5_PROGRAM, ett_kadm5);
	/* Register the procedure tables */
	rpc_init_proc_table(KADM5_PROGRAM, 2, kadm5_v2_proc,
	    hf_kadm5_procedure_v2);
}
