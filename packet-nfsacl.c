/* packet-nfsacl.c
 * Stubs for Sun's NFS ACL RPC service (runs on port 2049, and is presumably
 * handled by the same kernel server code that handles NFS)
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-nfsacl.c,v 1.5 2002/11/01 00:48:38 sahlberg Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif



#include "packet-rpc.h"

static int proto_nfsacl = -1;
static int hf_nfsacl_procedure_v1 = -1;
static int hf_nfsacl_procedure_v2 = -1;
static int hf_nfsacl_procedure_v3 = -1;

static gint ett_nfsacl = -1;

#define NFSACL_PROGRAM	100227

#define NFSACLPROC_NULL		0

#define NFSACLPROC2_GETACL	1
#define NFSACLPROC2_SETACL	2
#define NFSACLPROC2_GETATTR	3
#define NFSACLPROC2_ACCESS	4

#define NFSACLPROC3_GETACL	1
#define NFSACLPROC3_SETACL	2

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff nfsacl1_proc[] = {
	{ NFSACLPROC_NULL,	"NULL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string nfsacl1_proc_vals[] = {
	{ NFSACLPROC_NULL,	"NULL" },
	{ 0,	NULL }
};


static const vsff nfsacl2_proc[] = {
	{ NFSACLPROC_NULL,	"NULL",
		NULL,	NULL },
	{ NFSACLPROC2_GETACL,	"GETACL",
		NULL,	NULL },
	{ NFSACLPROC2_SETACL,	"SETACL",
		NULL,	NULL },
	{ NFSACLPROC2_GETATTR,	"GETATTR",
		NULL,	NULL },
	{ NFSACLPROC2_ACCESS,	"ACCESS",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string nfsacl2_proc_vals[] = {
	{ NFSACLPROC_NULL,	"NULL" },
	{ NFSACLPROC2_GETACL,	"GETACL" },
	{ NFSACLPROC2_SETACL,	"SETACL" },
	{ NFSACLPROC2_GETATTR,	"GETATTR" },
	{ NFSACLPROC2_ACCESS,	"ACCESS" },
	{ 0,	NULL }
};


static const vsff nfsacl3_proc[] = {
	{ NFSACLPROC_NULL,	"NULL",
		NULL,	NULL },
	{ NFSACLPROC3_GETACL,	"GETACL",
		NULL,	NULL },
	{ NFSACLPROC3_SETACL,	"SETACL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string nfsacl3_proc_vals[] = {
	{ NFSACLPROC_NULL,	"NULL" },
	{ NFSACLPROC3_GETACL,	"GETACL" },
	{ NFSACLPROC3_SETACL,	"SETACL" },
	{ 0,	NULL }
};

void
proto_register_nfsacl(void)
{
	static hf_register_info hf[] = {
		{ &hf_nfsacl_procedure_v1, {
			"V1 Procedure", "nfsacl.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(nfsacl1_proc_vals), 0, "V1 Procedure", HFILL }},
		{ &hf_nfsacl_procedure_v2, {
			"V2 Procedure", "nfsacl.procedure_v2", FT_UINT32, BASE_DEC,
			VALS(nfsacl2_proc_vals), 0, "V2 Procedure", HFILL }},
		{ &hf_nfsacl_procedure_v3, {
			"V3 Procedure", "nfsacl.procedure_v3", FT_UINT32, BASE_DEC,
			VALS(nfsacl3_proc_vals), 0, "V3 Procedure", HFILL }}
	};

	static gint *ett[] = {
		&ett_nfsacl,
	};

	proto_nfsacl = proto_register_protocol("NFSACL", "NFSACL", "nfsacl");
	proto_register_field_array(proto_nfsacl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nfsacl(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfsacl, NFSACL_PROGRAM, ett_nfsacl);
	/* Register the procedure tables */
	rpc_init_proc_table(NFSACL_PROGRAM, 1, nfsacl1_proc, hf_nfsacl_procedure_v1);
	rpc_init_proc_table(NFSACL_PROGRAM, 2, nfsacl2_proc, hf_nfsacl_procedure_v2);
	rpc_init_proc_table(NFSACL_PROGRAM, 3, nfsacl3_proc, hf_nfsacl_procedure_v3);
}
