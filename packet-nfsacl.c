/* packet-nfsacl.c
 * Stubs for Sun's NFS ACL RPC service (runs on port 2049, and is presumably
 * handled by the same kernel server code that handles NFS)
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-nfsacl.c,v 1.1 2002/05/15 07:21:41 guy Exp $
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


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif


#include "packet-rpc.h"

static int proto_nfsacl = -1;

static gint ett_nfsacl = -1;

#define NFSACL_PROGRAM	100227

#define NFSACLPROC_NULL		0

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff nfsacl1_proc[] = {
	{ NFSACLPROC_NULL,	"NULL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};

static const vsff nfsacl2_proc[] = {
	{ NFSACLPROC_NULL,	"NULL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};

static const vsff nfsacl3_proc[] = {
	{ NFSACLPROC_NULL,	"NULL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};

void
proto_register_nfsacl(void)
{
#if 0
	static hf_register_info hf[] = {
	};
#endif

	static gint *ett[] = {
		&ett_nfsacl,
	};

	proto_nfsacl = proto_register_protocol("NFSACL", "NFSACL", "nfsacl");
#if 0
	proto_register_field_array(proto_nfsacl, hf, array_length(hf));
#endif
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nfsacl(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfsacl, NFSACL_PROGRAM, ett_nfsacl);
	/* Register the procedure tables */
	rpc_init_proc_table(NFSACL_PROGRAM, 1, nfsacl1_proc);
	rpc_init_proc_table(NFSACL_PROGRAM, 2, nfsacl2_proc);
	rpc_init_proc_table(NFSACL_PROGRAM, 3, nfsacl3_proc);
}
