/* packet-nfsauth.c
 * Stubs for Sun's NFS AUTH RPC service
 *
 * Ronnie Sahlberg
 *
 * $Id: packet-nfsauth.c,v 1.3 2002/10/23 21:17:02 guy Exp $
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

static int proto_nfsauth = -1;

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

void
proto_register_nfsauth(void)
{
#if 0
	static hf_register_info hf[] = {
	};
#endif

	static gint *ett[] = {
		&ett_nfsauth,
	};

	proto_nfsauth = proto_register_protocol("NFSAUTH", "NFSAUTH", "nfsauth");
#if 0
	proto_register_field_array(proto_nfsauth, hf, array_length(hf));
#endif
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nfsauth(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfsauth, NFSAUTH_PROGRAM, ett_nfsauth);
	/* Register the procedure tables */
	rpc_init_proc_table(NFSAUTH_PROGRAM, 1, nfsauth1_proc, -1);
}
