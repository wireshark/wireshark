/* packet-rquota.c
 * Routines for rquota dissection
 * Copyright 2001, Mike Frisch <frisch@hummingbird.com>
 *
 * $Id: packet-rquota.c,v 1.1 2001/02/27 19:40:58 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif


#include "packet-rpc.h"
#include "packet-rquota.h"

static int proto_rquota = -1;

static gint ett_rquota = -1;

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff rquota1_proc[] = {
	{ RQUOTAPROC_NULL,	"NULL",		NULL,		NULL },
	{ 0,			NULL,		NULL,		NULL }
};
/* end of RQUOTA version 1 */

void
proto_register_rquota(void)
{
	static gint *ett[] = {
		&ett_rquota
	};

	proto_rquota = proto_register_protocol("Remote Quota",
	    "RQUOTA", "rquota");
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rquota(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_rquota, RQUOTA_PROGRAM, ett_rquota);
	/* Register the procedure tables */
	rpc_init_proc_table(RQUOTA_PROGRAM, 1, rquota1_proc);
}
