/* packet-ypbind.c
 * Routines for ypbind dissection
 *
 * $Id: packet-ypbind.c,v 1.4 2000/01/07 22:05:42 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-smb.c
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
#include "packet-ypbind.h"

static int proto_ypbind = -1;

static gint ett_ypbind = -1;

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */
const vsff ypbind1_proc[] = {
	{ YPBINDPROC_NULL,	"NULL",		NULL,				NULL },
	{ YPBINDPROC_DOMAIN,	"DOMAIN",		NULL,				NULL },
	{ YPBINDPROC_SETDOM,	"SETDOMAIN",		NULL,				NULL },
	{ 0,	NULL,		NULL,				NULL }
};
/* end of YPBind version 1 */

const vsff ypbind2_proc[] = {
	{ YPBINDPROC_NULL,	"NULL",		NULL,				NULL },
	{ YPBINDPROC_DOMAIN,	"DOMAIN",		NULL,				NULL },
	{ YPBINDPROC_SETDOM,	"SETDOMAIN",		NULL,				NULL },
    { 0,    NULL,       NULL,               NULL }
};
/* end of YPBind version 2 */


void
proto_register_ypbind(void)
{
	static gint *ett[] = {
		&ett_ypbind,
	};

	proto_ypbind = proto_register_protocol("Yellow Pages Bind", "ypbind");
	proto_register_subtree_array(ett, array_length(ett));

	/* Register the protocol as RPC */
	rpc_init_prog(proto_ypbind, YPBIND_PROGRAM, ett_ypbind);
	/* Register the procedure tables */
	rpc_init_proc_table(YPBIND_PROGRAM, 1, ypbind1_proc);
	rpc_init_proc_table(YPBIND_PROGRAM, 2, ypbind2_proc);
}
