/* packet-portmap.c
 * Routines for portmap dissection
 *
 * $Id: packet-portmap.c,v 1.1 1999/11/10 17:23:53 nneul Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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
#include "packet-portmap.h"

static int proto_portmap = -1;

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */
const vsff portmap1_proc[] = {
	{ PORTMAPPROC_NULL,	"NULL",		NULL,				NULL },
	{ PORTMAPPROC_SET,	"SET",		NULL,				NULL },
	{ PORTMAPPROC_UNSET,	"UNSET",		NULL,				NULL },
	{ PORTMAPPROC_GETPORT,	"GETPORT",		NULL,				NULL },
	{ PORTMAPPROC_DUMP,	"DUMP",		NULL,				NULL },
	{ PORTMAPPROC_CALLIT,	"CALLIT",		NULL,				NULL },
	{ 0,	NULL,		NULL,				NULL }
};
/* end of Portmap version 1 */

const vsff portmap2_proc[] = {
	{ PORTMAPPROC_NULL,	"NULL",		NULL,				NULL },
	{ PORTMAPPROC_SET,	"SET",		NULL,				NULL },
	{ PORTMAPPROC_UNSET,	"UNSET",		NULL,				NULL },
	{ PORTMAPPROC_GETPORT,	"GETPORT",		NULL,				NULL },
	{ PORTMAPPROC_DUMP,	"DUMP",		NULL,				NULL },
	{ PORTMAPPROC_CALLIT,	"CALLIT",		NULL,				NULL },
    { 0,    NULL,       NULL,               NULL }
};
/* end of Portmap version 2 */


void
proto_register_portmap(void)
{
	proto_portmap = proto_register_protocol("Portmap", "PORTMAP");

	/* Register the protocol as RPC */
	rpc_init_prog(proto_portmap, PORTMAP_PROGRAM, ETT_PORTMAP);
	/* Register the procedure tables */
	rpc_init_proc_table(PORTMAP_PROGRAM, 1, portmap1_proc);
	rpc_init_proc_table(PORTMAP_PROGRAM, 2, portmap2_proc);
}

