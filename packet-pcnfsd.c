/* packet-pcnfsd.c
 * Routines for PCNFSD dissection
 *
 * $Id: packet-pcnfsd.c,v 1.1 2001/11/06 13:42:04 girlich Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-ypbind.c
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
#include "packet-pcnfsd.h"

static int proto_pcnfsd = -1;

static gint ett_pcnfsd = -1;

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff pcnfsd1_proc[] = {
	{ 0,	"NULL",		NULL,				NULL },
	{ 1,	"AUTH",		NULL,				NULL },
	{ 2,	"PR_INIT",	NULL,				NULL },
	{ 3,	"PR_START",	NULL,				NULL },
	{ 0,	NULL,		NULL,				NULL }
};
/* end of PCNFS version 1 */

static const vsff pcnfsd2_proc[] = {
	{ 0,	"NULL",		NULL,				NULL },
	{ 1,	"INFO",		NULL,				NULL },
	{ 2,	"PR_INIT",	NULL,				NULL },
	{ 3,	"PR_START",	NULL,				NULL },
	{ 4,	"PR_LIST",	NULL,				NULL },
	{ 5,	"PR_QUEUE",	NULL,				NULL },
	{ 6,	"PR_STATUS",	NULL,				NULL },
	{ 7,	"PR_CANCEL",	NULL,				NULL },
	{ 8,	"PR_ADMIN",	NULL,				NULL },
	{ 9,	"PR_REQUEUE",	NULL,				NULL },
	{ 10,	"PR_HOLD",	NULL,				NULL },
	{ 11,	"PR_RELEASE",	NULL,				NULL },
	{ 12,	"MAPID",	NULL,				NULL },
	{ 13,	"AUTH",		NULL,				NULL },
	{ 14,	"ALERT",	NULL,				NULL },
	{ 0,	NULL,		NULL,				NULL }
};
/* end of PCNFS version 2 */


void
proto_register_pcnfsd(void)
{
	static gint *ett[] = {
		&ett_pcnfsd,
	};

	proto_pcnfsd = proto_register_protocol("PC NFS",
	    "PCNFSD", "pcnfsd");
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pcnfsd(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_pcnfsd, PCNFSD_PROGRAM, ett_pcnfsd);
	/* Register the procedure tables */
	rpc_init_proc_table(PCNFSD_PROGRAM, 1, pcnfsd1_proc);
	rpc_init_proc_table(PCNFSD_PROGRAM, 2, pcnfsd2_proc);
}

