/* packet-nlm.c
 * Routines for nlm dissection
 *
 * $Id: packet-nlm.c,v 1.3 1999/11/16 11:42:42 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-mount.c
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
#include "packet-nlm.h"


static int proto_nlm = -1;

static gint ett_nlm = -1;

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */
/* NLM protocol version 3 */
const vsff nlm3_proc[] = {
	{ 0,	"NULL",		NULL,	NULL },
	{ 1,	"TEST",		NULL,	NULL },
	{ 2,	"LOCK",		NULL,	NULL },
	{ 3,	"CANCEL",	NULL,	NULL },
	{ 4,	"UNLOCK",	NULL,	NULL },
	{ 5,	"GRANTED",	NULL,	NULL },
	{ 6,	"TEST_MSG",	NULL,	NULL },
	{ 7,	"LOCK_MSG",	NULL,	NULL },
	{ 8,	"CANCEL_MSG",	NULL,	NULL },
	{ 9,	"UNLOCK_MSG",	NULL,	NULL },
	{ 10,	"GRANTED_MSG",	NULL,	NULL },
	{ 11,	"TEST_RES",	NULL,	NULL },
	{ 12,	"LOCK_RES",	NULL,	NULL },
	{ 13,	"CANCEL_RES",	NULL,	NULL },
	{ 14,	"UNLOCK_RES",	NULL,	NULL },
	{ 15,	"GRANTED_RES",	NULL,	NULL },
	{ 20,	"SHARE",	NULL,	NULL },
	{ 21,	"UNSHARE",	NULL,	NULL },
	{ 22,	"NM_LOCK",	NULL,	NULL },
	{ 23,	"FREE_ALL",	NULL,	NULL },
	{ 0,	NULL,		NULL,	NULL }
};
/* end of NLM protocol version 3 */


void
proto_register_nlm(void)
{
	static gint *ett[] = {
		&ett_nlm,
	};

	proto_nlm = proto_register_protocol("Network Lock Manager Protocol", "nlm");
	proto_register_subtree_array(ett, array_length(ett));

	/* Register the protocol as RPC */
	rpc_init_prog(proto_nlm, NLM_PROGRAM, ett_nlm);
	/* Register the procedure table */
	rpc_init_proc_table(NLM_PROGRAM, 3, nlm3_proc);
}


