/* packet-nlm.c
 * Routines for nlm dissection
 *
 * $Id: packet-nlm.c,v 1.6 2000/08/02 11:36:18 girlich Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
/* NLM protocol version 1 */
const vsff nlm1_proc[] = {
	{ NLM_NULL,		"NULL",		NULL,	NULL },
	{ NLM_TEST,		"TEST",		NULL,	NULL },
	{ NLM_LOCK,		"LOCK",		NULL,	NULL },
	{ NLM_CANCEL,		"CANCEL",	NULL,	NULL },
	{ NLM_UNLOCK,		"UNLOCK",	NULL,	NULL },
	{ NLM_GRANTED,		"GRANTED",	NULL,	NULL },
	{ NLM_TEST_MSG,		"TEST_MSG",	NULL,	NULL },
	{ NLM_LOCK_MSG,		"LOCK_MSG",	NULL,	NULL },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",	NULL,	NULL },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",	NULL,	NULL },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",	NULL,	NULL },
	{ NLM_TEST_RES,		"TEST_RES",	NULL,	NULL },
	{ NLM_LOCK_RES,		"LOCK_RES",	NULL,	NULL },
	{ NLM_CANCEL_RES,	"CANCEL_RES",	NULL,	NULL },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",	NULL,	NULL },
	{ NLM_GRANTED_RES,	"GRANTED_RES",	NULL,	NULL },
	{ 0,			NULL,		NULL,	NULL }
};
/* end of NLM protocol version 1 */

/* NLM protocol version 2 */
const vsff nlm2_proc[] = {
	{ NLM_NULL,		"NULL",		NULL,	NULL },
	{ NLM_TEST,		"TEST",		NULL,	NULL },
	{ NLM_LOCK,		"LOCK",		NULL,	NULL },
	{ NLM_CANCEL,		"CANCEL",	NULL,	NULL },
	{ NLM_UNLOCK,		"UNLOCK",	NULL,	NULL },
	{ NLM_GRANTED,		"GRANTED",	NULL,	NULL },
	{ NLM_TEST_MSG,		"TEST_MSG",	NULL,	NULL },
	{ NLM_LOCK_MSG,		"LOCK_MSG",	NULL,	NULL },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",	NULL,	NULL },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",	NULL,	NULL },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",	NULL,	NULL },
	{ NLM_TEST_RES,		"TEST_RES",	NULL,	NULL },
	{ NLM_LOCK_RES,		"LOCK_RES",	NULL,	NULL },
	{ NLM_CANCEL_RES,	"CANCEL_RES",	NULL,	NULL },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",	NULL,	NULL },
	{ NLM_GRANTED_RES,	"GRANTED_RES",	NULL,	NULL },
	{ 0,			NULL,		NULL,	NULL }
};
/* end of NLM protocol version 2 */

/* NLM protocol version 3 */
const vsff nlm3_proc[] = {
	{ NLM_NULL,		"NULL",		NULL,	NULL },
	{ NLM_TEST,		"TEST",		NULL,	NULL },
	{ NLM_LOCK,		"LOCK",		NULL,	NULL },
	{ NLM_CANCEL,		"CANCEL",	NULL,	NULL },
	{ NLM_UNLOCK,		"UNLOCK",	NULL,	NULL },
	{ NLM_GRANTED,		"GRANTED",	NULL,	NULL },
	{ NLM_TEST_MSG,		"TEST_MSG",	NULL,	NULL },
	{ NLM_LOCK_MSG,		"LOCK_MSG",	NULL,	NULL },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",	NULL,	NULL },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",	NULL,	NULL },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",	NULL,	NULL },
	{ NLM_TEST_RES,		"TEST_RES",	NULL,	NULL },
	{ NLM_LOCK_RES,		"LOCK_RES",	NULL,	NULL },
	{ NLM_CANCEL_RES,	"CANCEL_RES",	NULL,	NULL },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",	NULL,	NULL },
	{ NLM_GRANTED_RES,	"GRANTED_RES",	NULL,	NULL },
	{ NLM_SHARE,		"SHARE",	NULL,	NULL },
	{ NLM_UNSHARE,		"UNSHARE",	NULL,	NULL },
	{ NLM_NM_LOCK,		"NM_LOCK",	NULL,	NULL },
	{ NLM_FREE_ALL,		"FREE_ALL",	NULL,	NULL },
	{ 0,			NULL,		NULL,	NULL }
};
/* end of NLM protocol version 3 */

/* NLM protocol version 4 */
const vsff nlm4_proc[] = {
	{ NLM_NULL,		"NULL",		NULL,	NULL },
	{ NLM_TEST,		"TEST",		NULL,	NULL },
	{ NLM_LOCK,		"LOCK",		NULL,	NULL },
	{ NLM_CANCEL,		"CANCEL",	NULL,	NULL },
	{ NLM_UNLOCK,		"UNLOCK",	NULL,	NULL },
	{ NLM_GRANTED,		"GRANTED",	NULL,	NULL },
	{ NLM_TEST_MSG,		"TEST_MSG",	NULL,	NULL },
	{ NLM_LOCK_MSG,		"LOCK_MSG",	NULL,	NULL },
	{ NLM_CANCEL_MSG,	"CANCEL_MSG",	NULL,	NULL },
	{ NLM_UNLOCK_MSG,	"UNLOCK_MSG",	NULL,	NULL },
	{ NLM_GRANTED_MSG,	"GRANTED_MSG",	NULL,	NULL },
	{ NLM_TEST_RES,		"TEST_RES",	NULL,	NULL },
	{ NLM_LOCK_RES,		"LOCK_RES",	NULL,	NULL },
	{ NLM_CANCEL_RES,	"CANCEL_RES",	NULL,	NULL },
	{ NLM_UNLOCK_RES,	"UNLOCK_RES",	NULL,	NULL },
	{ NLM_GRANTED_RES,	"GRANTED_RES",	NULL,	NULL },
	{ NLM_SHARE,		"SHARE",	NULL,	NULL },
	{ NLM_UNSHARE,		"UNSHARE",	NULL,	NULL },
	{ NLM_NM_LOCK,		"NM_LOCK",	NULL,	NULL },
	{ NLM_FREE_ALL,		"FREE_ALL",	NULL,	NULL },
	{ 0,			NULL,		NULL,	NULL }
};
/* end of NLM protocol version 4 */

void
proto_register_nlm(void)
{
	static gint *ett[] = {
		&ett_nlm,
	};

	proto_nlm = proto_register_protocol("Network Lock Manager Protocol", "nlm");
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nlm(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nlm, NLM_PROGRAM, ett_nlm);
	/* Register the procedure tables */
	rpc_init_proc_table(NLM_PROGRAM, 1, nlm1_proc);
	rpc_init_proc_table(NLM_PROGRAM, 2, nlm2_proc);
	rpc_init_proc_table(NLM_PROGRAM, 3, nlm3_proc);
	rpc_init_proc_table(NLM_PROGRAM, 4, nlm4_proc);
}
