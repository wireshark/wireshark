/* packet-sadmind.c
 * Stubs for the Solstice admin daemon RPC service
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-sadmind.c,v 1.1 2002/05/15 07:21:41 guy Exp $
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

static int proto_sadmind = -1;

static gint ett_sadmind = -1;

#define SADMIND_PROGRAM	100232

#define SADMINDPROC_NULL		0

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff sadmind1_proc[] = {
	{ SADMINDPROC_NULL,	"NULL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};

static const vsff sadmind2_proc[] = {
	{ SADMINDPROC_NULL,	"NULL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};

static const vsff sadmind3_proc[] = {
	{ SADMINDPROC_NULL,	"NULL",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};

void
proto_register_sadmind(void)
{
#if 0
	static hf_register_info hf[] = {
	};
#endif

	static gint *ett[] = {
		&ett_sadmind,
	};

	proto_sadmind = proto_register_protocol("SADMIND", "SADMIND", "sadmind");
#if 0
	proto_register_field_array(proto_sadmind, hf, array_length(hf));
#endif
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_sadmind(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_sadmind, SADMIND_PROGRAM, ett_sadmind);
	/* Register the procedure tables */
	rpc_init_proc_table(SADMIND_PROGRAM, 1, sadmind1_proc);
	rpc_init_proc_table(SADMIND_PROGRAM, 2, sadmind2_proc);
	rpc_init_proc_table(SADMIND_PROGRAM, 3, sadmind3_proc);
}
