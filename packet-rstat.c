/* packet-rstat.c
 * Stubs for Sun's remote statistics RPC service
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-rstat.c,v 1.1 2002/05/15 07:21:41 guy Exp $
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

static int proto_rstat = -1;

static gint ett_rstat = -1;

#define RSTAT_PROGRAM	100001

#define RSTATPROC_NULL		0
#define RSTATPROC_STATS		1
#define RSTATPROC_HAVEDISK	2

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff rstat1_proc[] = {
	{ RSTATPROC_NULL,	"NULL",
		NULL,	NULL },
	{ RSTATPROC_STATS,	"STATS",
		NULL,	NULL },
	{ RSTATPROC_HAVEDISK,	"HAVEDISK",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};

static const vsff rstat2_proc[] = {
	{ RSTATPROC_NULL,	"NULL",
		NULL,	NULL },
	{ RSTATPROC_STATS,	"STATS",
		NULL,	NULL },
	{ RSTATPROC_HAVEDISK,	"HAVEDISK",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};

static const vsff rstat3_proc[] = {
	{ RSTATPROC_NULL,	"NULL",
		NULL,	NULL },
	{ RSTATPROC_STATS,	"STATS",
		NULL,	NULL },
	{ RSTATPROC_HAVEDISK,	"HAVEDISK",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};

static const vsff rstat4_proc[] = {
	{ RSTATPROC_NULL,	"NULL",
		NULL,	NULL },
	{ RSTATPROC_STATS,	"STATS",
		NULL,	NULL },
	{ RSTATPROC_HAVEDISK,	"HAVEDISK",
		NULL,	NULL },
	{ 0,	NULL,	NULL,	NULL }
};

void
proto_register_rstat(void)
{
#if 0
	static hf_register_info hf[] = {
	};
#endif

	static gint *ett[] = {
		&ett_rstat,
	};

	proto_rstat = proto_register_protocol("RSTAT", "RSTAT", "rstat");
#if 0
	proto_register_field_array(proto_rstat, hf, array_length(hf));
#endif
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rstat(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_rstat, RSTAT_PROGRAM, ett_rstat);
	/* Register the procedure tables */
	rpc_init_proc_table(RSTAT_PROGRAM, 1, rstat1_proc);
	rpc_init_proc_table(RSTAT_PROGRAM, 2, rstat2_proc);
	rpc_init_proc_table(RSTAT_PROGRAM, 3, rstat3_proc);
	rpc_init_proc_table(RSTAT_PROGRAM, 4, rstat3_proc);
}
