/* packet-stat.c
 * Routines for stat dissection
 *
 * $Id: packet-stat.c,v 1.2 1999/11/16 11:42:58 guy Exp $
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
#include "packet-stat.h"

static int proto_stat = -1;

static gint ett_stat = -1;

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */

const vsff stat_proc[] = {
    { 0, "NULL", NULL, NULL },
    { STATPROC_STAT,   "STAT",      
		NULL, NULL },
    { STATPROC_MON,   "MON",      
		NULL, NULL },
    { STATPROC_UNMON, "UNMON",        
		NULL, NULL },
    { STATPROC_UNMON_ALL, "UNMON_ALL",        
		NULL, NULL },
    { STATPROC_SIMU_CRASH, "SIMU_CRASH",        
		NULL, NULL },
    { STATPROC_NOTIFY, "NOTIFY",        
		NULL, NULL },
    { 0, NULL, NULL, NULL }
};
/* end of stat version 1 */


void
proto_register_stat(void)
{
	static hf_register_info hf[] = {
#if 0
		{ &hf_stat_path, {
			"Path", "stat.path", FT_STRING, BASE_DEC,
			NULL, 0, "Path" }},
#endif
	};
	static gint *ett[] = {
		&ett_stat,
	};

	proto_stat = proto_register_protocol("Status Service", "stat");
	proto_register_field_array(proto_stat, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register the protocol as RPC */
	rpc_init_prog(proto_stat, STAT_PROGRAM, ett_stat);
	/* Register the procedure tables */
	rpc_init_proc_table(STAT_PROGRAM, 1, stat_proc);
}
