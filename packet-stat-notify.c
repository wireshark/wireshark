/* packet-stat.c
 * Routines for async NSM stat callback dissection
 * 2001 Ronnie Sahlberg <rsahlber@bigpond.net.au>
 *
 * $Id: packet-stat-notify.c,v 1.4 2001/06/12 06:31:14 guy Exp $
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
#include "packet-stat-notify.h"

static int proto_statnotify = -1;
static int hf_statnotify_name = -1;
static int hf_statnotify_state = -1;
static int hf_statnotify_priv = -1;

static gint ett_statnotify = -1;


static int
dissect_statnotify_mon(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{

	offset = dissect_rpc_string(tvb,pinfo,tree,hf_statnotify_name,offset,NULL);

	offset = dissect_rpc_uint32(tvb,pinfo,tree,hf_statnotify_state,offset);

	proto_tree_add_item(tree,hf_statnotify_priv,tvb,offset,16,FALSE);
	offset += 16;

	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */

static const vsff statnotify_proc[] = {
    { 0, "NULL", NULL, NULL },
    { STATNOTIFYPROC_MON,   "MON-CALLBACK",      
		dissect_statnotify_mon, NULL },
    { 0, NULL, NULL, NULL }
};
/* end of stat-notify version 1 */


void
proto_register_statnotify(void)
{
	static hf_register_info hf[] = {
		{ &hf_statnotify_name, {
			"Name", "statnotify.name", FT_STRING, BASE_DEC,
			NULL, 0, "Name of client that changed" }},
		{ &hf_statnotify_state, {
			"State", "statnotify.state", FT_UINT32, BASE_DEC,
			NULL, 0, "New state of client that changed" }},
		{ &hf_statnotify_priv, {
			"Priv", "statnotify.priv", FT_BYTES, BASE_HEX,
			NULL, 0, "Client supplied opaque data" }},
	};
	
	static gint *ett[] = {
		&ett_statnotify,
	};

	proto_statnotify = proto_register_protocol("Network Status Monitor CallBack Protocol", "STAT-CB", "stat-cb");
	proto_register_field_array(proto_statnotify, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_statnotify(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_statnotify, STATNOTIFY_PROGRAM, ett_statnotify);
	/* Register the procedure tables */
	rpc_init_proc_table(STATNOTIFY_PROGRAM, 1, statnotify_proc);
}
