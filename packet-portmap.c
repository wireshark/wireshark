/* packet-portmap.c
 * Routines for portmap dissection
 *
 * $Id: packet-portmap.c,v 1.6 1999/11/15 14:17:19 nneul Exp $
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
static int hf_portmap_proto = -1;
static int hf_portmap_prog = -1;
static int hf_portmap_proc = -1;
static int hf_portmap_version = -1;
static int hf_portmap_port = -1;
static int hf_portmap_answer = -1;

/* Dissect a getport call */
int dissect_getport_call(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	guint32 proto;
	guint32 prog;
	if ( !BYTES_ARE_IN_FRAME(offset, 16)) return offset;

	if ( tree )
	{
		prog = pntohl(&pd[offset+0]);
		proto_tree_add_item_format(tree, hf_portmap_prog,
			offset, 4, prog, "Program: %s (%d)",
			rpc_prog_name(prog), prog);
		proto_tree_add_item(tree, hf_portmap_version,
			offset+4, 4, pntohl(&pd[offset+4]));

		proto = pntohl(&pd[offset+8]);
		proto_tree_add_item_format(tree, hf_portmap_proto,
			offset+8, 4, proto, "Proto: %s (%d)", ipprotostr(proto), proto);

		proto_tree_add_item(tree, hf_portmap_port,
			offset+12, 4, pntohl(&pd[offset+12]));
	}
	
	return offset+16;
}

int dissect_getport_reply(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	if ( !BYTES_ARE_IN_FRAME(offset, 4)) return offset;
	if ( tree )
	{
		proto_tree_add_item(tree, hf_portmap_port,
			offset, 4, pntohl(&pd[offset+0]));
	}
    return offset+=4;
}

/* Dissect a 'set' call */
int dissect_set_call(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	guint32 proto;
	guint32 prog;
	if ( !BYTES_ARE_IN_FRAME(offset, 16)) return offset;

	if ( tree )
	{
		prog = pntohl(&pd[offset+0]);
		proto_tree_add_item_format(tree, hf_portmap_prog,
			offset, 4, prog, "Program: %s (%d)",
			rpc_prog_name(prog), prog);
		proto_tree_add_item(tree, hf_portmap_version,
			offset+4, 4, pntohl(&pd[offset+4]));

		proto = pntohl(&pd[offset+8]);
		proto_tree_add_item_format(tree, hf_portmap_proto,
			offset+8, 4, proto, "Proto: %s (%d)", ipprotostr(proto), proto);

		proto_tree_add_item(tree, hf_portmap_port,
			offset+12, 4, pntohl(&pd[offset+12]));
	}
	
	return offset+16;
}

/* Dissect a 'unset' call */
int dissect_unset_call(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	guint32 proto;
	guint32 prog;
	if ( !BYTES_ARE_IN_FRAME(offset, 16)) return offset;

	if ( tree )
	{
		prog = pntohl(&pd[offset+0]);
		proto_tree_add_item_format(tree, hf_portmap_prog,
			offset, 4, prog, "Program: %s (%d)",
			rpc_prog_name(prog), prog);
		proto_tree_add_item(tree, hf_portmap_version,
			offset+4, 4, pntohl(&pd[offset+4]));

		proto = pntohl(&pd[offset+8]);
		proto_tree_add_item(tree, hf_portmap_proto,
			offset+8, 4, proto);

		proto_tree_add_item(tree, hf_portmap_port,
			offset+12, 4, pntohl(&pd[offset+12]));
	}
	
	return offset+16;
}

int dissect_set_reply(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	if ( tree )
	{
		if ( !BYTES_ARE_IN_FRAME(offset, 4)) return offset;

		proto_tree_add_item(tree, hf_portmap_answer,
			offset, 4, pntohl(&pd[offset+0]));
		offset += 4;
	}
    return offset;
}

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
	{ PORTMAPPROC_NULL, "NULL",
		NULL, NULL },
	{ PORTMAPPROC_SET, "SET",
		dissect_set_call, dissect_set_reply },
	{ PORTMAPPROC_UNSET, "UNSET",
		dissect_unset_call, dissect_set_reply },
	{ PORTMAPPROC_GETPORT,	"GETPORT",
		dissect_getport_call, dissect_getport_reply },
	{ PORTMAPPROC_DUMP, "DUMP",
		NULL, NULL },
	{ PORTMAPPROC_CALLIT, "CALLIT",
		NULL, NULL },
    { 0, NULL, NULL, NULL }
};
/* end of Portmap version 2 */


/* Portmapper version 3, RFC 1833, Page 7 */
const vsff portmap3_proc[] = {
	{ RPCBPROC_NULL,	"NULL",
		NULL, NULL },
	{ RPCBPROC_SET,		"SET",
		NULL, NULL },
	{ RPCBPROC_UNSET,	"UNSET",
		NULL, NULL },
	{ RPCBPROC_GETADDR,	"GETADDR",
		NULL, NULL},
	{ RPCBPROC_DUMP,	"DUMP",
		NULL, NULL },
	{ RPCBPROC_CALLIT,	"CALLIT",
		NULL, NULL },
	{ RPCBPROC_GETTIME,	"GETTIME",
		NULL, NULL },
	{ RPCBPROC_UADDR2TADDR,	"UADDR2TADDR",
		NULL, NULL },
	{ RPCBPROC_TADDR2UADDR,	"TADDR2UADDR",
		NULL, NULL },
	{ 0, NULL, NULL, NULL }
};
/* end of Portmap version 3 */


/* Portmapper version 4, RFC 1833, Page 8 */
const vsff portmap4_proc[] = {
	{ RPCBPROC_NULL,	"NULL",
		NULL, NULL },
	{ RPCBPROC_SET,		"SET",
		NULL, NULL },
	{ RPCBPROC_UNSET,	"UNSET",
		NULL, NULL },
	{ RPCBPROC_GETADDR,	"GETADDR",
		NULL, NULL},
	{ RPCBPROC_DUMP,	"DUMP",
		NULL, NULL },
	{ RPCBPROC_BCAST,	"BCAST",
		NULL, NULL },
	{ RPCBPROC_GETTIME,	"GETTIME",
		NULL, NULL },
	{ RPCBPROC_UADDR2TADDR,	"UADDR2TADDR",
		NULL, NULL },
	{ RPCBPROC_TADDR2UADDR,	"TADDR2UADDR",
		NULL, NULL },
	{ RPCBPROC_GETVERSADDR,	"GETVERSADDR",
		NULL, NULL },
	{ RPCBPROC_INDIRECT,	"INDIRECT",
		NULL, NULL },
	{ RPCBPROC_GETADDRLIST,	"GETADDRLIST",
		NULL, NULL },
	{ RPCBPROC_GETSTAT,	"GETSTAT",
		NULL, NULL },
	{ 0, NULL, NULL, NULL }
};
/* end of Portmap version 4 */

void
proto_register_portmap(void)
{
	static hf_register_info hf[] = {
		{ &hf_portmap_prog, {
			"Program", "portmap.prog", FT_UINT32, BASE_DEC,
			NULL, 0, "Program" }},
		{ &hf_portmap_port, {
			"Port", "portmap.port", FT_UINT32, BASE_DEC,
			NULL, 0, "Port" }},
		{ &hf_portmap_proc, {
			"Procedure", "portmap.proc", FT_UINT32, BASE_DEC,
			NULL, 0, "Procedure" }},
		{ &hf_portmap_proto, {
			"Protocol", "portmap.proto", FT_UINT32, BASE_DEC,
			NULL, 0, "Protocol" }},
		{ &hf_portmap_version, {
			"Version", "portmap.version", FT_UINT32, BASE_DEC,
			NULL, 0, "Version" }},
		{ &hf_portmap_answer, {
			"Answer", "portmap.answer", FT_BOOLEAN, BASE_DEC,
			NULL, 0, "Answer" }},
	};

	proto_portmap = proto_register_protocol("Portmap", "portmap");
	proto_register_field_array(proto_portmap, hf, array_length(hf));

	/* Register the protocol as RPC */
	rpc_init_prog(proto_portmap, PORTMAP_PROGRAM, ETT_PORTMAP);
	/* Register the procedure tables */
	rpc_init_proc_table(PORTMAP_PROGRAM, 1, portmap1_proc);
	rpc_init_proc_table(PORTMAP_PROGRAM, 2, portmap2_proc);
	rpc_init_proc_table(PORTMAP_PROGRAM, 3, portmap3_proc);
	rpc_init_proc_table(PORTMAP_PROGRAM, 4, portmap4_proc);
}

