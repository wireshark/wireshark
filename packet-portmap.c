/* packet-portmap.c
 * Routines for portmap dissection
 *
 * $Id: packet-portmap.c,v 1.23 2001/01/22 07:19:38 guy Exp $
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
#include "packet-portmap.h"

/*
 * See:
 *
 *	RFC 1833, "Binding Protocols for ONC RPC Version 2".
 */

static int proto_portmap = -1;
static int hf_portmap_proto = -1;
static int hf_portmap_prog = -1;
static int hf_portmap_proc = -1;
static int hf_portmap_version = -1;
static int hf_portmap_port = -1;
static int hf_portmap_answer = -1;
static int hf_portmap_rpcb = -1;
static int hf_portmap_rpcb_prog = -1;
static int hf_portmap_rpcb_version = -1;
static int hf_portmap_rpcb_netid = -1;
static int hf_portmap_rpcb_addr = -1;
static int hf_portmap_rpcb_owner = -1;
static int hf_portmap_uaddr = -1;


static gint ett_portmap = -1;
static gint ett_portmap_rpcb = -1;
static gint ett_portmap_entry = -1;


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
		proto_tree_add_uint_format(tree, hf_portmap_prog, NullTVB,
			offset, 4, prog, "Program: %s (%u)",
			rpc_prog_name(prog), prog);
		proto_tree_add_uint(tree, hf_portmap_version, NullTVB,
			offset+4, 4, pntohl(&pd[offset+4]));

		proto = pntohl(&pd[offset+8]);
		proto_tree_add_uint_format(tree, hf_portmap_proto, NullTVB,
			offset+8, 4, proto, "Proto: %s (%u)", ipprotostr(proto), proto);

		proto_tree_add_uint(tree, hf_portmap_port, NullTVB,
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
		proto_tree_add_uint(tree, hf_portmap_port, NullTVB,
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
		proto_tree_add_uint_format(tree, hf_portmap_prog, NullTVB,
			offset, 4, prog, "Program: %s (%d)",
			rpc_prog_name(prog), prog);
		proto_tree_add_uint(tree, hf_portmap_version, NullTVB,
			offset+4, 4, pntohl(&pd[offset+4]));

		proto = pntohl(&pd[offset+8]);
		proto_tree_add_uint_format(tree, hf_portmap_proto, NullTVB,
			offset+8, 4, proto, "Proto: %s (%d)", ipprotostr(proto), proto);

		proto_tree_add_uint(tree, hf_portmap_port, NullTVB,
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
		proto_tree_add_uint_format(tree, hf_portmap_prog, NullTVB,
			offset, 4, prog, "Program: %s (%d)",
			rpc_prog_name(prog), prog);
		proto_tree_add_uint(tree, hf_portmap_version, NullTVB,
			offset+4, 4, pntohl(&pd[offset+4]));

		proto = pntohl(&pd[offset+8]);
		proto_tree_add_uint(tree, hf_portmap_proto, NullTVB,
			offset+8, 4, proto);

		proto_tree_add_uint(tree, hf_portmap_port, NullTVB,
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

		proto_tree_add_boolean(tree, hf_portmap_answer, NullTVB,
			offset, 4, pntohl(&pd[offset+0]));
		offset += 4;
	}
    return offset;
}

static int
dissect_dump_entry(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	int prog, version, proto, port;
	proto_item *ti, *subtree;

	if ( ! BYTES_ARE_IN_FRAME(offset, 16) )
	{
		if ( tree )
		{
			proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Map Entry: <TRUNCATED>");
		}
		return pi.captured_len;
	}
	prog = pntohl(&pd[offset+0]);
	version = pntohl(&pd[offset+4]);
	proto = pntohl(&pd[offset+8]);
	port = pntohl(&pd[offset+12]);
	if ( tree )
	{
		ti = proto_tree_add_text(tree, NullTVB, offset, 16, "Map Entry: %s (%u) V%d",
			rpc_prog_name(prog), prog, version);
		subtree = proto_item_add_subtree(ti, ett_portmap_entry);

		proto_tree_add_uint_format(subtree, hf_portmap_prog, NullTVB,
			offset+0, 4, prog,
			"Program: %s (%u)", rpc_prog_name(prog), prog);
		proto_tree_add_uint(subtree, hf_portmap_version, NullTVB,
			offset+4, 4, version);
		proto_tree_add_uint_format(subtree, hf_portmap_proto, NullTVB,
			offset+8, 4, proto, 
			"Protocol: %s (0x%02x)", ipprotostr(proto), proto);
		proto_tree_add_uint(subtree, hf_portmap_port, NullTVB,
			offset+12, 4, port);
	}
	offset += 16;
	return offset;
}

int dissect_dump_reply(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	offset = dissect_rpc_list(pd, offset, fd, tree, dissect_dump_entry);
	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff portmap1_proc[] = {
	{ PORTMAPPROC_NULL,	"NULL",		NULL,				NULL },
	{ PORTMAPPROC_SET,	"SET",		NULL,				NULL },
	{ PORTMAPPROC_UNSET,	"UNSET",		NULL,				NULL },
	{ PORTMAPPROC_GETPORT,	"GETPORT",		NULL,				NULL },
	{ PORTMAPPROC_DUMP,	"DUMP",		NULL,				NULL },
	{ PORTMAPPROC_CALLIT,	"CALLIT",		NULL,				NULL },
	{ 0,	NULL,		NULL,				NULL }
};
/* end of Portmap version 1 */

static const vsff portmap2_proc[] = {
	{ PORTMAPPROC_NULL, "NULL",
		NULL, NULL },
	{ PORTMAPPROC_SET, "SET",
		dissect_set_call, dissect_set_reply },
	{ PORTMAPPROC_UNSET, "UNSET",
		dissect_unset_call, dissect_set_reply },
	{ PORTMAPPROC_GETPORT,	"GETPORT",
		dissect_getport_call, dissect_getport_reply },
	{ PORTMAPPROC_DUMP, "DUMP",
		NULL, dissect_dump_reply },
	{ PORTMAPPROC_CALLIT, "CALLIT",
		NULL, NULL },
    { 0, NULL, NULL, NULL }
};
/* end of Portmap version 2 */


/* RFC 1833, Page 3 */
static int
dissect_rpcb(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_item* rpcb_item = NULL;
	proto_tree* rpcb_tree = NULL;
	int old_offset = offset;
	guint32 prog;
	guint32 version;

	if (tree) {
		rpcb_item = proto_tree_add_item(tree, hf_portmap_rpcb, NullTVB,
			offset+0, END_OF_FRAME, FALSE);
		if (rpcb_item)
			rpcb_tree = proto_item_add_subtree(rpcb_item, ett_portmap_rpcb);
	}

	if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;
	prog = EXTRACT_UINT(pd, offset + 0);
	if (rpcb_tree)
		proto_tree_add_uint_format(rpcb_tree, hf_portmap_rpcb_prog, NullTVB,
			offset+0, 4, prog, 
			"Program: %s (%u)", rpc_prog_name(prog), prog);
	offset += 4;

	if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;
	version = EXTRACT_UINT(pd, offset + 0);
	if (rpcb_tree)
		proto_tree_add_uint(rpcb_tree, hf_portmap_rpcb_version, NullTVB,
			offset+0, 4, version);
	offset += 4;

	offset = dissect_rpc_string(pd, offset, fd, rpcb_tree, hf_portmap_rpcb_netid,NULL);
	offset = dissect_rpc_string(pd, offset, fd, rpcb_tree, hf_portmap_rpcb_addr,NULL);
	offset = dissect_rpc_string(pd, offset, fd, rpcb_tree, hf_portmap_rpcb_owner,NULL);

	/* now we know, that rpcb is shorter */
	if (rpcb_item) {
		proto_item_set_len(rpcb_item, offset - old_offset);
	}

	return offset;
}



/* RFC 1833, Page 7 */
int dissect_rpcb3_getaddr_call(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	offset = dissect_rpcb(pd, offset, fd, tree);

	return offset;
}


/* RFC 1833, Page 7 */
int dissect_rpcb3_getaddr_reply(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	offset = dissect_rpc_string(pd, offset, fd, tree, hf_portmap_uaddr,NULL);

	return offset;
}


/* RFC 1833, Page 7 */
int dissect_rpcb3_dump_reply(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	offset = dissect_rpc_list(pd, offset, fd, tree, dissect_rpcb);
	return offset;
}


/* Portmapper version 3, RFC 1833, Page 7 */
static const vsff portmap3_proc[] = {
	{ RPCBPROC_NULL,	"NULL",
		NULL, NULL },
	{ RPCBPROC_SET,		"SET",
		NULL, NULL },
	{ RPCBPROC_UNSET,	"UNSET",
		NULL, NULL },
	{ RPCBPROC_GETADDR,	"GETADDR",
		dissect_rpcb3_getaddr_call, dissect_rpcb3_getaddr_reply},
	{ RPCBPROC_DUMP,	"DUMP",
		NULL, dissect_rpcb3_dump_reply },
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
static const vsff portmap4_proc[] = {
	{ RPCBPROC_NULL,	"NULL",
		NULL, NULL },
	{ RPCBPROC_SET,		"SET",
		NULL, NULL },
	{ RPCBPROC_UNSET,	"UNSET",
		NULL, NULL },
	{ RPCBPROC_GETADDR,	"GETADDR",
		dissect_rpcb3_getaddr_call, dissect_rpcb3_getaddr_reply},
	{ RPCBPROC_DUMP,	"DUMP",
		NULL, dissect_rpcb3_dump_reply },
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
		{ &hf_portmap_rpcb, {
			"RPCB", "portmap.rpcb", FT_NONE, 0,
			NULL, 0, "RPCB" }},
		{ &hf_portmap_rpcb_prog, {
			"Program", "portmap.rpcb.prog", FT_UINT32, BASE_DEC,
			NULL, 0, "Program" }},
		{ &hf_portmap_rpcb_version, {
			"Version", "portmap.rpcb.version", FT_UINT32, BASE_DEC,
			NULL, 0, "Version" }},
		{ &hf_portmap_rpcb_netid, {
			"Network Id", "portmap.rpcb.netid", FT_STRING, BASE_DEC,
			NULL, 0, "Network Id" }},
		{ &hf_portmap_rpcb_addr, {	/* address in rpcb structure in request */
			"Universal Address", "portmap.rpcb.addr", FT_STRING, BASE_DEC,
			NULL, 0, "Universal Address" }},
		{ &hf_portmap_rpcb_owner, {
			"Owner of this Service", "portmap.rpcb.owner", FT_STRING, BASE_DEC,
			NULL, 0, "Owner of this Service" }},
		{ &hf_portmap_uaddr, {	/* address in RPCBPROC_GETADDR reply */
			"Universal Address", "portmap.uaddr", FT_STRING, BASE_DEC,
			NULL, 0, "Universal Address" }},
	};
	static gint *ett[] = {
		&ett_portmap,
		&ett_portmap_rpcb,
		&ett_portmap_entry
	};

	proto_portmap = proto_register_protocol("Portmap", "Portmap", "portmap");
	proto_register_field_array(proto_portmap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_portmap(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_portmap, PORTMAP_PROGRAM, ett_portmap);
	/* Register the procedure tables */
	rpc_init_proc_table(PORTMAP_PROGRAM, 1, portmap1_proc);
	rpc_init_proc_table(PORTMAP_PROGRAM, 2, portmap2_proc);
	rpc_init_proc_table(PORTMAP_PROGRAM, 3, portmap3_proc);
	rpc_init_proc_table(PORTMAP_PROGRAM, 4, portmap4_proc);
}
