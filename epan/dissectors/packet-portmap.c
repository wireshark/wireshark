/* packet-portmap.c
 * Routines for portmap dissection
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"



#include "packet-rpc.h"
#include "packet-portmap.h"
#include <epan/ipproto.h>
#include <epan/conversation.h>
#include <epan/packet_info.h>

/*
 * See:
 *
 *	RFC 1833, "Binding Protocols for ONC RPC Version 2".
 */

static int proto_portmap = -1;
static int hf_portmap_procedure_v1 = -1;
static int hf_portmap_procedure_v2 = -1;
static int hf_portmap_procedure_v3 = -1;
static int hf_portmap_procedure_v4 = -1;
static int hf_portmap_proto = -1;
static int hf_portmap_prog = -1;
static int hf_portmap_proc = -1;
static int hf_portmap_version = -1;
static int hf_portmap_port = -1;
static int hf_portmap_answer = -1;
static int hf_portmap_args = -1;
static int hf_portmap_result = -1;
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

static dissector_handle_t rpc_handle;

/* Dissect a getport call */
static int
dissect_getport_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint32 proto, version;
	guint32 prog;
	const char *prog_name;
	const char *proto_name;

	/* make sure we remember protocol type until the reply packet */
	if(!pinfo->fd->flags.visited){
		rpc_call_info_value *rpc_call=pinfo->private_data;
		if(rpc_call){
			proto = tvb_get_ntohl(tvb, offset+8);
			if(proto==IP_PROTO_UDP){  /* only do this for UDP */
				rpc_call->private_data=(void *)PT_UDP;
			}
		}
	}

	/* program */
	prog = tvb_get_ntohl(tvb, offset+0);
	prog_name = rpc_prog_name(prog);
	proto_tree_add_uint_format(tree, hf_portmap_prog, tvb,
		offset, 4, prog, "Program: %s (%u)",
		prog_name, prog);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,  " %s(%u)", prog_name, prog);

	}
	proto_item_append_text(tree, " GETPORT Call %s(%u)", prog_name, prog);

	/* version */
	version = tvb_get_ntohl(tvb, offset+4);
	proto_tree_add_item(tree, hf_portmap_version, tvb,
		offset+4, 4, ENC_BIG_ENDIAN);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,  " V:%d", version);

	}
	proto_item_append_text(tree, " Version:%d", version);


	/* protocol */
	proto = tvb_get_ntohl(tvb, offset+8);
	proto_name = ipprotostr(proto);
	proto_tree_add_uint_format(tree, hf_portmap_proto, tvb,
		offset+8, 4, proto, "Proto: %s (%u)", proto_name, proto);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,  " %s", proto_name);

	}
	proto_item_append_text(tree, " %s", proto_name);

	/* port */
	proto_tree_add_item(tree, hf_portmap_port, tvb,
		offset+12, 4, ENC_BIG_ENDIAN);

	return offset+16;
}

static int
dissect_getport_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint32 portx;

	/* we might have learnt a <ipaddr><protocol><port> mapping for ONC-RPC*/
	if(!pinfo->fd->flags.visited){
		rpc_call_info_value *rpc_call=pinfo->private_data;
		/* only do this for UDP, TCP does not need anything like this */
		if(rpc_call && (GPOINTER_TO_UINT(rpc_call->private_data)==PT_UDP) ){
			guint32 port;
			port=tvb_get_ntohl(tvb, offset);
			if(port){
				conversation_t *conv;
				conv=find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, (port_type)rpc_call->private_data, port, 0, NO_ADDR_B|NO_PORT_B);
				if(!conv){
					conv=conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, (port_type)rpc_call->private_data, port, 0, NO_ADDR2|NO_PORT2);
				}
				conversation_set_dissector(conv, rpc_handle);
			}
		}
	}

	portx = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_portmap_port,
	    offset);
	proto_item_append_text(tree, " GETPORT Reply Port:%d", portx);
	if(portx){
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO,  " Port:%d", portx);
		}
		proto_item_append_text(tree, " Port:%d", portx);
	} else {
		col_append_str(pinfo->cinfo, COL_INFO,  " PROGRAM_NOT_AVAILABLE");
		proto_item_append_text(tree, " PROGRAM_NOT_AVAILABLE");
	}

	return offset;
}

/* Dissect a 'set' call */
static int
dissect_set_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint32 proto;
	guint32 prog;

	if ( tree )
	{
		prog = tvb_get_ntohl(tvb, offset+0);
		proto_tree_add_uint_format(tree, hf_portmap_prog, tvb,
			offset, 4, prog, "Program: %s (%d)",
			rpc_prog_name(prog), prog);
		proto_tree_add_item(tree, hf_portmap_version, tvb,
			offset+4, 4, ENC_BIG_ENDIAN);

		proto = tvb_get_ntohl(tvb, offset+8);
		proto_tree_add_uint_format(tree, hf_portmap_proto,tvb,
			offset+8, 4, proto, "Proto: %s (%d)", ipprotostr(proto), proto);

		proto_tree_add_item(tree, hf_portmap_port, tvb,
			offset+12, 4, ENC_BIG_ENDIAN);
	}

	return offset+16;
}

/* Dissect a 'unset' call */
static int
dissect_unset_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint32 proto;
	guint32 prog;

	if ( tree )
	{
		prog = tvb_get_ntohl(tvb, offset+0);
		proto_tree_add_uint_format(tree, hf_portmap_prog, tvb,
			offset, 4, prog, "Program: %s (%d)",
			rpc_prog_name(prog), prog);
		proto_tree_add_item(tree, hf_portmap_version, tvb,
			offset+4, 4, ENC_BIG_ENDIAN);

		proto = tvb_get_ntohl(tvb, offset+8);
		proto_tree_add_uint(tree, hf_portmap_proto, tvb,
			offset+8, 4, proto);

		proto_tree_add_item(tree, hf_portmap_port, tvb,
			offset+12, 4, ENC_BIG_ENDIAN);
	}

	return offset+16;
}

static int
dissect_set_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_bool(tvb, tree, hf_portmap_answer,
	    offset);
	return offset;
}

static int
dissect_dump_entry(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	int prog, version, proto, port;
	proto_item *ti, *subtree;

	prog = tvb_get_ntohl(tvb, offset+0);
	version = tvb_get_ntohl(tvb, offset+4);
	proto = tvb_get_ntohl(tvb, offset+8);
	port = tvb_get_ntohl(tvb, offset+12);
	if ( tree )
	{
		ti = proto_tree_add_text(tree, tvb, offset, 16,
			"Map Entry: %s (%u) V%d",
			rpc_prog_name(prog), prog, version);
		subtree = proto_item_add_subtree(ti, ett_portmap_entry);

		proto_tree_add_uint_format(subtree, hf_portmap_prog, tvb,
			offset+0, 4, prog,
			"Program: %s (%u)", rpc_prog_name(prog), prog);
		proto_tree_add_uint(subtree, hf_portmap_version, tvb,
			offset+4, 4, version);
		proto_tree_add_uint_format(subtree, hf_portmap_proto, tvb,
			offset+8, 4, proto,
			"Protocol: %s (0x%02x)", ipprotostr(proto), proto);
		proto_tree_add_uint(subtree, hf_portmap_port, tvb,
			offset+12, 4, port);
	}
	offset += 16;
	return offset;
}

static int
dissect_dump_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
		dissect_dump_entry);
	return offset;
}

/* Dissect a callit call */
static int
dissect_callit_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 prog, vers, proc;

	prog = tvb_get_ntohl(tvb, offset+0);
	if ( tree )
	{
		proto_tree_add_uint_format(tree, hf_portmap_prog, tvb,
			offset, 4, prog, "Program: %s (%u)",
			rpc_prog_name(prog), prog);
	}

	vers = tvb_get_ntohl(tvb, offset+4);
	if ( tree )
	{
		proto_tree_add_uint(tree, hf_portmap_version, tvb,
			offset+4, 4, vers);
	}

	proc = tvb_get_ntohl(tvb, offset+8);
	if ( tree )
	{
		proto_tree_add_uint_format(tree, hf_portmap_proc, tvb,
			offset+8, 4, proc, "Procedure: %s (%u)",
			rpc_proc_name(prog, vers, proc), proc);
	}

	offset += 12;

	/* Dissect the arguments for this procedure.
	   Make the columns non-writable, so the dissector won't change
	   them out from under us. */
	col_set_writable(pinfo->cinfo, FALSE);
	offset = dissect_rpc_indir_call(tvb, pinfo, tree, offset,
		hf_portmap_args, prog, vers, proc);

	return offset;
}

/* Dissect a callit reply */
static int
dissect_callit_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	if ( tree )
	{
		proto_tree_add_item(tree, hf_portmap_port, tvb,
			offset, 4, ENC_BIG_ENDIAN);
	}
	offset += 4;

	/* Dissect the result of this procedure.
	   Make the columns non-writable, so the dissector won't change
	   them out from under us. */
	col_set_writable(pinfo->cinfo, FALSE);
	offset = dissect_rpc_indir_reply(tvb, pinfo, tree, offset,
		hf_portmap_result, hf_portmap_prog, hf_portmap_version,
		hf_portmap_proc);

	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff portmap1_proc[] = {
	{ PORTMAPPROC_NULL,	"NULL",		NULL,	NULL },
	{ PORTMAPPROC_SET,	"SET",		NULL,	NULL },
	{ PORTMAPPROC_UNSET,	"UNSET",	NULL,	NULL },
	{ PORTMAPPROC_GETPORT,	"GETPORT",	NULL,	NULL },
	{ PORTMAPPROC_DUMP,	"DUMP",		NULL,	NULL },
	{ PORTMAPPROC_CALLIT,	"CALLIT",	NULL,	NULL },
	{ 0,			NULL,		NULL,	NULL }
};
static const value_string portmap1_proc_vals[] = {
	{ PORTMAPPROC_NULL,	"NULL" },
	{ PORTMAPPROC_SET,	"SET" },
	{ PORTMAPPROC_UNSET,	"UNSET" },
	{ PORTMAPPROC_GETPORT,	"GETPORT" },
	{ PORTMAPPROC_DUMP,	"DUMP" },
	{ PORTMAPPROC_CALLIT,	"CALLIT" },
	{ 0,			NULL }
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
		dissect_callit_call, dissect_callit_reply },
	{ 0, NULL, NULL, NULL }
};
static const value_string portmap2_proc_vals[] = {
	{ PORTMAPPROC_NULL, "NULL" },
	{ PORTMAPPROC_SET, "SET" },
	{ PORTMAPPROC_UNSET, "UNSET" },
	{ PORTMAPPROC_GETPORT,	"GETPORT" },
	{ PORTMAPPROC_DUMP, "DUMP" },
	{ PORTMAPPROC_CALLIT, "CALLIT" },
	{ 0, NULL }
};
/* end of Portmap version 2 */


/* RFC 1833, Page 3 */
static int
dissect_rpcb(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item* rpcb_item = NULL;
	proto_tree* rpcb_tree = NULL;
	int old_offset = offset;
	guint32 prog;

	if (tree) {
		rpcb_item = proto_tree_add_item(tree, hf_portmap_rpcb, tvb,
			offset, -1, ENC_NA);
		if (rpcb_item)
			rpcb_tree = proto_item_add_subtree(rpcb_item, ett_portmap_rpcb);
	}

	prog = tvb_get_ntohl(tvb, offset);
	if (rpcb_tree)
		proto_tree_add_uint_format(rpcb_tree, hf_portmap_rpcb_prog, tvb,
			offset, 4, prog,
			"Program: %s (%u)", rpc_prog_name(prog), prog);
	offset += 4;

	offset = dissect_rpc_uint32(tvb, rpcb_tree,
	    hf_portmap_rpcb_version, offset);
	offset = dissect_rpc_string(tvb, rpcb_tree,
	    hf_portmap_rpcb_netid, offset, NULL);
	offset = dissect_rpc_string(tvb, rpcb_tree,
	    hf_portmap_rpcb_addr, offset, NULL);
	offset = dissect_rpc_string(tvb, rpcb_tree,
	    hf_portmap_rpcb_owner, offset, NULL);

	/* now we know, that rpcb is shorter */
	if (rpcb_item) {
		proto_item_set_len(rpcb_item, offset - old_offset);
	}

	return offset;
}



/* RFC 1833, Page 7 */
static int
dissect_rpcb3_getaddr_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	offset = dissect_rpcb(tvb, offset, pinfo, tree);

	return offset;
}


/* RFC 1833, Page 7 */
static int
dissect_rpcb3_getaddr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree,
	    hf_portmap_uaddr, offset, NULL);

	return offset;
}


/* RFC 1833, Page 7 */
static int
dissect_rpcb3_dump_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	offset = dissect_rpc_list(tvb, pinfo, tree, offset, dissect_rpcb);
	return offset;
}

/* RFC 1833, page 4 */
static int
dissect_rpcb_rmtcallres(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	/* Dissect the remote universal address. */
	offset = dissect_rpc_string(tvb, tree,
	    hf_portmap_rpcb_addr, offset, NULL);

	/* Dissect the result of this procedure.
	   Make the columns non-writable, so the dissector won't change
	   them out from under us. */
	col_set_writable(pinfo->cinfo, FALSE);
	offset = dissect_rpc_indir_reply(tvb, pinfo, tree, offset,
		hf_portmap_result, hf_portmap_prog, hf_portmap_version,
		hf_portmap_proc);

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
		dissect_callit_call, dissect_rpcb_rmtcallres },
	{ RPCBPROC_GETTIME,	"GETTIME",
		NULL, NULL },
	{ RPCBPROC_UADDR2TADDR,	"UADDR2TADDR",
		NULL, NULL },
	{ RPCBPROC_TADDR2UADDR,	"TADDR2UADDR",
		NULL, NULL },
	{ 0, NULL, NULL, NULL }
};
static const value_string portmap3_proc_vals[] = {
	{ RPCBPROC_NULL,	"NULL" },
	{ RPCBPROC_SET,		"SET" },
	{ RPCBPROC_UNSET,	"UNSET" },
	{ RPCBPROC_GETADDR,	"GETADDR" },
	{ RPCBPROC_DUMP,	"DUMP" },
	{ RPCBPROC_CALLIT,	"CALLIT" },
	{ RPCBPROC_GETTIME,	"GETTIME" },
	{ RPCBPROC_UADDR2TADDR,	"UADDR2TADDR" },
	{ RPCBPROC_TADDR2UADDR,	"TADDR2UADDR" },
	{ 0, NULL }
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
		dissect_callit_call, dissect_rpcb_rmtcallres },
	{ RPCBPROC_GETTIME,	"GETTIME",
		NULL, NULL },
	{ RPCBPROC_UADDR2TADDR,	"UADDR2TADDR",
		NULL, NULL },
	{ RPCBPROC_TADDR2UADDR,	"TADDR2UADDR",
		NULL, NULL },
	{ RPCBPROC_GETVERSADDR,	"GETVERSADDR",
		NULL, NULL },
	{ RPCBPROC_INDIRECT,	"INDIRECT",
		dissect_callit_call, dissect_rpcb_rmtcallres },
	{ RPCBPROC_GETADDRLIST,	"GETADDRLIST",
		NULL, NULL },
	{ RPCBPROC_GETSTAT,	"GETSTAT",
		NULL, NULL },
	{ 0, NULL, NULL, NULL }
};
static const value_string portmap4_proc_vals[] = {
	{ RPCBPROC_NULL,	"NULL" },
	{ RPCBPROC_SET,		"SET" },
	{ RPCBPROC_UNSET,	"UNSET" },
	{ RPCBPROC_GETADDR,	"GETADDR" },
	{ RPCBPROC_DUMP,	"DUMP" },
	{ RPCBPROC_BCAST,	"BCAST" },
	{ RPCBPROC_GETTIME,	"GETTIME" },
	{ RPCBPROC_UADDR2TADDR,	"UADDR2TADDR" },
	{ RPCBPROC_TADDR2UADDR,	"TADDR2UADDR" },
	{ RPCBPROC_GETVERSADDR,	"GETVERSADDR" },
	{ RPCBPROC_INDIRECT,	"INDIRECT" },
	{ RPCBPROC_GETADDRLIST,	"GETADDRLIST" },
	{ RPCBPROC_GETSTAT,	"GETSTAT" },
	{ 0, NULL }
};
/* end of Portmap version 4 */

void
proto_register_portmap(void)
{
	static hf_register_info hf[] = {
		{ &hf_portmap_procedure_v1, {
			"V1 Procedure", "portmap.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(portmap1_proc_vals), 0, NULL, HFILL }},
		{ &hf_portmap_procedure_v2, {
			"V2 Procedure", "portmap.procedure_v2", FT_UINT32, BASE_DEC,
			VALS(portmap2_proc_vals), 0, NULL, HFILL }},
		{ &hf_portmap_procedure_v3, {
			"V3 Procedure", "portmap.procedure_v3", FT_UINT32, BASE_DEC,
			VALS(portmap3_proc_vals), 0, NULL, HFILL }},
		{ &hf_portmap_procedure_v4, {
			"V4 Procedure", "portmap.procedure_v4", FT_UINT32, BASE_DEC,
			VALS(portmap4_proc_vals), 0, NULL, HFILL }},
		{ &hf_portmap_prog, {
			"Program", "portmap.prog", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_port, {
			"Port", "portmap.port", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_proc, {
			"Procedure", "portmap.proc", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_proto, {
			"Protocol", "portmap.proto", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_version, {
			"Version", "portmap.version", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_answer, {
			"Answer", "portmap.answer", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_portmap_args, {
			"Arguments", "portmap.args", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_result, {
			"Result", "portmap.result", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_rpcb, {
			"RPCB", "portmap.rpcb", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_rpcb_prog, {
			"Program", "portmap.rpcb.prog", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_rpcb_version, {
			"Version", "portmap.rpcb.version", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_rpcb_netid, {
			"Network Id", "portmap.rpcb.netid", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_rpcb_addr, {	/* address in rpcb structure in request */
			"Universal Address", "portmap.rpcb.addr", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_rpcb_owner, {
			"Owner of this Service", "portmap.rpcb.owner", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_portmap_uaddr, {	/* address in RPCBPROC_GETADDR reply */
			"Universal Address", "portmap.uaddr", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
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
	rpc_init_proc_table(PORTMAP_PROGRAM, 1, portmap1_proc, hf_portmap_procedure_v1);
	rpc_init_proc_table(PORTMAP_PROGRAM, 2, portmap2_proc, hf_portmap_procedure_v2);
	rpc_init_proc_table(PORTMAP_PROGRAM, 3, portmap3_proc, hf_portmap_procedure_v3);
	rpc_init_proc_table(PORTMAP_PROGRAM, 4, portmap4_proc, hf_portmap_procedure_v4);
	rpc_handle = find_dissector("rpc");
}
