/* packet-bootparams.c
 * Routines for bootparams dissection
 *
 * $Id: packet-bootparams.c,v 1.17 2001/03/18 02:07:02 guy Exp $
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

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>

#include "packet-rpc.h"
#include "packet-bootparams.h"

static int proto_bootparams = -1;
static int hf_bootparams_host = -1;
static int hf_bootparams_domain = -1;
static int hf_bootparams_fileid = -1;
static int hf_bootparams_filepath = -1;
static int hf_bootparams_hostaddr = -1;
static int hf_bootparams_routeraddr = -1;
static int hf_bootparams_addresstype = -1;

static gint ett_bootparams = -1;


static const value_string addr_type[] =
{
	{ 	1,	"IPv4-ADDR"	},
	{	0,	NULL		}
};

static int
dissect_bp_address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hfindex)
{
	guint32 type;
	guint32 ipaddr;


	type = tvb_get_ntohl(tvb, offset);
	
	offset = dissect_rpc_uint32_tvb(tvb, pinfo, tree, hf_bootparams_addresstype, offset);

	switch(type){
	case 1:
		ipaddr = ((tvb_get_guint8(tvb, offset+3 )&0xff)<<24) 
			|((tvb_get_guint8(tvb, offset+7 )&0xff)<<16)
			|((tvb_get_guint8(tvb, offset+11)&0xff)<<8 )
			|((tvb_get_guint8(tvb, offset+15)&0xff) );
		proto_tree_add_ipv4(tree, hfindex, tvb, 
			offset, 16, ntohl(ipaddr));
		offset += 16;
		break;

	default:
		break;
	}

	return offset;
}


static int
dissect_getfile_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string_tvb(tvb, pinfo, tree, hf_bootparams_host, offset, NULL);
		offset = dissect_rpc_string_tvb(tvb, pinfo, tree, hf_bootparams_fileid, offset, NULL);
	}
	
	return offset;
}

static int
dissect_getfile_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string_tvb(tvb, pinfo, tree, hf_bootparams_host, offset, NULL);
		offset = dissect_bp_address(tvb, offset, pinfo, tree, hf_bootparams_hostaddr);
		offset = dissect_rpc_string_tvb(tvb, pinfo, tree, hf_bootparams_filepath, offset, NULL);
	}
	
	return offset;
}

static int
dissect_whoami_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_bp_address(tvb, offset, pinfo, tree, hf_bootparams_hostaddr);
	}
	
	return offset;
}

static int
dissect_whoami_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string_tvb(tvb, pinfo, tree, hf_bootparams_host, offset, NULL);
		offset = dissect_rpc_string_tvb(tvb, pinfo, tree, hf_bootparams_domain, offset, NULL);
		offset = dissect_bp_address(tvb, offset, pinfo, tree, hf_bootparams_routeraddr);
	}
	
	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff bootparams1_proc[] = {
	{ BOOTPARAMSPROC_NULL, "NULL",
		NULL, NULL },
	{ BOOTPARAMSPROC_WHOAMI, "WHOAMI", 
		dissect_whoami_call, dissect_whoami_reply },
	{ BOOTPARAMSPROC_GETFILE, "GETFILE", 
		dissect_getfile_call, dissect_getfile_reply },
	{ 0, NULL, NULL, NULL }
};
/* end of Bootparams version 1 */


void
proto_register_bootparams(void)
{
	static hf_register_info hf[] = {
		{ &hf_bootparams_host, {
			"Client Host", "bootparams.host", FT_STRING, BASE_DEC,
			NULL, 0, "Client Host" }},
		{ &hf_bootparams_domain, {
			"Client Domain", "bootparams.domain", FT_STRING, BASE_DEC,
			NULL, 0, "Client Domain" }},
		{ &hf_bootparams_fileid, {
			"File ID", "bootparams.fileid", FT_STRING, BASE_DEC,
			NULL, 0, "File ID" }},
		{ &hf_bootparams_filepath, {
			"File Path", "bootparams.filepath", FT_STRING, BASE_DEC,
			NULL, 0, "File Path" }},
		{ &hf_bootparams_hostaddr, {
			"Client Address", "bootparams.hostaddr", FT_IPv4, BASE_DEC,
			NULL, 0, "Address" }},
		{ &hf_bootparams_routeraddr, {
			"Router Address", "bootparams.routeraddr", FT_IPv4, BASE_DEC,
			NULL, 0, "Router Address" }},
		{ &hf_bootparams_addresstype, {
			"Address Type", "bootparams.type", FT_UINT32, BASE_DEC,
			VALS(addr_type), 0, "Address Type" }},
	};
	static gint *ett[] = {
		&ett_bootparams,
	};

	proto_bootparams = proto_register_protocol("Boot Parameters",
	    "BOOTPARAMS", "bootparams");
	proto_register_field_array(proto_bootparams, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bootparams(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_bootparams, BOOTPARAMS_PROGRAM, ett_bootparams);
	/* Register the procedure tables */
	rpc_init_proc_table(BOOTPARAMS_PROGRAM, 1, bootparams1_proc);
}
