/* packet-ypserv.c
 * Routines for ypserv dissection
 *
 * $Id: packet-ypserv.c,v 1.3 1999/11/11 20:18:46 nneul Exp $
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
#include "packet-ypserv.h"

static int proto_ypserv = -1;
static int hf_ypserv_domain = -1;
static int hf_ypserv_servesdomain = -1;
static int hf_ypserv_map = -1;
static int hf_ypserv_key = -1;
static int hf_ypserv_value = -1;

/* Dissect a domain call */
int dissect_domain_call(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string_item(pd,offset,fd,tree,hf_ypserv_domain);
	}
	
	return offset;
}

int dissect_domain_reply(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	if ( tree )
	{
		if ( !BYTES_ARE_IN_FRAME(offset, 1)) return offset;
		proto_tree_add_item(tree, hf_ypserv_servesdomain,
			offset, 4, pntohl(&pd[offset]));
        offset += 4;
	}
	
	return offset;
}

/* Dissect a next call */
int dissect_next_call(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string_item(pd,offset,fd,tree,hf_ypserv_domain);
		offset = dissect_rpc_string_item(pd,offset,fd,tree,hf_ypserv_map);
		offset = dissect_rpc_string_item(pd,offset,fd,tree,hf_ypserv_key);
	}
	
	return offset;
}

int dissect_first_call(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string_item(pd,offset,fd,tree,hf_ypserv_domain);
		offset = dissect_rpc_string_item(pd,offset,fd,tree,hf_ypserv_map);
	}
	
	return offset;
}

int dissect_match_call(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string_item(pd,offset,fd,tree,hf_ypserv_domain);
		offset = dissect_rpc_string_item(pd,offset,fd,tree,hf_ypserv_map);
		offset = dissect_rpc_string_item(pd,offset,fd,tree,hf_ypserv_key);
	}
	
	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */

/* someone please get me a version 1 trace */
const vsff ypserv1_proc[] = {
    { 0, "NULL", NULL, NULL },
    { YPPROC_ALL,   "ALL",      
		NULL, NULL },
    { YPPROC_CLEAR, "CLEAR",        
		NULL, NULL },
    { YPPROC_DOMAIN, "DOMAIN",
		NULL, NULL },
    { YPPROC_DOMAIN_NONACK, "DOMAIN_NONACK",
		NULL, NULL },
    { YPPROC_FIRST, "FIRST",        
		NULL, NULL },
    { YPPROC_MAPLIST,   "MAPLIST",      
		NULL, NULL },
    { YPPROC_MASTER,    "MASTER",       
		NULL, NULL },
    { YPPROC_MATCH, "MATCH",        
		NULL, NULL },
    { YPPROC_NEXT,  "NEXT",     
		NULL, NULL },
    { YPPROC_ORDER, "ORDER",        
		NULL, NULL },
    { YPPROC_XFR,   "XFR",      
		NULL, NULL },
    { 0, NULL, NULL, NULL }
};
/* end of YPServ version 2 */

const vsff ypserv2_proc[] = {
    { 0, "NULL", NULL, NULL },
    { YPPROC_ALL,   "ALL",      
		NULL, NULL },
    { YPPROC_CLEAR, "CLEAR",        
		NULL, NULL },
    { YPPROC_DOMAIN, "DOMAIN",
		dissect_domain_call, dissect_domain_reply },
    { YPPROC_DOMAIN_NONACK, "DOMAIN_NONACK",
		dissect_domain_call, dissect_domain_reply },
    { YPPROC_FIRST, "FIRST",        
		dissect_first_call, NULL },
    { YPPROC_MAPLIST,   "MAPLIST",      
		NULL, NULL },
    { YPPROC_MASTER,    "MASTER",       
		NULL, NULL },
    { YPPROC_MATCH, "MATCH",        
		dissect_match_call, NULL },
    { YPPROC_NEXT,  "NEXT",     
		dissect_next_call, NULL },
    { YPPROC_ORDER, "ORDER",        
		NULL, NULL },
    { YPPROC_XFR,   "XFR",      
		NULL, NULL },
    { 0, NULL, NULL, NULL }
};
/* end of YPServ version 2 */


void
proto_register_ypserv(void)
{
	static hf_register_info hf[] = {
		{ &hf_ypserv_domain, {
			"Domain", "ypserv.domain", FT_STRING, BASE_DEC,
			NULL, 0, "Domain" }},
		{ &hf_ypserv_servesdomain, {
			"Serves Domain", "ypserv.servesdomain", FT_BOOLEAN, BASE_DEC,
			NULL, 0, "Serves Domain" }},
		{ &hf_ypserv_map, {
			"Map Name", "ypserv.map", FT_STRING, BASE_DEC,
			NULL, 0, "Map Name" }},
		{ &hf_ypserv_key, {
			"Key", "ypserv.key", FT_STRING, BASE_DEC,
			NULL, 0, "Key" }},
		{ &hf_ypserv_value, {
			"Value", "ypserv.value", FT_STRING, BASE_DEC,
			NULL, 0, "Value" }},
	};

	proto_ypserv = proto_register_protocol("Yellow Pages Service", "ypserv");
	proto_register_field_array(proto_ypserv, hf, array_length(hf));

	/* Register the protocol as RPC */
	rpc_init_prog(proto_ypserv, YPSERV_PROGRAM, ETT_YPSERV);
	/* Register the procedure tables */
	rpc_init_proc_table(YPSERV_PROGRAM, 1, ypserv1_proc);
	rpc_init_proc_table(YPSERV_PROGRAM, 2, ypserv2_proc);
}

