/* packet-ypserv.c
 * Routines for ypserv dissection
 *
 * $Id: packet-ypserv.c,v 1.20 2002/02/20 21:02:46 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-smb.c
 *
 * 2001 Ronnie Sahlberg <See AUTHORS for email>
 *   Added all remaining dissectors for this protocol
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
static int hf_ypserv_peer = -1;
static int hf_ypserv_more = -1;
static int hf_ypserv_ordernum = -1;
static int hf_ypserv_transid = -1;
static int hf_ypserv_prog = -1;
static int hf_ypserv_port = -1;
static int hf_ypserv_value = -1;
static int hf_ypserv_status = -1;
static int hf_ypserv_map_parms = -1;
static int hf_ypserv_xfrstat = -1;

static gint ett_ypserv = -1;
static gint ett_ypserv_map_parms = -1;

static const value_string ypstat[] =
{
	{	1,	"YP_TRUE"	},
	{	2,	"YP_NOMORE"	},
	{	0,	"YP_FALSE"	},
	{	-1,	"YP_NOMAP"	},
	{	-2,	"YP_NODOM"	},
	{	-3,	"YP_NOKEY"	},
	{	-4,	"YP_BADOP"	},
	{	-5,	"YP_BADDB"	},
	{	-6,	"YP_YPERR"	},
	{	-7,	"YP_BADARGS"	},
	{	-8,	"YP_VERS"	},
	{	0,	NULL	},
};

static const value_string xfrstat[] =
{
	{	1,	"YPXFR_SUCC"	},
	{	2,	"YPXFR_AGE"	},
	{	-1,	"YPXFR_NOMAP"	},
	{	-2,	"YPXFR_NODOM"	},
	{	-3,	"YPXFR_RSRC"	},
	{	-4,	"YPXFR_RPC"	},
	{	-5,	"YPXFR_MADDR"	},
	{	-6,	"YPXFR_YPERR"	},
	{	-7,	"YPXFR_BADARGS"	},
	{	-8,	"YPXFR_DBM"	},
	{	-9,	"YPXFR_FILE"	},
	{	-10,	"YPXFR_SKEW"	},
	{	-11,	"YPXFR_CLEAR"	},
	{	-12,	"YPXFR_FORCE"	},
	{	-13,	"YPXFR_XFRERR"	},
	{	-14,	"YPXFR_REFUSED"	},
	{	0,	NULL	},
};

static int
dissect_domain_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string(tvb,pinfo,tree,hf_ypserv_domain,offset,NULL);
	}
	
	return offset;
}

static int
dissect_domain_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if ( tree )
	{
		proto_tree_add_boolean(tree, hf_ypserv_servesdomain, tvb,
			offset, 4, tvb_get_ntohl(tvb,offset));
	}

	offset += 4;	
	return offset;
}

static int
dissect_match_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_domain, offset, NULL);
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_map, offset, NULL);
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_key, offset, NULL);
	}
	
	return offset;
}

static int
dissect_match_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_status, offset);

		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_value,offset, NULL);
	}
	
	return offset;
}


static int
dissect_first_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/*
	 * XXX - does Sun's "yp.x" lie, and claim that the argument to a
	 * FIRST call is a "ypreq_key" rather than a "ypreq_nokey"?
	 * You presumably need the key for NEXT, as "next" is "next
	 * after some entry", and the key tells you which entry, but
	 * you don't need a key for FIRST, as there's only one entry that
	 * is the first entry.
	 *
	 * The NIS server originally used DBM, which has a "firstkey()"
	 * call, with no argument, and a "nextkey()" argument, with
	 * a key argument.  (Heck, it might *still* use DBM.)
	 *
	 * Given that, and given that at least one FIRST call from a Sun
	 * running Solaris 8 (the Sun on which I'm typing this, in fact)
	 * had a "ypreq_nokey" as the argument, I'm assuming that "yp.x"
	 * is buggy.
	 */
	
	if ( tree )
	{
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_domain, offset, NULL);
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_map, offset, NULL);
	}
	
	return offset;
}


static int
dissect_firstnext_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_status, offset);

		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_value, offset, NULL);
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_key, offset, NULL);
	}
	
	return offset;
}


static int
dissect_next_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_domain, offset, NULL);
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_map, offset, NULL);
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_key, offset, NULL);
	}
	
	return offset;
}

static int
dissect_xfr_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;
	int start_offset = offset;
	guint32 tid;

	if(tree){
		sub_item = proto_tree_add_item(tree, hf_ypserv_map_parms, tvb,
				offset, -1, FALSE);
		if(sub_item)
			sub_tree = proto_item_add_subtree(sub_item, ett_ypserv_map_parms);
	}

	offset = dissect_rpc_string(tvb, pinfo, sub_tree, hf_ypserv_domain, offset, NULL);
	
	offset = dissect_rpc_string(tvb, pinfo, sub_tree, hf_ypserv_map, offset, NULL);

	offset = dissect_rpc_uint32(tvb, pinfo, sub_tree, hf_ypserv_ordernum, offset);

	offset = dissect_rpc_string(tvb, pinfo, sub_tree, hf_ypserv_peer, offset, NULL);


	tid=tvb_get_ntohl(tvb,offset);
	tid=((tid&0x000000ff)<<24)|((tid&0x0000ff00)<<8)|((tid&0x00ff0000)>>8)|((tid&0xff000000)>>24);
	proto_tree_add_ipv4(tree, hf_ypserv_transid, tvb, offset, 4, tid);
	offset += 4;

	offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_prog, offset);
	offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_port, offset);

	if(sub_item)
		proto_item_set_len(sub_item, offset - start_offset);

	return offset;
}

static int
dissect_xfr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 tid;

	tid=tvb_get_ntohl(tvb,offset);
	tid=((tid&0x000000ff)<<24)|((tid&0x0000ff00)<<8)|((tid&0x00ff0000)>>8)|((tid&0xff000000)>>24);
	proto_tree_add_ipv4(tree, hf_ypserv_transid, tvb, offset, 4, tid);
	offset += 4;

	offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_xfrstat, offset);

	return offset;
}

static int
dissect_ypreq_nokey(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{

	offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_domain, offset, NULL);
	
	offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_map, offset, NULL);

	return offset;
}

static int
dissect_ypresp_all(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32	more;

	for (;;) {
		more = tvb_get_ntohl(tvb, offset);

		offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_more, offset);
		if (!more)
			break;
		offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_status, offset);
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_value, offset, NULL);
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_key, offset, NULL);
	}

	return offset;
}

static int
dissect_ypresp_master(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{

	offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_status, offset);

	offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_peer, offset, NULL);

	return offset;
}


static int
dissect_ypresp_order(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{

	offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_status, offset);

	offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_ordernum, offset);

	return offset;
}


static int
dissect_ypresp_maplist(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_status, offset);
	while(tvb_get_ntohl(tvb,offset)){
		offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_more, offset);
		offset = dissect_rpc_string(tvb, pinfo, tree, hf_ypserv_map, offset, NULL);

	}
	offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_ypserv_more, offset);
	return offset;
}


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */

/* someone please get me a version 1 trace */
static const vsff ypserv1_proc[] = {
    { 0, "NULL", NULL, NULL },
    { YPPROC_DOMAIN, "DOMAIN",
		NULL, NULL },
    { YPPROC_DOMAIN_NONACK, "DOMAIN_NONACK",
		NULL, NULL },
    { YPPROC_MATCH, "MATCH",        
		NULL, NULL },
    { YPPROC_FIRST, "FIRST",        
		NULL, NULL },
    { YPPROC_NEXT,  "NEXT",     
		NULL, NULL },
    { YPPROC_XFR,   "XFR",      
		NULL, NULL },
    { YPPROC_CLEAR, "CLEAR",        
		NULL, NULL },
    { YPPROC_ALL,   "ALL",      
		NULL, NULL },
    { YPPROC_MASTER,    "MASTER",       
		NULL, NULL },
    { YPPROC_ORDER, "ORDER",        
		NULL, NULL },
    { YPPROC_MAPLIST,   "MAPLIST",      
		NULL, NULL },
    { 0, NULL, NULL, NULL }
};
/* end of YPServ version 2 */

static const vsff ypserv2_proc[] = {
    { 0, "NULL", NULL, NULL },
    { YPPROC_DOMAIN, "DOMAIN",
		dissect_domain_call, dissect_domain_reply },
    { YPPROC_DOMAIN_NONACK, "DOMAIN_NONACK",
		dissect_domain_call, dissect_domain_reply },
    { YPPROC_MATCH, "MATCH",        
		dissect_match_call, dissect_match_reply },
    { YPPROC_FIRST, "FIRST",        
		dissect_first_call, dissect_firstnext_reply },
    { YPPROC_NEXT,  "NEXT",     
		dissect_next_call, dissect_firstnext_reply },
    { YPPROC_XFR,   "XFR",      
		dissect_xfr_call, dissect_xfr_reply },
    { YPPROC_CLEAR, "CLEAR",        
		NULL, NULL },
    { YPPROC_ALL,   "ALL",      
		dissect_ypreq_nokey, dissect_ypresp_all },
    { YPPROC_MASTER,    "MASTER",       
		dissect_ypreq_nokey, dissect_ypresp_master },
    { YPPROC_ORDER, "ORDER",        
		dissect_ypreq_nokey, dissect_ypresp_order },
    { YPPROC_MAPLIST,   "MAPLIST",      
		dissect_domain_call, dissect_ypresp_maplist },
    { 0, NULL, NULL, NULL }
};
/* end of YPServ version 2 */


void
proto_register_ypserv(void)
{
	/*static struct true_false_string okfailed = { "Ok", "Failed" };*/
	static struct true_false_string yesno = { "Yes", "No" };
		
	static hf_register_info hf[] = {
		{ &hf_ypserv_domain, {
			"Domain", "ypserv.domain", FT_STRING, BASE_DEC,
			NULL, 0, "Domain", HFILL }},
		{ &hf_ypserv_servesdomain, {
			"Serves Domain", "ypserv.servesdomain", FT_BOOLEAN, BASE_DEC,
			&yesno, 0, "Serves Domain", HFILL }},
		{ &hf_ypserv_map, {
			"Map Name", "ypserv.map", FT_STRING, BASE_DEC,
			NULL, 0, "Map Name", HFILL }},
		{ &hf_ypserv_peer, {
			"Peer Name", "ypserv.peer", FT_STRING, BASE_DEC,
			NULL, 0, "Peer Name", HFILL }},
		{ &hf_ypserv_more, {
			"More", "ypserv.more", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "More", HFILL }},
		{ &hf_ypserv_ordernum, {
			"Order Number", "ypserv.ordernum", FT_UINT32, BASE_DEC,
			NULL, 0, "Order Number for XFR", HFILL }},
		{ &hf_ypserv_transid, {
			"Host Transport ID", "ypserv.transid", FT_IPv4, BASE_DEC,
			NULL, 0, "Host Transport ID to use for XFR Callback", HFILL }},
		{ &hf_ypserv_prog, {
			"Program Number", "ypserv.prog", FT_UINT32, BASE_DEC,
			NULL, 0, "Program Number to use for XFR Callback", HFILL }},
		{ &hf_ypserv_port, {
			"Port", "ypserv.port", FT_UINT32, BASE_DEC,
			NULL, 0, "Port to use for XFR Callback", HFILL }},
		{ &hf_ypserv_key, {
			"Key", "ypserv.key", FT_STRING, BASE_DEC,
			NULL, 0, "Key", HFILL }},
		{ &hf_ypserv_value, {
			"Value", "ypserv.value", FT_STRING, BASE_DEC,
			NULL, 0, "Value", HFILL }},
		{ &hf_ypserv_status, {
			"Status", "ypserv.status", FT_INT32, BASE_DEC,
			VALS(ypstat) , 0, "Status", HFILL }},
		{ &hf_ypserv_map_parms, {
			"YP Map Parameters", "ypserv.map_parms", FT_NONE, BASE_DEC,
			NULL, 0, "YP Map Parameters", HFILL }},
		{ &hf_ypserv_xfrstat, {
			"Xfrstat", "ypserv.xfrstat", FT_INT32, BASE_DEC,
			VALS(xfrstat), 0, "Xfrstat", HFILL }},
	};
	static gint *ett[] = {
		&ett_ypserv,
		&ett_ypserv_map_parms,
	};

	proto_ypserv = proto_register_protocol("Yellow Pages Service",
	    "YPSERV", "ypserv");
	proto_register_field_array(proto_ypserv, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ypserv(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_ypserv, YPSERV_PROGRAM, ett_ypserv);
	/* Register the procedure tables */
	rpc_init_proc_table(YPSERV_PROGRAM, 1, ypserv1_proc);
	rpc_init_proc_table(YPSERV_PROGRAM, 2, ypserv2_proc);
}
