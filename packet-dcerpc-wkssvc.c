/* packet-dcerpc-wkssvc.c
 * Routines for SMB \\PIPE\\wkssvc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 * Copyright 2003, Richard Sharpe <rsharpe@richardsharpe.com>
 *
 * $Id: packet-dcerpc-wkssvc.c,v 1.6 2003/04/26 00:00:30 sharpe Exp $
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

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-wkssvc.h"

static int proto_dcerpc_wkssvc = -1;
static int hf_wkssvc_server = -1;
static int hf_wkssvc_info_level = -1;
static gint ett_dcerpc_wkssvc = -1;

static e_uuid_t uuid_dcerpc_wkssvc = {
        0x6bffd098, 0xa112, 0x3610,
        { 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a }
};

static guint16 ver_dcerpc_wkssvc = 1;

/*
 * IDL long NetrQueryInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long level,
 * IDL      [out] [ref] WKS_INFO_UNION *wks
 * IDL );
 */
static int
wkssvc_dissect_netrqueryinfo_rqst(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo, proto_tree *tree,
				  char *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "Server", 
					      hf_wkssvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_info_level, 0);

	return offset;

}

static int wkssvc_dissect_netrqueryinfo_reply(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      char *drep)
{

  return offset;
}

static dcerpc_sub_dissector dcerpc_wkssvc_dissectors[] = {
        { WKS_QUERY_INFO, "WKS_QUERY_INFO", 
	  wkssvc_dissect_netrqueryinfo_rqst, 
	  wkssvc_dissect_netrqueryinfo_reply},

        {0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_wkssvc(void)
{
        static hf_register_info hf[] = { 
	  { &hf_wkssvc_server,
	    { "Server", "wkssvc.server", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Server Name", HFILL}},
	  { &hf_wkssvc_info_level,
	    { "Info Level", "svrsvc.info_level", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Info Level", HFILL}},
	};
        static gint *ett[] = {
                &ett_dcerpc_wkssvc
        };

        proto_dcerpc_wkssvc = proto_register_protocol(
                "Microsoft Workstation Service", "WKSSVC", "wkssvc");

	proto_register_field_array(proto_dcerpc_wkssvc, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_wkssvc(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_wkssvc, ett_dcerpc_wkssvc,
                         &uuid_dcerpc_wkssvc, ver_dcerpc_wkssvc,
                         dcerpc_wkssvc_dissectors, -1);
}
