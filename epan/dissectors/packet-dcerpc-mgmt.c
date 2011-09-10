/* packet-dcerpc-mgmt.c
 * Routines for dcerpc mgmt dissection
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 * Copyright 2011, Matthieu Patou <mat@matws.net>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"


static int proto_mgmt = -1;
static int hf_mgmt_opnum = -1;
static int hf_mgmt_proto = -1;
static int hf_mgmt_rc = -1;
static int hf_mgmt_princ_size = -1;
static int hf_mgmt_princ_name = -1;
static gint ett_mgmt = -1;


static e_uuid_t uuid_mgmt = { 0xafa8bd80, 0x7d8a, 0x11c9, { 0xbe, 0xf4, 0x08, 0x00, 0x2b, 0x10, 0x29, 0x89 } };
static guint16  ver_mgmt = 1;

static int
mgmtrpc_dissect_inq_princ_name_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep,
					sizeof(guint8), hf_mgmt_princ_name, TRUE, NULL);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, hf_mgmt_rc, NULL);


	return offset;
}
static int
mgmtrpc_dissect_inq_princ_name_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_mgmt_proto, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_mgmt_princ_size, NULL);
	return offset;
}



static dcerpc_sub_dissector mgmt_dissectors[] = {
	{ 0, "rpc__mgmt_inq_if_ids", NULL, NULL },
	{ 1, "rpc__mgmt_inq_stats", NULL, NULL },
	{ 2, "rpc__mgmt_is_server_listening", NULL, NULL },
	{ 3, "rpc__mgmt_stop_server_listening", NULL, NULL },
	{ 4, "rpc__mgmt_inq_princ_name", mgmtrpc_dissect_inq_princ_name_request, mgmtrpc_dissect_inq_princ_name_response},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_mgmt (void)
{
	static hf_register_info hf[] = {
		{ &hf_mgmt_opnum,
		  { "Operation", "mgmt.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_mgmt_proto,
		  {"Authn Proto", "mgmt.proto", FT_UINT32, BASE_HEX,
                    NULL, 0x0, "Authn Proto", HFILL }},
		{ &hf_mgmt_princ_name,
		  {"Principal name", "mgmt.princ_name", FT_STRING, BASE_NONE,
                    NULL, 0, "Principal name", HFILL }},
		{ &hf_mgmt_princ_size,
		  {"Principal size", "mgmt.princ_size", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "Size of principal", HFILL }},
		{ &hf_mgmt_rc,
		  {"Status", "mgmt.rc", FT_UINT32, BASE_HEX,
                    NULL, 0x0, "Status", HFILL }},
	};

	static gint *ett[] = {
		&ett_mgmt
	};
	proto_mgmt = proto_register_protocol ("DCE/RPC Remote Management", "MGMT", "mgmt");
	proto_register_field_array (proto_mgmt, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_mgmt (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_mgmt, ett_mgmt, &uuid_mgmt, ver_mgmt, mgmt_dissectors, hf_mgmt_opnum);
}
