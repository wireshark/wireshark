/* packet-dcerpc-mapi.c
 * Routines for MS Exchange MAPI
 * Copyright 2002, Ronnie Sahlberg
 *
 * $Id: packet-dcerpc-mapi.c,v 1.2 2002/05/23 12:23:29 sahlberg Exp $
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
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-mapi.h"
#include "smb.h"	/* for "NT_errors[]" */

static int proto_dcerpc_mapi = -1;
static int hf_mapi_unknown_string = -1;
static int hf_mapi_unknown_data = -1;
static int hf_mapi_unknown_short = -1;
static int hf_mapi_hnd = -1;
static int hf_mapi_rc = -1;
static int hf_mapi_encap_datalen = -1;

static gint ett_dcerpc_mapi = -1;

static e_uuid_t uuid_dcerpc_mapi = {
        0xa4f1db00, 0xca47, 0x1067,
        { 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda }
};

static guint16 ver_dcerpc_mapi = 0;

#define DISSECT_UNKNOWN(len) \
	{\
	proto_tree_add_text(tree, tvb, offset, len,\
		"unknown data (%d byte%s)", len,\
		plurality(len, "", "s"));\
	offset += len;\
	}


static int
mapi_logon_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_STRING_string, NDR_POINTER_REF,
			"", hf_mapi_unknown_string, -1);

        DISSECT_UNKNOWN(tvb_length_remaining(tvb, offset));
  
	return offset;
}

/* The strings in this function are decoded properly on seen captures.
There might be offsets/padding mismatched due to potential pointer expansions
or padding bytes. Captures where this code breaks will tell us about that */
static int
mapi_logon_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_mapi_hnd, NULL, FALSE, FALSE);

        DISSECT_UNKNOWN(20); /* this is 20 bytes, unless there are pointers */

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_STRING_string, NDR_POINTER_REF,
			"", hf_mapi_unknown_string, -1);

        DISSECT_UNKNOWN(6); /* possibly 1 or 2 bytes padding here */

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_STRING_string, NDR_POINTER_REF,
			"", hf_mapi_unknown_string, -1);

        DISSECT_UNKNOWN( tvb_length_remaining(tvb, offset)-4 );

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_mapi_rc, NULL);

	return offset;
}

static int
mapi_unknown_02_request(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_mapi_hnd, NULL, FALSE, FALSE);

	/* this is a unidimensional varying and conformant array of
	   encrypted data */  
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_STRING_string, NDR_POINTER_REF,
			"", hf_mapi_unknown_data, -1);

	/* length of encrypted data. */
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_mapi_encap_datalen, NULL);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_mapi_unknown_short, NULL);

	return offset;
}
static int
mapi_unknown_02_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_mapi_hnd, NULL, FALSE, FALSE);

	/* this is a unidimensional varying and conformant array of
	   encrypted data */  
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_STRING_string, NDR_POINTER_REF,
			"", hf_mapi_unknown_data, -1);

	/* length of encrypted data */
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_mapi_encap_datalen, NULL);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_mapi_rc, NULL);

	return offset;
}


static dcerpc_sub_dissector dcerpc_mapi_dissectors[] = {
        { MAPI_LOGON,		"Logon", 
		mapi_logon_rqst,
		mapi_logon_reply },
        { MAPI_LOGOFF,		"Logoff", NULL, NULL },

        { MAPI_UNKNOWN_02,	"unknown_02", 
		mapi_unknown_02_request,
		mapi_unknown_02_reply },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_dcerpc_mapi(void)
{

static hf_register_info hf[] = {
	{ &hf_mapi_hnd,
		{ "Context Handle", "mapi.hnd", FT_BYTES, BASE_NONE, 
		NULL, 0x0, "", HFILL }},

	{ &hf_mapi_rc,
		{ "Return code", "mapi.rc", FT_UINT32, BASE_HEX, 
		VALS (NT_errors), 0x0, "", HFILL }},

	{ &hf_mapi_unknown_string,
		{ "Unknown string", "mapi.unknown_string", FT_STRING, BASE_NONE,
		NULL, 0, "Unknown string. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_mapi_unknown_short,
		{ "Unknown short", "mapi.unknown_short", FT_UINT16, BASE_HEX,
		NULL, 0, "Unknown short. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_mapi_unknown_data,
		{ "unknown encrypted data", "mapi.unknown_data", FT_BYTES, BASE_HEX,
		NULL, 0, "Unknown data. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_mapi_encap_datalen,
		{ "Length", "mapi.encap_len", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Length of encapsulated/encrypted data", HFILL }},


	};

        static gint *ett[] = {
                &ett_dcerpc_mapi,
        };

        proto_dcerpc_mapi = proto_register_protocol(
                "Microsoft Exchange MAPI", "MAPI", "mapi");

        proto_register_field_array(proto_dcerpc_mapi, hf, 
				   array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_mapi(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_mapi, ett_dcerpc_mapi, 
                         &uuid_dcerpc_mapi, ver_dcerpc_mapi, 
                         dcerpc_mapi_dissectors);
}
