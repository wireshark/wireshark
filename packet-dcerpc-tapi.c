/* packet-dcerpc-tapi.c
 * Routines for DCERPC TAPI packet disassembly
 * Copyright 2002, Ronnie Sahlberg
 *
 * $Id: packet-dcerpc-tapi.c,v 1.6 2003/06/26 04:30:30 tpot Exp $
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
/* The IDL file for this interface can be extracted by grepping for idl
 * in capitals.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-tapi.h"
#include "smb.h"

static int proto_dcerpc_tapi = -1;
static int hf_tapi_opnum = -1;
static int hf_tapi_rc = -1;
static int hf_tapi_hnd = -1;
static int hf_tapi_unknown_long = -1;
static int hf_tapi_unknown_string = -1;
static int hf_tapi_unknown_bytes = -1;

static gint ett_dcerpc_tapi = -1;

/*
  IDL [ uuid(2f5f6520-ca46-1067-b319-00dd010662da),
  IDL   version(1.0),
  IDL   implicit_handle(handle_t rpc_binding)
  IDL ] interface tapi
  IDL {
*/
static e_uuid_t uuid_dcerpc_tapi = {
        0x2f5f6520, 0xca46, 0x1067,
        { 0xb3, 0x19, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda }
};

static guint16 ver_dcerpc_tapi = 1;

/*
  IDL   long Function_00(
  IDL         [out] [context_handle] void *element_1,
  IDL         [in] long element_2,
  IDL         [out] long element_3,
  IDL         [in] [string] [ref] wchar_t *element_4,
  IDL         [in] [string] [ref] wchar_t *element_5
  IDL   );
*/
static int
dissect_tapi_UNKNOWN_00_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_tapi_unknown_long, NULL);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "unknown string", 
			 hf_tapi_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "unknown string", 
			 hf_tapi_unknown_string, 0);

	return offset;
}
static int
dissect_tapi_UNKNOWN_00_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ctx_hnd(tvb, offset, pinfo, tree, drep,
			hf_tapi_hnd, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_tapi_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_tapi_rc, NULL);

	return offset;
}

/*
  IDL   long Function_01(
  IDL         [in] [context_handle] void *element_6,
  IDL     [in,out] [size_is(element_8)] [length_is(???)] char element_7[*],
  IDL         [in] long element_8
  IDL   );
*/
static int
dissect_tapi_TYPE_1(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make ethereal eat the array header for the conformant run */
		offset =dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}

	proto_tree_add_item(tree, hf_tapi_unknown_bytes, tvb, offset,
		di->array_actual_count, FALSE);
	offset += di->array_actual_count;

	return offset;
}

static int
dissect_tapi_UNKNOWN_01_rqst(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ctx_hnd(tvb, offset, pinfo, tree, drep,
			hf_tapi_hnd, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_tapi_TYPE_1, NDR_POINTER_REF,
			"unknown array", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_tapi_unknown_long, NULL);

	return offset;
}
static int
dissect_tapi_UNKNOWN_01_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_tapi_rc, NULL);

	return offset;
}


/*
  IDL   void Function_02(
  IDL         void
  IDL   );
*/
static int
dissect_tapi_UNKNOWN_02_rqst(tvbuff_t *tvb _U_, int offset _U_,
			packet_info *pinfo _U_, proto_tree *tree _U_,
			char *drep _U_)
{
	return offset;
}
static int
dissect_tapi_UNKNOWN_02_reply(tvbuff_t *tvb _U_, int offset _U_,
			packet_info *pinfo _U_, proto_tree *tree _U_,
			char *drep _U_)
{
	return offset;
}

/*
  IDL }
*/
static dcerpc_sub_dissector dcerpc_tapi_dissectors[] = {
        { TAPI_UNKNOWN_00, "TAPI_UNKNOWN_00",
		dissect_tapi_UNKNOWN_00_rqst,
		dissect_tapi_UNKNOWN_00_reply },
        { TAPI_UNKNOWN_01, "TAPI_UNKNOWN_01",
		dissect_tapi_UNKNOWN_01_rqst,
		dissect_tapi_UNKNOWN_01_reply },
        { TAPI_UNKNOWN_02, "TAPI_UNKNOWN_02",
		dissect_tapi_UNKNOWN_02_rqst,
		dissect_tapi_UNKNOWN_02_reply },

        {0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_tapi(void)
{
static hf_register_info hf[] = {
	{ &hf_tapi_opnum, { 
		"Operation", "tapi.opnum", FT_UINT16, BASE_DEC,
		NULL, 0x0, "", HFILL }},
	{ &hf_tapi_rc, {
		"Return code", "tapi.rc", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0x0, "TAPI return code", HFILL }},
	{ &hf_tapi_hnd, {
		"Context Handle", "tapi.hnd", FT_BYTES, BASE_NONE,
		NULL, 0x0, "Context handle", HFILL }},
	{ &hf_tapi_unknown_long, {
		"Unknown long", "tapi.unknown.long", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Unknown long. If you know what this is, contact ethereal developers.", HFILL }},
	{ &hf_tapi_unknown_string, {
		"Unknown string", "tapi.unknown.string", FT_STRING, BASE_HEX,
		NULL, 0x0, "Unknown string. If you know what this is, contact ethereal developers.", HFILL }},
	{ &hf_tapi_unknown_bytes, {
		"Unknown bytes", "tapi.unknown.bytes", FT_BYTES, BASE_HEX,
		NULL, 0x0, "Unknown bytes. If you know what this is, contact ethereal developers.", HFILL }}
	};

        static gint *ett[] = {
                &ett_dcerpc_tapi
        };

        proto_dcerpc_tapi = proto_register_protocol(
                "Microsoft Telephony API Service", "TAPI", "tapi");

        proto_register_field_array(proto_dcerpc_tapi, hf,
				   array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_tapi(void)
{
	header_field_info *hf_info;

        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_tapi, ett_dcerpc_tapi,
                         &uuid_dcerpc_tapi, ver_dcerpc_tapi,
                         dcerpc_tapi_dissectors, hf_tapi_opnum);

	/* Set opnum strings from subdissector list */

	hf_info = proto_registrar_get_nth(hf_tapi_opnum);
	hf_info->strings = value_string_from_subdissectors(
		dcerpc_tapi_dissectors, array_length(dcerpc_tapi_dissectors));
}
