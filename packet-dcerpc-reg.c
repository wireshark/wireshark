/* packet-dcerpc-reg.c
 * Routines for SMB \PIPE\winreg packet disassembly
 * Copyright 2001-2003 Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-reg.c,v 1.14 2003/01/30 08:19:38 guy Exp $
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
#include "packet-dcerpc-reg.h"
#include "smb.h"

/* Global hf index fields */

static int hf_rc = -1;
static int hf_hnd = -1;
static int hf_access_mask = -1;

/* OpenHKLM */

static int hf_openhklm_unknown1 = -1;
static int hf_openhklm_unknown2 = -1;

/* QueryKey */

static int hf_querykey_class = -1;
static int hf_querykey_num_subkeys = -1;
static int hf_querykey_max_subkey_len = -1;
static int hf_querykey_reserved = -1;
static int hf_querykey_num_values = -1;
static int hf_querykey_max_valname_len = -1;
static int hf_querykey_max_valbuf_size = -1;
static int hf_querykey_secdesc = -1;
static int hf_querykey_modtime = -1;

/* OpenEntry */

static int hf_keyname = -1;
static int hf_openentry_unknown1 = -1;

/* Unknown 0x1A */

static int hf_unknown1A_unknown1 = -1;

/* Data that is passed to a open call */

static int
dissect_open_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
		  proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, drep,
		hf_openhklm_unknown1, NULL);

	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, drep,
		hf_openhklm_unknown1, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_access_mask, NULL);

	return offset;
}

/*
 * OpenHKLM
 */

static int
RegOpenHKLM_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
	      proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_open_data,
		NDR_POINTER_UNIQUE, "Unknown", -1);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int
RegOpenHKLM_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
	      proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep,
		hf_hnd, &policy_hnd, TRUE, FALSE);

	dcerpc_smb_store_pol_name(&policy_hnd, "HKLM handle");

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * OpenHKU
 */

static int
RegOpenHKU_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
	     proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_open_data,
		NDR_POINTER_UNIQUE, "Unknown", -1);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int
RegOpenHKU_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
	     proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep,
		hf_hnd, &policy_hnd, TRUE, FALSE);

	dcerpc_smb_store_pol_name(&policy_hnd, "HKU handle");

	offset = dissect_ntstatus(
		tvb, offset, pinfo, tree, drep, hf_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * OpenHKCR
 */

static int
RegOpenHKCR_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
	      proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_open_data,
		NDR_POINTER_UNIQUE, "Unknown", -1);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int
RegOpenHKCR_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
	      proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep,
		hf_hnd, &policy_hnd, TRUE, FALSE);

	dcerpc_smb_store_pol_name(&policy_hnd, "HKCR handle");

	offset = dissect_ntstatus(
		tvb, offset, pinfo, tree, drep, hf_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * RegClose
 */

static int
RegClose_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
	   proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep,
		hf_hnd, NULL, FALSE, TRUE);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int
RegClose_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
	   proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep,
		hf_hnd, NULL, FALSE, FALSE);

	offset = dissect_ntstatus(
		tvb, offset, pinfo, tree, drep, hf_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * RegQueryKey
 */

static int
RegQueryKey_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
	      proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep,
		hf_hnd, NULL, FALSE, FALSE);

	offset = dissect_ndr_nt_UNICODE_STRING(
		tvb, offset, pinfo, tree, drep, hf_querykey_class, 0);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int
RegQueryKey_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
	      proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_ndr_nt_UNICODE_STRING(
		tvb, offset, pinfo, tree, drep, hf_querykey_class, 0);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_querykey_num_subkeys, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_querykey_max_subkey_len, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_querykey_reserved, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_querykey_num_values, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_querykey_max_valname_len, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_querykey_max_valbuf_size, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_querykey_secdesc, NULL);

	offset = dissect_ndr_nt_NTTIME(
		tvb, offset, pinfo, tree, drep, hf_querykey_modtime);

	offset = dissect_ntstatus(
		tvb, offset, pinfo, tree, drep, hf_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * OpenEntry
 */

static int
RegOpenEntry_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep,
		hf_hnd, NULL, FALSE, FALSE);

	offset = dissect_ndr_nt_UNICODE_STRING(
		tvb, offset, pinfo, tree, drep, hf_querykey_class, 0);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_openentry_unknown1, NULL);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_access_mask, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int
RegOpenEntry_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep,
		hf_hnd, &policy_hnd, TRUE, FALSE);

	dcerpc_smb_store_pol_name(&policy_hnd, "OpenEntry handle");

	offset = dissect_ntstatus(
		tvb, offset, pinfo, tree, drep, hf_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * Unknown1A
 */

static int
RegUnknown1A_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep,
		hf_hnd, NULL, FALSE, FALSE);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int
RegUnknown1A_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep,
		hf_unknown1A_unknown1, NULL);

	offset = dissect_ntstatus(
		tvb, offset, pinfo, tree, drep, hf_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

/*
 * EnumKey
 */

static int
RegEnumKey_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
	     proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep,
		hf_hnd, NULL, FALSE, FALSE);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int
RegEnumKey_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
	     proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_ntstatus(
		tvb, offset, pinfo, tree, drep, hf_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

#if 0

/* Templates for new subdissectors */

/*
 * FOO
 */

static int
RegFoo_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
	 proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->rep_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Reply in frame %u", dcv->rep_frame);

	/* Parse packet */

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

static int
RegFoo_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
	 proto_tree *tree, char *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (dcv->req_frame != 0)
		proto_tree_add_text(tree, tvb, offset, 0,
				    "Request in frame %u", dcv->req_frame);

	/* Parse packet */

	offset = dissect_ntstatus(
		tvb, offset, pinfo, tree, drep, hf_rc, NULL);

	dcerpc_smb_check_long_frame(tvb, offset, pinfo, tree);

	return offset;
}

#endif

/* Registry data types */

const value_string reg_datatypes[] = {
	{ DCERPC_REG_NONE, "REG_NONE" },
	{ DCERPC_REG_SZ, "REG_SZ" },
	{ DCERPC_REG_EXPAND_SZ, "REG_EXPAND_SZ" },
	{ DCERPC_REG_BINARY, "REG_BINARY" },
	{ DCERPC_REG_DWORD, "REG_DWORD" },
	{ DCERPC_REG_DWORD_LE, "REG_DWORD_LE" },
	{ DCERPC_REG_DWORD_BE, "REG_DWORD_BE" },
	{ DCERPC_REG_LINK, "REG_LINK" },
	{ DCERPC_REG_MULTI_SZ, "REG_MULTI_SZ" },
	{ DCERPC_REG_RESOURCE_LIST, "REG_RESOURCE_LIST" },
	{ DCERPC_REG_FULL_RESOURCE_DESCRIPTOR, "REG_FULL_RESOURCE_DESCRIPTOR" },
	{ DCERPC_REG_RESOURCE_REQUIREMENTS_LIST, "REG_RESOURCE_REQUIREMENTS_LIST" },
	{0, NULL }
};

static int proto_dcerpc_reg = -1;
static int hf_reg_opnum = -1;
static gint ett_dcerpc_reg = -1;

static e_uuid_t uuid_dcerpc_reg = {
        0x338cd001, 0x2244, 0x31f1,
        { 0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03 }
};

static guint16 ver_dcerpc_reg = 1;

static dcerpc_sub_dissector dcerpc_reg_dissectors[] = {
        { REG_OPEN_HKCR, "OpenHKCR", RegOpenHKCR_q, RegOpenHKCR_r },
        { _REG_UNK_01, "Unknown01", NULL, NULL },
        { REG_OPEN_HKLM, "OpenHKLM", RegOpenHKLM_q, RegOpenHKLM_r },
        { _REG_UNK_03, "Unknown03", NULL, NULL },
        { REG_OPEN_HKU, "OpenHKU", RegOpenHKU_q, RegOpenHKU_r },
        { REG_CLOSE, "Close", RegClose_q, RegClose_r },
        { REG_CREATE_KEY, "CreateKey", NULL, NULL },
        { REG_DELETE_KEY, "DeleteKey", NULL, NULL },
        { REG_DELETE_VALUE, "DeleteValue", NULL, NULL },
        { REG_ENUM_KEY, "EnumKey", RegEnumKey_q, RegEnumKey_r },
        { REG_ENUM_VALUE, "EnumValue", NULL, NULL },
        { REG_FLUSH_KEY, "FlushKey", NULL, NULL },
        { REG_GET_KEY_SEC, "GetKeySecurity", NULL, NULL },
        { _REG_UNK_0D, "Unknown0d", NULL, NULL },
        { _REG_UNK_0E, "Unknown0e", NULL, NULL },
        { REG_OPEN_ENTRY, "OpenEntry", RegOpenEntry_q, RegOpenEntry_r },
        { REG_QUERY_KEY, "QueryKey", RegQueryKey_q, RegQueryKey_r },
        { REG_INFO, "Info", NULL, NULL },
        { _REG_UNK_12, "Unknown12", NULL, NULL },
        { _REG_UNK_13, "Unknown13", NULL, NULL },
        { _REG_UNK_14, "Unknown14", NULL, NULL },
        { REG_SET_KEY_SEC, "SetKeySecurity", NULL, NULL },
        { REG_CREATE_VALUE, "CreateValue", NULL, NULL },
        { _REG_UNK_17, "Unknown17", NULL, NULL },
        { REG_SHUTDOWN, "Shutdown", NULL, NULL },
        { REG_ABORT_SHUTDOWN, "AbortShutdown", NULL, NULL },
        { _REG_UNK_1A, "Unknown1A", RegUnknown1A_q, RegUnknown1A_r },

        { 0, NULL, NULL,  NULL }
};

static const value_string reg_opnum_vals[] = {
        { REG_OPEN_HKCR, "OpenHKCR" },
        { _REG_UNK_01, "Unknown01" },
        { REG_OPEN_HKLM, "OpenHKLM" },
        { _REG_UNK_03, "Unknown03" },
        { REG_OPEN_HKU, "OpenHKU" },
        { REG_CLOSE, "Close" },
        { REG_CREATE_KEY, "CreateKey" },
        { REG_DELETE_KEY, "DeleteKey" },
        { REG_DELETE_VALUE, "DeleteValue" },
        { REG_ENUM_KEY, "EnumKey" },
        { REG_ENUM_VALUE, "EnumValue" },
        { REG_FLUSH_KEY, "FlushKey" },
        { REG_GET_KEY_SEC, "GetKeySecurity" },
        { _REG_UNK_0D, "Unknown0d" },
        { _REG_UNK_0E, "Unknown0e" },
        { REG_OPEN_ENTRY, "OpenEntry" },
        { REG_QUERY_KEY, "QueryKey" },
        { REG_INFO, "Info" },
        { _REG_UNK_12, "Unknown12" },
        { _REG_UNK_13, "Unknown13" },
        { _REG_UNK_14, "Unknown14" },
        { REG_SET_KEY_SEC, "SetKeySecurity" },
        { REG_CREATE_VALUE, "CreateValue" },
        { _REG_UNK_17, "Unknown17" },
        { REG_SHUTDOWN, "Shutdown" },
        { REG_ABORT_SHUTDOWN, "AbortShutdown" },
        { _REG_UNK_1A, "Unknown1A" },
	{ 0, NULL }
};

void
proto_register_dcerpc_reg(void)
{
	static hf_register_info hf[] = {

		/* Global indexes */

		{ &hf_hnd,
		  { "Context handle", "reg.hnd", FT_BYTES, BASE_NONE,
		    NULL, 0x0, "REG policy handle", HFILL }},

		{ &hf_rc,
		  { "Return code", "reg.rc", FT_UINT32, BASE_HEX,
		    VALS(NT_errors), 0x0, "REG return code", HFILL }},

		{ &hf_reg_opnum,
		  { "Operation", "reg.opnum", FT_UINT16, BASE_DEC,
		    VALS(reg_opnum_vals), 0x0, "Operation", HFILL }},

		{ &hf_access_mask,
		  { "Access mask", "reg.access_mask", FT_UINT32, BASE_HEX,
		    NULL, 0x0, "Access mask", HFILL }},

		/* OpenHKLM */

		{ &hf_openhklm_unknown1,
		  { "Unknown 1", "reg.openhklm.unknown1", FT_UINT16, BASE_HEX,
		    NULL, 0x0, "Unknown 1", HFILL }},

		{ &hf_openhklm_unknown2,
		  { "Unknown 2", "reg.openhklm.unknown2", FT_UINT16, BASE_HEX,
		    NULL, 0x0, "Unknown 2", HFILL }},

		/* QueryClass */

		{ &hf_querykey_class,
		  { "Class", "reg.querykey.class", FT_STRING, BASE_NONE,
		    NULL, 0, "Class", HFILL }},

		{ &hf_querykey_num_subkeys,
		  { "Num subkeys", "reg.querykey.num_subkeys", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Num subkeys", HFILL }},

		{ &hf_querykey_max_subkey_len,
		  { "Max subkey len", "reg.querykey.max_subkey_len", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Max subkey len", HFILL }},

		{ &hf_querykey_reserved,
		  { "Reserved", "reg.querykey.reserved", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Reserved", HFILL }},

		{ &hf_querykey_num_values,
		  { "Num values", "reg.querykey.num_values", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Num values", HFILL }},

		{ &hf_querykey_max_valname_len,
		  { "Max valnum len", "reg.querykey.max_valname_len", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Max valname len", HFILL }},

		{ &hf_querykey_max_valbuf_size,
		  { "Max valbuf size", "reg.querykey.max_valbuf_size", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Max valbuf size", HFILL }},

		{ &hf_querykey_secdesc,
		  { "Secdesc", "reg.querykey.secdesc", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Secdesc", HFILL }},

		{ &hf_querykey_modtime,
		  { "Mod time", "reg.querykey.modtime", FT_ABSOLUTE_TIME, BASE_NONE,
		    NULL, 0x0, "Secdesc", HFILL }},

		/* OpenEntry */

		{ &hf_keyname,
		  { "Key name", "reg.keyname", FT_STRING, BASE_NONE,
		    NULL, 0x0, "Keyname", HFILL }},

		{ &hf_openentry_unknown1,
		  { "Unknown 1", "reg.openentry.unknown1", FT_UINT32, BASE_HEX,
		    NULL, 0x0, "Unknown 1", HFILL }},

		/* Unknown1A */

		{ &hf_unknown1A_unknown1,
		  { "Unknown 1", "reg.unknown1A.unknown1", FT_UINT32, BASE_HEX,
		    NULL, 0x0, "Unknown 1", HFILL }},

	};

        static gint *ett[] = {
                &ett_dcerpc_reg
        };

        proto_dcerpc_reg = proto_register_protocol(
                "Microsoft Registry", "WINREG", "winreg");

	proto_register_field_array(proto_dcerpc_reg, hf, array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_reg(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_reg, ett_dcerpc_reg, &uuid_dcerpc_reg,
                         ver_dcerpc_reg, dcerpc_reg_dissectors, hf_reg_opnum);
}
