/* packet-dcom-remact.c
 * Routines for DCOM Remote Activation
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* see packet-dcom.c for details about DCOM */

#include "config.h"

#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcom.h"


void proto_register_remact(void);
void proto_reg_handoff_remact(void);

static int hf_remact_opnum;

static int hf_remact_requested_protseqs;
static int hf_remact_protseqs;
static int hf_remact_interfaces;
static int hf_remact_mode;
static int hf_remact_client_impl_level;
static int hf_remact_object_name;
static int hf_remact_object_storage;
static int hf_remact_interface_data;

static int hf_remact_oxid_bindings;
static int hf_remact_authn_hint;


static int proto_remact;
static int ett_remact;
static e_guid_t uuid_remact = { 0x4d9f4ab8, 0x7d1c, 0x11cf, { 0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57 } };
static uint16_t ver_remact;


static int
dissect_remact_remote_activation_rqst(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep)
{
	uint32_t u32ClientImpLevel;
	uint32_t u32Mode;
	uint32_t u32Interfaces;
	uint32_t u32Pointer;
	uint32_t u32ArraySize;
	uint32_t u32ItemIdx;
	uint16_t u16ProtSeqs;
	e_guid_t clsid;
	e_guid_t iid;

	char 	szObjName[1000] = { 0 };
	uint32_t u32ObjNameLen = sizeof(szObjName);

	offset = dissect_dcom_this(tvb, offset, pinfo, tree, di, drep);

	offset = dissect_dcom_append_UUID(tvb, offset, pinfo, tree, di, drep,
					  hf_dcom_clsid, -1, &clsid);

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, di, drep,
					     &u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_BSTR(tvb, offset, pinfo, tree, di, drep,
					   hf_remact_object_name, szObjName, u32ObjNameLen);
	}

	offset = dissect_dcom_PMInterfacePointer(tvb, offset, pinfo, tree, di, drep,
						 hf_remact_object_storage, NULL /* XXX */);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
				    hf_remact_client_impl_level, &u32ClientImpLevel);
	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
				    hf_remact_mode, &u32Mode);

	/* Interfaces */
	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
				    hf_remact_interfaces, &u32Interfaces);
	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, di, drep,
					     &u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, di, drep,
							&u32ArraySize);
		u32ItemIdx = 1;
		while (u32Interfaces--) {
			offset = dissect_dcom_append_UUID(tvb, offset, pinfo, tree, di, drep,
							  hf_dcom_iid, u32ItemIdx, &iid);

			u32ItemIdx++;
		}
	}

	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, di, drep,
				   hf_remact_requested_protseqs, &u16ProtSeqs);

	offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, di, drep,
						&u32ArraySize);
	u32ItemIdx = 1;
	while (u32ArraySize--) {
		offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, di, drep,
					   hf_remact_protseqs, &u16ProtSeqs);
		u32ItemIdx++;
	}

	return offset;
}


static int
dissect_remact_remote_activation_resp(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep)
{
	uint32_t	u32Pointer;
	e_guid_t ipid;
	uint32_t	u32AuthnHint;
	uint16_t	u16VersionMajor;
	uint16_t	u16VersionMinor;
	uint32_t	u32HResult;
	uint32_t u32ArraySize;
	uint32_t u32Idx;
	uint32_t	u32VariableOffset;


	offset = dissect_dcom_that(tvb, offset, pinfo, tree, di, drep);

	offset = dissect_dcom_ID(tvb, offset, pinfo, tree, di, drep,
				 hf_dcom_oxid, NULL);
	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, di, drep,
					     &u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, di, drep,
							&u32ArraySize);
		offset = dissect_dcom_DUALSTRINGARRAY(tvb, offset, pinfo, tree, di, drep,
						      hf_remact_oxid_bindings, NULL);
	}

	offset = dissect_dcom_UUID(tvb, offset, pinfo, tree, di, drep,
				   hf_dcom_ipid, &ipid);
	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
				    hf_remact_authn_hint, &u32AuthnHint);
	offset = dissect_dcom_COMVERSION(tvb, offset, pinfo, tree, di, drep,
					 &u16VersionMajor, &u16VersionMinor);

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, di, drep,
				      &u32HResult);

	offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, di, drep,
						&u32ArraySize);
	u32VariableOffset = offset + u32ArraySize * 4;
	while (u32ArraySize--) {
		offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, di, drep,
						     &u32Pointer);
		if (u32Pointer) {
			u32VariableOffset = dissect_dcom_MInterfacePointer(tvb, u32VariableOffset, pinfo, tree, di, drep,
									   hf_remact_interface_data, NULL /* XXX */);
		}
	}
	offset = u32VariableOffset;

	offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, di, drep,
						&u32ArraySize);
	u32Idx = 1;
	while (u32ArraySize--) {
		offset = dissect_dcom_indexed_HRESULT(tvb, offset, pinfo, tree, di, drep,
						      &u32HResult, u32Idx);
		/* update column info now */
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s[%u]",
				val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)"),
				u32Idx);
		u32Idx++;
	}

	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, di, drep,
				      &u32HResult);

	/* update column info now */
	col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
			val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)"));

	return offset;
}


static const dcerpc_sub_dissector remact_dissectors[] = {
	{ 0, "RemoteActivation", dissect_remact_remote_activation_rqst, dissect_remact_remote_activation_resp },
	{ 0, NULL, NULL, NULL },
};


void
proto_register_remact (void)
{
	static hf_register_info hf_remact[] = {
		{ &hf_remact_opnum,
		  { "Operation", "remact.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_remact_requested_protseqs,
		  { "RequestedProtSeqs", "remact.req_prot_seqs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_remact_protseqs,
		  { "ProtSeqs", "remact.prot_seqs", FT_UINT16, BASE_DEC, VALS(dcom_protseq_vals), 0x0, NULL, HFILL }},
		{ &hf_remact_interfaces,
		  { "Interfaces", "remact.interfaces", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_remact_mode,
		  { "Mode", "remact.mode", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_remact_client_impl_level,
		  { "ClientImplLevel", "remact.client_impl_level", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_remact_object_name,
		  { "ObjectName", "remact.object_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_remact_object_storage,
		  { "ObjectStorage", "remact.object_storage", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_remact_interface_data,
		  { "InterfaceData", "remact.interface_data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_remact_oxid_bindings,
		  { "OxidBindings", "remact.oxid_bindings", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_remact_authn_hint,
		  { "AuthnHint", "remact.authn_hint", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_remact
	};

	proto_remact = proto_register_protocol ("DCOM IRemoteActivation", "REMACT", "remact");
	proto_register_field_array (proto_remact, hf_remact, array_length (hf_remact));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_remact (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_remact, ett_remact, &uuid_remact, ver_remact, remact_dissectors, hf_remact_opnum);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
