/* packet-dcom-dispatch.c
 * Routines for DCOM IDispatch
 *
 * $Id$
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

/* see packet-dcom.c for details about DCOM */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcom.h"


static int hf_dispatch_opnum = -1;

static int hf_dispatch_riid = -1;
static int hf_dispatch_name = -1;
static int hf_dispatch_names = -1;
static int hf_dispatch_lcid = -1;
static int hf_dispatch_id = -1;
static int hf_dispatch_flags2 = -1;

static int hf_dispatch_arg = -1;
static int hf_dispatch_args = -1;
static int hf_dispatch_named_args = -1;
static int hf_dispatch_varref = -1;
static int hf_dispatch_varrefidx = -1;
static int hf_dispatch_varrefarg = -1;

static int hf_dispatch_varresult = -1;

static gint ett_dispatch_flags = -1;
static int hf_dispatch_flags = -1;
static int hf_dispatch_flags_method = -1;
static int hf_dispatch_flags_propget = -1;
static int hf_dispatch_flags_propput = -1;
static int hf_dispatch_flags_propputref = -1;

#define DISPATCH_FLAGS_METHOD		1
#define DISPATCH_FLAGS_PROPGET		2
#define DISPATCH_FLAGS_PROPPUT		4
#define DISPATCH_FLAGS_PROPPUTREF	8


static e_uuid_t uuid_dispatch = { 0x00020400, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static guint16  ver_dispatch = 0;
static gint ett_dispatch = -1;
static int proto_dispatch = -1;



static int
dissect_IDispatch_GetIDsOfNames_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	e_uuid_t riid;
	guint32 u32Lcid;
	gchar 	szName[1000] = { 0 };
	guint32 u32MaxNameLen = sizeof(szName);
	guint32	u32Names;
	guint32	u32ArraySize;
	guint32	u32Pointer;
	guint32	u32Tmp;
	guint32 u32VariableOffset;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_UUID(tvb, offset, pinfo, tree, drep, 
						hf_dispatch_riid, &riid);

	offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep, 
						&u32ArraySize);

	u32VariableOffset = offset + u32ArraySize * 4;

	u32Tmp = u32ArraySize;
	while(u32Tmp--) {
		offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
					&u32Pointer);
		if (u32Pointer) {
			u32VariableOffset = dissect_dcom_LPWSTR(tvb, u32VariableOffset, pinfo, tree, drep, 
							hf_dispatch_name, szName, u32MaxNameLen);
			if (check_col(pinfo->cinfo, COL_INFO)) {
			  col_append_fstr(pinfo->cinfo, COL_INFO, " \"%s\"", szName);
			}
		}
	}

	offset = u32VariableOffset;

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_dispatch_names, &u32Names);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
						hf_dispatch_lcid, &u32Lcid);

	return offset;
}



static int
dissect_IDispatch_GetIDsOfNames_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32DispId;
	guint32 u32ArraySize;
	guint32 u32Tmp;
	guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep, 
						&u32ArraySize);

	u32Tmp = u32ArraySize;
	while (u32Tmp--) {
		offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                        hf_dispatch_id, &u32DispId);
		if (check_col(pinfo->cinfo, COL_INFO)) {
		  col_append_fstr(pinfo->cinfo, COL_INFO, " ID=0x%08x", u32DispId);
		}
	}

	/* HRESULT of call */
	offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep, 
                        &u32HResult);

	if (check_col(pinfo->cinfo, COL_INFO)) {
	  col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", 
	  val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
	}

	return offset;
}



static int
dissect_IDispatch_Invoke_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32DispIdMember;
	e_uuid_t riid;
	guint32 u32Lcid;
	guint16 u16Flags;
	guint16 u16Flags2;
	guint32 u32Args;
	guint32 u32NamedArgs;
	guint32 u32Pointer;
	guint32 u32ArraySize;
	guint32 u32VariableOffset;
	guint32 u32VarRef;
	guint32 u32VarRefIdx;
	guint32 u32TmpOffset;

	proto_item *feature_item;
	proto_tree *feature_tree;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                    hf_dispatch_id, &u32DispIdMember);
	offset = dissect_dcom_UUID(tvb, offset, pinfo, tree, drep, 
					hf_dispatch_riid, &riid);
	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
					hf_dispatch_lcid, &u32Lcid);
	
	/* dispatch flags */
	u32TmpOffset = dissect_dcom_WORD(tvb, offset, pinfo, NULL, drep, 
                        hf_dispatch_flags, &u16Flags);
    feature_item = proto_tree_add_uint (tree, hf_dispatch_flags, tvb, offset, 2, u16Flags);
    feature_tree = proto_item_add_subtree (feature_item, ett_dispatch_flags);
    if (feature_tree) {
        proto_tree_add_boolean (feature_tree, hf_dispatch_flags_propputref, tvb, offset, 2, u16Flags);
        proto_tree_add_boolean (feature_tree, hf_dispatch_flags_propput, tvb, offset, 2, u16Flags);
        proto_tree_add_boolean (feature_tree, hf_dispatch_flags_propget, tvb, offset, 2, u16Flags);
        proto_tree_add_boolean (feature_tree, hf_dispatch_flags_method, tvb, offset, 2, u16Flags);
    }

	if (u16Flags & DISPATCH_FLAGS_METHOD) {
		proto_item_append_text(feature_item, ", Method");
	}
	if (u16Flags & DISPATCH_FLAGS_PROPGET) {
		proto_item_append_text(feature_item, ", PropertyGet");
	}
	if (u16Flags & DISPATCH_FLAGS_PROPPUT) {
		proto_item_append_text(feature_item, ", PropertyPut");
	}
	if (u16Flags & DISPATCH_FLAGS_PROPPUTREF) {
		proto_item_append_text(feature_item, ", PropertyPutRef");
	}

	offset = u32TmpOffset;

	offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep, 
                    hf_dispatch_flags2, &u16Flags2);

	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);

	/* DISPPARAMS */
	/* VARIANT rgvarg[u32Args] */
	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep, 
								&u32ArraySize);
		u32VariableOffset = offset + u32ArraySize * 4;
		while(u32ArraySize--) {
			offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
								&u32Pointer);
			if (u32Pointer) {
				u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, tree, drep, hf_dispatch_arg);
			}
		}
		offset = u32VariableOffset;
	}

	/* DISPID rgdispidNamedArgs[u32NamedArgs] */
	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep, 
								&u32ArraySize);
		u32VariableOffset = offset + u32ArraySize * 4;
		while(u32ArraySize--) {
			u32VariableOffset = dissect_dcom_dcerpc_pointer(tvb, u32VariableOffset, pinfo, tree, drep, 
									&u32Pointer);
			if (u32Pointer) {
				offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
						hf_dispatch_id, &u32DispIdMember);
			}
		}
		offset = u32VariableOffset;
	}

	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                    hf_dispatch_args, &u32Args);
	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                    hf_dispatch_named_args, &u32NamedArgs);

	/* end of DISPPARAMS */
/*	offset = u32VariableOffset; */



	/* u32VarRef */
	offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                    hf_dispatch_varref, &u32VarRef);

	/* rgVarRefIdx: UINT[u32VarRef] */
	offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep, 
							&u32ArraySize);
	while(u32ArraySize--) {
		offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep, 
                    hf_dispatch_varrefidx, &u32VarRefIdx);
	}

	/* rgVarRef: VARIANT[u32VarRef] */
	offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep, 
							&u32ArraySize);
	u32VariableOffset = offset + u32ArraySize * 4;
	while(u32ArraySize--) {
		offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
							&u32Pointer);
		if (u32Pointer) {
			u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, tree, drep, hf_dispatch_varrefarg);
		}
	}

	return u32VariableOffset;
}

#if 0
typedef struct tagEXCEPINFO {
    WORD  wCode;            /* An error code describing the error. */
    WORD  wReserved;
    BSTR  bstrSource;       /* A source of the exception */
    BSTR  bstrDescription;  /* A description of the error */
    BSTR  bstrHelpFile;     /* Fully qualified drive, path, and file name */
    DWORD dwHelpContext;    /* help context of topic within the help file */
    ULONG pvReserved;
    ULONG pfnDeferredFillIn;
    SCODE scode;
} EXCEPINFO;
#endif

static int
dissect_IDispatch_Invoke_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 u32Pointer;
	guint32 u32VariableOffset;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	/* XXX: this is not correct and has to be improved! */
	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
		u32VariableOffset = offset;
		u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, tree, drep, hf_dispatch_varresult);
		offset = u32VariableOffset;
	}

	/* ExcepInfo */
	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_tobedone_data(tvb, offset, pinfo, tree, drep, 
					10000);
	}

	/* ArgErr */
	offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep, 
						&u32Pointer);
	if (u32Pointer) {
		offset = dissect_dcom_tobedone_data(tvb, offset, pinfo, tree, drep, 
					10000);
	}


	return offset;
}



/* sub dissector table of IDispatch interface */
static dcerpc_sub_dissector dispatch_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "GetTypeInfoCount", NULL, NULL },
    { 4, "GetTypeInfo", NULL, NULL },
    { 5, "GetIDsOfNames", dissect_IDispatch_GetIDsOfNames_rqst, dissect_IDispatch_GetIDsOfNames_resp },
    { 6, "Invoke", dissect_IDispatch_Invoke_rqst, dissect_IDispatch_Invoke_resp },
    { 0, NULL, NULL, NULL },
};


void
proto_register_dcom_dispatch(void)
{

	static hf_register_info hf_dispatch_array[] = {
        { &hf_dispatch_opnum,
	    { "Operation", "dispatch_opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "Operation", HFILL }},

		{ &hf_dispatch_riid,
		{ "RIID", "dispatch_riid", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dispatch_name,
        { "Name", "hf_dispatch_name", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_dispatch_names,
		{ "Names", "dispatch_names", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dispatch_lcid,
        { "LCID", "dispatch_lcid", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dispatch_id,
        { "ID", "dispatch_id", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dispatch_flags,
        { "Flags", "dispatch_flags", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dispatch_flags2,
        { "Flags2", "dispatch_flags2", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},

		{ &hf_dispatch_arg,
		{ "Argument", "dispatch_arg", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_dispatch_args,
		{ "Args", "dispatch_args", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_dispatch_named_args,
		{ "NamedArgs", "dispatch_named_args", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_dispatch_varref,
		{ "VarRef", "dispatch_varref", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_dispatch_varrefidx,
		{ "VarRefIdx", "dispatch_varrefidx", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_dispatch_varrefarg,
		{ "VarRef", "dispatch_varrefarg", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_dispatch_varresult,
		{ "VarResult", "dispatch_varresult", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},

        { &hf_dispatch_flags_method,
        { "Method", "dispatch_flags_method", FT_BOOLEAN, 16, TFS (&flags_set_truth), DISPATCH_FLAGS_METHOD, "", HFILL }},
        { &hf_dispatch_flags_propget,
        { "PropertyGet", "dispatch_flags_propget", FT_BOOLEAN, 16, TFS (&flags_set_truth), DISPATCH_FLAGS_PROPGET, "", HFILL }},
        { &hf_dispatch_flags_propput,
        { "PropertyPut", "dispatch_flags_propput", FT_BOOLEAN, 16, TFS (&flags_set_truth), DISPATCH_FLAGS_PROPPUT, "", HFILL }},
        { &hf_dispatch_flags_propputref,
        { "PropertyPutRef", "dispatch_flags_propputref", FT_BOOLEAN, 16, TFS (&flags_set_truth), DISPATCH_FLAGS_PROPPUTREF, "", HFILL }},
	};

	static gint *ett[] = {
		&ett_dispatch,
		&ett_dispatch_flags
	};


	/* IDispatch currently only partially implemented */
	proto_dispatch = proto_register_protocol ("DCOM IDispatch", "IDispatch", "dispatch");
	proto_register_field_array (proto_dispatch, hf_dispatch_array, array_length (hf_dispatch_array));
	proto_register_subtree_array (ett, array_length (ett));
}


void
proto_reg_handoff_dcom_dispatch(void)
{

	dcerpc_init_uuid(proto_dispatch, ett_dispatch,
		&uuid_dispatch, ver_dispatch,
		dispatch_dissectors, hf_dispatch_opnum);
}

