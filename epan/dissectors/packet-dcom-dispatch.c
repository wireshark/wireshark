/* packet-dcom-dispatch.c
 * Routines for DCOM IDispatch
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* see packet-dcom.c for details about DCOM */

#include "config.h"


#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcom.h"
#include "packet-dcom-dispatch.h"


static int hf_dispatch_opnum = -1;

static int hf_dispatch_riid = -1;
static int hf_dispatch_name = -1;
static int hf_dispatch_names = -1;
static int hf_dispatch_lcid = -1;
static int hf_dispatch_id = -1;

static int hf_dispatch_arg = -1;
static int hf_dispatch_args = -1;
static int hf_dispatch_named_args = -1;
static int hf_dispatch_varref = -1;
static int hf_dispatch_varrefidx = -1;
static int hf_dispatch_varrefarg = -1;

static int hf_dispatch_varresult = -1;
static int hf_dispatch_code = -1;
static int hf_dispatch_reserved16 = -1;
static int hf_dispatch_source = -1;
static int hf_dispatch_description = -1;
static int hf_dispatch_help_file = -1;
static int hf_dispatch_help_context = -1;
static int hf_dispatch_reserved32 = -1;
static int hf_dispatch_deferred_fill_in = -1;
static int hf_dispatch_arg_err = -1;

static int hf_dispatch_tinfo = -1;
static int hf_dispatch_itinfo = -1;
static int hf_dispatch_dispparams = -1;
static int hf_dispatch_excepinfo = -1;
static int hf_dispatch_scode = -1;


static int hf_dispatch_flags = -1;
static int hf_dispatch_flags_method = -1;
static int hf_dispatch_flags_propget = -1;
static int hf_dispatch_flags_propput = -1;
static int hf_dispatch_flags_propputref = -1;

#define DISPATCH_FLAGS_METHOD           1
#define DISPATCH_FLAGS_PROPGET          2
#define DISPATCH_FLAGS_PROPPUT          4
#define DISPATCH_FLAGS_PROPPUTREF       8

static gint ett_dispatch_flags = -1;
static gint ett_dispatch_params = -1;
static gint ett_dispatch_excepinfo = -1;

static e_uuid_t uuid_dispatch = { 0x00020400, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static guint16  ver_dispatch = 0;
static gint ett_dispatch = -1;
static int proto_dispatch = -1;


/* from MSDN "Locale Identifiers" */
/* see: http://msdn.microsoft.com/library/default.asp?url=/library/en-us/intl/nls_8sj7.asp */
/* values from cygwin's winnls.h and: */
/* http://msdn.microsoft.com/library/default.asp?url=/library/en-us/intl/nls_238z.asp */
static const value_string dcom_lcid_vals[] = {
    { 0x0000, "Language neutral" },
    { 0x0400, "LOCALE_USER_DEFAULT" },
    { 0x0409, "English (United States)" },
    { 0x0800, "LOCALE_SYSTEM_DEFAULT" },
    { 0,    NULL }
};



int
dissect_IDispatch_GetTypeInfoCount_resp(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32TInfo;
    guint32 u32HResult;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                                hf_dispatch_tinfo, &u32TInfo);

    /* HRESULT of call */
    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                                  &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
                    val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}

int
dissect_IDispatch_GetTypeInfo_rqst(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32TInfo;
    guint32 u32Lcid;

    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                                hf_dispatch_tinfo, &u32TInfo);
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                                hf_dispatch_lcid, &u32Lcid);

    return offset;
}


int
dissect_IDispatch_GetTypeInfo_resp(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32HResult;
    guint32 u32Pointer;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                                         &u32Pointer);
    if (u32Pointer) {
        offset = dissect_dcom_MInterfacePointer(tvb, offset, pinfo, tree, drep, hf_dispatch_itinfo, NULL /* XXX */);
    }

    /* HRESULT of call */
    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                                  &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
                    val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


int
dissect_IDispatch_GetIDsOfNames_rqst(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    e_uuid_t riid;
    guint32  u32Lcid;
    gchar    szName[1000] = { 0 };
    guint32  u32Names;
    guint32  u32ArraySize;
    guint32  u32Pointer;
    guint32  u32Tmp;
    guint32  u32VariableOffset;


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
                                                    hf_dispatch_name, szName, sizeof(szName));
            col_append_fstr(pinfo->cinfo, COL_INFO, " \"%s\"", szName);
        }
    }

    offset = u32VariableOffset;

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                                hf_dispatch_names, &u32Names);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                                hf_dispatch_lcid, &u32Lcid);

    return offset;
}



int
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
        col_append_fstr(pinfo->cinfo, COL_INFO, " ID=0x%x", u32DispId);
    }

    /* HRESULT of call */
    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                                  &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
                    val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}



int
dissect_IDispatch_Invoke_rqst(tvbuff_t *tvb, int offset,
                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32DispIdMember;
    e_uuid_t riid;
    guint32 u32Lcid;
    guint32 u32Flags;
    guint32 u32Args;
    guint32 u32NamedArgs;
    guint32 u32Pointer;
    guint32 u32Pointer2;
    guint32 u32ArraySize;
    guint32 u32VariableOffset;
    guint32 u32VarRef;
    guint32 u32VarRefIdx;
    guint32 u32TmpOffset;
    guint32 u32SubStart;

    proto_item *feature_item;
    proto_tree *feature_tree;
    proto_item *dispparams_item;
    proto_tree *dispparams_tree;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                                hf_dispatch_id, &u32DispIdMember);
    col_append_fstr(pinfo->cinfo, COL_INFO, " ID=0x%x", u32DispIdMember);

    offset = dissect_dcom_UUID(tvb, offset, pinfo, tree, drep,
                               hf_dispatch_riid, &riid);
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                                hf_dispatch_lcid, &u32Lcid);

    /* dispatch flags */
    u32TmpOffset = dissect_dcom_DWORD(tvb, offset, pinfo, NULL, drep,
                                      hf_dispatch_flags, &u32Flags);
    feature_item = proto_tree_add_uint (tree, hf_dispatch_flags, tvb, offset, 4, u32Flags);
    feature_tree = proto_item_add_subtree (feature_item, ett_dispatch_flags);
    if (feature_tree) {
        proto_tree_add_boolean (feature_tree, hf_dispatch_flags_propputref, tvb, offset, 4, u32Flags);
        proto_tree_add_boolean (feature_tree, hf_dispatch_flags_propput, tvb, offset, 4, u32Flags);
        proto_tree_add_boolean (feature_tree, hf_dispatch_flags_propget, tvb, offset, 4, u32Flags);
        proto_tree_add_boolean (feature_tree, hf_dispatch_flags_method, tvb, offset, 4, u32Flags);
    }

    if (u32Flags & DISPATCH_FLAGS_METHOD) {
        proto_item_append_text(feature_item, ", Method");
        col_append_str(pinfo->cinfo, COL_INFO, " Method");
    }
    if (u32Flags & DISPATCH_FLAGS_PROPGET) {
        proto_item_append_text(feature_item, ", PropertyGet");
        col_append_str(pinfo->cinfo, COL_INFO, " PropertyGet");
    }
    if (u32Flags & DISPATCH_FLAGS_PROPPUT) {
        proto_item_append_text(feature_item, ", PropertyPut");
        col_append_str(pinfo->cinfo, COL_INFO, " PropertyPut");
    }
    if (u32Flags & DISPATCH_FLAGS_PROPPUTREF) {
        proto_item_append_text(feature_item, ", PropertyPutRef");
        col_append_str(pinfo->cinfo, COL_INFO, " PropertyPutRef");
    }

    offset = u32TmpOffset;

    dispparams_item = proto_tree_add_item(tree, hf_dispatch_dispparams, tvb, offset, 0, ENC_NA);
    dispparams_tree = proto_item_add_subtree (dispparams_item, ett_dispatch_params);
    u32SubStart = offset;

    /* DISPPARAMS */
    /* VARIANT rgvarg[u32Args] */
    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, dispparams_tree, drep,
                                         &u32Pointer);

    /* DISPID rgdispidNamedArgs[u32NamedArgs] */
    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, dispparams_tree, drep,
                                         &u32Pointer2);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, dispparams_tree, drep,
                                hf_dispatch_args, &u32Args);
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, dispparams_tree, drep,
                                hf_dispatch_named_args, &u32NamedArgs);

    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, dispparams_tree, drep,
                                                &u32ArraySize);
        u32VariableOffset = offset + u32ArraySize * 4;
        while(u32ArraySize--) {
            offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, dispparams_tree, drep,
                                                 &u32Pointer);
            if (u32Pointer) {
                u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, dispparams_tree, drep, hf_dispatch_arg);
            }
        }
        offset = u32VariableOffset;
    }

    /* DISPID rgdispidNamedArgs[u32NamedArgs] */
    if (u32Pointer2) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, dispparams_tree, drep,
                                                &u32ArraySize);
        while(u32ArraySize--) {
            offset = dissect_dcom_DWORD(tvb, offset, pinfo, dispparams_tree, drep,
                                        hf_dispatch_id, &u32DispIdMember);
        }
    }

    proto_item_append_text(dispparams_item, ", Args: %u NamedArgs: %u", u32Args, u32NamedArgs);
    proto_item_set_len(dispparams_item, offset - u32SubStart);

    /* end of DISPPARAMS */

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

    col_append_fstr(pinfo->cinfo, COL_INFO,
                    " Args=%u NamedArgs=%u VarRef=%u", u32Args, u32NamedArgs, u32VarRef);

    return u32VariableOffset;
}

int
dissect_IDispatch_Invoke_resp(tvbuff_t *tvb, int offset,
                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Pointer;
    guint32 u32Pointer2;
    guint32 u32Pointer3;
    guint32 u32VariableOffset;
    guint32 u32ArraySize;
    guint32 u32SubStart;
    guint16 u16Code;
    guint16 u16Reserved;
    guint32 u32HelpContext;
    guint32 u32Reserved;
    guint32 u32DeferredFillIn;
    guint32 u32ArgErr;
    guint32 u32HResult;
    guint32 u32SCode;
    guint32 u32VarRef;
    gchar       szName[1000] = { 0 };
    proto_item *excepinfo_item;
    proto_tree *excepinfo_tree;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                                         &u32Pointer);
    if (u32Pointer) {
        offset = dissect_dcom_VARIANT(tvb, offset, pinfo, tree, drep, hf_dispatch_varresult);
    }

    /* ExcepInfo */
    excepinfo_item = proto_tree_add_item(tree, hf_dispatch_excepinfo, tvb, offset, 0, ENC_NA);
    excepinfo_tree = proto_item_add_subtree (excepinfo_item, ett_dispatch_excepinfo);
    u32SubStart = offset;

    offset = dissect_dcom_WORD(tvb, offset, pinfo, excepinfo_tree, drep,
                               hf_dispatch_code, &u16Code);
    offset = dissect_dcom_WORD(tvb, offset, pinfo, excepinfo_tree, drep,
                               hf_dispatch_reserved16, &u16Reserved);
    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, excepinfo_tree, drep,
                                         &u32Pointer);
    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, excepinfo_tree, drep,
                                         &u32Pointer2);
    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, excepinfo_tree, drep,
                                         &u32Pointer3);
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, excepinfo_tree, drep,
                                hf_dispatch_help_context, &u32HelpContext);
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, excepinfo_tree, drep,
                                hf_dispatch_reserved32, &u32Reserved);
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, excepinfo_tree, drep,
                                hf_dispatch_deferred_fill_in, &u32DeferredFillIn);
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, excepinfo_tree, drep,
                                hf_dispatch_scode, &u32SCode);

    if (u32Pointer) {
        offset = dissect_dcom_BSTR(tvb, offset, pinfo, excepinfo_tree, drep,
                                   hf_dispatch_source, szName, sizeof(szName));
    }
    if (u32Pointer2) {
        offset = dissect_dcom_BSTR(tvb, offset, pinfo, excepinfo_tree, drep,
                                   hf_dispatch_description, szName, sizeof(szName));
    }
    if (u32Pointer3) {
        offset = dissect_dcom_BSTR(tvb, offset, pinfo, excepinfo_tree, drep,
                                   hf_dispatch_help_file, szName, sizeof(szName));
    }

    proto_item_append_text(excepinfo_item, ", SCode: %s",
                           val_to_str(u32SCode, dcom_hresult_vals, "Unknown (0x%08x)"));
    proto_item_set_len(excepinfo_item, offset - u32SubStart);
    /* end of ExcepInfo */

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                                hf_dispatch_arg_err, &u32ArgErr);

    /* rgVarRef: VARIANT[u32VarRef] */
    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                                            &u32ArraySize);
    u32VarRef = u32ArraySize;
    u32VariableOffset = offset + u32ArraySize * 4;
    while(u32ArraySize--) {
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                                             &u32Pointer);
        if (u32Pointer) {
            u32VariableOffset = dissect_dcom_VARIANT(tvb, u32VariableOffset, pinfo, tree, drep, hf_dispatch_varrefarg);
        }
    }
    offset = u32VariableOffset;

    /* HRESULT of call */
    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                                  &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " SCode=%s VarRef=%u -> %s",
                    val_to_str(u32SCode, dcom_hresult_vals, "Unknown (0x%08x)"),
                    u32VarRef,
                    val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}



/* sub dissector table of IDispatch interface */
static dcerpc_sub_dissector dispatch_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "GetTypeInfoCount", dissect_dcom_simple_rqst, dissect_IDispatch_GetTypeInfoCount_resp },
    { 4, "GetTypeInfo", dissect_IDispatch_GetTypeInfo_rqst, dissect_IDispatch_GetTypeInfo_resp },
    { 5, "GetIDsOfNames", dissect_IDispatch_GetIDsOfNames_rqst, dissect_IDispatch_GetIDsOfNames_resp },
    { 6, "Invoke", dissect_IDispatch_Invoke_rqst, dissect_IDispatch_Invoke_resp },
    { 0, NULL, NULL, NULL },
};


void
proto_register_dcom_dispatch(void)
{

    static hf_register_info hf_dispatch_array[] = {
        { &hf_dispatch_opnum,
          { "Operation", "dispatch.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dispatch_riid,
          { "RIID", "dispatch.riid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_name,
          { "Name", "dispatch.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_names,
          { "Names", "dispatch.names", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_lcid,
          { "LCID", "dispatch.lcid", FT_UINT32, BASE_HEX, VALS(dcom_lcid_vals), 0x0, NULL, HFILL }},
        { &hf_dispatch_id,
          { "DispID", "dispatch.id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_flags,
          { "Flags", "dispatch.flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_dispatch_arg,
          { "Argument", "dispatch.arg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_args,
          { "Args", "dispatch.args", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_named_args,
          { "NamedArgs", "dispatch.named_args", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_varref,
          { "VarRef", "dispatch.varref", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_varrefidx,
          { "VarRefIdx", "dispatch.varrefidx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_varrefarg,
          { "VarRef", "dispatch.varrefarg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_varresult,
          { "VarResult", "dispatch.varresult", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_dispatch_flags_method,
          { "Method", "dispatch.flags_method", FT_BOOLEAN, 32, TFS (&tfs_set_notset), DISPATCH_FLAGS_METHOD, NULL, HFILL }},
        { &hf_dispatch_flags_propget,
          { "PropertyGet", "dispatch.flags_propget", FT_BOOLEAN, 32, TFS (&tfs_set_notset), DISPATCH_FLAGS_PROPGET, NULL, HFILL }},
        { &hf_dispatch_flags_propput,
          { "PropertyPut", "dispatch.flags_propput", FT_BOOLEAN, 32, TFS (&tfs_set_notset), DISPATCH_FLAGS_PROPPUT, NULL, HFILL }},
        { &hf_dispatch_flags_propputref,
          { "PropertyPutRef", "dispatch.flags_propputref", FT_BOOLEAN, 32, TFS (&tfs_set_notset), DISPATCH_FLAGS_PROPPUTREF, NULL, HFILL }},

        { &hf_dispatch_code,
          { "Code", "dispatch.code", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_reserved16,
          { "Reserved", "dispatch.reserved16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_source,
          { "Source", "dispatch.source", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_description,
          { "Description", "dispatch.description", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_help_file,
          { "HelpFile", "dispatch.help_file", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_help_context,
          { "HelpContext", "dispatch.help_context", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_reserved32,
          { "Reserved", "dispatch.reserved32", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_deferred_fill_in,
          { "DeferredFillIn", "dispatch.deferred_fill_in", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_arg_err,
          { "ArgErr", "dispatch.arg_err", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_dispatch_tinfo,
          { "TInfo", "dispatch.tinfo", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_itinfo,
          { "TInfo", "dispatch.itinfo", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_dispparams,
          { "DispParams", "dispatch.dispparams", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_excepinfo,
          { "ExcepInfo", "dispatch.excepinfo", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dispatch_scode,
          { "SCode", "dispatch.scode", FT_UINT32, BASE_HEX, VALS(dcom_hresult_vals), 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_dispatch,
        &ett_dispatch_flags,
        &ett_dispatch_params,
        &ett_dispatch_excepinfo
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

