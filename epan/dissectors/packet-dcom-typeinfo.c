/* packet-dcom-typeinfo.c
 * Routines for DCOM ITypeInfo
 * Copyright 2019, Alex Sirr <alexsirruw@gmail.com>
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

#include "packet-dcerpc-nt.h"

void proto_register_dcom_typeinfo(void);
void proto_reg_handoff_dcom_typeinfo(void);

static gint ett_typeinfo_funcdesc = -1;
static int hf_typeinfo_funcdesc = -1;
static int hf_typeinfo_funcdesc_funcflags = -1;
static gint ett_typeinfo_funcdesc_funcflags = -1;
static int hf_typeinfo_funcdesc_funcflags_frestricted = -1;
static int hf_typeinfo_funcdesc_funcflags_fsource = -1;
static int hf_typeinfo_funcdesc_funcflags_fbindable = -1;
static int hf_typeinfo_funcdesc_funcflags_frequestedit = -1;
static int hf_typeinfo_funcdesc_funcflags_fdisplaybind = -1;
static int hf_typeinfo_funcdesc_funcflags_fdefaultbind = -1;
static int hf_typeinfo_funcdesc_funcflags_fhidden = -1;
static int hf_typeinfo_funcdesc_funcflags_fusesgetlasterror = -1;
static int hf_typeinfo_funcdesc_funcflags_fdefaultcollelem = -1;
static int hf_typeinfo_funcdesc_funcflags_fuidefault = -1;
static int hf_typeinfo_funcdesc_funcflags_fnowbrowsable = -1;
static int hf_typeinfo_funcdesc_funcflags_freplaceable = -1;
static int hf_typeinfo_funcdesc_funcflags_fimmediatebind = -1;

#define FUNCFLAG_FRESTRICTED 0x1
#define FUNCFLAG_FSOURCE 0x2
#define FUNCFLAG_FBINDABLE 0x4
#define FUNCFLAG_FREQUESTEDIT 0x8
#define FUNCFLAG_FDISPLAYBIND 0x10
#define FUNCFLAG_FDEFAULTBIND 0x20
#define FUNCFLAG_FHIDDEN 0x40
#define FUNCFLAG_FUSESGETLASTERROR 0x80
#define FUNCFLAG_FDEFAULTCOLLELEM 0x100
#define FUNCFLAG_FUIDEFAULT 0x200
#define FUNCFLAG_FNONBROWSABLE 0x400
#define FUNCFLAG_FREPLACEABLE 0x800
#define FUNCFLAG_FIMMEDIATEBIND 0x1000

static int hf_typeinfo_funcdesc_funckind = -1;
static int hf_typeinfo_funcdesc_invkind = -1;
static int hf_typeinfo_funcdesc_callconv = -1;
static int hf_typeinfo_funcdesc_params = -1;
static int hf_typeinfo_funcdesc_paramsopt = -1;
static int hf_typeinfo_funcdesc_memid = -1;
static int hf_typeinfo_funcdesc_vft = -1;
static int hf_typeinfo_funcdesc_resv16 = -1;
static int hf_typeinfo_funcdesc_resv32 = -1;
static gint ett_typeinfo_elemdesc = -1;
static int hf_typeinfo_funcdesc_elemdesc = -1;

static gint ett_typeinfo_typedesc = -1;
static int hf_typeinfo_typedesc = -1;

static gint ett_typeinfo_paramdesc = -1;
static int hf_typeinfo_paramdesc = -1;
static gint ett_typeinfo_paramdesc_paramflags = -1;
static int hf_typeinfo_paramdesc_paramflags = -1;
static int hf_typeinfo_paramdesc_paramflags_fin = -1;
static int hf_typeinfo_paramdesc_paramflags_fout = -1;
static int hf_typeinfo_paramdesc_paramflags_flcid = -1;
static int hf_typeinfo_paramdesc_paramflags_fretval = -1;
static int hf_typeinfo_paramdesc_paramflags_fopt = -1;
static int hf_typeinfo_paramdesc_paramflags_fhasdefault = -1;
static int hf_typeinfo_paramdesc_paramflags_fhascustdata = -1;

#define PARAMFLAG_FIN 0x1
#define PARAMFLAG_FOUT 0x2
#define PARAMFLAG_FLCID 0x4
#define PARAMFLAG_FRETVAL 0x8
#define PARAMFLAG_FOPT 0x10
#define PARAMFLAG_FHASDEFAULT 0x20
#define PARAMFLAG_FHASCUSTDATA 0x40

static gint ett_typeinfo_paramdescex = -1;
static int hf_typeinfo_paramdescex = -1;
static int hf_typeinfo_paramdescex_cbytes = -1;
static int hf_typeinfo_paramdescex_varDefaultValue = -1;

static int hf_typeinfo_typedesc_vtret = -1;
static int hf_typeinfo_typedesc_hreftype = -1;

static int hf_typeinfo_opnum = -1;
static int hf_typeinfo_index = -1;

static int hf_typeinfo_memid = -1;
static int hf_typeinfo_reserved32 = -1;
static int hf_typeinfo_reserved16 = -1;

static int hf_typeinfo_names = -1;
static int hf_typeinfo_names_value = -1;
static int hf_typeinfo_maxnames = -1;

static int hf_typeinfo_docname = -1;
static int hf_typeinfo_docstring = -1;
static int hf_typeinfo_helpctx = -1;
static int hf_typeinfo_helpfile = -1;

static gint ett_typeinfo_docflags = -1;
static int hf_typeinfo_docflags = -1;
static int hf_typeinfo_docflags_name = -1;
static int hf_typeinfo_docflags_docstring = -1;
static int hf_typeinfo_docflags_helpctx = -1;
static int hf_typeinfo_docflags_helpfile = -1;

#define TYPEINFO_DOCFLAGS_NameArg 1
#define TYPEINFO_DOCFLAGS_DocStringArg 2
#define TYPEINFO_DOCFLAGS_HelpContextArg 4
#define TYPEINFO_DOCFLAGS_HelpFileArg 8

static gint ett_typeinfo_typeflags = -1;
static int hf_typeinfo_typeflags = -1;
static int hf_typeinfo_typeflags_fappobject = -1;
static int hf_typeinfo_typeflags_fcancreate = -1;
static int hf_typeinfo_typeflags_flicensed = -1;
static int hf_typeinfo_typeflags_fpredeclid = -1;
static int hf_typeinfo_typeflags_fhidden = -1;
static int hf_typeinfo_typeflags_fcontrol = -1;
static int hf_typeinfo_typeflags_fdual = -1;
static int hf_typeinfo_typeflags_fnonextensible = -1;
static int hf_typeinfo_typeflags_foleautomation = -1;
static int hf_typeinfo_typeflags_frestricted = -1;
static int hf_typeinfo_typeflags_faggregatable = -1;
static int hf_typeinfo_typeflags_freplaceable = -1;
static int hf_typeinfo_typeflags_fdispatchable = -1;
static int hf_typeinfo_typeflags_fproxy = -1;

#define TYPEINFO_TYPEFLAG_FAPPOBJECT 0x1
#define TYPEINFO_TYPEFLAG_FCANCREATE 0x2
#define TYPEINFO_TYPEFLAG_FLICENSED 0x4
#define TYPEINFO_TYPEFLAG_FPREDECLID 0x8
#define TYPEINFO_TYPEFLAG_FHIDDEN 0x10
#define TYPEINFO_TYPEFLAG_FCONTROL 0x20
#define TYPEINFO_TYPEFLAG_FDUAL 0x40
#define TYPEINFO_TYPEFLAG_FNONEXTENSIBLE 0x80
#define TYPEINFO_TYPEFLAG_FOLEAUTOMATION 0x100
#define TYPEINFO_TYPEFLAG_FRESTRICTED 0x200
#define TYPEINFO_TYPEFLAG_FAGGREGATABLE 0x400
#define TYPEINFO_TYPEFLAG_FREPLACEABLE 0x800
#define TYPEINFO_TYPEFLAG_FDISPATCHABLE 0x1000
#define TYPEINFO_TYPEFLAG_FPROXY 0x4000

static gint ett_typeinfo_typeattr = -1;
static int hf_typeinfo_typeattr = -1;
static int hf_typeinfo_guid = -1;
static int hf_typeinfo_lcid = -1;
static int hf_typeinfo_sizeInstance = -1;
static int hf_typeinfo_typekind = -1;
static int hf_typeinfo_cFuncs = -1;
static int hf_typeinfo_cVars = -1;
static int hf_typeinfo_cImplTypes = -1;
static int hf_typeinfo_cbSizeVft = -1;
static int hf_typeinfo_cbAlignment = -1;
static int hf_typeinfo_wMajorVerNum = -1;
static int hf_typeinfo_wMinorVerNum = -1;

static gint ett_typeinfo_names = -1;

static e_guid_t uuid_typeinfo = {0x00020401, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static guint16 ver_typeinfo = 0;
static gint ett_typeinfo = -1;
static int proto_typeinfo = -1;

static const value_string dcom_lcid_vals[] = {
    {0x0000, "Language neutral"},
    {0x0400, "LOCALE_USER_DEFAULT"},
    {0x0409, "English (United States)"},
    {0x0800, "LOCALE_SYSTEM_DEFAULT"},
    {0, NULL}};

static const value_string typekind_vals[] = {
    {0x0, "TKIND_ENUM"},
    {0x01, "TKIND_RECORD"},
    {0x02, "TKIND_MODULE"},
    {0x03, "TKIND_INTERFACE"},
    {0x04, "TKIND_DISPATCH"},
    {0x05, "TKIND_COCLASS"},
    {0x06, "TKIND_ALIAS"},
    {0x07, "TKIND_UNION"},
    {0, NULL}};



static int dissect_typeinfo_PARAMDESCEX(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex);
static int dissect_typeinfo_PARAMDESCEX_through_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_typeinfo_PARAMDESC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex);
static int dissect_typeinfo_TYPEDESC_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_typeinfo_TYPEDESC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex);
static int dissect_typeinfo_ELEMDESC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex);
static int dissect_typeinfo_ELEMDESC_through_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_typeinfo_ELEMDESC_array(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_typeinfo_FUNCDESC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex);
static int dissect_typeinfo_TYPEATTR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex);
static int dissect_typeinfo_TYPEATTR_through_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_typeinfo_FUNCDESC_through_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_ITypeInfo_GetFuncDesc_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_ITypeInfo_GetFuncDesc_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_ITypeInfo_GetNames_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_ITypeInfo_GetNames_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_ITypeInfo_GetDocumentation_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_ITypeInfo_GetDocumentation_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_ITypeInfo_GetTypeAttr_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);
static int dissect_ITypeInfo_GetTypeAttr_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep);

int dissect_typeinfo_PARAMDESCEX(tvbuff_t *tvb, int offset, packet_info *pinfo,
                             proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex)
{
    guint32 u32Pointer;

    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;

    /* alignment of 4 needed for a PARAMDESCEX */
    ALIGN_TO_4_BYTES;

    sub_item = proto_tree_add_item(tree, hfindex, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_typeinfo_paramdescex);

    u32SubStart = offset;

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_paramdescex_cbytes, NULL);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, di, drep, &u32Pointer);

    if (u32Pointer)
    {
        offset = dissect_dcom_VARIANT(tvb, offset, pinfo, sub_tree, di, drep,
                                      hf_typeinfo_paramdescex_varDefaultValue);
    }

    proto_item_set_len(sub_item, offset - u32SubStart);
    return offset;
}

int dissect_typeinfo_PARAMDESCEX_through_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                             proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    return dissect_typeinfo_PARAMDESCEX(tvb, offset, pinfo, tree, di, drep, hf_typeinfo_paramdescex);
}

int dissect_typeinfo_PARAMDESC(tvbuff_t *tvb, int offset, packet_info *pinfo,
                           proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex)
{
    guint16 u16wParamFlags;

    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;

    static int * const flags[] = {
        &hf_typeinfo_paramdesc_paramflags_fin,
        &hf_typeinfo_paramdesc_paramflags_fout,
        &hf_typeinfo_paramdesc_paramflags_flcid,
        &hf_typeinfo_paramdesc_paramflags_fretval,
        &hf_typeinfo_paramdesc_paramflags_fopt,
        &hf_typeinfo_paramdesc_paramflags_fhasdefault,
        &hf_typeinfo_paramdesc_paramflags_fhascustdata,
        NULL};

    /* alignment of 4 needed for a PARAMDESC */
    ALIGN_TO_4_BYTES;

    sub_item = proto_tree_add_item(tree, hfindex, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_typeinfo_paramdesc);

    u32SubStart = offset;

    // pparamdescex
    offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, sub_tree, di, drep, dissect_typeinfo_PARAMDESCEX_through_pointer,
                                          NDR_POINTER_PTR, "Pointer to ParamDescEx", hf_typeinfo_paramdescex);

    // wParamFlags
    guint16 u16TmpOffset;
    u16TmpOffset = dissect_dcom_WORD(tvb, offset, pinfo, NULL, di, drep, -1, &u16wParamFlags);

    proto_tree_add_bitmask_value(sub_tree, tvb, offset, hf_typeinfo_paramdesc_paramflags,
                                 ett_typeinfo_paramdesc_paramflags, flags, u16wParamFlags);

    offset = u16TmpOffset;

    proto_item_set_len(sub_item, offset - u32SubStart);
    return offset;
}

int dissect_typeinfo_TYPEDESC_item(tvbuff_t *tvb, int offset, packet_info *pinfo,
                               proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    return dissect_typeinfo_TYPEDESC(tvb, offset, pinfo, tree, di, drep, hf_typeinfo_typedesc);
}

int dissect_typeinfo_TYPEDESC(tvbuff_t *tvb, int offset, packet_info *pinfo,
                          proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex)
{
    guint16 u16vtrettag;

    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;

    /* alignment of 4 needed for a TYPEDESC */
    ALIGN_TO_4_BYTES;

    sub_item = proto_tree_add_item(tree, hfindex, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_typeinfo_typedesc);

    u32SubStart = offset;

    // vt of ret (union tag)
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_typedesc_vtret, &u16vtrettag);

    if (u16vtrettag == 26 || u16vtrettag == 27) // WIRESHARK_VT_PTR || WIRESHARK_VT_SAFEARRAY
    {
        offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, sub_tree, di, drep, dissect_typeinfo_TYPEDESC_item,
                                              NDR_POINTER_PTR, "TypeDesc", hf_typeinfo_typedesc);
    }
    else if (u16vtrettag == 28) //WIRESHARK_VT_CARRAY
    {
        // NOT IMPLEMENTED
    }
    else if (u16vtrettag == 29) //WIRESHARK_VT_USERDEFINED
    {
        // typedef DWORD HREFTYPE;
        offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                    hf_typeinfo_typedesc_hreftype, NULL);
    }

    // vt of ret
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_typedesc_vtret, NULL);

    proto_item_set_len(sub_item, offset - u32SubStart);
    return offset;
}

int dissect_typeinfo_ELEMDESC(tvbuff_t *tvb, int offset, packet_info *pinfo,
                          proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;

    /* alignment of 4 needed for a ELEMDESC */
    ALIGN_TO_4_BYTES;

    sub_item = proto_tree_add_item(tree, hfindex, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_typeinfo_elemdesc);

    u32SubStart = offset;

    offset = dissect_typeinfo_TYPEDESC(tvb, offset, pinfo, sub_tree, di, drep, hf_typeinfo_typedesc);
    offset = dissect_typeinfo_PARAMDESC(tvb, offset, pinfo, sub_tree, di, drep, hf_typeinfo_paramdesc);

    proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}

int dissect_typeinfo_ELEMDESC_through_pointer(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    return dissect_typeinfo_ELEMDESC(tvb, offset, pinfo, tree, di, drep, hf_typeinfo_funcdesc_elemdesc);
}

int dissect_typeinfo_ELEMDESC_array(tvbuff_t *tvb, int offset,
                           packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    return dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep, dissect_typeinfo_ELEMDESC_through_pointer);
}

int dissect_typeinfo_FUNCDESC(tvbuff_t *tvb, int offset,
                          packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex)
{
    guint16 u16Funcflags;

    proto_item *sub_item;
    proto_tree *sub_tree;

    proto_item *func_elemdesc_sub_item;
    proto_tree *func_elemdesc_tree;

    guint32 u32SubStart;

    static int * const flags[] = {
        &hf_typeinfo_funcdesc_funcflags_frestricted,
        &hf_typeinfo_funcdesc_funcflags_fsource,
        &hf_typeinfo_funcdesc_funcflags_fbindable,
        &hf_typeinfo_funcdesc_funcflags_frequestedit,
        &hf_typeinfo_funcdesc_funcflags_fdisplaybind,
        &hf_typeinfo_funcdesc_funcflags_fdefaultbind,
        &hf_typeinfo_funcdesc_funcflags_fhidden,
        &hf_typeinfo_funcdesc_funcflags_fusesgetlasterror,
        &hf_typeinfo_funcdesc_funcflags_fdefaultcollelem,
        &hf_typeinfo_funcdesc_funcflags_fuidefault,
        &hf_typeinfo_funcdesc_funcflags_fnowbrowsable,
        &hf_typeinfo_funcdesc_funcflags_freplaceable,
        &hf_typeinfo_funcdesc_funcflags_fimmediatebind,
        NULL};

    sub_item = proto_tree_add_item(tree, hfindex, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_typeinfo_funcdesc);

    u32SubStart = offset;

    // memid
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_funcdesc_memid, NULL);

    // lReserved1
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_funcdesc_resv32, NULL);
    // lprgelemdescParam
    offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, sub_tree, di, drep,
                                          dissect_typeinfo_ELEMDESC_array, NDR_POINTER_PTR, "Parameter ElemDesc", hf_typeinfo_funcdesc_elemdesc);

    // funckind
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_funcdesc_funckind, NULL);

    // invkind
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_funcdesc_invkind, NULL);

    // callconv
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_funcdesc_callconv, NULL);

    // cParams
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_funcdesc_params, NULL);

    // cParamsOpt
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_funcdesc_paramsopt, NULL);

    // oVft
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_funcdesc_vft, NULL);

    // cReserved2
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_funcdesc_resv16, NULL);

    // create tree for function element description
    func_elemdesc_sub_item = proto_tree_add_item(sub_tree, hfindex, tvb, offset, 0, ENC_NA);
    func_elemdesc_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 0,
                                                ett_typeinfo_elemdesc, &func_elemdesc_sub_item, "Function ElemDesc");
    // elemdescFunc
    offset = dissect_typeinfo_ELEMDESC(tvb, offset, pinfo, func_elemdesc_tree, di, drep, hf_typeinfo_funcdesc_elemdesc);

    // func flags
    guint16 u16TmpOffset;
    u16TmpOffset = dissect_dcom_WORD(tvb, offset, pinfo, NULL, di, drep, -1, &u16Funcflags);

    proto_tree_add_bitmask_value(sub_tree, tvb, offset, hf_typeinfo_funcdesc_funcflags,
                                 ett_typeinfo_funcdesc_funcflags, flags, u16Funcflags);

    offset = u16TmpOffset;

    proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}

int dissect_typeinfo_FUNCDESC_through_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                          proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    return dissect_typeinfo_FUNCDESC(tvb, offset, pinfo, tree, di, drep, hf_typeinfo_funcdesc);
}

int dissect_typeinfo_TYPEATTR(tvbuff_t *tvb, int offset, packet_info *pinfo,
                              proto_tree *tree, dcerpc_info *di, guint8 *drep, int hfindex)
{
    guint16 u16wTypeFlags;

    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;

    static int * const flags[] = {
        &hf_typeinfo_typeflags_fappobject,
        &hf_typeinfo_typeflags_fcancreate,
        &hf_typeinfo_typeflags_flicensed,
        &hf_typeinfo_typeflags_fpredeclid,
        &hf_typeinfo_typeflags_fhidden,
        &hf_typeinfo_typeflags_fcontrol,
        &hf_typeinfo_typeflags_fdual,
        &hf_typeinfo_typeflags_fnonextensible,
        &hf_typeinfo_typeflags_foleautomation,
        &hf_typeinfo_typeflags_frestricted,
        &hf_typeinfo_typeflags_faggregatable,
        &hf_typeinfo_typeflags_freplaceable,
        &hf_typeinfo_typeflags_fdispatchable,
        &hf_typeinfo_typeflags_fproxy,
        NULL};

    sub_item = proto_tree_add_item(tree, hfindex, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_typeinfo_typeattr);

    u32SubStart = offset;

    // guid
    offset = dissect_dcom_UUID(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_guid, NULL);

    // lcid
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_lcid, NULL);

    // dwReserved1
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_reserved32, NULL);

    // dwReserved2
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_reserved32, NULL);

    // dwReserved3
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_reserved32, NULL);

    // lpstrReserved4
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_reserved32, NULL);

    // cbSizeInstance
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_sizeInstance, NULL);

    // typekind
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_typekind, NULL);

    // cFuncs
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_cFuncs, NULL);

    // cVars
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_cVars, NULL);

    // cImplTypes
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_cImplTypes, NULL);

    // cbSizeVft
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_cbSizeVft, NULL);

    // cbAlignment
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_cbAlignment, NULL);

    // wTypeFlags
    guint16 u16TmpOffset;
    u16TmpOffset = dissect_dcom_WORD(tvb, offset, pinfo, NULL, di, drep, -1, &u16wTypeFlags);

    proto_tree_add_bitmask_value(sub_tree, tvb, offset, hf_typeinfo_typeflags,
                                 ett_typeinfo_typeflags, flags, u16wTypeFlags);

    offset = u16TmpOffset;

    // wMajorVerNum
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_wMajorVerNum, NULL);

    // wMinorVerNum
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_wMinorVerNum, NULL);

    offset = dissect_typeinfo_TYPEDESC(tvb, offset, pinfo, sub_tree, di, drep, hf_typeinfo_typedesc);

    // dwReserved5
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                hf_typeinfo_reserved32, NULL);

    // wReserved6
    offset = dissect_dcom_WORD(tvb, offset, pinfo, sub_tree, di, drep,
                               hf_typeinfo_reserved16, NULL);

    proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}

int dissect_typeinfo_TYPEATTR_through_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo,
                                              proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    return offset = dissect_typeinfo_TYPEATTR(tvb, offset, pinfo, tree, di, drep, hf_typeinfo_typeattr);
}

static int
dissect_bstr_through_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    gchar szName[1000] = {0};
    offset = dissect_dcom_BSTR(tvb, offset, pinfo, tree, di, drep,
                               di->hf_index, szName, sizeof(szName));
    return offset;
}

static int
dissect_dword_through_pointer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
                                di->hf_index, NULL);

    return offset;
}

int dissect_ITypeInfo_GetFuncDesc_rqst(tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    offset = dissect_dcom_this(tvb, offset, pinfo, tree, di, drep);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
                                hf_typeinfo_index, NULL);

    return offset;
}

int dissect_ITypeInfo_GetFuncDesc_resp(tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    offset = dissect_dcom_that(tvb, offset, pinfo, tree, di, drep);

    // funcdesc
    offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, dissect_typeinfo_FUNCDESC_through_pointer, NDR_POINTER_UNIQUE, "Pointer to FuncDesc", hf_typeinfo_funcdesc);

    // reserved
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
                                hf_typeinfo_reserved32, NULL);

    /* HRESULT of call */
    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, di, drep,
                                  NULL);

    return offset;
}

int dissect_ITypeInfo_GetNames_rqst(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    offset = dissect_dcom_this(tvb, offset, pinfo, tree, di, drep);

    // memid
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
                                hf_typeinfo_memid, NULL);

    // cMaxNames
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
                                hf_typeinfo_maxnames, NULL);

    return offset;
}

int dissect_ITypeInfo_GetNames_resp(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    guint32 u32ArrayLength;
    guint32 u32Pointer;

    guint32 u32VarOffset;
    guint32 u32Tmp;

    gchar szName[1000] = {0};

    proto_item *sub_item;
    proto_tree *sub_tree;
    guint32 u32SubStart;

    offset = dissect_dcom_that(tvb, offset, pinfo, tree, di, drep);

    sub_item = proto_tree_add_item(tree, hf_typeinfo_names, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_typeinfo_names);

    u32SubStart = offset;

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, sub_tree, di, drep, NULL);
    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, di, drep, NULL);
    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, sub_tree, di, drep,
                                            &u32ArrayLength);

    u32VarOffset = offset + u32ArrayLength * 4;
    u32Tmp = u32ArrayLength;
    while (u32Tmp--)
    {
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, di, drep,
                                             &u32Pointer);
        if (u32Pointer)
        {
            u32VarOffset = dissect_dcom_BSTR(tvb, u32VarOffset, pinfo, sub_tree, di, drep,
                                             hf_typeinfo_names_value, szName, sizeof(szName));
        }
    }
    offset = u32VarOffset;

    col_append_fstr(pinfo->cinfo, COL_INFO,
                    " %u Names", u32ArrayLength);

    proto_item_set_len(sub_item, offset - u32SubStart);

    // pcNames
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
                                hf_typeinfo_maxnames, NULL);

    /* HRESULT of call */
    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, di, drep, NULL);

    return offset;
}

int dissect_ITypeInfo_GetDocumentation_rqst(tvbuff_t *tvb, int offset,
                                            packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    guint32 u32Flags;

    guint32 u32TmpOffset;

    static int * const flags[] = {
        &hf_typeinfo_docflags_name,
        &hf_typeinfo_docflags_docstring,
        &hf_typeinfo_docflags_helpctx,
        &hf_typeinfo_docflags_helpfile,
        NULL};

    offset = dissect_dcom_this(tvb, offset, pinfo, tree, di, drep);

    // memid
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
                                hf_typeinfo_memid, NULL);

    // refPtrFlags
    u32TmpOffset = dissect_dcom_DWORD(tvb, offset, pinfo, NULL, di, drep, -1, &u32Flags);

    proto_tree_add_bitmask_value(tree, tvb, offset, hf_typeinfo_docflags,
                                 ett_typeinfo_docflags, flags, u32Flags);

    offset = u32TmpOffset;

    return offset;
}

int dissect_ITypeInfo_GetDocumentation_resp(tvbuff_t *tvb, int offset,
                                            packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    offset = dissect_dcom_that(tvb, offset, pinfo, tree, di, drep);

    // pBstrDocName
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, di, drep, dissect_bstr_through_pointer, NDR_POINTER_UNIQUE, "Pointer to Doc Name", hf_typeinfo_docname);

    // pBstrDocString
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, di, drep, dissect_bstr_through_pointer, NDR_POINTER_UNIQUE, "Pointer to Doc String", hf_typeinfo_docstring);

    // pdwHelpContext
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, di, drep, dissect_dword_through_pointer, NDR_POINTER_UNIQUE, "Pointer to Help Context", hf_typeinfo_helpctx);

    // pBstrHelpFile
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, di, drep, dissect_bstr_through_pointer, NDR_POINTER_UNIQUE, "Pointer to Help File", hf_typeinfo_helpfile);

    /* HRESULT of call */
    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, di, drep, NULL);
    return offset;
}

int dissect_ITypeInfo_GetTypeAttr_rqst(tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    offset = dissect_dcom_this(tvb, offset, pinfo, tree, di, drep);
    return offset;
}

int dissect_ITypeInfo_GetTypeAttr_resp(tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    offset = dissect_dcom_that(tvb, offset, pinfo, tree, di, drep);

    offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, di, drep, dissect_typeinfo_TYPEATTR_through_pointer, NDR_POINTER_UNIQUE, "Pointer to TypeAttr", hf_typeinfo_typeattr);

    // reserved
    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
                                hf_typeinfo_reserved32, NULL);

    /* HRESULT of call */
    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, di, drep, NULL);

    return offset;
}

/* sub dissector table of ITypeInfo interface */
static dcerpc_sub_dissector typeinfo_dissectors[] = {
    {3, "GetTypeAttr", dissect_ITypeInfo_GetTypeAttr_rqst, dissect_ITypeInfo_GetTypeAttr_resp},
    {4, "GetTypeComp", NULL, NULL},
    {5, "GetFuncDesc", dissect_ITypeInfo_GetFuncDesc_rqst, dissect_ITypeInfo_GetFuncDesc_resp},
    {6, "GetVarDesc", NULL, NULL},
    {7, "GetNames", dissect_ITypeInfo_GetNames_rqst, dissect_ITypeInfo_GetNames_resp},
    {8, "GetRefTypeOfImplType", NULL, NULL},
    {9, "GetImplTypeFlags", NULL, NULL},
    {12, "GetDocumentation", dissect_ITypeInfo_GetDocumentation_rqst, dissect_ITypeInfo_GetDocumentation_resp},
    {13, "GetDllEntry", NULL, NULL},
    {14, "GetRefTypeInfo", NULL, NULL},
    {16, "CreateInstance", NULL, NULL},
    {17, "GetMops", NULL, NULL},
    {18, "GetContainingTypeLib", NULL, NULL},

    {0, NULL, NULL, NULL},
};

void proto_register_dcom_typeinfo(void)
{
    static hf_register_info hf_typeinfo_typedesc_array[] = {
        {&hf_typeinfo_typedesc,
         {"TypeDesc", "typeinfo.typedesc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_typedesc_vtret,
         {"VT Return Type", "typeinfo.typedesc.vtret", FT_UINT16, BASE_HEX, VALS(dcom_variant_type_vals), 0x0, NULL, HFILL}},
        {&hf_typeinfo_typedesc_hreftype,
         {"Ref Type", "typeinfo.typedesc.reftype", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    };
    static hf_register_info hf_typeinfo_paramdesc_array[] = {
        {&hf_typeinfo_paramdesc,
         {"ParamDesc", "typeinfo.paramdesc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_paramdesc_paramflags,
         {"Param Flags", "typeinfo.paramdesc.paramflags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_paramdesc_paramflags_fin,
         {"FIN", "typeinfo.paramdesc.paramflags_fin", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PARAMFLAG_FIN, NULL, HFILL}},
        {&hf_typeinfo_paramdesc_paramflags_fout,
         {"FOUT", "typeinfo.paramdesc.paramflags_fout", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PARAMFLAG_FOUT, NULL, HFILL}},
        {&hf_typeinfo_paramdesc_paramflags_flcid,
         {"FLCID", "typeinfo.paramdesc.paramflags_flcid", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PARAMFLAG_FLCID, NULL, HFILL}},
        {&hf_typeinfo_paramdesc_paramflags_fretval,
         {"FRETVAL", "typeinfo.paramdesc.paramflags_fretval", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PARAMFLAG_FRETVAL, NULL, HFILL}},
        {&hf_typeinfo_paramdesc_paramflags_fopt,
         {"FOPT", "typeinfo.paramdesc.paramflags_fopt", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PARAMFLAG_FOPT, NULL, HFILL}},
        {&hf_typeinfo_paramdesc_paramflags_fhasdefault,
         {"FHASDEFAULT", "typeinfo.paramdesc.paramflags_fhasdefault", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PARAMFLAG_FHASDEFAULT, NULL, HFILL}},
        {&hf_typeinfo_paramdesc_paramflags_fhascustdata,
         {"FHASCUSTDATA", "typeinfo.paramdesc.paramflags_fhascustdata", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PARAMFLAG_FHASCUSTDATA, NULL, HFILL}},
    };

    static hf_register_info hf_typeinfo_paramdescex_array[] = {
        {&hf_typeinfo_paramdescex,
         {"ParamDescEx", "typeinfo.paramdescex", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_paramdescex_cbytes,
         {"Length", "typeinfo.paramdescex.len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_paramdescex_varDefaultValue,
         {"VT Default Value", "typeinfo.paramdescex.vtdefaultval", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    };

    static hf_register_info hf_typeinfo_funcdesc_array[] = {
        {&hf_typeinfo_funcdesc,
         {"FuncDesc", "typeinfo.funcdesc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_memid,
         {"MemberID", "typeinfo.funcdesc.memberid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funckind,
         {"Function Kind", "typeinfo.funcdesc.funckind", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_invkind,
         {"Invoke Kind", "typeinfo.funcdesc.invkind", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_callconv,
         {"Call Conv", "typeinfo.funcdesc.callconv", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_params,
         {"Param Count", "typeinfo.funcdesc.params", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_paramsopt,
         {"Param Optional Count", "typeinfo.funcdesc.paramsopt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_vft,
         {"VFT Offset", "typeinfo.funcdesc.ovft", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_resv16,
         {"Reserved", "typeinfo.funcdesc.resv", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_resv32,
         {"Reserved", "typeinfo.funcdesc.resv", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_elemdesc,
         {"ElemDesc", "typeinfo.funcdesc.elemdesc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        {&hf_typeinfo_funcdesc_funcflags,
         {"FuncFlags", "typeinfo.funcdesc.funcflags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_frestricted,
         {"FRESTRICTED", "typeinfo.funcdesc.funcflags_frestricted", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FRESTRICTED, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_fsource,
         {"FSOURCE", "typeinfo.funcdesc.funcflags_fsource", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FSOURCE, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_fbindable,
         {"FBINDABLE", "typeinfo.funcdesc.funcflags_fbindable", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FBINDABLE, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_frequestedit,
         {"FREQUESTEDIT", "typeinfo.funcdesc.funcflags_frequestedit", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FREQUESTEDIT, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_fdisplaybind,
         {"FDISPLAYBIND", "typeinfo.funcdesc.funcflags_fdisplaybind", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FDISPLAYBIND, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_fdefaultbind,
         {"FDEFAULTBIND", "typeinfo.funcdesc.funcflags_fdefaultbind", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FDEFAULTBIND, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_fhidden,
         {"FHIDDEN", "typeinfo.funcdesc.funcflags_fhidden", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FHIDDEN, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_fusesgetlasterror,
         {"FUSESGETLASTERROR", "typeinfo.funcdesc.funcflags_fusesgetlasterror", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FUSESGETLASTERROR, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_fdefaultcollelem,
         {"FDEFAULTCOLLELEM", "typeinfo.funcdesc.funcflags_fdefaultcollelem", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FDEFAULTCOLLELEM, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_fuidefault,
         {"FUIDEFAULT", "typeinfo.funcdesc.funcflags_fuidefault", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FUIDEFAULT, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_fnowbrowsable,
         {"FNONBROWSABLE", "typeinfo.funcdesc.funcflags_fnowbrowsable", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FNONBROWSABLE, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_freplaceable,
         {"FREPLACEABLE", "typeinfo.funcdesc.funcflags_freplaceable", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FREPLACEABLE, NULL, HFILL}},
        {&hf_typeinfo_funcdesc_funcflags_fimmediatebind,
         {"FIMMEDIATEBIND", "typeinfo.funcdesc.funcflags_fimmediatebind", FT_BOOLEAN, 32, TFS(&tfs_set_notset), FUNCFLAG_FIMMEDIATEBIND, NULL, HFILL}},

    };

    static hf_register_info hf_typeinfo_array[] = {
        {&hf_typeinfo_opnum,
         {"Operation", "typeinfo.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_index,
         {"Function Index", "typeinfo.funcindex", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_reserved32,
         {"Reserved", "typeinfo.resv", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_reserved16,
         {"Reserved", "typeinfo.resv", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_typeinfo_memid,
         {"MemberID", "typeinfo.memberid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_typeinfo_names,
         {"Names", "typeinfo.names", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_names_value,
         {"Value", "typeinfo.names.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_maxnames,
         {"Max Names", "typeinfo.maxnames", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

        {&hf_typeinfo_docflags,
         {"Documentation Flags", "typeinfo.docflags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_typeinfo_docflags_name,
         {"NameArg", "typeinfo.docflags_namearg", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_DOCFLAGS_NameArg, NULL, HFILL}},
        {&hf_typeinfo_docflags_docstring,
         {"DocStringArg", "typeinfo.docflags_docstringarg", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_DOCFLAGS_DocStringArg, NULL, HFILL}},
        {&hf_typeinfo_docflags_helpctx,
         {"HelpContextArg", "typeinfo.docflags_helpctxarg", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_DOCFLAGS_HelpContextArg, NULL, HFILL}},
        {&hf_typeinfo_docflags_helpfile,
         {"HelpFileArg", "typeinfo.docflags_helpfilearg", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_DOCFLAGS_HelpFileArg, NULL, HFILL}},

        {&hf_typeinfo_docname,
         {"Doc Name", "typeinfo.docname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_docstring,
         {"Doc String", "typeinfo.docstring", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_helpfile,
         {"Help File", "typeinfo.helpfile", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_helpctx,
         {"Help Ctx", "typeinfo.helpctx", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_typeinfo_typeattr,
         {"TypeAttr", "typeinfo.typeattr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_guid,
         {"GUID", "typeinfo.guid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_lcid,
         {"LCID", "typeinfo.lcid", FT_UINT32, BASE_HEX, VALS(dcom_lcid_vals), 0x0, NULL, HFILL}},
        {&hf_typeinfo_sizeInstance,
         {"Size Instance", "typeinfo.sizeinstance", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_typekind,
         {"Type Kind", "typeinfo.typekind", FT_UINT32, BASE_HEX, VALS(typekind_vals), 0x0, NULL, HFILL}},
        {&hf_typeinfo_cFuncs,
         {"Func Count", "typeinfo.funcs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_cVars,
         {"Variables Count", "typeinfo.vars", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_cImplTypes,
         {"Implemented Interface Count", "typeinfo.impltypes", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_cbSizeVft,
         {"Virtual Table Size", "typeinfo.sizevft", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_cbAlignment,
         {"Byte Alignment", "typeinfo.balignment", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_wMajorVerNum,
         {"MajorVerNum", "typeinfo.majorvernum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_wMinorVerNum,
         {"MinorVerNum", "typeinfo.minorvernum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

        {&hf_typeinfo_typeflags,
         {"Type Flags", "typeinfo.typeflags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_typeinfo_typeflags_fappobject,
         {"FAPPOBJECT", "typeinfo.typeflags_fappobject", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FAPPOBJECT, NULL, HFILL}},
        {&hf_typeinfo_typeflags_fcancreate,
         {"FCANCREATE", "typeinfo.typeflags_fcancreate", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FCANCREATE, NULL, HFILL}},
        {&hf_typeinfo_typeflags_flicensed,
         {"FLICENSED", "typeinfo.typeflags_flicensed", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FLICENSED, NULL, HFILL}},
        {&hf_typeinfo_typeflags_fpredeclid,
         {"FPREDECLID", "typeinfo.typeflags_fpredeclid", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FPREDECLID, NULL, HFILL}},
        {&hf_typeinfo_typeflags_fhidden,
         {"FHIDDEN", "typeinfo.typeflags_fhidden", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FHIDDEN, NULL, HFILL}},
        {&hf_typeinfo_typeflags_fcontrol,
         {"FCONTROL", "typeinfo.typeflags_fcontrol", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FCONTROL, NULL, HFILL}},
        {&hf_typeinfo_typeflags_fdual,
         {"FDUAL", "typeinfo.typeflags_fdual", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FDUAL, NULL, HFILL}},
        {&hf_typeinfo_typeflags_fnonextensible,
         {"FNONEXTENSIBLE", "typeinfo.typeflags_fnonextensible", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FNONEXTENSIBLE, NULL, HFILL}},
        {&hf_typeinfo_typeflags_foleautomation,
         {"FOLEAUTOMATION", "typeinfo.typeflags_foleautomation", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FOLEAUTOMATION, NULL, HFILL}},
        {&hf_typeinfo_typeflags_frestricted,
         {"FRESTRICTED", "typeinfo.typeflags_frestricted", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FRESTRICTED, NULL, HFILL}},
        {&hf_typeinfo_typeflags_faggregatable,
         {"FAGGREGATABLE", "typeinfo.typeflags_faggregatable", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FAGGREGATABLE, NULL, HFILL}},
        {&hf_typeinfo_typeflags_freplaceable,
         {"FREPLACEABLE", "typeinfo.typeflags_freplaceable", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FREPLACEABLE, NULL, HFILL}},
        {&hf_typeinfo_typeflags_fdispatchable,
         {"FDISPATCHABLE", "typeinfo.typeflags_fdispatchable", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FDISPATCHABLE, NULL, HFILL}},
        {&hf_typeinfo_typeflags_fproxy,
         {"FPROXY", "typeinfo.typeflags_fproxy", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TYPEINFO_TYPEFLAG_FPROXY, NULL, HFILL}},
    };

    static gint *ett[] = {
        &ett_typeinfo,
        &ett_typeinfo_docflags,
        &ett_typeinfo_typeflags,
        &ett_typeinfo_names,
        &ett_typeinfo_typeattr,
        &ett_typeinfo_elemdesc,
        &ett_typeinfo_typedesc,
        &ett_typeinfo_paramdesc,
        &ett_typeinfo_paramdesc_paramflags,
        &ett_typeinfo_paramdescex,
        &ett_typeinfo_funcdesc,
        &ett_typeinfo_funcdesc_funcflags,
    };

    /* ITypeInfo currently only partially implemented */
    proto_typeinfo = proto_register_protocol("DCOM ITypeInfo", "ITypeInfo", "typeinfo");
    proto_register_field_array(proto_typeinfo, hf_typeinfo_typedesc_array, array_length(hf_typeinfo_typedesc_array));
    proto_register_field_array(proto_typeinfo, hf_typeinfo_paramdesc_array, array_length(hf_typeinfo_paramdesc_array));
    proto_register_field_array(proto_typeinfo, hf_typeinfo_paramdescex_array, array_length(hf_typeinfo_paramdescex_array));
    proto_register_field_array(proto_typeinfo, hf_typeinfo_funcdesc_array, array_length(hf_typeinfo_funcdesc_array));
    proto_register_field_array(proto_typeinfo, hf_typeinfo_array, array_length(hf_typeinfo_array));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcom_typeinfo(void)
{
    dcerpc_init_uuid(proto_typeinfo, ett_typeinfo,
                     &uuid_typeinfo, ver_typeinfo,
                     typeinfo_dissectors, hf_typeinfo_opnum);
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
