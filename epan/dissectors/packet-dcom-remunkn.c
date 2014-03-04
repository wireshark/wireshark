/* packet-dcom-remunkn.c
 * Routines for the IRemUnknown interface
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
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
#include <epan/wmem/wmem.h>
#include "packet-dcerpc.h"
#include "packet-dcom.h"
#include "guid-utils.h"

void proto_register_remunk(void);
void proto_reg_handoff_remunk(void);

static int hf_remunk_opnum = -1;


static int hf_remunk_refs = -1;
static int hf_remunk_iids = -1;

/* static int hf_remunk_flags = -1; */
static int hf_remunk_qiresult = -1;

static gint ett_remunk_reminterfaceref = -1;
static int hf_remunk_reminterfaceref = -1;
static int hf_remunk_interface_refs = -1;
static int hf_remunk_public_refs = -1;
static int hf_remunk_private_refs = -1;


static gint ett_remunk_rqi_result = -1;


static gint ett_remunk = -1;
static e_uuid_t uuid_remunk = { 0x00000131, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static guint16  ver_remunk = 0;
static int proto_remunk = -1;

static e_uuid_t ipid_remunk = { 0x00000131, 0x1234, 0x5678, { 0xCA, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

/* There is a little bit confusion about the IRemUnknown2 interface UUIDs */
/* DCOM documentation tells us: 0x00000142 (7 methods) */
/* win2000 registry tells us: 0x00000142 IRemoteQI (4 methods) */
/* win2000 registry tells us: 0x00000143 IRemUnknown2 (7 methods) */
/* There is some evidence, that the DCOM documentation is wrong, so using 143 for IRemUnknown2 now. */

static gint ett_remunk2 = -1;
static e_uuid_t uuid_remunk2 = { 0x00000143, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static guint16  ver_remunk2 = 0;
static int proto_remunk2 = -1;


typedef struct remunk_remqueryinterface_call_s {
    guint        iid_count;
    e_uuid_t    *iids;
} remunk_remqueryinterface_call_t;


static int
dissect_remunk_remqueryinterface_rqst(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    e_uuid_t     ipid;
    guint32      u32Refs;
    guint16      u16IIDs;
    guint32      u32ArraySize;
    guint32      u32ItemIdx;
    e_uuid_t     iid;
    remunk_remqueryinterface_call_t *call;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, di, drep);

    offset = dissect_dcom_UUID(tvb, offset, pinfo, tree, di, drep,
                               hf_dcom_ipid, &ipid);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
                                hf_remunk_refs, &u32Refs);

    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, di, drep,
                               hf_remunk_iids, &u16IIDs);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, di, drep,
                                            &u32ArraySize);

    /* limit the allocation to a reasonable size */
    if(u32ArraySize < 100) {
        call = (remunk_remqueryinterface_call_t *)wmem_alloc(wmem_file_scope(), sizeof(remunk_remqueryinterface_call_t) + u32ArraySize * sizeof(e_uuid_t));
        call->iid_count = u32ArraySize;
        call->iids = (e_uuid_t *) (call+1);
        di->call_data->private_data = call;
    } else {
        call = NULL;
    }

    for (u32ItemIdx = 0; u32ArraySize--; u32ItemIdx++) {
        offset = dissect_dcom_append_UUID(tvb, offset,  pinfo, tree, di, drep,
                                          hf_dcom_iid, u32ItemIdx+1, &iid);
        if(call != NULL) {
            call->iids[u32ItemIdx] = iid;
        }
    }

    return offset;
}


static int
dissect_remunk_remqueryinterface_resp(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    guint32      u32Pointer;
    guint32      u32ArraySize;
    guint32      u32ItemIdx;
    proto_item  *sub_item;
    proto_tree  *sub_tree;
    guint32      u32HResult;
    guint32      u32SubStart;
    e_uuid_t     iid;
    e_uuid_t     iid_null = DCERPC_UUID_NULL;
    remunk_remqueryinterface_call_t *call = (remunk_remqueryinterface_call_t *)di->call_data->private_data;
    guint64      oxid;
    guint64      oid;
    e_uuid_t     ipid;


    offset = dissect_dcom_that(tvb, offset, pinfo, tree, di, drep);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, di, drep,
                                         &u32Pointer);
    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, di, drep,
                                            &u32ArraySize);

    u32ItemIdx = 1;
    while (u32ArraySize--) {
        /* add subtree */
        sub_item = proto_tree_add_item(tree, hf_remunk_qiresult, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_remunk_rqi_result);

        /* REMQIRESULT */
        offset = dissect_dcom_HRESULT(tvb, offset, pinfo, sub_tree, di, drep,
                                      &u32HResult);
        u32SubStart = offset - 4;
        offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, sub_tree, di, drep,
                                             &u32Pointer);

        /* try to read the iid from the request */
        if(call != NULL && u32ItemIdx <= call->iid_count) {
            iid = call->iids[u32ItemIdx-1];
        } else {
            iid = iid_null;
        }

        /* XXX - this doesn't seem to be dependent on the pointer above?!? */
        /*if (u32Pointer) {*/
        offset = dissect_dcom_STDOBJREF(tvb, offset, pinfo, sub_tree, di, drep, 0 /* hfindex */,
                                        &oxid, &oid, &ipid);
        /*}*/

        /* add interface instance to database (we currently only handle IPv4) */
        if(pinfo->net_src.type == AT_IPv4) {
            dcom_interface_new(pinfo,
                               (guint8 *)pinfo->net_src.data,
                               &iid, oxid, oid, &ipid);
        }

        /* update subtree */
        proto_item_append_text(sub_item, "[%u]: %s",
                               u32ItemIdx,
                               val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );
        proto_item_set_len(sub_item, offset - u32SubStart);

        /* update column info now */
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s[%u]",
                        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)"),
                        u32ItemIdx);
        u32ItemIdx++;
    }

    /* HRESULT of call */
    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, di, drep,
                                  &u32HResult);

    /* update column info now */
    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
                    val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)"));

    return offset;
}


static int
dissect_remunk_remrelease_rqst(tvbuff_t *tvb, int offset,
                               packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep)
{
    guint32      u32Pointer;
    guint32      u32IntRefs;
    guint32      u32ItemIdx;
    e_uuid_t     ipid;
    guint32      u32PublicRefs;
    guint32      u32PrivateRefs;
    const gchar *pszFormat;
    proto_item  *sub_item;
    proto_tree  *sub_tree;
    guint32      u32SubStart;


    offset = dissect_dcom_this(tvb, offset, pinfo, tree, di, drep);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, di, drep,
                                         &u32Pointer);

    offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, di, drep,
                                hf_remunk_interface_refs, &u32IntRefs);

    /* update column info now */
    if (u32IntRefs) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Cnt=%u Refs=", u32IntRefs);
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, " Cnt=0");
    }


    u32ItemIdx = 1;
    while (u32IntRefs--) {
        /* add subtree */
        sub_item = proto_tree_add_item(tree, hf_remunk_reminterfaceref, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_remunk_reminterfaceref);
        u32SubStart = offset;

        offset = dissect_dcom_UUID(tvb, offset, pinfo, sub_tree, di, drep,
                                   hf_dcom_ipid, &ipid);

        offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                    hf_remunk_public_refs, &u32PublicRefs);

        offset = dissect_dcom_DWORD(tvb, offset, pinfo, sub_tree, di, drep,
                                    hf_remunk_private_refs, &u32PrivateRefs);

        /* update subtree */
        proto_item_append_text(sub_item, "[%u]: IPID=%s, PublicRefs=%u, PrivateRefs=%u",
                               u32ItemIdx,
                               guids_resolve_uuid_to_str(&ipid),
                               u32PublicRefs, u32PrivateRefs);
        proto_item_set_len(sub_item, offset - u32SubStart);

        /* update column info now */
        pszFormat = "";
        if (u32ItemIdx == 1) {
            pszFormat = "%u-%u";
        } else if (u32ItemIdx < 10) {
            pszFormat = ",%u-%u";
        } else if (u32ItemIdx == 10) {
            pszFormat = ",...";
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, pszFormat, u32PublicRefs, u32PrivateRefs);

        u32ItemIdx++;
    }

    return offset;
}


/* sub dissector table of IRemUnknown interface */
static dcerpc_sub_dissector remunk_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "RemQueryInterface", dissect_remunk_remqueryinterface_rqst, dissect_remunk_remqueryinterface_resp },
    { 4, "RemAddRef", NULL, NULL },
    { 5, "RemRelease", dissect_remunk_remrelease_rqst, dissect_dcom_simple_resp },
    { 0, NULL, NULL, NULL }
};

/* sub dissector table of IRemUnknown2 interface */
static dcerpc_sub_dissector remunk2_dissectors[] = {
    { 0, "QueryInterface", NULL, NULL },
    { 1, "AddRef", NULL, NULL },
    { 2, "Release", NULL, NULL },

    { 3, "RemQueryInterface", dissect_remunk_remqueryinterface_rqst, dissect_remunk_remqueryinterface_resp },
    { 4, "RemAddRef", NULL, NULL },
    { 5, "RemRelease", dissect_remunk_remrelease_rqst, dissect_dcom_simple_resp },

    { 6, "RemQueryInterface2", NULL, NULL },
    { 0, NULL, NULL, NULL }
};



void
proto_register_remunk (void)
{
    static hf_register_info hf_remunk_rqi_array[] = {
        { &hf_remunk_opnum,
          { "Operation", "remunk.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_remunk_refs,
          { "Refs", "remunk.refs", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_remunk_iids,
          { "IIDs", "remunk.iids", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_remunk_qiresult,
          { "QIResult", "remunk.qiresult", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
#if 0
        { &hf_remunk_flags,
          { "Flags", "remunk.flags",  FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
#endif
        { &hf_remunk_public_refs,
          { "PublicRefs", "remunk.public_refs",  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_remunk_reminterfaceref,
          { "RemInterfaceRef", "remunk.reminterfaceref",  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_remunk_interface_refs,
          { "InterfaceRefs", "remunk.int_refs",  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_remunk_private_refs,
          { "PrivateRefs", "remunk.private_refs",  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }}
    };

    static gint *ett_remunk_array[] = {
        &ett_remunk,
        &ett_remunk_rqi_result,
        &ett_remunk2,
        &ett_remunk_reminterfaceref
    };

    proto_remunk = proto_register_protocol ("IRemUnknown", "IRemUnknown", "remunk");
    proto_register_field_array (proto_remunk, hf_remunk_rqi_array, array_length (hf_remunk_rqi_array));

    proto_remunk2 = proto_register_protocol ("IRemUnknown2", "IRemUnknown2", "remunk2");

    proto_register_subtree_array (ett_remunk_array, array_length (ett_remunk_array));
}

void
proto_reg_handoff_remunk (void)
{

    /* Register the IPID */
    guids_add_uuid(&ipid_remunk, "IPID-IRemUnknown");

    /* Register the interfaces */
    dcerpc_init_uuid(proto_remunk, ett_remunk,
                     &uuid_remunk, ver_remunk,
                     remunk_dissectors, hf_remunk_opnum);

    dcerpc_init_uuid(proto_remunk2, ett_remunk2,
                     &uuid_remunk2, ver_remunk2,
                     remunk2_dissectors, hf_remunk_opnum);
}
