/* packet-dcom-oxid.c
 * Routines for DCOM OXID Resolver
 * Copyright 2001, Todd Sabin <tas@webspan.net>
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

static int proto_oxid = -1;

static int hf_oxid_opnum = -1;
static int hf_oxid_setid = -1;
static int hf_oxid_seqnum = -1;
static int hf_oxid_addtoset = -1;
static int hf_oxid_delfromset = -1;
static int hf_oxid_oid = -1;
static int hf_oxid_ping_backoff_factor = -1;
static int hf_oxid_oxid = -1;
static int hf_oxid_requested_protseqs = -1;
static int hf_oxid_protseqs = -1;
static int hf_oxid_bindings = -1;
static int hf_oxid_ipid = -1;
static int hf_oxid_authn_hint = -1;

static int hf_oxid_Unknown1 = -1;
static int hf_oxid_Unknown2 = -1;
static int hf_oxid_ds_array = -1;


static gint ett_oxid = -1;

static e_uuid_t uuid_oxid = { 0x99fcfec4, 0x5260, 0x101b, { 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a } };
static guint16  ver_oxid = 0;


static int
dissect_oxid_simple_ping_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_dcom_ID(tvb, offset, pinfo, tree, drep,
                        hf_oxid_setid, NULL);

    return offset;
}


static int
dissect_oxid_simple_ping_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32HResult;


    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
      val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_oxid_server_alive_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32HResult;


    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
      val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_oxid_complex_ping_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16SeqNum;
    guint16 u16AddToSet;
    guint16 u16DelFromSet;
    guint32 u32Pointer;
    guint32 u32ArraySize;

    offset = dissect_dcom_ID(tvb, offset, pinfo, tree, drep,
                        hf_oxid_setid, NULL);

    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_oxid_seqnum, &u16SeqNum);
    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_oxid_addtoset, &u16AddToSet);
    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_oxid_delfromset, &u16DelFromSet);

    col_append_fstr(pinfo->cinfo, COL_INFO, " AddToSet=%u DelFromSet=%u",
            u16AddToSet, u16DelFromSet);

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);
    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        while (u16AddToSet--) {
            offset = dissect_dcom_ID(tvb, offset, pinfo, tree, drep,
                            hf_oxid_oid, NULL);
        }
    }

    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);
    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        while (u16DelFromSet--) {
            offset = dissect_dcom_ID(tvb, offset, pinfo, tree, drep,
                            hf_oxid_oid, NULL);
        }
    }

    return offset;
}


static int
dissect_oxid_complex_ping_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16PingBackoffFactor;
    guint32 u32HResult;


    offset = dissect_dcom_ID(tvb, offset, pinfo, tree, drep,
                        hf_oxid_setid, NULL);
    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_oxid_ping_backoff_factor, &u16PingBackoffFactor);

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

    col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
      val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_oxid_resolve_oxid2_rqst(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16 u16ProtSeqs;
    guint32 u32ArraySize;
    guint32 u32ItemIdx;


    offset = dissect_dcom_ID(tvb, offset, pinfo, tree, drep,
                        hf_oxid_oxid, NULL);

    offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                        hf_oxid_requested_protseqs, &u16ProtSeqs);

    offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                        &u32ArraySize);

    u32ItemIdx = 1;
    while (u32ArraySize--) {
        offset = dissect_dcom_WORD(tvb, offset, pinfo, tree, drep,
                            hf_oxid_protseqs, &u16ProtSeqs);
        u32ItemIdx++;
    }

    return offset;
}


static int
dissect_oxid_resolve_oxid2_resp(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 u32Pointer;
    guint32 u32ArraySize;
    e_uuid_t ipid;
    guint32 u32AuthnHint;
    guint16 u16VersionMajor;
    guint16 u16VersionMinor;
    guint32 u32HResult;


    offset = dissect_dcom_dcerpc_pointer(tvb, offset, pinfo, tree, drep,
                        &u32Pointer);
    if (u32Pointer) {
        offset = dissect_dcom_dcerpc_array_size(tvb, offset, pinfo, tree, drep,
                            &u32ArraySize);

        offset = dissect_dcom_DUALSTRINGARRAY(tvb, offset, pinfo, tree, drep,
                            hf_oxid_bindings, NULL);

        offset = dissect_dcom_UUID(tvb, offset, pinfo, tree, drep,
                            hf_oxid_ipid, &ipid);

        offset = dissect_dcom_DWORD(tvb, offset, pinfo, tree, drep,
                            hf_oxid_authn_hint, &u32AuthnHint);

        offset = dissect_dcom_COMVERSION(tvb, offset, pinfo, tree, drep,
                    &u16VersionMajor, &u16VersionMinor);
    }

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep,
                        &u32HResult);

     col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s",
        val_to_str(u32HResult, dcom_hresult_vals, "Unknown (0x%08x)") );

    return offset;
}


static int
dissect_oxid_server_alive2_resp(tvbuff_t *tvb, int offset, packet_info *pinfo,
                proto_tree *tree, guint8 *drep) {
    guint16 u16VersionMajor;
    guint16 u16VersionMinor;

    offset = dissect_dcom_COMVERSION(tvb, offset, pinfo, tree, drep, &u16VersionMajor, &u16VersionMinor);

    /* XXX - understand what those 8 bytes mean! don't skip'em!*/
    dissect_dcerpc_uint64(tvb , offset, pinfo, tree, drep, hf_oxid_Unknown1, NULL);
    offset += 8;

    offset = dissect_dcom_DUALSTRINGARRAY(tvb, offset, pinfo, tree, drep, hf_oxid_ds_array, NULL);

    /* unknown field 2 */
    dissect_dcerpc_uint64(tvb, offset, pinfo, tree, drep, hf_oxid_Unknown2, NULL);
    offset += 8;
    return offset;
}


/* XXX - some dissectors still need to be done */
static dcerpc_sub_dissector oxid_dissectors[] = {
    { 0, "ResolveOxid", NULL, NULL },
    { 1, "SimplePing", dissect_oxid_simple_ping_rqst, dissect_oxid_simple_ping_resp },
    { 2, "ComplexPing", dissect_oxid_complex_ping_rqst, dissect_oxid_complex_ping_resp },
    { 3, "ServerAlive", NULL /* no input parameters */, dissect_oxid_server_alive_resp },
    { 4, "ResolveOxid2", dissect_oxid_resolve_oxid2_rqst, dissect_oxid_resolve_oxid2_resp },
    { 5, "ServerAlive2", NULL, dissect_oxid_server_alive2_resp },
    { 0, NULL, NULL, NULL },
};


void
proto_register_oxid (void)
{
    static hf_register_info hf[] = {
        { &hf_oxid_opnum,
          { "Operation", "oxid.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_oxid_setid,
          { "SetId", "oxid.setid",  FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_oxid_seqnum,
          { "SeqNum", "oxid.seqnum",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_oxid_addtoset,
          { "AddToSet", "oxid.addtoset",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_oxid_delfromset,
          { "DelFromSet", "oxid.delfromset",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_oxid_oid,
          { "OID", "oxid.oid",  FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_oxid_ping_backoff_factor,
          { "PingBackoffFactor", "oxid.ping_backoff_factor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_oxid_oxid,
          { "OXID", "oxid.oxid", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_oxid_requested_protseqs,
          { "RequestedProtSeq", "oxid.requested_protseqs",  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_oxid_protseqs,
          { "ProtSeq", "oxid.protseqs",  FT_UINT16, BASE_DEC, VALS(dcom_protseq_vals), 0x0, NULL, HFILL }},

        { &hf_oxid_bindings,
          { "OxidBindings", "oxid.bindings", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_oxid_ipid,
          { "IPID", "oxid.ipid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_oxid_authn_hint,
          { "AuthnHint", "oxid.authn_hint", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_oxid_ds_array,
          { "Address", "dcom.oxid.address", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_oxid_Unknown1,
          { "unknown 8 bytes 1", "oxid.unknown1", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_oxid_Unknown2,
                  { "unknown 8 bytes 2", "oxid.unknown2", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }}
    };
    static gint *ett[] = {
        &ett_oxid
    };
    proto_oxid = proto_register_protocol ("DCOM OXID Resolver", "IOXIDResolver", "oxid");
    proto_register_field_array (proto_oxid, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_oxid (void)
{
    /* Register the protocol as dcerpc */
    dcerpc_init_uuid (proto_oxid, ett_oxid, &uuid_oxid, ver_oxid, oxid_dissectors, hf_oxid_opnum);
}
