/* packet-dcerpc.c
 * Routines for DCERPC packet disassembly
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc.c,v 1.4 2001/04/27 01:27:36 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include "packet.h"
#include "packet-dcerpc.h"

static const value_string pckt_vals[] = {
    { 0, "Request"},
    { 1, "Ping"},
    { 2, "Response"},
    { 3, "Fault"},
    { 4, "Working"},
    { 5, "Nocall"},
    { 6, "Reject"},
    { 7, "Ack"},
    { 8, "Cl_cancel"},
    { 9, "Fack"},
    { 10, "Cancel_ack"},
    { 11, "Bind"},
    { 12, "Bind_ack"},
    { 13, "Bind_nak"},
    { 14, "Alter_context"},
    { 15, "Alter_context_resp"},
    { 16, "AUTH3?"},
    { 17, "Shutdown"},
    { 18, "Co_cancel"},
    { 19, "Orphaned"},
};

static const true_false_string flags_set_truth = {
  "Set",
  "Not set"
};

static int proto_dcerpc = -1;

/* field defines */
static int hf_dcerpc_ver = -1;
static int hf_dcerpc_ver_minor = -1;
static int hf_dcerpc_packet_type = -1;
static int hf_dcerpc_cn_flags = -1;
static int hf_dcerpc_cn_flags_first_frag = -1;
static int hf_dcerpc_cn_flags_last_frag = -1;
static int hf_dcerpc_cn_flags_cancel_pending = -1;
static int hf_dcerpc_cn_flags_reserved = -1;
static int hf_dcerpc_cn_flags_mpx = -1;
static int hf_dcerpc_cn_flags_dne = -1;
static int hf_dcerpc_cn_flags_maybe = -1;
static int hf_dcerpc_cn_flags_object = -1;
static int hf_dcerpc_cn_frag_len = -1;
static int hf_dcerpc_cn_auth_len = -1;
static int hf_dcerpc_cn_call_id = -1;
static int hf_dcerpc_cn_max_xmit = -1;
static int hf_dcerpc_cn_max_recv = -1;
static int hf_dcerpc_cn_assoc_group = -1;
static int hf_dcerpc_cn_num_ctx_items = -1;
static int hf_dcerpc_cn_ctx_id = -1;
static int hf_dcerpc_cn_num_trans_items = -1;
static int hf_dcerpc_cn_bind_if_id = -1;
static int hf_dcerpc_cn_bind_if_ver = -1;
static int hf_dcerpc_cn_bind_trans_id = -1;
static int hf_dcerpc_cn_bind_trans_ver = -1;
static int hf_dcerpc_cn_alloc_hint = -1;
static int hf_dcerpc_cn_sec_addr_len = -1;
static int hf_dcerpc_cn_num_results = -1;
static int hf_dcerpc_cn_ack_result = -1;
static int hf_dcerpc_cn_ack_reason = -1;
static int hf_dcerpc_dg_flags1 = -1;
static int hf_dcerpc_dg_flags1_rsrvd_01 = -1;
static int hf_dcerpc_dg_flags1_last_frag = -1;
static int hf_dcerpc_dg_flags1_frag = -1;
static int hf_dcerpc_dg_flags1_nofack = -1;
static int hf_dcerpc_dg_flags1_maybe = -1;
static int hf_dcerpc_dg_flags1_idempotent = -1;
static int hf_dcerpc_dg_flags1_broadcast = -1;
static int hf_dcerpc_dg_flags1_rsrvd_80 = -1;
static int hf_dcerpc_dg_flags2 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_01 = -1;
static int hf_dcerpc_dg_flags2_cancel_pending = -1;
static int hf_dcerpc_dg_flags2_rsrvd_04 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_08 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_10 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_20 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_40 = -1;
static int hf_dcerpc_dg_flags2_rsrvd_80 = -1;
static int hf_dcerpc_dg_serial_hi = -1;
static int hf_dcerpc_obj_id = -1;
static int hf_dcerpc_dg_if_id = -1;
static int hf_dcerpc_dg_act_id = -1;
static int hf_dcerpc_dg_serial_lo = -1;
static int hf_dcerpc_dg_ahint = -1;
static int hf_dcerpc_dg_ihint = -1;
static int hf_dcerpc_dg_frag_len = -1;
static int hf_dcerpc_dg_frag_num = -1;
static int hf_dcerpc_dg_auth_proto = -1;
static int hf_dcerpc_opnum = -1;
static int hf_dcerpc_dg_seqnum = -1;
static int hf_dcerpc_dg_server_boot = -1;
static int hf_dcerpc_dg_if_ver = -1;

static gint ett_dcerpc = -1;
static gint ett_dcerpc_cn_flags = -1;
static gint ett_dcerpc_dg_flags1 = -1;
static gint ett_dcerpc_dg_flags2 = -1;


guint16
dcerpc_tvb_get_ntohs (tvbuff_t *tvb, gint offset, char *drep)
{
    if (drep[0] & 0x10) {
        return tvb_get_letohs (tvb, offset);
    } else {
        return tvb_get_ntohs (tvb, offset);
    }
}

guint32
dcerpc_tvb_get_ntohl (tvbuff_t *tvb, gint offset, char *drep)
{
    if (drep[0] & 0x10) {
        return tvb_get_letohl (tvb, offset);
    } else {
        return tvb_get_ntohl (tvb, offset);
    }
}

void
dcerpc_tvb_get_uuid (tvbuff_t *tvb, gint offset, char *drep, e_uuid_t *uuid)
{
    unsigned int i;
    uuid->Data1 = dcerpc_tvb_get_ntohl (tvb, offset, drep);
    uuid->Data2 = dcerpc_tvb_get_ntohs (tvb, offset+4, drep);
    uuid->Data3 = dcerpc_tvb_get_ntohs (tvb, offset+6, drep);

    for (i=0; i<sizeof (uuid->Data4); i++) {
        uuid->Data4[i] = tvb_get_guint8 (tvb, offset+8+i);
    }
}


static void
dissect_dcerpc_cn_bind (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                        e_dce_cn_common_hdr_t *hdr)
{
    guint16 max_xmit, max_recv;
    guint32 assoc_group;
    guint8 num_ctx_items;
    guint16 ctx_id;
    guint16 num_trans_items;
    e_uuid_t if_id;
    e_uuid_t trans_id;
    guint32 if_ver, trans_ver;
    int offset = 16;

    max_xmit = dcerpc_tvb_get_ntohs (tvb, offset, hdr->drep);
    offset += 2;

    max_recv = dcerpc_tvb_get_ntohs (tvb, offset, hdr->drep);
    offset += 2;

    assoc_group = dcerpc_tvb_get_ntohl (tvb, offset, hdr->drep);
    offset += 4;

    num_ctx_items = tvb_get_guint8 (tvb, offset);
    offset++;

    /* padding */
    offset += 3;

    ctx_id = dcerpc_tvb_get_ntohs (tvb, offset, hdr->drep);
    offset += 2;

    num_trans_items = dcerpc_tvb_get_ntohs (tvb, offset, hdr->drep);
    offset += 2;

    dcerpc_tvb_get_uuid (tvb, offset, hdr->drep, &if_id);
    offset += 16;

    if_ver = dcerpc_tvb_get_ntohl (tvb, offset, hdr->drep);
    offset += 4;

    dcerpc_tvb_get_uuid (tvb, offset, hdr->drep, &trans_id);
    offset += 16;

    trans_ver = dcerpc_tvb_get_ntohl (tvb, offset, hdr->drep);
    offset += 4;

    if (check_col (pinfo->fd, COL_INFO)) {
        col_add_fstr (pinfo->fd, COL_INFO, "Bind: UUID %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x ver %d",
                         if_id.Data1, if_id.Data2, if_id.Data3,
                         if_id.Data4[0], if_id.Data4[1],
                         if_id.Data4[2], if_id.Data4[3],
                         if_id.Data4[4], if_id.Data4[5],
                         if_id.Data4[6], if_id.Data4[7],
                         if_ver);
    }

    if (dcerpc_tree) {
        offset = 16;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_max_xmit, tvb, offset, 2, max_xmit);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_max_recv, tvb, offset, 2, max_recv);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_assoc_group, tvb, offset, 4, assoc_group);
        offset += 4;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_num_ctx_items, tvb, offset, 1, num_ctx_items);
        offset++;

        /* padding */
        offset += 3;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_ctx_id, tvb, offset, 2, ctx_id);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_num_trans_items, tvb, offset, 2, num_trans_items);
        offset += 2;

        proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_cn_bind_if_id, tvb,
                                      offset, 16, "HMMM",
                                      "Interface UUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      if_id.Data1, if_id.Data2, if_id.Data3,
                                      if_id.Data4[0],
                                      if_id.Data4[1],
                                      if_id.Data4[2],
                                      if_id.Data4[3],
                                      if_id.Data4[4],
                                      if_id.Data4[5],
                                      if_id.Data4[6],
                                      if_id.Data4[7]);
        offset += 16;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_bind_if_ver, tvb, offset, 4, if_ver);
        offset += 4;

        proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_cn_bind_trans_id, tvb,
                                      offset, 16, "HMMM",
                                      "Transfer Syntax: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      trans_id.Data1, trans_id.Data2, trans_id.Data3,
                                      trans_id.Data4[0],
                                      trans_id.Data4[1],
                                      trans_id.Data4[2],
                                      trans_id.Data4[3],
                                      trans_id.Data4[4],
                                      trans_id.Data4[5],
                                      trans_id.Data4[6],
                                      trans_id.Data4[7]);
        offset += 16;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_bind_trans_ver, tvb, offset, 4, trans_ver);
        offset += 4;
    }
}

static void
dissect_dcerpc_cn_bind_ack (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                            e_dce_cn_common_hdr_t *hdr)
{
    guint16 max_xmit, max_recv;
    guint32 assoc_group;
    guint16 sec_addr_len;
    guint8 num_results;
    guint16 result = 0;
    guint16 reason = 0;

    int offset = 16;

    max_xmit = dcerpc_tvb_get_ntohs (tvb, offset, hdr->drep);
    offset += 2;

    max_recv = dcerpc_tvb_get_ntohs (tvb, offset, hdr->drep);
    offset += 2;

    assoc_group = dcerpc_tvb_get_ntohl (tvb, offset, hdr->drep);
    offset += 4;

    sec_addr_len = dcerpc_tvb_get_ntohs (tvb, offset, hdr->drep);
    offset += 2 + sec_addr_len;

    if (offset % 4) {
        offset += 4 - offset % 4;
    }

    num_results = tvb_get_guint8 (tvb, offset);
    offset++;

    /* padding */
    offset += 3;

    if (num_results == 1) {
        result = dcerpc_tvb_get_ntohs (tvb, offset, hdr->drep);
        offset += 2;
        
        reason = dcerpc_tvb_get_ntohs (tvb, offset, hdr->drep);
        offset += 2;
    }
    
    if (check_col (pinfo->fd, COL_INFO)) {
        if (num_results == 1 && result == 0) {
            col_add_fstr (pinfo->fd, COL_INFO, "Bind ack: accept  max_xmit: %d  max_recv: %d",
                             max_xmit, max_recv);
            
        } else {
            /* FIXME: should put in reason */
            col_add_fstr (pinfo->fd, COL_INFO, "Bind ack: %s",
                             result == 1 ? "User reject" :
                             result == 2 ? "Provider reject" :
                             "Unknown");
        }
    }

    if (dcerpc_tree) {
        offset = 16;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_max_xmit, tvb, offset, 2, max_xmit);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_max_recv, tvb, offset, 2, max_recv);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_assoc_group, tvb, offset, 4, assoc_group);
        offset += 4;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_sec_addr_len, tvb, offset, 2, sec_addr_len);
        offset +=2 + sec_addr_len;

        if (offset % 4) {
            offset += 4 - offset % 4;
        }

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_num_results, tvb, offset, 1, num_results);
        offset++;

        /* padding */
        offset += 3;

        if (num_results == 1) {
            proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_ack_result, tvb, offset, 2, result);
            offset += 2;

            proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_ack_reason, tvb, offset, 2, reason);
            offset += 2;
        }
    }
}

static void
dissect_dcerpc_cn_rqst (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                        e_dce_cn_common_hdr_t *hdr)
{
    guint32 alloc_hint;
    guint16 ctx_id;
    guint16 opnum;
    e_uuid_t obj_id;

    int offset = 16;

    alloc_hint = dcerpc_tvb_get_ntohl (tvb, offset, hdr->drep);
    offset += 4;

    ctx_id = dcerpc_tvb_get_ntohs (tvb, offset, hdr->drep);
    offset += 2;

    opnum = dcerpc_tvb_get_ntohs (tvb, offset, hdr->drep);
    offset += 2;

    if (hdr->flags & 0x80) {
        dcerpc_tvb_get_uuid (tvb, offset, hdr->drep, &obj_id);
        offset += 16;
    }

    if (check_col (pinfo->fd, COL_INFO)) {
        col_add_fstr (pinfo->fd, COL_INFO, "Request: opnum: %d  ctx_id:%d",
                         opnum, ctx_id);
    }

    if (dcerpc_tree) {
        offset = 16;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_alloc_hint, tvb, offset, 4, alloc_hint);
        offset += 4;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_ctx_id, tvb, offset, 2, ctx_id);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_opnum, tvb, offset, 2, opnum);
        offset += 2;

        if (hdr->flags & 0x80) {
            proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_obj_id, tvb,
                                          offset, 16, "HMMM",
                                          "Object UUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                          obj_id.Data1, obj_id.Data2, obj_id.Data3,
                                          obj_id.Data4[0],
                                          obj_id.Data4[1],
                                          obj_id.Data4[2],
                                          obj_id.Data4[3],
                                          obj_id.Data4[4],
                                          obj_id.Data4[5],
                                          obj_id.Data4[6],
                                          obj_id.Data4[7]);
            offset += 16;
        }
    }
}

/*
 * DCERPC dissector for connection oriented calls
 */
static gboolean
dissect_dcerpc_cn (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *tf = NULL;
    proto_tree *dcerpc_tree = NULL;
    proto_tree *cn_flags_tree = NULL;
    e_dce_cn_common_hdr_t hdr;
    int offset = 0;

    /*
     * Check if this looks like a C/O DCERPC call
     */
    if (!tvb_bytes_exist (tvb, 0, sizeof (hdr))) {
        return FALSE;
    }
    hdr.rpc_ver = tvb_get_guint8 (tvb, offset++);
    if (hdr.rpc_ver != 5)
        return FALSE;
    hdr.rpc_ver_minor = tvb_get_guint8 (tvb, offset++);
    if (hdr.rpc_ver_minor != 0 && hdr.rpc_ver_minor != 1)
        return FALSE;
    hdr.ptype = tvb_get_guint8 (tvb, offset++);
    if (hdr.ptype > 19)
        return FALSE;

    if (check_col (pinfo->fd, COL_PROTOCOL))
        col_set_str (pinfo->fd, COL_PROTOCOL, "DCERPC");
    if (check_col (pinfo->fd, COL_INFO))
        col_set_str (pinfo->fd, COL_INFO, pckt_vals[hdr.ptype].strptr);

    hdr.flags = tvb_get_guint8 (tvb, offset++);
    tvb_memcpy (tvb, (guint8 *)hdr.drep, offset, sizeof (hdr.drep));
    offset += sizeof (hdr.drep);

    hdr.frag_len = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.auth_len = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.call_id = dcerpc_tvb_get_ntohl (tvb, offset, hdr.drep);
    offset += 4;

    if (tree) {
        ti = proto_tree_add_item (tree, proto_dcerpc, tvb, 0, tvb_length(tvb), FALSE);
        if (ti) {
            dcerpc_tree = proto_item_add_subtree (ti, ett_dcerpc);
        }
        offset = 0;
        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_ver, tvb, offset++, 1, hdr.rpc_ver);
        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_ver_minor, tvb, offset++, 1, hdr.rpc_ver_minor);
        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_packet_type, tvb, offset++, 1, hdr.ptype);
        tf = proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_flags, tvb, offset, 1, hdr.flags);
        cn_flags_tree = proto_item_add_subtree (tf, ett_dcerpc_cn_flags);
        if (cn_flags_tree) {
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_first_frag, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_last_frag, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_cancel_pending, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_reserved, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_mpx, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_dne, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_maybe, tvb, offset, 1, hdr.flags);
            proto_tree_add_boolean (cn_flags_tree, hf_dcerpc_cn_flags_object, tvb, offset, 1, hdr.flags);
        }
        offset++;

        proto_tree_add_text (dcerpc_tree, tvb, offset, sizeof (hdr.drep), "Data Rep");
        offset += sizeof (hdr.drep);

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_frag_len, tvb, offset, 2, hdr.frag_len);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_auth_len, tvb, offset, 2, hdr.auth_len);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_cn_call_id, tvb, offset, 4, hdr.call_id);
        offset += 4;
    }
    /*
     * Packet type specific stuff is next.
     */
    switch (hdr.ptype) {
    case PDU_BIND:
        dissect_dcerpc_cn_bind (tvb, pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_BIND_ACK:
        dissect_dcerpc_cn_bind_ack (tvb, pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_REQ:
        dissect_dcerpc_cn_rqst (tvb, pinfo, dcerpc_tree, &hdr);
        break;

    default:
        break;
    }
    return TRUE;
}

/*
 * DCERPC dissector for connectionless calls
 */
static gboolean
dissect_dcerpc_dg (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_item *tf = NULL;
    proto_tree *dcerpc_tree = NULL;
    proto_tree *dg_flags1_tree = NULL;
    proto_tree *dg_flags2_tree = NULL;
    e_dce_dg_common_hdr_t hdr;
    int offset = 0;

    /*
     * Check if this looks like a CL DCERPC call.  All dg packets
     * have an 80 byte header on them.  Which starts with
     * version (4), pkt_type.
     */
    if (!tvb_bytes_exist (tvb, 0, sizeof (hdr))) {
        return FALSE;
    }
    hdr.rpc_ver = tvb_get_guint8 (tvb, offset++);
    if (hdr.rpc_ver != 4)
        return FALSE;
    hdr.ptype = tvb_get_guint8 (tvb, offset++);
    if (hdr.ptype > 19)
        return FALSE;

    if (check_col (pinfo->fd, COL_PROTOCOL))
        col_set_str (pinfo->fd, COL_PROTOCOL, "DCERPC");
    if (check_col (pinfo->fd, COL_INFO))
        col_set_str (pinfo->fd, COL_INFO, pckt_vals[hdr.ptype].strptr);

    hdr.flags1 = tvb_get_guint8 (tvb, offset++);
    hdr.flags2 = tvb_get_guint8 (tvb, offset++);
    tvb_memcpy (tvb, (guint8 *)hdr.drep, offset, sizeof (hdr.drep));
    offset += sizeof (hdr.drep);
    hdr.serial_hi = tvb_get_guint8 (tvb, offset++);
    dcerpc_tvb_get_uuid (tvb, offset, hdr.drep, &hdr.obj_id);
    offset += 16;
    dcerpc_tvb_get_uuid (tvb, offset, hdr.drep, &hdr.if_id);
    offset += 16;
    dcerpc_tvb_get_uuid (tvb, offset, hdr.drep, &hdr.act_id);
    offset += 16;
    hdr.server_boot = dcerpc_tvb_get_ntohl (tvb, offset, hdr.drep);
    offset += 4;
    hdr.if_ver = dcerpc_tvb_get_ntohl (tvb, offset, hdr.drep);
    offset += 4;
    hdr.seqnum = dcerpc_tvb_get_ntohl (tvb, offset, hdr.drep);
    offset += 4;
    hdr.opnum = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.ihint = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.ahint = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.frag_len = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.frag_num = dcerpc_tvb_get_ntohs (tvb, offset, hdr.drep);
    offset += 2;
    hdr.auth_proto = tvb_get_guint8 (tvb, offset++);
    hdr.serial_lo = tvb_get_guint8 (tvb, offset++);

    if (tree) {
        ti = proto_tree_add_item (tree, proto_dcerpc, tvb, 0, tvb_length(tvb), FALSE);
        if (ti) {
            dcerpc_tree = proto_item_add_subtree(ti, ett_dcerpc);
        }
        offset = 0;
        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_ver, tvb, offset++, 1, hdr.rpc_ver);

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_packet_type, tvb, offset++, 1, hdr.ptype);

        tf = proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_flags1, tvb, offset, 1, hdr.flags1);
        dg_flags1_tree = proto_item_add_subtree (tf, ett_dcerpc_dg_flags1);
        if (dg_flags1_tree) {
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_rsrvd_01, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_last_frag, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_frag, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_nofack, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_maybe, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_idempotent, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_broadcast, tvb, offset, 1, hdr.flags1);
            proto_tree_add_boolean (dg_flags1_tree, hf_dcerpc_dg_flags1_rsrvd_80, tvb, offset, 1, hdr.flags1);
        }
        offset++;

        tf = proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_flags2, tvb, offset, 1, hdr.flags2);
        dg_flags2_tree = proto_item_add_subtree (tf, ett_dcerpc_dg_flags2);
        if (dg_flags2_tree) {
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_01, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_cancel_pending, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_04, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_08, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_10, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_20, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_40, tvb, offset, 1, hdr.flags2);
            proto_tree_add_boolean (dg_flags2_tree, hf_dcerpc_dg_flags2_rsrvd_80, tvb, offset, 1, hdr.flags2);
        }
        offset++;

        proto_tree_add_text (dcerpc_tree, tvb, offset, sizeof (hdr.drep), "Data Rep");
        offset += sizeof (hdr.drep);

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_serial_hi, tvb, offset++, 1, hdr.serial_hi);

        proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_obj_id, tvb,
                                      offset, 16, "HMMM",
                                      "Object: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      hdr.obj_id.Data1, hdr.obj_id.Data2, hdr.obj_id.Data3,
                                      hdr.obj_id.Data4[0],
                                      hdr.obj_id.Data4[1],
                                      hdr.obj_id.Data4[2],
                                      hdr.obj_id.Data4[3],
                                      hdr.obj_id.Data4[4],
                                      hdr.obj_id.Data4[5],
                                      hdr.obj_id.Data4[6],
                                      hdr.obj_id.Data4[7]);
        offset += 16;

        proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_dg_if_id, tvb,
                                      offset, 16, "HMMM",
                                      "Interface: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      hdr.if_id.Data1, hdr.if_id.Data2, hdr.if_id.Data3,
                                      hdr.if_id.Data4[0],
                                      hdr.if_id.Data4[1],
                                      hdr.if_id.Data4[2],
                                      hdr.if_id.Data4[3],
                                      hdr.if_id.Data4[4],
                                      hdr.if_id.Data4[5],
                                      hdr.if_id.Data4[6],
                                      hdr.if_id.Data4[7]);
        offset += 16;

        proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_dg_act_id, tvb,
                                      offset, 16, "HMMM",
                                      "Activity: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      hdr.act_id.Data1, hdr.act_id.Data2, hdr.act_id.Data3,
                                      hdr.act_id.Data4[0],
                                      hdr.act_id.Data4[1],
                                      hdr.act_id.Data4[2],
                                      hdr.act_id.Data4[3],
                                      hdr.act_id.Data4[4],
                                      hdr.act_id.Data4[5],
                                      hdr.act_id.Data4[6],
                                      hdr.act_id.Data4[7]);
        offset += 16;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_server_boot, tvb, offset, 4, hdr.server_boot);
        offset += 4;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_if_ver, tvb, offset, 4, hdr.if_ver);
        offset += 4;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_seqnum, tvb, offset, 4, hdr.seqnum);
        offset += 4;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_opnum, tvb, offset, 2, hdr.opnum);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_ihint, tvb, offset, 2, hdr.ihint);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_ahint, tvb, offset, 2, hdr.ahint);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_frag_len, tvb, offset, 2, hdr.frag_len);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_frag_num, tvb, offset, 2, hdr.frag_num);
        offset += 2;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_auth_proto, tvb, offset, 1, hdr.auth_proto);
        offset++;

        proto_tree_add_uint (dcerpc_tree, hf_dcerpc_dg_serial_lo, tvb, offset, 1, hdr.serial_lo);
        offset++;
    }
    /*
     * Packet type specific stuff is next.
     */

    return TRUE;
}


void
proto_register_dcerpc(void)
{
    static hf_register_info hf[] = {
        { &hf_dcerpc_ver,
          { "Version", "dcerpc.ver", FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_ver_minor,
          { "Version (minor)", "dcerpc.ver_minor", FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_packet_type,
          { "Packet type", "dcerpc.pkt_type", FT_UINT8, BASE_HEX, VALS (pckt_vals), 0x0, "" }},
        { &hf_dcerpc_cn_flags,
          { "Packet Flags", "dcerpc.cn_flags", FT_UINT8, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_flags_first_frag,
          { "First Frag", "dcerpc.cn_flags.first_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x1, "" }},
        { &hf_dcerpc_cn_flags_last_frag,
          { "Last Frag", "dcerpc.cn_flags.last_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x2, "" }},
        { &hf_dcerpc_cn_flags_cancel_pending,
          { "Cancel Pending", "dcerpc.cn_flags.cancel_pending", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x4, "" }},
        { &hf_dcerpc_cn_flags_reserved,
          { "Reserved", "dcerpc.cn_flags.reserved", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x8, "" }},
        { &hf_dcerpc_cn_flags_mpx,
          { "Multiplex", "dcerpc.cn_flags.mpx", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x10, "" }},
        { &hf_dcerpc_cn_flags_dne,
          { "Did Not Execute", "dcerpc.cn_flags.dne", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x20, "" }},
        { &hf_dcerpc_cn_flags_maybe,
          { "Maybe", "dcerpc.cn_flags.maybe", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x40, "" }},
        { &hf_dcerpc_cn_flags_object,
          { "Object", "dcerpc.cn_flags.object", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x80, "" }},
        { &hf_dcerpc_cn_frag_len,
          { "Frag Length", "dcerpc.cn_frag_len", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_auth_len,
          { "Auth Length", "dcerpc.cn_auth_len", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_call_id,
          { "Call ID", "dcerpc.cn_call_id", FT_UINT32, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_max_xmit,
          { "Max Xmit Frag", "dcerpc.cn_max_xmit", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_max_recv,
          { "Max Recv Frag", "dcerpc.cn_max_recv", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_assoc_group,
          { "Assoc Group", "dcerpc.cn_assoc_group", FT_UINT32, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_num_ctx_items,
          { "Num Ctx Items", "dcerpc.cn_num_ctx_items", FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_ctx_id,
          { "Context ID", "dcerpc.cn_ctx_id", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_num_trans_items,
          { "Num Trans Items", "dcerpc.cn_num_trans_items", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_bind_if_id,
          { "Interface UUID", "dcerpc.cn_bind_to_uuid", FT_STRING, BASE_NONE, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_bind_if_ver,
          { "Interface Ver", "dcerpc.cn_bind_if_ver", FT_UINT32, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_bind_trans_id,
          { "Transfer Syntax", "dcerpc.cn_bind_trans_id", FT_STRING, BASE_NONE, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_bind_trans_ver,
          { "Syntax ver", "dcerpc.cn_bind_trans_ver", FT_UINT32, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_alloc_hint,
          { "Alloc hint", "dcerpc.cn_alloc_hint", FT_UINT32, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_sec_addr_len,
          { "Scndry Addr len", "dcerpc.cn_sec_addr_len", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_num_results,
          { "Num results", "dcerpc.cn_num_results", FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_ack_result,
          { "Ack result", "dcerpc.cn_ack_result", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_cn_ack_reason,
          { "Ack reason", "dcerpc.cn_ack_reason", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_flags1,
          { "Flags1", "dcerpc.dg_flags1", FT_UINT8, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_flags1_rsrvd_01,
          { "Reserved", "dcerpc.dg_flags1_rsrvd_01", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x01, "" }},
        { &hf_dcerpc_dg_flags1_last_frag,
          { "Last Fragment", "dcerpc.dg_flags1_last_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x02, "" }},
        { &hf_dcerpc_dg_flags1_frag,
          { "Fragment", "dcerpc.dg_flags1_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x04, "" }},
        { &hf_dcerpc_dg_flags1_nofack,
          { "No Fack", "dcerpc.dg_flags1_nofack", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x08, "" }},
        { &hf_dcerpc_dg_flags1_maybe,
          { "Maybe", "dcerpc.dg_flags1_maybe", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x10, "" }},
        { &hf_dcerpc_dg_flags1_idempotent,
          { "Idempotent", "dcerpc.dg_flags1_idempotent", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x20, "" }},
        { &hf_dcerpc_dg_flags1_broadcast,
          { "Broadcast", "dcerpc.dg_flags1_broadcast", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x40, "" }},
        { &hf_dcerpc_dg_flags1_rsrvd_80,
          { "Reserved", "dcerpc.dg_flags1_rsrvd_80", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x80, "" }},
        { &hf_dcerpc_dg_flags2,
          { "Flags2", "dcerpc.dg_flags2", FT_UINT8, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_flags2_rsrvd_01,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_01", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x01, "" }},
        { &hf_dcerpc_dg_flags2_cancel_pending,
          { "Cancel Pending", "dcerpc.dg_flags2_cancel_pending", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x02, "" }},
        { &hf_dcerpc_dg_flags2_rsrvd_04,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_04", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x04, "" }},
        { &hf_dcerpc_dg_flags2_rsrvd_08,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_08", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x08, "" }},
        { &hf_dcerpc_dg_flags2_rsrvd_10,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_10", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x10, "" }},
        { &hf_dcerpc_dg_flags2_rsrvd_20,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_20", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x20, "" }},
        { &hf_dcerpc_dg_flags2_rsrvd_40,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_40", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x40, "" }},
        { &hf_dcerpc_dg_flags2_rsrvd_80,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_80", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x80, "" }},
        { &hf_dcerpc_dg_serial_lo,
          { "Serial Low", "dcerpc.dg_serial_lo", FT_UINT8, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_serial_hi,
          { "Serial High", "dcerpc.dg_serial_hi", FT_UINT8, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_ahint,
          { "Activity Hint", "dcerpc.dg_ahint", FT_UINT16, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_ihint,
          { "Interface Hint", "dcerpc.dg_ihint", FT_UINT16, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_frag_len,
          { "Fragment len", "dcerpc.dg_frag_len", FT_UINT16, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_frag_num,
          { "Fragment num", "dcerpc.dg_frag_num", FT_UINT16, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_auth_proto,
          { "Auth proto", "dcerpc.dg_auth_proto", FT_UINT8, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_seqnum,
          { "Sequence num", "dcerpc.dg_seqnum", FT_UINT32, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_server_boot,
          { "Server boot time", "dcerpc.dg_server_boot", FT_UINT32, BASE_HEX, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_if_ver,
          { "Interface Ver", "dcerpc.dg_if_ver", FT_UINT32, BASE_DEC, NULL, 0x0, "" }},
        { &hf_dcerpc_obj_id,
          { "Object", "dcerpc.obj_id", FT_STRING, BASE_NONE, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_if_id,
          { "Interface", "dcerpc.dg_if_id", FT_STRING, BASE_NONE, NULL, 0x0, "" }},
        { &hf_dcerpc_dg_act_id,
          { "Activitiy", "dcerpc.dg_act_id", FT_STRING, BASE_NONE, NULL, 0x0, "" }},
        { &hf_dcerpc_opnum,
          { "Opnum", "dcerpc.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},


    };
    static gint *ett[] = {
        &ett_dcerpc,
        &ett_dcerpc_cn_flags,
        &ett_dcerpc_dg_flags1,
        &ett_dcerpc_dg_flags2,
    };

    proto_dcerpc = proto_register_protocol ("DCE RPC", "DCERPC", "dcerpc");
    proto_register_field_array (proto_dcerpc, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_dcerpc(void)
{
    heur_dissector_add ("tcp", dissect_dcerpc_cn, proto_dcerpc);
    heur_dissector_add ("udp", dissect_dcerpc_dg, proto_dcerpc);
}
