/* packet-dcerpc.c
 * Routines for DCERPC packet disassembly
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc.c,v 1.11 2001/09/30 21:56:24 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include "packet.h"
#include "packet-dcerpc.h"
#include "conversation.h"

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

static const value_string drep_byteorder_vals[] = {
    { 0, "Big-endian" },
    { 1, "Little-endian" }
};

static const value_string drep_character_vals[] = {
    { 0, "ASCII" },
    { 1, "EBCDIC" }
};

static const value_string drep_fp_vals[] = {
    { 0, "IEEE" },
    { 1, "VAX" },
    { 2, "Cray" },
    { 3, "IBM" }
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
static int hf_dcerpc_cn_drep = -1;
static int hf_dcerpc_cn_drep_byteorder = -1;
static int hf_dcerpc_cn_drep_character = -1;
static int hf_dcerpc_cn_drep_fp = -1;
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
static int hf_dcerpc_cn_bind_if_ver_minor = -1;
static int hf_dcerpc_cn_bind_trans_id = -1;
static int hf_dcerpc_cn_bind_trans_ver = -1;
static int hf_dcerpc_cn_alloc_hint = -1;
static int hf_dcerpc_cn_sec_addr_len = -1;
static int hf_dcerpc_cn_num_results = -1;
static int hf_dcerpc_cn_ack_result = -1;
static int hf_dcerpc_cn_ack_reason = -1;
static int hf_dcerpc_cn_ack_trans_id = -1;
static int hf_dcerpc_cn_ack_trans_ver = -1;
static int hf_dcerpc_cn_cancel_count = -1;
static int hf_dcerpc_auth_type = -1;
static int hf_dcerpc_auth_level = -1;
static int hf_dcerpc_auth_pad_len = -1;
static int hf_dcerpc_auth_rsrvd = -1;
static int hf_dcerpc_auth_ctx_id = -1;
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
static gint ett_dcerpc_cn_drep = -1;
static gint ett_dcerpc_dg_flags1 = -1;
static gint ett_dcerpc_dg_flags2 = -1;

/*
 * Subdissectors
 */

/* the registered subdissectors */
static GHashTable *dcerpc_uuids;

typedef struct _dcerpc_uuid_key {
    e_uuid_t uuid;
    guint16 ver;
} dcerpc_uuid_key;

typedef struct _dcerpc_uuid_value {
    int proto;
    int ett;
    gchar *name;
    dcerpc_sub_dissector *procs;
} dcerpc_uuid_value;

static gint
dcerpc_uuid_equal (gconstpointer k1, gconstpointer k2)
{
    dcerpc_uuid_key *key1 = (dcerpc_uuid_key *)k1;
    dcerpc_uuid_key *key2 = (dcerpc_uuid_key *)k2;
    return ((memcmp (&key1->uuid, &key2->uuid, sizeof (e_uuid_t)) == 0)
            && (key1->ver == key2->ver));
}

static guint
dcerpc_uuid_hash (gconstpointer k)
{
    dcerpc_uuid_key *key = (dcerpc_uuid_key *)k;
    /* This isn't perfect, but the Data1 part of these is almost always
       unique. */
    return key->uuid.Data1;
}

void
dcerpc_init_uuid (int proto, int ett, e_uuid_t *uuid, guint16 ver,
                  dcerpc_sub_dissector *procs)
{
    dcerpc_uuid_key *key = g_malloc (sizeof (*key));
    dcerpc_uuid_value *value = g_malloc (sizeof (*value));

    key->uuid = *uuid;
    key->ver = ver;

    value->proto = proto;
    value->ett = ett;
    value->name = proto_get_protocol_short_name (proto);
    value->procs = procs;

    g_hash_table_insert (dcerpc_uuids, key, value);
}


/*
 * To keep track of ctx_id mappings.  Should really use some
 * generic conversation support instead.
 */
static GHashTable *dcerpc_convs;

typedef struct _dcerpc_conv_key {
    conversation_t *conv;
    guint16 ctx_id;
} dcerpc_conv_key;

static GMemChunk *dcerpc_conv_key_chunk;

typedef struct _dcerpc_conv_value {
    e_uuid_t uuid;
    guint16 ver;
} dcerpc_conv_value;

static GMemChunk *dcerpc_conv_value_chunk;

static gint
dcerpc_conv_equal (gconstpointer k1, gconstpointer k2)
{
    dcerpc_conv_key *key1 = (dcerpc_conv_key *)k1;
    dcerpc_conv_key *key2 = (dcerpc_conv_key *)k2;
    return (key1->conv == key2->conv
            && key1->ctx_id == key2->ctx_id);
}

static guint
dcerpc_conv_hash (gconstpointer k)
{
    dcerpc_conv_key *key = (dcerpc_conv_key *)k;
    return ((guint)key->conv) + key->ctx_id;
}



/*
 * To keep track of callid mappings.  Should really use some generic
 * conversation support instead.
 */
static GHashTable *dcerpc_calls;

typedef struct _dcerpc_call_key {
    conversation_t *conv;
    guint32 call_id;
} dcerpc_call_key;

static GMemChunk *dcerpc_call_key_chunk;

typedef struct _dcerpc_call_value {
    e_uuid_t uuid;
    guint16 ver;
    guint16 opnum;
} dcerpc_call_value;

static GMemChunk *dcerpc_call_value_chunk;

static gint
dcerpc_call_equal (gconstpointer k1, gconstpointer k2)
{
    dcerpc_call_key *key1 = (dcerpc_call_key *)k1;
    dcerpc_call_key *key2 = (dcerpc_call_key *)k2;
    return (key1->conv == key2->conv
            && key1->call_id == key2->call_id);
}

static guint
dcerpc_call_hash (gconstpointer k)
{
    dcerpc_call_key *key = (dcerpc_call_key *)k;
    return ((guint32)key->conv) ^ key->call_id;
}

static void
dcerpc_call_add_map (guint32 call_id, conversation_t *conv,
                     guint16 opnum, guint16 ver, e_uuid_t *uuid)
{
    dcerpc_call_key *key = g_mem_chunk_alloc (dcerpc_call_key_chunk);
    dcerpc_call_value *value = g_mem_chunk_alloc (dcerpc_call_value_chunk);

    key->call_id = call_id;
    key->conv = conv;
    value->uuid = *uuid;
    value->ver = ver;
    value->opnum = opnum;
    g_hash_table_insert (dcerpc_calls, key, value);
}

static dcerpc_call_value*
dcerpc_call_lookup (guint32 call_id, conversation_t *conv)
{
    dcerpc_call_key key;

    key.call_id = call_id;
    key.conv = conv;
    return g_hash_table_lookup (dcerpc_calls, &key);
}


/*
 * Utility functions.  Modeled after packet-rpc.c
 */

int
dissect_dcerpc_uint8 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                      proto_tree *tree, char *drep, 
                      int hfindex, guint8 *pdata)
{
    guint8 data;

    data = tvb_get_guint8 (tvb, offset);
    if (tree) {
        proto_tree_add_item (tree, hfindex, tvb, offset, 1, (drep[0] & 0x10));
    }
    if (pdata)
        *pdata = data;
    return offset + 1;
}

int
dissect_dcerpc_uint16 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, char *drep, 
                       int hfindex, guint16 *pdata)
{
    guint16 data;

    data = ((drep[0] & 0x10)
            ? tvb_get_letohs (tvb, offset)
            : tvb_get_ntohs (tvb, offset));
    
    if (tree) {
        proto_tree_add_item (tree, hfindex, tvb, offset, 2, (drep[0] & 0x10));
    }
    if (pdata)
        *pdata = data;
    return offset + 2;
}

int
dissect_dcerpc_uint32 (tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, char *drep, 
                       int hfindex, guint32 *pdata)
{
    guint32 data;

    data = ((drep[0] & 0x10)
            ? tvb_get_letohl (tvb, offset)
            : tvb_get_ntohl (tvb, offset));
    
    if (tree) {
        proto_tree_add_item (tree, hfindex, tvb, offset, 4, (drep[0] & 0x10));
    }
    if (pdata)
        *pdata = data;
    return offset+4;
}

/*
 * a couple simpler things
 */
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

static int
dcerpc_try_handoff (packet_info *pinfo, proto_tree *tree,
                    proto_tree *dcerpc_tree,
                    tvbuff_t *tvb, gint offset,
                    e_uuid_t *uuid, guint16 ver, 
                    guint16 opnum, gboolean is_rqst)
{
    dcerpc_uuid_key key;
    dcerpc_uuid_value *sub_proto;
    int length;
    proto_item *sub_item;
    proto_tree *sub_tree;
    dcerpc_sub_dissector *proc;
    gchar *name = NULL;

    key.uuid = *uuid;
    key.ver = ver;

    
    if ((sub_proto = g_hash_table_lookup (dcerpc_uuids, &key)) == 0) {
        length = tvb_length_remaining (tvb, offset);
        if (length > 0) {
            proto_tree_add_text (dcerpc_tree, tvb, offset, length,
                                 "Stub data (%d byte%s)", length,
                                 plurality(length, "", "s"));
        }
        return -1;
    }

    if (tree) {
        sub_item = proto_tree_add_item (tree, sub_proto->proto, tvb, offset, 
                                        tvb_length (tvb) - offset, FALSE);
        if (sub_item) {
            sub_tree = proto_item_add_subtree (sub_item, sub_proto->ett);
        }
        
    }
    for (proc = sub_proto->procs; proc->name; proc++) {
        if (proc->num == opnum) {
            name = proc->name;
            break;
        }
    }

    if (!name)
        name = "Unknown?!";

    if (check_col (pinfo->fd, COL_INFO)) {
        col_add_fstr (pinfo->fd, COL_INFO, "%s %s:%s(...)",
                      is_rqst ? "rqst" : "rply",
                      sub_proto->name, name);
    }

    if (check_col (pinfo->fd, COL_PROTOCOL)) {
        col_set_str (pinfo->fd, COL_PROTOCOL, sub_proto->name);
    }
    /* FIXME: call approp. dissector */
    return 0;
}

static int
dissect_dcerpc_cn_auth (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                        e_dce_cn_common_hdr_t *hdr)
{
    int offset;
    guint8 auth_pad_len;

    /*
     * The authentication information is at the *end* of the PDU; in
     * request and response PDUs, the request and response stub data
     * come before it.
     *
     * If the full packet is here, and we've got an auth len, and it's
     * valid, then dissect the auth info
     */
    if (tvb_length (tvb) >= hdr->frag_len
        && hdr->auth_len
        && (hdr->auth_len + 8 <= hdr->frag_len)) {

        offset = hdr->frag_len - (hdr->auth_len + 8);
        
        offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                       hf_dcerpc_auth_type, NULL);
        offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                       hf_dcerpc_auth_level, NULL);
        offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                       hf_dcerpc_auth_pad_len, &auth_pad_len);
        offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                       hf_dcerpc_auth_rsrvd, NULL);
        offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                        hf_dcerpc_auth_ctx_id, NULL);

        proto_tree_add_text (dcerpc_tree, tvb, offset, hdr->auth_len, "Auth Data");

        /* figure out where the auth padding starts */
        offset = hdr->frag_len - (hdr->auth_len + 8 + auth_pad_len);
        if (offset > 0 && auth_pad_len) {
            proto_tree_add_text (dcerpc_tree, tvb, offset, 
                                 auth_pad_len, "Auth padding");
            return hdr->auth_len + 8 + auth_pad_len;
        } else {
            return hdr->auth_len + 8;
        }
    } else {
        return 0;
    }
}



/*
 * Connection oriented packet types
 */

static void
dissect_dcerpc_cn_bind (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                        e_dce_cn_common_hdr_t *hdr)
{
    conversation_t *conv = NULL;
    dcerpc_conv_key *key;
    dcerpc_conv_value *value;
    guint8 num_ctx_items;
    guint i;
    gboolean saw_ctx_item = FALSE;
    guint16 ctx_id;
    guint16 num_trans_items;
    guint j;
    e_uuid_t if_id;
    e_uuid_t trans_id;
    guint32 trans_ver;
    guint16 if_ver, if_ver_minor;
    int offset = 16;

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_max_xmit, NULL);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_max_recv, NULL);

    offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_assoc_group, NULL);

    offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_num_ctx_items, &num_ctx_items);

    /* padding */
    offset += 3;

    for (i = 0; i < num_ctx_items; i++) {
      offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                      hf_dcerpc_cn_ctx_id, &ctx_id);

      offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                      hf_dcerpc_cn_num_trans_items, &num_trans_items);

      dcerpc_tvb_get_uuid (tvb, offset, hdr->drep, &if_id);
      if (dcerpc_tree) {
          proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_cn_bind_if_id, tvb,
                                        offset, 16, "HMMM",
                                        "Interface UUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                        if_id.Data1, if_id.Data2, if_id.Data3,
                                        if_id.Data4[0], if_id.Data4[1],
                                        if_id.Data4[2], if_id.Data4[3],
                                        if_id.Data4[4], if_id.Data4[5],
                                        if_id.Data4[6], if_id.Data4[7]);
      }
      offset += 16;

      if (hdr->drep[0] & 0x10) {
          offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                          hf_dcerpc_cn_bind_if_ver, &if_ver);
          offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                          hf_dcerpc_cn_bind_if_ver_minor, &if_ver_minor);
      } else {
          offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                          hf_dcerpc_cn_bind_if_ver_minor, &if_ver_minor);
          offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                          hf_dcerpc_cn_bind_if_ver, &if_ver);
      }

      if (!saw_ctx_item) {
        conv = find_conversation (&pinfo->src, &pinfo->dst, pinfo->ptype,
                                  pinfo->srcport, pinfo->destport, 0);
        if (conv == NULL) {
            conv = conversation_new (&pinfo->src, &pinfo->dst, pinfo->ptype,
                                     pinfo->srcport, pinfo->destport, 0);
        }

        key = g_mem_chunk_alloc (dcerpc_conv_key_chunk);
        key->conv = conv;
        key->ctx_id = ctx_id;

        value = g_mem_chunk_alloc (dcerpc_conv_value_chunk);
        value->uuid = if_id;
        value->ver = if_ver;

        g_hash_table_insert (dcerpc_convs, key, value);

        if (check_col (pinfo->fd, COL_INFO)) {
          col_add_fstr (pinfo->fd, COL_INFO, "%s: UUID %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x ver %d.%d",
                        hdr->ptype == PDU_BIND ? "Bind" : "Alter Ctx",
                        if_id.Data1, if_id.Data2, if_id.Data3,
                        if_id.Data4[0], if_id.Data4[1],
                        if_id.Data4[2], if_id.Data4[3],
                        if_id.Data4[4], if_id.Data4[5],
                        if_id.Data4[6], if_id.Data4[7],
                        if_ver, if_ver_minor);
        }
        saw_ctx_item = TRUE;
      }

      for (j = 0; j < num_trans_items; j++) {
        dcerpc_tvb_get_uuid (tvb, offset, hdr->drep, &trans_id);
        if (dcerpc_tree) {
            proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_cn_bind_trans_id, tvb,
                                          offset, 16, "HMMM",
                                          "Transfer Syntax: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                          trans_id.Data1, trans_id.Data2, trans_id.Data3,
                                          trans_id.Data4[0], trans_id.Data4[1],
                                          trans_id.Data4[2], trans_id.Data4[3],
                                          trans_id.Data4[4], trans_id.Data4[5],
                                          trans_id.Data4[6], trans_id.Data4[7]);
        }
        offset += 16;

        offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                        hf_dcerpc_cn_bind_trans_ver, &trans_ver);
      }
    }

    dissect_dcerpc_cn_auth (tvb, pinfo, dcerpc_tree, hdr);
}

static void
dissect_dcerpc_cn_bind_ack (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                            e_dce_cn_common_hdr_t *hdr)
{
    guint16 max_xmit, max_recv;
    guint16 sec_addr_len;
    guint8 num_results;
    guint i;
    guint16 result;
    guint16 reason;
    e_uuid_t trans_id;
    guint32 trans_ver;

    int offset = 16;

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_max_xmit, &max_xmit);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_max_recv, &max_recv);

    offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_assoc_group, NULL);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_sec_addr_len, &sec_addr_len);
    offset += sec_addr_len;

    if (offset % 4) {
        offset += 4 - offset % 4;
    }

    offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_num_results, &num_results);

    /* padding */
    offset += 3;

    for (i = 0; i < num_results; i++) {
        offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, 
                                        hdr->drep, hf_dcerpc_cn_ack_result,
                                        &result);
        offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, 
                                        hdr->drep, hf_dcerpc_cn_ack_reason,
                                        &reason);

        dcerpc_tvb_get_uuid (tvb, offset, hdr->drep, &trans_id);
        if (dcerpc_tree) {
            proto_tree_add_string_format (dcerpc_tree, hf_dcerpc_cn_ack_trans_id, tvb,
                                          offset, 16, "HMMM",
                                          "Transfer Syntax: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                          trans_id.Data1, trans_id.Data2, trans_id.Data3,
                                          trans_id.Data4[0], trans_id.Data4[1],
                                          trans_id.Data4[2], trans_id.Data4[3],
                                          trans_id.Data4[4], trans_id.Data4[5],
                                          trans_id.Data4[6], trans_id.Data4[7]);
        }
        offset += 16;

        offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                        hf_dcerpc_cn_ack_trans_ver, &trans_ver);
    }
    
    dissect_dcerpc_cn_auth (tvb, pinfo, dcerpc_tree, hdr);

    if (check_col (pinfo->fd, COL_INFO)) {
        if (num_results != 0 && result == 0) {
            col_add_fstr (pinfo->fd, COL_INFO, "%s ack: accept  max_xmit: %d  max_recv: %d",
                          hdr->ptype == PDU_BIND_ACK ? "Bind" : "Alter ctx",
                          max_xmit, max_recv);
        } else {
            /* FIXME: should put in reason */
            col_add_fstr (pinfo->fd, COL_INFO, "%s ack: %s",
                          hdr->ptype == PDU_BIND_ACK ? "Bind" : "Alter ctx",
                          result == 1 ? "User reject" :
                          result == 2 ? "Provider reject" :
                          "Unknown");
        }
    }
}

static void
dissect_dcerpc_cn_rqst (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                        proto_tree *tree, e_dce_cn_common_hdr_t *hdr)
{
    conversation_t *conv;
    guint16 ctx_id;
    guint16 opnum;
    e_uuid_t obj_id;
    int auth_sz = 0;
    int offset = 16;

    offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_alloc_hint, NULL);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_ctx_id, &ctx_id);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_opnum, &opnum);

    if (check_col (pinfo->fd, COL_INFO)) {
        col_add_fstr (pinfo->fd, COL_INFO, "Request: opnum: %d  ctx_id:%d",
                         opnum, ctx_id);
    }

    if (hdr->flags & 0x80) {
        dcerpc_tvb_get_uuid (tvb, offset, hdr->drep, &obj_id);
        if (dcerpc_tree) {
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
        }
        offset += 16;
    }

    auth_sz = dissect_dcerpc_cn_auth (tvb, pinfo, dcerpc_tree, hdr);

    conv = find_conversation (&pinfo->src, &pinfo->dst, pinfo->ptype,
                              pinfo->srcport, pinfo->destport, 0);
    if (!conv) {

    } else {
        dcerpc_conv_key key;
        dcerpc_conv_value *value;
        int length, reported_length, stub_length;

        key.conv = conv;
        key.ctx_id = ctx_id;

        value = g_hash_table_lookup (dcerpc_convs, &key);
        if (value) {
            /* add an entry for this call, so we can catch the reply */
            dcerpc_call_add_map (hdr->call_id, conv, opnum,
                                 value->ver, &value->uuid);

            /* handoff this call */
            length = tvb_length_remaining(tvb, offset);
            reported_length = tvb_reported_length_remaining(tvb, offset);
            stub_length = hdr->frag_len - offset - auth_sz;
            if (length > stub_length)
              length = stub_length;
            if (reported_length > stub_length)
              reported_length = stub_length;
            dcerpc_try_handoff (pinfo, tree, dcerpc_tree,
                                tvb_new_subset (tvb, offset, length,
                                                reported_length),
                                0, &value->uuid, value->ver,
                                opnum, TRUE);
        }
    }
}

static void
dissect_dcerpc_cn_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *dcerpc_tree,
                        proto_tree *tree, e_dce_cn_common_hdr_t *hdr)
{
    conversation_t *conv;
    guint16 ctx_id;
    int auth_sz = 0;
    int offset = 16;

    offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_alloc_hint, NULL);

    offset = dissect_dcerpc_uint16 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                    hf_dcerpc_cn_ctx_id, &ctx_id);

    if (check_col (pinfo->fd, COL_INFO)) {
        col_add_fstr (pinfo->fd, COL_INFO, "Response: call_id: %d  ctx_id:%d",
                      hdr->call_id, ctx_id);
    }

    offset = dissect_dcerpc_uint8 (tvb, offset, pinfo, dcerpc_tree, hdr->drep,
                                   hf_dcerpc_cn_cancel_count, NULL);
    /* padding */
    offset++;

    auth_sz = dissect_dcerpc_cn_auth (tvb, pinfo, dcerpc_tree, hdr);

    conv = find_conversation (&pinfo->src, &pinfo->dst, pinfo->ptype,
                              pinfo->srcport, pinfo->destport, 0);
    if (!conv) {
        /* no point in creating one here, really */
    } else {
        dcerpc_call_value *value = dcerpc_call_lookup (hdr->call_id, conv);
        int length, reported_length, stub_length;

        if (value) {
            /* handoff this call */
            length = tvb_length_remaining(tvb, offset);
            reported_length = tvb_reported_length_remaining(tvb, offset);
            stub_length = hdr->frag_len - offset - auth_sz;
            if (length > stub_length)
              length = stub_length;
            if (reported_length > stub_length)
              reported_length = stub_length;
            dcerpc_try_handoff (pinfo, tree, dcerpc_tree,
                                tvb_new_subset (tvb, offset, length,
                                                reported_length),
                                0, &value->uuid, value->ver,
                                value->opnum, FALSE);
        }
    }
}

/*
 * DCERPC dissector for connection oriented calls
 */
static gboolean
dissect_dcerpc_cn (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    static char nulls[4] = { 0 };
    proto_item *ti = NULL;
    proto_item *tf = NULL;
    proto_tree *dcerpc_tree = NULL;
    proto_tree *cn_flags_tree = NULL;
    proto_tree *cn_drep_tree = NULL;
    e_dce_cn_common_hdr_t hdr;
    int offset = 0;

    /*
     * Check if this looks like a C/O DCERPC call
     */
    /*
     * when done over nbt, dcerpc requests are padded with 4 bytes of null
     * data for some reason.
     */
    if (tvb_bytes_exist (tvb, 0, 4) && tvb_memeql (tvb, 0, nulls, 4) == 0) {
        tvb = tvb_new_subset (tvb, 4, -1, -1);
    }
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

        tf = proto_tree_add_bytes (dcerpc_tree, hf_dcerpc_cn_drep, tvb, offset, 4, hdr.drep);
        cn_drep_tree = proto_item_add_subtree(tf, ett_dcerpc_cn_drep);
        if (cn_drep_tree) {
            proto_tree_add_uint(cn_drep_tree, hf_dcerpc_cn_drep_byteorder, tvb, offset, 1, hdr.drep[0] >> 4);
            proto_tree_add_uint(cn_drep_tree, hf_dcerpc_cn_drep_character, tvb, offset, 1, hdr.drep[0] & 0x0f);
            proto_tree_add_uint(cn_drep_tree, hf_dcerpc_cn_drep_fp, tvb, offset, 1, hdr.drep[1]);
        }
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
    case PDU_ALTER:
        dissect_dcerpc_cn_bind (tvb, pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_BIND_ACK:
    case PDU_ALTER_ACK:
        dissect_dcerpc_cn_bind_ack (tvb, pinfo, dcerpc_tree, &hdr);
        break;

    case PDU_REQ:
        dissect_dcerpc_cn_rqst (tvb, pinfo, dcerpc_tree, tree, &hdr);
        break;

    case PDU_RESP:
        dissect_dcerpc_cn_resp (tvb, pinfo, dcerpc_tree, tree, &hdr);
        break;

    default:
        /* might as well dissect the auth info */
        dissect_dcerpc_cn_auth (tvb, pinfo, dcerpc_tree, &hdr);
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
    conversation_t *conv;

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
     * keeping track of the conversation shouldn't really be necessary
     * for connectionless packets, because everything we need to know
     * to dissect is in the header for each packet.  Unfortunately,
     * Microsoft's implementation is buggy and often puts the
     * completely wrong if_id in the header.  go figure.  So, keep
     * track of the seqnum and use that if possible.  Note: that's not
     * completely correct.  It should really be done based on both the
     * activity_id and seqnum.  I haven't seen anywhere that it would
     * make a difference, but for future reference...
     */
    conv = find_conversation (&pinfo->src, &pinfo->dst, pinfo->ptype,
                              pinfo->srcport, pinfo->destport, 0);
    if (!conv) {
        conv = conversation_new (&pinfo->src, &pinfo->dst, pinfo->ptype,
                                 pinfo->srcport, pinfo->destport, 0);
    }

    /*
     * Packet type specific stuff is next.
     */
    switch (hdr.ptype) {
    case PDU_REQ:
        dcerpc_call_add_map (hdr.seqnum, conv, hdr.opnum,
                             hdr.if_ver, &hdr.if_id);
        dcerpc_try_handoff (pinfo, tree, dcerpc_tree, tvb, offset,
                            &hdr.if_id, hdr.if_ver, hdr.opnum, TRUE);
        break;
    case PDU_RESP:
        {
            dcerpc_call_value *v = dcerpc_call_lookup (hdr.seqnum, conv);
            if (v) {
                dcerpc_try_handoff (pinfo, tree, dcerpc_tree, tvb, offset,
                                    &v->uuid, v->ver, v->opnum, FALSE);
            } else {
                dcerpc_try_handoff (pinfo, tree, dcerpc_tree, tvb, offset,
                                    &hdr.if_id, hdr.if_ver, hdr.opnum, FALSE);
            }
        }
        break;
    }

    return TRUE;
}

static void
dcerpc_init_protocol (void)
{
    if (dcerpc_convs)
        g_hash_table_destroy (dcerpc_convs);
    if (dcerpc_calls)
        g_hash_table_destroy (dcerpc_calls);
    if (dcerpc_conv_key_chunk)
        g_mem_chunk_destroy (dcerpc_conv_key_chunk);
    if (dcerpc_conv_value_chunk)
        g_mem_chunk_destroy (dcerpc_conv_value_chunk);
    if (dcerpc_call_key_chunk)
        g_mem_chunk_destroy (dcerpc_call_key_chunk);
    if (dcerpc_call_value_chunk)
        g_mem_chunk_destroy (dcerpc_call_value_chunk);

    dcerpc_convs = g_hash_table_new (dcerpc_conv_hash, dcerpc_conv_equal);
    dcerpc_calls = g_hash_table_new (dcerpc_call_hash, dcerpc_call_equal);
    dcerpc_conv_key_chunk = g_mem_chunk_new ("dcerpc_conv_key_chunk",
                                             sizeof (dcerpc_conv_key),
                                             200 * sizeof (dcerpc_conv_key),
                                             G_ALLOC_ONLY);
    dcerpc_conv_value_chunk = g_mem_chunk_new ("dcerpc_conv_value_chunk",
                                             sizeof (dcerpc_conv_value),
                                             200 * sizeof (dcerpc_conv_value),
                                             G_ALLOC_ONLY);
    dcerpc_call_key_chunk = g_mem_chunk_new ("dcerpc_call_key_chunk",
                                             sizeof (dcerpc_call_key),
                                             200 * sizeof (dcerpc_call_key),
                                             G_ALLOC_ONLY);
    dcerpc_call_value_chunk = g_mem_chunk_new ("dcerpc_call_value_chunk",
                                             sizeof (dcerpc_call_value),
                                             200 * sizeof (dcerpc_call_value),
                                             G_ALLOC_ONLY);
}

void
proto_register_dcerpc (void)
{
    static hf_register_info hf[] = {
        { &hf_dcerpc_ver,
          { "Version", "dcerpc.ver", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_ver_minor,
          { "Version (minor)", "dcerpc.ver_minor", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_packet_type,
          { "Packet type", "dcerpc.pkt_type", FT_UINT8, BASE_HEX, VALS (pckt_vals), 0x0, "", HFILL }},
        { &hf_dcerpc_cn_flags,
          { "Packet Flags", "dcerpc.cn_flags", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_flags_first_frag,
          { "First Frag", "dcerpc.cn_flags.first_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x1, "", HFILL }},
        { &hf_dcerpc_cn_flags_last_frag,
          { "Last Frag", "dcerpc.cn_flags.last_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x2, "", HFILL }},
        { &hf_dcerpc_cn_flags_cancel_pending,
          { "Cancel Pending", "dcerpc.cn_flags.cancel_pending", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x4, "", HFILL }},
        { &hf_dcerpc_cn_flags_reserved,
          { "Reserved", "dcerpc.cn_flags.reserved", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x8, "", HFILL }},
        { &hf_dcerpc_cn_flags_mpx,
          { "Multiplex", "dcerpc.cn_flags.mpx", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x10, "", HFILL }},
        { &hf_dcerpc_cn_flags_dne,
          { "Did Not Execute", "dcerpc.cn_flags.dne", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x20, "", HFILL }},
        { &hf_dcerpc_cn_flags_maybe,
          { "Maybe", "dcerpc.cn_flags.maybe", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x40, "", HFILL }},
        { &hf_dcerpc_cn_flags_object,
          { "Object", "dcerpc.cn_flags.object", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x80, "", HFILL }},
        { &hf_dcerpc_cn_drep,
          { "Data Representation", "dcerpc.cn_drep", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_drep_byteorder,
          { "Byte order", "dcerpc.cn_drep.byteorder", FT_UINT8, BASE_DEC, VALS (drep_byteorder_vals), 0x0, "", HFILL }},
        { &hf_dcerpc_cn_drep_character,
          { "Character", "dcerpc.cn_drep.character", FT_UINT8, BASE_DEC, VALS (drep_character_vals), 0x0, "", HFILL }},
        { &hf_dcerpc_cn_drep_fp,
          { "Floating-point", "dcerpc.cn_drep.fp", FT_UINT8, BASE_DEC, VALS (drep_fp_vals), 0x0, "", HFILL }},
        { &hf_dcerpc_cn_frag_len,
          { "Frag Length", "dcerpc.cn_frag_len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_auth_len,
          { "Auth Length", "dcerpc.cn_auth_len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_call_id,
          { "Call ID", "dcerpc.cn_call_id", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_max_xmit,
          { "Max Xmit Frag", "dcerpc.cn_max_xmit", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_max_recv,
          { "Max Recv Frag", "dcerpc.cn_max_recv", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_assoc_group,
          { "Assoc Group", "dcerpc.cn_assoc_group", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_num_ctx_items,
          { "Num Ctx Items", "dcerpc.cn_num_ctx_items", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_ctx_id,
          { "Context ID", "dcerpc.cn_ctx_id", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_num_trans_items,
          { "Num Trans Items", "dcerpc.cn_num_trans_items", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_bind_if_id,
          { "Interface UUID", "dcerpc.cn_bind_to_uuid", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_bind_if_ver,
          { "Interface Ver", "dcerpc.cn_bind_if_ver", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_bind_if_ver_minor,
          { "Interface Ver Minor", "dcerpc.cn_bind_if_ver_minor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_bind_trans_id,
          { "Transfer Syntax", "dcerpc.cn_bind_trans_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_bind_trans_ver,
          { "Syntax ver", "dcerpc.cn_bind_trans_ver", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_alloc_hint,
          { "Alloc hint", "dcerpc.cn_alloc_hint", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_sec_addr_len,
          { "Scndry Addr len", "dcerpc.cn_sec_addr_len", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_num_results,
          { "Num results", "dcerpc.cn_num_results", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_ack_result,
          { "Ack result", "dcerpc.cn_ack_result", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_ack_reason,
          { "Ack reason", "dcerpc.cn_ack_reason", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_ack_trans_id,
          { "Transfer Syntax", "dcerpc.cn_ack_trans_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_ack_trans_ver,
          { "Syntax ver", "dcerpc.cn_ack_trans_ver", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_cn_cancel_count,
          { "Cancel count", "dcerpc.cn_cancel_count", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_auth_type,
          { "Auth type", "dcerpc.auth_type", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_auth_level,
          { "Auth level", "dcerpc.auth_level", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_auth_pad_len,
          { "Auth pad len", "dcerpc.auth_pad_len", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_auth_rsrvd,
          { "Auth Rsrvd", "dcerpc.auth_rsrvd", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_auth_ctx_id,
          { "Auth Context ID", "dcerpc.auth_ctx_id", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_flags1,
          { "Flags1", "dcerpc.dg_flags1", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_flags1_rsrvd_01,
          { "Reserved", "dcerpc.dg_flags1_rsrvd_01", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x01, "", HFILL }},
        { &hf_dcerpc_dg_flags1_last_frag,
          { "Last Fragment", "dcerpc.dg_flags1_last_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x02, "", HFILL }},
        { &hf_dcerpc_dg_flags1_frag,
          { "Fragment", "dcerpc.dg_flags1_frag", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x04, "", HFILL }},
        { &hf_dcerpc_dg_flags1_nofack,
          { "No Fack", "dcerpc.dg_flags1_nofack", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x08, "", HFILL }},
        { &hf_dcerpc_dg_flags1_maybe,
          { "Maybe", "dcerpc.dg_flags1_maybe", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x10, "", HFILL }},
        { &hf_dcerpc_dg_flags1_idempotent,
          { "Idempotent", "dcerpc.dg_flags1_idempotent", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x20, "", HFILL }},
        { &hf_dcerpc_dg_flags1_broadcast,
          { "Broadcast", "dcerpc.dg_flags1_broadcast", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x40, "", HFILL }},
        { &hf_dcerpc_dg_flags1_rsrvd_80,
          { "Reserved", "dcerpc.dg_flags1_rsrvd_80", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x80, "", HFILL }},
        { &hf_dcerpc_dg_flags2,
          { "Flags2", "dcerpc.dg_flags2", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_01,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_01", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x01, "", HFILL }},
        { &hf_dcerpc_dg_flags2_cancel_pending,
          { "Cancel Pending", "dcerpc.dg_flags2_cancel_pending", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x02, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_04,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_04", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x04, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_08,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_08", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x08, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_10,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_10", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x10, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_20,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_20", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x20, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_40,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_40", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x40, "", HFILL }},
        { &hf_dcerpc_dg_flags2_rsrvd_80,
          { "Reserved", "dcerpc.dg_flags2_rsrvd_80", FT_BOOLEAN, 8, TFS (&flags_set_truth), 0x80, "", HFILL }},
        { &hf_dcerpc_dg_serial_lo,
          { "Serial Low", "dcerpc.dg_serial_lo", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_serial_hi,
          { "Serial High", "dcerpc.dg_serial_hi", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_ahint,
          { "Activity Hint", "dcerpc.dg_ahint", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_ihint,
          { "Interface Hint", "dcerpc.dg_ihint", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_frag_len,
          { "Fragment len", "dcerpc.dg_frag_len", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_frag_num,
          { "Fragment num", "dcerpc.dg_frag_num", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_auth_proto,
          { "Auth proto", "dcerpc.dg_auth_proto", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_seqnum,
          { "Sequence num", "dcerpc.dg_seqnum", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_server_boot,
          { "Server boot time", "dcerpc.dg_server_boot", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_if_ver,
          { "Interface Ver", "dcerpc.dg_if_ver", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_obj_id,
          { "Object", "dcerpc.obj_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_if_id,
          { "Interface", "dcerpc.dg_if_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_dg_act_id,
          { "Activitiy", "dcerpc.dg_act_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
        { &hf_dcerpc_opnum,
          { "Opnum", "dcerpc.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},


    };
    static gint *ett[] = {
        &ett_dcerpc,
        &ett_dcerpc_cn_flags,
        &ett_dcerpc_cn_drep,
        &ett_dcerpc_dg_flags1,
        &ett_dcerpc_dg_flags2,
    };

    proto_dcerpc = proto_register_protocol ("DCE RPC", "DCERPC", "dcerpc");
    proto_register_field_array (proto_dcerpc, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    register_init_routine (dcerpc_init_protocol);

    dcerpc_uuids = g_hash_table_new (dcerpc_uuid_hash, dcerpc_uuid_equal);
}

void
proto_reg_handoff_dcerpc (void)
{
    heur_dissector_add ("tcp", dissect_dcerpc_cn, proto_dcerpc);
    heur_dissector_add ("netbios", dissect_dcerpc_cn, proto_dcerpc);
    heur_dissector_add ("udp", dissect_dcerpc_dg, proto_dcerpc);
}
