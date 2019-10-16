/* packet-thrift.c
 * Routines for thrift protocol dissection.
 * Based on work by John Song <jsong@facebook.com> and
 * Bill Fumerola <bill@facebook.com>
 *
 * https://github.com/andrewcox/wireshark-with-thrift-plugin/blob/wireshark-1.8.6-with-thrift-plugin/plugins/thrift/packet-thrift.cpp
 *
 * Copyright 2015, Anders Broman <anders.broman[at]ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
 /* Ref https://thrift.apache.org/developers */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-tls.h"
#include "packet-thrift.h"


void proto_register_thrift(void);
void proto_reg_handoff_thrift(void);

#define THRIFT_VERSION_MASK     0xffff0000
#define THRIFT_VERSION_1        0x80010000
#define THRIFT_COMPACT          0x80020000

#define THRIFT_T_STOP 0
#define THRIFT_T_VOID 1
#define THRIFT_T_BOL 2
#define THRIFT_T_BYTE 3
#define THRIFT_T_DOUBLE 4
#define THRIFT_T_I16 6
#define THRIFT_T_I32 8
#define THRIFT_T_U64 9
#define THRIFT_T_I64 10
#define THRIFT_T_UTF7 11
#define THRIFT_T_STRUCT 12
#define THRIFT_T_MAP 13
#define THRIFT_T_SET 14
#define THRIFT_T_LIST 15
#define THRIFT_T_UTF8 16
#define THRIFT_T_UTF16 17

static dissector_handle_t thrift_handle;
static guint thrift_tls_port = 0;

static gboolean show_internal_thrift_fields = FALSE;

static dissector_table_t thrift_method_name_dissector_table;

static int proto_thrift = -1;
static int hf_thrift_version = -1;
static int hf_thrift_mtype = -1;
static int hf_thrift_str_len = -1;
static int hf_thrift_method = -1;
static int hf_thrift_seq_id = -1;
static int hf_thrift_type = -1;
static int hf_thrift_key_type = -1;
static int hf_thrift_value_type = -1;
static int hf_thrift_fid = -1;
static int hf_thrift_i16 = -1;
static int hf_thrift_i32 = -1;
static int hf_thrift_utf7str = -1;
static int hf_thrift_num_list_item = -1;
static int hf_thrift_num_set_item = -1;
static int hf_thrift_num_map_item = -1;
static int hf_thrift_bool = -1;
static int hf_thrift_byte = -1;
static int hf_thrift_i64 = -1;
static int hf_thrift_u64 = -1;
static int hf_thrift_double = -1;

static int ett_thrift = -1;

static expert_field ei_thrift_wrong_type = EI_INIT;
static expert_field ei_thrift_struct_type_not_imp = EI_INIT;
static expert_field ei_thrift_struct_type_not_in_seq = EI_INIT;

static const value_string thrift_type_vals[] = {
    {  0, "T_STOP" },
    {  1, "T_VOID" },
    {  2, "T_BOL" },
    {  3, "T_BYTE" },
    {  4, "T_DOUBLE" },
    {  5, "Not Used" },
    {  6, "T_I16" },
    {  7, "Not Used" },
    {  8, "T_I32" },
    {  9, "T_U64" },
    { 10, "T_I64" },
    { 11, "T_UTF7" },
    { 12, "T_STRUCT" },
    { 13, "T_MAP" },
    { 14, "T_SET" },
    { 15, "T_LIST" },
    { 16, "T_UTF8" },
    { 17, "T_UTF16" },
    { 0, NULL },
};

static const value_string thrift_mtype_vals[] = {
    { 0, "NONE" },
    { 1, "CALL" },
    { 2, "REPLY" },
    { 3, "EXCEPTION" },
    { 4, "ONEWAY" },
    { 0, NULL },
};

static const value_string thrift_bool_vals[] = {
    { 0, "FALSE" },
    { 1, "TRUE" },
    { 0, NULL },
};

static int dissect_thrift_type(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* pi, int type, int* offset, int length);

int
dissect_thrift_t_stop(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset)
{
    guint32 type;

    proto_tree_add_item_ret_uint(tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
    if (type != THRIFT_T_STOP) {
        proto_tree_add_expert(tree, pinfo, &ei_thrift_wrong_type, tvb, offset, 1);
    }
    offset++;

    return offset;
}

int
dissect_thrift_t_byte(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int field_id _U_, gint hf_id)
{
    guint8 type;

    type = tvb_get_guint8(tvb, offset);
    if (type != THRIFT_T_BYTE) {
        proto_tree_add_expert(tree, pinfo, &ei_thrift_wrong_type, tvb, offset, 1);
    }

    if(show_internal_thrift_fields){
        proto_tree_add_item(tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(tree, hf_thrift_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else {
        offset += 3;
    }

    /*T_BYTE , T_I08*/
    proto_tree_add_item(tree, hf_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

int
dissect_thrift_t_i32(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int field_id _U_, gint hf_id)
{
    guint8 type;

    type = tvb_get_guint8(tvb, offset);
    if (type != THRIFT_T_I32) {
        proto_tree_add_expert(tree, pinfo, &ei_thrift_wrong_type, tvb, offset, 1);
    }

    if (show_internal_thrift_fields) {
        proto_tree_add_item(tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(tree, hf_thrift_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else {
        offset += 3;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

int
dissect_thrift_t_i64(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int field_id _U_, gint hf_id)
{
    guint8 type;

    type = tvb_get_guint8(tvb, offset);
    if (type != THRIFT_T_I64) {
        proto_tree_add_expert(tree, pinfo, &ei_thrift_wrong_type, tvb, offset, 1);
    }

    if (show_internal_thrift_fields) {
        proto_tree_add_item(tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(tree, hf_thrift_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    else {
        offset += 3;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

int
dissect_thrift_t_u64(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int field_id _U_, gint hf_id)
{
    guint8 type;

    type = tvb_get_guint8(tvb, offset);
    if (type != THRIFT_T_U64) {
        proto_tree_add_expert(tree, pinfo, &ei_thrift_wrong_type, tvb, offset, 1);
    }

    if (show_internal_thrift_fields) {
        proto_tree_add_item(tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(tree, hf_thrift_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    else {
        offset += 3;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

int
dissect_thrift_t_utf7(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int field_id _U_, gint hf_id)
{
    guint32 str_len;
    guint8 type;

    type = tvb_get_guint8(tvb, offset);
    if (type != THRIFT_T_UTF7) {
        proto_tree_add_expert(tree, pinfo, &ei_thrift_wrong_type, tvb, offset, 1);
    }
    if (show_internal_thrift_fields) {
        proto_tree_add_item(tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(tree, hf_thrift_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item_ret_uint(tree, hf_thrift_str_len, tvb, offset, 4, ENC_BIG_ENDIAN, &str_len);
        offset += 4;
    } else {
        offset += 3;
        str_len = tvb_get_ntohl(tvb, offset);
        offset += 4;
    }

    proto_tree_add_item(tree, hf_id, tvb, offset, str_len, ENC_ASCII | ENC_NA);
    offset = offset + str_len;

    return offset;

}

int
dissect_thrift_t_struct(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, const thrift_struct_t *seq, int field_id _U_, gint hf_id, gint ett_id)
{
    proto_item *ti;
    proto_tree *sub_tree;

    guint8 type;
    int start_offset = offset;

    /* Add the struct to the tree*/
    ti = proto_tree_add_item(tree, hf_id, tvb, offset, -1, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(ti, ett_id);

    type = tvb_get_guint8(tvb, offset);
    if (type != THRIFT_T_STRUCT) {
        proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_wrong_type, tvb, offset, 1);
    }
    if (show_internal_thrift_fields) {
        proto_tree_add_item(sub_tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(sub_tree, hf_thrift_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    else {
        offset += 3;
    }

    while (seq->fid) {
        type = tvb_get_guint8(tvb, offset);
        if (type != seq->type) {
            /* Wrong field in sequence*/
            if (seq->optional == TRUE) {
                /* Skip to next element*/
                seq++;
                continue;
            } else {
                proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_struct_type_not_in_seq, tvb, offset, 1);
                return offset;
            }
        }
        switch (seq->type) {
        case DE_THRIFT_T_STOP:
            offset = dissect_thrift_t_stop(tvb, pinfo, sub_tree, offset);
            break;
        case DE_THRIFT_T_VOID:
        case DE_THRIFT_T_BOL:
            proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_struct_type_not_imp, tvb, offset, 1);
            break;
        case DE_THRIFT_T_BYTE:
            offset = dissect_thrift_t_byte(tvb, pinfo, sub_tree, offset, seq->fid, *seq->p_id);
            break;
        case DE_THRIFT_T_DOUBLE:
        case DE_THRIFT_T_UNUSED_5:
        case DE_THRIFT_T_I16:
        case DE_THRIFT_T_UNUSED_7:
            proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_struct_type_not_imp, tvb, offset, 1);
            break;
        case DE_THRIFT_T_I32:
            offset = dissect_thrift_t_i32(tvb, pinfo, sub_tree, offset, seq->fid, *seq->p_id);
            break;
        case DE_THRIFT_T_U64:
            offset = dissect_thrift_t_u64(tvb, pinfo, sub_tree, offset, seq->fid, *seq->p_id);
            break;
        case DE_THRIFT_T_I64:
            offset = dissect_thrift_t_i64(tvb, pinfo, sub_tree, offset, seq->fid, *seq->p_id);
            break;
        case DE_THRIFT_T_UTF7:
            offset = dissect_thrift_t_utf7(tvb, pinfo, sub_tree, offset, seq->fid, *seq->p_id);
            break;
        case DE_THRIFT_T_STRUCT:
        case DE_THRIFT_T_MAP:
        case DE_THRIFT_T_SET:
        case DE_THRIFT_T_LIST:
        case DE_THRIFT_T_UTF8:
        case DE_THRIFT_T_UTF16:
        default:
            proto_tree_add_expert(sub_tree, pinfo, &ei_thrift_struct_type_not_imp, tvb, offset, 1);
            break;
        }
        seq++;
    }

    if (show_internal_thrift_fields) {
        proto_tree_add_item(sub_tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset++;

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_thrift_utf7(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int length _U_)
{
    guint32 str_len;

    proto_tree_add_item_ret_uint(tree, hf_thrift_str_len, tvb, offset, 4, ENC_BIG_ENDIAN, &str_len);
    offset += 4;

    proto_tree_add_item(tree, hf_thrift_utf7str, tvb, offset, str_len, ENC_ASCII | ENC_NA);
    offset = offset + str_len;

    return offset;

}

static int
dissect_thrift_list(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int length)
{
    proto_tree *sub_tree;
    proto_item *ti, *type_pi;
    guint32 type;
    int start_offset = offset;
    guint32 list_len, i;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_thrift, &ti, "List");
    type_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
    offset++;
    proto_tree_add_item_ret_uint(sub_tree, hf_thrift_num_list_item, tvb, offset, 4, ENC_BIG_ENDIAN, &list_len);
    offset += 4;

    for (i = 0; i < list_len; ++i) {
        if (dissect_thrift_type(tvb, pinfo, sub_tree, type_pi, type, &offset, length) < 0) {
            break;
        }
    }
    list_len = offset - start_offset;
    proto_item_set_len(ti, list_len);

    return offset;

}

static int
dissect_thrift_set(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int length)
{
    proto_tree *sub_tree;
    proto_item *ti, *type_pi;
    guint32 type;
    int start_offset = offset;
    guint32 set_len, i;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_thrift, &ti, "Set");
    type_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
    offset++;
    proto_tree_add_item_ret_uint(sub_tree, hf_thrift_num_set_item, tvb, offset, 4, ENC_BIG_ENDIAN, &set_len);
    offset += 4;

    for (i = 0; i < set_len; ++i) {
        if (dissect_thrift_type(tvb, pinfo, sub_tree, type_pi, type, &offset, length) < 0) {
            break;
        }
    }
    set_len = offset - start_offset;
    proto_item_set_len(ti, set_len);

    return offset;

}


static int
dissect_thrift_struct(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int length)
{
    proto_tree *sub_tree;
    proto_item *ti, *type_pi;
    guint32 type;
    int start_offset = offset, struct_len;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_thrift, &ti, "Struct");

    if (offset >= length) {
        /* ensure this function is never a non-op */
        return length;
    }

    while (offset < length) {
        /* Read type and field id */
        type_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
        offset++;
        if (type == 0){
            /* T_STOP */
            struct_len = offset - start_offset;
            proto_item_set_len(ti, struct_len);
            break;
        }
        proto_tree_add_item(sub_tree, hf_thrift_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        if (dissect_thrift_type(tvb, pinfo, sub_tree, type_pi, type, &offset, length) < 0) {
            break;
        }
    }

    return offset;
}

static int
dissect_thrift_map(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int length)
{
    proto_tree *sub_tree;
    proto_item *ti, *ktype_pi, *vtype_pi;
    guint32 ktype;
    guint32 vtype;
    guint32 map_len, i;
    int start_offset = offset;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_thrift, &ti, "Map");
    ktype_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_key_type, tvb, offset, 1, ENC_BIG_ENDIAN, &ktype);
    offset++;
    vtype_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_value_type, tvb, offset, 1, ENC_BIG_ENDIAN, &vtype);
    offset++;
    proto_tree_add_item_ret_uint(sub_tree, hf_thrift_num_map_item, tvb, offset, 4, ENC_BIG_ENDIAN, &map_len);
    offset += 4;

    for (i = 0; i < map_len; ++i) {
        if (dissect_thrift_type(tvb, pinfo, sub_tree, ktype_pi, ktype, &offset, length) < 0) {
            break;
        }
        if (dissect_thrift_type(tvb, pinfo, sub_tree, vtype_pi, vtype, &offset, length) < 0) {
            break;
        }
    }
    map_len = offset - start_offset;
    proto_item_set_len(ti, map_len);

    return offset;
}

static int
dissect_thrift_type(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree,
                    proto_item* pi, int type, int* offset, int length)
{
    switch (type){
    case 2:
        /*T_BOOL*/
        proto_tree_add_item(tree, hf_thrift_bool, tvb, *offset, 1, ENC_BIG_ENDIAN);
        *offset += 1;
        break;
    case 3:
        /*T_BYTE , T_I08*/
        proto_tree_add_item(tree, hf_thrift_byte, tvb, *offset, 1, ENC_BIG_ENDIAN);
        *offset += 1;
        break;
    case 4:
        /*T_DOUBLE*/
        proto_tree_add_item(tree, hf_thrift_double, tvb, *offset, 8, ENC_BIG_ENDIAN);
        *offset += 8;
        break;
    case 6:
        /*T_I16 Integer 16*/
        proto_tree_add_item(tree, hf_thrift_i16, tvb, *offset, 2, ENC_BIG_ENDIAN);
        *offset += 2;
        break;
    case 8:
        /*T_I32 Integer 32*/
        proto_tree_add_item(tree, hf_thrift_i32, tvb, *offset, 4, ENC_BIG_ENDIAN);
        *offset += 4;
        break;
    case 9:
        /*T_U64 Integer 64*/
        proto_tree_add_item(tree, hf_thrift_u64, tvb, *offset, 8, ENC_BIG_ENDIAN);
        *offset += 8;
        break;
    case 10:
        /*T_I64 Integer 64*/
        proto_tree_add_item(tree, hf_thrift_i64, tvb, *offset, 8, ENC_BIG_ENDIAN);
        *offset += 8;
        break;
    case 11:
        /* T_UTF7 */
        *offset = dissect_thrift_utf7(tvb, pinfo, tree, *offset, length);
        break;
    case 12:
        /* T_STRUCT */
        *offset = dissect_thrift_struct(tvb, pinfo, tree, *offset, length);
        break;
    case 13:
        /* T_MAP */
        *offset = dissect_thrift_map(tvb, pinfo, tree, *offset, length);
        break;
    case 14:
        /* T_SET */
        *offset = dissect_thrift_set(tvb, pinfo, tree, *offset, length);
        break;
    case 15:
        /* T_LIST */
        *offset = dissect_thrift_list(tvb, pinfo, tree, *offset, length);
        break;
    default:
        /* Bail out */
        expert_add_info(pinfo, pi, &ei_thrift_wrong_type);
        *offset = tvb_reported_length(tvb);
        return -1;
    }

    return *offset;
}

static int
dissect_thrift_common(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void *data _U_)
{
    proto_tree *sub_tree;
    proto_item *type_pi;
    int offset = 0;
    int str_len;
    guint8 mtype;
    guint16 version;
    guint32 seq_id;
    guint8 *method_str;
    int length = tvb_reported_length(tvb);
    guint32 type;
    tvbuff_t *msg_tvb;
    int len;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "THRIFT");
    col_clear(pinfo->cinfo, COL_INFO);

    version = tvb_get_ntohs(tvb, 0);
    mtype = tvb_get_guint8(tvb, 3);
    str_len = tvb_get_ntohl(tvb, 4);

    seq_id = tvb_get_ntohl(tvb, str_len + 8);
    method_str = tvb_get_string_enc(wmem_packet_scope(), tvb, 8, str_len, ENC_UTF_8);

    proto_tree_add_item(tree, proto_thrift, tvb, 0, -1, ENC_NA);
    sub_tree = proto_tree_add_subtree_format(tree, tvb, 0, -1, ett_thrift, NULL, "%s[ version:0x%x, seqid:%d, method:%s]",
        val_to_str(mtype, thrift_mtype_vals, "%d"),
        version,
        seq_id,
        method_str);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", val_to_str(mtype, thrift_mtype_vals, "%d"), method_str);

    if (tree){
        proto_tree_add_item(sub_tree, hf_thrift_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        /* Not used byte ?*/
        offset++;
        proto_tree_add_item(sub_tree, hf_thrift_mtype, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(sub_tree, hf_thrift_str_len, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(sub_tree, hf_thrift_method, tvb, offset, str_len, ENC_ASCII | ENC_NA);
        offset = offset + str_len;
        proto_tree_add_item(sub_tree, hf_thrift_seq_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

    }
    else{
        offset = 12 + str_len;
    }

    /* Call method dissector here using dissector_try_string()*/
    msg_tvb = tvb_new_subset_length(tvb, offset, length - offset);
    len = dissector_try_string(thrift_method_name_dissector_table, method_str, msg_tvb, pinfo, tree, NULL);
    if (len > 0) {
        /* The sub dissector dissected the tvb*/
        return tvb_reported_length(tvb);
    } else if (len < 0) {
        /* The subdissector requested more bytes ( len = -1 )*/
        return len;
    }
    /* len = 0, no subdissector */
    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_thrift, NULL, "Data");
    while (offset < length){
        /*Read type and field id */
        type_pi = proto_tree_add_item_ret_uint(sub_tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
        if (type == 0){
            return tvb_reported_length(tvb);
        }
        offset++;
        proto_tree_add_item(sub_tree, hf_thrift_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (dissect_thrift_type(tvb, pinfo, sub_tree, type_pi, type, &offset, length) < 0) {
            break;
        }
    }
    /* We did not encounter T_STOP*/
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    return 0;
}

/*
Binary protocol Message, strict encoding, 12+ bytes:
   +--------+--------+--------+--------+--------+--------+--------+--------+--------+...+--------+--------+--------+--------+--------+
   |1vvvvvvv|vvvvvvvv|unused  |00000mmm| name length                       | name                | seq id                            |
   +--------+--------+--------+--------+--------+--------+--------+--------+--------+...+--------+--------+--------+--------+--------+
   '''

   Where:

   * 'vvvvvvvvvvvvvvv' is the version, an unsigned 15 bit number fixed to '1' (in binary: '000 0000 0000 0001').
   The leading bit is '1'.
   * 'unused' is an ignored byte.
   * 'mmm' is the message type, an unsigned 3 bit integer. The 5 leading bits must be '0' as some clients (checked for
   java in 0.9.1) take the whole byte.
   * 'name length' is the byte length of the name field, a signed 32 bit integer encoded in network (big endian) order (must be >= 0).
   * 'name' is the method name, a UTF-8 encoded string.
   * 'seq id' is the sequence id, a signed 32 bit integer encoded in network (big endian) order.
Compact protocol Message (4+ bytes):
   +--------+--------+--------+...+--------+--------+...+--------+--------+...+--------+
   |pppppppp|mmmvvvvv| seq id              | name length         | name                |
   +--------+--------+--------+...+--------+--------+...+--------+--------+...+--------+


   Where:

   * 'pppppppp' is the protocol id, fixed to '1000 0010', 0x82.
   3 * 'mmm' is the message type, an unsigned 3 bit integer.
   * 'vvvvv' is the version, an unsigned 5 bit integer, fixed to '00001'.
   * 'seq id' is the sequence id, a signed 32 bit integer encoded as a var int.
   * 'name length' is the byte length of the name field, a signed 32 bit integer encoded as a var int (must be >= 0).
   * 'name' is the method name to invoke, a UTF-8 encoded string.

   Message types are encoded with the following values:

   * _Call_: 1
   * _Reply_: 2
   * _Exception_: 3
   * _Oneway_: 4
*/
static int
dissect_thrift_tcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void *data)
{
    int str_len, length = tvb_reported_length(tvb);


    /* Need at least 13 bytes for a thrift message */
    if (length < 13) {
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        return 0;
    }

    str_len = tvb_get_ntohl(tvb, 4);

    /* Header 8 + string + seq_id + at least 4 bytes?*/
    if (length < str_len + 8 + 4 + 4) {
        pinfo->desegment_offset = 0;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        return 0;
    }

    return dissect_thrift_common(tvb, pinfo, tree, data);
}

static gboolean
dissect_thrift_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void *data) {
    int offset = 0;
    guint32 header;
    gint tframe_length;
    int length = tvb_captured_length(tvb);
    int str_length;
    guchar c;

    /* Need at least 9 bytes for a thrift message */
    if (length < 9){
        return FALSE;
    }

    header = tvb_get_ntohl(tvb, offset);

    if ((header & THRIFT_VERSION_MASK) != THRIFT_VERSION_1) {
        /* if at first we don't see the Thrift header, look ahead;
         * if this packet is using TFramedTransport, the header will be
         * preceded by a message length, type int32 */
        tframe_length = header;
        offset += 4;
        header = tvb_get_ntohl(tvb, offset);

        /* ensure TFramedTransport's length is no greater than the underlying
         * Thrift packet length; this allows both full AND truncated packets to
         * pass this heuristic */
        if (tframe_length > (length - 4)) {
            return FALSE;
        }
        else if ((header & THRIFT_VERSION_MASK) != THRIFT_VERSION_1) {
            return FALSE;
        }
        else {
            /* strip off TFramedTransport */
            tvb = tvb_new_subset_remaining(tvb, 4);
            offset -= 4;
            length -= 4;
        }
    }

    offset += 4;
    str_length = tvb_get_ntohl(tvb, offset);
    if ((str_length < 1) ||(length < str_length + 8)){
        return FALSE;
    }
    offset += 4;
    if (length < offset + str_length){
        return FALSE;
    }
    while (offset < (str_length + 8)){
        c = tvb_get_guint8(tvb, offset);
        if (!g_ascii_isprint(c)){
            return FALSE;
        }
        offset++;
    }

    dissect_thrift_common(tvb, pinfo, tree, data);

    return TRUE;

}

void proto_register_thrift(void) {

    static hf_register_info hf[] = {
        { &hf_thrift_version,
        { "Version", "thrift.version",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_mtype,
        { "Message type", "thrift.mtype",
        FT_UINT8, BASE_DEC, VALS(thrift_mtype_vals), 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_str_len,
        { "Length", "thrift.str_len",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_method,
        { "Method", "thrift.method",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_seq_id,
        { "Sequence Id", "thrift.seq_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_type,
        { "Type", "thrift.type",
        FT_UINT8, BASE_DEC, VALS(thrift_type_vals), 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_key_type,
        { "Key Type", "thrift.type",
        FT_UINT8, BASE_DEC, VALS(thrift_type_vals), 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_value_type,
        { "Value Type", "thrift.type",
        FT_UINT8, BASE_DEC, VALS(thrift_type_vals), 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_fid,
        { "Field Id", "thrift.fid",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_i16,
        { "Integer16", "thrift.i16",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_i32,
        { "Integer32", "thrift.i32",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_utf7str,
        { "UTF7 String", "thrift.utf7str",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_num_set_item,
        { "Number of Set Items", "thrift.num_set_item",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_num_list_item,
        { "Number of List Items", "thrift.num_list_item",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_num_map_item,
        { "Number of Map Items", "thrift.num_map_item",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_bool,
        { "Boolean", "thrift.bool",
        FT_UINT8, BASE_DEC, VALS(thrift_bool_vals), 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_byte,
        { "Byte", "thrift.byte",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_i64,
        { "Integer64", "thrift.i64",
        FT_INT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_u64,
        { "Integer64", "thrift.u64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_thrift_double,
        { "Double", "thrift.double",
        FT_DOUBLE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
        },
    };


    /* setup protocol subtree arrays */
    static gint* ett[] = {
        &ett_thrift,
    };

    static ei_register_info ei[] = {
        { &ei_thrift_wrong_type,{ "thrift.wrong_type", PI_PROTOCOL, PI_ERROR, "Type value not expected", EXPFILL } },
        { &ei_thrift_struct_type_not_imp,{ "thrift.struct_type_not_imp", PI_PROTOCOL, PI_ERROR, "Struct type handling not implemented in Wireshak yet", EXPFILL } },
        { &ei_thrift_struct_type_not_in_seq,{ "thrift.struct_type_not_in_seq", PI_PROTOCOL, PI_ERROR, "Wrong element in struct", EXPFILL } },
    };


    module_t *thrift_module;
    expert_module_t* expert_thrift;


    /* Register protocol name and description */
    proto_thrift = proto_register_protocol("Thrift Protocol", "Thrift", "thrift");

    expert_thrift = expert_register_protocol(proto_thrift);

    /* register field array */
    proto_register_field_array(proto_thrift, hf, array_length(hf));

    /* register subtree array */
    proto_register_subtree_array(ett, array_length(ett));

    expert_register_field_array(expert_thrift, ei, array_length(ei));

    /* register dissector */
    thrift_handle = register_dissector("thrift", dissect_thrift_tcp, proto_thrift);

    thrift_module = prefs_register_protocol(proto_thrift, proto_reg_handoff_thrift);

    thrift_method_name_dissector_table = register_dissector_table("thrift.method_names", "Thrift Method names",
        proto_thrift, FT_STRING, BASE_NONE);

    prefs_register_uint_preference(thrift_module, "tls.port",
        "Thrift TLS Port",
        "Thrift TLS Port",
        10, &thrift_tls_port);

}

void proto_reg_handoff_thrift(void) {
    static guint saved_thrift_tls_port;
    static dissector_handle_t thrift_http_handle;
    static gboolean thrift_initialized = FALSE;

    thrift_http_handle = create_dissector_handle(dissect_thrift_heur, proto_thrift);

    if (!thrift_initialized) {
        thrift_initialized = TRUE;
        heur_dissector_add("tcp", dissect_thrift_heur, "Thrift over TCP", "thrift_tcp", proto_thrift, HEURISTIC_ENABLE);
        dissector_add_string("media_type", "application/x-thrift", thrift_http_handle);
    } else {
        ssl_dissector_delete(saved_thrift_tls_port, thrift_handle);
    }

    ssl_dissector_add(thrift_tls_port, thrift_handle);
    saved_thrift_tls_port = thrift_tls_port;


}
/*
* Editor modelines  -  https://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* vi: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
