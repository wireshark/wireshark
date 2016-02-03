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
 /* Ref https://thrift.apache.org/developers */

#include "config.h"

#include <epan/packet.h>

void proto_register_thrift(void);
void proto_reg_handoff_thrift(void);

#define THRIFT_VERSION_MASK     0xffff0000
#define THRIFT_VERSION_1        0x80010000

static int proto_thrift = -1;
static int hf_thrift_version = -1;
static int hf_thrift_mtype = -1;
static int hf_thrift_str_len = -1;
static int hf_thrift_method = -1;
static int hf_thrift_seq_id = -1;
static int hf_thrift_type = -1;
static int hf_thrift_fid = -1;
static int hf_thrift_i16 = -1;
static int hf_thrift_i32 = -1;
static int hf_thrift_utf7str = -1;
static int hf_thrift_num_list_item = -1;
static int hf_thrift_num_map_item = -1;
static int hf_thrift_bool = -1;
static int hf_thrift_byte = -1;
static int hf_thrift_i64 = -1;
static int hf_thrift_u64 = -1;
static int hf_thrift_double = -1;

static int ett_thrift = -1;

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

static int dissect_thrift_type(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int type, int offset, int length);

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
    proto_item *ti;
    guint32 type;
    int start_offset = offset, i;
    guint32 list_len;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_thrift, &ti, "List");
    proto_tree_add_item_ret_uint(sub_tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
    offset++;
    proto_tree_add_item_ret_uint(sub_tree, hf_thrift_num_list_item, tvb, offset, 4, ENC_BIG_ENDIAN, &list_len);
    offset += 4;

    for (i = 0; i < (int)list_len; ++i) {
        offset = dissect_thrift_type(tvb, pinfo, sub_tree, type, offset, length);
    }
    list_len = offset - start_offset;
    proto_item_set_len(ti, list_len);

    return offset;

}

static int
dissect_thrift_struct(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int length)
{
    proto_tree *sub_tree;
    proto_item *ti;
    guint8 type;
    int start_offset = offset, struct_len;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_thrift, &ti, "Struct");

    if (offset >= length) {
        /* ensure this function is never a non-op */
        return length;
    }

    while (offset < length) {
        /* Read type and field id */
        type = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(sub_tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        if (type == 0){
            /* T_STOP */
            struct_len = offset - start_offset;
            proto_item_set_len(ti, struct_len);
            break;
        }
        proto_tree_add_item(sub_tree, hf_thrift_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        offset = dissect_thrift_type(tvb, pinfo, sub_tree, type, offset, length);
    }

    return offset;
}

static int
dissect_thrift_map(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int length)
{
    proto_tree *sub_tree;
    proto_item *ti;
    guint32 ktype;
    guint32 vtype;
    guint32 map_len;
    int start_offset = offset, i;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_thrift, &ti, "Map");
    proto_tree_add_item_ret_uint(sub_tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN, &ktype);
    offset++;
    proto_tree_add_item_ret_uint(sub_tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN, &vtype);
    offset++;
    proto_tree_add_item_ret_uint(sub_tree, hf_thrift_num_map_item, tvb, offset, 4, ENC_BIG_ENDIAN, &map_len);
    offset += 4;

    for (i = 0; i < (int)map_len; ++i) {
        offset = dissect_thrift_type(tvb, pinfo, sub_tree, ktype, offset, length);
        offset = dissect_thrift_type(tvb, pinfo, sub_tree, vtype, offset, length);
    }
    map_len = offset - start_offset;
    proto_item_set_len(ti, map_len);

    return offset;
}

static int
dissect_thrift_type(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int type, int offset, int length)
{
    switch (type){
    case 2:
        /*T_BOOL*/
        proto_tree_add_item(tree, hf_thrift_bool, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;
    case 3:
        /*T_BYTE , T_I08*/
        proto_tree_add_item(tree, hf_thrift_byte, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;
    case 4:
        /*T_DOUBLE*/
        proto_tree_add_item(tree, hf_thrift_double, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        break;
    case 6:
        /*T_I16 Integer 16*/
        proto_tree_add_item(tree, hf_thrift_i16, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        break;
    case 8:
        /*T_I32 Integer 32*/
        proto_tree_add_item(tree, hf_thrift_i32, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case 9:
        /*T_U64 Integer 64*/
        proto_tree_add_item(tree, hf_thrift_u64, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        break;
    case 10:
        /*T_I64 Integer 64*/
        proto_tree_add_item(tree, hf_thrift_i64, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        break;
    case 11:
        /* T_UTF7 */
        offset = dissect_thrift_utf7(tvb, pinfo, tree, offset, length);
        break;
    case 12:
        /* T_STRUCT */
        offset = dissect_thrift_struct(tvb, pinfo, tree, offset, length);
        break;
    case 13:
        /* T_MAP */
        offset = dissect_thrift_map(tvb, pinfo, tree, offset, length);
        break;
    case 15:
        /* T_LIST */
        offset = dissect_thrift_list(tvb, pinfo, tree, offset, length);
        break;
    default:
        /* Bail out */
        return length;
    }

    return offset;
}

static void
dissect_thrift_common(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    proto_tree *sub_tree;
    int offset = 0;
    guint32 str_len;
    guint8 mtype;
    guint16 version;
    guint32 seq_id;
    guint8 *method_str;
    int length = tvb_reported_length(tvb);
    guint8 type;

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
    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_thrift, NULL, "Data");
    if (tree){
        while (offset < length){
            /*Read type and field id */
            type = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(sub_tree, hf_thrift_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (type == 0){
                return;
            }
            offset++;
            proto_tree_add_item(sub_tree, hf_thrift_fid, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            offset = dissect_thrift_type(tvb, pinfo, sub_tree, type, offset, length);
        }
    }
}

static gboolean
dissect_thrift_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void *data _U_) {
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

    dissect_thrift_common(tvb, pinfo, tree);

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

    /* Register protocol name and description */
    proto_thrift = proto_register_protocol("Thrift Protocol", "Thrift", "thrift");

    /* register field array */
    proto_register_field_array(proto_thrift, hf, array_length(hf));

    /* register subtree array */
    proto_register_subtree_array(ett, array_length(ett));

    /* register dissector */
    /*register_dissector("thrift", dissect_thrift, proto_thrift); */
}

void proto_reg_handoff_thrift(void) {

    heur_dissector_add("tcp", dissect_thrift_heur, "Thrift over TCP", "thrift_tcp", proto_thrift, HEURISTIC_ENABLE);

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
