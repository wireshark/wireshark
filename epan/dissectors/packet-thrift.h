/* packet-thrift.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Note used by proprietarry dissectors (too).
 */

#ifndef __PACKET_THRIFT_H__
#define __PACKET_THRIFT_H__

#include "ws_symbol_export.h"


typedef enum
{
    DE_THRIFT_T_STOP = 0,
    DE_THRIFT_T_VOID,
    DE_THRIFT_T_BOL,
    DE_THRIFT_T_BYTE,
    DE_THRIFT_T_DOUBLE,
    DE_THRIFT_T_UNUSED_5,
    DE_THRIFT_T_I16,
    DE_THRIFT_T_UNUSED_7,
    DE_THRIFT_T_I32,
    DE_THRIFT_T_U64,
    DE_THRIFT_T_I64,
    DE_THRIFT_T_UTF7,
    DE_THRIFT_T_STRUCT,
    DE_THRIFT_T_MAP,
    DE_THRIFT_T_SET,
    DE_THRIFT_T_LIST,
    DE_THRIFT_T_UTF8,
    DE_THRIFT_T_UTF16
} trift_type_enum_t;

typedef struct _thrift_struct_t {
    const int *p_id;                 /* The hf field for the struct member*/
    int fid;                         /* The Thrift field id of the stuct memeber*/
    gboolean optional;               /* TRUE if element is optional, FALSE otherwise */
    trift_type_enum_t type;          /* The thrift type of the struct member */
} thrift_struct_t;

/*
These functions are to be used by dissectors dissecting Thrift based protocols sinilar to packet-ber.c

*/
WS_DLL_PUBLIC int dissect_thrift_t_stop(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset);

WS_DLL_PUBLIC int dissect_thrift_t_byte(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int field_id _U_, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_i32(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int field_id _U_, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_u64(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int field_id _U_, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_i64(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int field_id _U_, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_utf7(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int field_id _U_, gint hf_id);

/** Dissect a Thrift struct
* Dissect a Thrift struct by calling the struct member dissector in turn from the thrift_struct_t array
*
* @param[in] tvb tvb with the thrift data
* @param[in] pinfo The packet info struct
* @param[in] tree the packet tree
* @param[in] offset the offset where to start dissection in the given tvb
* @param[in] seq an array of thrift_struct_t's containing thrift type of the struct members the hf variable to use etc.
* @param[in] field_id the Thrift field id of the struct
* @param[in] hf_id a header field of FT_BYTES which will be the struct header field
* @param[in] ett_id an ett field used for the subtree created to list the struct members.
* @return The number of bytes dissected.
*/
WS_DLL_PUBLIC int dissect_thrift_t_struct(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, const thrift_struct_t *seq,
    int field_id _U_, gint hf_id, gint ett_id);

#endif /*__PACKET_THRIFT_H__ */
