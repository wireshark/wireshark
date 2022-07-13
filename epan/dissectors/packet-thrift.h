/* packet-thrift.h
 *
 * Copyright 2015, Anders Broman <anders.broman[at]ericsson.com>
 * Copyright 2019-2021, Triton Circonflexe <triton[at]kumal.info>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Note: used by proprietary dissectors (too).
 */

#ifndef __PACKET_THRIFT_H__
#define __PACKET_THRIFT_H__

#include "ws_symbol_export.h"


typedef enum {
    DE_THRIFT_T_GENERIC = -1, // Use this to delegate field dissection to generic dissector.
    DE_THRIFT_T_STOP,
    DE_THRIFT_T_VOID, // DE_THRIFT_T_UNUSED_1?
    DE_THRIFT_T_BOOL,
    DE_THRIFT_T_I8,
    DE_THRIFT_T_DOUBLE,
    DE_THRIFT_T_UNUSED_5, // Intended for U16?
    DE_THRIFT_T_I16,
    DE_THRIFT_T_UNUSED_7, // Intended for U32?
    DE_THRIFT_T_I32,
    DE_THRIFT_T_UNUSED_9, // Intended for U64?
    DE_THRIFT_T_I64,
    DE_THRIFT_T_BINARY,
    DE_THRIFT_T_STRUCT,
    DE_THRIFT_T_MAP,
    DE_THRIFT_T_SET,
    DE_THRIFT_T_LIST,
    DE_THRIFT_T_UUID,
} thrift_type_enum_t;

typedef enum {
    ME_THRIFT_T_CALL = 1,
    ME_THRIFT_T_REPLY,
    ME_THRIFT_T_EXCEPTION,
    ME_THRIFT_T_ONEWAY,
} thrift_method_type_enum_t;

/*
 * This is a list of flags even though not all combinations are available.
 * - Framed is compatible with everything;
 * - Default (0x00) is old binary;
 * - Binary can be augmented with Strict (message header is different but content is the same);
 * - Compact is incompatible with Binary & Strict as everything is coded differently;
 * - If Compact bit is set, Strict bit will be ignored (0x06 ~= 0x04).
 *
 * Valid values go from 0x00 (old binary format) to 0x05 (framed compact).
 *
 * Note: Compact is not fully supported yet.
 */
typedef enum {
    PROTO_THRIFT_BINARY = 0x00,
    PROTO_THRIFT_FRAMED = 0x01,
    PROTO_THRIFT_STRICT = 0x02,
    PROTO_THRIFT_COMPACT = 0x04
} thrift_protocol_enum_t;

#define THRIFT_OPTION_DATA_CANARY 0x8001da7a
#define THRIFT_REQUEST_REASSEMBLY       (-1)
#define THRIFT_SUBDISSECTOR_ERROR       (-2)

typedef struct _thrift_option_data_t {
    guint32 canary;                     /* Ensure that we don't read garbage.
                                         * Sub-dissectors should check against THRIFT_OPTION_DATA_CANARY. */
    thrift_method_type_enum_t mtype;    /* Method type necessary to know how to decode the message. */
    thrift_protocol_enum_t tprotocol;   /* Type and version of Thrift TProtocol.
                                         * Framed?((Strict? Binary)|Compact) */
    gint64 reply_field_id;              /* First (and theoretically only) field id of the current REPLY.
                                         * This is useful for the sub-dissectors to handle exceptions. */
    gint64 previous_field_id;           /* Last field id that was present in the current struct.
                                         * Set by dissect_thrift_t_struct after the field has been
                                         * entirely read.
                                         * Read by the next dissect_thrift_t_field_header if only
                                         * a delta is available (for TCompactProtocol). */
    proto_tree *reassembly_tree;        /* Tree were the reassembly was requested. */
                                        /* Useful if the caller can't reassemble (Framed). */
    gint32 reassembly_offset;           /* Where the incomplete data starts. */
    gint32 reassembly_length;           /* Expected size of the data. */
    guint32 nested_type_depth;          /* Number of nested types allowed below the parameter or result type. */
} thrift_option_data_t;

#define TMFILL NULL, { .m = { NULL, NULL } }

typedef struct _thrift_member_t thrift_member_t;
struct _thrift_member_t {
    const gint *p_hf_id;             /* The hf field for the struct member*/
    const gint16 fid;                /* The Thrift field id of the stuct memeber*/
    const gboolean optional;         /* TRUE if element is optional, FALSE otherwise */
    const thrift_type_enum_t type;   /* The thrift type of the struct member */
    const gint *p_ett_id;            /* An ett field used for the subtree created if the member is a compound type. */
    union {
        const guint encoding;
        const thrift_member_t *element;
        const thrift_member_t *members;
        struct {
            const thrift_member_t *key;
            const thrift_member_t *value;
        } m;
    } u;
};

/* These functions are to be used by dissectors dissecting Thrift based protocols similar to packet-ber.c
 *
 * param[in] tvb           Pointer to the tvbuff_t holding the captured data.
 * param[in] pinfo         Pointer to the packet_info holding information about the currently dissected packet.
 * param[in] tree          Pointer to the proto_tree used to hold the display tree in Wireshark's interface.
 * param[in] offset        Offset from the beginning of the tvbuff_t where the Thrift field is. Function will dissect type, id, & data.
 * param[in] thrift_opt    Options from the Thrift dissector that will be necessary for sub-dissection (binary vs. compact, ...)
 * param[in] is_field      Indicate if the offset point to a field element and if field type and field id must be dissected.
 *                          Only for containers internal use. Sub-dissectors must always use TRUE except for struct (see below).
 * param[in] field_id      Thrift field identifier, to check that the right field is being dissected (in case of optional fields).
 * param[in] hf_id         Header field info that describes the field to display (display name, filter name, FT_TYPE, ...).
 *
 * param[in] encoding      Encoding used for string display. (Only for dissect_thrift_t_string_enc)
 *
 * return                  Offset of the first non-dissected byte in case of success,
 *                         THRIFT_REQUEST_REASSEMBLY (-1) in case reassembly is required, or
 *                         THRIFT_SUBDISSECTOR_ERROR (-2) in case of error.
 *                         Sub-dissector must follow the same convention on return.
 *                         Replacing THRIFT_SUBDISSECTOR_ERROR with a 0 return value has the same effect
 *                         as activating "Fallback to generic Thrift dissector if sub-dissector fails"
 *                         in this dissector (thrift.fallback_on_generic option).
 */
WS_DLL_PUBLIC int dissect_thrift_t_stop      (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset);
WS_DLL_PUBLIC int dissect_thrift_t_bool      (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_i8        (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_i16       (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_i32       (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_i64       (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_double    (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_uuid      (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_binary    (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_string    (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id);
WS_DLL_PUBLIC int dissect_thrift_t_string_enc(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, guint encoding);

/* Dissect a Thrift struct
 * Dissect a Thrift struct by calling the struct member dissector in turn from the thrift_member_t array
 *
 * param[in] tvb           Pointer to the tvbuff_t holding the captured data.
 * param[in] pinfo         Pointer to the packet_info holding information about the currently dissected packet.
 * param[in] tree          Pointer to the proto_tree used to hold the display tree in Wireshark's interface.
 * param[in] offset        Offset from the beginning of the tvbuff_t where the Thrift field is. Function will dissect type, id, & data.
 * param[in] thrift_opt    Options from the Thrift dissector that will be necessary for sub-dissection (binary vs. compact, ...)
 * param[in] is_field      Indicate if the offset point to a field element and if field type and field id must be dissected.
 *                         Only for internal use in containers. Sub-dissectors must always use TRUE except for struct (see below).
 *                         Sub-dissectors should always use TRUE except in one case:
 *                         - Define the parameters of the Thrift command as a struct (including T_STOP at the end)
 *                         - Single call to dissect_thrift_t_struct with is_field = FALSE.
 * param[in] field_id      Thrift field identifier, to check that the right field is being dissected (in case of optional fields).
 * param[in] hf_id         A header field of FT_BYTES which will be the struct header field
 *
 * param[in] ett_id        An ett field used for the subtree created to list the container's elements.
 *
 * param[in] key           Description of the map's key elements.
 * param[in] val           Description of the map's value elements.
 *
 * param[in] elt           Description of the list's or set's elements.
 *
 * param[in] seq           Sequence of descriptions of the structure's members.
 *                          An array of thrift_member_t's containing thrift type of the struct members the hf variable to use etc.
 *
 * return                  Offset of the first non-dissected byte in case of success,
 *                         Same error values and remarks as above.
 */
WS_DLL_PUBLIC int dissect_thrift_t_map   (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *key, const thrift_member_t *val);
WS_DLL_PUBLIC int dissect_thrift_t_set   (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *elt);
WS_DLL_PUBLIC int dissect_thrift_t_list  (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *elt);
WS_DLL_PUBLIC int dissect_thrift_t_struct(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, thrift_option_data_t *thrift_opt, gboolean is_field, int field_id, gint hf_id, gint ett_id, const thrift_member_t *seq);

#endif /*__PACKET_THRIFT_H__ */
