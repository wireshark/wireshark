/* packet-protobuf.c
 * Routines for Google Protocol Buffers dissection
 * Copyright 2017, Huang Qiangxiong <qiangxiong.huang@qq.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The information used comes from:
 * https://developers.google.cn/protocol-buffers/docs/encoding
 *
 * This protobuf dissector may be invoked by GRPC dissector.
 *
 * TODO
 *   Support custom preference settings for embedded messages.
 *   Dissect message according to '*.proto' files.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/proto_data.h>

#include "packet-protobuf.h"

#include "wsutil/pint.h"

/* converting */
static inline gdouble
protobuf_uint64_to_double(guint64 value) {
    union { gdouble f; guint64 i; } double_uint64_union;

    double_uint64_union.i = value;
    return double_uint64_union.f;
}

static inline gfloat
protobuf_uint32_to_float(guint32 value) {
    union { gfloat f; guint32 i; } float_uint32_union;

    float_uint32_union.i = value;
    return float_uint32_union.f;
}

VALUE_STRING_ARRAY_GLOBAL_DEF(protobuf_wire_type);

/* Protobuf field type. Must be kept in sync with FieldType of protobuf wire_format_lite.h */
#define protobuf_field_type_VALUE_STRING_LIST(XXX)    \
    XXX(PROTOBUF_TYPE_NONE, 0, "") \
    XXX(PROTOBUF_TYPE_DOUBLE, 1, "double")  \
    XXX(PROTOBUF_TYPE_FLOAT, 2, "float")   \
    XXX(PROTOBUF_TYPE_INT64, 3, "int64") \
    XXX(PROTOBUF_TYPE_UINT64, 4, "uint64") \
    XXX(PROTOBUF_TYPE_INT32, 5, "int32") \
    XXX(PROTOBUF_TYPE_FIXED64, 6, "fixed64") \
    XXX(PROTOBUF_TYPE_FIXED32, 7, "fixed32")  \
    XXX(PROTOBUF_TYPE_BOOL, 8, "bool")  \
    XXX(PROTOBUF_TYPE_STRING, 9, "string")  \
    XXX(PROTOBUF_TYPE_GROUP, 10, "group(packed_repeated)")  \
    XXX(PROTOBUF_TYPE_MESSAGE, 11, "message")  \
    XXX(PROTOBUF_TYPE_BYTES, 12, "bytes")  \
    XXX(PROTOBUF_TYPE_UINT32, 13, "uint32")  \
    XXX(PROTOBUF_TYPE_ENUM, 14, "enum")  \
    XXX(PROTOBUF_TYPE_SFIXED32, 15, "sfixed32")  \
    XXX(PROTOBUF_TYPE_SFIXED64, 16, "sfixed64")  \
    XXX(PROTOBUF_TYPE_SINT32, 17, "sint32")  \
    XXX(PROTOBUF_TYPE_SINT64, 18, "sint64")

#define PROTOBUF_MAX_FIELD_TYPE 18

VALUE_STRING_ENUM(protobuf_field_type);
VALUE_STRING_ARRAY(protobuf_field_type);

/* which field type of each wire type could be */
static int protobuf_wire_to_field_type[6][9] = {
    /* PROTOBUF_WIRETYPE_VARINT, 0, "varint") */
    { PROTOBUF_TYPE_INT32, PROTOBUF_TYPE_INT64, PROTOBUF_TYPE_UINT32, PROTOBUF_TYPE_UINT64,
      PROTOBUF_TYPE_SINT32, PROTOBUF_TYPE_SINT64, PROTOBUF_TYPE_BOOL, PROTOBUF_TYPE_ENUM,
      PROTOBUF_TYPE_NONE },

    /* PROTOBUF_WIRETYPE_FIXED64, 1, "64-bit")   */
    { PROTOBUF_TYPE_FIXED64, PROTOBUF_TYPE_SFIXED64, PROTOBUF_TYPE_DOUBLE,
      PROTOBUF_TYPE_NONE },

    /* PROTOBUF_WIRETYPE_LENGTH_DELIMITED, 2, "Length-delimited") */
    { PROTOBUF_TYPE_STRING, PROTOBUF_TYPE_BYTES, PROTOBUF_TYPE_MESSAGE, PROTOBUF_TYPE_GROUP,
      PROTOBUF_TYPE_NONE },

    /* PROTOBUF_WIRETYPE_START_GROUP, 3, "Start group (deprecated)") */
    { PROTOBUF_TYPE_NONE },

    /* PROTOBUF_WIRETYPE_END_GROUP, 4, "End group (deprecated)") */
    { PROTOBUF_TYPE_NONE },

    /* PROTOBUF_WIRETYPE_FIXED32, 5, "32-bit") */
    { PROTOBUF_TYPE_FIXED32, PROTOBUF_TYPE_SINT32, PROTOBUF_TYPE_FLOAT,
      PROTOBUF_TYPE_NONE }
};

void proto_register_protobuf(void);
void proto_reg_handoff_protobuf(void);

static int proto_protobuf = -1;

/* field tag */
static int hf_protobuf_field_number = -1;
static int hf_protobuf_wire_type = -1;

/* field value */
static int hf_protobuf_value_length = -1; /* only Length-delimited field has */
static int hf_protobuf_value_data = -1;
static int hf_protobuf_value_double = -1;
static int hf_protobuf_value_float = -1;
static int hf_protobuf_value_int64 = -1;
static int hf_protobuf_value_uint64 = -1;
static int hf_protobuf_value_int32 = -1;
static int hf_protobuf_value_uint32 = -1;
static int hf_protobuf_value_bool = -1;
static int hf_protobuf_value_string = -1;
static int hf_protobuf_value_repeated = -1;

/* expert */
static expert_field ei_protobuf_failed_parse_tag = EI_INIT;
static expert_field ei_protobuf_failed_parse_length_delimited_field = EI_INIT;
static expert_field ei_protobuf_failed_parse_field = EI_INIT;
static expert_field ei_protobuf_wire_type_invalid = EI_INIT;

/* trees */
static int ett_protobuf = -1;
static int ett_protobuf_field = -1;
static int ett_protobuf_value = -1;
static int ett_protobuf_packed_repeated = -1;

/* preferences */
gboolean try_dissect_as_string = FALSE;
gboolean try_dissect_as_repeated = FALSE;
gboolean show_all_possible_field_types = FALSE;

static dissector_handle_t protobuf_handle;

/* Stuff for generation/handling of fields */
typedef struct {
    gchar* call_path; /* equals to grpc :path, for example: "/helloworld.Greeter/SayHello" */
    guint direction_type; /* 0: request, 1: response */
    guint field_type; /* type of field, refer to protobuf_field_type vals. */
    gchar* field_name; /* field name, will display in tree */
    guint field_number; /* field number in .proto file*/
} protobuf_field_t;

static GHashTable* protobuf_fields_hash = NULL;

/* get field info according to call_path, direction_type and field_number
* user should free the returned struct. */
static protobuf_field_t*
protobuf_find_field_info(const gchar* call_path_direction_type, int field_number)
{
    gchar* key = wmem_strdup_printf(wmem_packet_scope(), "%s,%d", call_path_direction_type, field_number);
    protobuf_field_t* p = (protobuf_field_t*)g_hash_table_lookup(protobuf_fields_hash, key);
    return p;
}

/* If you use int32 or int64 as the type for a negative number, the resulting varint is always
 * ten bytes long - it is, effectively, treated like a very large unsigned integer. If you use
 * one of the signed types, the resulting varint uses ZigZag encoding, which is much more efficient.
 * ZigZag encoding maps signed integers to unsigned integers so that numbers with a small absolute
 * value (for instance, -1) have a small varint encoded value too. (refers to protobuf spec)
 *      sint32 encoded using   (n << 1) ^ (n >> 31)
 */
static gint32
sint32_decode(guint32 sint32) {
    return (sint32 >> 1) ^ ((gint32)sint32 << 31 >> 31);
}

/* sint64 encoded using   (n << 1) ^ (n >> 63) */
static gint64
sint64_decode(guint64 sint64) {
    return (sint64 >> 1) ^ ((gint64)sint64 << 63 >> 63);
}

/* declare first because it will be called by dissect_packed_repeated_field_values */
static void
protobuf_try_dissect_field_value_on_multi_types(proto_tree *value_tree, tvbuff_t *tvb, guint offset, guint length,
    packet_info *pinfo, void *data, proto_item *ti_field, int wire_type, int* field_types, const guint64 value);

/* format tag + varint + varint + varint ...
return consumed bytes */
static guint
dissect_packed_repeated_field_values(proto_tree *value_tree, tvbuff_t *tvb, guint start, guint length, packet_info *pinfo,
    void *data, proto_item *ti_field, int wire_type, int* field_types, const gchar* prepend_text)
{
    guint64 sub_value;
    guint sub_value_length;
    guint offset = start;
    guint max_offset = offset + length;
    int i;

    for (i = 0; field_types[i] != PROTOBUF_TYPE_NONE; ++i) {
        if (field_types[i] == PROTOBUF_TYPE_GROUP) {
            return 0; /* prevent dead loop */
        }
    }

    proto_item_append_text(ti_field, "%s Repeated: [", (prepend_text ? prepend_text : ""));
    proto_item *ti = proto_tree_add_item(value_tree, hf_protobuf_value_repeated, tvb, start, length, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_protobuf_packed_repeated);

    /* add varints into the packed-repeated subtree */
    while (offset < max_offset) {
        sub_value_length = tvb_get_varint(tvb, offset, max_offset - offset, &sub_value, ENC_VARINT_PROTOBUF);
        if (sub_value_length == 0) {
            /* not a valid packed repeated field */
            return 0;
        }

        protobuf_try_dissect_field_value_on_multi_types(subtree, tvb, offset, sub_value_length, pinfo, data,
            ti_field, wire_type, field_types, sub_value);

        offset += sub_value_length;
    }

    proto_item_append_text(ti_field, "]");

    return length;
}

/* dissect field value based on a specific type. if pfield_info is given,  we use pfield_info->field_type
 * insteadof field_type parameter and we will show field_name.
 */
static void
protobuf_dissect_field_value(proto_tree *value_tree, tvbuff_t *tvb, guint offset, guint length, packet_info *pinfo,
    void *data, proto_item *ti_field, int wire_type, int field_type, const guint64 value, protobuf_field_t *pfield_info)
{
    gdouble double_value;
    gfloat float_value;
    gint64 int64_value;
    gint32 int32_value;
    guint8* buf;
    gboolean add_datatype = TRUE;

    gchar* prepend_text;

    if (pfield_info && pfield_info->field_name && strlen(pfield_info->field_name) >0) {
        field_type = pfield_info->field_type;
        prepend_text = wmem_strdup_printf(wmem_packet_scope(), ", %s =", pfield_info->field_name);
    } else {
        prepend_text = ",";
    }

    switch (field_type)
    {
    case PROTOBUF_TYPE_DOUBLE:
        double_value = protobuf_uint64_to_double(value);
        proto_tree_add_double(value_tree, hf_protobuf_value_double, tvb, offset, length, double_value);
        proto_item_append_text(ti_field, "%s %lf", prepend_text, double_value);
        break;

    case PROTOBUF_TYPE_FLOAT:
        float_value = protobuf_uint32_to_float((guint32) value);
        proto_tree_add_float(value_tree, hf_protobuf_value_float, tvb, offset, length, float_value);
        proto_item_append_text(ti_field, "%s %f", prepend_text, float_value);
        break;

    case PROTOBUF_TYPE_INT64:
    case PROTOBUF_TYPE_SFIXED64:
        int64_value = (gint64) value;
        proto_tree_add_int64(value_tree, hf_protobuf_value_int64, tvb, offset, length, int64_value);
        proto_item_append_text(ti_field, "%s %" G_GINT64_MODIFIER "d", prepend_text, int64_value);
        break;

    case PROTOBUF_TYPE_UINT64:
    case PROTOBUF_TYPE_FIXED64: /* same as UINT64 */
        proto_tree_add_uint64(value_tree, hf_protobuf_value_uint64, tvb, offset, length, value);
        proto_item_append_text(ti_field, "%s %" G_GINT64_MODIFIER "u", prepend_text, value);
        break;

    case PROTOBUF_TYPE_INT32:
    case PROTOBUF_TYPE_SFIXED32:
        int32_value = (gint32) value;
        proto_tree_add_int(value_tree, hf_protobuf_value_int32, tvb, offset, length, int32_value);
        proto_item_append_text(ti_field, "%s %d", prepend_text, int32_value);
        break;

    case PROTOBUF_TYPE_BOOL:
        if (length > 1) break; /* boolean should not use more than one bytes */
        proto_tree_add_boolean(value_tree, hf_protobuf_value_bool, tvb, offset, length, (guint32)value);
        proto_item_append_text(ti_field, "%s %s", prepend_text, value ? "true" : "false");
        break;

    case PROTOBUF_TYPE_STRING:
        buf = (guint8*) wmem_alloc(wmem_packet_scope(), length + 1);
        tvb_get_nstringz0(tvb, offset, length + 1, buf);
        proto_tree_add_string(value_tree, hf_protobuf_value_string, tvb, offset, length, buf);
        proto_item_append_text(ti_field, "%s %s", prepend_text, buf);
        break;

    case PROTOBUF_TYPE_GROUP:
        if (try_dissect_as_repeated) {
            int field_types[] = { PROTOBUF_TYPE_UINT64, PROTOBUF_TYPE_NONE };
            dissect_packed_repeated_field_values(value_tree, tvb, offset, length, pinfo, data, ti_field, wire_type,
                field_types, prepend_text);
        }
        add_datatype = FALSE;
        break;

    case PROTOBUF_TYPE_MESSAGE:
        /* may call dissect_protobuf(tvb, pinfo, value_tree, data); */
        add_datatype = FALSE;
        break;

    case PROTOBUF_TYPE_BYTES:
        /* do nothing */
        add_datatype = FALSE;
        break;

    case PROTOBUF_TYPE_ENUM:
    case PROTOBUF_TYPE_UINT32:
    case PROTOBUF_TYPE_FIXED32: /* same as UINT32 */
        proto_tree_add_uint(value_tree, hf_protobuf_value_uint32, tvb, offset, length, (guint32)value);
        proto_item_append_text(ti_field, "%s %u", prepend_text, (guint32)value);
        break;

    case PROTOBUF_TYPE_SINT32:
        int32_value = sint32_decode((guint32)value);
        proto_tree_add_int(value_tree, hf_protobuf_value_int32, tvb, offset, length, int32_value);
        proto_item_append_text(ti_field, "%s %d", prepend_text, int32_value);
        break;

    case PROTOBUF_TYPE_SINT64:
        int64_value = sint64_decode(value);
        proto_tree_add_int64(value_tree, hf_protobuf_value_int64, tvb, offset, length, int64_value);
        proto_item_append_text(ti_field, "%s %" G_GINT64_MODIFIER "d", prepend_text, int64_value);
        break;

    default:
        /* ignore unknown field type */
        add_datatype = FALSE;
        break;
    }

    if (add_datatype)
        proto_item_append_text(ti_field, " (%s)", val_to_str(field_type, protobuf_field_type, "Unknown type (%d)"));

}

/* add all possible values according to field types. */
static void
protobuf_try_dissect_field_value_on_multi_types(proto_tree *value_tree, tvbuff_t *tvb, guint offset, guint length,
    packet_info *pinfo, void *data, proto_item *ti_field, int wire_type, int* field_types, const guint64 value)
{
    int i;
    for (i = 0; field_types[i] != PROTOBUF_TYPE_NONE; ++i) {
        protobuf_dissect_field_value(value_tree, tvb, offset, length, pinfo, data, ti_field, wire_type, field_types[i],
            value, NULL);
    }
}

static gboolean
dissect_one_protobuf_field(tvbuff_t *tvb, guint* offset, guint maxlen, packet_info *pinfo,
    proto_tree *protobuf_tree, void *data)
{
    guint64 tag_value; /* tag value = (field_number << 3) | wire_type */
    guint tag_length; /* how many bytes this tag has */
    guint64 field_number;
    guint32 wire_type;
    guint64 value_uint64; /* uint64 value of numeric field (type of varint, 64-bit, 32-bit */
    guint value_length;
    guint value_length_size = 0; /* only Length-delimited field has it */
    proto_item *ti_field, *ti_wire;
    proto_item *ti_value;
    proto_tree *field_tree;
    proto_tree *value_tree;
    protobuf_field_t* pfield_info = NULL;

    /* A protocol buffer message is a series of key-value pairs. The binary version of a message just uses
     * the field's number as the key. a wire type that provides just enough information to find the length of
     * the following value.
     * Format of protobuf is:
     *       protobuf field -> tag value
     *       tag -> (field_number << 3) | wire_type  (the last three bits of the number store the wire type)
     *       value -> according to wiret_type, value may be
     *                 - varint (int32, int64, uint32, uint64, sint32, sint64, bool, enum),
     *                 - 64-bit number (fixed64, sfixed64, double)
     *                 - Length-delimited (string, bytes, embedded messages, packed repeated fields)
     *                 - deprecated 'Start group' or 'End group' (we stop dissecting when encountered them)
     *                 - 32-bit (fixed32, sfixed32, float)
     * All numbers in protobuf are stored in little-endian byte order.
     */

    field_tree = proto_tree_add_subtree(protobuf_tree,  tvb, *offset, 0, ett_protobuf_field, &ti_field, "Field");

    /* parsing Tag */
    tag_length = tvb_get_varint(tvb, *offset, maxlen, &tag_value, ENC_VARINT_PROTOBUF);

    if (tag_length == 0) { /* not found a valid varint */
        expert_add_info(pinfo, ti_field, &ei_protobuf_failed_parse_tag);
        return FALSE;
    }

    proto_tree_add_item_ret_uint64(field_tree, hf_protobuf_field_number, tvb, *offset, tag_length, ENC_LITTLE_ENDIAN|ENC_VARINT_PROTOBUF, &field_number);
    ti_wire = proto_tree_add_item_ret_uint(field_tree, hf_protobuf_wire_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN|ENC_VARINT_PROTOBUF, &wire_type);
    (*offset) += tag_length;

    proto_item_append_text(ti_field, "[%" G_GINT64_MODIFIER "u]", field_number);

    /* determine value_length, uint of numeric value and maybe value_length_size according to wire_type */
    switch (wire_type)
    {
    case PROTOBUF_WIRETYPE_VARINT: /* varint, format: tag + varint */
        /* get value length and real value */
        value_length = tvb_get_varint(tvb, *offset, maxlen - tag_length, &value_uint64, ENC_VARINT_PROTOBUF);
        if (value_length == 0) {
            expert_add_info(pinfo, ti_wire, &ei_protobuf_failed_parse_field);
            return FALSE;
        }
        break;

    case PROTOBUF_WIRETYPE_FIXED64: /* fixed 64-bit type, format: tag + 64-bit-value */
        /* get value length and real value */
        value_length = 8;
        value_uint64 = tvb_get_letoh64(tvb, *offset);
        break;

    case PROTOBUF_WIRETYPE_FIXED32: /* fixed 32-bit type, format: tag + 32-bit-value */
        value_length = 4;
        value_uint64 = tvb_get_letohl(tvb, *offset);
        break;

    case PROTOBUF_WIRETYPE_LENGTH_DELIMITED: /* Length-delimited, format: tag + length(varint) + bytes_value */
        /* this time value_uint64 is the length of following value bytes */
        value_length_size = tvb_get_varint(tvb, *offset, maxlen - tag_length, &value_uint64, ENC_VARINT_PROTOBUF);
        if (value_length_size == 0) {
            expert_add_info(pinfo, ti_field, &ei_protobuf_failed_parse_length_delimited_field);
            return FALSE;
        }

        proto_tree_add_uint64(field_tree, hf_protobuf_value_length, tvb, *offset, value_length_size, value_uint64);
        (*offset) += value_length_size;

        /* we believe the length of following value will not be bigger than guint */
        value_length = (guint) value_uint64;
        break;

    default:
        expert_add_info(pinfo, ti_wire, &ei_protobuf_wire_type_invalid);
        return FALSE;
    }

    proto_item_set_len(ti_field, tag_length + value_length_size + value_length);

    /* add value as bytes first */
    ti_value = proto_tree_add_item(field_tree, hf_protobuf_value_data, tvb, *offset, value_length, ENC_NA);

    /* add value subtree. we add uint value for numeric field or string for length-delimited at least. */
    value_tree = proto_item_add_subtree(ti_value, ett_protobuf_value);

    /* try to find field_info first */
    if (data) {
        const gchar* message_info = (const gchar*)data;
        /* find call_path + request or response part from format:
        *   http2_content_type "," http2_path "," ("request" / "response")
        * Acording to grpc wire format guide, it will be:
        *   "application/grpc" [("+proto" / "+json" / {custom})] "," "/" service-name "/" method-name "/" "," ("request" / "response")
        * For example:
        *   application/grpc,/helloworld.Greeter/SayHello,request
        */
        message_info = strchr(message_info, ',');
        if (message_info) {
            message_info++;
        }
        pfield_info = protobuf_find_field_info(message_info, (gint) field_number);
    }

    if (pfield_info) {
        protobuf_dissect_field_value(value_tree, tvb, *offset, value_length, pinfo, data, ti_field, wire_type,
            pfield_info->field_type, value_uint64, pfield_info);
    } else {
        if (show_all_possible_field_types) {
            /* try dissect every possible field type */
            protobuf_try_dissect_field_value_on_multi_types(value_tree, tvb, *offset, value_length, pinfo, data,
                ti_field, wire_type, protobuf_wire_to_field_type[wire_type], value_uint64);
        } else {
            int field_type = (wire_type == PROTOBUF_WIRETYPE_LENGTH_DELIMITED)
                /* print string at least for length-delimited */
                ? (try_dissect_as_string ? PROTOBUF_TYPE_STRING : PROTOBUF_TYPE_NONE)
                /* use uint32 or uint64 */
                : (value_uint64 <= 0xFFFFFFFF ? PROTOBUF_TYPE_UINT32 : PROTOBUF_TYPE_UINT64);
            int field_types[] = { field_type, PROTOBUF_TYPE_NONE };

            protobuf_try_dissect_field_value_on_multi_types(value_tree, tvb, *offset, value_length, pinfo, data,
                ti_field, wire_type, field_types, value_uint64);
        }
    }

    (*offset) += value_length;
    return TRUE;
}

static int
dissect_protobuf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *protobuf_tree;
    guint offset = 0;

    /* may set col_set_str(pinfo->cinfo, COL_PROTOCOL, "PROTOBUF"); */
    col_append_str(pinfo->cinfo, COL_INFO, " (PROTOBUF)");

    ti = proto_tree_add_item(tree, proto_protobuf, tvb, 0, -1, ENC_NA);
    protobuf_tree = proto_item_add_subtree(ti, ett_protobuf);

    if (data) {
        /* append to proto item */
        proto_item_append_text(ti, ": %s", (const gchar*)data);
    }

    /* each time we dissect one protobuf field. */
    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        if (!dissect_one_protobuf_field(tvb, &offset, tvb_reported_length_remaining(tvb, offset), pinfo, protobuf_tree, data))
            break;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_protobuf(void)
{
    static hf_register_info hf[] = {
        { &hf_protobuf_field_number,
            { "Field Number", "protobuf.field.number",
               FT_UINT64, BASE_DEC, NULL, G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFF8),
              "Field number encoded in varint", HFILL }
        },
        { &hf_protobuf_wire_type,
            { "Wire Type", "protobuf.field.wiretype",
               FT_UINT8, BASE_DEC, VALS(protobuf_wire_type), 0x07,
              "The Wire Type of the field.", HFILL }
        },
        { &hf_protobuf_value_length,
            { "Value Length", "protobuf.field.value.length",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "The length of length-delimited field value.", HFILL }
        },
        { &hf_protobuf_value_data,
            { "Value", "protobuf.field.value",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "The wire type determines value format", HFILL }
        },
        { &hf_protobuf_value_double,
            { "Double", "protobuf.field.value.double",
               FT_DOUBLE, BASE_NONE, NULL, 0x0,
              "Dissect value as double", HFILL }
        },
        { &hf_protobuf_value_float,
            { "Float", "protobuf.field.value.float",
               FT_FLOAT, BASE_NONE, NULL, 0x0,
              "Dissect value as float", HFILL }
        },
        { &hf_protobuf_value_int64,
            { "Int64", "protobuf.field.value.int64",
               FT_INT64, BASE_DEC, NULL, 0x0,
              "Dissect value as int64", HFILL }
        },
        { &hf_protobuf_value_uint64,
            { "Uint64", "protobuf.field.value.uint64",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "Dissect value as uint64", HFILL }
        },
        { &hf_protobuf_value_int32,
            { "Int32", "protobuf.field.value.int32",
               FT_INT32, BASE_DEC, NULL, 0x0,
              "Dissect value as int32", HFILL }
        },
        { &hf_protobuf_value_uint32,
            { "Uint32", "protobuf.field.value.uint32",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "Dissect value as uint32", HFILL }
        },
        { &hf_protobuf_value_bool,
            { "Bool", "protobuf.field.value.bool",
               FT_BOOLEAN, BASE_DEC, NULL, 0x0,
              "Dissect value as bool", HFILL }
        },
        { &hf_protobuf_value_string,
            { "String", "protobuf.field.value.string",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "Dissect value as string", HFILL }
        },
        { &hf_protobuf_value_repeated,
            { "Repeated", "protobuf.field.value.repeated",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "Dissect value as repeated", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_protobuf,
        &ett_protobuf_field,
        &ett_protobuf_value,
        &ett_protobuf_packed_repeated
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_protobuf_failed_parse_tag,
          { "protobuf.failed_parse_tag", PI_MALFORMED, PI_ERROR,
            "Failed to parse tag field", EXPFILL }
        },
        { &ei_protobuf_wire_type_invalid,
          { "protobuf.field.wiretype.invalid", PI_PROTOCOL, PI_WARN,
            "Unknown or unsupported wiretype", EXPFILL }
        },
        { &ei_protobuf_failed_parse_length_delimited_field,
          { "protobuf.field.failed_parse_length_delimited_field", PI_MALFORMED, PI_ERROR,
            "Failed to parse length delimited field", EXPFILL }
        },
        { &ei_protobuf_failed_parse_field,
          { "protobuf.field.failed_parse_field", PI_MALFORMED, PI_ERROR,
            "Failed to parse value field", EXPFILL }
        },
    };

    module_t *protobuf_module;
    expert_module_t *expert_protobuf;

    proto_protobuf = proto_register_protocol("Protocol Buffers", "ProtoBuf", "protobuf");

    proto_register_field_array(proto_protobuf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    protobuf_module = prefs_register_protocol(proto_protobuf, NULL);

    prefs_register_bool_preference(protobuf_module, "try_dissect_all_length_delimited_field_as_string",
        "Try to dissect all length-delimited field as string.",
        "Try to dissect all length-delimited field as string.",
        &try_dissect_as_string);

    prefs_register_bool_preference(protobuf_module, "try_dissect_length_delimited_field_as_repeated",
        "Try to dissect length-delimited field as repeated.",
        "Try to dissect length-delimited field as repeated.",
        &try_dissect_as_repeated);

    prefs_register_bool_preference(protobuf_module, "show_all_possible_field_types",
        "Try to show all possible field types for each field.",
        "Try to show all possible field types for each field according to wire type.",
        &show_all_possible_field_types);

    expert_protobuf = expert_register_protocol(proto_protobuf);
    expert_register_field_array(expert_protobuf, ei, array_length(ei));

    protobuf_handle = register_dissector("protobuf", dissect_protobuf, proto_protobuf);
}

void
proto_reg_handoff_protobuf(void)
{
    dissector_add_uint_range_with_preference("udp.port", "", protobuf_handle);

    dissector_add_string("grpc_message_type", "application/grpc", protobuf_handle);
    dissector_add_string("grpc_message_type", "application/grpc+proto", protobuf_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
