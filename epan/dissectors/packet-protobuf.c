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
 * https://developers.google.com/protocol-buffers/docs/encoding
 *
 * This protobuf dissector may be invoked by GRPC dissector or other dissectors.
 * Other dissectors can give protobuf message type info by the data argument or private_table["pb_msg_type"]
 * before call protobuf dissector.
 * For GRPC dissector the data argument format is:
 *    "application/grpc" ["+proto"] "," "/" service-name "/" method-name "," ("request" / "response")
 * For example:
 *    application/grpc,/helloworld.Greeter/SayHello,request
 * In this format, we will try to get real protobuf message type by method (service-name.method-name)
 * and in/out type (request / reponse).
 * For other dissectors can specifies message type directly, like:
 *    "message," message_type_name
 * For example:
 *    message,helloworld.HelloRequest      (helloworld is package, HelloRequest is message type)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/strutil.h>
#include <epan/proto_data.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/pint.h>
#include <wsutil/ws_printf.h>
#include <wsutil/report_message.h>

#include "protobuf-helper.h"
#include "packet-protobuf.h"

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

#define PREFS_UPDATE_PROTOBUF_SEARCH_PATHS            1
#define PREFS_UPDATE_PROTOBUF_UDP_MESSAGE_TYPES       2
#define PREFS_UPDATE_ALL   (PREFS_UPDATE_PROTOBUF_SEARCH_PATHS | PREFS_UPDATE_PROTOBUF_UDP_MESSAGE_TYPES)

static void protobuf_reinit(int target);

static int proto_protobuf = -1;

static gboolean protobuf_dissector_called = FALSE;

/* information get from *.proto files */
static int hf_protobuf_message_name = -1;
static int hf_protobuf_field_name = -1;
static int hf_protobuf_field_type = -1;

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
static expert_field et_protobuf_message_type_not_found = EI_INIT;
static expert_field et_protobuf_wire_type_not_support_packed_repeated = EI_INIT;
static expert_field et_protobuf_failed_parse_packed_repeated_field = EI_INIT;

/* trees */
static int ett_protobuf = -1;
static int ett_protobuf_message = -1;
static int ett_protobuf_field = -1;
static int ett_protobuf_value = -1;
static int ett_protobuf_packed_repeated = -1;

/* preferences */
static gboolean try_dissect_as_string = FALSE;
static gboolean show_all_possible_field_types = FALSE;
static gboolean dissect_bytes_as_string = FALSE;
static gboolean old_dissect_bytes_as_string = FALSE;
static gboolean show_details = FALSE;
static gboolean pbf_as_hf = FALSE; /* dissect protobuf fields as header fields of wireshark */

/* dynamic wireshark header fields for protobuf fields */
static hf_register_info *dynamic_hf = NULL;
static guint dynamic_hf_size = 0;
/* the key is full name of protobuf fields, the value is header field id */
static GHashTable *pbf_hf_hash = NULL;

/* Protobuf field value subdissector table list.
 * Only valid for the value of PROTOBUF_TYPE_BYTES or PROTOBUF_TYPE_STRING fields.
 */
static dissector_table_t protobuf_field_subdissector_table;

static dissector_handle_t protobuf_handle;

/* store varint tvb info */
typedef struct {
    guint offset;
    guint length;
    guint64 value;
} protobuf_varint_tvb_info_t;

static PbwDescriptorPool* pbw_pool = NULL;

/* protobuf source files search paths */
typedef struct {
    char* path; /* protobuf source files searching directory path */
    gboolean load_all; /* load all *.proto files in this directory and its sub directories */
} protobuf_search_path_t;

static protobuf_search_path_t* protobuf_search_paths = NULL;
static guint num_protobuf_search_paths = 0;

static void *
protobuf_search_paths_copy_cb(void* n, const void* o, size_t siz _U_)
{
    protobuf_search_path_t* new_rec = (protobuf_search_path_t*)n;
    const protobuf_search_path_t* old_rec = (const protobuf_search_path_t*)o;

    /* copy interval values like gint */
    memcpy(new_rec, old_rec, sizeof(protobuf_search_path_t));

    if (old_rec->path)
        new_rec->path = g_strdup(old_rec->path);

    return new_rec;
}

static void
protobuf_search_paths_free_cb(void*r)
{
    protobuf_search_path_t* rec = (protobuf_search_path_t*)r;

    g_free(rec->path);
}

UAT_DIRECTORYNAME_CB_DEF(protobuf_search_paths, path, protobuf_search_path_t)
UAT_BOOL_CB_DEF(protobuf_search_paths, load_all, protobuf_search_path_t)

/* the protobuf message type of the data on certain udp ports */
typedef struct {
    range_t  *udp_port_range; /* dissect data on these udp ports as protobuf */
    gchar    *message_type; /* protobuf message type of data on these udp ports */
} protobuf_udp_message_type_t;

static protobuf_udp_message_type_t* protobuf_udp_message_types = NULL;
static guint num_protobuf_udp_message_types = 0;

static void *
protobuf_udp_message_types_copy_cb(void* n, const void* o, size_t siz _U_)
{
    protobuf_udp_message_type_t* new_rec = (protobuf_udp_message_type_t*)n;
    const protobuf_udp_message_type_t* old_rec = (const protobuf_udp_message_type_t*)o;

    /* copy interval values like gint */
    memcpy(new_rec, old_rec, sizeof(protobuf_udp_message_type_t));

    if (old_rec->udp_port_range)
        new_rec->udp_port_range = range_copy(NULL, old_rec->udp_port_range);
    if (old_rec->message_type)
        new_rec->message_type = g_strdup(old_rec->message_type);

    return new_rec;
}

static gboolean
protobuf_udp_message_types_update_cb(void *r, char **err)
{
    protobuf_udp_message_type_t* rec = (protobuf_udp_message_type_t*)r;
    static range_t *empty;

    empty = range_empty(NULL);
    if (ranges_are_equal(rec->udp_port_range, empty)) {
        *err = g_strdup("Must specify UDP port(s) (like 8000 or 8000,8008-8088)");
        wmem_free(NULL, empty);
        return FALSE;
    }

    wmem_free(NULL, empty);
    return TRUE;
}

static void
protobuf_udp_message_types_free_cb(void*r)
{
    protobuf_udp_message_type_t* rec = (protobuf_udp_message_type_t*)r;

    wmem_free(NULL, rec->udp_port_range);
    g_free(rec->message_type);
}

UAT_RANGE_CB_DEF(protobuf_udp_message_types, udp_port_range, protobuf_udp_message_type_t)
UAT_CSTRING_CB_DEF(protobuf_udp_message_types, message_type, protobuf_udp_message_type_t)

static GSList* old_udp_port_ranges = NULL;

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
protobuf_dissect_field_value(proto_tree *value_tree, tvbuff_t *tvb, guint offset, guint length, packet_info *pinfo,
    proto_item *ti_field, int field_type, const guint64 value, const gchar* prepend_text, const PbwFieldDescriptor* field_desc, gboolean is_top_level);

static void
dissect_protobuf_message(tvbuff_t *tvb, guint offset, guint length, packet_info *pinfo, proto_tree *protobuf_tree, const PbwDescriptor* message_desc, gboolean is_top_level);

/* Only repeated fields of primitive numeric types (types which use the varint, 32-bit, or 64-bit wire types) can
 * be declared "packed".
 * The format of a packed_repeated field likes: tag + varint + varint + varint ...
 * or likes: tag + fixed64 + fixed64 + fixed64 ...
 * Return consumed bytes
 */
static guint
dissect_packed_repeated_field_values(tvbuff_t *tvb, guint start, guint length, packet_info *pinfo,
    proto_item *ti_field, int wire_type, int field_type, const gchar* prepend_text, const PbwFieldDescriptor* field_desc)
{
    guint64 sub_value;
    guint sub_value_length;
    guint offset = start;
    protobuf_varint_tvb_info_t *info;
    guint max_offset = offset + length;
    wmem_list_frame_t *lframe;
    wmem_list_t* varint_list;
    int value_size = 0;

    if (prepend_text == NULL) {
        prepend_text = "";
    }

    /* prepare subtree */
    proto_item_append_text(ti_field, "%s [", prepend_text);
    proto_item *ti = proto_tree_add_item(proto_item_get_subtree(ti_field), hf_protobuf_value_repeated, tvb, start, length, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_protobuf_packed_repeated);

    prepend_text = "";

    switch (field_type)
    {
    /* packed for Varint encoded types (int32, int64, uint32, uint64, sint32, sint64, bool, enum) */
    /* format: tag + varint + varint + varint ... */
    case PROTOBUF_TYPE_INT32:
    case PROTOBUF_TYPE_INT64:
    case PROTOBUF_TYPE_UINT32:
    case PROTOBUF_TYPE_UINT64:
    case PROTOBUF_TYPE_SINT32:
    case PROTOBUF_TYPE_SINT64:
    case PROTOBUF_TYPE_BOOL:
    case PROTOBUF_TYPE_ENUM:
        varint_list = wmem_list_new(wmem_packet_scope());

        /* try to test all can parsed as varint */
        while (offset < max_offset) {
            sub_value_length = tvb_get_varint(tvb, offset, max_offset - offset, &sub_value, ENC_VARINT_PROTOBUF);
            if (sub_value_length == 0) {
                /* not a valid packed repeated field */
                wmem_destroy_list(varint_list);
                return 0;
            }

            /* temporarily store varint info in the list */
            info = wmem_new(wmem_packet_scope(), protobuf_varint_tvb_info_t);
            info->offset = offset;
            info->length = sub_value_length;
            info->value = sub_value;
            wmem_list_append(varint_list, info);

            offset += sub_value_length;
        }

        /* all parsed, we add varints into the packed-repeated subtree */
        for (lframe = wmem_list_head(varint_list); lframe != NULL; lframe = wmem_list_frame_next(lframe)) {
            info = (protobuf_varint_tvb_info_t*)wmem_list_frame_data(lframe);
            protobuf_dissect_field_value(subtree, tvb, info->offset, info->length, pinfo,
                ti_field, field_type, info->value, prepend_text, field_desc,  FALSE);
            prepend_text = ",";
        }

        wmem_destroy_list(varint_list);
        break;

    /* packed for 64-bit encoded types (fixed64, sfixed64, double) and 32-bit encoded types (fixed32, sfixed32, float) */
    /* format like: tag + sint32 + sint32 + sint32 ... */
    case PROTOBUF_TYPE_FIXED64:
    case PROTOBUF_TYPE_SFIXED64:
    case PROTOBUF_TYPE_DOUBLE:
        value_size = 8; /* 64-bit */
        /* FALLTHROUGH */
    case PROTOBUF_TYPE_FIXED32:
    case PROTOBUF_TYPE_SFIXED32:
    case PROTOBUF_TYPE_FLOAT:
        if (value_size == 0) {
            value_size = 4; /* 32-bit */
        }

        if (length % value_size != 0) {
            expert_add_info(pinfo, ti_field, &et_protobuf_failed_parse_packed_repeated_field);
            return 0;
        }

        for (offset = start; offset < max_offset; offset += value_size) {
            protobuf_dissect_field_value(subtree, tvb, offset, value_size, pinfo, ti_field, field_type,
                (wire_type == PROTOBUF_WIRETYPE_FIXED32 ? tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN)
                    : tvb_get_guint64(tvb, offset, ENC_LITTLE_ENDIAN)),
                prepend_text, field_desc, FALSE);
            prepend_text = ",";
        }

        break;

    default:
        expert_add_info(pinfo, ti_field, &et_protobuf_wire_type_not_support_packed_repeated);
        return 0; /* prevent dead loop */
    }

    proto_item_append_text(ti_field, "]");
    return length;
}

/* Dissect field value based on a specific type. */
static void
protobuf_dissect_field_value(proto_tree *value_tree, tvbuff_t *tvb, guint offset, guint length, packet_info *pinfo,
    proto_item *ti_field, int field_type, const guint64 value, const gchar* prepend_text, const PbwFieldDescriptor* field_desc, gboolean is_top_level)
{
    gdouble double_value;
    gfloat float_value;
    gint64 int64_value;
    gint32 int32_value;
    char* buf;
    gboolean add_datatype = TRUE;
    proto_item* ti = NULL;
    proto_tree* subtree = NULL;
    const char* enum_value_name = NULL;
    const PbwDescriptor* sub_message_desc = NULL;
    const PbwEnumDescriptor* enum_desc = NULL;
    int* hf_id_ptr = NULL;
    const gchar* field_full_name = field_desc ? pbw_FieldDescriptor_full_name(field_desc) : NULL;
    proto_tree* field_tree = proto_item_get_subtree(ti_field);
    proto_tree* field_parent_tree = proto_tree_get_parent_tree(field_tree);
    proto_tree* pbf_tree = field_tree;

    if (pbf_as_hf && field_full_name) {
        hf_id_ptr = (int*)g_hash_table_lookup(pbf_hf_hash, field_full_name);
        DISSECTOR_ASSERT_HINT(hf_id_ptr && (*hf_id_ptr) > 0, "hf must have been initialized properly");
    }

    if (pbf_as_hf && hf_id_ptr && !show_details) {
        /* set ti_field (Field(x)) item hidden if there is header_field */
        proto_item_set_hidden(ti_field);
        pbf_tree = field_parent_tree;
    }

    if (prepend_text == NULL) {
        prepend_text = "";
    }

    switch (field_type)
    {
    case PROTOBUF_TYPE_DOUBLE:
        double_value = protobuf_uint64_to_double(value);
        proto_tree_add_double(value_tree, hf_protobuf_value_double, tvb, offset, length, double_value);
        proto_item_append_text(ti_field, "%s %lf", prepend_text, double_value);
        if (is_top_level) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "=%lf", double_value);
        }
        if (hf_id_ptr) {
            proto_tree_add_double(pbf_tree, *hf_id_ptr, tvb, offset, length, double_value);
        }
        break;

    case PROTOBUF_TYPE_FLOAT:
        float_value = protobuf_uint32_to_float((guint32) value);
        proto_tree_add_float(value_tree, hf_protobuf_value_float, tvb, offset, length, float_value);
        proto_item_append_text(ti_field, "%s %f", prepend_text, float_value);
        if (is_top_level) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "=%f", float_value);
        }
        if (hf_id_ptr) {
            proto_tree_add_float(pbf_tree, *hf_id_ptr, tvb, offset, length, float_value);
        }
        break;

    case PROTOBUF_TYPE_INT64:
    case PROTOBUF_TYPE_SFIXED64:
        int64_value = (gint64) value;
        proto_tree_add_int64(value_tree, hf_protobuf_value_int64, tvb, offset, length, int64_value);
        proto_item_append_text(ti_field, "%s %" G_GINT64_MODIFIER "d", prepend_text, int64_value);
        if (is_top_level) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "=%" G_GINT64_MODIFIER "d", int64_value);
        }
        if (hf_id_ptr) {
            proto_tree_add_int64(pbf_tree, *hf_id_ptr, tvb, offset, length, int64_value);
        }
        break;

    case PROTOBUF_TYPE_UINT64:
    case PROTOBUF_TYPE_FIXED64: /* same as UINT64 */
        proto_tree_add_uint64(value_tree, hf_protobuf_value_uint64, tvb, offset, length, value);
        proto_item_append_text(ti_field, "%s %" G_GINT64_MODIFIER "u", prepend_text, value);
        if (is_top_level) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "=%" G_GINT64_MODIFIER "u", value);
        }
        if (hf_id_ptr) {
            proto_tree_add_uint64(pbf_tree, *hf_id_ptr, tvb, offset, length, value);
        }
        break;

    case PROTOBUF_TYPE_INT32:
    case PROTOBUF_TYPE_SFIXED32:
        int32_value = (gint32)value;
        proto_tree_add_int(value_tree, hf_protobuf_value_int32, tvb, offset, length, int32_value);
        proto_item_append_text(ti_field, "%s %d", prepend_text, int32_value);
        if (is_top_level) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "=%d", int32_value);
        }
        if (hf_id_ptr) {
            proto_tree_add_int(pbf_tree, *hf_id_ptr, tvb, offset, length, int32_value);
        }
        break;

    case PROTOBUF_TYPE_ENUM:
        int32_value = (gint32) value;
        /* get the name of enum value */
        if (field_desc) {
            enum_desc = pbw_FieldDescriptor_enum_type(field_desc);
            if (enum_desc) {
                const PbwEnumValueDescriptor* enum_value_desc = pbw_EnumDescriptor_FindValueByNumber(enum_desc, int32_value);
                if (enum_value_desc) {
                    enum_value_name = pbw_EnumValueDescriptor_name(enum_value_desc);
                }
            }
        }
        ti = proto_tree_add_int(value_tree, hf_protobuf_value_int32, tvb, offset, length, int32_value);
        if (enum_value_name) { /* show enum value name */
            proto_item_append_text(ti_field, "%s %s(%d)", prepend_text, enum_value_name, int32_value);
            proto_item_append_text(ti, " (%s)", enum_value_name);
            if (is_top_level) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "=%s", enum_value_name);
            }
        } else {
            proto_item_append_text(ti_field, "%s %d", prepend_text, int32_value);
            if (is_top_level) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "=%d", int32_value);
            }

        }
        if (hf_id_ptr) {
            proto_tree_add_int(pbf_tree, *hf_id_ptr, tvb, offset, length, int32_value);
        }
        break;

    case PROTOBUF_TYPE_BOOL:
        if (length > 1) break; /* boolean should not use more than one bytes */
        proto_tree_add_boolean(value_tree, hf_protobuf_value_bool, tvb, offset, length, (guint32)value);
        proto_item_append_text(ti_field, "%s %s", prepend_text, value ? "true" : "false");
        if (is_top_level) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "=%s", value ? "true" : "false");
        }
        if (hf_id_ptr) {
            proto_tree_add_boolean(pbf_tree, *hf_id_ptr, tvb, offset, length, (guint32)value);
        }
        break;

    case PROTOBUF_TYPE_BYTES:
        if (!dissect_bytes_as_string) {
            if (hf_id_ptr) {
                ti = proto_tree_add_bytes_format_value(pbf_tree, *hf_id_ptr, tvb, offset, length, NULL, "(%u bytes)", length);
            }
            break;
        }
        /* or continue dissect BYTES as STRING */
        /* FALLTHROUGH */
    case PROTOBUF_TYPE_STRING:
        ti = proto_tree_add_item_ret_display_string(value_tree, hf_protobuf_value_string, tvb, offset, length, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &buf);
        proto_item_append_text(ti_field, "%s %s", prepend_text, buf);
        if (is_top_level) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "=%s", buf);
        }
        if (hf_id_ptr) {
            ti = proto_tree_add_item_ret_display_string(pbf_tree, *hf_id_ptr, tvb, offset, length, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &buf);
        }
        break;

    case PROTOBUF_TYPE_GROUP: /* This feature is deprecated. GROUP is identical to Nested MESSAGE. */
    case PROTOBUF_TYPE_MESSAGE:
        subtree = field_tree;
        if (hf_id_ptr) {
            ti = proto_tree_add_bytes_format_value(pbf_tree, *hf_id_ptr, tvb, offset, length, NULL, "(%u bytes)", length);
            subtree = proto_item_add_subtree(ti, ett_protobuf_message);
        }
        if (field_desc) {
            sub_message_desc = pbw_FieldDescriptor_message_type(field_desc);
            if (sub_message_desc) {
                dissect_protobuf_message(tvb, offset, length, pinfo,
                    subtree, sub_message_desc, FALSE);
            } else {
                expert_add_info(pinfo, ti_field, &et_protobuf_message_type_not_found);
            }
        } else {
            /* we don't continue with unknown mssage type */
        }
        break;

    case PROTOBUF_TYPE_UINT32:
    case PROTOBUF_TYPE_FIXED32: /* same as UINT32 */
        proto_tree_add_uint(value_tree, hf_protobuf_value_uint32, tvb, offset, length, (guint32)value);
        proto_item_append_text(ti_field, "%s %u", prepend_text, (guint32)value);
        if (is_top_level) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "=%u", (guint32)value);
        }
        if (hf_id_ptr) {
            proto_tree_add_uint(pbf_tree, *hf_id_ptr, tvb, offset, length, (guint32)value);
        }
        break;

    case PROTOBUF_TYPE_SINT32:
        int32_value = sint32_decode((guint32)value);
        proto_tree_add_int(value_tree, hf_protobuf_value_int32, tvb, offset, length, int32_value);
        proto_item_append_text(ti_field, "%s %d", prepend_text, int32_value);
        if (is_top_level) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "=%d", int32_value);
        }
        if (hf_id_ptr) {
            proto_tree_add_int(pbf_tree, *hf_id_ptr, tvb, offset, length, int32_value);
        }
        break;

    case PROTOBUF_TYPE_SINT64:
        int64_value = sint64_decode(value);
        proto_tree_add_int64(value_tree, hf_protobuf_value_int64, tvb, offset, length, int64_value);
        proto_item_append_text(ti_field, "%s %" G_GINT64_MODIFIER "d", prepend_text, int64_value);
        if (is_top_level) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "=%" G_GINT64_MODIFIER "d", int64_value);
        }
        if (hf_id_ptr) {
            proto_tree_add_int64(pbf_tree, *hf_id_ptr, tvb, offset, length, int64_value);
        }
        break;

    default:
        /* ignore unknown field type */
        add_datatype = FALSE;
        break;
    }

    /* try dissect field value according to protobuf_field dissector table */
    if (field_full_name && (field_type == PROTOBUF_TYPE_BYTES || field_type == PROTOBUF_TYPE_STRING)) {
        /* determine the tree passing to the subdissector */
        subtree = value_tree;
        if (ti) {
            subtree = proto_item_get_subtree(ti);
            if (!subtree) {
                subtree = proto_item_add_subtree(ti, ett_protobuf_value);
            }
        }

        dissector_try_string(protobuf_field_subdissector_table, field_full_name,
            tvb_new_subset_length(tvb, offset, length), pinfo, subtree, NULL);
    }

    if (add_datatype)
        proto_item_append_text(ti_field, " (%s)", val_to_str(field_type, protobuf_field_type, "Unknown type (%d)"));

}

/* add all possible values according to field types. */
static void
protobuf_try_dissect_field_value_on_multi_types(proto_tree *value_tree, tvbuff_t *tvb, guint offset, guint length,
    packet_info *pinfo, proto_item *ti_field, int* field_types, const guint64 value, const gchar* prepend_text)
{
    int i;

    if (prepend_text == NULL) {
        prepend_text = "";
    }

    for (i = 0; field_types[i] != PROTOBUF_TYPE_NONE; ++i) {
        protobuf_dissect_field_value(value_tree, tvb, offset, length, pinfo, ti_field, field_types[i], value, prepend_text, NULL, FALSE);
        prepend_text = ",";
    }
}

static guint
dissect_one_protobuf_field(tvbuff_t *tvb, guint* offset, guint maxlen, packet_info *pinfo, proto_tree *protobuf_tree,
    const PbwDescriptor* message_desc, gboolean is_top_level)
{
    guint64 tag_value; /* tag value = (field_number << 3) | wire_type */
    guint tag_length; /* how many bytes this tag has */
    guint64 field_number;
    guint32 wire_type;
    guint64 value_uint64; /* uint64 value of numeric field (type of varint, 64-bit, 32-bit */
    guint value_length;
    guint value_length_size = 0; /* only Length-delimited field has it */
    proto_item *ti_field, *ti_field_number, *ti_wire, *ti_value_length = NULL;
    proto_item *ti_value, *ti_field_name, *ti_field_type = NULL;
    proto_tree *field_tree;
    proto_tree *value_tree;
    const gchar* field_name = NULL;
    int field_type = -1;
    gboolean is_packed_repeated = FALSE;
    const PbwFieldDescriptor* field_desc = NULL;

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

    field_tree = proto_tree_add_subtree(protobuf_tree, tvb, *offset, 0, ett_protobuf_field, &ti_field, "Field");

    /* parsing Tag */
    tag_length = tvb_get_varint(tvb, *offset, maxlen, &tag_value, ENC_VARINT_PROTOBUF);

    if (tag_length == 0) { /* not found a valid varint */
        expert_add_info(pinfo, ti_field, &ei_protobuf_failed_parse_tag);
        return FALSE;
    }

    ti_field_number = proto_tree_add_item_ret_uint64(field_tree, hf_protobuf_field_number, tvb, *offset, tag_length, ENC_LITTLE_ENDIAN|ENC_VARINT_PROTOBUF, &field_number);
    ti_wire = proto_tree_add_item_ret_uint(field_tree, hf_protobuf_wire_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN|ENC_VARINT_PROTOBUF, &wire_type);
    (*offset) += tag_length;

    /* try to find field_info first */
    if (message_desc) {
        /* find field descriptor according to field number from message descriptor */
        field_desc = pbw_Descriptor_FindFieldByNumber(message_desc, (int) field_number);
        if (field_desc) {
            field_name = pbw_FieldDescriptor_name(field_desc);
            field_type = pbw_FieldDescriptor_type(field_desc);
            is_packed_repeated = pbw_FieldDescriptor_is_packed(field_desc)
                && pbw_FieldDescriptor_is_repeated(field_desc);
        }
    }

    proto_item_append_text(ti_field, "(%" G_GINT64_MODIFIER "u):", field_number);

    /* support filtering with field name */
    ti_field_name = proto_tree_add_string(field_tree, hf_protobuf_field_name, tvb, *offset, 1,
        (field_name ? field_name : "<UNKNOWN>"));
    proto_item_set_generated(ti_field_name);
    if (field_name) {
        proto_item_append_text(ti_field, " %s %s", field_name,
            (field_type == PROTOBUF_TYPE_MESSAGE || field_type == PROTOBUF_TYPE_GROUP
                || (field_type == PROTOBUF_TYPE_BYTES && !dissect_bytes_as_string))
            ? "" : "="
        );
        if (field_type > 0) {
            ti_field_type = proto_tree_add_int(field_tree, hf_protobuf_field_type, tvb, *offset, 1, field_type);
            proto_item_set_generated(ti_field_type);
        }

        if (is_top_level) {
            /* Show field name in Info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", field_name);
        }
    }

    /* move ti_field_number and ti_wire after ti_field_type (or field_type) for good look */
    proto_tree_move_item(field_tree, (ti_field_type ? ti_field_type : ti_field_name), ti_wire);
    proto_tree_move_item(field_tree, (ti_field_type ? ti_field_type : ti_field_name), ti_field_number);

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

        ti_value_length = proto_tree_add_uint64(field_tree, hf_protobuf_value_length, tvb, *offset, value_length_size, value_uint64);
        (*offset) += value_length_size;

        /* we believe the length of following value will not be bigger than guint */
        value_length = (guint) value_uint64;
        break;

    default:
        expert_add_info(pinfo, ti_wire, &ei_protobuf_wire_type_invalid);
        return FALSE;
    }

    proto_item_set_len(ti_field, tag_length + value_length_size + value_length);
    proto_item_set_len(ti_field_name, tag_length + value_length_size + value_length);
    if (ti_field_type) {
        proto_item_set_len(ti_field_type, tag_length + value_length_size + value_length);
    }

    /* add value as bytes first */
    ti_value = proto_tree_add_item(field_tree, hf_protobuf_value_data, tvb, *offset, value_length, ENC_NA);

    /* add value subtree. we add uint value for numeric field or string for length-delimited at least. */
    value_tree = proto_item_add_subtree(ti_value, ett_protobuf_value);

    if (field_desc) {
        if (is_packed_repeated) {
            dissect_packed_repeated_field_values(tvb, *offset, value_length, pinfo, ti_field,
                wire_type, field_type, "", field_desc);
        } else {
            protobuf_dissect_field_value(value_tree, tvb, *offset, value_length, pinfo, ti_field, field_type, value_uint64, "", field_desc,
                                         is_top_level);
        }
    } else {
        if (show_all_possible_field_types) {
            /* try dissect every possible field type */
            protobuf_try_dissect_field_value_on_multi_types(value_tree, tvb, *offset, value_length, pinfo,
                ti_field, protobuf_wire_to_field_type[wire_type], value_uint64, "");
        } else {
            field_type = (wire_type == PROTOBUF_WIRETYPE_LENGTH_DELIMITED)
                /* print string at least for length-delimited */
                ? (try_dissect_as_string ? PROTOBUF_TYPE_STRING : PROTOBUF_TYPE_NONE)
                /* use uint32 or uint64 */
                : (value_uint64 <= 0xFFFFFFFF ? PROTOBUF_TYPE_UINT32 : PROTOBUF_TYPE_UINT64);
            int field_types[] = { field_type, PROTOBUF_TYPE_NONE };

            protobuf_try_dissect_field_value_on_multi_types(value_tree, tvb, *offset, value_length, pinfo,
                ti_field, field_types, value_uint64, "");
        }
    }

    if (field_desc && !show_details) {
        proto_item_set_hidden(ti_field_number);
        proto_item_set_hidden(ti_wire);
        proto_item_set_hidden(ti_value_length);
        proto_item_set_hidden(ti_field_name);
        proto_item_set_hidden(ti_field_type);
        if (field_type != PROTOBUF_TYPE_BYTES && field_type != PROTOBUF_TYPE_GROUP) {
            proto_item_set_hidden(ti_value);
        }
    }

    (*offset) += value_length;
    return TRUE;
}

static void
dissect_protobuf_message(tvbuff_t *tvb, guint offset, guint length, packet_info *pinfo, proto_tree *protobuf_tree,
    const PbwDescriptor* message_desc, gboolean is_top_level)
{
    proto_tree *message_tree;
    proto_item *ti_message, *ti;
    const gchar* message_name = "<UNKNOWN> Message Type";
    guint max_offset = offset + length;

    if (message_desc) {
        message_name = pbw_Descriptor_full_name(message_desc);
    }

    if (pbf_as_hf && message_desc) {
        /* support filtering with message name as wireshark field name */
        int *hf_id_ptr = (int*)g_hash_table_lookup(pbf_hf_hash, message_name);
        DISSECTOR_ASSERT_HINT(hf_id_ptr && (*hf_id_ptr) > 0, "hf of message should initialized properly");
        ti_message = proto_tree_add_item(protobuf_tree, *hf_id_ptr, tvb, offset, length, ENC_NA);
        proto_item_set_text(ti_message, "Message: %s", message_name);

        if (show_details) {
            /* show "Message" item and add its fields under this item */
            message_tree = proto_item_add_subtree(ti_message, ett_protobuf_message);
        } else {
            /* hidden "Message" item (but still can be filtered by wireshark field name with "pbm.xxx" prefix),
             * and add its fields under the parent (field or protobuf protocol) item directly */
            proto_item_set_hidden(ti_message);
            message_tree = protobuf_tree;
            ti_message = proto_tree_get_parent(message_tree);
            proto_item_append_text(ti_message, " (Message: %s)", message_name);
        }
    } else {
        message_tree = proto_tree_add_subtree_format(protobuf_tree, tvb, offset, length, ett_protobuf_message,
            &ti_message, "Message: %s", message_name);
    }

    if (is_top_level) {
        col_clear(pinfo->cinfo, COL_PROTOCOL);
        col_append_fstr(pinfo->cinfo, COL_PROTOCOL, "PB(%s)", message_name);
        /* Top-level info will get written into Info column. */
        col_clear(pinfo->cinfo, COL_INFO);
    }

    /* support filtering with message name */
    ti = proto_tree_add_string(message_tree, hf_protobuf_message_name, tvb, offset, length, message_name);
    proto_item_set_generated(ti);
    if (!show_details) {
        proto_item_set_hidden(ti);
    }

    /* each time we dissect one protobuf field. */
    while (offset < max_offset)
    {
        if (!dissect_one_protobuf_field(tvb, &offset, max_offset - offset, pinfo, message_tree, message_desc, is_top_level))
            break;
    }
}

/* try to find message type by UDP port */
static const PbwDescriptor*
find_message_type_by_udp_port(packet_info *pinfo)
{
    range_t* udp_port_range;
    const gchar* message_type;
    guint i;
    for (i = 0; i < num_protobuf_udp_message_types; ++i) {
        udp_port_range = protobuf_udp_message_types[i].udp_port_range;
        if (value_is_in_range(udp_port_range, pinfo->srcport)
            || value_is_in_range(udp_port_range, pinfo->destport))
        {
            message_type = protobuf_udp_message_types[i].message_type;
            if (message_type && strlen(message_type) > 0) {
                return pbw_DescriptorPool_FindMessageTypeByName(pbw_pool, message_type);
            }
        }
    }
    return NULL;
}

static int
dissect_protobuf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *protobuf_tree;
    guint offset = 0;
    guint i;
    const PbwDescriptor* message_desc = NULL;
    const gchar* data_str = NULL;

    /* initialize only the first time the protobuf dissector is called */
    if (!protobuf_dissector_called) {
        protobuf_dissector_called = TRUE;
        protobuf_reinit(PREFS_UPDATE_ALL);
    }

    /* may set col_set_str(pinfo->cinfo, COL_PROTOCOL, "PROTOBUF"); */
    col_append_str(pinfo->cinfo, COL_INFO, " (PROTOBUF)");

    ti = proto_tree_add_item(tree, proto_protobuf, tvb, 0, -1, ENC_NA);
    protobuf_tree = proto_item_add_subtree(ti, ett_protobuf);

    /* The dissectors written in Lua are not able to specify the message type by data
       parameter when calling protobuf dissector. But they can tell Protobuf dissector
       the message type by the value of pinfo->private_table["pb_msg_type"]. */
    if (data) {
        data_str = (const gchar*)data;
    } else if (pinfo->private_table) {
        data_str = (const gchar*)g_hash_table_lookup(pinfo->private_table, "pb_msg_type");
    }

    if (data_str) {
        /* The data_str has two formats:
        * (1) Come from GRPC dissector like:
        *    http2_content_type "," http2_path "," ("request" / "response")
        * Acording to grpc wire format guide, it will be:
        *    "application/grpc" ["+proto"] "," "/" service-name "/" method-name "," ("request" / "response")
        * For example:
        *    application/grpc,/helloworld.Greeter/SayHello,request
        * In this format, we will try to get real protobuf message type by method (service-name.method-name)
        * and in/out type (request / reponse).
        * (2) Come from other dissector which specifies message type directly, like:
        *    "message," message_type_name
        * For example:
        *    message,helloworld.HelloRequest      (helloworld is package, HelloRequest is message type)
        */
        const gchar* message_info = strchr(data_str, ',');

        if (message_info) {
            message_info++; /* ignore ',' */
            proto_item_append_text(ti, ": %s", message_info);  /* append to proto item */

            if (g_str_has_prefix(data_str, "message,")) {
                /* find message type by name directly */
                message_desc = pbw_DescriptorPool_FindMessageTypeByName(pbw_pool, message_info);
            } else /* if (g_str_has_prefix(data_str, "application/grpc,") */ {
                /* get long method-name like: helloworld.Greeter.SayHello */
                if (message_info[0] == '/') {
                    message_info++; /* ignore first '/' */
                }

                gchar** tmp_names = wmem_strsplit(wmem_packet_scope(), message_info, ",", 2);
                gchar* method_name = (tmp_names[0]) ? tmp_names[0] : NULL;
                gchar* direction_type = (method_name && tmp_names[1]) ? tmp_names[1] : NULL;

                /* replace all '/' to '.', so helloworld.Greeter/SayHello converted to helloworld.Greeter.SayHello */
                if (method_name) {
                    for (i = 0; method_name[i] != 0; i++) {
                        if (method_name[i] == '/') {
                            method_name[i] = '.';
                        }
                    }
                }

                /* find message type according to method descriptor */
                if (direction_type) {
                    const PbwMethodDescriptor* method_desc = pbw_DescriptorPool_FindMethodByName(pbw_pool, method_name);
                    if (method_desc) {
                        message_desc = strcmp(direction_type, "request") == 0
                            ? pbw_MethodDescriptor_input_type(method_desc)
                            : pbw_MethodDescriptor_output_type(method_desc);
                    }
                }
            }

            if (message_desc) {
                const char* message_full_name = pbw_Descriptor_full_name(message_desc);
                if (message_full_name) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", message_full_name);
                }
            }
        }

    } else if (pinfo->ptype == PT_UDP) {
        message_desc = find_message_type_by_udp_port(pinfo);
    }

    dissect_protobuf_message(tvb, offset, tvb_reported_length_remaining(tvb, offset), pinfo,
        protobuf_tree, message_desc, pinfo->ptype == PT_UDP);

    return tvb_captured_length(tvb);
}

static gboolean
load_all_files_in_dir(PbwDescriptorPool* pool, const gchar* dir_path)
{
    WS_DIR        *dir;             /* scanned directory */
    WS_DIRENT     *file;            /* current file */
    const gchar   *dot;
    const gchar   *name;            /* current file or dir name (without parent dir path) */
    gchar         *path;            /* sub file or dir path of dir_path */

    if (g_file_test(dir_path, G_FILE_TEST_IS_DIR)) {
        if ((dir = ws_dir_open(dir_path, 0, NULL)) != NULL) {
            while ((file = ws_dir_read_name(dir)) != NULL) {
                /* load all files with '.proto' suffix */
                name = ws_dir_get_name(file);
                path = g_build_filename(dir_path, name, NULL);
                dot = strrchr(name, '.');
                if (dot && g_ascii_strcasecmp(dot + 1, "proto") == 0) {
                    /* Note: pbw_load_proto_file support absolute or relative (to one of search paths) path */
                    if (pbw_load_proto_file(pool, path)) {
                        return FALSE;
                    }
                } else {
                    if (!load_all_files_in_dir(pool, path)) {
                        return FALSE;
                    }
                }
                g_free(path);
            }
            ws_dir_close(dir);
        }
    }
    return TRUE;
}

/* There might be a lot of errors to be found during parsing .proto files.
   We buffer the errors first, and print them in one list finally. */
static wmem_strbuf_t* err_msg_buf = NULL;
#define MIN_ERR_STR_BUF_SIZE 512
#define MAX_ERR_STR_BUF_SIZE 1024

static void
buffer_error(const gchar *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    if (err_msg_buf == NULL)
        err_msg_buf = wmem_strbuf_sized_new(wmem_epan_scope(), MIN_ERR_STR_BUF_SIZE, MAX_ERR_STR_BUF_SIZE);

    wmem_strbuf_append_vprintf(err_msg_buf, fmt, ap);

    va_end(ap);
}

static void
flush_and_report_error(void)
{
    char* str;
    if (err_msg_buf) {
        str = wmem_strbuf_finalize(err_msg_buf);
        err_msg_buf = NULL;
        report_failure("Protobuf: Error(s):\n%s", str);
        wmem_free(wmem_epan_scope(), str);
    }
}

static void
update_protobuf_search_paths(void)
{
    protobuf_reinit(PREFS_UPDATE_PROTOBUF_SEARCH_PATHS);
}

static void
update_protobuf_udp_message_types(void)
{
    protobuf_reinit(PREFS_UPDATE_PROTOBUF_UDP_MESSAGE_TYPES);
}

static void
deregister_header_fields(void)
{
    if (dynamic_hf) {
        /* Deregister all fields */
        for (guint i = 0; i < dynamic_hf_size; i++) {
            proto_deregister_field(proto_protobuf, *(dynamic_hf[i].p_id));
            g_free(dynamic_hf[i].p_id);
            /* dynamic_hf[i].name and .abbrev will be freed by proto_add_deregistered_data */
        }

        proto_add_deregistered_data(dynamic_hf);
        dynamic_hf = NULL;
        dynamic_hf_size = 0;
    }

    if (pbf_hf_hash) {
        g_hash_table_destroy(pbf_hf_hash);
        pbf_hf_hash = NULL;
    }
}

/* convert the names of the enum's values to value_string array */
static value_string*
enum_to_value_string(const PbwEnumDescriptor* enum_desc)
{
    value_string* vals;
    int i, value_count;
    if (enum_desc == NULL || (value_count = pbw_EnumDescriptor_value_count(enum_desc)) == 0) {
        return NULL;
    }

    vals = g_new0(value_string, value_count + 1);
    for (i = 0; i < value_count; i++) {
        const PbwEnumValueDescriptor* enum_value_desc = pbw_EnumDescriptor_value(enum_desc, i);
        vals[i].value = pbw_EnumValueDescriptor_number(enum_value_desc);
        vals[i].strptr = g_strdup(pbw_EnumValueDescriptor_name(enum_value_desc));
    }
    /* the strptr of last element of vals must be NULL */
    return vals;
}

/* create wireshark header fields according to each message's fields
 * and add them into pbf_as_hf hash table */
static void
collect_fields(const PbwDescriptor* message, void* userdata)
{
    wmem_list_t* hf_list = (wmem_list_t*) userdata;
    hf_register_info* hf;
    const PbwFieldDescriptor* field_desc;
    const PbwEnumDescriptor* enum_desc;
    int i, field_type, total_num = pbw_Descriptor_field_count(message);

    /* add message as field */
    hf = g_new0(hf_register_info, 1);
    hf->p_id = g_new(gint, 1);
    *(hf->p_id) = -1;
    hf->hfinfo.name = g_strdup(pbw_Descriptor_name(message));
    hf->hfinfo.abbrev = g_strdup_printf("pbm.%s", pbw_Descriptor_full_name(message));
    hf->hfinfo.type = FT_BYTES;
    hf->hfinfo.display = BASE_NONE;
    wmem_list_append(hf_list, hf);
    g_hash_table_insert(pbf_hf_hash, g_strdup(pbw_Descriptor_full_name(message)), hf->p_id);

    /* add fields of this message as fields */
    for (i = 0; i < total_num; i++) {
        field_desc = pbw_Descriptor_field(message, i);
        field_type = pbw_FieldDescriptor_type(field_desc);
        if (field_type <= PROTOBUF_TYPE_NONE ||field_type > PROTOBUF_MAX_FIELD_TYPE) {
            /* not a valid field type */
            continue;
        }
        hf = g_new0(hf_register_info, 1);
        hf->p_id = g_new(gint, 1);
        *(hf->p_id) = -1;

        hf->hfinfo.name = g_strdup(pbw_FieldDescriptor_name(field_desc));
        hf->hfinfo.abbrev = g_strdup_printf("pbf.%s", pbw_FieldDescriptor_full_name(field_desc));
        switch (field_type) {
        case PROTOBUF_TYPE_DOUBLE:
            hf->hfinfo.type = FT_DOUBLE;
            hf->hfinfo.display = BASE_NONE;
            break;

        case PROTOBUF_TYPE_FLOAT:
            hf->hfinfo.type = FT_FLOAT;
            hf->hfinfo.display = BASE_NONE;
            break;

        case PROTOBUF_TYPE_INT64:
        case PROTOBUF_TYPE_SFIXED64:
        case PROTOBUF_TYPE_SINT64:
            hf->hfinfo.type = FT_INT64;
            hf->hfinfo.display = BASE_DEC;
            break;

        case PROTOBUF_TYPE_UINT64:
        case PROTOBUF_TYPE_FIXED64:
            hf->hfinfo.type = FT_UINT64;
            hf->hfinfo.display = BASE_DEC;
            break;

        case PROTOBUF_TYPE_INT32:
        case PROTOBUF_TYPE_SFIXED32:
        case PROTOBUF_TYPE_SINT32:
            hf->hfinfo.type = FT_INT32;
            hf->hfinfo.display = BASE_DEC;
            break;

        case PROTOBUF_TYPE_UINT32:
        case PROTOBUF_TYPE_FIXED32:
            hf->hfinfo.type = FT_UINT32;
            hf->hfinfo.display = BASE_DEC;
            break;

        case PROTOBUF_TYPE_ENUM:
            hf->hfinfo.type = FT_INT32;
            hf->hfinfo.display = BASE_DEC;
            enum_desc = pbw_FieldDescriptor_enum_type(field_desc);
            if (enum_desc) {
                hf->hfinfo.strings = enum_to_value_string(enum_desc);
            }
            break;

        case PROTOBUF_TYPE_BOOL:
            hf->hfinfo.type = FT_BOOLEAN;
            hf->hfinfo.display = BASE_NONE;
            break;

        case PROTOBUF_TYPE_BYTES:
            hf->hfinfo.type = dissect_bytes_as_string ? FT_STRING : FT_BYTES;
            hf->hfinfo.display = BASE_NONE;
            break;

        case PROTOBUF_TYPE_STRING:
            hf->hfinfo.type = FT_STRING;
            hf->hfinfo.display = BASE_NONE;
            break;

        case PROTOBUF_TYPE_GROUP:
        case PROTOBUF_TYPE_MESSAGE:
            hf->hfinfo.type = FT_BYTES;
            hf->hfinfo.display = BASE_NONE;
            break;

        default:
            /* should not happen */
            break;
        }

        wmem_list_append(hf_list, hf);
        g_hash_table_insert(pbf_hf_hash, g_strdup(pbw_FieldDescriptor_full_name(field_desc)), hf->p_id);
    }
}

static void
update_header_fields(gboolean force_reload)
{
    if (!force_reload && pbf_as_hf && dynamic_hf) {
        /* If initialized, do nothing. */
        return;
    }
    deregister_header_fields();

    if (pbf_as_hf) {
        int i;
        wmem_list_frame_t *it;
        wmem_list_t* hf_list = wmem_list_new(NULL);
        pbf_hf_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        DISSECTOR_ASSERT(pbw_pool);
        pbw_foreach_message(pbw_pool, collect_fields, hf_list);
        dynamic_hf_size = wmem_list_count(hf_list);
        if (dynamic_hf_size == 0) {
            deregister_header_fields();
            return;
        }
        dynamic_hf = g_new0(hf_register_info, dynamic_hf_size);

        for (it = wmem_list_head(hf_list), i = 0; it; it = wmem_list_frame_next(it), i++) {
            hf_register_info* hf = (hf_register_info*) wmem_list_frame_data(it);
            /* copy hf_register_info structure */
            dynamic_hf[i] = *hf;
            g_free(hf);
            HFILL_INIT(dynamic_hf[i]);
        }

        wmem_destroy_list(hf_list);
        proto_register_field_array(proto_protobuf, dynamic_hf, dynamic_hf_size);
    }
}

static void
protobuf_reinit(int target)
{
    guint i;
    gchar **source_paths;
    GSList* it;
    range_t* udp_port_range;
    const gchar* message_type;
    gboolean loading_completed = TRUE;

    if (target & PREFS_UPDATE_PROTOBUF_UDP_MESSAGE_TYPES) {
        /* delete protobuf dissector from old udp ports */
        for (it = old_udp_port_ranges; it; it = it->next) {
            udp_port_range = (range_t*) it->data;
            dissector_delete_uint_range("udp.port", udp_port_range, protobuf_handle);
            wmem_free(NULL, udp_port_range);
        }

        if (old_udp_port_ranges) {
            g_slist_free(old_udp_port_ranges);
            old_udp_port_ranges = NULL;
        }

        /* add protobuf dissector to new udp ports */
        for (i = 0; i < num_protobuf_udp_message_types; ++i) {
            udp_port_range = protobuf_udp_message_types[i].udp_port_range;
            if (udp_port_range) {
                udp_port_range = range_copy(NULL, udp_port_range);
                old_udp_port_ranges = g_slist_append(old_udp_port_ranges, udp_port_range);
                dissector_add_uint_range("udp.port", udp_port_range, protobuf_handle);
            }
        }
    }

    /* loading .proto files and checking message types of UDP port will be done only after dissector is called */
    if (!protobuf_dissector_called) {
        return;
    }

    if (target & PREFS_UPDATE_PROTOBUF_SEARCH_PATHS) {
        /* convert protobuf_search_path_t array to char* array. should release by g_free(). */
        source_paths = g_new0(char *, num_protobuf_search_paths + 1);

        for (i = 0; i < num_protobuf_search_paths; ++i) {
            source_paths[i] = protobuf_search_paths[i].path;
        }

        /* init DescriptorPool of protobuf */
        pbw_reinit_DescriptorPool(&pbw_pool, (const char**)source_paths, buffer_error);

        /* load all .proto files in the marked search paths, we can invoke FindMethodByName etc later. */
        for (i = 0; i < num_protobuf_search_paths; ++i) {
            if (protobuf_search_paths[i].load_all) {
                if (!load_all_files_in_dir(pbw_pool, protobuf_search_paths[i].path)) {
                    buffer_error("Protobuf: Loading .proto files action stopped!\n");
                    loading_completed = FALSE;
                    break; /* stop loading when error occurs */
                }
            }
        }

        g_free(source_paths);
        update_header_fields(TRUE);
    }

    /* check if the message types of UDP port exist */
    for (i = 0; i < num_protobuf_udp_message_types; ++i) {
        message_type = protobuf_udp_message_types[i].message_type;
        if (loading_completed && message_type && strlen(message_type) > 0
            && pbw_DescriptorPool_FindMessageTypeByName(pbw_pool, message_type) == NULL) {
            buffer_error("Protobuf: the message type \"%s\" of UDP Message Type preferences does not exist!\n", message_type);
        }
    }

    /* report error if encountered */
    flush_and_report_error();
}

void
proto_register_protobuf(void)
{
    static hf_register_info hf[] = {
        { &hf_protobuf_message_name,
            { "Message Name", "protobuf.message.name",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "The name of the protobuf message", HFILL }
        },
        { &hf_protobuf_field_name,
            { "Field Name", "protobuf.field.name",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "The name of the field", HFILL }
        },
        { &hf_protobuf_field_type,
            { "Field Type", "protobuf.field.type",
               FT_INT32, BASE_DEC, VALS(protobuf_field_type), 0x0,
              "The type of the field", HFILL }
        },
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
        &ett_protobuf_message,
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
        { &et_protobuf_message_type_not_found,
          { "protobuf.field.message_type_not_found", PI_PROTOCOL, PI_WARN,
            "Failed to find message type of a field", EXPFILL }
        },
        { &et_protobuf_wire_type_not_support_packed_repeated,
          { "protobuf.field.wire_type_not_support_packed_repeated", PI_MALFORMED, PI_ERROR,
            "The wire type does not support protobuf packed repeated field", EXPFILL }
        },
        { &et_protobuf_failed_parse_packed_repeated_field,
          { "protobuf.field.failed_parse_packed_repeated_field", PI_MALFORMED, PI_ERROR,
            "Failed to parse packed repeated field", EXPFILL }
        },
    };

    module_t *protobuf_module;
    expert_module_t *expert_protobuf;

    static uat_field_t protobuf_search_paths_table_columns[] = {
        UAT_FLD_DIRECTORYNAME(protobuf_search_paths, path, "Protobuf source directory", "Directory of the root of protobuf source files"),
        UAT_FLD_BOOL(protobuf_search_paths, load_all, "Load all files", "Load all .proto files from this directory and its subdirectories"),
        UAT_END_FIELDS
    };
    uat_t* protobuf_search_paths_uat;

    static uat_field_t protobuf_udp_message_types_table_columns[] = {
        UAT_FLD_RANGE(protobuf_udp_message_types, udp_port_range, "UDP Ports", 0xFFFF, "UDP ports on which data will be dissected as protobuf"),
        UAT_FLD_CSTRING(protobuf_udp_message_types, message_type, "Message Type", "Protobuf message type of data on these udp ports"),
        UAT_END_FIELDS
    };
    uat_t* protobuf_udp_message_types_uat;

    proto_protobuf = proto_register_protocol("Protocol Buffers", "ProtoBuf", "protobuf");

    proto_register_field_array(proto_protobuf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    protobuf_module = prefs_register_protocol(proto_protobuf, proto_reg_handoff_protobuf);

    protobuf_search_paths_uat = uat_new("Protobuf Search Paths",
        sizeof(protobuf_search_path_t),
        "protobuf_search_paths",
        TRUE,
        &protobuf_search_paths,
        &num_protobuf_search_paths,
        UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
        "ChProtobufSearchPaths",
        protobuf_search_paths_copy_cb,
        NULL,
        protobuf_search_paths_free_cb,
        update_protobuf_search_paths,
        NULL,
        protobuf_search_paths_table_columns
    );

    prefs_register_uat_preference(protobuf_module, "search_paths", "Protobuf search paths",
        "Specify the directories where .proto files are recursively loaded from, or in which to search for imports.",
        protobuf_search_paths_uat);

    prefs_register_bool_preference(protobuf_module, "pbf_as_hf",
        "Dissect Protobuf fields as Wireshark fields.",
        "If Protobuf messages and fields are defined in loaded .proto files,"
        " they will be dissected as wireshark fields if this option is turnned on."
        " The names of all these wireshark fields will be prefixed with \"pbf.\" (for fields)"
        " or \"pbm.\" (for messages) followed by their full names in the .proto files.",
        &pbf_as_hf);

    prefs_set_preference_effect_fields(protobuf_module, "pbf_as_hf");

    prefs_register_bool_preference(protobuf_module, "show_details",
        "Show details of message, fields and enums.",
        "Show the names of message, field, enum and enum_value."
        " Show the wire type and field number format of field."
        " Show value nodes of field and enum_value.",
        &show_details);

    prefs_register_bool_preference(protobuf_module, "bytes_as_string",
        "Show all fields of bytes type as string.",
        "Show all fields of bytes type as string. For example ETCD string",
        &dissect_bytes_as_string);

    protobuf_udp_message_types_uat = uat_new("Protobuf UDP Message Types",
        sizeof(protobuf_udp_message_type_t),
        "protobuf_udp_message_types",
        TRUE,
        &protobuf_udp_message_types,
        &num_protobuf_udp_message_types,
        UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
        "ChProtobufUDPMessageTypes",
        protobuf_udp_message_types_copy_cb,
        protobuf_udp_message_types_update_cb,
        protobuf_udp_message_types_free_cb,
        update_protobuf_udp_message_types,
        NULL,
        protobuf_udp_message_types_table_columns
    );

    prefs_register_uat_preference(protobuf_module, "udp_message_types", "Protobuf UDP message types",
        "Specify the Protobuf message type of data on certain UDP ports.",
        protobuf_udp_message_types_uat);

    /* Following preferences are for undefined fields, that happened while message type is not specified
       when calling dissect_protobuf(), or message type or field information is not found in search paths
    */
    prefs_register_bool_preference(protobuf_module, "try_dissect_as_string",
        "Try to dissect all undefined length-delimited fields as string.",
        "Try to dissect all undefined length-delimited fields as string.",
        &try_dissect_as_string);

    prefs_register_bool_preference(protobuf_module, "show_all_types",
        "Try to show all possible field types for each undefined field.",
        "Try to show all possible field types for each undefined field according to wire type.",
        &show_all_possible_field_types);

    prefs_register_static_text_preference(protobuf_module, "field_dissector_table_note",
        "Subdissector can register itself in \"protobuf_field\" dissector table for parsing"
        " the value of the field of bytes or string type.",
        "The key of \"protobuf_field\" table is the full name of field.");

    protobuf_field_subdissector_table =
        register_dissector_table("protobuf_field", "Protobuf field subdissector table",
            proto_protobuf, FT_STRING, BASE_NONE);

    expert_protobuf = expert_register_protocol(proto_protobuf);
    expert_register_field_array(expert_protobuf, ei, array_length(ei));

    protobuf_handle = register_dissector("protobuf", dissect_protobuf, proto_protobuf);
}

void
proto_reg_handoff_protobuf(void)
{
    if (protobuf_dissector_called) {
        update_header_fields( /* if bytes_as_string preferences changed, we force reload header fields */
            (old_dissect_bytes_as_string && !dissect_bytes_as_string) || (!old_dissect_bytes_as_string && dissect_bytes_as_string)
        );
    }
    old_dissect_bytes_as_string = dissect_bytes_as_string;
    dissector_add_string("grpc_message_type", "application/grpc", protobuf_handle);
    dissector_add_string("grpc_message_type", "application/grpc+proto", protobuf_handle);
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
