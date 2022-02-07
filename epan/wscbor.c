/* wscbor.c
 * Wireshark CBOR item decoding API.
 * References:
 *     RFC 8949: https://tools.ietf.org/html/rfc8949
 *
 * Copyright 2019-2021, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <stdio.h>
#include <inttypes.h>
#include "wscbor.h"

/// Pseudo-protocol to register expert info
static int proto_wscbor = -1;

static expert_field ei_cbor_invalid = EI_INIT;
static expert_field ei_cbor_overflow = EI_INIT;
static expert_field ei_cbor_wrong_type = EI_INIT;
static expert_field ei_cbor_array_wrong_size = EI_INIT;
static expert_field ei_cbor_indef_string = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_cbor_invalid, {"_ws.wscbor.cbor_invalid", PI_MALFORMED, PI_ERROR, "CBOR cannot be decoded", EXPFILL}},
    {&ei_cbor_overflow, {"_ws.wscbor.cbor_overflow", PI_UNDECODED, PI_ERROR, "CBOR overflow of Wireshark value", EXPFILL}},
    {&ei_cbor_wrong_type, {"_ws.wscbor.cbor_wrong_type", PI_MALFORMED, PI_ERROR, "CBOR is wrong type", EXPFILL}},
    {&ei_cbor_array_wrong_size, {"_ws.wscbor.array_wrong_size", PI_MALFORMED, PI_WARN, "CBOR array is the wrong size", EXPFILL}},
    {&ei_cbor_indef_string, {"_ws.wscbor.indef_string", PI_COMMENTS_GROUP, PI_COMMENT, "String uses indefinite-length encoding", EXPFILL}},
};

/// The basic header structure of CBOR encoding
typedef struct {
    /// The start offset of this header
    gint start;
    /// The length of just this header
    gint length;
    /// The expert info object (if error)
    expert_field *error;

    /// Major type of this item (cbor_type)
    guint8 type_major;
    /// Minor type of this item
    guint8 type_minor;
    /// Raw head "value" which may be from the @c type_minor
    guint64 rawvalue;
} wscbor_head_t;

/** Read the raw value from a CBOR head.
 * @param[in,out] head The head to read into.
 * @param tvb The buffer to read from.
 */
static void wscbor_read_unsigned(wscbor_head_t *head, tvbuff_t *tvb) {
    switch (head->type_minor) {
        case 0x18:
            head->rawvalue = tvb_get_guint8(tvb, head->start + head->length);
            head->length += 1;
            break;
        case 0x19:
            head->rawvalue = tvb_get_guint16(tvb, head->start + head->length, ENC_BIG_ENDIAN);
            head->length += 2;
            break;
        case 0x1A:
            head->rawvalue = tvb_get_guint32(tvb, head->start + head->length, ENC_BIG_ENDIAN);
            head->length += 4;
            break;
        case 0x1B:
            head->rawvalue = tvb_get_guint64(tvb, head->start + head->length, ENC_BIG_ENDIAN);
            head->length += 8;
            break;
        default:
            if (head->type_minor <= 0x17) {
                head->rawvalue = head->type_minor;
            }
            break;
    }
}

/** Read just the CBOR head octet.
 * @param alloc The allocator to use.
 * @param tvb The TVB to read from.
 * @param[in,out] offset The offset with in @c tvb.
 * This is updated with just the head length.
 * @return The new head object.
 * This never returns NULL.
 * @post Will throw wireshark exception if read fails.
 */
static wscbor_head_t * wscbor_head_read(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset) {
    wscbor_head_t *head = wmem_new0(alloc, wscbor_head_t);

    head->start = *offset;
    const guint8 first = tvb_get_guint8(tvb, head->start);
    head->length += 1;

    // Match libcbor enums
    head->type_major = (first & 0xe0) >> 5;
    head->type_minor = (first & 0x1f);
    switch ((cbor_type)(head->type_major)) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NEGINT:
        case CBOR_TYPE_TAG:
            wscbor_read_unsigned(head, tvb);
            if (head->type_minor > 0x1B) {
                head->error = &ei_cbor_invalid;
            }
            break;
        case CBOR_TYPE_BYTESTRING:
        case CBOR_TYPE_STRING:
        case CBOR_TYPE_ARRAY:
        case CBOR_TYPE_MAP:
        case CBOR_TYPE_FLOAT_CTRL:
            wscbor_read_unsigned(head, tvb);
            if ((head->type_minor > 0x1B) && (head->type_minor < 0x1F)) {
                head->error = &ei_cbor_invalid;
            }
            break;

        default:
            head->error = &ei_cbor_invalid;
            break;
    }

    *offset += head->length;
    return head;
}

/** Force a head to be freed.
 */
static void wscbor_head_free(wmem_allocator_t *alloc, wscbor_head_t *head) {
    wmem_free(alloc, head);
}

struct _wscbor_chunk_priv_t {
    /// The allocator used for wscbor_chunk_t.errors and wscbor_chunk_t.tags
    wmem_allocator_t *alloc;
    /// Non-error expert info on this chunk (type wscbor_error_t*)
    wmem_list_t *infos;
    /// For string types, including indefinite length, the item payload.
    /// Otherwise NULL.
    tvbuff_t *str_value;
};

/** Get a clamped string length suitable for tvb functions.
 * @param[in,out] chunk The chunk to set errors on.
 * @param head_value The value to clamp.
 * @return The clamped length value.
 */
static gint wscbor_get_length(wscbor_chunk_t *chunk, guint64 head_value) {
    gint length;
    if (head_value > G_MAXINT) {
        wmem_list_append(chunk->errors, wscbor_error_new(
                chunk->_priv->alloc, &ei_cbor_overflow,
                NULL
        ));
        length = G_MAXINT;
    }
    else {
        length = (gint) head_value;
    }
    return length;
}

wscbor_error_t * wscbor_error_new(wmem_allocator_t *alloc, expert_field *ei, const char *format, ...) {
    wscbor_error_t *err = wmem_new0(alloc, wscbor_error_t);
    err->ei = ei;
    if (format) {
        wmem_strbuf_t *buf = wmem_strbuf_new(alloc, "");

        va_list ap;
        va_start(ap, format);
        wmem_strbuf_append_vprintf(buf, format, ap);
        va_end(ap);

        err->msg = wmem_strbuf_finalize(buf);
    }
    return err;
}

wscbor_chunk_t * wscbor_chunk_read(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset) {
    DISSECTOR_ASSERT(alloc != NULL);
    DISSECTOR_ASSERT(offset != NULL);
    DISSECTOR_ASSERT(tvb != NULL);

    wscbor_chunk_t *chunk = wmem_new0(alloc, wscbor_chunk_t);
    chunk->_priv = wmem_new0(alloc, struct _wscbor_chunk_priv_t);
    chunk->_priv->alloc = alloc;
    chunk->_priv->infos = wmem_list_new(alloc);
    chunk->errors = wmem_list_new(alloc);
    chunk->tags = wmem_list_new(alloc);
    chunk->start = *offset;

    // Read a sequence of tags followed by an item header
    while (TRUE) {
        // This will break out of the loop if it runs out of buffer
        wscbor_head_t *head = wscbor_head_read(alloc, tvb, offset);
        chunk->head_length += head->length;
        if (head->error) {
            wmem_list_append(chunk->errors, wscbor_error_new(alloc, head->error, NULL));
        }
        if (head->type_major == CBOR_TYPE_TAG) {
            wscbor_tag_t *tag = wmem_new(alloc, wscbor_tag_t);
            tag->start = head->start;
            tag->length = head->length;
            tag->value = head->rawvalue;
            wmem_list_append(chunk->tags, tag);
            // same chunk, next part
            wscbor_head_free(alloc, head);
            continue;
        }

        // An actual (non-tag) header
        chunk->type_major = (cbor_type)head->type_major;
        chunk->type_minor = head->type_minor;
        chunk->head_value = head->rawvalue;

        wscbor_head_free(alloc, head);
        break;
    }

    // Data beyond the tags and item head
    chunk->data_length = chunk->head_length;
    switch (chunk->type_major) {
        case CBOR_TYPE_BYTESTRING:
        case CBOR_TYPE_STRING:
            if (chunk->type_minor != 31) {
                const gint datalen = wscbor_get_length(chunk, chunk->head_value);
                // skip over definite data
                *offset += datalen;
                chunk->data_length += datalen;
                if(datalen) {
                    chunk->_priv->str_value = tvb_new_subset_length(tvb, chunk->start + chunk->head_length, datalen);
                }
            }
            else {
                // indefinite length, sequence of definite items
                chunk->_priv->str_value = tvb_new_composite();

                while (TRUE) {
                    wscbor_head_t *head = wscbor_head_read(alloc, tvb, offset);
                    chunk->data_length += head->length;
                    if (head->error) {
                        wmem_list_append(chunk->errors, wscbor_error_new(alloc, head->error, NULL));
                    }
                    const gboolean is_break = (
                        (head->type_major == CBOR_TYPE_FLOAT_CTRL)
                        && (head->type_minor == 31)
                    );
                    if (!is_break) {
                        if (head->type_major != chunk->type_major) {
                            wmem_list_append(chunk->errors, wscbor_error_new(
                                    chunk->_priv->alloc, &ei_cbor_wrong_type,
                                    "Indefinite sub-string item has major type %d, should be %d",
                                    head->type_major, chunk->type_major
                            ));
                        }
                        else {
                            const gint datalen = wscbor_get_length(chunk, head->rawvalue);
                            *offset += datalen;
                            chunk->data_length += datalen;
                            if(datalen) {
                                tvb_composite_append(
                                    chunk->_priv->str_value,
                                    tvb_new_subset_length(tvb, head->start + head->length, datalen)
                                );
                            }
                        }
                    }

                    wscbor_head_free(alloc, head);
                    if (is_break) {
                        break;
                    }
                }

                wmem_list_append(chunk->_priv->infos, wscbor_error_new(
                        chunk->_priv->alloc, &ei_cbor_indef_string,
                        NULL
                ));
                tvb_composite_finalize(chunk->_priv->str_value);
            }
            break;
        default:
            break;
    }

    return chunk;
}

static void wscbor_subitem_free(gpointer data, gpointer userdata) {
    wmem_allocator_t *alloc = (wmem_allocator_t *) userdata;
    wmem_free(alloc, data);
}

void wscbor_chunk_free(wscbor_chunk_t *chunk) {
    DISSECTOR_ASSERT(chunk);
    wmem_allocator_t *alloc = chunk->_priv->alloc;
    wmem_list_foreach(chunk->_priv->infos, wscbor_subitem_free, alloc);
    wmem_destroy_list(chunk->_priv->infos);
    wmem_list_foreach(chunk->errors, wscbor_subitem_free, alloc);
    wmem_destroy_list(chunk->errors);
    wmem_list_foreach(chunk->tags, wscbor_subitem_free, alloc);
    wmem_destroy_list(chunk->tags);
    wmem_free(alloc, chunk);
}

/// User data for wscbor_expert_add()
typedef struct {
    packet_info *pinfo;
    proto_item *item;
} wscbor_expert_add_t;

/// A callback for wmem_list_foreach() to add the info
static void wscbor_expert_add(gpointer data, gpointer userdata) {
    const wscbor_error_t *err = (const wscbor_error_t *)data;
    wscbor_expert_add_t *ctx = (wscbor_expert_add_t *)userdata;

    if (err->msg) {
        expert_add_info_format(ctx->pinfo, ctx->item, err->ei, "%s", err->msg);
    }
    else {
        expert_add_info(ctx->pinfo, ctx->item, err->ei);
    }
}

guint64 wscbor_chunk_mark_errors(packet_info *pinfo, proto_item *item, const wscbor_chunk_t *chunk) {
    wscbor_expert_add_t ctx = {pinfo, item};
    wmem_list_foreach(chunk->errors, wscbor_expert_add, &ctx);
    wmem_list_foreach(chunk->_priv->infos, wscbor_expert_add, &ctx);

    return wmem_list_count(chunk->errors);
}

guint wscbor_has_errors(const wscbor_chunk_t *chunk) {
    return wmem_list_count(chunk->errors);
}

gboolean wscbor_is_indefinite_break(const wscbor_chunk_t *chunk) {
    return (
        (chunk->type_major == CBOR_TYPE_FLOAT_CTRL)
        && (chunk->type_minor == 31)
    );
}

gboolean wscbor_skip_next_item(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset) {
    wscbor_chunk_t *chunk = wscbor_chunk_read(alloc, tvb, offset);
    switch (chunk->type_major) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NEGINT:
        case CBOR_TYPE_TAG:
        case CBOR_TYPE_FLOAT_CTRL:
            break;
        case CBOR_TYPE_BYTESTRING:
        case CBOR_TYPE_STRING:
            // wscbor_read_chunk() sets offset past string value
            break;
        case CBOR_TYPE_ARRAY: {
            if (chunk->type_minor == 31) {
                // wait for indefinite break
                while (!wscbor_skip_next_item(alloc, tvb, offset)) {}
            }
            else {
                const guint64 count = chunk->head_value;
                for (guint64 ix = 0; ix < count; ++ix) {
                    wscbor_skip_next_item(alloc, tvb, offset);
                }
            }
            break;
        }
        case CBOR_TYPE_MAP: {
            if (chunk->type_minor == 31) {
                // wait for indefinite break
                while (!wscbor_skip_next_item(alloc, tvb, offset)) {}
            }
            else {
                const guint64 count = chunk->head_value;
                for (guint64 ix = 0; ix < count; ++ix) {
                    wscbor_skip_next_item(alloc, tvb, offset);
                    wscbor_skip_next_item(alloc, tvb, offset);
                }
            }
            break;
        }
    }
    const gboolean is_break = wscbor_is_indefinite_break(chunk);
    wscbor_chunk_free(chunk);
    return is_break;
}

gboolean wscbor_skip_if_errors(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset, const wscbor_chunk_t *chunk) {
    if (wscbor_has_errors(chunk) == 0) {
        return FALSE;
    }

    *offset = chunk->start;
    wscbor_skip_next_item(alloc, tvb, offset);
    return TRUE;
}

void wscbor_init(void) {
    proto_wscbor = proto_register_protocol(
        "CBOR Item Decoder",
        "CBOR Item Decoder",
        "_ws.wscbor"
    );

    expert_module_t *expert_wscbor = expert_register_protocol(proto_wscbor);
    /* This isn't really a protocol, it's an error indication;
       disabling them makes no sense. */
    proto_set_cant_toggle(proto_wscbor);

    expert_register_field_array(expert_wscbor, expertitems, array_length(expertitems));
}

const ei_register_info * wscbor_expert_items(int *size) {
    if (size) {
        *size = array_length(expertitems);
    }
    return expertitems;
}

gboolean wscbor_require_major_type(wscbor_chunk_t *chunk, cbor_type major) {
    if (chunk->type_major == major) {
        return TRUE;
    }
    wmem_list_append(chunk->errors, wscbor_error_new(
            chunk->_priv->alloc, &ei_cbor_wrong_type,
            "Item has major type %d, should be %d",
            chunk->type_major, major
    ));
    return FALSE;
}

gboolean wscbor_require_array(wscbor_chunk_t *chunk) {
    return wscbor_require_major_type(chunk, CBOR_TYPE_ARRAY);
}

gboolean wscbor_require_array_size(wscbor_chunk_t *chunk, guint64 count_min, guint64 count_max) {
    if (!wscbor_require_array(chunk)) {
        return FALSE;
    }
    if ((chunk->head_value < count_min) || (chunk->head_value > count_max)) {
        wmem_list_append(chunk->errors, wscbor_error_new(
                chunk->_priv->alloc, &ei_cbor_array_wrong_size,
                "Array has %" PRId64 " items, should be within [%"PRId64", %"PRId64"]",
                chunk->head_value, count_min, count_max
        ));
        return FALSE;
    }
    return TRUE;
}

gboolean wscbor_require_map(wscbor_chunk_t *chunk) {
    return wscbor_require_major_type(chunk, CBOR_TYPE_MAP);
}

gboolean * wscbor_require_boolean(wmem_allocator_t *alloc, wscbor_chunk_t *chunk) {
    if (!wscbor_require_major_type(chunk, CBOR_TYPE_FLOAT_CTRL)) {
        return NULL;
    }

    switch (chunk->type_minor) {
        case CBOR_CTRL_TRUE:
        case CBOR_CTRL_FALSE: {
            gboolean *value = NULL;
            value = wmem_new(alloc, gboolean);
            *value = (chunk->type_minor == CBOR_CTRL_TRUE);
            return value;
        }
        default:
            wmem_list_append(chunk->errors, wscbor_error_new(
                    chunk->_priv->alloc, &ei_cbor_wrong_type,
                    "Item has minor type %d, should be %d or %d",
                    chunk->type_minor, CBOR_CTRL_TRUE, CBOR_CTRL_FALSE
            ));
            break;
    }
    return NULL;
}

guint64 * wscbor_require_uint64(wmem_allocator_t *alloc, wscbor_chunk_t *chunk) {
    if (!wscbor_require_major_type(chunk, CBOR_TYPE_UINT)) {
        return NULL;
    }

    guint64 *result = wmem_new(alloc, guint64);
    *result = chunk->head_value;
    return result;
}

gint64 * wscbor_require_int64(wmem_allocator_t *alloc, wscbor_chunk_t *chunk) {
    gint64 *result = NULL;
    switch (chunk->type_major) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NEGINT: {
            gint64 clamped;
            if (chunk->head_value > INT64_MAX) {
                clamped = INT64_MAX;
                wmem_list_append(chunk->errors, wscbor_error_new(
                        chunk->_priv->alloc, &ei_cbor_overflow,
                        NULL
                ));
            }
            else {
                clamped = chunk->head_value;
            }

            result = wmem_new(alloc, gint64);
            if (chunk->type_major == CBOR_TYPE_NEGINT) {
                *result = -clamped - 1;
            }
            else {
                *result = clamped;
            }
            break;
        }
        default:
            wmem_list_append(chunk->errors, wscbor_error_new(
                    chunk->_priv->alloc, &ei_cbor_wrong_type,
                    "Item has major type %d, should be %d or %d",
                    chunk->type_major, CBOR_TYPE_UINT, CBOR_TYPE_NEGINT
            ));
            break;
    }
    return result;
}

char * wscbor_require_tstr(wmem_allocator_t *alloc, wscbor_chunk_t *chunk) {
    if (!wscbor_require_major_type(chunk, CBOR_TYPE_STRING)) {
        return NULL;
    }

    return (char *)tvb_get_string_enc(alloc, chunk->_priv->str_value, 0, tvb_reported_length(chunk->_priv->str_value), ENC_UTF_8);
}

tvbuff_t * wscbor_require_bstr(wmem_allocator_t *alloc _U_, wscbor_chunk_t *chunk) {
    if (!wscbor_require_major_type(chunk, CBOR_TYPE_BYTESTRING)) {
        return NULL;
    }

    return chunk->_priv->str_value;
}

proto_item * proto_tree_add_cbor_container(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk) {
    const header_field_info *hfinfo = proto_registrar_get_nth(hfindex);
    proto_item *item;
    if (IS_FT_UINT(hfinfo->type)) {
        item = proto_tree_add_uint64(tree, hfindex, tvb, chunk->start, chunk->head_length, chunk->head_value);
    }
    else if (IS_FT_INT(hfinfo->type)) {
        item = proto_tree_add_int64(tree, hfindex, tvb, chunk->start, chunk->head_length, chunk->head_value);
    }
    else {
        item = proto_tree_add_item(tree, hfindex, tvb, chunk->start, -1, 0);
    }
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_ctrl(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk) {
    proto_item *item = proto_tree_add_item(tree, hfindex, tvb, chunk->start, chunk->head_length, 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_boolean(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const gboolean *value) {
    proto_item *item = proto_tree_add_boolean(tree, hfindex, tvb, chunk->start, chunk->data_length, value ? *value : FALSE);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_uint64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const guint64 *value) {
    proto_item *item = proto_tree_add_uint64(tree, hfindex, tvb, chunk->start, chunk->head_length, value ? *value : 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_int64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const gint64 *value) {
    proto_item *item = proto_tree_add_int64(tree, hfindex, tvb, chunk->start, chunk->head_length, value ? *value : 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_bitmask(proto_tree *tree, int hfindex, const gint ett, int *const *fields, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const guint64 *value) {
    header_field_info *field = proto_registrar_get_nth(hfindex);
    gint flagsize = 0;
    switch (field->type) {
        case FT_UINT8:
            flagsize = 1;
            break;
        case FT_UINT16:
            flagsize = 2;
            break;
        case FT_UINT32:
            flagsize = 4;
            break;
        case FT_UINT64:
            flagsize = 8;
            break;
        default:
            fprintf(stderr, "Unhandled bitmask size: %d", field->type);
            return NULL;
    }

    // Fake TVB data for these functions
    guint8 *flags = (guint8 *) wmem_alloc0(pinfo->pool, flagsize);
    { // Inject big-endian value directly
        guint64 buf = (value ? *value : 0);
        for (gint ix = flagsize - 1; ix >= 0; --ix) {
            flags[ix] = buf & 0xFF;
            buf >>= 8;
        }
    }
    tvbuff_t *tvb_flags = tvb_new_child_real_data(tvb, flags, flagsize, flagsize);

    proto_item *item = proto_tree_add_bitmask_value(tree, tvb_flags, 0, hfindex, ett, fields, value ? *value : 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_tstr(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb _U_, const wscbor_chunk_t *chunk) {
    if (chunk->_priv->str_value) {
        proto_item *item = proto_tree_add_item(tree, hfindex, chunk->_priv->str_value, 0, tvb_reported_length(chunk->_priv->str_value), 0);
        wscbor_chunk_mark_errors(pinfo, item, chunk);
        return item;
    } else {
        return NULL;
    }
}

proto_item * proto_tree_add_cbor_bstr(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb _U_, const wscbor_chunk_t *chunk) {
    if (chunk->_priv->str_value) {
        proto_item *item = proto_tree_add_item(tree, hfindex, chunk->_priv->str_value, 0, tvb_reported_length(chunk->_priv->str_value), 0);
        wscbor_chunk_mark_errors(pinfo, item, chunk);
        return item;
    } else {
        return NULL;
    }
}
