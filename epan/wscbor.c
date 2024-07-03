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

#include <wsutil/array.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <stdio.h>
#include <inttypes.h>
#include "wscbor.h"

/// Pseudo-protocol to register expert info
static int proto_wscbor;

static expert_field ei_cbor_invalid;
static expert_field ei_cbor_overflow;
static expert_field ei_cbor_wrong_type;
static expert_field ei_cbor_array_wrong_size;
static expert_field ei_cbor_indef_string;
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
    int start;
    /// The length of just this header
    int length;
    /// The expert info object (if error)
    expert_field *error;

    /// Major type of this item (cbor_type)
    uint8_t type_major;
    /// Minor type of this item
    uint8_t type_minor;
    /// Raw head "value" which may be from the @c type_minor
    uint64_t rawvalue;
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
static wscbor_head_t * wscbor_head_read(wmem_allocator_t *alloc, tvbuff_t *tvb, int *offset) {
    wscbor_head_t *head = wmem_new0(alloc, wscbor_head_t);

    head->start = *offset;
    const uint8_t first = tvb_get_guint8(tvb, head->start);
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
static int wscbor_get_length(wscbor_chunk_t *chunk, uint64_t head_value) {
    int length;
    if (head_value > INT_MAX) {
        wmem_list_append(chunk->errors, wscbor_error_new(
                chunk->_priv->alloc, &ei_cbor_overflow,
                NULL
        ));
        length = INT_MAX;
    }
    else {
        length = (int) head_value;
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

wscbor_chunk_t * wscbor_chunk_read(wmem_allocator_t *alloc, tvbuff_t *tvb, int *offset) {
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
    while (true) {
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
                const int datalen = wscbor_get_length(chunk, chunk->head_value);
                // skip over definite data
                *offset += datalen;
                chunk->data_length += datalen;
                // allow even zero-length strings
                chunk->_priv->str_value = tvb_new_subset_length(tvb, chunk->start + chunk->head_length, datalen);
            }
            else {
                // indefinite length, sequence of definite items
                chunk->_priv->str_value = NULL;

                while (true) {
                    wscbor_head_t *head = wscbor_head_read(alloc, tvb, offset);
                    chunk->data_length += head->length;
                    if (head->error) {
                        wmem_list_append(chunk->errors, wscbor_error_new(alloc, head->error, NULL));
                    }
                    const bool is_break = (
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
                            const int datalen = wscbor_get_length(chunk, head->rawvalue);
                            *offset += datalen;
                            chunk->data_length += datalen;
                            if(datalen) {
                                if (!chunk->_priv->str_value) {
                                    chunk->_priv->str_value = tvb_new_composite ();
                                }
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

                if (chunk->_priv->str_value) {
                    tvb_composite_finalize(chunk->_priv->str_value);
                }
                else {
                    // Create an empty subset tvb. str_value is expected to be non-NULL for string types.
                    chunk->_priv->str_value = tvb_new_subset_length (tvb, 0, 0);
                }
            }
            break;
        default:
            break;
    }

    return chunk;
}

static void wscbor_subitem_free(void *data, void *userdata) {
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
static void wscbor_expert_add(void *data, void *userdata) {
    const wscbor_error_t *err = (const wscbor_error_t *)data;
    wscbor_expert_add_t *ctx = (wscbor_expert_add_t *)userdata;

    if (err->msg) {
        expert_add_info_format(ctx->pinfo, ctx->item, err->ei, "%s", err->msg);
    }
    else {
        expert_add_info(ctx->pinfo, ctx->item, err->ei);
    }
}

uint64_t wscbor_chunk_mark_errors(packet_info *pinfo, proto_item *item, const wscbor_chunk_t *chunk) {
    wscbor_expert_add_t ctx = {pinfo, item};
    wmem_list_foreach(chunk->errors, wscbor_expert_add, &ctx);
    wmem_list_foreach(chunk->_priv->infos, wscbor_expert_add, &ctx);

    return wmem_list_count(chunk->errors);
}

unsigned wscbor_has_errors(const wscbor_chunk_t *chunk) {
    return wmem_list_count(chunk->errors);
}

bool wscbor_is_indefinite_break(const wscbor_chunk_t *chunk) {
    return (
        (chunk->type_major == CBOR_TYPE_FLOAT_CTRL)
        && (chunk->type_minor == 31)
    );
}

/** Add output parameter to indicate internal state.
 * @param alloc The allocator to use.
 * @param tvb The data buffer.
 * @param[in,out] offset The initial offset to read and skip over.
 * @param[out] is_break If non-null, set to true only when the item was
 * an indefinite break.
 * @return True if the skipped item was fully valid.
 */
static bool wscbor_skip_next_item_internal(wmem_allocator_t *alloc, tvbuff_t *tvb, int *offset, bool *is_break) {
    wscbor_chunk_t *chunk = wscbor_chunk_read(alloc, tvb, offset);
    if (wscbor_has_errors(chunk)) {
        wscbor_chunk_free(chunk);
        return false;
    }
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
                bool was_break = false;
                do {
                    if (!wscbor_skip_next_item_internal(alloc, tvb, offset, &was_break)) {
                        return false;
                    }
                }
                while (!was_break);
            }
            else {
                const uint64_t count = chunk->head_value;
                for (uint64_t ix = 0; ix < count; ++ix) {
                    if (!wscbor_skip_next_item_internal(alloc, tvb, offset, NULL)) {
                        return false;
                    }
                }
            }
            break;
        }
        case CBOR_TYPE_MAP: {
            if (chunk->type_minor == 31) {
                // wait for indefinite break
                bool was_break = false;
                do {
                    if (!wscbor_skip_next_item_internal(alloc, tvb, offset, &was_break)) {
                        return false;
                    }
                }
                while (!was_break);
            }
            else {
                const uint64_t count = chunk->head_value;
                for (uint64_t ix = 0; ix < count; ++ix) {
                    if (!wscbor_skip_next_item_internal(alloc, tvb, offset, NULL)) {
                        return false;
                    }
                    if (!wscbor_skip_next_item_internal(alloc, tvb, offset, NULL)) {
                        return false;
                    }
                }
            }
            break;
        }
    }
    const bool got_break = wscbor_is_indefinite_break(chunk);
    if (is_break) {
        *is_break = got_break;
    }
    wscbor_chunk_free(chunk);
    // RFC 8949 Sec 3.2.1: a break code outside of an indefinite container is
    // not valid, and is_break is non-null only in indefinite container.
    return is_break || !got_break;
}

bool wscbor_skip_next_item(wmem_allocator_t *alloc, tvbuff_t *tvb, int *offset) {
    return wscbor_skip_next_item_internal(alloc, tvb, offset, NULL);
}

bool wscbor_skip_if_errors(wmem_allocator_t *alloc, tvbuff_t *tvb, int *offset, const wscbor_chunk_t *chunk) {
    if (wscbor_has_errors(chunk) == 0) {
        return false;
    }

    *offset = chunk->start;
    wscbor_skip_next_item(alloc, tvb, offset);
    return true;
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

bool wscbor_require_major_type(wscbor_chunk_t *chunk, cbor_type major) {
    if (chunk->type_major == major) {
        return true;
    }
    wmem_list_append(chunk->errors, wscbor_error_new(
            chunk->_priv->alloc, &ei_cbor_wrong_type,
            "Item has major type %d, should be %d",
            chunk->type_major, major
    ));
    return false;
}

bool wscbor_require_array(wscbor_chunk_t *chunk) {
    return wscbor_require_major_type(chunk, CBOR_TYPE_ARRAY);
}

bool wscbor_require_array_size(wscbor_chunk_t *chunk, uint64_t count_min, uint64_t count_max) {
    if (!wscbor_require_array(chunk)) {
        return false;
    }
    if ((chunk->head_value < count_min) || (chunk->head_value > count_max)) {
        wmem_list_append(chunk->errors, wscbor_error_new(
                chunk->_priv->alloc, &ei_cbor_array_wrong_size,
                "Array has %" PRId64 " items, should be within [%"PRId64", %"PRId64"]",
                chunk->head_value, count_min, count_max
        ));
        return false;
    }
    return true;
}

bool wscbor_require_map(wscbor_chunk_t *chunk) {
    return wscbor_require_major_type(chunk, CBOR_TYPE_MAP);
}

bool * wscbor_require_boolean(wmem_allocator_t *alloc, wscbor_chunk_t *chunk) {
    if (!wscbor_require_major_type(chunk, CBOR_TYPE_FLOAT_CTRL)) {
        return NULL;
    }

    switch (chunk->type_minor) {
        case CBOR_CTRL_TRUE:
        case CBOR_CTRL_FALSE: {
            bool *value = NULL;
            value = wmem_new(alloc, bool);
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

uint64_t * wscbor_require_uint64(wmem_allocator_t *alloc, wscbor_chunk_t *chunk) {
    if (!wscbor_require_major_type(chunk, CBOR_TYPE_UINT)) {
        return NULL;
    }

    uint64_t *result = wmem_new(alloc, uint64_t);
    *result = chunk->head_value;
    return result;
}

int64_t * wscbor_require_int64(wmem_allocator_t *alloc, wscbor_chunk_t *chunk) {
    int64_t *result = NULL;
    switch (chunk->type_major) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NEGINT: {
            int64_t clamped;
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

            result = wmem_new(alloc, int64_t);
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
    if (FT_IS_UINT(hfinfo->type)) {
        item = proto_tree_add_uint64(tree, hfindex, tvb, chunk->start, chunk->head_length, chunk->head_value);
    }
    else if (FT_IS_INT(hfinfo->type)) {
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

proto_item * proto_tree_add_cbor_boolean(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const bool *value) {
    proto_item *item = proto_tree_add_boolean(tree, hfindex, tvb, chunk->start, chunk->data_length, value ? *value : false);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_uint64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const uint64_t *value) {
    proto_item *item = proto_tree_add_uint64(tree, hfindex, tvb, chunk->start, chunk->head_length, value ? *value : 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_int64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const int64_t *value) {
    proto_item *item = proto_tree_add_int64(tree, hfindex, tvb, chunk->start, chunk->head_length, value ? *value : 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_bitmask(proto_tree *tree, int hfindex, const int ett, int *const *fields, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const uint64_t *value) {
    header_field_info *field = proto_registrar_get_nth(hfindex);
    int flagsize = 0;
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
    uint8_t *flags = (uint8_t *) wmem_alloc0(pinfo->pool, flagsize);
    { // Inject big-endian value directly
        uint64_t buf = (value ? *value : 0);
        for (int ix = flagsize - 1; ix >= 0; --ix) {
            flags[ix] = buf & 0xFF;
            buf >>= 8;
        }
    }
    tvbuff_t *tvb_flags = tvb_new_child_real_data(tvb, flags, flagsize, flagsize);

    proto_item *item = proto_tree_add_bitmask_value(tree, tvb_flags, 0, hfindex, ett, fields, value ? *value : 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_tstr(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk) {
    proto_item *item;
    if (chunk->_priv->str_value) {
        item = proto_tree_add_item(tree, hfindex, chunk->_priv->str_value, 0, tvb_reported_length(chunk->_priv->str_value), ENC_UTF_8);
    }
    else {
        // still show an empty item with errors
        item = proto_tree_add_item(tree, hfindex, tvb, chunk->start, 0, 0);
    }
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_bstr(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk) {
    proto_item *item;
    if (chunk->_priv->str_value) {
        item = proto_tree_add_item(tree, hfindex, chunk->_priv->str_value, 0, tvb_reported_length(chunk->_priv->str_value), 0);
    }
    else {
        // still show an empty item with errors
        item = proto_tree_add_item(tree, hfindex, tvb, chunk->start, 0, 0);
    }
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_strlen(proto_tree *tree, int hfindex, packet_info *pinfo _U_, tvbuff_t *tvb, const wscbor_chunk_t *chunk) {
    const unsigned str_len = (chunk->_priv->str_value ? tvb_reported_length(chunk->_priv->str_value) : 0);
    proto_item *item = proto_tree_add_uint64(tree, hfindex, tvb, chunk->start, chunk->head_length, str_len);
    return item;
}
