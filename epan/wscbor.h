/** @file
 * Definitions for the Wireshark CBOR item decoding API.
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

#ifndef __WSCBOR_H__
#define __WSCBOR_H__

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <wsutil/wmem/wmem_list.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Register expert info and other wireshark data.
 */
WS_DLL_PUBLIC
void wscbor_init(void);

/** Expose available expert info for this library.
 * @param[out] size Set to the size of the array.
 * @return The array of expert info objects.
 */
WS_DLL_PUBLIC
const ei_register_info * wscbor_expert_items(int *size);

/// The same enumeration from libcbor-0.5
typedef enum cbor_type {
    CBOR_TYPE_UINT = 0, ///< positive integers
    CBOR_TYPE_NEGINT = 1, ///< negative integers
    CBOR_TYPE_BYTESTRING = 2, ///< byte strings
    CBOR_TYPE_STRING = 3, ///< text strings
    CBOR_TYPE_ARRAY = 4, ///< arrays
    CBOR_TYPE_MAP = 5, ///< maps
    CBOR_TYPE_TAG = 6, ///< tags
    CBOR_TYPE_FLOAT_CTRL = 7, ///< decimals and special values (true, false, nil, ...)
} cbor_type;

/// The same enumeration from libcbor-0.5
typedef enum {
    CBOR_CTRL_NONE = 0,
    CBOR_CTRL_FALSE = 20,
    CBOR_CTRL_TRUE = 21,
    CBOR_CTRL_NULL = 22,
    CBOR_CTRL_UNDEF = 23
} _cbor_ctrl;

/// Decoding or require_* error
typedef struct {
    /// The associated expert info
    expert_field *ei;
    /// Optional specific text
    const char *msg;
} wscbor_error_t;

/** Construct a new error object.
 *
 * @param alloc The allocator to use.
 * @param ei The specific error type.
 * @param format If non-NULL, a message format string.
 * @return The new object.
 */
WS_DLL_PUBLIC
wscbor_error_t * wscbor_error_new(wmem_allocator_t *alloc, expert_field *ei, const char *format, ...);

/// Tag metadata and value
typedef struct {
    /// The start offset of this tag head
    int start;
    /// The length of just this tag head
    int length;
    /// The tag value
    uint64_t value;
} wscbor_tag_t;

struct _wscbor_chunk_priv_t;
typedef struct _wscbor_chunk_priv_t wscbor_chunk_priv_t;
/// A data-containing, optionally-tagged chunk of CBOR
typedef struct {
    /// Internal private data
    wscbor_chunk_priv_t *_priv;

    /// The start offset of this chunk
    int start;
    /// The length of just this header and any preceding tags
    int head_length;
    /// The length of this chunk and its immediate definite data (i.e. strings)
    int data_length;
    /// Errors processing this chunk (type wscbor_error_t*)
    wmem_list_t *errors;
    /// Tags on this chunk, in encoded order (type wscbor_tag_t*)
    wmem_list_t *tags;

    /// Major type of this block.
    /// This will be one of the cbor_type values.
    cbor_type type_major;
    /// Minor type of this item
    uint8_t type_minor;
    /// The header-encoded value
    uint64_t head_value;
} wscbor_chunk_t;

/** Scan for a tagged chunk of headers.
 * The chunk of byte string and text string items includes the data content
 * in its @c offset.
 *
 * @param alloc The allocator to use.
 * @param tvb The TVB to read from.
 * @param[in,out] offset The offset with in @c tvb.
 * This is updated to be just past the new chunk.
 * @return The chunk of data found, including any errors.
 * This never returns NULL.
 * @post This can throw ReportedBoundsError or ContainedBoundsError
 * if the read itself ran out of data.
 */
WS_DLL_PUBLIC
wscbor_chunk_t * wscbor_chunk_read(wmem_allocator_t *alloc, tvbuff_t *tvb, int *offset);

/** Free a chunk and its lists.
 */
WS_DLL_PUBLIC
void wscbor_chunk_free(wscbor_chunk_t *chunk);

/** After both reading and decoding a chunk, report on any errors found.
 * @param pinfo The associated packet.
 * @param item The associated tree item.
 * @param chunk The chunk with possible errors.
 * @return The error count.
 */
WS_DLL_PUBLIC
uint64_t wscbor_chunk_mark_errors(packet_info *pinfo, proto_item *item, const wscbor_chunk_t *chunk);

/** Determine if a chunk has errors.
 * @param chunk The chunk with possible errors.
 * @return The error count.
 */
WS_DLL_PUBLIC
unsigned wscbor_has_errors(const wscbor_chunk_t *chunk);

/** Determine if an indefinite break is present.
 *
 * @param chunk The chunk to check.
 * @return True if it's an indefinite break.
 */
WS_DLL_PUBLIC
bool wscbor_is_indefinite_break(const wscbor_chunk_t *chunk);

/** Recursively skip items from a stream.
 *
 * @param alloc The allocator to use.
 * @param tvb The data buffer.
 * @param[in,out] offset The initial offset to read and skip over.
 * Will be set to one-past the last valid CBOR (possibly nested) present.
 * @return True if the skipped item was fully valid.
 * @post This can throw ReportedBoundsError or ContainedBoundsError
 * if the read itself ran out of data.
 */
WS_DLL_PUBLIC
bool wscbor_skip_next_item(wmem_allocator_t *alloc, tvbuff_t *tvb, int *offset);

/** Skip over an item if a chunk has errors.
 * This allows skipping an entire array or map if the major type or size is
 * not as expected.
 *
 * @param alloc The allocator to use.
 * @param tvb The data buffer.
 * @param[in,out] offset The initial offset to read and skip over.
 * @param chunk The chunk with possible errors.
 * @return True if there were errors and the item skipped.
 */
WS_DLL_PUBLIC
bool wscbor_skip_if_errors(wmem_allocator_t *alloc, tvbuff_t *tvb, int *offset, const wscbor_chunk_t *chunk);


/** Require a specific item major type.
 *
 * @param[in,out] chunk The chunk to read from and write errors on.
 * @param major The required major type.
 * @return True if the item is that type.
 */
WS_DLL_PUBLIC
bool wscbor_require_major_type(wscbor_chunk_t *chunk, cbor_type major);

/** Require an array item.
 *
 * @param[in,out] chunk The chunk to read from and write errors on.
 * @return True if the item is an array.
 */
WS_DLL_PUBLIC
bool wscbor_require_array(wscbor_chunk_t *chunk);

/** Require an array have a specific ranged size.
 *
 * @param[in,out] chunk The chunk to read from and write errors on.
 * @param count_min The minimum acceptable size.
 * @param count_max The maximum acceptable size.
 * @return True if the size is acceptable.
 */
WS_DLL_PUBLIC
bool wscbor_require_array_size(wscbor_chunk_t *chunk, uint64_t count_min, uint64_t count_max);

/** Require a map item.
 *
 * @param[in,out] chunk The chunk to read from and write errors on.
 * @return True if the item is a map.
 */
WS_DLL_PUBLIC
bool wscbor_require_map(wscbor_chunk_t *chunk);

/** Require a CBOR item to have a boolean value.
 *
 * @param alloc The allocator to use.
 * @param[in,out] chunk The chunk to read from and write errors on.
 * @return Pointer to the boolean value, if the item was boolean.
 * The value can be deleted with wscbor_require_delete().
 */
WS_DLL_PUBLIC
bool * wscbor_require_boolean(wmem_allocator_t *alloc, wscbor_chunk_t *chunk);

/** Require a CBOR item to have an unsigned-integer value.
 * @note This reader will clip the most significant bit of the value.
 *
 * @param alloc The allocator to use.
 * @param[in,out] chunk The chunk to read from and write errors on.
 * @return Pointer to the boolean value, if the item was an integer.
 * The value can be deleted with wscbor_require_delete().
 */
WS_DLL_PUBLIC
uint64_t * wscbor_require_uint64(wmem_allocator_t *alloc, wscbor_chunk_t *chunk);

/** Require a CBOR item to have an signed- or unsigned-integer value.
 * @note This reader will clip the most significant bit of the value.
 *
 * @param alloc The allocator to use.
 * @param[in,out] chunk The chunk to read from and write errors on.
 * @return Pointer to the value, if the item was an integer.
 * The value can be deleted with wscbor_require_delete().
 */
WS_DLL_PUBLIC
int64_t * wscbor_require_int64(wmem_allocator_t *alloc, wscbor_chunk_t *chunk);

/** Require a CBOR item to have a text-string value.
 * If the actual text string is not needed, use the following to avoid an
 * unnecessary allocation.
 * @code
 * wscbor_require_major_type(chunk, CBOR_TYPE_STRING)
 * @endcode
 *
 * @param alloc The allocator to use.
 * @param[in,out] chunk The chunk to read from and write errors on.
 * @return Pointer to the null-terminated UTF-8, if the item was a tstr.
 * @post This can throw ContainedBoundsError string ran out of data.
 */
WS_DLL_PUBLIC
char * wscbor_require_tstr(wmem_allocator_t *alloc, wscbor_chunk_t *chunk);

/** Require a CBOR item to have a byte-string value.
 * Use tvb_memdup() or similar if the raw byte-string is needed.
 *
 * @param alloc The allocator to use.
 * @param[in,out] chunk The chunk to read from and write errors on.
 * @return Pointer to the value, if the item was an bstr.
 * The value is memory managed by wireshark.
 */
WS_DLL_PUBLIC
tvbuff_t * wscbor_require_bstr(wmem_allocator_t *alloc, wscbor_chunk_t *chunk);

/** Add an item representing an array or map container.
 * If the item is type FT_UINT* or FT_INT* the count of (array) items
 * or map (pairs) is used as the iterm value.
 */
WS_DLL_PUBLIC
proto_item * proto_tree_add_cbor_container(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk);

/** Add an item representing a non-boolean, non-float control value.
 */
WS_DLL_PUBLIC
proto_item * proto_tree_add_cbor_ctrl(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk);

WS_DLL_PUBLIC
proto_item * proto_tree_add_cbor_boolean(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const bool *value);

WS_DLL_PUBLIC
proto_item * proto_tree_add_cbor_uint64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const uint64_t *value);

WS_DLL_PUBLIC
proto_item * proto_tree_add_cbor_int64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const int64_t *value);

WS_DLL_PUBLIC
proto_item * proto_tree_add_cbor_bitmask(proto_tree *tree, int hfindex, const int ett, int *const *fields, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const uint64_t *value);

WS_DLL_PUBLIC
proto_item * proto_tree_add_cbor_tstr(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk);

WS_DLL_PUBLIC
proto_item * proto_tree_add_cbor_bstr(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk);

/** Add an item representing the length of a bstr or tstr value.
 */
WS_DLL_PUBLIC
proto_item * proto_tree_add_cbor_strlen(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk);

#ifdef __cplusplus
}
#endif

#endif /* __WSCBOR_H__ */
