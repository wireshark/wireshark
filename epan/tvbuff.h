/** @file
 *
 * Testy, Virtual(-izable) Buffer of uint8_t*'s
 *
 * "Testy" -- the buffer gets mad when an attempt is made to access data
 *      beyond the bounds of the buffer. An exception is thrown.
 *
 * "Virtual" -- the buffer can have its own data, can use a subset of
 *      the data of a backing tvbuff, or can be a composite of
 *      other tvbuffs.
 *
 * Copyright (c) 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TVBUFF_H__
#define __TVBUFF_H__

#include <ws_symbol_export.h>
#include <ws_attributes.h>

#include <epan/guid-utils.h>

#include <wsutil/inet_addr.h>
#include <wsutil/nstime.h>
#include "wsutil/ws_mempbrk.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief "testy, virtual(-izable) buffer".
 *
 * They are testy in that they get mad when
 * an attempt is made to access data beyond the bounds of their array. In that
 * case, they throw an exception.
 *
 * They are virtualizable in that new tvbuff's can be made from other tvbuffs,
 * while only the original tvbuff may have data. That is, the new tvbuff has
 * virtual data.
 */
struct tvbuff;
typedef struct tvbuff tvbuff_t;

/** @defgroup tvbuff Testy, Virtual(-izable) Buffers
 *
 * Dissector use and management
 *
 *  Consider a collection of tvbs as being a chain or stack of tvbs.
 *
 *  When dissecting a frame:
 *   The top-level dissector (packet.c) pushes the initial tvb (containing
 *   the complete frame) onto the stack (starts the chain) and then calls
 *   a sub-dissector which in turn calls the next sub-dissector and so on.
 *   Each sub-dissector may chain additional tvbs (see below) to the tvb
 *   handed to that dissector. After dissection is complete and control has
 *   returned to the top-level dissector, the chain of tvbs (stack) is free'd
 *   via a call to tvb_free_chain() (in epan_dissect_cleanup()).
 *
 * A dissector:
 *  - Can chain new tvbs (subset, real, composite) to the
 *    tvb handed to the dissector using tvb_new_subset_length_caplen(),
 *    tvb_new_subset_length(), tvb_new_subset_remaining(),
 *    tvb_new_child_real_data(), tvb_set_child_real_data_tvbuff(),
 *    tvb_composite_finalize(), and tvb_child_uncompress(). (Composite
 *    tvbs should reference only tvbs which are already part of the chain).
 *  - Must not save for later use (e.g., when dissecting another frame) a
 *    pointer to a tvb handed to the dissector; (A higher level function
 *    may very well free the chain thus leaving a dangling pointer).
 *    This (obviously) also applies to any tvbs chained to the tvb handed
 *    to the dissector.
 *  - Can create its own tvb chain (using tvb_new_real_data() which the
 *    dissector is free to manage as desired.
 * @{
 */

/** A "real" tvbuff contains a uint8_t* that points to real data.
 * The data is allocated and contiguous.
 *
 * A "subset" tvbuff has a backing tvbuff. It is a "window" through
 * which the program sees only a portion of the backing tvbuff.
 *
 * A "composite" tvbuff combines multiple tvbuffs sequentially to
 * produce a larger byte array.
 *
 * tvbuff's of any type can be used as the backing-tvbuff of a
 * "subset" tvbuff or as a member of a "composite" tvbuff.
 * "composite" tvbuffs can have member-tvbuffs of different types.
 *
 * Once a tvbuff is create/initialized/finalized, the tvbuff is read-only.
 * That is, it cannot point to any other data. A new tvbuff must be created if
 * you want a tvbuff that points to other data.
 *
 * tvbuff's are normally chained together to allow efficient de-allocation of
 * tvbuff's.
 */

typedef void (*tvbuff_free_cb_t)(void*);

 /**
 * @brief Extracts a specified number of bits starting at a given bit offset,
 *        aligning the result to octet boundaries.
 *
 * Bits are counted from most significant bit (MSB = 0) to least significant bit (LSB = 7)
 * within each octet. The returned tvbuff is newly allocated and octet-aligned.
 *
 * @param tvb         The source tvbuff to extract bits from.
 * @param bit_offset  The starting bit offset within the tvbuff.
 * @param no_of_bits  The number of bits to extract.
 *
 * @return A pointer to a newly initialized, g_malloc'd tvbuff containing the extracted bits,
 *         aligned to octet boundaries.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_new_octet_aligned(tvbuff_t *tvb,
    uint32_t bit_offset, int32_t no_of_bits);

 /**
 * @brief Extracts a specified number of bits starting at a given bit offset,
 *        with bits counted from least significant bit (LSB = 0) to most significant bit (MSB = 7)
 *        within each octet.
 *
 * @param tvb         The source tvbuff to extract bits from.
 * @param bit_offset  The starting bit offset within the tvbuff.
 * @param no_of_bits  The number of bits to extract.
 *
 * @return A pointer to a tvbuff containing the extracted bits.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_new_octet_right_aligned(tvbuff_t *tvb,
    uint32_t bit_offset, int32_t no_of_bits);

/**
 * @brief Create a new chained tvbuff from a parent and backing buffer.
 *
 * This function constructs a new @ref tvbuff_t that is logically layered on top
 * of a backing buffer. The parent buffer provides context (e.g., metadata or ownership),
 * while the backing buffer supplies the actual data. This is useful for creating
 * virtual buffers that reference or reinterpret existing data without duplication.
 *
 * @param parent   The parent @ref tvbuff_t providing context.
 * @param backing  The backing @ref tvbuff_t containing actual data.
 *
 * @return A newly allocated chained @ref tvbuff_t.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_new_chain(tvbuff_t *parent, tvbuff_t *backing);

/**
 * @brief Creates a full clone of the given tvbuff.
 *
 * @param tvb  The tvbuff to clone.
 * @return A pointer to a new tvbuff containing a complete copy of the original data.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_clone(tvbuff_t *tvb);

/**
 * @brief Clones a portion of the given tvbuff starting at a specific offset and length.
 *
 * If the tvbuff's operations structure provides a custom `tvb_clone` implementation,
 * it will be used to perform the clone. Otherwise, a generic clone is performed.
 *
 * @param tvb     The source tvbuff to clone from.
 * @param offset  The starting offset within the tvbuff.
 * @param len     The number of bytes to clone.
 *
 * @return A pointer to a new tvbuff containing the cloned data region.
 *
 * @see tvb_generic_clone_offset_len()
 */
WS_DLL_PUBLIC tvbuff_t *tvb_clone_offset_len(tvbuff_t *tvb, unsigned offset,
    unsigned len);

 /**
 * @brief Free a tvbuff_t and all tvbuffs chained from it.
 *
 * The tvbuff must be the 'head' (initial) tvb of a chain or must not be in a chain.
 * If specified, a callback to free the tvbuff data will be invoked for each tvbuff freed.
 *
 * @param tvb  The tvbuff to free along with all chained tvbuffs.
 */
WS_DLL_PUBLIC void tvb_free(tvbuff_t *tvb);

/**
 * @brief Free the tvbuff_t and all tvbuffs chained from it.
 *
 * The tvbuff must be the 'head' (initial) tvb of a chain or must not be in a chain.
 * If specified, a callback to free the tvbuff data will be invoked for each tvbuff freed.
 *
 * @param tvb  The tvbuff to free along with all chained tvbuffs.
 */
WS_DLL_PUBLIC void tvb_free_chain(tvbuff_t *tvb);

/**
 * @brief Set a callback function to be called when a tvbuff is actually freed.
 *
 * One argument is passed to that callback — a void* that points to the real data.
 * Obviously, this only applies to a "real" tvbuff.
 *
 * @param tvb   The tvbuff for which to set the free callback.
 * @param func  The callback function to invoke when the tvbuff is freed.
 */
WS_DLL_PUBLIC void tvb_set_free_cb(tvbuff_t *tvb, const tvbuff_free_cb_t func);

/**
 * @brief Attach a "real" tvbuff to a parent tvbuff.
 *
 * This connection is used during a tvb_free_chain(). The "child" "real" tvbuff acts as if it
 * is part of the chain-of-creation of the parent tvbuff, although it isn't.
 *
 * This is useful if you need to take the data from some tvbuff, run some operation on it,
 * like decryption or uncompression, and make a new tvbuff from it, yet want the new tvbuff
 * to be part of the chain.
 *
 * The reality is that the new tvbuff *is* part of the "chain of creation", but in a way that
 * these tvbuff routines are ignorant of. Use this function to make the tvbuff routines
 * knowledgeable of this fact.
 *
 * @param parent  The parent tvbuff to which the child tvbuff will be attached.
 * @param child   The "real" child tvbuff to attach to the parent.
 */
WS_DLL_PUBLIC void tvb_set_child_real_data_tvbuff(tvbuff_t *parent,
    tvbuff_t *child);

/**
 * @brief Create a new child tvbuff with real data.
 *
 * This function creates a new @ref tvbuff_t that is a child of the given
 * parent buffer but uses the specified data buffer directly.
 *
 * @param parent          The parent @ref tvbuff_t for context and ownership.
 * @param data            Pointer to the data buffer to use.
 * @param length          The length of the data buffer.
 * @param reported_length The length to report for this tvbuff (may differ from actual length).
 *
 * @return A new child @ref tvbuff_t referencing the provided data.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_new_child_real_data(tvbuff_t *parent,
    const uint8_t *data, const unsigned length, const int reported_length);

/**
 * @brief Create a tvbuff backed by existing data.
 *
 * Create a tvbuff backed by existing data. Can throw ReportedBoundsError.
 * Normally, a callback to free the data should be registered using @ref tvb_set_free_cb "tvb_set_free_cb()";
 * when this tvbuff is freed, your callback will be called, allowing you to free your original data.
 *
 * @param data            Pointer to the existing data buffer.
 * @param length          Length of the data buffer in bytes.
 * @param reported_length The length reported for this tvbuff (may differ from actual length).
 *
 * @return A pointer to the newly created tvbuff backed by the provided data.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_new_real_data(const uint8_t *data,
    const unsigned length, const int reported_length);

/**
 * @brief Create a subset tvbuff with an explicitly limited captured length.
 *
 * Create a tvbuff that's a subset of another tvbuff, with the captured
 * length explicitly given. You probably want @ref tvb_new_subset_length() or
 * @ref tvb_new_subset_remaining() instead.
 *
 * @param backing The backing tvbuff onto which the new tvbuff is a view
 * @param backing_offset If positive, is the offset from the beginning of
 * the backing tvbuff at which the new tvbuff's data begins, and, if
 * negative, is the offset from the end of the backing tvbuff at which
 * the new tvbuff's data begins.
 * @param backing_length The length of the data to include in the new
 * tvbuff, starting with the byte at 'backing_offset'; if -1, it
 * means "to the end of the backing tvbuff".  It can be 0, although
 * the usefulness of the buffer would be rather limited.  The length
 * actually included will be no more than the reported length.
 * @param reported_length The reported length of the new tvbuff; if -1, it
 * means "the reported length to the end of the backing tvbuff".  It can
 * be 0, although the usefulness of the buffer would be rather limited.
 *
 * @return A tvbuff that is a subset of the backing tvbuff beginning at
 * backing_offset (which is offset 0 in the subset) and with the given
 * reported_length, with captured length no more than backing_length.
 *
 * @note In most cases use tvb_new_subset_length() (or equivalently, pass -1
 * as 'backing_length') or tvb_new_subset_remaining() instead.  Use this when
 * the backing tvbuff includes bytes at the end that must not be included in
 * the subset regardless of the reported length, such as an FCS or padding.
 * In such cases it may still be simpler to call tvb_new_subset_length()
 * twice, once to remove the trailing bytes and once to select the chosen
 * payload bytes.
 *
 * @warning Will throw BoundsError if 'backing_offset'/'length'
 * is beyond the bounds of the backing tvbuff.
 * Can throw ReportedBoundsError. */
WS_DLL_PUBLIC tvbuff_t *tvb_new_subset_length_caplen(tvbuff_t *backing,
    const int backing_offset, const int backing_length,
    const int reported_length);

/**
 * @brief Create a subset tvbuff with captured length fitting within backing and reported lengths.
 *
 * Similar to @ref tvb_new_subset_length_caplen() but with captured length calculated
 * to fit within the existing captured length and the specified reported length.
 *
 * Can throw ReportedBoundsError.
 *
 * @param backing         The backing tvbuff.
 * @param backing_offset  The offset into the backing tvbuff.
 * @param reported_length The reported length for the new subset.
 *
 * @return A pointer to the newly created subset tvbuff.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_new_subset_length(tvbuff_t *backing,
    const int backing_offset, const int reported_length);

/**
 * @brief Similar to @ref tvb_new_subset_length_caplen() but with backing_length and reported_length set to -1.
 *
 * Can throw ReportedBoundsError.
 *
 * @param backing         The backing tvbuff.
 * @param backing_offset  The offset into the backing tvbuff.
 *
 * @return A pointer to the newly created subset tvbuff.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_new_subset_remaining(tvbuff_t *backing,
    const int backing_offset);

/**
 * @brief Append to the list of tvbuffs that make up this composite tvbuff.
 *
 * Can throw BoundsError if member_offset or member_length goes beyond the bounds
 * of the 'member' tvbuff.
 *
 * @param tvb     The composite tvbuff to which a member will be appended.
 * @param member  The tvbuff member to append.
 */
WS_DLL_PUBLIC void tvb_composite_append(tvbuff_t *tvb, tvbuff_t *member);

/**
 * @brief Prepend to the list of tvbuffs that make up this composite tvbuff.
 *
 * Can throw BoundsError if member_offset or member_length goes beyond the bounds
 * of the 'member' tvbuff.
 *
 * @param tvb     The composite tvbuff to which a member will be prepended.
 * @param member  The tvbuff member to prepend.
 */
extern void tvb_composite_prepend(tvbuff_t *tvb, tvbuff_t *member);

/**
 * @brief Create an empty composite tvbuff.
 *
 * @return A pointer to a new, empty composite tvbuff.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_new_composite(void);


/**
 * @brief Mark a composite tvbuff as finalized.
 *
 * After finalization, no further appends or prepends may occur,
 * and data access can finally take place.
 *
 * @param tvb  The composite tvbuff to finalize.
 */
WS_DLL_PUBLIC void tvb_composite_finalize(tvbuff_t *tvb);


/**
 * @brief Get the amount of captured data in the buffer.
 *
 * This is *NOT* necessarily the length of the packet.
 * You probably want to use @ref tvb_reported_length instead.
 *
 * @param tvb  The tvbuff to query.
 *
 * @return The number of bytes of captured data in the tvbuff.
 */
WS_DLL_PUBLIC unsigned tvb_captured_length(const tvbuff_t *tvb);

/**
 * @brief Computes bytes to end of buffer from the given offset.
 *
 * The offset can be negative to indicate bytes from the end of the buffer.
 * The function returns 0 if the offset is either at the end of the buffer or out of bounds.
 * No exception is thrown.
 * You probably want @ref tvb_reported_length_remaining instead.
 *
 * @param tvb    The tvbuff to query.
 * @param offset The offset from which to compute the remaining bytes (can be negative).
 *
 * @return The number of bytes remaining to the end of the buffer from the given offset.
 */
WS_DLL_PUBLIC int tvb_captured_length_remaining(const tvbuff_t *tvb, const int offset);

/**
 * @brief Same as @ref tvb_captured_length_remaining, but throws an exception if the offset is out of bounds.
 *
 * This function verifies that the offset is within the captured data; if not,
 * it throws an exception instead of returning zero.
 *
 * @param tvb    The @ref tvbuff_t to check.
 * @param offset The offset to ensure is within captured data.
 *
 * @return The number of bytes remaining to the end of the buffer from the given offset.
 *
 * @throws Exception if the offset is beyond the captured length.
 */
WS_DLL_PUBLIC unsigned tvb_ensure_captured_length_remaining(const tvbuff_t *tvb,
    const int offset);

/**
 * @brief Check that the specified bytes exist in the tvbuff without throwing an exception.
 *
 * This function verifies whether the byte range starting at `offset` and spanning
 * `length` bytes exists within the given @ref tvb buffer. Unlike some
 * access functions, it does not throw an exception if the range is out of bounds;
 * instead, it returns false.
 *
 * @param tvb     The tvbuff to check.
 * @param offset  The starting offset in the buffer.
 * @param length  The number of bytes to check for existence.
 *
 * @return True if the specified byte range exists within the buffer; false otherwise.
 */
WS_DLL_PUBLIC bool tvb_bytes_exist(const tvbuff_t *tvb, const int offset,
    const int length);

/**
 * @brief Checks that the bytes referred to by 'offset' and 'length' actually exist in the buffer.
 *
 * The 'length' parameter is a 64-bit unsigned integer.
 * Throws an exception if the bytes do not exist.
 *
 * @param tvb    The tvbuff to check.
 * @param offset The starting offset within the tvbuff.
 * @param length The number of bytes to check for existence.
 *
 * @see tvb_ensure_bytes_exist()
 */
WS_DLL_PUBLIC void tvb_ensure_bytes_exist64(const tvbuff_t *tvb,
    const int offset, const uint64_t length);

/**
 * @brief Checks that the bytes referred to by 'offset' and 'length' actually exist in the buffer.
 *
 * Throws an exception if the bytes do not exist.
 *
 * @param tvb    The tvbuff to check.
 * @param offset The starting offset within the tvbuff.
 * @param length The number of bytes to check for existence.
 *
 * @see tvb_ensure_bytes_exist64()
 */
WS_DLL_PUBLIC void tvb_ensure_bytes_exist(const tvbuff_t *tvb,
    const int offset, const int length);

/**
 * @brief Checks (without throwing an exception) whether the offset exists in the buffer.
 *
 * @param tvb    The tvbuff to check.
 * @param offset The offset to verify.
 *
 * @return true if the offset exists within the buffer; false otherwise.
 */
WS_DLL_PUBLIC bool tvb_offset_exists(const tvbuff_t *tvb,
    const int offset);

/**
 * @brief Get reported length of buffer.
 *
 * @param tvb The tvbuff to query.
 *
 * @return The reported length of the buffer.
 */
WS_DLL_PUBLIC unsigned tvb_reported_length(const tvbuff_t *tvb);

/**
 * @brief Computes bytes of reported packet data from the given offset to the end of buffer.
 *
 * The offset can be negative to indicate bytes from the end of the buffer.
 * The function returns 0 if the offset is at the end of the buffer or out of bounds.
 * No exception is thrown.
 *
 * @param tvb    The tvbuff to query.
 * @param offset The offset from which to compute the remaining bytes (can be negative).
 *
 * @return The number of bytes remaining to the end of the buffer from the given offset.
 */
WS_DLL_PUBLIC int tvb_reported_length_remaining(const tvbuff_t *tvb,
    const int offset);

/**
 * @brief Same as @ref tvb_reported_length_remaining but throws an exception if the offset is out of bounds.
 *
 * @param tvb    The tvbuff to query.
 * @param offset The offset from which to compute remaining bytes (can be negative).
 *
 * @return The number of bytes remaining to the end of the buffer from the given offset.
 *
 * @throws ReportedBoundsError if the offset is out of bounds.
 */
WS_DLL_PUBLIC unsigned tvb_ensure_reported_length_remaining(const tvbuff_t *tvb,
    const int offset);

/**
 * @brief Set a tvbuff's reported_length to a given value.
 *
 * Used for protocols whose headers contain an explicit length and where the
 * calling dissector's payload may include padding as well as the packet for
 * this protocol.
 *
 * Also adjusts the available and contained length accordingly.
 *
 * @param tvb             The tvbuff whose reported length is to be set.
 * @param reported_length The new reported length.
 */
WS_DLL_PUBLIC void tvb_set_reported_length(tvbuff_t *tvb, const unsigned reported_length);


/**
 * @brief Repair a tvbuff when captured length exceeds reported length.
 *
 * This function fixes a @ref tvbuff_t where the captured length is greater than
 * the reported length. Such a condition is invalid because it is impossible
 * to capture more data than is actually in the packet.
 *
 * @param tvb The tvbuff to repair.
 */
WS_DLL_PUBLIC void tvb_fix_reported_length(tvbuff_t *tvb);

/**
 * @brief Returns the offset from the beginning of the real (backing) buffer.
 *
 * This function computes the offset of the given @ref tvbuff_t relative to the
 * start of its underlying real data buffer. This is useful for determining how
 * far into the original data a virtual or subset buffer begins.
 *
 * @param tvb The @ref tvbuff_t to query.
 *
 * @return The offset from the beginning of the real buffer.
 */
WS_DLL_PUBLIC unsigned tvb_offset_from_real_beginning(const tvbuff_t *tvb);

/**
 * @brief Returns the offset from the first byte of real data.
 *
 * This function returns the offset within the tvbuff where the actual underlying
 * data begins. This offset is useful when dealing with virtual or chained buffers
 * that reference subsets or views of other buffers.
 *
 * @param tvb The tvbuff to query.
 *
 * @return The offset from the first byte of real data in the buffer.
 */
WS_DLL_PUBLIC int tvb_raw_offset(tvbuff_t *tvb);

/**
 * @brief Set the "this is a fragment" flag on a tvbuff.
 *
 * Setting this flag changes the error handling behavior during buffer bounds checks.
 * Specifically, it causes a @c FragmentBoundsError to be thrown instead of either
 * @c ContainedBoundsError or @c ReportedBoundsError when bounds violations occur.
 *
 * @param tvb The @ref tvbuff_t to mark as a fragment.
 */
WS_DLL_PUBLIC void tvb_set_fragment(tvbuff_t *tvb);

/**
 * @brief Retrieve the data source tvbuff from a given tvbuff.
 *
 * This function returns the underlying @ref tvbuff_t that serves as the data source
 * for the provided buffer. This is typically the original buffer that holds the real data,
 * as opposed to virtual or subset buffers layered on top.
 *
 * @param tvb The @ref tvbuff_t to query.
 *
 * @return The data source @ref tvbuff_t associated with the input buffer.
 */
WS_DLL_PUBLIC struct tvbuff *tvb_get_ds_tvb(tvbuff_t *tvb);


/************** START OF ACCESSORS ****************/
/* All accessors will throw an exception if appropriate */

/**
 * @brief Retrieve an 8-bit unsigned value from a tvbuff at the specified offset.
 *
 * This function reads a single byte from the given @ref tvbuff_t at the specified offset.
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to read the byte.
 *
 * @return The 8-bit unsigned value at the given offset.
 */
WS_DLL_PUBLIC uint8_t tvb_get_uint8(tvbuff_t *tvb, const int offset);

/**
 * @brief Deprecated accessor for an 8-bit unsigned value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_uint8.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to read the byte.
 *
 * @return The 8-bit unsigned value at the given offset.
 *
 * @deprecated Use @ref tvb_get_uint8 instead.
 */
WS_DEPRECATED_X("Use tvb_get_uint8 instead")
static inline uint8_t tvb_get_guint8(tvbuff_t *tvb, const int offset) {
    return tvb_get_uint8(tvb, offset);
}

/**
 * @brief Retrieve an 8-bit signed value from a tvbuff at the specified offset.
 *
 * This function reads a single byte from the given @ref tvbuff_t at the specified offset.
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to read the byte.
 *
 * @return The 8-bit signed value at the given offset.
 */
WS_DLL_PUBLIC int8_t tvb_get_int8(tvbuff_t *tvb, const int offset);

/**
 * @brief Deprecated accessor for an 8-bit signed value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_int8.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to read the byte.
 *
 * @return The 8-bit signed value at the given offset.
 *
 * @deprecated Use @ref tvb_get_int8 instead.
 */
WS_DEPRECATED_X("Use tvb_get_int8 instead")
static inline int8_t tvb_get_gint8(tvbuff_t *tvb, const int offset) { return tvb_get_int8(tvb, offset); }

/**
 * @brief Retrieve a 16-bit unsigned value in network byte order.
 *
 * Reads two bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 16-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 16-bit unsigned value in host byte order.
 *
 * @see tvb_get_ntohis
 */
WS_DLL_PUBLIC uint16_t tvb_get_ntohs(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 16-bit signed value in network byte order.
 *
 * Reads two bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 16-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 16-bit signed value in host byte order.
 *
 * @see tvb_get_ntohs
 */
WS_DLL_PUBLIC int16_t tvb_get_ntohis(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 24-bit unsigned value in network byte order.
 *
 * Reads three bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 24-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 24-bit unsigned value in host byte order.
 *
 * @see tvb_get_ntohi24
 */
WS_DLL_PUBLIC uint32_t tvb_get_ntoh24(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 24-bit signed value in network byte order.
 *
 * Reads three bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 24-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 24-bit signed value in host byte order.
 *
 * @see tvb_get_ntoh24
 */
WS_DLL_PUBLIC int32_t tvb_get_ntohi24(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 32-bit unsigned value in network byte order.
 *
 * Reads four bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 32-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 32-bit unsigned value in host byte order.
 *
 * @see tvb_get_ntohil
 */
WS_DLL_PUBLIC uint32_t tvb_get_ntohl(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 32-bit signed value in network byte order.
 *
 * Reads four bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 32-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 32-bit signed value in host byte order.
 *
 * @see tvb_get_ntohl
 */
WS_DLL_PUBLIC int32_t tvb_get_ntohil(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 40-bit unsigned value in network byte order.
 *
 * Reads five bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 40-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 40-bit unsigned value in host byte order.
 *
 * @see tvb_get_ntohi40
 */
WS_DLL_PUBLIC uint64_t tvb_get_ntoh40(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 40-bit signed value in network byte order.
 *
 * Reads five bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 40-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 40-bit signed value in host byte order.
 *
 * @see tvb_get_ntoh40
 */
WS_DLL_PUBLIC int64_t tvb_get_ntohi40(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 48-bit unsigned value in network byte order.
 *
 * Reads six bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 48-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 48-bit unsigned value in host byte order.
 *
 * @see tvb_get_ntohi48
 */
WS_DLL_PUBLIC uint64_t tvb_get_ntoh48(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 48-bit signed value in network byte order.
 *
 * Reads six bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 48-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 48-bit signed value in host byte order.
 *
 * @see tvb_get_ntoh48
 */
WS_DLL_PUBLIC int64_t tvb_get_ntohi48(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 56-bit unsigned value in network byte order.
 *
 * Reads seven bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 56-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 56-bit unsigned value in host byte order.
 *
 * @see tvb_get_ntohi56
 */
WS_DLL_PUBLIC uint64_t tvb_get_ntoh56(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 56-bit signed value in network byte order.
 *
 * Reads seven bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 56-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 56-bit signed value in host byte order.
 *
 * @see tvb_get_ntoh56
 */
WS_DLL_PUBLIC int64_t tvb_get_ntohi56(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 64-bit unsigned value in network byte order.
 *
 * Reads eight bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 64-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 64-bit unsigned value in host byte order.
 *
 * @see tvb_get_ntohi64
 */
WS_DLL_PUBLIC uint64_t tvb_get_ntoh64(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 64-bit signed value in network byte order.
 *
 * Reads eight bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) 64-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 64-bit signed value in host byte order.
 *
 * @see tvb_get_ntoh64
 */
WS_DLL_PUBLIC int64_t tvb_get_ntohi64(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 32-bit IEEE float in network byte order.
 *
 * Reads four bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) IEEE 754 float,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The IEEE float value in host byte order.
 *
 * @see tvb_get_ntohieee_double
 */
WS_DLL_PUBLIC float tvb_get_ntohieee_float(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 64-bit IEEE double in network byte order.
 *
 * Reads eight bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a big-endian (network byte order) IEEE 754 double,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The IEEE double value in host byte order.
 *
 * @see tvb_get_ntohieee_float
 */
WS_DLL_PUBLIC double tvb_get_ntohieee_double(tvbuff_t *tvb,
    const int offset);

/**
 * @brief Retrieve a 16-bit unsigned value in little-endian byte order.
 *
 * Reads two bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 16-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 16-bit unsigned value in host byte order.
 *
 * @see tvb_get_letohis
 */
WS_DLL_PUBLIC uint16_t tvb_get_letohs(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 16-bit signed value in little-endian byte order.
 *
 * Reads two bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 16-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 16-bit signed value in host byte order.
 *
 * @see tvb_get_letohs
 */
WS_DLL_PUBLIC int16_t tvb_get_letohis(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 24-bit unsigned value in little-endian byte order.
 *
 * Reads three bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 24-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 24-bit unsigned value in host byte order.
 *
 * @see tvb_get_letohi24
 */
WS_DLL_PUBLIC uint32_t tvb_get_letoh24(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 24-bit signed value in little-endian byte order.
 *
 * Reads three bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 24-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 24-bit signed value in host byte order.
 *
 * @see tvb_get_letoh24
 */
WS_DLL_PUBLIC int32_t tvb_get_letohi24(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 32-bit unsigned value in little-endian byte order.
 *
 * Reads four bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 32-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 32-bit unsigned value in host byte order.
 *
 * @see tvb_get_letohil
 */
WS_DLL_PUBLIC uint32_t tvb_get_letohl(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 32-bit signed value in little-endian byte order.
 *
 * Reads four bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 32-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 32-bit signed value in host byte order.
 *
 * @see tvb_get_letohl
 */
WS_DLL_PUBLIC int32_t tvb_get_letohil(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 40-bit unsigned value in little-endian byte order.
 *
 * Reads five bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 40-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 40-bit unsigned value in host byte order.
 *
 * @see tvb_get_letohi40
 */
WS_DLL_PUBLIC uint64_t tvb_get_letoh40(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 40-bit signed value in little-endian byte order.
 *
 * Reads five bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 40-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 40-bit signed value in host byte order.
 *
 * @see tvb_get_letoh40
 */
WS_DLL_PUBLIC int64_t tvb_get_letohi40(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 48-bit unsigned value in little-endian byte order.
 *
 * Reads six bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 48-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 48-bit unsigned value in host byte order.
 *
 * @see tvb_get_letohi48
 */
WS_DLL_PUBLIC uint64_t tvb_get_letoh48(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 48-bit signed value in little-endian byte order.
 *
 * Reads six bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 48-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 48-bit signed value in host byte order.
 *
 * @see tvb_get_letoh48
 */
WS_DLL_PUBLIC int64_t tvb_get_letohi48(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 56-bit unsigned value in little-endian byte order.
 *
 * Reads seven bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 56-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 56-bit unsigned value in host byte order.
 *
 * @see tvb_get_letohi56
 */
WS_DLL_PUBLIC uint64_t tvb_get_letoh56(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 56-bit signed value in little-endian byte order.
 *
 * Reads seven bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 56-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 56-bit signed value in host byte order.
 *
 * @see tvb_get_letoh56
 */
WS_DLL_PUBLIC int64_t tvb_get_letohi56(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 64-bit unsigned value in little-endian byte order.
 *
 * Reads eight bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 64-bit unsigned integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 64-bit unsigned value in host byte order.
 *
 * @see tvb_get_letohi64
 */
WS_DLL_PUBLIC uint64_t tvb_get_letoh64(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 64-bit signed value in little-endian byte order.
 *
 * Reads eight bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian 64-bit signed integer,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 64-bit signed value in host byte order.
 *
 * @see tvb_get_letoh64
 */
WS_DLL_PUBLIC int64_t tvb_get_letohi64(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 32-bit IEEE float in little-endian byte order.
 *
 * Reads four bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian IEEE 754 float,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The IEEE float value in host byte order.
 *
 * @see tvb_get_letohieee_double
 */
WS_DLL_PUBLIC float tvb_get_letohieee_float(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve a 64-bit IEEE double in little-endian byte order.
 *
 * Reads eight bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a little-endian IEEE 754 double,
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The IEEE double value in host byte order.
 *
 * @see tvb_get_letohieee_float
 */
WS_DLL_PUBLIC double tvb_get_letohieee_double(tvbuff_t *tvb,
    const int offset);

/**
 * @brief Retrieve a 16-bit unsigned value from a tvbuff using the specified encoding.
 *
 * Reads two bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them according to the provided encoding (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN),
 * and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 16-bit unsigned value in host byte order.
 */
WS_DLL_PUBLIC uint16_t tvb_get_uint16(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 16-bit unsigned value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_uint16.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 16-bit unsigned value in host byte order.
 *
 * @deprecated Use @ref tvb_get_uint16 instead.
 */
WS_DEPRECATED_X("Use tvb_get_uint16 instead")
static inline uint16_t tvb_get_guint16(tvbuff_t *tvb, const int offset, const unsigned encoding) {
    return tvb_get_uint16(tvb, offset, encoding);
}

/**
 * @brief Retrieve a 16-bit signed value from a tvbuff using the specified encoding.
 *
 * Reads two bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 16-bit signed integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 16-bit signed value in host byte order.
 */
WS_DLL_PUBLIC int16_t tvb_get_int16(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 16-bit signed value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_int16.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 16-bit signed value in host byte order.
 *
 * @deprecated Use @ref tvb_get_int16 instead.
 */
WS_DEPRECATED_X("Use tvb_get_int16 instead")
static inline int16_t tvb_get_gint16(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int16(tvb, offset, encoding); }

/**
 * @brief Retrieve a 24-bit unsigned value from a tvbuff using the specified encoding.
 *
 * Reads three bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 24-bit unsigned integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 24-bit unsigned value in host byte order.
 */
WS_DLL_PUBLIC uint32_t tvb_get_uint24(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 24-bit unsigned value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_uint24.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 24-bit unsigned value in host byte order.
 *
 * @deprecated Use @ref tvb_get_uint24 instead.
 */
WS_DEPRECATED_X("Use tvb_get_uint24 instead")
static inline uint32_t tvb_get_guint24(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_uint24(tvb, offset, encoding); }

/**
 * @brief Retrieve a 24-bit signed value from a tvbuff using the specified encoding.
 *
 * Reads three bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 24-bit signed integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 24-bit signed value in host byte order.
 */
WS_DLL_PUBLIC int32_t tvb_get_int24(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 24-bit signed value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_int24.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 24-bit signed value in host byte order.
 *
 * @deprecated Use @ref tvb_get_int24 instead.
 */
WS_DEPRECATED_X("Use tvb_get_int24 instead")
static inline int32_t tvb_get_gint24(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int24(tvb, offset, encoding); }

/**
 * @brief Retrieve a 32-bit unsigned value from a tvbuff using the specified encoding.
 *
 * Reads four bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 32-bit unsigned integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 32-bit unsigned value in host byte order.
 */
WS_DLL_PUBLIC uint32_t tvb_get_uint32(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 32-bit unsigned value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_uint32.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 32-bit unsigned value in host byte order.
 *
 * @deprecated Use @ref tvb_get_uint32 instead.
 */
WS_DEPRECATED_X("Use tvb_get_uint32 instead")
static inline uint32_t tvb_get_guint32(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_uint32(tvb, offset, encoding); }

/**
 * @brief Retrieve a 32-bit signed value from a tvbuff using the specified encoding.
 *
 * Reads four bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 32-bit signed integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 32-bit signed value in host byte order.
 */
WS_DLL_PUBLIC int32_t tvb_get_int32(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 32-bit signed value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_int32.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 32-bit signed value in host byte order.
 *
 * @deprecated Use @ref tvb_get_int32 instead.
 */
WS_DEPRECATED_X("Use tvb_get_int32 instead")
static inline int32_t tvb_get_gint32(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int32(tvb, offset, encoding); }

/**
 * @brief Retrieve a 40-bit unsigned value from a tvbuff using the specified encoding.
 *
 * Reads five bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 40-bit unsigned integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 40-bit unsigned value in host byte order.
 */
WS_DLL_PUBLIC uint64_t tvb_get_uint40(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 40-bit unsigned value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_uint40.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 40-bit unsigned value in host byte order.
 *
 * @deprecated Use @ref tvb_get_uint40 instead.
 */
WS_DEPRECATED_X("Use tvb_get_uint40 instead")
static inline uint64_t tvb_get_guint40(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_uint40(tvb, offset, encoding); }

/**
 * @brief Retrieve a 40-bit signed value from a tvbuff using the specified encoding.
 *
 * Reads five bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 40-bit signed integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 40-bit signed value in host byte order.
 */
WS_DLL_PUBLIC int64_t tvb_get_int40(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 40-bit signed value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_int40.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 40-bit signed value in host byte order.
 *
 * @deprecated Use @ref tvb_get_int40 instead.
 */
WS_DEPRECATED_X("Use tvb_get_int40 instead")
static inline int64_t tvb_get_gint40(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int40(tvb, offset, encoding); }

/**
 * @brief Retrieve a 48-bit unsigned value from a tvbuff using the specified encoding.
 *
 * Reads six bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 48-bit unsigned integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 48-bit unsigned value in host byte order.
 */
WS_DLL_PUBLIC uint64_t tvb_get_uint48(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 48-bit unsigned value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_uint48.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 48-bit unsigned value in host byte order.
 *
 * @deprecated Use @ref tvb_get_uint48 instead.
 */
WS_DEPRECATED_X("Use tvb_get_uint48 instead")
static inline uint64_t tvb_get_guint48(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_uint48(tvb, offset, encoding); }

/**
 * @brief Retrieve a 48-bit signed value from a tvbuff using the specified encoding.
 *
 * Reads six bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 48-bit signed integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 48-bit signed value in host byte order.
 */
WS_DLL_PUBLIC int64_t tvb_get_int48(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 48-bit signed value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_int48.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 48-bit signed value in host byte order.
 *
 * @deprecated Use @ref tvb_get_int48 instead.
 */
WS_DEPRECATED_X("Use tvb_get_int48 instead")
static inline int64_t tvb_get_gint48(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int48(tvb, offset, encoding); }

/**
 * @brief Retrieve a 56-bit unsigned value from a tvbuff using the specified encoding.
 *
 * Reads seven bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 56-bit unsigned integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 56-bit unsigned value in host byte order.
 */
WS_DLL_PUBLIC uint64_t tvb_get_uint56(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 56-bit unsigned value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_uint56.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 56-bit unsigned value in host byte order.
 *
 * @deprecated Use @ref tvb_get_uint56 instead.
 */
WS_DEPRECATED_X("Use tvb_get_uint56 instead")
static inline uint64_t tvb_get_guint56(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_uint56(tvb, offset, encoding); }

/**
 * @brief Retrieve a 56-bit signed value from a tvbuff using the specified encoding.
 *
 * Reads seven bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 56-bit signed integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 56-bit signed value in host byte order.
 */
WS_DLL_PUBLIC int64_t tvb_get_int56(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 56-bit signed value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_int56.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 56-bit signed value in host byte order.
 *
 * @deprecated Use @ref tvb_get_int56 instead.
 */
WS_DEPRECATED_X("Use tvb_get_int56 instead")
static inline int64_t tvb_get_gint56(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int56(tvb, offset, encoding); }

/**
 * @brief Retrieve a 64-bit unsigned value from a tvbuff using the specified encoding.
 *
 * Reads eight bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 64-bit unsigned integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 64-bit unsigned value in host byte order.
 *
 * @see tvb_get_uint64_with_length
 */
WS_DLL_PUBLIC uint64_t tvb_get_uint64(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Retrieve a variable-length unsigned value (up to 64 bits) from a tvbuff using the specified encoding.
 *
 * Reads up to eight bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a variable-length unsigned integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset or length is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param length    The number of bytes to read (must be between 1 and 8).
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The unsigned value in host byte order.
 *
 * @see tvb_get_uint64
 */
WS_DLL_PUBLIC uint64_t tvb_get_uint64_with_length(tvbuff_t *tvb, const int offset, unsigned length, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 64-bit unsigned value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_uint64.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 64-bit unsigned value in host byte order.
 *
 * @deprecated Use @ref tvb_get_uint64 instead.
 */
WS_DEPRECATED_X("Use tvb_get_uint64 instead")
static inline uint64_t tvb_get_guint64(tvbuff_t *tvb, const int offset, const unsigned encoding) {return tvb_get_uint64(tvb, offset, encoding); }

/**
 * @brief Retrieve a 64-bit signed value from a tvbuff using the specified encoding.
 *
 * Reads eight bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 64-bit signed integer according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 64-bit signed value in host byte order.
 */
WS_DLL_PUBLIC int64_t tvb_get_int64(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Deprecated accessor for a 64-bit signed value from a tvbuff.
 *
 * This function is equivalent to @ref tvb_get_int64.
 * It is deprecated and should not be used in new code.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The 64-bit signed value in host byte order.
 *
 * @deprecated Use @ref tvb_get_int64 instead.
 */
WS_DEPRECATED_X("Use tvb_get_int64 instead")
static inline int64_t tvb_get_gint64(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int64(tvb, offset, encoding); }

/**
 * @brief Retrieve a 32-bit IEEE float from a tvbuff using the specified encoding.
 *
 * Reads four bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 32-bit IEEE 754 floating-point value according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The IEEE float value in host byte order.
 *
 * @see tvb_get_ieee_double
 */
WS_DLL_PUBLIC float tvb_get_ieee_float(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @brief Retrieve a 64-bit IEEE double from a tvbuff using the specified encoding.
 *
 * Reads eight bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a 64-bit IEEE 754 floating-point value according to the provided encoding
 * (e.g., ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN), and returns the value in host byte order.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param encoding  The encoding to use when interpreting the bytes.
 *
 * @return The IEEE double value in host byte order.
 *
 * @see tvb_get_ieee_float
 */
WS_DLL_PUBLIC double tvb_get_ieee_double(tvbuff_t *tvb, const int offset, const unsigned encoding);

/**
 * @def tvb_get_h_uint16
 * @brief Fetch a 16-bit value in host byte order.
 *
 * This macro is used for pseudo-headers in pcap/pcapng files, which are stored in the
 * byte order of the capturing host and must be interpreted in the byte
 * order of the reading host.
 */

/**
 * @def tvb_get_h_uint32
 * @brief Fetch a 32-bit value in host byte order.
 *
 * This macro is used for pseudo-headers in pcap/pcapng files, which are stored in the
 * byte order of the capturing host and must be interpreted in the byte
 * order of the reading host.
 */
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
#define tvb_get_h_uint16  tvb_get_letohs
#define tvb_get_h_uint32  tvb_get_letohl
#elif G_BYTE_ORDER == G_BIG_ENDIAN
#define tvb_get_h_uint16  tvb_get_ntohs
#define tvb_get_h_uint32  tvb_get_ntohl
#else
#error "Unsupported byte order"
#endif

/**
 * @brief Fetch a time value from an ASCII-style string in the tvbuff.
 *
 * @param[in] offset The beginning offset in the tvb (cannot be negative)
 * @param[in] length The field's length in the tvb (or -1 for remaining)
 * @param[in] encoding The ENC_* that defines the format (e.g., ENC_ISO_8601_DATE_TIME)
 * @param[in,out] ns The pre-allocated nstime_t that will be set to the decoded value
 * @param[out] endoff if not NULL, should point to a int that this
 *     routine will then set to be the offset to the character after
 *     the last character used in the conversion. This is useful because
 *     they may not consume the whole section.
 *
 * @return a pointer to the nstime_t passed-in, or NULL on failure; if no
 *    valid conversion could be performed, *endoff is set to 0,  and the
 *    nstime_t* passed-in will be cleared.
 *
 * @note The conversion ignores leading spaces, and will succeed even if it does
 *    not consume the entire string. If you care about such things, always compare
 *    the *endoff to where you expect it to be (namely, offset+length).
 *
 * This routine will not throw an error unless the passed-in arguments are
 * invalid (e.g., offset is beyond the tvb's length).
 *
 * @warning This only works for string encodings which encode ASCII characters in
 * a single byte: ENC_ASCII, ENC_UTF_8, ENC_ISO_8859_*, etc. It does NOT work
 * for purely multi-byte encodings such as ENC_UTF_16, ENC_UCS_*, etc.
 */
WS_DLL_PUBLIC
nstime_t* tvb_get_string_time(tvbuff_t *tvb, const int offset, const int length,
                              const unsigned encoding, nstime_t* ns, int *endoff);

/**
 * @brief Parse a case-insensitive hex string with optional separators into a byte array.
 *
 * Converts a string from the given @ref tvbuff_t into binary data, interpreting it
 * as a sequence of hexadecimal characters. Leading spaces are ignored. Optional
 * separators are allowed based on the ENC_SEP_* flags in the encoding parameter.
 *
 * The caller must pre-allocate the @ref GByteArray using `g_byte_array_new()`.
 * The parsed bytes are appended to this array. The return value is the same pointer,
 * or NULL on error.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The beginning offset in the tvbuff (must be non-negative).
 * @param length    The length of the field to parse, or -1 to use the remaining buffer.
 * @param encoding  The ENC_* constant defining the format and separator rules.
 * @param bytes     A pre-allocated @ref GByteArray to receive the parsed bytes.
 * @param endoff    If not NULL, will be set to the offset of the character immediately
 *                  following the last one used in the conversion.
 *
 * @return The same @ref GByteArray pointer passed in, or NULL on failure.
 */
WS_DLL_PUBLIC
GByteArray* tvb_get_string_bytes(tvbuff_t *tvb, const int offset, const int length,
                                 const unsigned encoding, GByteArray* bytes, int *endoff);

/**
 * @brief Retrieve an IPv4 address from a tvbuff in network byte order.
 *
 * Reads four bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as an IPv4 address in network byte order, and returns
 * the raw 32-bit value without converting to host byte order.
 *
 * This function does not perform any byte order conversion, as callers
 * are expected to handle the value in network format.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 *
 * @return The 32-bit IPv4 address in network byte order.
 */
WS_DLL_PUBLIC uint32_t tvb_get_ipv4(tvbuff_t *tvb, const int offset);

/**
 * @brief Retrieve an IPv6 address from a tvbuff.
 *
 * Reads sixteen bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as an IPv6 address in network byte order, and stores the result
 * in the caller-provided @ref ws_in6_addr structure.
 *
 * This function does not perform any byte order conversion, as IPv6 addresses
 * are typically handled in network format.
 *
 * If the offset is out of bounds, or another error occurs, an exception will be thrown.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 * @param addr    A pointer to a @ref ws_in6_addr structure to receive the IPv6 address.
 */
WS_DLL_PUBLIC void tvb_get_ipv6(tvbuff_t *tvb, const int offset, ws_in6_addr *addr);

/**
 * @brief Fetch an IPv4 address from a tvbuff and mask out bits not covered by a prefix length.
 *
 * Fetches an IPv4 address from a tvbuff and
 * masks out bits other than those covered by a prefix length
 *
 * @param tvb tvbuff to read an IPv4 address from
 * @param offset offset in the tvbuff to read the IPv4 address from
 * @param addr memory location where the IPv4 address read should be stored
 * @param prefix_len the length of the prefix (in bits)
 * @return the length (in bytes) of the address on success, or -1 on failure
 */
extern int tvb_get_ipv4_addr_with_prefix_len(tvbuff_t *tvb, int offset,
    ws_in4_addr *addr, uint32_t prefix_len);

/**
 * @brief Fetch an IPv6 address from a tvbuff and mask out bits not covered by a prefix length.
 *
 * Reads an IPv6 address from the given tvbuff starting at the specified offset,
 * then applies a mask to zero out bits outside the specified prefix length.
 *
 * @param tvb         The tvbuff to read an IPv6 address from.
 * @param offset      The offset in the tvbuff to read the IPv6 address from.
 * @param addr        Memory location where the fetched IPv6 address should be stored.
 * @param prefix_len  The length of the prefix (in bits).
 *
 * @return The length (in bytes) of the address on success, or -1 on failure.
 */
extern int tvb_get_ipv6_addr_with_prefix_len(tvbuff_t *tvb, int offset,
    ws_in6_addr *addr, uint32_t prefix_len);

/**
 * @brief Retrieve a GUID from a tvbuff in network byte order.
 *
 * Reads 16 bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a GUID in network byte order, and stores the result
 * in the caller-provided @ref e_guid_t structure.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 * @param guid    A pointer to an @ref e_guid_t structure to receive the GUID.
 */
WS_DLL_PUBLIC void tvb_get_ntohguid(tvbuff_t *tvb, const int offset, e_guid_t *guid);

/**
 * @brief Retrieve a GUID from a tvbuff in little-endian byte order.
 *
 * Reads 16 bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a GUID in little-endian byte order, and stores the result
 * in the caller-provided @ref e_guid_t structure.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset within the buffer to begin reading.
 * @param guid    A pointer to an @ref e_guid_t structure to receive the GUID.
 */
WS_DLL_PUBLIC void tvb_get_letohguid(tvbuff_t *tvb, const int offset, e_guid_t *guid);

/**
 * @brief Retrieve a GUID from a tvbuff using the specified encoding.
 *
 * Reads 16 bytes from the given @ref tvbuff_t at the specified offset,
 * interprets them as a GUID according to the provided encoding
 * (e.g., ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN), and stores the result
 * in the caller-provided @ref e_guid_t structure.
 *
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset within the buffer to begin reading.
 * @param guid      A pointer to an @ref e_guid_t structure to receive the GUID.
 * @param encoding  The encoding to use when interpreting the GUID bytes.
 */
WS_DLL_PUBLIC void tvb_get_guid(tvbuff_t *tvb, const int offset, e_guid_t *guid, const unsigned encoding);

/**
 * @brief Retrieve a byte array from a tvbuff using a bit-level offset and encoding.
 *
 * Extracts a sequence of bits from the given @ref tvbuff_t starting at the specified
 * bit offset, interprets them according to the provided encoding, and returns the
 * result as a newly allocated byte array.
 *
 * The caller must provide a @ref wmem_allocator_t scope for memory allocation.
 * The number of bytes written is returned via `data_length`.
 *
 * @param scope        The @ref wmem_allocator_t to use for allocating the result.
 * @param tvb          The @ref tvbuff_t to read from.
 * @param offset       The bit offset within the buffer to begin reading.
 * @param length       The number of bits to extract.
 * @param data_length  Pointer to a size_t that will be set to the number of bytes returned.
 * @param encoding     The ENC_* constant defining bit order and alignment.
 *
 * @return A pointer to the allocated byte array, or NULL on failure.
 */
WS_DLL_PUBLIC uint8_t* tvb_get_bits_array(wmem_allocator_t *scope, tvbuff_t *tvb,
    const int offset, size_t length, size_t *data_length, const unsigned encoding);

/**
 * @brief Retrieve 1–8 bits from a tvbuff and return them as a uint8_t.
 *
 * Extracts a sequence of bits starting at the specified bit offset in the given
 * @ref tvbuff_t. The bits are returned as an unsigned 8-bit value.
 *
 * Note that bit offsets 0–7 refer to bits within octet 0 of the buffer.
 * This function does not use the encoding parameter.
 *
 * @param tvb          The @ref tvbuff_t to read from.
 * @param bit_offset   The bit offset within the buffer to begin reading.
 * @param no_of_bits   The number of bits to extract (must be between 1 and 8).
 *
 * @return The extracted bits as a uint8_t.
 *
 * @see tvb_get_bits16
 * @see tvb_get_bits32
 * @see tvb_get_bits64
 */
WS_DLL_PUBLIC uint8_t tvb_get_bits8(tvbuff_t *tvb, unsigned bit_offset,
    const int no_of_bits);

/**
 * @brief Retrieve 1–16 bits from a tvbuff and return them as a uint16_t.
 *
 * Extracts a sequence of bits starting at the specified bit offset in the given
 * @ref tvbuff_t. The bits are interpreted according to the specified encoding
 * (which defines bit ordering within each octet) and returned as an unsigned 16-bit value.
 *
 * Note that bit offsets 0–7 refer to bits within octet 0 of the buffer.
 * Versions of Wireshark prior to 3.6 ignored the encoding parameter.
 *
 * @param tvb          The @ref tvbuff_t to read from.
 * @param bit_offset   The bit offset within the buffer to begin reading.
 * @param no_of_bits   The number of bits to extract (must be between 1 and 16).
 * @param encoding     The ENC_* constant defining bit ordering.
 *
 * @return The extracted bits as a uint16_t.
 *
 * @see tvb_get_bits8
 * @see tvb_get_bits32
 * @see tvb_get_bits64
 */
WS_DLL_PUBLIC uint16_t tvb_get_bits16(tvbuff_t *tvb, unsigned bit_offset,
    const int no_of_bits, const unsigned encoding);

/**
 * @brief Retrieve 1–32 bits from a tvbuff and return them as a uint32_t.
 *
 * Extracts a sequence of bits starting at the specified bit offset in the given
 * @ref tvbuff_t. The bits are interpreted according to the specified encoding
 * (which defines bit ordering within each octet) and returned as an unsigned 32-bit value.
 *
 * Note that bit offsets 0–7 refer to bits within octet 0 of the buffer.
 * Versions of Wireshark prior to 3.6 ignored the encoding parameter.
 *
 * @param tvb          The @ref tvbuff_t to read from.
 * @param bit_offset   The bit offset within the buffer to begin reading.
 * @param no_of_bits   The number of bits to extract (must be between 1 and 32).
 * @param encoding     The ENC_* constant defining bit ordering.
 *
 * @return The extracted bits as a uint32_t.
 *
 * @see tvb_get_bits8
 * @see tvb_get_bits16
 * @see tvb_get_bits64
 */
WS_DLL_PUBLIC uint32_t tvb_get_bits32(tvbuff_t *tvb, unsigned bit_offset,
    const int no_of_bits, const unsigned encoding);

/**
 * @brief Retrieve 1–64 bits from a tvbuff and return them as a uint64_t.
 *
 * Extracts a sequence of bits starting at the specified bit offset in the given
 * @ref tvbuff_t. The bits are interpreted according to the specified encoding
 * (which defines bit ordering within each octet) and returned as an unsigned 64-bit value.
 *
 * Note that bit offsets 0–7 refer to bits within octet 0 of the buffer.
 * Versions of Wireshark prior to 3.6 ignored the encoding parameter.
 *
 * @param tvb          The @ref tvbuff_t to read from.
 * @param bit_offset   The bit offset within the buffer to begin reading.
 * @param no_of_bits   The number of bits to extract (must be between 1 and 64).
 * @param encoding     The ENC_* constant defining bit ordering.
 *
 * @return The extracted bits as a uint64_t.
 *
 * @see tvb_get_bits8
 * @see tvb_get_bits16
 * @see tvb_get_bits32
 */
WS_DLL_PUBLIC uint64_t tvb_get_bits64(tvbuff_t *tvb, unsigned bit_offset,
    const int no_of_bits, const unsigned encoding);

/**
 * @brief Deprecated accessor for extracting bits from a tvbuff.
 *
 * This function extracts 1–32 bits starting at the specified bit offset and returns
 * them as a uint32_t, using the specified encoding to determine bit ordering.
 *
 * @param tvb          The @ref tvbuff_t to read from.
 * @param bit_offset   The bit offset within the buffer to begin reading.
 * @param no_of_bits   The number of bits to extract (must be between 1 and 32).
 * @param encoding     The ENC_* constant defining bit ordering.
 *
 * @return The extracted bits as a uint32_t.
 *
 * @deprecated Use @ref tvb_get_bits32 instead.
 *
 * @see tvb_get_bits32
 */
WS_DLL_PUBLIC
WS_DEPRECATED_X("Use tvb_get_bits32() instead")
uint32_t tvb_get_bits(tvbuff_t *tvb, const unsigned bit_offset,
    const int no_of_bits, const unsigned encoding);

/**
 * @brief Copy a range of bytes from a tvbuff into a pre-allocated target buffer.
 *
 * Copies `length` bytes from the given @ref tvbuff_t starting at the specified offset
 * into the caller-provided `target` buffer. Unlike @ref tvb_get_ptr, this function
 * handles fragmented tvbuffs intelligently and performs chunked copying when needed.
 *
 * The target buffer must be pre-allocated by the caller. This function does not
 * allocate or free memory.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param target  A pointer to the destination buffer to copy into.
 * @param offset  The offset within the buffer to begin copying.
 * @param length  The number of bytes to copy.
 *
 * @return The same `target` pointer passed in, for convenience.
 *
 * @see tvb_get_ptr
 */
WS_DLL_PUBLIC void *tvb_memcpy(tvbuff_t *tvb, void *target, const int offset,
    size_t length);

/**
 * @brief Duplicate a block of data from a tvbuff into a newly allocated buffer.
 *
 * Allocates a buffer using the provided @ref wmem_allocator_t scope,
 * copies `length` bytes from the given @ref tvbuff_t starting at `offset`
 * into that buffer using @ref tvb_memcpy, and returns a pointer to the new buffer.
 *
 * Throws an exception if the tvbuff is too short for the requested range.
 *
 * If `scope` is NULL, it is the caller’s responsibility to free the allocated memory
 * using @c wmem_free(). Otherwise, the allocated memory is automatically freed
 * when the allocator's lifetime ends.
 *
 * @param scope   The memory allocator scope for buffer allocation, or NULL.
 * @param tvb     The @ref tvbuff_t to read data from.
 * @param offset  The byte offset within the tvbuff to start copying.
 * @param length  The number of bytes to copy.
 *
 * @return Pointer to the newly allocated buffer containing the copied data.
 */
WS_DLL_PUBLIC void *tvb_memdup(wmem_allocator_t *scope, tvbuff_t *tvb,
    const int offset, size_t length);

/**
 * @brief Returns a raw pointer to tvbuff data. Use with extreme caution.
 *
 * WARNING! This function is possibly expensive, temporarily allocating
 * another copy of the packet data. Furthermore, it's dangerous because once
 * this pointer is given to the user, there's no guarantee that the user will
 * honor the 'length' and not overstep the boundaries of the buffer.
 *
 * If you're thinking of using tvb_get_ptr, STOP WHAT YOU ARE DOING
 * IMMEDIATELY. Go take a break. Consider that tvb_get_ptr hands you
 * a raw, unprotected pointer that you can easily use to create a
 * security vulnerability or otherwise crash Wireshark. Then consider
 * that you can probably find a function elsewhere in this file that
 * does exactly what you want in a much more safe and robust manner.
 *
 * The returned pointer is data that is internal to the tvbuff, so do not
 * attempt to free it. Don't modify the data, either, because another tvbuff
 * that might be using this tvbuff may have already copied that portion of
 * the data (sometimes tvbuff's need to make copies of data, but that's the
 * internal implementation that you need not worry about). Assume that the
 * uint8_t* points to read-only data that the tvbuff manages.
 *
 * Return a pointer into our buffer if the data asked for via 'offset'/'length'
 * is contiguous (which might not be the case for a "composite" tvbuff). If the
 * data is not contiguous, a tvb_memdup() is called for the entire buffer
 * and the pointer to the newly-contiguous data is returned. This dynamically-
 * allocated memory will be freed when the tvbuff is freed, after the
 * tvbuff_free_cb_t() is called, if any.
 *
 * @param tvb     The tvbuff to read from.
 * @param offset  The starting offset in the tvbuff.
 * @param length  The number of bytes requested.
 *
 * @return A pointer to the data, or a newly allocated contiguous copy.
 */
WS_DLL_PUBLIC const uint8_t *tvb_get_ptr(tvbuff_t *tvb, const int offset,
    const int length);

/**
 * @brief Find the first occurrence of a byte value in a tvbuff.
 *
 * Searches for the first occurrence of `needle` in the given @ref tvbuff_t,
 * starting at `offset` and scanning up to `maxlength` bytes. If `maxlength` is -1,
 * the search continues to the end of the tvbuff.
 *
 * This function does not throw an exception, even if `maxlength` exceeds the
 * tvbuff boundary. In such cases, -1 is returned if the boundary is reached
 * before finding the needle.
 *
 * @param tvb         The @ref tvbuff_t to search.
 * @param offset      The offset in the tvbuff to begin searching.
 * @param maxlength   The maximum number of bytes to search, or -1 to search to the end.
 * @param needle      The byte value to search for.
 *
 * @return The offset of the found needle, or -1 if not found.
 */
WS_DLL_PUBLIC int tvb_find_uint8(tvbuff_t *tvb, const int offset,
    const int maxlength, const uint8_t needle);

/**
 * @brief Deprecated accessor for finding a byte value in a tvbuff.
 *
 * This function is equivalent to @ref tvb_find_uint8 and should not be used in new code.
 * It searches for the first occurrence of `needle` starting at `offset`, scanning up to
 * `maxlength` bytes. If `maxlength` is -1, the search continues to the end of the tvbuff.
 *
 * This function does not throw exceptions, even if `maxlength` exceeds the tvbuff boundary.
 * In such cases, -1 is returned if the boundary is reached before finding the needle.
 *
 * @param tvb         The @ref tvbuff_t to search.
 * @param offset      The offset in the tvbuff to begin searching.
 * @param maxlength   The maximum number of bytes to search, or -1 to search to the end.
 * @param needle      The byte value to search for.
 *
 * @return The offset of the found needle, or -1 if not found.
 *
 * @deprecated Use @ref tvb_find_uint8 instead.
 *
 * @see tvb_find_uint8
 */
WS_DEPRECATED_X("Use tvb_find_uint8 instead")
static inline int tvb_find_guint8(tvbuff_t* tvb, const int offset,
	const int maxlength, const uint8_t needle) { return tvb_find_uint8(tvb, offset, maxlength, needle); }

/**
 * @brief Find the first occurrence of a 16-bit value in a tvbuff.
 *
 * Searches for the first occurrence of the 16-bit `needle` in the given @ref tvbuff_t,
 * starting at `offset` and scanning up to `maxlength` bytes. If `maxlength` is -1,
 * the search continues to the end of the tvbuff.
 *
 * This function does not throw an exception, even if `maxlength` exceeds the
 * tvbuff boundary. In such cases, -1 is returned if the boundary is reached
 * before finding the needle.
 *
 * @param tvb         The @ref tvbuff_t to search.
 * @param offset      The offset in the tvbuff to begin searching.
 * @param maxlength   The maximum number of bytes to search, or -1 to search to the end.
 * @param needle      The 16-bit value to search for.
 *
 * @return The offset of the found needle, or -1 if not found.
 *
 * @see tvb_find_uint8
 */
WS_DLL_PUBLIC int tvb_find_uint16(tvbuff_t *tvb, const int offset,
    const int maxlength, const uint16_t needle);

/**
 * @brief Deprecated accessor for finding a 16-bit value in a tvbuff.
 *
 * This function is equivalent to @ref tvb_find_uint16 and should not be used in new code.
 * It searches for the first occurrence of `needle` starting at `offset`, scanning up to
 * `maxlength` bytes. If `maxlength` is -1, the search continues to the end of the tvbuff.
 *
 * This function does not throw exceptions, even if `maxlength` exceeds the tvbuff boundary.
 * In such cases, -1 is returned if the boundary is reached before finding the needle.
 *
 * @param tvb         The @ref tvbuff_t to search.
 * @param offset      The offset in the tvbuff to begin searching.
 * @param maxlength   The maximum number of bytes to search, or -1 to search to the end.
 * @param needle      The 16-bit value to search for.
 *
 * @return The offset of the found needle, or -1 if not found.
 *
 * @deprecated Use @ref tvb_find_uint16 instead.
 *
 * @see tvb_find_uint16
 */
WS_DEPRECATED_X("Use tvb_find_uint16 instead")
static inline int tvb_find_guint16(tvbuff_t* tvb, const int offset,
	const int maxlength, const uint16_t needle) {
	return tvb_find_uint16(tvb, offset, maxlength, needle);
}

/**
 * @brief Find the first occurrence of any needle from a pre-compiled pattern in a tvbuff.
 *
 * Searches the given @ref tvbuff_t starting at `offset` for any of the bytes defined in the
 * pre-compiled `pattern` (compiled using `ws_mempbrk_compile()`).
 * The search scans at most `maxlength` bytes.
 *
 * This function will not throw an exception, even if `maxlength` exceeds the tvbuff boundary.
 * In such cases, -1 is returned if the boundary is reached before finding any needle.
 *
 * @param tvb          The @ref tvbuff_t to search.
 * @param offset       The offset within the tvbuff to begin searching.
 * @param maxlength    The maximum number of bytes to search.
 * @param pattern      The pre-compiled pattern of needles to search for.
 * @param found_needle Pointer to an unsigned char that will be set to the found needle value.
 *
 * @return The offset of the found needle, or -1 if no needle was found.
 */
WS_DLL_PUBLIC int tvb_ws_mempbrk_pattern_uint8(tvbuff_t *tvb, const int offset,
    const int maxlength, const ws_mempbrk_pattern* pattern, unsigned char *found_needle);

/**
 * @brief Deprecated accessor for finding the first occurrence of any needle from a pre-compiled pattern in a tvbuff.
 *
 * This function is equivalent to @ref tvb_ws_mempbrk_pattern_uint8 and should not be used in new code.
 * It searches for the first occurrence of any byte from the pre-compiled `pattern` in the given
 * @ref tvbuff_t, starting at `offset` and scanning up to `maxlength` bytes.
 *
 * If `maxlength` is -1, the search continues to the end of the tvbuff.
 * The found byte is returned via `found_needle`, and the offset of the match is returned.
 * If no match is found, -1 is returned and `*found_needle` is not modified.
 *
 * This function does not throw exceptions, even if `maxlength` exceeds the tvbuff boundary.
 *
 * @param tvb            The @ref tvbuff_t to search.
 * @param offset         The offset within the tvbuff to begin searching.
 * @param maxlength      The maximum number of bytes to search.
 * @param pattern        The pre-compiled pattern of needles to search for.
 * @param found_needle   Pointer to an unsigned char that will be set to the found needle value.
 *
 * @return The offset of the found needle, or -1 if not found.
 *
 * @deprecated Use @ref tvb_ws_mempbrk_pattern_uint8 instead.
 *
 * @see tvb_ws_mempbrk_pattern_uint8
 */
WS_DEPRECATED_X("Use tvb_ws_mempbrk_pattern_uint8 instead")
static inline int tvb_ws_mempbrk_pattern_guint8(tvbuff_t* tvb, const int offset,
	const int maxlength, const ws_mempbrk_pattern* pattern, unsigned char* found_needle) {
	return tvb_ws_mempbrk_pattern_uint8(tvb, offset, maxlength, pattern, found_needle);
}

/**
 * @brief Determine the size of a NUL-terminated string in a tvbuff.
 *
 * Finds the size of a stringz (NUL-terminated string) by searching for the
 * terminating NUL byte starting at the given offset. The returned size includes
 * the terminating NUL.
 *
 * If the NUL is not found, this function throws the appropriate exception.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset in the tvbuff to begin searching.
 *
 * @return The size of the string, including the terminating NUL.
 */
WS_DLL_PUBLIC unsigned tvb_strsize(tvbuff_t *tvb, const int offset);

/**
 * @brief Determine the size of a UCS-2 or UTF-16 NUL-terminated string in a tvbuff.
 *
 * Finds the size of a stringz (NUL-terminated string) encoded in UCS-2 or UTF-16
 * by searching for the terminating 16-bit NUL starting at the given offset.
 * The returned size includes the terminating NUL.
 *
 * If the terminating NUL is not found, this function throws the appropriate exception.
 *
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset in the tvbuff to begin searching.
 *
 * @return The size of the string, including the terminating 16-bit NUL.
 */
WS_DLL_PUBLIC unsigned tvb_unicode_strsize(tvbuff_t *tvb, const int offset);

/**
 * @brief Find the length of a NUL-terminated string in a tvbuff, up to a maximum limit.
 *
 * Searches for the end of a zero-terminated string starting at the given offset,
 * scanning up to `maxlength` characters. If `maxlength` is -1, the search continues
 * to the end of the tvbuff.
 *
 * Returns -1 if the end of string (EOS) is not found within the specified range.
 *
 * @param tvb         The @ref tvbuff_t to read from.
 * @param offset      The offset in the tvbuff to begin searching.
 * @param maxlength   The maximum number of characters to search, or -1 to search to the end.
 *
 * @return The length of the string (excluding the NUL), or -1 if EOS is not found.
 */
WS_DLL_PUBLIC int tvb_strnlen(tvbuff_t *tvb, const int offset,
    const unsigned maxlength);

/**
 * @brief Format a block of tvbuff data as printable text.
 *
 * Converts `size` bytes of data from the given @ref tvbuff_t starting at `offset`
 * into a printable string representation. Non-printable characters are escaped
 * or replaced as needed for safe display.
 *
 * The returned string is allocated using the provided @ref wmem_allocator_t scope.
 *
 * @param scope   The memory allocator scope for the formatted string.
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset in the tvbuff to begin formatting.
 * @param size    The number of bytes to format.
 *
 * @return A pointer to the formatted string.
 */
WS_DLL_PUBLIC char *tvb_format_text(wmem_allocator_t *scope, tvbuff_t *tvb, const int offset,
    const int size);

/**
 * @brief Format tvbuff data as printable text, omitting C-style escapes.
 *
 * Similar to @ref tvb_format_text, but tailored for whitespace-preserving contexts.
 * Characters are shown as-is without escaping non-printables using C-style sequences.
 *
 * The returned string is allocated using the provided @ref wmem_allocator_t scope.
 *
 * @param allocator  The memory allocator scope for the formatted string.
 * @param tvb        The @ref tvbuff_t to read from.
 * @param offset     The offset in the tvbuff to begin formatting.
 * @param size       The number of bytes to format.
 *
 * @return A pointer to the formatted string.
 *
 * @see tvb_format_text
 */
WS_DLL_PUBLIC char *tvb_format_text_wsp(wmem_allocator_t* allocator, tvbuff_t *tvb, const int offset,
    const int size);

/**
 * @brief Format a null-padded string from a tvbuff as printable text.
 *
 * Similar to @ref tvb_format_text, but tailored for null-padded strings.
 * Null padding characters are not shown as C-style escapes (e.g., "\000").
 *
 * The returned string is allocated using the provided @ref wmem_allocator_t scope.
 *
 * @param scope   The memory allocator scope for the formatted string.
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset in the tvbuff to begin formatting.
 * @param size    The number of bytes to format.
 *
 * @return A pointer to the formatted string.
 *
 * @see tvb_format_text
 */
extern char *tvb_format_stringzpad(wmem_allocator_t *scope, tvbuff_t *tvb, const int offset,
    const int size);

/**
 * @brief Format a null-padded string from a tvbuff as printable text, preserving whitespace.
 *
 * Similar to @ref tvb_format_text_wsp, but tailored for null-padded strings.
 * Null padding characters are not shown as C-style escapes (e.g., "\000").
 *
 * The returned string is allocated using the provided @ref wmem_allocator_t scope.
 *
 * @param allocator  The memory allocator scope for the formatted string.
 * @param tvb        The @ref tvbuff_t to read from.
 * @param offset     The offset in the tvbuff to begin formatting.
 * @param size       The number of bytes to format.
 *
 * @return A pointer to the formatted string.
 *
 * @see tvb_format_text_wsp
 * @see tvb_format_stringzpad
 */
extern char *tvb_format_stringzpad_wsp(wmem_allocator_t* allocator, tvbuff_t *tvb, const int offset,
    const int size);

/**
 * @brief Extract and convert a string from a tvbuff to UTF-8 using the specified encoding.
 *
 * Given an allocator scope, a tvbuff, a byte offset, a byte length, and a string encoding,
 * this function allocates a buffer using the specified scope, converts the string from the
 * specified encoding to UTF-8 (mapping invalid sequences to the Unicode REPLACEMENT CHARACTER),
 * appends a trailing '\0', and returns a pointer to the resulting buffer.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * If `scope` is NULL, the caller is responsible for freeing the memory using @c wmem_free().
 * Otherwise, the memory is automatically freed when the scope lifetime ends.
 *
 * @param scope     The memory allocator scope for the result, or NULL.
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The offset in the tvbuff where the string begins.
 * @param length    The length in bytes of the string to convert.
 * @param encoding  The ENC_* constant specifying the string's encoding.
 *
 * @return A pointer to the UTF-8 encoded string, including a trailing NUL.
 */
WS_DLL_PUBLIC uint8_t *tvb_get_string_enc(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, const int length, const unsigned encoding);

/**
 * @brief Extract and convert a 3GPP TS 23.038 7-bit packed string from a tvbuff to UTF-8.
 *
 * Given an allocator scope, a tvbuff, a bit offset, and a length in 7-bit characters
 * (not octets), this function:
 *
 * - Allocates a buffer using the specified scope.
 * - Converts the string from the 3GPP TS 23.038 7-bit packed encoding to UTF-8,
 *   mapping invalid sequences or characters to the Unicode REPLACEMENT CHARACTER.
 * - Stores the resulting UTF-8 string, including a trailing null terminator, into that buffer.
 *
 * Throws an exception if the tvbuff ends before the entire string is read.
 *
 * If `scope` is NULL, the caller is responsible for freeing the allocated memory using `wmem_free()`.
 * Otherwise, the memory is automatically freed when the scope lifetime ends.
 *
 * @param scope        The memory allocator scope for the returned string, or NULL.
 * @param tvb          The @ref tvbuff_t to read from.
 * @param bit_offset   The bit offset within the tvbuff where the string begins.
 * @param no_of_chars  The number of 7-bit characters to decode.
 *
 * @return A pointer to the UTF-8 encoded string with a trailing '\0'.
 */
WS_DLL_PUBLIC char *tvb_get_ts_23_038_7bits_string_packed(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int bit_offset, int no_of_chars);

/**
 * @brief Extract and convert a 3GPP TS 23.038 7-bit unpacked string from a tvbuff to UTF-8.
 *
 * Given an allocator scope, a tvbuff, an offset, and a length in octets, this function:
 *
 * - Allocates a buffer using the specified scope.
 * - Converts the string from the 3GPP TS 23.038 7-bit encoding (one octet per code point,
 *   with the 8th bit expected to be 0) to UTF-8.
 * - Maps invalid octets or characters to the Unicode REPLACEMENT CHARACTER.
 * - Appends a trailing '\0' and returns a pointer to the resulting buffer.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * If `scope` is NULL, the caller is responsible for freeing the allocated memory using `wmem_free()`.
 * Otherwise, the memory is automatically freed when the scope lifetime ends.
 *
 * @param scope    The memory allocator scope for the returned string, or NULL.
 * @param tvb      The @ref tvbuff_t to read from.
 * @param offset   The byte offset within the tvbuff where the string begins.
 * @param length   The number of octets to decode.
 *
 * @return A pointer to the UTF-8 encoded string with a trailing '\0'.
 */
WS_DLL_PUBLIC char *tvb_get_ts_23_038_7bits_string_unpacked(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, int length);

/**
 * @brief Extract and convert a string encoded per ETSI TS 102 221 Annex A from a tvbuff to UTF-8.
 *
 * Given an allocator scope, a tvbuff, an offset, and a length in octets, this function:
 *
 * - Allocates a buffer using the specified scope.
 * - Converts the string from the ETSI TS 102 221 Annex A encoding to UTF-8,
 *   mapping some characters or invalid octet sequences to the Unicode REPLACEMENT CHARACTER.
 * - Appends a trailing '\0' to the resulting UTF-8 string.
 * - Returns a pointer to the allocated buffer containing the converted string.
 *
 * Throws an exception if the tvbuff ends before the full string is read.
 *
 * If `scope` is NULL, it is the caller’s responsibility to free the allocated memory using `wmem_free()`.
 * Otherwise, the memory is automatically freed when the scope lifetime ends.
 *
 * @param scope    The memory allocator scope for the result, or NULL.
 * @param tvb      The @ref tvbuff_t to read from.
 * @param offset   The byte offset within the tvbuff where the string begins.
 * @param length   The length in octets of the string to convert.
 *
 * @return A pointer to the UTF-8 encoded string including the trailing NUL.
 */
WS_DLL_PUBLIC char *tvb_get_etsi_ts_102_221_annex_a_string(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, int length);

/**
 * @brief Extract and convert an ASCII 7-bit encoded string from a tvbuff to UTF-8.
 *
 * Given an allocator scope, a tvbuff, a bit offset, and a length in 7-bit characters
 * (not octets), this function:
 *
 * - Allocates a buffer using the specified scope.
 * - Converts the string from the ASCII 7-bit encoding to UTF-8,
 *   mapping invalid characters or octet sequences to the Unicode REPLACEMENT CHARACTER.
 * - Appends a trailing null terminator ('\0') to the resulting UTF-8 string.
 *
 * Throws an exception if the tvbuff ends before the entire string is read.
 *
 * If `scope` is NULL, the caller is responsible for freeing the allocated memory using `wmem_free()`.
 * Otherwise, the memory is automatically freed when the scope lifetime ends.
 *
 * @param scope       The memory allocator scope for the returned string, or NULL.
 * @param tvb         The @ref tvbuff_t to read from.
 * @param bit_offset  The bit offset within the tvbuff where the string begins.
 * @param no_of_chars The number of 7-bit characters to decode.
 *
 * @return A pointer to the UTF-8 encoded string including the trailing NUL.
 */
WS_DLL_PUBLIC char *tvb_get_ascii_7bits_string(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int bit_offset, int no_of_chars);

/**
 * @brief Extract and convert a null-padded string from a tvbuff to UTF-8.
 *
 * Given an allocator scope, a tvbuff, a byte offset, a byte length, and a string encoding,
 * this function:
 *
 * - Allocates a buffer using the specified scope.
 * - Converts the string from the specified encoding to UTF-8, mapping some characters
 *   or invalid octet sequences to the Unicode REPLACEMENT CHARACTER.
 * - Copies the converted string plus a trailing '\0' into the allocated buffer.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * If `scope` is NULL, the caller is responsible for freeing the allocated memory
 * using `wmem_free()`. Otherwise, the memory is automatically freed when the scope lifetime ends.
 *
 * @param scope    The memory allocator scope for the returned string, or NULL.
 * @param tvb      The @ref tvbuff_t to read from.
 * @param offset   The offset in the tvbuff where the string starts.
 * @param length   The length in bytes of the null-padded string.
 * @param encoding The ENC_* constant specifying the string encoding.
 *
 * @return A pointer to the UTF-8 encoded string, null-terminated.
 */
WS_DLL_PUBLIC uint8_t *tvb_get_stringzpad(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, const int length, const unsigned encoding);

/**
 * @brief Extract and convert a null-terminated string from a tvbuff to UTF-8 using the specified encoding.
 *
 * Given an allocator scope, a tvbuff, a byte offset, a pointer to an int, and a string encoding,
 * this function:
 *
 * - Finds the length of the null-terminated string (throws an exception if the tvbuff ends before the NUL).
 * - Allocates a buffer using the specified scope.
 * - Converts the string from the specified encoding to UTF-8, mapping invalid sequences or characters
 *   to the Unicode REPLACEMENT CHARACTER.
 * - Appends a trailing '\0' to the resulting UTF-8 string.
 * - If `lengthp` is non-null, sets the pointed-to int to the length of the string.
 *
 * If `scope` is NULL, the caller is responsible for freeing the allocated memory using `wmem_free()`.
 * Otherwise, the memory is automatically freed when the scope lifetime ends.
 *
 * @param scope     The memory allocator scope for the result, or NULL.
 * @param tvb       The @ref tvbuff_t to read from.
 * @param offset    The byte offset in the tvbuff where the string begins.
 * @param lengthp   Pointer to an int to receive the string length, or NULL.
 * @param encoding  The ENC_* constant specifying the string encoding.
 *
 * @return A pointer to the UTF-8 encoded string including the trailing NUL.
 */
WS_DLL_PUBLIC uint8_t *tvb_get_stringz_enc(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, int *lengthp, const unsigned encoding);

/**
 * @brief Deprecated function to retrieve a raw, unmodifiable null-terminated string from a tvbuff.
 *
 * Given a @ref tvbuff_t and an offset assumed to point to a null-terminated string,
 * this function finds the string length (including the terminating null), allocates
 * a buffer to hold the string, copies the raw octets into it, and returns a pointer
 * to the string. The length of the string (including the null terminator) is returned
 * through `lengthp`.
 *
 * The returned string is constant and does not need to be freed by the caller; it is
 * automatically freed when the next packet is dissected.
 *
 * This function is more efficient than other string extraction routines but does not
 * perform any UTF-8 translation or validation. The string consists of raw octets as
 * present in the packet, including any invalid sequences.
 *
 * @warning This function is deprecated because it does not validate or convert string
 * encoding. Avoid using it in new code. Prefer safer alternatives such as:
 * - @ref tvb_get_stringz_enc
 * - @ref proto_tree_add_item_ret_string_and_length
 * - @ref tvb_strsize combined with manual validation of the string memory.
 *
 * @param tvb      The @ref tvbuff_t to read from.
 * @param offset   The offset in the tvbuff where the string begins.
 * @param lengthp  Pointer to an int to receive the string length including NUL.
 *
 * @return A pointer to the constant, raw string data.
 *
 * @deprecated Use APIs that return validated UTF-8 strings instead.
 */
WS_DLL_PUBLIC
WS_DEPRECATED_X("Use APIs that return a valid UTF-8 string instead")
const uint8_t *tvb_get_const_stringz(tvbuff_t *tvb,
    const int offset, int *lengthp);

/**
 * @brief Copy up to a specified number of bytes from a tvbuff into a buffer as a NUL-terminated string.
 *
 * Searches the given @ref tvbuff_t starting at `offset` for a NUL byte and copies
 * no more than `bufsize` bytes—including the terminating NUL—into the provided `buffer`.
 *
 * Returns the number of bytes copied, excluding the terminating NUL.
 *
 * If the remaining packet data is less than `bufsize`, this function will not throw
 * an exception if the end of the packet is reached before the NUL byte is found.
 * In that case, the buffer is still guaranteed to be NUL-terminated.
 *
 * @param tvb      The @ref tvbuff_t to read from.
 * @param offset   The offset in the tvbuff to start searching and copying.
 * @param bufsize  The maximum number of bytes to copy, including the terminating NUL.
 * @param buffer   The destination buffer where bytes will be copied.
 *
 * @return The number of bytes copied, excluding the terminating NUL.
 */
WS_DLL_PUBLIC int tvb_get_raw_bytes_as_stringz(tvbuff_t *tvb, const int offset,
    const unsigned bufsize, uint8_t *buffer);

/**
 * @brief Extract raw bytes from a tvbuff into a buffer as a NUL-terminated string.
 *
 * Copies as many bytes as are available in the given @ref tvbuff_t starting at `offset`
 * into the provided `buffer`, up to `bufsize - 1` bytes to leave room for a terminating NUL.
 *
 * The copied data consists of raw bytes; a NUL byte is appended at the end to ensure proper termination.
 *
 * @param tvb      The @ref tvbuff_t to read from.
 * @param offset   The offset in the tvbuff at which to start extracting bytes.
 * @param buffer   The destination buffer to copy bytes into.
 * @param bufsize  The size of the destination buffer (including space for terminating NUL).
 *
 * @return The number of bytes copied into the buffer, excluding the terminating NUL.
 */
WS_DLL_PUBLIC int tvb_get_raw_bytes_as_string(tvbuff_t *tvb, const int offset, char *buffer, size_t bufsize);

/**
 * @brief Check whether all bytes in a tvbuff range are ASCII printable characters.
 *
 * Iterates over the specified portion of the @ref tvbuff_t starting at `offset`
 * and spanning `length` bytes, verifying that each byte is an ASCII printable character
 * (i.e., in the range 0x20 to 0x7E).
 *
 * @param tvb      The @ref tvbuff_t to inspect.
 * @param offset   The offset in the tvbuff to begin checking.
 * @param length   The number of bytes to check.
 *
 * @return true if all bytes are printable ASCII characters, @c false otherwise.
 */
WS_DLL_PUBLIC bool tvb_ascii_isprint(tvbuff_t *tvb, const int offset,
	const int length);

/**
 * @brief Check if a portion of a tvbuff contains only valid, printable UTF-8 characters.
 *
 * Iterates over the specified portion of the @ref tvbuff_t starting at `offset`
 * and spanning `length` bytes (or until the end if `length` is -1),
 * verifying that the data forms valid UTF-8 sequences consisting entirely of printable characters.
 *
 * Partial UTF-8 sequences at the end of the range are considered invalid,
 * and in such cases the function returns false.
 *
 * @param tvb     The @ref tvbuff_t to check.
 * @param offset  The offset within the tvbuff where the check begins.
 * @param length  The number of bytes to check, or -1 to check until the end.
 *
 * @return true if all characters are valid and printable UTF-8, @c false otherwise.
 *
 * @see isprint_utf8_string()
 */
WS_DLL_PUBLIC bool tvb_utf_8_isprint(tvbuff_t *tvb, const int offset,
	const int length);

/**
 * @brief Check if all bytes in a tvbuff range are ASCII digits.
 *
 * Iterates over the specified portion of the @ref tvbuff_t starting at `offset`
 * and spanning `length` bytes, verifying that each byte is an ASCII digit
 * (characters '0' through '9').
 *
 * @param tvb      The @ref tvbuff_t to inspect.
 * @param offset   The offset in the tvbuff to begin checking.
 * @param length   The number of bytes to check.
 *
 * @return true if all bytes are ASCII digits, @c false otherwise.
 */
WS_DLL_PUBLIC bool tvb_ascii_isdigit(tvbuff_t *tvb, const int offset,
	const int length);

/**
 * @brief Locate the end of a line in a tvbuff, optionally desegmenting.
 *
 * Scans the given @ref tvbuff_t starting at `offset` for a line terminator,
 * examining up to `len` bytes (or to the end of the tvbuff if `len` is -1).
 * Returns the length of the line, excluding the terminator.
 *
 * If no line terminator is found:
 * - Returns -1 if `desegment` is true.
 * - Returns the remaining number of bytes if `desegment` is false.
 *
 * If `next_offset` is non-null and a line terminator is found, sets
 * `*next_offset` to the offset immediately following the terminator.
 * If no terminator is found and `desegment` is false, sets `*next_offset`
 * to the end of the buffer. If -1 is returned, `*next_offset` is not modified.
 *
 * @param tvb          The @ref tvbuff_t to scan.
 * @param offset       The offset in the tvbuff where the line begins.
 * @param len          The maximum number of bytes to scan, or -1 to scan to the end.
 * @param next_offset  Pointer to receive the offset past the line terminator, or NULL.
 * @param desegment    Whether to return -1 if no terminator is found.
 *
 * @return The length of the line (excluding terminator), or -1 if desegmenting and no terminator is found.
 */
WS_DLL_PUBLIC int tvb_find_line_end(tvbuff_t *tvb, const int offset, int len,
    int *next_offset, const bool desegment);

/**
 * @brief Locate the end of a line in a tvbuff, ignoring newlines inside quoted strings.
 *
 * Scans the given @ref tvbuff_t starting at `offset` for a line terminator,
 * examining up to `len` bytes (or to the end of the tvbuff if `len` is -1).
 * Quoted strings are treated specially—newlines within quotes are not considered
 * line terminators.
 *
 * Returns the length of the line, excluding the line terminator. If no terminator
 * is found, returns the remaining number of bytes in the buffer.
 *
 * If `next_offset` is non-null, sets `*next_offset` to the offset immediately
 * following the line terminator, or to the end of the buffer if no terminator is found.
 *
 * @param tvb          The @ref tvbuff_t to scan.
 * @param offset       The offset in the tvbuff where the line begins.
 * @param len          The maximum number of bytes to scan, or -1 to scan to the end.
 * @param next_offset  Pointer to receive the offset past the line terminator, or NULL.
 *
 * @return The length of the line (excluding terminator), or the remaining buffer size if no terminator is found.
 */
WS_DLL_PUBLIC int tvb_find_line_end_unquoted(tvbuff_t *tvb, const int offset,
    int len, int *next_offset);

/**
 * @brief Skip ASCII whitespace in a tvbuff and return the offset of the first non-whitespace byte.
 *
 * Scans the given @ref tvbuff_t starting at `offset`, skipping up to `maxlength` bytes,
 * and returns the offset of the first non-whitespace character found.
 * Whitespace characters include space (0x20), tab (0x09), carriage return (0x0D), and line feed (0x0A).
 *
 * The scan stops at `offset + maxlength - 1`, whichever comes first.
 *
 * @param tvb        The @ref tvbuff_t to scan.
 * @param offset     The offset in the tvbuff to begin skipping whitespace.
 * @param maxlength  The maximum number of bytes to scan from the offset.
 *
 * @return The offset of the first non-whitespace character, or `offset + maxlength` if none found.
 *
 * @see tvb_skip_wsp_return
 */
WS_DLL_PUBLIC int tvb_skip_wsp(tvbuff_t *tvb, const int offset,
    const int maxlength);

/**
 * @brief Skip ASCII whitespace in a tvbuff and return the next non-whitespace offset.
 *
 * Scans the given @ref tvbuff_t starting at `offset`, skipping over ASCII whitespace
 * characters (space, tab, carriage return, line feed) until a non-whitespace byte is found
 * or the end of the buffer is reached.
 *
 * @param tvb     The @ref tvbuff_t to scan.
 * @param offset  The offset in the tvbuff to begin skipping.
 *
 * @return The offset of the first non-whitespace character, or the end of the buffer.
 *
 * @see tvb_skip_wsp
 */
WS_DLL_PUBLIC int tvb_skip_wsp_return(tvbuff_t *tvb, const int offset);

/**
 * @brief Skip consecutive occurrences of a specific byte value in a tvbuff.
 *
 * Scans the given @ref tvbuff_t starting at `offset`, skipping up to `maxlength` bytes
 * as long as each byte matches the specified value `ch`. Returns the offset of the first
 * non-matching byte or `offset + maxlength` if all scanned bytes match.
 *
 * This function does not throw exceptions if the scan reaches beyond the tvbuff boundary;
 * it safely stops at the end of the buffer.
 *
 * @param tvb        The @ref tvbuff_t to scan.
 * @param offset     The offset in the tvbuff to begin scanning.
 * @param maxlength  The maximum number of bytes to scan.
 * @param ch         The byte value to skip.
 *
 * @return The offset of the first non-matching byte, or the end of the scan range.
 */
int tvb_skip_uint8(tvbuff_t *tvb, int offset, const int maxlength, const uint8_t ch);

/**
 * @brief Deprecated accessor for skipping consecutive bytes in a tvbuff.
 *
 * This function is equivalent to @ref tvb_skip_uint8 and should not be used in new code.
 * It scans the given @ref tvbuff_t starting at `offset`, skipping up to `maxlength` bytes
 * as long as each byte matches the specified value `ch`. Returns the offset of the first
 * non-matching byte or `offset + maxlength` if all scanned bytes match.
 *
 * This function does not throw exceptions if the scan reaches beyond the tvbuff boundary.
 *
 * @param tvb        The @ref tvbuff_t to scan.
 * @param offset     The offset in the tvbuff to begin scanning.
 * @param maxlength  The maximum number of bytes to scan.
 * @param ch         The byte value to skip.
 *
 * @return The offset of the first non-matching byte, or the end of the scan range.
 *
 * @deprecated Use @ref tvb_skip_uint8 instead.
 *
 * @see tvb_skip_uint8
 */
WS_DEPRECATED_X("Use tvb_skip_uint8 instead")
static inline int tvb_skip_guint8(tvbuff_t *tvb, int offset, const int maxlength, const uint8_t ch) {
	return tvb_skip_uint8(tvb, offset, maxlength, ch);
}

/**
 * @brief Determine the length of a token in a tvbuff, optionally desegmenting.
 *
 * Scans the given @ref tvbuff_t starting at `offset` for the end of a token,
 * examining up to `len` bytes (or to the end of the tvbuff if `len` is -1).
 * A token is defined as a sequence of non-separator characters terminated by a delimiter.
 *
 * If a terminator is found, returns the length of the token (excluding the terminator).
 * If no terminator is found:
 * - Returns -1 if `desegment` is true.
 * - Returns the remaining number of bytes if `desegment` is false.
 *
 * If `next_offset` is non-null and a terminator is found, sets `*next_offset` to the offset
 * immediately following the terminator. If no terminator is found and `desegment` is false,
 * sets `*next_offset` to the end of the buffer. If -1 is returned, `*next_offset` is not modified.
 *
 * @param tvb          The @ref tvbuff_t to scan.
 * @param offset       The offset in the tvbuff where the token begins.
 * @param len          The maximum number of bytes to scan, or -1 to scan to the end.
 * @param next_offset  Pointer to receive the offset past the token terminator, or NULL.
 * @param desegment    Whether to return -1 if no terminator is found.
 *
 * @return The length of the token (excluding terminator), or -1 if desegmenting and no terminator is found.
 */
WS_DLL_PUBLIC int tvb_get_token_len(tvbuff_t *tvb, const int offset, int len, int *next_offset, const bool desegment);

/**
 * @brief Compare a string in a tvbuff to a reference string using strncmp semantics.
 *
 * Checks whether there are at least `size` bytes remaining in the @ref tvbuff_t starting
 * at `offset`. If so, compares those bytes to the given reference string `str` using
 * `strncmp`. Returns 0 if the strings match, -1 otherwise.
 *
 * If there are fewer than `size` bytes remaining in the tvbuff, returns -1 without calling `strncmp`.
 *
 * @param tvb    The @ref tvbuff_t to read from.
 * @param offset The offset in the tvbuff where the comparison begins.
 * @param str    The reference string to compare against.
 * @param size   The number of bytes to compare.
 *
 * @return 0 if the tvbuff substring matches `str`, -1 otherwise.
 */
WS_DLL_PUBLIC int tvb_strneql(tvbuff_t *tvb, const int offset,
    const char *str, const size_t size);

/**
 * @brief Case-insensitive comparison of tvbuff bytes against a reference string.
 *
 * Checks whether there are at least `size` bytes remaining in the @ref tvbuff_t
 * starting at `offset`. If so, compares those bytes to the given reference string `str`
 * using `g_ascii_strncasecmp`. Returns 0 if the strings match (case-insensitively),
 * -1 otherwise.
 *
 * If there are fewer than `size` bytes remaining in the tvbuff, returns -1 without
 * performing the comparison.
 *
 * @param tvb    The @ref tvbuff_t to read from.
 * @param offset The offset in the tvbuff where the comparison begins.
 * @param str    The reference string to compare against.
 * @param size   The number of bytes to compare.
 *
 * @return 0 if the tvbuff substring matches `str` (case-insensitively), -1 otherwise.
 *
 * @see tvb_strneql
 */
WS_DLL_PUBLIC int tvb_strncaseeql(tvbuff_t *tvb, const int offset,
    const char *str, const size_t size);

/**
 * @brief Compare raw bytes in a tvbuff to a reference buffer using memcmp semantics.
 *
 * Checks whether there are at least `size` bytes remaining in the @ref tvbuff_t
 * starting at `offset`. If so, compares those bytes to the reference buffer `str`
 * using `memcmp`. Returns 0 if the buffers match, -1 otherwise.
 *
 * If there are fewer than `size` bytes remaining in the tvbuff, returns -1 without
 * performing the comparison.
 *
 * @param tvb    The @ref tvbuff_t to read from.
 * @param offset The offset in the tvbuff where the comparison begins.
 * @param str    The reference buffer to compare against.
 * @param size   The number of bytes to compare.
 *
 * @return 0 if the tvbuff bytes match `str`, -1 otherwise.
 */
WS_DLL_PUBLIC int tvb_memeql(tvbuff_t *tvb, const int offset,
    const uint8_t *str, size_t size);

/**
 * @brief Format a sequence of bytes from a tvbuff as a string with a custom separator.
 *
 * Converts `len` bytes of data from the given @ref tvbuff_t starting at `offset`
 * into a printable string representation, with each byte formatted as a two-digit
 * hexadecimal value and separated by the specified `punct` character.
 *
 * The resulting string is allocated using the provided @ref wmem_allocator_t scope.
 *
 * Example output: "01:AF:3B" if `punct` is ':'.
 *
 * @param scope   The memory allocator scope for the formatted string.
 * @param tvb     The @ref tvbuff_t to read from.
 * @param offset  The offset in the tvbuff to begin formatting.
 * @param len     The number of bytes to format.
 * @param punct   The character to use as a separator between bytes.
 *
 * @return A pointer to the formatted string.
 */
WS_DLL_PUBLIC char *tvb_bytes_to_str_punct(wmem_allocator_t *scope, tvbuff_t *tvb, const int offset,
    const int len, const char punct);

/**
 * @brief Format a sequence of bytes from a tvbuff as a hexadecimal string.
 *
 * Converts `len` bytes of data from the given @ref tvbuff_t starting at `offset`
 * into a printable string representation, with each byte formatted as a two-digit
 * hexadecimal value and no separator between bytes.
 *
 * The resulting string is allocated using the provided @ref wmem_allocator_t scope.
 *
 * Example output: "01AF3B" for three bytes.
 *
 * @param allocator  The memory allocator scope for the formatted string.
 * @param tvb        The @ref tvbuff_t to read from.
 * @param offset     The offset in the tvbuff to begin formatting.
 * @param len        The number of bytes to format.
 *
 * @return A pointer to the formatted string.
 *
 * @see tvb_bytes_to_str_punct
 */
WS_DLL_PUBLIC char *tvb_bytes_to_str(wmem_allocator_t *allocator, tvbuff_t *tvb,
    const int offset, const int len);

/**
 * @brief Digit mapping table for BCD decoding.
 *
 * Represents a set of output characters used to format BCD-encoded nibbles.
 * Each entry in the `out` array maps a 4-bit value (0–15) to a corresponding
 * display character. This allows customization of digit rendering, including
 * support for overdecadic values or alternate digit sets.
 *
 * Used by functions like @ref tvb_bcd_dig_to_str to convert BCD data into
 * readable strings.
 *
 * If a digit set is not provided, a default mapping of '0'–'9' with '?' for
 * values 10–15 is used.
 */
typedef struct dgt_set_t
{
    const unsigned char out[16]; /**< Output character for each BCD nibble value (0x0–0xF). */
}
dgt_set_t;

/**
 * @brief Convert BCD-encoded digits from a tvbuff into a formatted string.
 *
 * Extracts BCD-encoded digits from the given @ref tvbuff_t starting at `offset`
 * and spanning `len` bytes (or to the end if `len` is -1). Each byte contains two
 * BCD digits (high and low nibbles). The conversion begins with either the high
 * or low nibble depending on `skip_first`.
 *
 * Digits are formatted using the provided digit set `dgt`. If `dgt` is NULL,
 * a default digit set of '0'–'9' is used, and any overdecadic values (10–15)
 * are rendered as '?'.
 *
 * A nibble value of 0xF is treated as a filler and terminates the conversion early.
 * The resulting string is allocated using the specified @ref wmem_allocator_t scope.
 *
 * @param scope       The memory allocator scope for the result.
 * @param tvb         The @ref tvbuff_t to read from.
 * @param offset      The offset in the tvbuff where BCD data begins.
 * @param len         The number of bytes to decode, or -1 to decode to the end.
 * @param dgt         Pointer to a digit set mapping (or NULL for default).
 * @param skip_first  If true, skip the first nibble and start with the second.
 *
 * @return A pointer to the WMEM-allocated string containing the formatted digits.
 */
WS_DLL_PUBLIC const char *tvb_bcd_dig_to_str(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, const int len, const dgt_set_t *dgt,
    bool skip_first);

/**
 * @brief Convert BCD-encoded digits from a tvbuff to a formatted string (big-endian nibble order).
 *
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset (which may be -1 for "all the way to the end of the
 * tvbuff"), fetch BCD encoded digits from a tvbuff starting from either
 * the low or high half byte, formatting the digits according to an input digit
 * set, if NUL a default digit set of 0-9 returning "?" for overdecadic digits
 * will be used.  A pointer to the WMEM-allocated string will
 * be returned.
 *
 * @note A tvbuff content of 0xf is considered a 'filler' and will
 * end the conversion. Function uses big endian convention: first digit is based
 * on high order nibble, second digit is based on low order nibble.
 *
 * @param scope       The memory allocator scope for the result.
 * @param tvb         The @ref tvbuff_t to read from.
 * @param offset      The offset in the tvbuff where BCD data begins.
 * @param len         The number of bytes to decode, or -1 to decode to the end.
 * @param dgt         Pointer to a digit set mapping (or NULL for default).
 * @param skip_first  If true, skip the first nibble and start with the second.
 *
 * @return A pointer to the WMEM-allocated string containing the formatted digits.
 *
 * @see dgt_set_t
 */
WS_DLL_PUBLIC const char *tvb_bcd_dig_to_str_be(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, const int len, const dgt_set_t *dgt,
    bool skip_first);

/**
 * @brief Convert BCD-encoded digits from a tvbuff to a UTF-8 string with flexible nibble handling.
 *
 * Extracts BCD-encoded digits from the given @ref tvbuff_t starting at `offset` and spanning
 * `len` bytes (or to the end if `len` is -1). Each byte contains two nibbles representing digits.
 * The conversion behavior is controlled by `skip_first`, `odd`, and `bigendian` flags:
 *
 * - If `skip_first` is true, the first nibble (high-order) of the first byte is ignored.
 * - If `odd` is true, the high-order nibble of the last byte is skipped.
 * - If `bigendian` is true, each byte is interpreted with the high-order nibble as the first digit
 *   and the low-order nibble as the second digit; otherwise, the order is reversed.
 *
 * Digits are formatted using the provided digit set `dgt`. If `dgt` is NULL, a default digit set
 * of '0'–'9' is used, and any overdecadic values (10–15) are rendered as '?'.
 *
 * A nibble value of 0xF is treated as a filler and terminates the conversion early.
 * The resulting UTF-8 string is allocated using the specified @ref wmem_allocator_t scope.
 *
 * @param scope       The memory allocator scope for the result.
 * @param tvb         The @ref tvbuff_t to read from.
 * @param offset      The offset in the tvbuff where BCD data begins.
 * @param len         The number of bytes to decode, or -1 to decode to the end.
 * @param dgt         Pointer to a digit set mapping (or NULL for default).
 * @param skip_first  If true, skip the first nibble and start with the second.
 * @param odd         If true, skip the high nibble of the last byte.
 * @param bigendian   If true, treat high nibble as first digit in each byte.
 *
 * @return A pointer to the WMEM-allocated UTF-8 string containing the formatted digits.
 *
 * @see dgt_set_t
 */
WS_DLL_PUBLIC char *tvb_get_bcd_string(wmem_allocator_t *scope, tvbuff_t *tvb,
    const int offset, int len, const dgt_set_t *dgt,
    bool skip_first, bool odd, bool bigendian);

/**
 * @brief Search for a sub-tvbuff within another tvbuff starting at a given offset.
 *
 * Scans the contents of `haystack_tvb` starting at `haystack_offset` for the first
 * occurrence of the full contents of `needle_tvb`. If found, returns the offset of
 * the match relative to the beginning of `haystack_tvb` (not relative to `haystack_offset`).
 *
 * If no match is found, returns -1.
 *
 * @param haystack_tvb     The @ref tvbuff_t to search within.
 * @param needle_tvb       The @ref tvbuff_t to search for.
 * @param haystack_offset  The offset in `haystack_tvb` where the search begins.
 *
 * @return The offset of the match relative to the start of `haystack_tvb`, or -1 if not found.
 */
WS_DLL_PUBLIC int tvb_find_tvb(tvbuff_t *haystack_tvb, tvbuff_t *needle_tvb,
    const int haystack_offset);

/* From tvbuff_zlib.c */
/**
 * @brief Deprecated interface for uncompressing data from a tvbuff using zlib.
 *
 * Uncompresses `comprlen` bytes of compressed data from the given @ref tvbuff_t
 * starting at `offset`, returning a new @ref tvbuff_t containing the uncompressed data.
 *
 * This function is deprecated and should not be used in new code. Prefer
 * @ref tvb_uncompress_zlib for improved clarity and maintainability.
 *
 * @param tvb       The @ref tvbuff_t containing compressed data.
 * @param offset    The offset in the tvbuff where compressed data begins.
 * @param comprlen  The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t containing the uncompressed data.
 *
 * @deprecated Use @ref tvb_uncompress_zlib instead.
 *
 * @see tvb_uncompress_zlib
 */
WS_DEPRECATED_X("Use tvb_uncompress_zlib instead")
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress(tvbuff_t *tvb, const int offset,
    int comprlen);

/**
 * @brief Uncompress zlib-compressed data from a tvbuff.
 *
 * Uncompresses `comprlen` bytes of zlib-compressed data from the given
 * @ref tvbuff_t starting at `offset`. If successful, returns a new @ref tvbuff_t
 * containing the uncompressed data. If uncompression fails, returns NULL.
 *
 * The returned tvbuff must be either:
 * - Freed manually using `tvb_free()`, or
 * - Added to the chain of another tvbuff to ensure proper memory management.
 *
 * For simpler ownership handling, consider using @ref tvb_child_uncompress.
 *
 * @param tvb       The @ref tvbuff_t containing compressed data.
 * @param offset    The offset in the tvbuff where compressed data begins.
 * @param comprlen  The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data, or NULL on failure.
 *
 * @see tvb_child_uncompress
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_zlib(tvbuff_t *tvb, const int offset,
    int comprlen);

/**
 * @brief Deprecated interface for uncompressing data and chaining the result to a parent tvbuff.
 *
 * Uncompresses `comprlen` bytes of compressed data from the given @ref tvbuff_t starting at `offset`,
 * and returns a new @ref tvbuff_t containing the uncompressed data. The returned tvbuff is automatically
 * chained to the specified `parent` tvbuff for memory management.
 *
 * This function is deprecated and should not be used in new code. Prefer
 * @ref tvb_child_uncompress_zlib for clearer semantics and zlib-specific handling.
 *
 * @param parent     The parent @ref tvbuff_t to which the result will be chained.
 * @param tvb        The @ref tvbuff_t containing compressed data.
 * @param offset     The offset in the tvbuff where compressed data begins.
 * @param comprlen   The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data, chained to `parent`, or NULL on failure.
 *
 * @deprecated Use @ref tvb_child_uncompress_zlib instead.
 *
 * @see tvb_child_uncompress_zlib
 */
WS_DEPRECATED_X("Use tvb_child_uncompress_zlib instead")
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress(tvbuff_t *parent, tvbuff_t *tvb,
    const int offset, int comprlen);

/**
 * @brief Uncompress a zlib-compressed packet inside a tvbuff and attach the result to a parent tvbuff.
 *
 * Uncompress `comprlen` bytes of zlib-compressed data from the given @ref tvbuff_t
 * starting at `offset`. If successful, returns a new @ref tvbuff_t containing the uncompressed data,
 * which is automatically attached as a child to the specified `parent` tvbuff for proper memory management.
 *
 * Returns NULL if uncompression fails.
 *
 * @param parent    The parent @ref tvbuff_t to which the uncompressed tvbuff will be attached.
 * @param tvb       The @ref tvbuff_t containing compressed data.
 * @param offset    The offset in the tvbuff where compressed data begins.
 * @param comprlen  The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data attached to `parent`, or NULL on failure.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_zlib(tvbuff_t *parent, tvbuff_t *tvb,
    const int offset, int comprlen);

/* From tvbuff_brotli.c */

/**
 * @brief Uncompress Brotli-compressed data from a tvbuff.
 *
 * Uncompresses `comprlen` bytes of Brotli-compressed data from the given
 * @ref tvbuff_t starting at `offset`. If successful, returns a new @ref tvbuff_t
 * containing the uncompressed data. If uncompression fails, returns NULL.
 *
 * The returned tvbuff must be either:
 * - Freed manually using `tvb_free()`, or
 * - Added to the chain of another tvbuff to ensure proper memory management.
 *
 * For simpler ownership handling, consider using @ref tvb_child_uncompress_brotli.
 *
 * @param tvb       The @ref tvbuff_t containing Brotli-compressed data.
 * @param offset    The offset in the tvbuff where compressed data begins.
 * @param comprlen  The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data, or NULL on failure.
 *
 * @see tvb_child_uncompress_brotli
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_brotli(tvbuff_t *tvb, const int offset,
    int comprlen);

/**
 * @brief Uncompress Brotli-compressed data from a tvbuff and attach the result to a parent tvbuff.
 *
 * Uncompresses `comprlen` bytes of Brotli-compressed data from the given @ref tvbuff_t
 * starting at `offset`. If successful, returns a new @ref tvbuff_t containing the uncompressed data,
 * which is automatically attached as a child to the specified `parent` tvbuff for proper memory management.
 *
 * Returns NULL if uncompression fails.
 *
 * @param parent     The parent @ref tvbuff_t to which the uncompressed tvbuff will be attached.
 * @param tvb        The @ref tvbuff_t containing Brotli-compressed data.
 * @param offset     The offset in the tvbuff where compressed data begins.
 * @param comprlen   The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data attached to `parent`, or NULL on failure.
 *
 * @see tvb_uncompress_brotli
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_brotli(tvbuff_t *parent, tvbuff_t *tvb,
    const int offset, int comprlen);

/* From tvbuff_snappy.c */

/**
 * @brief Uncompress Snappy-compressed data from a tvbuff.
 *
 * Uncompress `comprlen` bytes of Snappy-compressed data from the given
 * @ref tvbuff_t starting at `offset`. If successful, returns a new @ref tvbuff_t
 * containing the uncompressed data. If uncompression fails, returns NULL.
 *
 * The returned tvbuff must be either:
 * - Freed manually using `tvb_free()`, or
 * - Added to the chain of another tvbuff to ensure proper memory management.
 *
 * @param tvb       The @ref tvbuff_t containing Snappy-compressed data.
 * @param offset    The offset in the tvbuff where compressed data begins.
 * @param comprlen  The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data, or NULL on failure.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_snappy(tvbuff_t *tvb, const int offset,
    int comprlen);

/**
 * @brief Uncompress Snappy-compressed data from a tvbuff and attach the result to a parent tvbuff.
 *
 * Uncompresses `comprlen` bytes of Snappy-compressed data from the given @ref tvbuff_t
 * starting at `offset`. If successful, returns a new @ref tvbuff_t containing the uncompressed data,
 * which is automatically attached as a child to the specified `parent` tvbuff for proper memory management.
 *
 * Returns NULL if uncompression fails.
 *
 * @param parent     The parent @ref tvbuff_t to which the uncompressed tvbuff will be attached.
 * @param tvb        The @ref tvbuff_t containing Snappy-compressed data.
 * @param offset     The offset in the tvbuff where compressed data begins.
 * @param comprlen   The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data attached to `parent`, or NULL on failure.
 *
 * @see tvb_uncompress_snappy
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_snappy(tvbuff_t *parent, tvbuff_t *tvb,
    const int offset, int comprlen);

/* From tvbuff_lz77.c */

/**
 * @brief Uncompress Microsoft Plain LZ77-compressed data from a tvbuff.
 *
 * Uncompresses `comprlen` bytes of Microsoft Plain LZ77-compressed data
 * from the given @ref tvbuff_t starting at `offset`. If successful, returns a new
 * @ref tvbuff_t containing the uncompressed data. If uncompression fails, returns NULL.
 *
 * The returned tvbuff must be either:
 * - Freed manually using `tvb_free()`, or
 * - Added to the chain of another tvbuff to ensure proper memory management.
 *
 * For simpler ownership handling, consider using @ref tvb_child_uncompress_lz77.
 *
 * @param tvb       The @ref tvbuff_t containing LZ77-compressed data.
 * @param offset    The offset in the tvbuff where compressed data begins.
 * @param comprlen  The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data, or NULL on failure.
 *
 * @see tvb_child_uncompress_lz77
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_lz77(tvbuff_t *tvb,
    const int offset, int comprlen);

/**
 * @brief Uncompress Microsoft Plain LZ77-compressed data from a tvbuff and attach the result to a parent tvbuff.
 *
 * Uncompress `comprlen` bytes of Microsoft Plain LZ77-compressed data from the given
 * @ref tvbuff_t starting at `offset`. If successful, returns a new @ref tvbuff_t containing the
 * uncompressed data, which is automatically attached as a child to the specified `parent` tvbuff
 * for proper memory management.
 *
 * Returns NULL if uncompression fails.
 *
 * @param parent     The parent @ref tvbuff_t to which the uncompressed tvbuff will be attached.
 * @param tvb        The @ref tvbuff_t containing LZ77-compressed data.
 * @param offset     The offset in the tvbuff where compressed data begins.
 * @param comprlen   The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data attached to `parent`, or NULL on failure.
 *
 * @see tvb_uncompress_lz77
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_lz77(tvbuff_t *parent,
     tvbuff_t *tvb, const int offset, int comprlen);

/* From tvbuff_lz77huff.c */

/**
 * @brief Uncompress Microsoft LZ77+Huffman-compressed data from a tvbuff.
 *
 * Uncompress `comprlen` bytes of Microsoft LZ77+Huffman-compressed data
 * from the given @ref tvbuff_t starting at `offset`. If successful, returns a new
 * @ref tvbuff_t containing the uncompressed data. If uncompression fails, returns NULL.
 *
 * The returned tvbuff must be either:
 * - Freed manually using `tvb_free()`, or
 * - Added to the chain of another tvbuff to ensure proper memory management.
 *
 * For simpler ownership handling, consider using @ref tvb_child_uncompress_lz77huff.
 *
 * @param tvb       The @ref tvbuff_t containing LZ77+Huffman-compressed data.
 * @param offset    The offset in the tvbuff where compressed data begins.
 * @param comprlen  The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data, or NULL on failure.
 *
 * @see tvb_child_uncompress_lz77huff
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_lz77huff(tvbuff_t *tvb,
    const int offset, int comprlen);

/**
 * @brief Uncompress Microsoft LZ77+Huffman-compressed data from a tvbuff and attach the result to a parent tvbuff.
 *
 * Uncompresses `comprlen` bytes of Microsoft LZ77+Huffman-compressed data from the given
 * @ref tvbuff_t starting at `offset`. If successful, returns a new @ref tvbuff_t containing the
 * uncompressed data, which is automatically attached as a child to the specified `parent` tvbuff
 * for proper memory management.
 *
 * Returns NULL if uncompression fails.
 *
 * @param parent     The parent @ref tvbuff_t to which the uncompressed tvbuff will be attached.
 * @param tvb        The @ref tvbuff_t containing LZ77+Huffman-compressed data.
 * @param offset     The offset in the tvbuff where compressed data begins.
 * @param comprlen   The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data attached to `parent`, or NULL on failure.
 *
 * @see tvb_uncompress_lz77huff
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_lz77huff(tvbuff_t *parent,
    tvbuff_t *tvb, const int offset, int comprlen);

/* From tvbuff_lznt1.c */

/**
 * @brief Uncompress Microsoft LZNT1-compressed data from a tvbuff.
 *
 * Uncompress `comprlen` bytes of Microsoft LZNT1-compressed data
 * from the given @ref tvbuff_t starting at `offset`. If successful, returns a new
 * @ref tvbuff_t containing the uncompressed data. If uncompression fails, returns NULL.
 *
 * The returned tvbuff must be either:
 * - Freed manually using `tvb_free()`, or
 * - Added to the chain of another tvbuff to ensure proper memory management.
 *
 * For simpler ownership handling, consider using @ref tvb_child_uncompress_lznt1.
 *
 * @param tvb       The @ref tvbuff_t containing LZNT1-compressed data.
 * @param offset    The offset in the tvbuff where compressed data begins.
 * @param comprlen  The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data, or NULL on failure.
 *
 * @see tvb_child_uncompress_lznt1
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_lznt1(tvbuff_t *tvb,
    const int offset, int comprlen);

/**
 * @brief Uncompress Microsoft LZNT1-compressed data from a tvbuff and attach the result to a parent tvbuff.
 *
 * Uncompress `comprlen` bytes of Microsoft LZNT1-compressed data from the given
 * @ref tvbuff_t starting at `offset`. If successful, returns a new @ref tvbuff_t containing the
 * uncompressed data, which is automatically attached as a child to the specified `parent` tvbuff
 * for proper memory management.
 *
 * Returns NULL if uncompression fails.
 *
 * @param parent     The parent @ref tvbuff_t to which the uncompressed tvbuff will be attached.
 * @param tvb        The @ref tvbuff_t containing LZNT1-compressed data.
 * @param offset     The offset in the tvbuff where compressed data begins.
 * @param comprlen   The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data attached to `parent`, or NULL on failure.
 *
 * @see tvb_uncompress_lznt1
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_lznt1(tvbuff_t *parent,
    tvbuff_t *tvb, const int offset, int comprlen);

/**
 * @brief Uncompress Zstandard (ZSTD)-compressed data from a tvbuff.
 *
 * Uncompress `comprlen` bytes of ZSTD-compressed data from the given
 * @ref tvbuff_t starting at `offset`. If successful, returns a new @ref tvbuff_t
 * containing the uncompressed data. If uncompression fails, returns NULL.
 *
 * The returned tvbuff must be either:
 * - Freed manually using `tvb_free()`, or
 * - Added to the chain of another tvbuff to ensure proper memory management.
 *
 * For simpler ownership handling, consider using @ref tvb_child_uncompress_zstd.
 *
 * @param tvb       The @ref tvbuff_t containing ZSTD-compressed data.
 * @param offset    The offset in the tvbuff where compressed data begins.
 * @param comprlen  The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data, or NULL on failure.
 *
 * @see tvb_child_uncompress_zstd
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_zstd(tvbuff_t *tvb,
    const int offset, int comprlen);

/**
 * @brief Uncompress Zstandard (ZSTD)-compressed data from a tvbuff and attach the result to a parent tvbuff.
 *
 * Uncompress `comprlen` bytes of ZSTD-compressed data from the given
 * @ref tvbuff_t starting at `offset`. If successful, returns a new @ref tvbuff_t containing the
 * uncompressed data, which is automatically attached as a child to the specified `parent` tvbuff
 * for proper memory management.
 *
 * Returns NULL if uncompression fails.
 *
 * @param parent     The parent @ref tvbuff_t to which the uncompressed tvbuff will be attached.
 * @param tvb        The @ref tvbuff_t containing ZSTD-compressed data.
 * @param offset     The offset in the tvbuff where compressed data begins.
 * @param comprlen   The number of bytes of compressed data to uncompress.
 *
 * @return A new @ref tvbuff_t with uncompressed data attached to `parent`, or NULL on failure.
 *
 * @see tvb_uncompress_zstd
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_zstd(tvbuff_t *parent,
    tvbuff_t *tvb, const int offset, int comprlen);

/* From tvbuff_base64.c */

/**
 * @brief Decode a base64-encoded string into a tvbuff and attach it to a parent tvbuff.
 *
 * Converts the given base64-encoded string `base64` into its binary representation,
 * returning a new @ref tvbuff_t containing the decoded data. The resulting tvbuff is
 * automatically attached as a child to the specified `parent` tvbuff for proper memory management.
 *
 * This is useful for handling embedded base64 payloads in protocol dissectors.
 *
 * @param parent  The parent @ref tvbuff_t to which the decoded tvbuff will be attached.
 * @param base64  The base64-encoded string to decode.
 *
 * @return A new @ref tvbuff_t containing the decoded binary data, or NULL on failure.
 */
extern tvbuff_t* base64_to_tvb(tvbuff_t *parent, const char *base64);

/**
 * @brief Decode a base64-encoded string from a tvbuff region and attach the result to a parent tvbuff.
 *
 * Extracts a base64-encoded string from the given @ref tvbuff_t starting at `offset` and spanning
 * `length` bytes. Decodes the string into its binary representation and returns a new @ref tvbuff_t
 * containing the decoded data. The resulting tvbuff is automatically attached as a child to the
 * specified `parent` tvbuff for proper memory management.
 *
 * This is useful for decoding embedded base64 payloads directly from packet data.
 *
 * @param parent  The parent @ref tvbuff_t to which the decoded tvbuff will be attached.
 * @param offset  The offset in the tvbuff where the base64 string begins.
 * @param length  The length of the base64 string to decode.
 *
 * @return A new @ref tvbuff_t containing the decoded binary data, or NULL on failure.
 *
 * @see base64_to_tvb
 */
extern tvbuff_t* base64_tvb_to_new_tvb(tvbuff_t* parent, int offset, int length);

/**
 * @brief Decode a base64url-encoded string from a tvbuff region and attach the result to a parent tvbuff.
 *
 * Extracts a base64url-encoded string from the given @ref tvbuff_t starting at `offset` and spanning
 * `length` bytes. Decodes the string into its binary representation and returns a new @ref tvbuff_t
 * containing the decoded data. The resulting tvbuff is automatically attached as a child to the
 * specified `parent` tvbuff for proper memory management.
 *
 * This variant uses base64url decoding semantics, where '-' and '_' are used instead of '+' and '/',
 * and padding may be omitted.
 *
 * @param parent  The parent @ref tvbuff_t to which the decoded tvbuff will be attached.
 * @param offset  The offset in the tvbuff where the base64url string begins.
 * @param length  The length of the base64url string to decode.
 *
 * @return A new @ref tvbuff_t containing the decoded binary data, or NULL on failure.
 *
 * @see base64_tvb_to_new_tvb
 */
extern tvbuff_t* base64uri_tvb_to_new_tvb(tvbuff_t* parent, int offset, int length);

/* From tvbuff_hpackhuff.c */

/**
 * @brief Decode HPACK Huffman-encoded data from a tvbuff into a string buffer.
 *
 * Extracts `len` bytes of HPACK Huffman-encoded data from the given @ref tvbuff_t
 * starting at `offset`, decodes it into a UTF-8 string, and returns a @ref wmem_strbuf_t
 * containing the result. The string buffer is allocated using the specified @ref wmem_allocator_t scope.
 *
 * This is typically used when parsing HPACK header blocks in HTTP/2 or related protocols.
 *
 * @param scope   The memory allocator scope for the resulting string buffer.
 * @param tvb     The @ref tvbuff_t containing HPACK Huffman-encoded data.
 * @param offset  The offset in the tvbuff where the encoded data begins.
 * @param len     The number of bytes to decode.
 *
 * @return A @ref wmem_strbuf_t containing the decoded string, or NULL on failure.
 */
WS_DLL_PUBLIC wmem_strbuf_t* tvb_get_hpack_huffman_strbuf(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, const int len);

/**
 * @brief Decode HPACK Huffman-encoded data from a tvbuff region and attach the result to a parent tvbuff.
 *
 * Extracts `length` bytes of HPACK Huffman-encoded data from the given @ref tvbuff_t
 * starting at `offset`, decodes it into a UTF-8 string, and returns a new @ref tvbuff_t
 * containing the decoded data. The resulting tvbuff is automatically attached as a child
 * to the specified `parent` tvbuff for proper memory management.
 *
 * This is typically used when parsing HPACK header blocks in HTTP/2 or related protocols.
 *
 * @param parent  The parent @ref tvbuff_t to which the decoded tvbuff will be attached.
 * @param offset  The offset in the tvbuff where the encoded data begins.
 * @param length  The number of bytes of encoded data to decode.
 *
 * @return A new @ref tvbuff_t containing the decoded string data attached to `parent`, or NULL on failure.
 *
 * @see tvb_get_hpack_huffman_strbuf
 */
WS_DLL_PUBLIC tvbuff_t* tvb_child_uncompress_hpack_huff(tvbuff_t *parent,
    int offset, int length);

/**
 * @brief Extract a variable-length integer from a tvbuff using the specified encoding.
 *
 * Parses a variable-length integer from the given @ref tvbuff_t starting at `offset`,
 * using up to `maxlen` bytes. The encoding format is specified by `encoding`, which
 * must be one of the supported ENC_VARINT_* types (e.g., ENC_VARINT_PROTOBUF,
 * ENC_VARINT_QUIC, ENC_VARINT_ZIGZAG, ENC_VARINT_SDNV).
 *
 * Each byte in the varint, except the last, has its most significant bit (MSB) set,
 * indicating continuation. For example, the sequence `0xAC 0x02` encodes the value 300.
 *
 * If parsing succeeds, the decoded value is stored in `value`, and the function returns
 * the number of bytes consumed. If parsing fails, returns 0.
 *
 * @param tvb       The @ref tvbuff_t from which to extract the varint.
 * @param offset    The offset in the tvbuff where parsing begins.
 * @param maxlen    The maximum number of bytes to inspect.
 * @param value     Pointer to a uint64_t where the parsed value will be stored.
 * @param encoding  The encoding format (one of the ENC_VARINT_* constants).
 *
 * @return The number of bytes consumed during parsing, or 0 if parsing failed.
 */
WS_DLL_PUBLIC unsigned tvb_get_varint(tvbuff_t *tvb, unsigned offset, unsigned maxlen, uint64_t *value, const unsigned encoding);

/************** END OF ACCESSORS ****************/

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TVBUFF_H__ */

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
