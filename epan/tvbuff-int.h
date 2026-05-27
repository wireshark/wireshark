/** @file
 *
 * Structures that most TVB users should not be accessing directly.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
struct tvbuff;

/**
 * @brief Vtable of low-level operations implementing a specific tvbuff backing type.
 */
struct tvb_ops {
    size_t tvb_size; /**< Size in bytes of the tvbuff implementation struct, used for allocation. */

    /**
     * @brief Releases any resources owned by the tvbuff when it is freed.
     * @param tvb The tvbuff to free.
     */
    void (*tvb_free)(struct tvbuff *tvb);

    /**
     * @brief Translates a logical counter value to a physical byte offset within the tvbuff's backing data.
     * @param tvb     The tvbuff to query.
     * @param counter The logical counter value to translate.
     * @return The corresponding physical byte offset.
     */
    unsigned (*tvb_offset)(const struct tvbuff *tvb, unsigned counter);

    /**
     * @brief Returns a pointer to a contiguous region of the tvbuff's backing data.
     * @param tvb        The tvbuff to access.
     * @param abs_offset Absolute byte offset at which the region begins.
     * @param abs_length Number of bytes in the region.
     * @return Pointer to the first byte of the requested region.
     */
    const uint8_t *(*tvb_get_ptr)(struct tvbuff *tvb, unsigned abs_offset, unsigned abs_length);

    /**
     * @brief Copies bytes from the tvbuff into a caller-supplied buffer.
     * @param tvb    The tvbuff to copy from.
     * @param target Destination buffer to copy bytes into.
     * @param offset Absolute byte offset within the tvbuff at which copying begins.
     * @param length Number of bytes to copy.
     * @return Pointer to the destination buffer.
     */
    void *(*tvb_memcpy)(struct tvbuff *tvb, void *target, unsigned offset, unsigned length);

    /**
     * @brief Searches for the first occurrence of a single byte value within a region of the tvbuff.
     * @param tvb          The tvbuff to search.
     * @param abs_offset   Absolute byte offset at which to begin searching.
     * @param limit        Maximum number of bytes to search.
     * @param needle       The byte value to search for.
     * @param found_offset Set to the absolute offset of the first matching byte if found.
     * @return True if the needle was found, false otherwise.
     */
    bool (*tvb_find_uint8)(tvbuff_t *tvb, unsigned abs_offset, unsigned limit, uint8_t needle, unsigned *found_offset);

    /**
     * @brief Searches for the first byte within a region that matches any byte in a pre-compiled pattern.
     * @param tvb          The tvbuff to search.
     * @param abs_offset   Absolute byte offset at which to begin searching.
     * @param limit        Maximum number of bytes to search.
     * @param pattern      Pre-compiled set of needle bytes to search for.
     * @param found_offset Set to the absolute offset of the first matching byte if found.
     * @param found_needle Set to the matching byte value if a match is found.
     * @return True if any pattern byte was found, false otherwise.
     */
    bool (*tvb_ws_mempbrk_pattern_uint8)(tvbuff_t *tvb, unsigned abs_offset, unsigned limit, const ws_mempbrk_pattern* pattern, unsigned *found_offset, unsigned char *found_needle);

    /**
     * @brief Creates a new tvbuff that is a subset clone of a region of the given tvbuff.
     * @param tvb        The source tvbuff to clone from.
     * @param abs_offset Absolute byte offset within the source tvbuff at which the clone begins.
     * @param abs_length Number of bytes the cloned tvbuff should cover.
     * @return Pointer to the newly created tvbuff clone.
     */
    tvbuff_t *(*tvb_clone)(tvbuff_t *tvb, unsigned abs_offset, unsigned abs_length);
};

/*
 * Tvbuff flags.
 */
#define TVBUFF_FRAGMENT   0x00000001 /**< Indicates that this tvbuff represents a fragment of a larger PDU. */
#define TVBUFF_RAW_OFFSET 0x00000002 /**< Indicates that the raw_offset field has been explicitly set on this tvbuff. */

/**
 * @brief Core tvbuff (testy virtual buffer) structure representing a region of packet data, possibly backed lazily.
 */
struct tvbuff {
    /* Doubly linked list pointers */
    tvbuff_t*              next;              /**< Pointer to the next tvbuff in the chain of tvbuffs for this packet; NULL if last. */

    /* Record-keeping */
    const struct tvb_ops*  ops;              /**< Vtable of backing-type-specific operations for this tvbuff. */
    bool                   initialized;      /**< True if this tvbuff has been fully initialized and is safe to access. */
    unsigned               flags;            /**< Bitmask of TVBUFF_* flags describing the state of this tvbuff. */
    struct tvbuff*         ds_tvb;           /**< Pointer to the top-level data-source tvbuff from which this tvbuff ultimately derives. */

    /** Pointer to the underlying raw data for this tvbuff.
     * May be NULL either because this is a zero-length tvbuff, or because
     * the tvbuff was lazily constructed and the backing buffer has not yet
     * been allocated or filled (e.g. before tvb_get_ptr() is first called). */
    const uint8_t*         real_data;

    /** Number of bytes of data actually available from the capture file.
     * Represents the length of the virtual buffer and/or real_data.
     * May be less than reported_length if the packet was truncated by the
     * capture process. Must never exceed reported_length or contained_length. */
    unsigned               length;

    /** Number of bytes reported as being present in the original packet or
     * data stream, regardless of how much was actually captured.
     * May exceed length when the packet was captured truncated. */
    unsigned               reported_length;

    /** Number of bytes of this tvbuff's data reported as present in the
     * parent tvbuff from which it was extracted, if applicable.
     * May exceed reported_length if the parent tvbuff's length field
     * indicated more data than was actually available to extract.
     * If this tvbuff was not extracted from a parent, equals reported_length.
     * Must never exceed reported_length. */
    unsigned               contained_length;

    /** Byte offset of this tvbuff's data from the beginning of the
     * first real (non-subset) tvbuff in the chain. Computed lazily. */
    unsigned               raw_offset;
};

/**
 * @brief Creates a new TVB (Packet Buffer) with the specified operations.
 *
 * @param ops Pointer to the TVB operations structure.
 * @return Pointer to the newly created TVB.
 */
tvbuff_t *tvb_new(const struct tvb_ops *ops);

/**
 * @brief Creates a new TVBuffer that is a proxy for an existing TVBuffer.
 *
 * @param backing The existing TVBuffer to proxy.
 * @return A new TVBuffer that proxies the given TVBuffer.
 */
tvbuff_t *tvb_new_proxy(tvbuff_t *backing);

/**
 * @brief Adds a child tvbuff to the parent tvbuff chain.
 *
 * @param parent The parent tvbuff to which the child will be added.
 * @param child The child tvbuff to add to the parent.
 */
void tvb_add_to_chain(tvbuff_t *parent, tvbuff_t *child);

/**
 * @brief Calculates the offset from the real beginning of a TVBuffer using a counter.
 *
 * @param tvb The TVBuffer for which to calculate the offset.
 * @param counter The counter value to use for calculation.
 * @return The calculated offset from the real beginning of the TVBuffer.
 */
unsigned tvb_offset_from_real_beginning_counter(const tvbuff_t *tvb, const unsigned counter);

/**
 * @brief Validates that an offset and length are within the bounds of a TVBuffer.
 *
 * @param tvb The TVBuffer to validate against.
 * @param offset The starting offset for validation.
 * @param length The length to validate from the offset.
 */
void tvb_validate_offset_length(const tvbuff_t *tvb, const unsigned offset, const unsigned length);

/**
 * @brief Validates that an offset and remaining length are within the bounds of a TVBuffer.
 *
 * @param tvb The TVBuffer to validate against.
 * @param offset The starting offset for validation.
 * @param rem_len Pointer to the remaining length to validate from the offset.
 */
void tvb_validate_offset_and_remaining(const tvbuff_t *tvb, const unsigned offset, unsigned *rem_len);

/**
 * @brief Validates that an offset and length are within the bounds of a tvbuff.
 *
 * @param tvb The tvbuff to check.
 * @param offset The starting offset.
 * @param length_val The length to validate.
 * @param offset_ptr Pointer to store the adjusted offset (if needed).
 * @param length_ptr Pointer to store the adjusted length (if needed).
 */
void tvb_check_offset_length(const tvbuff_t *tvb, const int offset, int const length_val, unsigned *offset_ptr, unsigned *length_ptr);
