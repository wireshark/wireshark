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

#include <glib.h>
#include <ws_attributes.h>
#include <epan/guid-utils.h>
#include <epan/wmem_scopes.h>

#include <wsutil/inet_cidr.h>
#include <wsutil/nstime.h>
#include "wsutil/ws_mempbrk.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * "testy, virtual(-izable) buffer".  They are testy in that they get mad when
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

/** Extracts 'number of bits' starting at 'bit offset'.
 * Returns a pointer to a newly initialized g_malloc'd REAL_DATA
 * tvbuff with the bits octet aligned.
 * Bits are counted from MSB (0) to LSB (7) within octets.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_new_octet_aligned(tvbuff_t *tvb,
    uint32_t bit_offset, int32_t no_of_bits);

/** Extracts 'number of bits' starting at 'bit offset'.
 * Bits are counted from LSB (0) to MSB (7) within octets.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_new_octet_right_aligned(tvbuff_t *tvb,
    uint32_t bit_offset, int32_t no_of_bits);

WS_DLL_PUBLIC tvbuff_t *tvb_new_chain(tvbuff_t *parent, tvbuff_t *backing);

WS_DLL_PUBLIC tvbuff_t *tvb_clone(tvbuff_t *tvb);

WS_DLL_PUBLIC tvbuff_t *tvb_clone_offset_len(tvbuff_t *tvb, unsigned offset,
    unsigned len);

/** Free a tvbuff_t and all tvbuffs chained from it
 * The tvbuff must be 'the 'head' (initial) tvb of a chain or
 * must not be in a chain.
 * If specified, a callback to free the tvbuff data will be invoked
 * for each tvbuff free'd */
WS_DLL_PUBLIC void tvb_free(tvbuff_t *tvb);

/** Free the tvbuff_t and all tvbuffs chained from it.
 * The tvbuff must be 'the 'head' (initial) tvb of a chain or
 * must not be in a chain.
 * If specified, a callback to free the tvbuff data will be invoked
 * for each tvbuff free'd */
WS_DLL_PUBLIC void tvb_free_chain(tvbuff_t *tvb);

/** Set a callback function to call when a tvbuff is actually freed
 * One argument is passed to that callback --- a void* that points
 * to the real data. Obviously, this only applies to a
 * "real" tvbuff. */
WS_DLL_PUBLIC void tvb_set_free_cb(tvbuff_t *tvb, const tvbuff_free_cb_t func);

/** Attach a "real" tvbuff to a parent tvbuff. This connection is used
 * during a tvb_free_chain()... the "child" "real" tvbuff acts as if it
 * is part of the chain-of-creation of the parent tvbuff, although it
 * isn't. This is useful if you need to take the data from some tvbuff,
 * run some operation on it, like decryption or decompression, and make
 * a new tvbuff from it, yet want the new tvbuff to be part of the chain.
 * The reality is that the new tvbuff *is* part of the "chain of creation",
 * but in a way that these tvbuff routines are ignorant of. Use this
 * function to make the tvbuff routines knowledgable of this fact. */
WS_DLL_PUBLIC void tvb_set_child_real_data_tvbuff(tvbuff_t *parent,
    tvbuff_t *child);

WS_DLL_PUBLIC tvbuff_t *tvb_new_child_real_data(tvbuff_t *parent,
    const uint8_t *data, const unsigned length, const int reported_length);

/** Create a tvbuff backed by existing data. Can throw ReportedBoundsError.
 * Normally, a callback to free the data should be registered using
 * tvb_set_free_cb(); when this tvbuff is freed, then your callback will be
 * called, and at that time you can free your original data. */
WS_DLL_PUBLIC tvbuff_t *tvb_new_real_data(const uint8_t *data,
    const unsigned length, const int reported_length);

/** Create a tvbuff that's a subset of another tvbuff, with the captured
 * length explicitly given. You probably want tvb_new_subset_length() or
 * tvb_new_subset_remaining() instead.
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
 * Similar to tvb_new_subset_length_caplen() but with captured length calculated
 * to fit within the existing captured length and the specified
 * reported length.
 * Can throw ReportedBoundsError. */
WS_DLL_PUBLIC tvbuff_t *tvb_new_subset_length(tvbuff_t *backing,
    const int backing_offset, const int reported_length);

/** Similar to tvb_new_subset_length_caplen() but with backing_length and reported_length set
 * to -1.  Can throw ReportedBoundsError. */
WS_DLL_PUBLIC tvbuff_t *tvb_new_subset_remaining(tvbuff_t *backing,
    const int backing_offset);

/*
* Both tvb_composite_append and tvb_composite_prepend can throw
 * BoundsError if member_offset/member_length goes beyond bounds of
 * the 'member' tvbuff. */

/** Append to the list of tvbuffs that make up this composite tvbuff */
WS_DLL_PUBLIC void tvb_composite_append(tvbuff_t *tvb, tvbuff_t *member);

/** Prepend to the list of tvbuffs that make up this composite tvbuff */
extern void tvb_composite_prepend(tvbuff_t *tvb, tvbuff_t *member);

/** Create an empty composite tvbuff. */
WS_DLL_PUBLIC tvbuff_t *tvb_new_composite(void);

/** Mark a composite tvbuff as initialized. No further appends or prepends
 * occur, data access can finally happen after this finalization. */
WS_DLL_PUBLIC void tvb_composite_finalize(tvbuff_t *tvb);


/* Get amount of captured data in the buffer (which is *NOT* necessarily the
 * length of the packet). You probably want tvb_reported_length instead. */
WS_DLL_PUBLIC unsigned tvb_captured_length(const tvbuff_t *tvb);

/** Computes bytes to end of buffer, from offset (which can be negative,
 * to indicate bytes from end of buffer). Function returns 0 if offset is
 * either at the end of the buffer or out of bounds. No exception is thrown.
 * You probably want tvb_reported_length_remaining instead. */
WS_DLL_PUBLIC int tvb_captured_length_remaining(const tvbuff_t *tvb, const int offset);

/** Same as above, but throws an exception if the offset is out of bounds. */
WS_DLL_PUBLIC unsigned tvb_ensure_captured_length_remaining(const tvbuff_t *tvb,
    const int offset);

/* Checks (w/o throwing exception) that the bytes referred to by
 * 'offset'/'length' actually exist in the buffer */
WS_DLL_PUBLIC bool tvb_bytes_exist(const tvbuff_t *tvb, const int offset,
    const int length);

/** Checks that the bytes referred to by 'offset'/'length', where 'length'
 * is a 64-bit unsigned integer, actually exist in the buffer, and throws
 * an exception if they aren't. */
WS_DLL_PUBLIC void tvb_ensure_bytes_exist64(const tvbuff_t *tvb,
    const int offset, const uint64_t length);

/** Checks that the bytes referred to by 'offset'/'length' actually exist
 * in the buffer, and throws an exception if they aren't. */
WS_DLL_PUBLIC void tvb_ensure_bytes_exist(const tvbuff_t *tvb,
    const int offset, const int length);

/* Checks (w/o throwing exception) that offset exists in buffer */
WS_DLL_PUBLIC bool tvb_offset_exists(const tvbuff_t *tvb,
    const int offset);

/* Get reported length of buffer */
WS_DLL_PUBLIC unsigned tvb_reported_length(const tvbuff_t *tvb);

/** Computes bytes of reported packet data to end of buffer, from offset
 * (which can be negative, to indicate bytes from end of buffer). Function
 * returns 0 if offset is either at the end of the buffer or out of bounds.
 * No exception is thrown. */
WS_DLL_PUBLIC int tvb_reported_length_remaining(const tvbuff_t *tvb,
    const int offset);

/** Same as above, but throws an exception if the offset is out of bounds. */
WS_DLL_PUBLIC unsigned tvb_ensure_reported_length_remaining(const tvbuff_t *tvb,
    const int offset);

/** Set the reported length of a tvbuff to a given value; used for protocols
   whose headers contain an explicit length and where the calling
   dissector's payload may include padding as well as the packet for
   this protocol.

   Also adjusts the available and contained length. */
WS_DLL_PUBLIC void tvb_set_reported_length(tvbuff_t *tvb, const unsigned);

/* Repair a tvbuff where the captured length is greater than the
 * reported length; such a tvbuff makes no sense, as it's impossible
 * to capture more data than is in the packet.
 */
WS_DLL_PUBLIC void tvb_fix_reported_length(tvbuff_t *tvb);

WS_DLL_PUBLIC unsigned tvb_offset_from_real_beginning(const tvbuff_t *tvb);

/* Returns the offset from the first byte of real data. */
WS_DLL_PUBLIC int tvb_raw_offset(tvbuff_t *tvb);

/** Set the "this is a fragment" flag. This affects whether
 * FragmentBoundsError is thrown instead of ContainedBoundsError
 * or ReportedBoundsError. */
WS_DLL_PUBLIC void tvb_set_fragment(tvbuff_t *tvb);

WS_DLL_PUBLIC struct tvbuff *tvb_get_ds_tvb(tvbuff_t *tvb);


/************** START OF ACCESSORS ****************/
/* All accessors will throw an exception if appropriate */

WS_DLL_PUBLIC uint8_t tvb_get_uint8(tvbuff_t *tvb, const int offset);
static inline uint8_t tvb_get_guint8(tvbuff_t *tvb, const int offset) { return tvb_get_uint8(tvb, offset); }
WS_DLL_PUBLIC int8_t tvb_get_int8(tvbuff_t *tvb, const int offset);
static inline int8_t tvb_get_gint8(tvbuff_t *tvb, const int offset) { return tvb_get_int8(tvb, offset); }

WS_DLL_PUBLIC uint16_t tvb_get_ntohs(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int16_t tvb_get_ntohis(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint32_t tvb_get_ntoh24(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int32_t tvb_get_ntohi24(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint32_t tvb_get_ntohl(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int32_t tvb_get_ntohil(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint64_t tvb_get_ntoh40(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int64_t tvb_get_ntohi40(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint64_t tvb_get_ntoh48(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int64_t tvb_get_ntohi48(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint64_t tvb_get_ntoh56(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int64_t tvb_get_ntohi56(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint64_t tvb_get_ntoh64(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int64_t tvb_get_ntohi64(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC float tvb_get_ntohieee_float(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC double tvb_get_ntohieee_double(tvbuff_t *tvb,
    const int offset);

WS_DLL_PUBLIC uint16_t tvb_get_letohs(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int16_t tvb_get_letohis(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint32_t tvb_get_letoh24(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int32_t tvb_get_letohi24(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint32_t tvb_get_letohl(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int32_t tvb_get_letohil(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint64_t tvb_get_letoh40(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int64_t tvb_get_letohi40(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint64_t tvb_get_letoh48(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int64_t tvb_get_letohi48(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint64_t tvb_get_letoh56(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int64_t tvb_get_letohi56(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC uint64_t tvb_get_letoh64(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC int64_t tvb_get_letohi64(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC float tvb_get_letohieee_float(tvbuff_t *tvb, const int offset);
WS_DLL_PUBLIC double tvb_get_letohieee_double(tvbuff_t *tvb,
    const int offset);

WS_DLL_PUBLIC uint16_t tvb_get_uint16(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline uint16_t tvb_get_guint16(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_uint16(tvb, offset, encoding); }
WS_DLL_PUBLIC int16_t tvb_get_int16(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline int16_t tvb_get_gint16(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int16(tvb, offset, encoding); }
WS_DLL_PUBLIC uint32_t tvb_get_uint24(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline uint32_t tvb_get_guint24(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_uint24(tvb, offset, encoding); }
WS_DLL_PUBLIC int32_t tvb_get_int24(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline int32_t tvb_get_gint24(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int24(tvb, offset, encoding); }
WS_DLL_PUBLIC uint32_t tvb_get_uint32(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline uint32_t tvb_get_guint32(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_uint32(tvb, offset, encoding); }
WS_DLL_PUBLIC int32_t tvb_get_int32(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline int32_t tvb_get_gint32(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int32(tvb, offset, encoding); }
WS_DLL_PUBLIC uint64_t tvb_get_uint40(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline uint64_t tvb_get_guint40(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_uint40(tvb, offset, encoding); }
WS_DLL_PUBLIC int64_t tvb_get_int40(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline int64_t tvb_get_gint40(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int40(tvb, offset, encoding); }
WS_DLL_PUBLIC uint64_t tvb_get_uint48(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline uint64_t tvb_get_guint48(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_uint48(tvb, offset, encoding); }
WS_DLL_PUBLIC int64_t tvb_get_int48(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline int64_t tvb_get_gint48(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int48(tvb, offset, encoding); }
WS_DLL_PUBLIC uint64_t tvb_get_uint56(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline uint64_t tvb_get_guint56(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_uint56(tvb, offset, encoding); }
WS_DLL_PUBLIC int64_t tvb_get_int56(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline int64_t tvb_get_gint56(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int56(tvb, offset, encoding); }
WS_DLL_PUBLIC uint64_t tvb_get_uint64(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline uint64_t tvb_get_guint64(tvbuff_t *tvb, const int offset, const unsigned encoding) {return tvb_get_uint64(tvb, offset, encoding); }
WS_DLL_PUBLIC int64_t tvb_get_int64(tvbuff_t *tvb, const int offset, const unsigned encoding);
static inline int64_t tvb_get_gint64(tvbuff_t *tvb, const int offset, const unsigned encoding) { return tvb_get_int64(tvb, offset, encoding); }
WS_DLL_PUBLIC float tvb_get_ieee_float(tvbuff_t *tvb, const int offset, const unsigned encoding);
WS_DLL_PUBLIC double tvb_get_ieee_double(tvbuff_t *tvb, const int offset, const unsigned encoding);

/*
 * Fetch 16-bit and 32-bit values in host byte order.
 * Used for some pseudo-headers in pcap/pcapng files, in which the
 * headers are, when capturing, in the byte order of the host, and
 * are converted to the byte order of the host reading the file
 * when reading a capture file.
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


/* Fetch a time value from an ASCII-style string in the tvb.
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

/* Similar to above, but returns a GByteArray based on the case-insensitive
 * hex-char strings with optional separators, and with optional leading spaces.
 * The separators allowed are based on the ENC_SEP_* passed in the encoding param.
 *
 * The passed-in bytes is set to the values, and its pointer is also the return
 * value or NULL on error. The GByteArray bytes must be pre-constructed with
 * g_byte_array_new().
 */
WS_DLL_PUBLIC
GByteArray* tvb_get_string_bytes(tvbuff_t *tvb, const int offset, const int length,
                                 const unsigned encoding, GByteArray* bytes, int *endoff);

/**
 * Fetch an IPv4 address, in network byte order.
 * We do *not* convert it to host byte order; we leave it in
 * network byte order, as that's what its callers expect. */
WS_DLL_PUBLIC uint32_t tvb_get_ipv4(tvbuff_t *tvb, const int offset);

/* Fetch an IPv6 address. */
WS_DLL_PUBLIC void tvb_get_ipv6(tvbuff_t *tvb, const int offset,
    ws_in6_addr *addr);

/**
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
* Fetches an IPv6 address from a tvbuff and
* masks out bits other than those covered by a prefix length
*
* @param tvb tvbuff to read an IPv6 address from
* @param offset offset in the tvbuff to read the IPv6 address from
* @param addr memory location where the IPv6 address read should be stored
* @param prefix_len the length of the prefix (in bits)
* @return the length (in bytes) of the address on success, or -1 on failure
*/
extern int tvb_get_ipv6_addr_with_prefix_len(tvbuff_t *tvb, int offset,
    ws_in6_addr *addr, uint32_t prefix_len);

/* Fetch a GUID. */
WS_DLL_PUBLIC void tvb_get_ntohguid(tvbuff_t *tvb, const int offset,
    e_guid_t *guid);

WS_DLL_PUBLIC void tvb_get_letohguid(tvbuff_t *tvb, const int offset,
    e_guid_t *guid);

WS_DLL_PUBLIC void tvb_get_guid(tvbuff_t *tvb, const int offset,
    e_guid_t *guid, const unsigned encoding);

/* Fetches a byte array given a bit offset in a tvb */
WS_DLL_PUBLIC uint8_t* tvb_get_bits_array(wmem_allocator_t *scope, tvbuff_t *tvb,
    const int offset, size_t length, size_t *data_length, const unsigned encoding);

/* Fetch a specified number of bits from bit offset in a tvb.  All of these
 * functions are equivalent, except for the type of the return value.  Note
 * that the parameter encoding (where supplied) is meaningless and ignored */

/* get 1 - 8 bits returned in a uint8_t */
WS_DLL_PUBLIC uint8_t tvb_get_bits8(tvbuff_t *tvb, unsigned bit_offset,
    const int no_of_bits);

/* get 1 - 16 bits returned in a uint16_t */
WS_DLL_PUBLIC uint16_t tvb_get_bits16(tvbuff_t *tvb, unsigned bit_offset,
    const int no_of_bits, const unsigned encoding);

/* get 1 - 32 bits returned in a uint32_t */
WS_DLL_PUBLIC uint32_t tvb_get_bits32(tvbuff_t *tvb, unsigned bit_offset,
    const int no_of_bits, const unsigned encoding);

/* get 1 - 64 bits returned in a uint64_t */
WS_DLL_PUBLIC uint64_t tvb_get_bits64(tvbuff_t *tvb, unsigned bit_offset,
    const int no_of_bits, const unsigned encoding);

/**
 *  This function has EXACTLY the same behavior as
 *  tvb_get_bits32()
 */
WS_DLL_PUBLIC uint32_t tvb_get_bits(tvbuff_t *tvb, const unsigned bit_offset,
    const int no_of_bits, const unsigned encoding);

/** Returns target for convenience. Does not suffer from possible
 * expense of tvb_get_ptr(), since this routine is smart enough
 * to copy data in chunks if the request range actually exists in
 * different "real" tvbuffs. This function assumes that the target
 * memory is already allocated; it does not allocate or free the
 * target memory. */
WS_DLL_PUBLIC void *tvb_memcpy(tvbuff_t *tvb, void *target, const int offset,
    size_t length);

/** Given an allocator scope, a tvbuff, a byte offset, a byte length:
 *
 *    allocate a buffer using the specified scope;
 *
 *    copy the data from the tvbuff specified by the offset and length
 *    into that buffer, using tvb_memcpy();
 *
 *    and return a pointer to the buffer.
 *
 * Throws an exception if the tvbuff ends before the data being copied does.
 *
 * If scope is set to NULL it is the user's responsibility to wmem_free()
 * the memory allocated. Otherwise memory is automatically freed when the
 * scope lifetime is reached.
 */
WS_DLL_PUBLIC void *tvb_memdup(wmem_allocator_t *scope, tvbuff_t *tvb,
    const int offset, size_t length);

/** WARNING! This function is possibly expensive, temporarily allocating
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
 * tvbuff_free_cb_t() is called, if any. */
WS_DLL_PUBLIC const uint8_t *tvb_get_ptr(tvbuff_t *tvb, const int offset,
    const int length);

/** Find first occurrence of needle in tvbuff, starting at offset. Searches
 * at most maxlength number of bytes; if maxlength is -1, searches to
 * end of tvbuff.
 * Returns the offset of the found needle, or -1 if not found.
 * Will not throw an exception, even if maxlength exceeds boundary of tvbuff;
 * in that case, -1 will be returned if the boundary is reached before
 * finding needle. */
WS_DLL_PUBLIC int tvb_find_guint8(tvbuff_t *tvb, const int offset,
    const int maxlength, const uint8_t needle);

/** Same as tvb_find_guint8() with 16bit needle. */
WS_DLL_PUBLIC int tvb_find_guint16(tvbuff_t *tvb, const int offset,
    const int maxlength, const uint16_t needle);

/** Find first occurrence of any of the needles of the pre-compiled pattern in
 * tvbuff, starting at offset. The passed in pattern must have been "compiled"
 * before-hand, using ws_mempbrk_compile().
 * Searches at most maxlength number of bytes. Returns the offset of the
 * found needle, or -1 if not found and the found needle.
 * Will not throw an exception, even if
 * maxlength exceeds boundary of tvbuff; in that case, -1 will be returned if
 * the boundary is reached before finding needle. */
WS_DLL_PUBLIC int tvb_ws_mempbrk_pattern_guint8(tvbuff_t *tvb, const int offset,
    const int maxlength, const ws_mempbrk_pattern* pattern, unsigned char *found_needle);


/** Find size of stringz (NUL-terminated string) by looking for terminating
 * NUL.  The size of the string includes the terminating NUL.
 *
 * If the NUL isn't found, it throws the appropriate exception.
 */
WS_DLL_PUBLIC unsigned tvb_strsize(tvbuff_t *tvb, const int offset);

/** Find size of UCS-2 or UTF-16 stringz (NUL-terminated string) by
 * looking for terminating 16-bit NUL.  The size of the string includes
 * the terminating NUL.
 *
 * If the NUL isn't found, it throws the appropriate exception.
 */
WS_DLL_PUBLIC unsigned tvb_unicode_strsize(tvbuff_t *tvb, const int offset);

/** Find length of string by looking for end of zero terminated string, up to
 * 'maxlength' characters'; if 'maxlength' is -1, searches to end
 * of tvbuff.
 * Returns -1 if 'maxlength' reached before finding EOS. */
WS_DLL_PUBLIC int tvb_strnlen(tvbuff_t *tvb, const int offset,
    const unsigned maxlength);

/**
 * Format the data in the tvb from offset for size.
 */
WS_DLL_PUBLIC char *tvb_format_text(wmem_allocator_t *scope, tvbuff_t *tvb, const int offset,
    const int size);

/**
 * Like "tvb_format_text()", but for 'wsp'; don't show
 * the characters as C-style escapes.
 */
WS_DLL_PUBLIC char *tvb_format_text_wsp(wmem_allocator_t* allocator, tvbuff_t *tvb, const int offset,
    const int size);

/**
 * Like "tvb_format_text()", but for null-padded strings; don't show
 * the null padding characters as "\000".
 */
extern char *tvb_format_stringzpad(wmem_allocator_t *scope, tvbuff_t *tvb, const int offset,
    const int size);

/**
 * Like "tvb_format_text_wsp()", but for null-padded strings; don't show
 * the null padding characters as "\000".
 */
extern char *tvb_format_stringzpad_wsp(wmem_allocator_t* allocator, tvbuff_t *tvb, const int offset,
    const int size);

/**
 * Given an allocator scope, a tvbuff, a byte offset, a byte length, and
 * a string encoding, with the specified offset and length referring to
 * a string in the specified encoding:
 *
 *    allocate a buffer using the specified scope;
 *
 *    convert the string from the specified encoding to UTF-8, possibly
 *    mapping some characters or invalid octet sequences to the Unicode
 *    REPLACEMENT CHARACTER, and put the resulting UTF-8 string, plus a
 *    trailing '\0', into that buffer;
 *
 *    and return a pointer to the buffer.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * If scope is set to NULL it is the user's responsibility to wmem_free()
 * the memory allocated. Otherwise memory is automatically freed when the
 * scope lifetime is reached.
 */
WS_DLL_PUBLIC uint8_t *tvb_get_string_enc(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, const int length, const unsigned encoding);

/**
 * Given an allocator scope, a tvbuff, a bit offset, and a length in
 * 7-bit characters (not octets!), with the specified offset and
 * length referring to a string in the 3GPP TS 23.038 7bits encoding,
 * with code points packed into 7 bits:
 *
 *    allocate a buffer using the specified scope;
 *
 *    convert the string from the specified encoding to UTF-8, possibly
 *    mapping some characters or invalid octet sequences to the Unicode
 *    REPLACEMENT CHARACTER, and put the resulting UTF-8 string, plus a
 *    trailing '\0', into that buffer;
 *
 *    and return a pointer to the buffer.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * If scope is set to NULL it is the user's responsibility to wmem_free()
 * the memory allocated. Otherwise memory is automatically freed when the
 * scope lifetime is reached.
 */
WS_DLL_PUBLIC char *tvb_get_ts_23_038_7bits_string_packed(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int bit_offset, int no_of_chars);

/**
 * Given an allocator scope, a tvbuff, an offset, and a length in
 * octets with the specified offset and length referring to a string
 * in the 3GPP TS 23.038 7bits encoding, with one octet per code poiint
 * (the 8th bit of each octet should be 0; if not, the octet is invalid):
 *
 *    allocate a buffer using the specified scope;
 *
 *    convert the string from the specified encoding to UTF-8, possibly
 *    mapping some characters or invalid octet sequences to the Unicode
 *    REPLACEMENT CHARACTER, and put the resulting UTF-8 string, plus a
 *    trailing '\0', into that buffer;
 *
 *    and return a pointer to the buffer.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * If scope is set to NULL it is the user's responsibility to wmem_free()
 * the memory allocated. Otherwise memory is automatically freed when the
 * scope lifetime is reached.
 */
WS_DLL_PUBLIC char *tvb_get_ts_23_038_7bits_string_unpacked(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, int length);

/**
 * Given an allocator scope, a tvbuff, an offset, and a length in
 * octets with the specified offset and length referring to a string
 * in the ETSI TS 102 221 Annex A encodings; if not:
 *
 *    allocate a buffer using the specified scope;
 *
 *    convert the string from the specified encoding to UTF-8, possibly
 *    mapping some characters or invalid octet sequences to the Unicode
 *    REPLACEMENT CHARACTER, and put the resulting UTF-8 string, plus a
 *    trailing '\0', into that buffer;
 *
 *    and return a pointer to the buffer.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * If scope is set to NULL it is the user's responsibility to wmem_free()
 * the memory allocated. Otherwise memory is automatically freed when the
 * scope lifetime is reached.
 */
WS_DLL_PUBLIC char *tvb_get_etsi_ts_102_221_annex_a_string(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, int length);

/**
 * Given an allocator scope, a tvbuff, an offset, and a length in
 * 7-bit characters (not octets!), with the specified offset and
 * length referring to a string in the ASCII 7bits encoding:
 *
 *    allocate a buffer using the specified scope;
 *
 *    convert the string from the specified encoding to UTF-8, possibly
 *    mapping some characters or invalid octet sequences to the Unicode
 *    REPLACEMENT CHARACTER, and put the resulting UTF-8 string, plus a
 *    trailing '\0', into that buffer;
 *
 *    and return a pointer to the buffer.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * If scope is set to NULL it is the user's responsibility to wmem_free()
 * the memory allocated. Otherwise memory is automatically freed when the
 * scope lifetime is reached.
 */
WS_DLL_PUBLIC char *tvb_get_ascii_7bits_string(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int bit_offset, int no_of_chars);

/**
 * Given an allocator scope, a tvbuff, a byte offset, a byte length, and
 * a string encoding, with the specified offset and length referring to
 * a null-padded string in the specified encoding:
 *
 *    allocate a buffer using the specified scope;
 *
 *    convert the string from the specified encoding to UTF-8, possibly
 *    mapping some characters or invalid octet sequences to the Unicode
 *    REPLACEMENT CHARACTER, and put the resulting UTF-8 string, plus a
 *    trailing '\0', into that buffer;
 *
 *    and return a pointer to the buffer.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * If scope is set to NULL it is the user's responsibility to wmem_free()
 * the memory allocated. Otherwise memory is automatically freed when the
 * scope lifetime is reached.
 */
WS_DLL_PUBLIC uint8_t *tvb_get_stringzpad(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, const int length, const unsigned encoding);

/**
 * Given an allocator scope, a tvbuff, a byte offset, a pointer to a
 * int, and a string encoding, with the specified offset referring to
 * a null-terminated string in the specified encoding:
 *
 *    find the length of that string (and throw an exception if the tvbuff
 *    ends before we find the null);
 *
 *    allocate a buffer using the specified scope;
 *
 *    convert the string from the specified encoding to UTF-8, possibly
 *    mapping some characters or invalid octet sequences to the Unicode
 *    REPLACEMENT CHARACTER, and put the resulting UTF-8 string, plus a
 *    trailing '\0', into that buffer;
 *
 *    if the pointer to the int is non-null, set the int to which it
 *    points to the length of the string;
 *
 *    and return a pointer to the buffer.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * If scope is set to NULL it is the user's responsibility to wmem_free()
 * the memory allocated. Otherwise memory is automatically freed when the
 * scope lifetime is reached.
 */
WS_DLL_PUBLIC uint8_t *tvb_get_stringz_enc(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, int *lengthp, const unsigned encoding);

/**
 * Given a tvbuff and an offset, with the offset assumed to refer to
 * a null-terminated string, find the length of that string (and throw
 * an exception if the tvbuff ends before we find the null), allocate
 * a buffer big enough to hold the string, copy the string into it,
 * and return a pointer to the string.  Also return the length of the
 * string (including the terminating null) through a pointer.
 *
 * This returns a constant (unmodifiable) string that does not need
 * to be freed; instead, it will automatically be freed once the next
 * packet is dissected.
 *
 * It is slightly more efficient than the other routines, but does *NOT*
 * do any translation to UTF-8 - the string consists of the raw octets
 * of the string, in whatever encoding they happen to be in, and, if
 * the string is not valid in that encoding, with invalid octet sequences
 * as they are in the packet.
 *
 * This function is deprecated because it does no validation of the string
 * encoding. Do not use in new code. Prefer other APIs such as:
 * 	tvb_get_stringz_enc()
 * 	proto_tree_add_item_ret_string_and_length()
 * 	tvb_strsize() and validate the pointed to memory region manually.
 */
WS_DLL_PUBLIC
WS_DEPRECATED_X("Use APIs that return a valid UTF-8 string instead")
const uint8_t *tvb_get_const_stringz(tvbuff_t *tvb,
    const int offset, int *lengthp);

/** Looks for a NUL byte in tvbuff and copies
 * no more than bufsize number of bytes, including terminating NUL, to buffer.
 * Returns number of bytes copied (not including terminating NUL).
 *
 * When processing a packet where the remaining number of bytes is less
 * than bufsize, an exception is not thrown if the end of the packet
 * is reached before the NUL is found. The byte buffer is guaranteed to
 * have a terminating NUL.
 */
WS_DLL_PUBLIC int tvb_get_raw_bytes_as_stringz(tvbuff_t *tvb, const int offset,
    const unsigned bufsize, uint8_t *buffer);

/*
 * Given a tvbuff, an offset into the tvbuff, a buffer, and a buffer size,
 * extract as many raw bytes from the tvbuff, starting at the offset,
 * as 1) are available in the tvbuff and 2) will fit in the buffer, leaving
 * room for a terminating NUL.
 */
WS_DLL_PUBLIC int tvb_get_raw_bytes_as_string(tvbuff_t *tvb, const int offset, char *buffer, size_t bufsize);

/** Iterates over the provided portion of the tvb checking that each byte
* is an ascii printable character.
* Returns true if all bytes are printable, false otherwise
*/
WS_DLL_PUBLIC bool tvb_ascii_isprint(tvbuff_t *tvb, const int offset,
	const int length);

/** Iterates over the provided portion of the tvb checking that it is
* valid UTF-8 consisting entirely of printable characters. (The characters
* must be complete; if the portion ends in a partial sequence that could
* begin a valid character, this returns false.) The length may be -1 for
* "all the way to the end of the tvbuff".
* Returns true if printable, false otherwise
*
* @see isprint_utf8_string()
*/
WS_DLL_PUBLIC bool tvb_utf_8_isprint(tvbuff_t *tvb, const int offset,
	const int length);

/** Iterates over the provided portion of the tvb checking that each byte
* is an ascii digit.
* Returns true if all bytes are digits, false otherwise
*/
WS_DLL_PUBLIC bool tvb_ascii_isdigit(tvbuff_t *tvb, const int offset,
	const int length);

/**
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset (which may be -1 for "all the way to the end of the
 * tvbuff"), find the end of the (putative) line that starts at the
 * specified offset in the tvbuff, going no further than the specified
 * length.
 *
 * Return the length of the line (not counting the line terminator at
 * the end), or, if we don't find a line terminator:
 *
 *  if "deseg" is true, return -1;
 *
 *  if "deseg" is false, return the amount of data remaining in
 *  the buffer.
 *
 * If "next_offset" is not NULL, set "*next_offset" to the offset of the
 * character past the line terminator, or past the end of the buffer if
 * we don't find a line terminator.  (It's not set if we return -1.)
 */
WS_DLL_PUBLIC int tvb_find_line_end(tvbuff_t *tvb, const int offset, int len,
    int *next_offset, const bool desegment);

/**
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset (which may be -1 for "all the way to the end of the
 * tvbuff"), find the end of the (putative) line that starts at the
 * specified offset in the tvbuff, going no further than the specified
 * length.
 *
 * However, treat quoted strings inside the buffer specially - don't
 * treat newlines in quoted strings as line terminators.
 *
 * Return the length of the line (not counting the line terminator at
 * the end), or the amount of data remaining in the buffer if we don't
 * find a line terminator.
 *
 * If "next_offset" is not NULL, set "*next_offset" to the offset of the
 * character past the line terminator, or past the end of the buffer if
 * we don't find a line terminator.
 */
WS_DLL_PUBLIC int tvb_find_line_end_unquoted(tvbuff_t *tvb, const int offset,
    int len, int *next_offset);

/**
 * Copied from the mgcp dissector. (This function should be moved to /epan )
 * tvb_skip_wsp - Returns the position in tvb of the first non-whitespace
 *                character following offset or offset + maxlength -1 whichever
 *                is smaller.
 *
 * Parameters:
 * tvb - The tvbuff in which we are skipping whitespace.
 * offset - The offset in tvb from which we begin trying to skip whitespace.
 * maxlength - The maximum distance from offset that we may try to skip
 * whitespace.
 *
 * Returns: The position in tvb of the first non-whitespace
 *          character following offset or offset + maxlength -1 whichever
 *          is smaller.
 */

WS_DLL_PUBLIC int tvb_skip_wsp(tvbuff_t *tvb, const int offset,
    const int maxlength);

WS_DLL_PUBLIC int tvb_skip_wsp_return(tvbuff_t *tvb, const int offset);

int tvb_skip_guint8(tvbuff_t *tvb, int offset, const int maxlength, const uint8_t ch);

/**
* Given a tvbuff, an offset into the tvbuff, and a length that starts
* at that offset (which may be -1 for "all the way to the end of the
* tvbuff"), find the end of the token that starts at the
* specified offset in the tvbuff, going no further than the specified
* length.
*
* Return the length of the token, or, if we don't find a terminator:
*
*  if "deseg" is true, return -1;
*
*  if "deseg" is false, return the amount of data remaining in
*  the buffer.
*
* Set "*next_offset" to the offset of the character past the
* terminator, or past the end of the buffer if we don't find a line
* terminator.  (It's not set if we return -1.)
*/
WS_DLL_PUBLIC int tvb_get_token_len(tvbuff_t *tvb, const int offset, int len, int *next_offset, const bool desegment);

/**
 * Call strncmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
WS_DLL_PUBLIC int tvb_strneql(tvbuff_t *tvb, const int offset,
    const char *str, const size_t size);

/**
 * Call g_ascii_strncasecmp after checking if enough chars left, returning
 * 0 if it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
WS_DLL_PUBLIC int tvb_strncaseeql(tvbuff_t *tvb, const int offset,
    const char *str, const size_t size);

/**
 * Call memcmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
WS_DLL_PUBLIC int tvb_memeql(tvbuff_t *tvb, const int offset,
    const uint8_t *str, size_t size);

/**
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data, with "punct" as a byte
 * separator.
 */
WS_DLL_PUBLIC char *tvb_bytes_to_str_punct(wmem_allocator_t *scope, tvbuff_t *tvb, const int offset,
    const int len, const char punct);

/**
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data.
 */
WS_DLL_PUBLIC char *tvb_bytes_to_str(wmem_allocator_t *allocator, tvbuff_t *tvb,
    const int offset, const int len);

/**
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset (which may be -1 for "all the way to the end of the
 * tvbuff"), fetch BCD encoded digits from a tvbuff starting from either
 * the low or high half byte, formatting the digits according to an input digit
 * set, if NUL a default digit set of 0-9 returning "?" for overdecadic digits
 * will be used.  A pointer to the WMEM-allocated string will
 * be returned. Note a tvbuff content of 0xf is considered a 'filler' and will
 * end the conversion.
 */
typedef struct dgt_set_t
{
    const unsigned char out[16];
}
dgt_set_t;

WS_DLL_PUBLIC const char *tvb_bcd_dig_to_str(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, const int len, const dgt_set_t *dgt,
    bool skip_first);

/**
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset (which may be -1 for "all the way to the end of the
 * tvbuff"), fetch BCD encoded digits from a tvbuff starting from either
 * the low or high half byte, formatting the digits according to an input digit
 * set, if NUL a default digit set of 0-9 returning "?" for overdecadic digits
 * will be used.  A pointer to the WMEM-allocated string will
 * be returned. Note a tvbuff content of 0xf is considered a 'filler' and will
 * end the conversion. Function uses big endian convetion: first digit is based
 * on high order nibble, second digit is based on low order nibble.
 */
WS_DLL_PUBLIC const char *tvb_bcd_dig_to_str_be(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, const int len, const dgt_set_t *dgt,
    bool skip_first);

/**
 * Given a wmem scope, a tvbuff, an offset, a length, an input digit
 * set, and a boolean indicator, fetch BCD-encoded digits from a
 * tvbuff starting from either the low or high half byte of the
 * first byte depending on the boolean indicator (true means "start
 * with the high half byte, ignoring the low half byte", and false
 * means "start with the low half byte and proceed to the high half
 * byte), formating the digits into characters according to the
 * input digit set, and return a pointer to a UTF-8 string, allocated
 * using the wmem scope.  A high-order nibble of 0xf is considered a
 * 'filler' and will end the conversion. If odd is set the high order
 * nibble in the last octet will be skipped. If bigendian is set then
 * high order nibble is taken as first digit of a byte and low order
 * nibble as second digit.
 */
WS_DLL_PUBLIC char *tvb_get_bcd_string(wmem_allocator_t *scope, tvbuff_t *tvb,
    const int offset, int len, const dgt_set_t *dgt,
    bool skip_first, bool odd, bool bigendian);

/** Locate a sub-tvbuff within another tvbuff, starting at position
 * 'haystack_offset'. Returns the index of the beginning of 'needle' within
 * 'haystack', or -1 if 'needle' is not found. The index is relative
 * to the start of 'haystack', not 'haystack_offset'. */
WS_DLL_PUBLIC int tvb_find_tvb(tvbuff_t *haystack_tvb, tvbuff_t *needle_tvb,
    const int haystack_offset);

/* From tvbuff_zlib.c */

WS_DEPRECATED_X("Use tvb_uncompress_zlib instead")
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress(tvbuff_t *tvb, const int offset,
    int comprlen);

/**
 * Uncompresses a zlib compressed packet inside a tvbuff at offset with
 * length comprlen.  Returns an uncompressed tvbuffer if uncompression
 * succeeded or NULL if uncompression failed.
 *
 * The returned tvbuffer must be freed with `tvb_free` or added to the
 * chain of another tvbuffer to avoid a memory leak. Consider using
 * tvb_child_uncompress to simplify memory management.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_zlib(tvbuff_t *tvb, const int offset,
    int comprlen);

WS_DEPRECATED_X("Use tvb_child_uncompress_zlib instead")
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress(tvbuff_t *parent, tvbuff_t *tvb,
    const int offset, int comprlen);

/**
 * Uncompresses a zlib compressed packet inside a tvbuff at offset with
 * length comprlen.  Returns an uncompressed tvbuffer attached to parent if
 * uncompression succeeded or NULL if uncompression failed.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_zlib(tvbuff_t *parent, tvbuff_t *tvb,
    const int offset, int comprlen);

/* From tvbuff_brotli.c */

/**
 * Uncompresses a brotli compressed packet inside a tvbuff at offset with
 * length comprlen.  Returns an uncompressed tvbuffer if uncompression
 * succeeded or NULL if uncompression failed.
 *
 * The returned tvbuffer must be freed with `tvb_free` or added to the
 * chain of another tvbuffer to avoid a memory leak. Consider using
 * tvb_child_uncompress_brotli to simplify memory management.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_brotli(tvbuff_t *tvb, const int offset,
    int comprlen);

/**
 * Uncompresses a brotli compressed packet inside a tvbuff at offset with
 * length comprlen.  Returns an uncompressed tvbuffer attached to parent if
 * uncompression succeeded or NULL if uncompression failed.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_brotli(tvbuff_t *parent, tvbuff_t *tvb,
    const int offset, int comprlen);

/* From tvbuff_snappy.c */

/**
 * Uncompresses a snappy compressed packet inside a tvbuff at offset with
 * length comprlen.  Returns an uncompressed tvbuffer if uncompression
 * succeeded or NULL if uncompression failed.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_snappy(tvbuff_t *tvb, const int offset,
    int comprlen);

/**
 * Uncompresses a snappy compressed packet inside a tvbuff at offset with
 * length comprlen.  Returns an uncompressed tvbuffer attached to tvb if
 * uncompression succeeded or NULL if uncompression failed.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_snappy(tvbuff_t *parent, tvbuff_t *tvb,
    const int offset, int comprlen);

/* From tvbuff_lz77.c */

/**
 * Uncompresses a Microsoft Plain LZ77 compressed payload inside a
 * tvbuff at offset with length comprlen.  Returns an uncompressed
 * tvbuffer if uncompression succeeded or NULL if uncompression
 * failed.
 *
 * The returned tvbuffer must be freed with `tvb_free` or added to the
 * chain of another tvbuffer to avoid a memory leak. Consider using
 * tvb_child_uncompress_lz77 to simplify memory management.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_lz77(tvbuff_t *tvb,
    const int offset, int comprlen);

/**
 * Uncompresses a Microsoft Plain LZ77 compressed payload inside a
 * tvbuff at offset with length comprlen.  Returns an uncompressed
 * tvbuffer attached to parent if uncompression succeeded or NULL if
 * uncompression failed.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_lz77(tvbuff_t *parent,
     tvbuff_t *tvb, const int offset, int comprlen);

/* From tvbuff_lz77huff.c */

/**
 * Uncompresses a Microsoft LZ77+Huffman compressed payload inside a
 * tvbuff at offset with length comprlen.  Returns an uncompressed
 * tvbuffer if uncompression succeeded or NULL if uncompression
 * failed.
 *
 * The returned tvbuffer must be freed with `tvb_free` or added to the
 * chain of another tvbuffer to avoid a memory leak. Consider using
 * tvb_child_uncompress_lz77huff to simplify memory management.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_lz77huff(tvbuff_t *tvb,
    const int offset, int comprlen);

/**
 * Uncompresses a Microsoft LZ77+Huffman compressed payload inside a
 * tvbuff at offset with length comprlen.  Returns an uncompressed
 * tvbuffer attached to parent if uncompression succeeded or NULL if
 * uncompression failed.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_lz77huff(tvbuff_t *parent,
    tvbuff_t *tvb, const int offset, int comprlen);

/* From tvbuff_lznt1.c */

/**
 * Uncompresses a Microsoft LZNT1 compressed payload inside
 * a tvbuff at offset with length comprlen.  Returns an uncompressed
 * tvbuffer if uncompression succeeded or NULL if uncompression
 * failed.
 *
 * The returned tvbuffer must be freed with `tvb_free` or added to the
 * chain of another tvbuffer to avoid a memory leak. Consider using
 * tvb_child_uncompress_lznt1 to simplify memory management.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_lznt1(tvbuff_t *tvb,
    const int offset, int comprlen);

/**
 * Uncompresses a Microsoft LZNT1 compressed payload inside
 * a tvbuff at offset with length comprlen.  Returns an uncompressed
 * tvbuffer attached to parent if uncompression succeeded or NULL if
 * uncompression failed.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_lznt1(tvbuff_t *parent,
    tvbuff_t *tvb, const int offset, int comprlen);

/**
 * Uncompresses a ZSTD compressed payload inside a
 * tvbuff at offset with length comprlen.  Returns an uncompressed
 * tvbuffer if uncompression succeeded or NULL if uncompression
 * failed.
 *
 * The returned tvbuffer must be freed with `tvb_free` or added to the
 * chain of another tvbuffer to avoid a memory leak. Consider using
 * tvb_child_uncompress_zstd to simplify memory management.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress_zstd(tvbuff_t *tvb,
    const int offset, int comprlen);

/**
 * Uncompresses a ZSTD compressed payload inside a
 * tvbuff at offset with length comprlen.  Returns an uncompressed
 * tvbuffer attached to parent if uncompression succeeded or NULL
 * if uncompression failed.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress_zstd(tvbuff_t *parent,
    tvbuff_t *tvb, const int offset, int comprlen);

/* From tvbuff_base64.c */

/** Return a tvb that contains the binary representation of a base64
 *  string as a child of the indicated tvb.
 *
 * @param parent The parent tvbuff.
 * @param base64 The base64 encoded string which binary representation will be
 *               returned in the child tvb.
 *
 * @return   A tvb with the binary representation of the base64 decoded string.
 */
extern tvbuff_t* base64_to_tvb(tvbuff_t *parent, const char *base64);


/** Return a tvb that contains the binary representation of a base64
 *  encoded string in the parent tvb as a child of the indicated tvb.
 *
 * @param parent The parent tvbuff.
 * @param offset Start of the base64 string in the tvb
 * @param length Length of the base64 string in the tvb
 *
 * @return   A tvb with the binary representation of the base64 decoded string.
 */
extern tvbuff_t* base64_tvb_to_new_tvb(tvbuff_t* parent, int offset, int length);

extern tvbuff_t* base64uri_tvb_to_new_tvb(tvbuff_t* parent, int offset, int length);

/* From tvbuff_hpackhuff.c */

WS_DLL_PUBLIC wmem_strbuf_t* tvb_get_hpack_huffman_strbuf(wmem_allocator_t *scope,
    tvbuff_t *tvb, const int offset, const int len);

WS_DLL_PUBLIC tvbuff_t* tvb_child_uncompress_hpack_huff(tvbuff_t *parent,
    int offset, int length);

/**
 * Extract a variable length integer from a tvbuff.
 * Each byte in a varint, except the last byte, has the most significant bit (msb)
 * set -- this indicates that there are further bytes to come. For example,
 *   1010 1100 0000 0010 is 300
 *
 * @param tvb The tvbuff in which we are extracting integer.
 * @param offset The offset in tvb from which we begin trying to extract integer.
 * @param maxlen The maximum distance from offset that we may try to extract integer
 * @param value  if parsing succeeds, parsed varint will store here.
 * @param encoding The ENC_* that defines the format (e.g., ENC_VARINT_PROTOBUF, ENC_VARINT_QUIC, ENC_VARINT_ZIGZAG, ENC_VARINT_SDNV)
 * @return   the length of this varint in tvb. 0 means parsing failed.
 */
WS_DLL_PUBLIC unsigned tvb_get_varint(tvbuff_t *tvb, unsigned offset, unsigned maxlen, uint64_t *value, const unsigned encoding);

/************** END OF ACCESSORS ****************/

/** @} */

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
