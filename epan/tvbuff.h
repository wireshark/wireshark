/* tvbuff.h
 *
 * Testy, Virtual(-izable) Buffer of guint8*'s
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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __TVBUFF_H__
#define __TVBUFF_H__

#include <glib.h>
#include <epan/guid-utils.h>
#include <epan/wmem/wmem.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
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

struct e_in6_addr; /* ipv6-utils.h */
struct nstime_t;   /* nstime.h */

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
 *    tvb handed to the dissector using tvb_new_subset(),
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
 *
 *    dissector is free to manage as desired.
 * @{
 */

/** TVBUFF_REAL_DATA contains a guint8* that points to real data.
 * The data is allocated and contiguous.
 *
 * TVBUFF_SUBSET has a backing tvbuff. The TVBUFF_SUBSET is a "window"
 * through which the program sees only a portion of the backing tvbuff.
 *
 * TVBUFF_COMPOSITE combines multiple tvbuffs sequentially to produce
 * a larger byte array.
 *
 * tvbuff's of any type can be used as the backing-tvbuff of a
 * TVBUFF_SUBSET or as the member of a TVBUFF_COMPOSITE.
 * TVBUFF_COMPOSITEs can have member-tvbuffs of different types.
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
 */
WS_DLL_PUBLIC tvbuff_t *tvb_new_octet_aligned(tvbuff_t *tvb,
    guint32 bit_offset, gint32 no_of_bits);

WS_DLL_PUBLIC tvbuff_t *tvb_new_chain(tvbuff_t *parent, tvbuff_t *backing);

WS_DLL_PUBLIC tvbuff_t *tvb_clone(tvbuff_t *tvb);

WS_DLL_PUBLIC tvbuff_t *tvb_clone_offset_len(tvbuff_t *tvb, guint offset,
    guint len);

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
 * TVBUFF_REAL_DATA tvbuff. */
WS_DLL_PUBLIC void tvb_set_free_cb(tvbuff_t *tvb, const tvbuff_free_cb_t func);

/** Attach a TVBUFF_REAL_DATA tvbuff to a parent tvbuff. This connection
 * is used during a tvb_free_chain()... the "child" TVBUFF_REAL_DATA acts
 * as if it is part of the chain-of-creation of the parent tvbuff, although it
 * isn't. This is useful if you need to take the data from some tvbuff,
 * run some operation on it, like decryption or decompression, and make a new
 * tvbuff from it, yet want the new tvbuff to be part of the chain. The reality
 * is that the new tvbuff *is* part of the "chain of creation", but in a way
 * that these tvbuff routines are ignorant of. Use this function to make
 * the tvbuff routines knowledgable of this fact. */
WS_DLL_PUBLIC void tvb_set_child_real_data_tvbuff(tvbuff_t *parent,
    tvbuff_t *child);

WS_DLL_PUBLIC tvbuff_t *tvb_new_child_real_data(tvbuff_t *parent,
    const guint8 *data, const guint length, const gint reported_length);

/** Create a tvbuff backed by existing data. Can throw ReportedBoundsError.
 * Normally, a callback to free the data should be registered using
 * tvb_set_free_cb(); when this tvbuff is freed, then your callback will be
 * called, and at that time you can free your original data. */
WS_DLL_PUBLIC tvbuff_t *tvb_new_real_data(const guint8 *data,
    const guint length, const gint reported_length);

/** Create a tvbuff that's a subset of another tvbuff.
 *
 * 'backing_offset', if positive, is the offset from the beginning of
 * the backing tvbuff at which the new tvbuff's data begins, and, if
 * negative, is the offset from the end of the backing tvbuff at which
 * the new tvbuff's data begins.
 *
 * 'backing_length' is the length of the data to include in the new
 * tvbuff, starting with the byte at 'backing_offset"; if -1, it
 * means "to the end of the backing tvbuff".  It can be 0, although
 * the usefulness of the buffer would be rather limited.
 *
 * Will throw BoundsError if 'backing_offset'/'length'
 * is beyond the bounds of the backing tvbuff.
 * Can throw ReportedBoundsError. */
WS_DLL_PUBLIC tvbuff_t *tvb_new_subset(tvbuff_t *backing,
    const gint backing_offset, const gint backing_length,
    const gint reported_length);

/**
 * Similar to tvb_new_subset() but with captured length calculated
 * to fit within the existing captured length and the specified
 * backing length (which is used as the reported length).
 * Can throw ReportedBoundsError. */
WS_DLL_PUBLIC tvbuff_t *tvb_new_subset_length(tvbuff_t *backing,
    const gint backing_offset, const gint backing_length);

/** Similar to tvb_new_subset() but with backing_length and reported_length set
 * to -1.  Can throw ReportedBoundsError. */
WS_DLL_PUBLIC tvbuff_t *tvb_new_subset_remaining(tvbuff_t *backing,
    const gint backing_offset);

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
WS_DLL_PUBLIC guint tvb_captured_length(const tvbuff_t *tvb);

/* DEPRECATED, do not use in new code, call tvb_captured_length directly! */
#define tvb_length tvb_captured_length

/** Computes bytes to end of buffer, from offset (which can be negative,
 * to indicate bytes from end of buffer). Function returns 0 if offset is
 * either at the end of the buffer or out of bounds. No exception is thrown.
 * You probably want tvb_reported_length_remaining instead. */
WS_DLL_PUBLIC gint tvb_captured_length_remaining(const tvbuff_t *tvb, const gint offset);

/* DEPRECATED, do not use in new code, call tvb_captured_length_remaining directly! */
#define tvb_length_remaining tvb_captured_length_remaining

/** Same as above, but throws an exception if the offset is out of bounds. */
WS_DLL_PUBLIC guint tvb_ensure_captured_length_remaining(const tvbuff_t *tvb,
    const gint offset);

/* DEPRECATED, do not use in new code, call tvb_ensure_captured_length_remaining directly! */
#define tvb_ensure_length_remaining tvb_ensure_captured_length_remaining

/* Checks (w/o throwing exception) that the bytes referred to by
 * 'offset'/'length' actually exist in the buffer */
WS_DLL_PUBLIC gboolean tvb_bytes_exist(const tvbuff_t *tvb, const gint offset,
    const gint length);

/** Checks that the bytes referred to by 'offset'/'length' actually exist
 * in the buffer, and throws an exception if they aren't. */
WS_DLL_PUBLIC void tvb_ensure_bytes_exist(const tvbuff_t *tvb,
    const gint offset, const gint length);

/* Checks (w/o throwing exception) that offset exists in buffer */
WS_DLL_PUBLIC gboolean tvb_offset_exists(const tvbuff_t *tvb,
    const gint offset);

/* Get reported length of buffer */
WS_DLL_PUBLIC guint tvb_reported_length(const tvbuff_t *tvb);

/** Computes bytes of reported packet data to end of buffer, from offset
 * (which can be negative, to indicate bytes from end of buffer). Function
 * returns 0 if offset is either at the end of the buffer or out of bounds.
 * No exception is thrown. */
WS_DLL_PUBLIC gint tvb_reported_length_remaining(const tvbuff_t *tvb,
    const gint offset);

/** Set the reported length of a tvbuff to a given value; used for protocols
   whose headers contain an explicit length and where the calling
   dissector's payload may include padding as well as the packet for
   this protocol.

   Also adjusts the data length. */
WS_DLL_PUBLIC void tvb_set_reported_length(tvbuff_t *tvb, const guint);

WS_DLL_PUBLIC guint tvb_offset_from_real_beginning(const tvbuff_t *tvb);

/* Returns the offset from the first byte of real data. */
WS_DLL_PUBLIC gint tvb_raw_offset(tvbuff_t *tvb);

/** Set the "this is a fragment" flag. */
WS_DLL_PUBLIC void tvb_set_fragment(tvbuff_t *tvb);

WS_DLL_PUBLIC struct tvbuff *tvb_get_ds_tvb(tvbuff_t *tvb);


/************** START OF ACCESSORS ****************/
/* All accessors will throw an exception if appropriate */

WS_DLL_PUBLIC guint8 tvb_get_guint8(tvbuff_t *tvb, const gint offset);

WS_DLL_PUBLIC guint16 tvb_get_ntohs(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint32 tvb_get_ntoh24(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint32 tvb_get_ntohl(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint64 tvb_get_ntoh40(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gint64 tvb_get_ntohi40(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint64 tvb_get_ntoh48(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gint64 tvb_get_ntohi48(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint64 tvb_get_ntoh56(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gint64 tvb_get_ntohi56(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint64 tvb_get_ntoh64(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gfloat tvb_get_ntohieee_float(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gdouble tvb_get_ntohieee_double(tvbuff_t *tvb,
    const gint offset);

WS_DLL_PUBLIC guint16 tvb_get_letohs(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint32 tvb_get_letoh24(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint32 tvb_get_letohl(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint64 tvb_get_letoh40(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gint64 tvb_get_letohi40(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint64 tvb_get_letoh48(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gint64 tvb_get_letohi48(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint64 tvb_get_letoh56(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gint64 tvb_get_letohi56(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC guint64 tvb_get_letoh64(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gfloat tvb_get_letohieee_float(tvbuff_t *tvb, const gint offset);
WS_DLL_PUBLIC gdouble tvb_get_letohieee_double(tvbuff_t *tvb,
    const gint offset);

/*
 * Fetch 16-bit and 32-bit values in host byte order.
 * Used for some pseudo-headers in pcap/pcap-ng files, in which the
 * headers are, when capturing, in the byte order of the host, and
 * are converted to the byte order of the host reading the file
 * when reading a capture file.
 */
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
#define tvb_get_h_guint16   tvb_get_letohs
#define tvb_get_h_guint32   tvb_get_letohl
#elif G_BYTE_ORDER == G_BIG_ENDIAN
#define tvb_get_h_guint16   tvb_get_ntohs
#define tvb_get_h_guint32   tvb_get_ntohl
#else
#error "Unsupported byte order"
#endif


/* Fetch a time value from an ASCII-style string in the tvb.
 *
 * @param[in] offset The beginning offset in the tvb (cannot be negative)
 * @param[in] length The field's length in the tvb (or -1 for remaining)
 * @param[in] encoding The ENC_* that defines the format (e.g., ENC_ISO_8601_DATE_TIME)
 * @param[in,out] ns The pre-allocated nstime_t that will be set to the decoded value
 * @param[out] endoff if not NULL, should point to a gint that this
 *     routine will then set to be the offset to the character after
 *     the last character used in the conversion. This is useful because
 *     they may not consume the whole section.
 *
 * @return a pointer to the nstime_t passed-in, or NULL on failure; if no
 *    valid conversion could be performed, *endoff is set to 0, and errno will be
 *    EDOM or ERANGE, and the nstime_t* passed-in will be cleared.
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
struct nstime_t* tvb_get_string_time(tvbuff_t *tvb, const gint offset, const gint length,
                              const guint encoding, struct nstime_t* ns, gint *endoff);

/* Similar to above, but returns a GByteArray based on the case-insensitive
 * hex-char strings with optional separators, and with optional leading spaces.
 * The separators allowed are based on the ENC_SEP_* passed in the encoding param.
 *
 * The passed-in bytes is set to the values, and its pointer is also the return
 * value or NULL on error. The GByteArray bytes must be pre-constructed with
 * g_byte_array_new().
 */
WS_DLL_PUBLIC
GByteArray* tvb_get_string_bytes(tvbuff_t *tvb, const gint offset, const gint length,
                                 const guint encoding, GByteArray* bytes, gint *endoff);

/**
 * Fetch an IPv4 address, in network byte order.
 * We do *not* convert it to host byte order; we leave it in
 * network byte order, as that's what its callers expect. */
WS_DLL_PUBLIC guint32 tvb_get_ipv4(tvbuff_t *tvb, const gint offset);

/* Fetch an IPv6 address. */
WS_DLL_PUBLIC void tvb_get_ipv6(tvbuff_t *tvb, const gint offset,
    struct e_in6_addr *addr);

/* Fetch a GUID. */
WS_DLL_PUBLIC void tvb_get_ntohguid(tvbuff_t *tvb, const gint offset,
    e_guid_t *guid);
WS_DLL_PUBLIC void tvb_get_letohguid(tvbuff_t *tvb, const gint offset,
    e_guid_t *guid);
WS_DLL_PUBLIC void tvb_get_guid(tvbuff_t *tvb, const gint offset,
    e_guid_t *guid, const guint representation);

/* Fetch a specified number of bits from bit offset in a tvb.  All of these
 * functions are equivalent, except for the type of the return value.  Note
 * that the parameter encoding (where supplied) is meaningless and ignored */

/* get 1 - 8 bits returned in a guint8 */
WS_DLL_PUBLIC guint8 tvb_get_bits8(tvbuff_t *tvb, guint bit_offset,
    const gint no_of_bits);
/* get 1 - 16 bits returned in a guint16 */
WS_DLL_PUBLIC guint16 tvb_get_bits16(tvbuff_t *tvb, guint bit_offset,
    const gint no_of_bits, const guint encoding);
/* get 1 - 32 bits returned in a guint32 */
WS_DLL_PUBLIC guint32 tvb_get_bits32(tvbuff_t *tvb, guint bit_offset,
    const gint no_of_bits, const guint encoding);
/* get 1 - 64 bits returned in a guint64 */
WS_DLL_PUBLIC guint64 tvb_get_bits64(tvbuff_t *tvb, guint bit_offset,
    const gint no_of_bits, const guint encoding);

/**
 *  This function has EXACTLY the same behavior as
 *  tvb_get_bits32()
 */
WS_DLL_PUBLIC guint32 tvb_get_bits(tvbuff_t *tvb, const guint bit_offset,
    const gint no_of_bits, const guint encoding);

/** Returns target for convenience. Does not suffer from possible
 * expense of tvb_get_ptr(), since this routine is smart enough
 * to copy data in chunks if the request range actually exists in
 * different TVBUFF_REAL_DATA tvbuffs. This function assumes that the
 * target memory is already allocated; it does not allocate or free the
 * target memory. */
WS_DLL_PUBLIC void *tvb_memcpy(tvbuff_t *tvb, void *target, const gint offset,
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
    const gint offset, size_t length);

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
 * guint8* points to read-only data that the tvbuff manages.
 *
 * Return a pointer into our buffer if the data asked for via 'offset'/'length'
 * is contiguous (which might not be the case for TVBUFF_COMPOSITE). If the
 * data is not contiguous, a tvb_memdup() is called for the entire buffer
 * and the pointer to the newly-contiguous data is returned. This dynamically-
 * allocated memory will be freed when the tvbuff is freed, after the
 * tvbuff_free_cb_t() is called, if any. */
WS_DLL_PUBLIC const guint8 *tvb_get_ptr(tvbuff_t *tvb, const gint offset,
    const gint length);

/** Find first occurrence of needle in tvbuff, starting at offset. Searches
 * at most maxlength number of bytes; if maxlength is -1, searches to
 * end of tvbuff.
 * Returns the offset of the found needle, or -1 if not found.
 * Will not throw an exception, even if maxlength exceeds boundary of tvbuff;
 * in that case, -1 will be returned if the boundary is reached before
 * finding needle. */
WS_DLL_PUBLIC gint tvb_find_guint8(tvbuff_t *tvb, const gint offset,
    const gint maxlength, const guint8 needle);

/** Find first occurrence of any of the needles in tvbuff, starting at offset.
 * Searches at most maxlength number of bytes. Returns the offset of the
 * found needle, or -1 if not found and the found needle.
 * Will not throw an exception, even if
 * maxlength exceeds boundary of tvbuff; in that case, -1 will be returned if
 * the boundary is reached before finding needle. */
WS_DLL_PUBLIC gint tvb_pbrk_guint8(tvbuff_t *tvb, const gint offset,
    const gint maxlength, const guint8 *needles, guchar *found_needle);

/** Find size of stringz (NUL-terminated string) by looking for terminating
 * NUL.  The size of the string includes the terminating NUL.
 *
 * If the NUL isn't found, it throws the appropriate exception.
 */
WS_DLL_PUBLIC guint tvb_strsize(tvbuff_t *tvb, const gint offset);

/** Find size of UCS-2 or UTF-16 stringz (NUL-terminated string) by
 * looking for terminating 16-bit NUL.  The size of the string includes
 * the terminating NUL.
 *
 * If the NUL isn't found, it throws the appropriate exception.
 */
WS_DLL_PUBLIC guint tvb_unicode_strsize(tvbuff_t *tvb, const gint offset);

/** Find length of string by looking for end of zero terminated string, up to
 * 'maxlength' characters'; if 'maxlength' is -1, searches to end
 * of tvbuff.
 * Returns -1 if 'maxlength' reached before finding EOS. */
WS_DLL_PUBLIC gint tvb_strnlen(tvbuff_t *tvb, const gint offset,
    const guint maxlength);

/**
 * Format the data in the tvb from offset for size ...
 */
WS_DLL_PUBLIC gchar *tvb_format_text(tvbuff_t *tvb, const gint offset,
    const gint size);

/**
 * Like "tvb_format_text()", but for 'wsp'; don't show
 * the characters as C-style escapes.
 */
WS_DLL_PUBLIC gchar *tvb_format_text_wsp(tvbuff_t *tvb, const gint offset,
    const gint size);

/**
 * Like "tvb_format_text()", but for null-padded strings; don't show
 * the null padding characters as "\000".
 */
extern gchar *tvb_format_stringzpad(tvbuff_t *tvb, const gint offset,
    const gint size);

/**
 * Like "tvb_format_text_wsp()", but for null-padded strings; don't show
 * the null padding characters as "\000".
 */
extern gchar *tvb_format_stringzpad_wsp(tvbuff_t *tvb, const gint offset,
    const gint size);

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
WS_DLL_PUBLIC guint8 *tvb_get_string_enc(wmem_allocator_t *scope,
    tvbuff_t *tvb, const gint offset, const gint length, const guint encoding);

/*
 * DEPRECATED, do not use in new code, call tvb_get_string_enc directly with
 * the appropriate extension!  Do not assume that ENC_ASCII will work
 * with arbitrary string encodings; it will map all bytes with the 8th
 * bit set to the Unicode REPLACEMENT CHARACTER, so it won't show non-ASCII
 * characters as anything other than an ugly blob.
 */
#define tvb_get_string(SCOPE, TVB, OFFSET, LENGTH) \
    tvb_get_string_enc(SCOPE, TVB, OFFSET, LENGTH, ENC_ASCII)

/**
 * Given an allocator scope, a tvbuff, a bit offset, and a length in
 * 7-bit characters (not octets!), with the specified offset and
 * length referring to a string in the 3GPP TS 23.038 7bits encoding:
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
WS_DLL_PUBLIC gchar *tvb_get_ts_23_038_7bits_string(wmem_allocator_t *scope,
    tvbuff_t *tvb, const gint bit_offset, gint no_of_chars);

/**
 * Given an allocator scope, a tvbuff, a bit offset, and a length in
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
WS_DLL_PUBLIC gchar *tvb_get_ascii_7bits_string(wmem_allocator_t *scope,
    tvbuff_t *tvb, const gint bit_offset, gint no_of_chars);

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
WS_DLL_PUBLIC guint8 *tvb_get_stringzpad(wmem_allocator_t *scope,
    tvbuff_t *tvb, const gint offset, const gint length, const guint encoding);

/**
 * Given an allocator scope, a tvbuff, a byte offset, a pointer to a
 * gint, and a string encoding, with the specified offset referring to
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
 *    if the pointer to the gint is non-null, set the gint to which it
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
WS_DLL_PUBLIC guint8 *tvb_get_stringz_enc(wmem_allocator_t *scope,
    tvbuff_t *tvb, const gint offset, gint *lengthp, const guint encoding);

/*
 * DEPRECATED, do not use in new code, call tvb_get_string_enc directly with
 * the appropriate extension!  Do not assume that ENC_ASCII will work
 * with arbitrary string encodings; it will map all bytes with the 8th
 * bit set to the Unicode REPLACEMENT CHARACTER, so it won't show non-ASCII
 * characters as anything other than an ugly blob.
 */
#define tvb_get_stringz(SCOPE, TVB, OFFSET, LENGTHP) \
    tvb_get_stringz_enc(SCOPE, TVB, OFFSET, LENGTHP, ENC_ASCII)

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
 */
WS_DLL_PUBLIC const guint8 *tvb_get_const_stringz(tvbuff_t *tvb,
    const gint offset, gint *lengthp);

/** Looks for a stringz (NUL-terminated string) in tvbuff and copies
 * no more than bufsize number of bytes, including terminating NUL, to buffer.
 * Returns length of string (not including terminating NUL), or -1 if the
 * string was truncated in the buffer due to not having reached the terminating
 * NUL.  In this way, it acts like g_snprintf().
 *
 * When processing a packet where the remaining number of bytes is less
 * than bufsize, an exception is not thrown if the end of the packet
 * is reached before the NUL is found. If no NUL is found before reaching
 * the end of the short packet, -1 is still returned, and the string
 * is truncated with a NUL, albeit not at buffer[bufsize - 1], but
 * at the correct spot, terminating the string.
 */
WS_DLL_PUBLIC gint tvb_get_nstringz(tvbuff_t *tvb, const gint offset,
    const guint bufsize, guint8 *buffer);

/** Like tvb_get_nstringz(), but never returns -1. The string is guaranteed to
 * have a terminating NUL. If the string was truncated when copied into buffer,
 * a NUL is placed at the end of buffer to terminate it.
 *
 * bufsize MUST be greater than 0.
 */
WS_DLL_PUBLIC gint tvb_get_nstringz0(tvbuff_t *tvb, const gint offset,
    const guint bufsize, guint8 *buffer);

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
 * Set "*next_offset" to the offset of the character past the line
 * terminator, or past the end of the buffer if we don't find a line
 * terminator.  (It's not set if we return -1.)
 */
WS_DLL_PUBLIC gint tvb_find_line_end(tvbuff_t *tvb, const gint offset, int len,
    gint *next_offset, const gboolean desegment);

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
 * Set "*next_offset" to the offset of the character past the line
 * terminator, or past the end of the buffer if we don't find a line
 * terminator.
 */
WS_DLL_PUBLIC gint tvb_find_line_end_unquoted(tvbuff_t *tvb, const gint offset,
    int len, gint *next_offset);

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

WS_DLL_PUBLIC gint tvb_skip_wsp(tvbuff_t *tvb, const gint offset,
    const gint maxlength);

WS_DLL_PUBLIC gint tvb_skip_wsp_return(tvbuff_t *tvb, const gint offset);

int tvb_skip_guint8(tvbuff_t *tvb, int offset, const int maxlength, const guint8 ch);

/**
 * Call strncmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
WS_DLL_PUBLIC gint tvb_strneql(tvbuff_t *tvb, const gint offset,
    const gchar *str, const size_t size);

/**
 * Call g_ascii_strncasecmp after checking if enough chars left, returning
 * 0 if it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
WS_DLL_PUBLIC gint tvb_strncaseeql(tvbuff_t *tvb, const gint offset,
    const gchar *str, const size_t size);

/**
 * Call memcmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
WS_DLL_PUBLIC gint tvb_memeql(tvbuff_t *tvb, const gint offset,
    const guint8 *str, size_t size);

/**
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data, with "punct" as a byte
 * separator.
 */
WS_DLL_PUBLIC gchar *tvb_bytes_to_ep_str_punct(tvbuff_t *tvb, const gint offset,
    const gint len, const gchar punct);

/**
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data.
 */
WS_DLL_PUBLIC gchar *tvb_bytes_to_ep_str(tvbuff_t *tvb, const gint offset,
    const gint len);

/**
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset (which may be -1 for "all the way to the end of the
 * tvbuff"), fetch BCD encoded digits from a tvbuff starting from either
 * the low or high half byte, formatting the digits according to an input digit
 * set, if NUL a default digit set of 0-9 returning "?" for overdecadic digits
 * will be used.  A pointer to the EP allocated string will be returned.
 * Note a tvbuff content of 0xf is considered a 'filler' and will end the
 * conversion.
 */
typedef struct dgt_set_t
{
    const unsigned char out[16];
}
dgt_set_t;

WS_DLL_PUBLIC const gchar *tvb_bcd_dig_to_wmem_packet_str(tvbuff_t *tvb,
    const gint offset, const gint len, dgt_set_t *dgt, gboolean skip_first);

/** Locate a sub-tvbuff within another tvbuff, starting at position
 * 'haystack_offset'. Returns the index of the beginning of 'needle' within
 * 'haystack', or -1 if 'needle' is not found. The index is relative
 * to the start of 'haystack', not 'haystack_offset'. */
WS_DLL_PUBLIC gint tvb_find_tvb(tvbuff_t *haystack_tvb, tvbuff_t *needle_tvb,
    const gint haystack_offset);

/* From tvbuff_zlib.c */

/**
 * Uncompresses a zlib compressed packet inside a tvbuff at offset with
 * length comprlen.  Returns an uncompressed tvbuffer if uncompression
 * succeeded or NULL if uncompression failed.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_uncompress(tvbuff_t *tvb, const int offset,
    int comprlen);

/**
 * Uncompresses a zlib compressed packet inside a tvbuff at offset with
 * length comprlen.  Returns an uncompressed tvbuffer attached to tvb if
 * uncompression succeeded or NULL if uncompression failed.
 */
WS_DLL_PUBLIC tvbuff_t *tvb_child_uncompress(tvbuff_t *parent, tvbuff_t *tvb,
    const int offset, int comprlen);

/* From tvbuff_base64.c */

/** Return a tvb that contains the binary representation of a base64
 *  string
 */
extern tvbuff_t* base64_to_tvb(tvbuff_t *parent, const char *base64);

/************** END OF ACCESSORS ****************/

/** @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TVBUFF_H__ */

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
