/* tvbuff.h
 *
 * Testy, Virtual(-izable) Buffer of guint8*'s
 *
 * "Testy" -- the buffer gets mad when an attempt is made to access data
 * 		beyond the bounds of the buffer. An exception is thrown.
 *
 * "Virtual" -- the buffer can have its own data, can use a subset of
 * 		the data of a backing tvbuff, or can be a composite of
 * 		other tvbuffs.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __TVBUFF_H__
#define __TVBUFF_H__

#include <glib.h>
#include <epan/ipv6-utils.h>
#include <epan/guid-utils.h>
#include "exceptions.h"

/** @file
 * "testy, virtual(-izable) buffer".  They are testy in that they get mad when
 * an attempt is made to access data beyond the bounds of their array. In that
 * case, they throw an exception.
 *
 * They are virtualizable in that new tvbuff's can be made from other tvbuffs,
 * while only the original tvbuff may have data. That is, the new tvbuff has
 * virtual data.
 */

/** The different types of tvbuff's */
typedef enum {
	TVBUFF_REAL_DATA,
	TVBUFF_SUBSET,
	TVBUFF_COMPOSITE
} tvbuff_type;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

/**
 * tvbuffs: dissector use and management
 *
 *  Consider a collection of tvbs as being a chain or stack of tvbs.
 *
 *  The top-level dissector (packet.c) pushes the initial tvb onto the stack
 *  (starts the chain) and then calls a sub-dissector which in turn calls the next
 *  sub-dissector and so on. Each sub-dissector may chain additional tvbs to
 *  the tvb handed to that dissector. After dissection is complete and control has
 *  returned to the top-level dissector, the chain of tvbs (stack) is free'd
 *  via a call to tvb_free_chain() (in epan_dissect_cleanup()).
 *
 * A dissector:
 * - Can chain new tvbs (real, subset, composite) to the tvb
 *    handed to the dissector via tvb_subset(), tvb_new_child_real_data(), etc.
 *    (Subset and Composite tvbs should reference only tvbs which are
 *    already part of the chain).
 * - Must not save a pointer to a tvb handed to the dissector for
 *    use when dissecting another frame; A higher level function
 *    may very well free the chain). This also applies to any tvbs chained
 *    by the dissector to the tvb handed to the dissector.
 * - Can create its own tvb chain (using tvb_new_real_data() which
 *    the dissector is free to manage as desired. */

/** TVBUFF_REAL_DATA contains a guint8* that points to real data.
 * The data is allocated and contiguous.
 *
 * TVBUFF_SUBSET has a backing tvbuff. The TVBUFF_SUBSET is a "window"
 * through which the program sees only a portion of the backing tvbuff.
 *
 * TVBUFF_COMPOSITE combines multiple tvbuffs sequentually to produce
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
 * tvbuff's are normally chained together to allow efficient de-allocation of tvbuff's.
 *
 */

typedef void (*tvbuff_free_cb_t)(void*);

/** Returns a pointer to a newly initialized tvbuff. Note that
 * tvbuff's of types TVBUFF_SUBSET and TVBUFF_COMPOSITE
 * require further initialization via the appropriate functions. */
extern tvbuff_t* tvb_new(tvbuff_type);

/** Extracts 'number of bits' starting at 'bit offset'.
 * Returns a pointer to a newly initialized ep_alloc'd REAL_DATA
 * tvbuff with the bits octet aligned.
 */
extern tvbuff_t* tvb_new_octet_aligned(tvbuff_t *tvb, guint32 bit_offset, gint32 no_of_bits);

/** Free a tvbuff_t and all tvbuffs chained from it
 * The tvbuff must be 'the 'head' (initial) tvb of a chain or
 * must not be in a chain.
 * If specified, a callback to free the tvbuff data will be invoked
 * for each tvbuff free'd */
extern void tvb_free(tvbuff_t*);

/** Free the tvbuff_t and all tvbuffs chained from it.
 * The tvbuff must be 'the 'head' (initial) tvb of a chain or
 * must not be in a chain.
 * If specified, a callback to free the tvbuff data will be invoked
 * for each tvbuff free'd */
extern void tvb_free_chain(tvbuff_t*);

/** Set a callback function to call when a tvbuff is actually freed
 * One argument is passed to that callback --- a void* that points
 * to the real data. Obviously, this only applies to a
 * TVBUFF_REAL_DATA tvbuff. */
extern void tvb_set_free_cb(tvbuff_t*, const tvbuff_free_cb_t);

/** Attach a TVBUFF_REAL_DATA tvbuff to a parent tvbuff. This connection
 * is used during a tvb_free_chain()... the "child" TVBUFF_REAL_DATA acts
 * as if is part of the chain-of-creation of the parent tvbuff, although it
 * isn't. This is useful if you need to take the data from some tvbuff,
 * run some operation on it, like decryption or decompression, and make a new
 * tvbuff from it, yet want the new tvbuff to be part of the chain. The reality
 * is that the new tvbuff *is* part of the "chain of creation", but in a way
 * that these tvbuff routines are ignorant of. Use this function to make
 * the tvbuff routines knowledgable of this fact. */
extern void tvb_set_child_real_data_tvbuff(tvbuff_t* parent, tvbuff_t* child);

extern tvbuff_t* tvb_new_child_real_data(tvbuff_t* parent, const guint8* data, const guint length,
    const gint reported_length);

/** Sets parameters for TVBUFF_REAL_DATA. Can throw ReportedBoundsError. */
extern void tvb_set_real_data(tvbuff_t*, const guint8* data, const guint length,
    const gint reported_length);

/** Combination of tvb_new() and tvb_set_real_data(). Can throw ReportedBoundsError.
 * Normally, a callback to free the data should be registered using tvb_set_free_cb();
 * when this tvbuff is freed, then your callback will be called, and at that time
 * you can free your original data. */
extern tvbuff_t* tvb_new_real_data(const guint8* data, const guint length,
    const gint reported_length);

/** Define the subset of the backing buffer to use.
 *
 * 'backing_offset' can be negative, to indicate bytes from
 * the end of the backing buffer.
 *
 * 'backing_length' can be 0, although the usefulness of the buffer would
 * be rather limited.
 *
 * 'backing_length' of -1 means "to the end of the backing buffer"
 *
 * Will throw BoundsError if 'backing_offset'/'length'
 * is beyond the bounds of the backing tvbuff.
 * Can throw ReportedBoundsError. */
extern void tvb_set_subset(tvbuff_t* tvb, tvbuff_t* backing,
		const gint backing_offset, const gint backing_length, const gint reported_length);

/** Combination of tvb_new() and tvb_set_subset()
 * Can throw ReportedBoundsError. */
extern tvbuff_t* tvb_new_subset(tvbuff_t* backing,
		const gint backing_offset, const gint backing_length, const gint reported_length);

/** Similar to tvb_new_subset() but with backing_length and reported_length set to -1.
 * Can throw ReportedBoundsError. */
extern tvbuff_t* tvb_new_subset_remaining(tvbuff_t* backing,
		const gint backing_offset);

/** Both tvb_composite_append and tvb_composite_prepend can throw
 * BoundsError if member_offset/member_length goes beyond bounds of
 * the 'member' tvbuff. */

/** Append to the list of tvbuffs that make up this composite tvbuff */
extern void tvb_composite_append(tvbuff_t* tvb, tvbuff_t* member);

/** Prepend to the list of tvbuffs that make up this composite tvbuff */
extern void tvb_composite_prepend(tvbuff_t* tvb, tvbuff_t* member);

/** Helper function that calls tvb_new(TVBUFF_COMPOSITE).
 * Provided only to maintain symmetry with other constructors */
extern tvbuff_t* tvb_new_composite(void);

/** Mark a composite tvbuff as initialized. No further appends or prepends
 * occur, data access can finally happen after this finalization. */
extern void tvb_composite_finalize(tvbuff_t* tvb);


/* Get total length of buffer */
extern guint tvb_length(const tvbuff_t*);

/** Computes bytes to end of buffer, from offset (which can be negative,
 * to indicate bytes from end of buffer). Function returns -1 to
 * indicate that offset is out of bounds. No exception is thrown. */
extern gint tvb_length_remaining(const tvbuff_t*, const gint offset);

/** Same as above, but throws an exception if the offset is out of bounds. */
extern guint tvb_ensure_length_remaining(const tvbuff_t*, const gint offset);

/* Checks (w/o throwing exception) that the bytes referred to by
 * 'offset'/'length' actually exist in the buffer */
extern gboolean tvb_bytes_exist(const tvbuff_t*, const gint offset, const gint length);

/** Checks that the bytes referred to by 'offset'/'length' actually exist
 * in the buffer, and throws an exception if they aren't. */
extern void tvb_ensure_bytes_exist(const tvbuff_t *tvb, const gint offset, const gint length);

/* Checks (w/o throwing exception) that offset exists in buffer */
extern gboolean tvb_offset_exists(const tvbuff_t*, const gint offset);

/* Get reported length of buffer */
extern guint tvb_reported_length(const tvbuff_t*);

/** Computes bytes of reported packet data to end of buffer, from offset
 * (which can be negative, to indicate bytes from end of buffer). Function
 * returns -1 to indicate that offset is out of bounds. No exception is
 * thrown. */
extern gint tvb_reported_length_remaining(const tvbuff_t *tvb, const gint offset);

/** Set the reported length of a tvbuff to a given value; used for protocols
   whose headers contain an explicit length and where the calling
   dissector's payload may include padding as well as the packet for
   this protocol.

   Also adjusts the data length. */
extern void tvb_set_reported_length(tvbuff_t*, const guint);

extern guint tvb_offset_from_real_beginning(const tvbuff_t *tvb);

/* Returns the offset from the first byte of real data. */
extern gint tvb_raw_offset(tvbuff_t *tvb);

/************** START OF ACCESSORS ****************/
/* All accessors will throw an exception if appropriate */

extern guint8  tvb_get_guint8(tvbuff_t*, const gint offset);

extern guint16 tvb_get_ntohs(tvbuff_t*, const gint offset);
extern guint32 tvb_get_ntoh24(tvbuff_t*, const gint offset);
extern guint32 tvb_get_ntohl(tvbuff_t*, const gint offset);
extern guint64 tvb_get_ntoh40(tvbuff_t*, const gint offset);
extern guint64 tvb_get_ntoh48(tvbuff_t*, const gint offset);
extern guint64 tvb_get_ntoh56(tvbuff_t*, const gint offset);
extern guint64 tvb_get_ntoh64(tvbuff_t*, const gint offset);
extern gfloat tvb_get_ntohieee_float(tvbuff_t*, const gint offset);
extern gdouble tvb_get_ntohieee_double(tvbuff_t*, const gint offset);

extern guint16 tvb_get_letohs(tvbuff_t*, const gint offset);
extern guint32 tvb_get_letoh24(tvbuff_t*, const gint offset);
extern guint32 tvb_get_letohl(tvbuff_t*, const gint offset);
extern guint64 tvb_get_letoh40(tvbuff_t*, const gint offset);
extern guint64 tvb_get_letoh48(tvbuff_t*, const gint offset);
extern guint64 tvb_get_letoh56(tvbuff_t*, const gint offset);
extern guint64 tvb_get_letoh64(tvbuff_t*, const gint offset);
extern gfloat tvb_get_letohieee_float(tvbuff_t*, const gint offset);
extern gdouble tvb_get_letohieee_double(tvbuff_t*, const gint offset);

/**
 * Fetch an IPv4 address, in network byte order.
 * We do *not* convert it to host byte order; we leave it in
 * network byte order, as that's what its callers expect. */
extern guint32 tvb_get_ipv4(tvbuff_t*, const gint offset);

/* Fetch an IPv6 address. */
extern void tvb_get_ipv6(tvbuff_t*, const gint offset, struct e_in6_addr *addr);

/* Fetch a GUID. */
extern void tvb_get_ntohguid(tvbuff_t *tvb, const gint offset, e_guid_t *guid);
extern void tvb_get_letohguid(tvbuff_t *tvb, const gint offset, e_guid_t *guid);
extern void tvb_get_guid(tvbuff_t *tvb, const gint offset, e_guid_t *guid, const guint representation);

/* Fetch a specified number of bits from bit offset in a tvb */
extern guint8 tvb_get_bits8(tvbuff_t *tvb, gint bit_offset, const gint no_of_bits);
extern guint16 tvb_get_bits16(tvbuff_t *tvb, gint bit_offset, const gint no_of_bits, const guint encoding);
extern guint32 tvb_get_bits32(tvbuff_t *tvb, gint bit_offset, const gint no_of_bits, const guint encoding);
extern guint64 tvb_get_bits64(tvbuff_t *tvb, gint bit_offset, const gint no_of_bits, const guint encoding);

/**
 * Fetch a specified number of bits from bit offset in a tvb, but allow number
 * of bits to range between 1 and 32. If the requested number of bits is known
 * beforehand, or its range can be handled by a single function of the group
 * above, use one of them instead.
 */
extern guint32 tvb_get_bits(tvbuff_t *tvb, const gint bit_offset, const gint no_of_bits, const guint encoding);

void tvb_get_bits_buf(tvbuff_t *tvb, gint bit_offset, gint no_of_bits, guint8 *buf, gboolean lsb0);
guint8 *ep_tvb_get_bits(tvbuff_t *tvb, gint bit_offset, gint no_of_bits, gboolean lsb0);

/** Returns target for convenience. Does not suffer from possible
 * expense of tvb_get_ptr(), since this routine is smart enough
 * to copy data in chunks if the request range actually exists in
 * different TVBUFF_REAL_DATA tvbuffs. This function assumes that the
 * target memory is already allocated; it does not allocate or free the
 * target memory. */
extern void* tvb_memcpy(tvbuff_t*, void* target, const gint offset, size_t length);

/** It is the user's responsibility to g_free() the memory allocated by
 * tvb_memdup(). Calls tvb_memcpy() */
extern void* tvb_memdup(tvbuff_t*, const gint offset, size_t length);

/* Same as above but the buffer returned from this function does not have to
* be freed. It will be automatically freed after the packet is dissected.
* Buffers allocated by this function are NOT persistent.
*/
extern void* ep_tvb_memdup(tvbuff_t *tvb, const gint offset, size_t length);

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
extern const guint8* tvb_get_ptr(tvbuff_t*, const gint offset, const gint length);

/** Find first occurence of any of the needles in tvbuff, starting at offset.
 * Searches at most maxlength number of bytes; if maxlength is -1, searches
 * to end of tvbuff.
 * Returns the offset of the found needle, or -1 if not found.
 * Will not throw an exception, even if maxlength exceeds boundary of tvbuff;
 * in that case, -1 will be returned if the boundary is reached before
 * finding needle. */
extern gint tvb_find_guint8(tvbuff_t*, const gint offset, const gint maxlength,
    const guint8 needle);

/** Find first occurence of any of the needles in tvbuff, starting at offset.
 * Searches at most maxlength number of bytes. Returns the offset of the
 * found needle, or -1 if not found and the found needle.
 * Will not throw an exception, even if
 * maxlength exceeds boundary of tvbuff; in that case, -1 will be returned if
 * the boundary is reached before finding needle. */
extern gint tvb_pbrk_guint8(tvbuff_t *, const gint offset, const gint maxlength,
    const guint8 *needles, guchar *found_needle);

/** Find size of stringz (NUL-terminated string) by looking for terminating
 * NUL.  The size of the string includes the terminating NUL.
 *
 * If the NUL isn't found, it throws the appropriate exception.
 */
extern guint tvb_strsize(tvbuff_t *tvb, const gint offset);

/** Find length of string by looking for end of zero terminated string, up to
 * 'maxlength' characters'; if 'maxlength' is -1, searches to end
 * of tvbuff.
 * Returns -1 if 'maxlength' reached before finding EOS. */
extern gint tvb_strnlen(tvbuff_t*, const gint offset, const guint maxlength);

/** Convert a string from Unicode to ASCII.  At the moment we fake it by
 * assuming all characters are ASCII  )-:  The len parameter is the number
 * of guint16's to convert from Unicode.
 *
 * XXX - These functions have been superceded by tvb_get_unicode_string()
 *       and tvb_get_ephemeral_unicode_string()
 *
 * tvb_fake_unicode() returns a buffer allocated by g_malloc() and must
 *                    be g_free() by the caller.
 * tvb_get_ephemeral_faked_unicode() returns a buffer that does not need
 *                    to be explicitely freed. Instead this buffer is
 *                    automatically freed when wireshark starts dissecting
 *                    the next packet.
 */
extern char *tvb_fake_unicode(tvbuff_t *tvb, int offset, const int len,
                              const gboolean little_endian);
extern char *tvb_get_ephemeral_faked_unicode(tvbuff_t *tvb, int offset, const int len,
                              const gboolean little_endian);

/**
 * Format the data in the tvb from offset for size ...
 */
extern gchar * tvb_format_text(tvbuff_t *tvb, const gint offset, const gint size);

/**
 * Like "tvb_format_text()", but for 'wsp'; don't show
 * the characters as C-style escapes.
 */
extern gchar * tvb_format_text_wsp(tvbuff_t *tvb, const gint offset, const gint size);

/**
 * Like "tvb_format_text()", but for null-padded strings; don't show
 * the null padding characters as "\000".
 */
extern gchar *tvb_format_stringzpad(tvbuff_t *tvb, const gint offset, const gint size);

/**
 * Like "tvb_format_text_wsp()", but for null-padded strings; don't show
 * the null padding characters as "\000".
 */
extern gchar *tvb_format_stringzpad_wsp(tvbuff_t *tvb, const gint offset, const gint size);


/**
 * Given a tvbuff, an offset, and a length, allocate a buffer big enough
 * to hold a non-null-terminated string of that length at that offset,
 * plus a trailing zero, copy the string into it, and return a pointer
 * to the string.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * tvb_get_string()  returns a string allocated by g_malloc() and therefore
 *                   MUST be g_free() by the caller in order not to leak
 *                   memory.
 *
 * tvb_get_unicode_string() Unicode (UTF-16) version of above
 *
 * tvb_get_ephemeral_string() returns a string that does not need to be freed,
 *                   instead it will automatically be freed once the next
 *                   packet is dissected.
 *
 * tvb_get_ephemeral_string_enc() takes a string encoding as well, and
 *                   converts to UTF-8 from the encoding (only UTF-8 and
 *                   EBCDIC supported)
 *
 * tvb_get_ephemeral_unicode_string() Unicode (UTF-16) version of above
 *
 * tvb_get_seasonal_string() returns a string that does not need to be freed,
 *                   instead it will automatically be freed when a new capture
 *                   or file is opened.
 */
extern guint8 *tvb_get_string(tvbuff_t *tvb, const gint offset, const gint length);
extern gchar  *tvb_get_unicode_string(tvbuff_t *tvb, const gint offset, gint length, const guint encoding);
extern guint8 *tvb_get_ephemeral_string(tvbuff_t *tvb, const gint offset, const gint length);
extern guint8 *tvb_get_ephemeral_string_enc(tvbuff_t *tvb, const gint offset,
    const gint length, const gint encoding);
extern gchar  *tvb_get_ephemeral_unicode_string(tvbuff_t *tvb, const gint offset, gint length, const guint encoding);
extern guint8 *tvb_get_seasonal_string(tvbuff_t *tvb, const gint offset, const gint length);


/**
 * Given a tvbuff and an offset, with the offset assumed to refer to
 * a null-terminated string, find the length of that string (and throw
 * an exception if the tvbuff ends before we find the null), allocate
 * a buffer big enough to hold the string, copy the string into it,
 * and return a pointer to the string.  Also return the length of the
 * string (including the terminating null) through a pointer.
 *
 * tvb_get_stringz() returns a string allocated by g_malloc() and therefore
 *                   MUST be g_free() by the caller in order not to leak
 *                   memory.
 *
 * tvb_get_stringz_enc() takes a string encoding as well, and converts to
 *                   UTF-8 from the encoding (only UTF-8 and EBCDIC supported)
 *
 * tvb_get_const_stringz() returns a constant (unmodifiable) string that does
 *                   not need to be freed, instead it will automatically be
 *                   freed once the next packet is dissected.  It is slightly
 *                   more efficient than the other routines.
 *
 * tvb_get_ephemeral_stringz() returns a string that does not need to be freed,
 *                   instead it will automatically be freed once the next
 *                   packet is dissected.
 *
 * tvb_get_ephemeral_stringz_enc() takes a string encoding as well, and
 *                   converts to UTF-8 from the encoding (only UTF-8 and
 *                   EBCDIC supported)
 *                   packet is dissected.
 *
 * tvb_get_ephemeral_unicode_stringz() Unicode (UTF-16) version of above
 *
 * tvb_get_seasonal_stringz() returns a string that does not need to be freed,
 *                   instead it will automatically be freed when a new capture
 *                   or file is opened.
 */
extern guint8 *tvb_get_stringz(tvbuff_t *tvb, const gint offset, gint *lengthp);
extern guint8 *tvb_get_stringz_enc(tvbuff_t *tvb, const gint offset, gint *lengthp, gint encoding);
extern const guint8 *tvb_get_const_stringz(tvbuff_t *tvb, const gint offset, gint *lengthp);
extern guint8 *tvb_get_ephemeral_stringz(tvbuff_t *tvb, const gint offset, gint *lengthp);
extern guint8 *tvb_get_ephemeral_stringz_enc(tvbuff_t *tvb, const gint offset, gint *lengthp, gint encoding);
extern gchar  *tvb_get_ephemeral_unicode_stringz(tvbuff_t *tvb, const gint offset, gint *lengthp, const guint encoding);
extern guint8 *tvb_get_seasonal_stringz(tvbuff_t *tvb, const gint offset, gint *lengthp);

/** Looks for a stringz (NUL-terminated string) in tvbuff and copies
 * no more than bufsize number of bytes, including terminating NUL, to buffer.
 * Returns length of string (not including terminating NUL), or -1 if the string was
 * truncated in the buffer due to not having reached the terminating NUL.
 * In this way, it acts like g_snprintf().
 *
 * When processing a packet where the remaining number of bytes is less
 * than bufsize, an exception is not thrown if the end of the packet
 * is reached before the NUL is found. If no NUL is found before reaching
 * the end of the short packet, -1 is still returned, and the string
 * is truncated with a NUL, albeit not at buffer[bufsize - 1], but
 * at the correct spot, terminating the string.
 */
extern gint tvb_get_nstringz(tvbuff_t *tvb, const gint offset, const guint bufsize,
    guint8* buffer);

/** Like tvb_get_nstringz(), but never returns -1. The string is guaranteed to
 * have a terminating NUL. If the string was truncated when copied into buffer,
 * a NUL is placed at the end of buffer to terminate it.
 *
 * bufsize MUST be greater than 0.
 */
extern gint tvb_get_nstringz0(tvbuff_t *tvb, const gint offset, const guint bufsize,
    guint8* buffer);

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
 *	if "deseg" is true, return -1;
 *
 *	if "deseg" is false, return the amount of data remaining in
 *	the buffer.
 *
 * Set "*next_offset" to the offset of the character past the line
 * terminator, or past the end of the buffer if we don't find a line
 * terminator.  (It's not set if we return -1.)
 */
extern gint tvb_find_line_end(tvbuff_t *tvb, const gint offset, int len,
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
extern gint tvb_find_line_end_unquoted(tvbuff_t *tvb, const gint offset, int len,
    gint *next_offset);

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

extern gint tvb_skip_wsp(tvbuff_t* tvb, const gint offset, const gint maxlength);

extern gint tvb_skip_wsp_return(tvbuff_t* tvb, const gint offset);

/**
 * Call strncmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
extern gint tvb_strneql(tvbuff_t *tvb, const gint offset, const gchar *str,
    const size_t size);

/**
 * Call g_ascii_strncasecmp after checking if enough chars left, returning
 * 0 if it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
extern gint tvb_strncaseeql(tvbuff_t *tvb, const gint offset, const gchar *str,
    const size_t size);

/**
 * Call memcmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
extern gint tvb_memeql(tvbuff_t *tvb, const gint offset, const guint8 *str,
    size_t size);

/**
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data, with "punct" as a byte
 * separator.
 */
extern gchar *tvb_bytes_to_str_punct(tvbuff_t *tvb, const gint offset, const gint len,
    const gchar punct);

/**
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data.
 */
extern gchar *tvb_bytes_to_str(tvbuff_t *tvb, const gint offset, const gint len);

/**
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset (which may be -1 for "all the way to the end of the
 * tvbuff"), fetch BCD encoded digits from a tvbuff starting from either
 * the low or high half byte, formating the digits according to an input digit set,
 * if NUll a default digit set of 0-9 returning "?" for overdecadic digits will be used.
 * A pointer to the EP allocated string will be returned.
 * Note a tvbuff content of 0xf is considered a 'filler' and will end the conversion.
 */
typedef struct dgt_set_t
{
	const unsigned char out[15];
}
dgt_set_t;

extern const gchar *tvb_bcd_dig_to_ep_str(tvbuff_t *tvb, const gint offset, const gint len, dgt_set_t *dgt, gboolean skip_first);

struct tvbuff *tvb_get_ds_tvb(tvbuff_t *tvb);

/** Locate a sub-tvbuff within another tvbuff, starting at position
 * 'haystack_offset'. Returns the index of the beginning of 'needle' within
 * 'haystack', or -1 if 'needle' is not found. The index is relative
 * to the start of 'haystack', not 'haystack_offset'. */
extern gint tvb_find_tvb(tvbuff_t *haystack_tvb, tvbuff_t *needle_tvb,
	const gint haystack_offset);

/**
 * Uncompresses a zlib compressed packet inside a tvbuff at offset with
 * length comprlen.  Returns an uncompressed tvbuffer if uncompression
 * succeeded or NULL if uncompression failed.
 */
extern tvbuff_t* tvb_uncompress(tvbuff_t *tvb, const int offset,  int comprlen);

/**
 * Uncompresses a zlib compressed packet inside a tvbuff at offset with
 * length comprlen.  Returns an uncompressed tvbuffer attached to tvb if uncompression
 * succeeded or NULL if uncompression failed.
 */
extern tvbuff_t* tvb_child_uncompress(tvbuff_t *parent, tvbuff_t *tvb, const int offset, int comprlen);

/************** END OF ACCESSORS ****************/

#endif /* __TVBUFF_H__ */
