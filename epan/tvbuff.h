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
 * $Id: tvbuff.h,v 1.5 2000/11/11 19:55:48 guy Exp $
 *
 * Copyright (c) 2000 by Gilbert Ramirez <gram@xiexie.org>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#include "exceptions.h"

typedef struct tvbuff tvbuff_t;

typedef void (*tvbuff_free_cb_t)(void*);

/* The different types of tvbuff's */
typedef enum {
	TVBUFF_REAL_DATA,
	TVBUFF_SUBSET,
	TVBUFF_COMPOSITE
} tvbuff_type;

/* TVBUFF_REAL_DATA contains a guint8* that points to real data.
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
 */


/* "class" initialization. Called once during execution of program
 * so that tvbuff.c can initialize its data. */
void tvbuff_init(void);

/* "class" cleanup. Called once during execution of program
 * so that tvbuff.c can clean up its data. */
void tvbuff_cleanup(void);


/* Returns a pointer to a newly initialized tvbuff. Note that
 * tvbuff's of types TVBUFF_SUBSET and TVBUFF_COMPOSITE
 * require further initialization via the appropriate functions */
tvbuff_t* tvb_new(tvbuff_type);

/* Marks a tvbuff for freeing. The guint8* data of a TVBUFF_REAL_DATA
 * is *never* freed by the tvbuff routines. The tvbuff itself is actually freed
 * once its usage  count drops to 0.
 *
 * Usage counts increment for any time the tvbuff is
 * used as a member of another tvbuff, i.e., as the backing buffer for
 * a TVBUFF_SUBSET or as a member of a TVBUFF_COMPOSITE.
 *
 * Although you may call tvb_free(), the tvbuff may still be in use
 * by other tvbuff's (TVBUFF_SUBSET or TVBUFF_COMPOSITE), so it is not
 * safe, unless you know otherwise, to free your guint8* data. If you
 * cannot be sure that your TVBUFF_REAL_DATA is not in use by another
 * tvbuff, register a callback with tvb_set_free_cb(); when your tvbuff
 * is _really_ freed, then your callback will be called, and at that time
 * you can free your original data.
 *
 * The caller can artificially increment/decrement the usage count
 * with tvbuff_increment_usage_count()/tvbuff_decrement_usage_count().
 */
void tvb_free(tvbuff_t*);

/* Free the tvbuff_t and all tvbuff's created from it. */
void tvb_free_chain(tvbuff_t*);

/* Both return the new usage count, after the increment or decrement */
guint tvb_increment_usage_count(tvbuff_t*, guint count);

/* If a decrement causes the usage count to drop to 0, a the tvbuff
 * is immediately freed. Be sure you know exactly what you're doing
 * if you decide to use this function, as another tvbuff could
 * still have a pointer to the just-freed tvbuff, causing corrupted data
 * or a segfault in the future */
guint tvb_decrement_usage_count(tvbuff_t*, guint count);

/* Set a callback function to call when a tvbuff is actually freed
 * (once the usage count drops to 0). One argument is passed to
 * that callback --- the guint* that points to the real data.
 * Obviously, this only applies to a TVBUFF_REAL_DATA tvbuff. */
void tvb_set_free_cb(tvbuff_t*, tvbuff_free_cb_t);


/* Sets parameters for TVBUFF_REAL_DATA. Can throw ReportedBoundsError. */
void tvb_set_real_data(tvbuff_t*, const guint8* data, guint length, gint reported_length);

/* Combination of tvb_new() and tvb_set_real_data(). Can throw ReportedBoundsError. */
tvbuff_t* tvb_new_real_data(const guint8* data, guint length, gint reported_length);


/* Define the subset of the backing buffer to use.
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
void tvb_set_subset(tvbuff_t* tvb, tvbuff_t* backing,
		gint backing_offset, gint backing_length, gint reported_length);

/* Combination of tvb_new() and tvb_set_subset()
 * Can throw ReportedBoundsError. */
tvbuff_t* tvb_new_subset(tvbuff_t* backing,
		gint backing_offset, gint backing_length, gint reported_length);


/* Both tvb_composite_append and tvb_composite_prepend can throw
 * BoundsError if member_offset/member_length goes beyond bounds of
 * the 'member' tvbuff. */

/* Append to the list of tvbuffs that make up this composite tvbuff */
void tvb_composite_append(tvbuff_t* tvb, tvbuff_t* member);

/* Prepend to the list of tvbuffs that make up this composite tvbuff */
void tvb_composite_prepend(tvbuff_t* tvb, tvbuff_t* member);

/* Helper function that calls tvb_new(TVBUFF_COMPOSITE).
 * Provided only to maintain symmetry with other constructors */
tvbuff_t* tvb_new_composite(void);

/* Mark a composite tvbuff as initialized. No further appends or prepends
 * occur, data access can finally happen after this finalization. */
void tvb_composite_finalize(tvbuff_t* tvb);


/* Get total length of buffer */
guint tvb_length(tvbuff_t*);

/* Computes bytes to end of buffer, from offset (which can be negative,
 * to indicate bytes from end of buffer). Function returns -1 to
 * indicate that offset is out of bounds. No exception is thrown. */
guint tvb_length_remaining(tvbuff_t*, gint offset);

/* Checks (w/o throwing exception) that the bytes referred to by 'offset'/'length'
 * actualy exist in the buffer */
gboolean tvb_bytes_exist(tvbuff_t*, gint offset, gint length);

/* Checks (w/o throwing exception) that offset exists in buffer */
gboolean tvb_offset_exists(tvbuff_t*, gint offset);

/* Get reported length of buffer */
guint tvb_reported_length(tvbuff_t*);

/* Returns the offset from the first byte of real data. This is
 * the same value as 'offset' in tvb_compat() */
gint tvb_raw_offset(tvbuff_t*);

/************** START OF ACCESSORS ****************/
/* All accessors will throw BoundsError or ReportedBoundsError if appropriate */

guint8  tvb_get_guint8(tvbuff_t*, gint offset);

guint16 tvb_get_ntohs(tvbuff_t*, gint offset);
guint32 tvb_get_ntoh24(tvbuff_t*, gint offset);
guint32 tvb_get_ntohl(tvbuff_t*, gint offset);
#ifdef G_HAVE_GINT64
guint64 tvb_get_ntohll(tvbuff_t*, gint offset);
#endif

guint16 tvb_get_letohs(tvbuff_t*, gint offset);
guint32 tvb_get_letoh24(tvbuff_t*, gint offset);
guint32 tvb_get_letohl(tvbuff_t*, gint offset);
#ifdef G_HAVE_GINT64
guint64 tvb_get_letohll(tvbuff_t*, gint offset);
#endif

/* Returns target for convenience. Does not suffer from possible
 * expense of tvb_get_ptr(), since this routine is smart enough
 * to copy data in chunks if the request range actually exists in
 * different TVBUFF_REAL_DATA tvbuffs. This function assumes that the
 * target memory is already allocated; it does not allocate or free the
 * target memory. */
guint8* tvb_memcpy(tvbuff_t*, guint8* target, gint offset, gint length);

/* It is the user's responsibility to g_free() the memory allocated by
 * tvb_memdup(). Calls tvb_memcpy() */
guint8* tvb_memdup(tvbuff_t*, gint offset, gint length);

/* WARNING! This function is possibly expensive, temporarily allocating
 * another copy of the packet data. Furthermore, it's dangerous because once
 * this pointer is given to the user, there's no guarantee that the user will
 * honor the 'length' and not overstep the boundaries of the buffer.
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
guint8* tvb_get_ptr(tvbuff_t*, gint offset, gint length);

/* Find first occurence of any of the needles in tvbuff, starting at offset.
 * Searches at most maxlength number of bytes; if maxlength is -1, searches
 * to end of tvbuff.
 * Returns the offset of the found needle, or -1 if not found.
 * Will not throw an exception, even if maxlength exceeds boundary of tvbuff;
 * in that case, -1 will be returned if the boundary is reached before
 * finding needle. */
gint tvb_find_guint8(tvbuff_t*, gint offset, guint maxlength, guint8 needle);

/* Find first occurence of any of the needles in tvbuff, starting at offset.
 * Searches at most maxlength number of bytes. Returns the offset of the
 * found needle, or -1 if not found. Will not throw an exception, even if
 * maxlength exceeds boundary of tvbuff; in that case, -1 will be returned if
 * the boundary is reached before finding needle. */
gint tvb_pbrk_guint8(tvbuff_t *, gint offset, guint maxlength, guint8 *needles);

/* Find length of string by looking for end of string ('\0'), up to
 * 'maxlength' characters'; if 'maxlength' is -1, searches to end
 * of tvbuff.
 * Returns -1 if 'maxlength' reached before finding EOS. */
gint tvb_strnlen(tvbuff_t*, gint offset, guint maxlength);

/*
 * Format the data in the tvb from offset for size ...
 */
guint8 * tvb_format_text(tvbuff_t *tvb, gint offset, gint size);

/* Looks for a stringz (NUL-terminated string) in tvbuff and copies
 * no more than maxlength number of bytes, including terminating NUL, to buffer.
 * Returns length of string (not including terminating NUL), or -1 if the string was
 * truncated in the buffer due to not having reached the terminating NUL.
 * In this way, it acts like snprintf().
 */
gint tvb_get_nstringz(tvbuff_t *tvb, gint offset, guint maxlength, guint8* buffer);

/* Like tvb_get_nstringz(), but never returns -1. The string is guaranteed to
 * have a terminating NUL. If the string was truncated when copied into buffer,
 * a NUL is placed at the end of buffer to terminate it.
 */
gint tvb_get_nstringz0(tvbuff_t *tvb, gint offset, guint maxlength, guint8* buffer);

/*
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset (which may be -1 for "all the way to the end of the
 * tvbuff"), find the end of the (putative) line that starts at the
 * specified offset in the tvbuff, going no further than the specified
 * length.
 *
 * Return the offset right past the end of the line as the return value,
 * and return the offset of the EOL character(s) in "*eol".
 */
gint tvb_find_line_end(tvbuff_t *tvb, gint offset, int len, gint *eol);

/*
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
gint tvb_find_line_end_unquoted(tvbuff_t *tvb, gint offset, int len,
    gint *next_offset);

/* Call strncmp after checking if enough chars left, otherwise return -1 */
gint tvb_strneql(tvbuff_t *tvb, gint offset, const guint8 *str, gint size);

/* Call strncasecmp after checking if enough chars left, otherwise return -1 */
gint tvb_strncaseeql(tvbuff_t *tvb, gint offset, const guint8 *str, gint size);

/************** END OF ACCESSORS ****************/

/* Sets pd and offset so that tvbuff's can be used with code
 * that only understands pd/offset and not tvbuffs.
 * This is the "compatibility" function */
void tvb_compat(tvbuff_t*, const guint8 **pd, int *offset);

#define tvb_create_from_top(offset) \
	tvb_new_subset(pi.compat_top_tvb, (offset), \
				pi.captured_len - (offset), pi.len - (offset))

#endif /* __TVBUFF_H__ */
