/* tvbuff.c
 *
 * Testy, Virtual(-izable) Buffer of guint8*'s
 *
 * "Testy" -- the buffer gets mad when an attempt to access data
 *		beyond the bounds of the buffer. An exception is thrown.
 *
 * "Virtual" -- the buffer can have its own data, can use a subset of
 *		the data of a backing tvbuff, or can be a composite of
 *		other tvbuffs.
 *
 * Copyright (c) 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Code to convert IEEE floating point formats to native floating point
 * derived from code Copyright (c) Ashok Narayanan, 2000
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

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "wsutil/pint.h"
#include "wsutil/sign_ext.h"
#include "wsutil/unicode-utils.h"
#include "wsutil/nstime.h"
#include "wsutil/time_util.h"
#include "wsutil/ws_mempbrk.h"
#include "tvbuff.h"
#include "tvbuff-int.h"
#include "strutil.h"
#include "to_str.h"
#include "charsets.h"
#include "proto.h"	/* XXX - only used for DISSECTOR_ASSERT, probably a new header file? */
#include "exceptions.h"

/*
 * Just make sure we include the prototype for strptime as well
 * (needed for glibc 2.2) but make sure we do this only if not
 * yet defined.
 */
#include <time.h>
/*#ifdef NEED_STRPTIME_H*/
#ifndef strptime
#include "wsutil/strptime.h"
#endif
 /*#endif*/

static guint64
_tvb_get_bits64(tvbuff_t *tvb, guint bit_offset, const gint total_no_of_bits);

static inline gint
_tvb_captured_length_remaining(const tvbuff_t *tvb, const gint offset);

static inline const guint8*
ensure_contiguous(tvbuff_t *tvb, const gint offset, const gint length);

static inline guint8 *
tvb_get_raw_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint length);

tvbuff_t *
tvb_new(const struct tvb_ops *ops)
{
	tvbuff_t *tvb;
	gsize     size = ops->tvb_size;

	g_assert(size >= sizeof(*tvb));

	tvb = (tvbuff_t *) g_slice_alloc(size);

	tvb->next	     = NULL;
	tvb->ops	     = ops;
	tvb->initialized     = FALSE;
	tvb->flags	     = 0;
	tvb->length	     = 0;
	tvb->reported_length = 0;
	tvb->real_data	     = NULL;
	tvb->raw_offset	     = -1;
	tvb->ds_tvb	     = NULL;

	return tvb;
}

static void
tvb_free_internal(tvbuff_t *tvb)
{
	gsize     size;

	DISSECTOR_ASSERT(tvb);

	if (tvb->ops->tvb_free)
		tvb->ops->tvb_free(tvb);

	size = tvb->ops->tvb_size;

	g_slice_free1(size, tvb);
}

/* XXX: just call tvb_free_chain();
 *      Not removed so that existing dissectors using tvb_free() need not be changed.
 *      I'd argue that existing calls to tvb_free() should have actually beeen
 *      calls to tvb_free_chain() although the calls were OK as long as no
 *      subsets, etc had been created on the tvb. */
void
tvb_free(tvbuff_t *tvb)
{
	tvb_free_chain(tvb);
}

void
tvb_free_chain(tvbuff_t  *tvb)
{
	tvbuff_t *next_tvb;
	DISSECTOR_ASSERT(tvb);
	while (tvb) {
		next_tvb = tvb->next;
		tvb_free_internal(tvb);
		tvb  = next_tvb;
	}
}

tvbuff_t *
tvb_new_chain(tvbuff_t *parent, tvbuff_t *backing)
{
	tvbuff_t *tvb = tvb_new_proxy(backing);

	tvb_add_to_chain(parent, tvb);
	return tvb;
}

void
tvb_add_to_chain(tvbuff_t *parent, tvbuff_t *child)
{
	tvbuff_t *tmp = child;

	DISSECTOR_ASSERT(parent);
	DISSECTOR_ASSERT(child);

	while (child) {
		tmp   = child;
		child = child->next;

		tmp->next    = parent->next;
		parent->next = tmp;
	}
}

#define COMPUTE_OFFSET(tvb, offset, offset_ptr, exception) \
	if (offset >= 0) { \
		/* Positive offset - relative to the beginning of the packet. */ \
		if ((guint) offset <= tvb->length) { \
			*offset_ptr = offset; \
		} else if ((guint) offset <= tvb->reported_length) { \
			exception = BoundsError; \
		} else if (tvb->flags & TVBUFF_FRAGMENT) { \
			exception = FragmentBoundsError; \
		} else { \
			exception = ReportedBoundsError; \
		} \
	} \
	else { \
		/* Negative offset - relative to the end of the packet. */ \
		if ((guint) -offset <= tvb->length) { \
			*offset_ptr = tvb->length + offset; \
		} else if ((guint) -offset <= tvb->reported_length) { \
			exception =  BoundsError; \
		} else if (tvb->flags & TVBUFF_FRAGMENT) { \
			exception = FragmentBoundsError; \
		} else { \
			exception = ReportedBoundsError; \
		} \
	} \

#define COMPUTE_OFFSET_AND_REMAINING(tvb, offset, offset_ptr, rem_len, exception) \
	if (offset >= 0) { \
		/* Positive offset - relative to the beginning of the packet. */ \
		if ((guint) offset <= tvb->length) { \
			*offset_ptr = offset; \
		} else if ((guint) offset <= tvb->reported_length) { \
			exception = BoundsError; \
		} else if (tvb->flags & TVBUFF_FRAGMENT) { \
			exception = FragmentBoundsError; \
		} else { \
			exception = ReportedBoundsError; \
		} \
	} \
	else { \
		/* Negative offset - relative to the end of the packet. */ \
		if ((guint) -offset <= tvb->length) { \
			*offset_ptr = tvb->length + offset; \
		} else if ((guint) -offset <= tvb->reported_length) { \
			exception =  BoundsError; \
		} else if (tvb->flags & TVBUFF_FRAGMENT) { \
			exception = FragmentBoundsError; \
		} else { \
			exception = ReportedBoundsError; \
		} \
	} \
	if (!exception) \
		rem_len = tvb->length - *offset_ptr; \

/* Computes the absolute offset and length based on a possibly-negative offset
 * and a length that is possible -1 (which means "to the end of the data").
 * Returns integer indicating whether the offset is in bounds (0) or
 * not (exception number). The integer ptrs are modified with the new offset and length.
 * No exception is thrown.
 *
 * XXX - we return success (0), if the offset is positive and right
 * after the end of the tvbuff (i.e., equal to the length).  We do this
 * so that a dissector constructing a subset tvbuff for the next protocol
 * will get a zero-length tvbuff, not an exception, if there's no data
 * left for the next protocol - we want the next protocol to be the one
 * that gets an exception, so the error is reported as an error in that
 * protocol rather than the containing protocol.  */
static inline int
check_offset_length_no_exception(const tvbuff_t *tvb,
				 const gint offset, gint const length_val,
				 guint *offset_ptr, guint *length_ptr)
{
	guint end_offset;
	int   exception = 0;

	DISSECTOR_ASSERT(offset_ptr);
	DISSECTOR_ASSERT(length_ptr);

	/* Compute the offset */
	COMPUTE_OFFSET(tvb, offset, offset_ptr, exception);
	if (exception)
		return exception;

	if (length_val < -1) {
		/* XXX - ReportedBoundsError? */
		return BoundsError;
	}

	/* Compute the length */
	if (length_val == -1)
		*length_ptr = tvb->length - *offset_ptr;
	else
		*length_ptr = length_val;

	/*
	 * Compute the offset of the first byte past the length.
	 */
	end_offset = *offset_ptr + *length_ptr;

	/*
	 * Check for an overflow
	 */
	if (end_offset < *offset_ptr)
		return BoundsError;

	/*
	 * Check whether that offset goes more than one byte past the
	 * end of the buffer.
	 *
	 * If not, return 0; otherwise, return exception
	 */
	if (G_LIKELY(end_offset <= tvb->length))
		return 0;
	else if (end_offset <= tvb->reported_length)
		return BoundsError;
	else if (tvb->flags & TVBUFF_FRAGMENT)
		return FragmentBoundsError;
	else
		return ReportedBoundsError;

}

/* Checks (+/-) offset and length and throws an exception if
 * either is out of bounds. Sets integer ptrs to the new offset
 * and length. */
static inline void
check_offset_length(const tvbuff_t *tvb,
		    const gint offset, gint const length_val,
		    guint *offset_ptr, guint *length_ptr)
{
	int exception;

	exception = check_offset_length_no_exception(tvb, offset, length_val, offset_ptr, length_ptr);
	if (exception)
		THROW(exception);
}

void
tvb_check_offset_length(const tvbuff_t *tvb,
		        const gint offset, gint const length_val,
		        guint *offset_ptr, guint *length_ptr)
{
	check_offset_length(tvb, offset, length_val, offset_ptr, length_ptr);
}

static const unsigned char left_aligned_bitmask[] = {
	0xff,
	0x80,
	0xc0,
	0xe0,
	0xf0,
	0xf8,
	0xfc,
	0xfe
};

tvbuff_t *
tvb_new_octet_aligned(tvbuff_t *tvb, guint32 bit_offset, gint32 no_of_bits)
{
	tvbuff_t     *sub_tvb = NULL;
	guint32       byte_offset;
	gint32        datalen, i;
	guint8        left, right, remaining_bits, *buf;
	const guint8 *data;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	byte_offset = bit_offset >> 3;
	left = bit_offset % 8; /* for left-shifting */
	right = 8 - left; /* for right-shifting */

	if (no_of_bits == -1) {
		datalen = _tvb_captured_length_remaining(tvb, byte_offset);
		remaining_bits = 0;
	} else {
		datalen = no_of_bits >> 3;
		remaining_bits = no_of_bits % 8;
		if (remaining_bits) {
			datalen++;
		}
	}

	/* already aligned -> shortcut */
	if ((left == 0) && (remaining_bits == 0)) {
		return tvb_new_subset(tvb, byte_offset, datalen, -1);
	}

	DISSECTOR_ASSERT(datalen>0);

	/* if at least one trailing byte is available, we must use the content
	* of that byte for the last shift (i.e. tvb_get_ptr() must use datalen + 1
	* if non extra byte is available, the last shifted byte requires
	* special treatment
	*/
	if (_tvb_captured_length_remaining(tvb, byte_offset) > datalen) {
		data = ensure_contiguous(tvb, byte_offset, datalen + 1); /* tvb_get_ptr */

		/* Do this allocation AFTER tvb_get_ptr() (which could throw an exception) */
		buf = (guint8 *)g_malloc(datalen);

		/* shift tvb data bit_offset bits to the left */
		for (i = 0; i < datalen; i++)
			buf[i] = (data[i] << left) | (data[i+1] >> right);
	} else {
		data = ensure_contiguous(tvb, byte_offset, datalen); /* tvb_get_ptr() */

		/* Do this allocation AFTER tvb_get_ptr() (which could throw an exception) */
		buf = (guint8 *)g_malloc(datalen);

		/* shift tvb data bit_offset bits to the left */
		for (i = 0; i < (datalen-1); i++)
			buf[i] = (data[i] << left) | (data[i+1] >> right);
		buf[datalen-1] = data[datalen-1] << left; /* set last octet */
	}
	buf[datalen-1] &= left_aligned_bitmask[remaining_bits];

	sub_tvb = tvb_new_child_real_data(tvb, buf, datalen, datalen);
	tvb_set_free_cb(sub_tvb, g_free);

	return sub_tvb;
}

static tvbuff_t *
tvb_generic_clone_offset_len(tvbuff_t *tvb, guint offset, guint len)
{
	tvbuff_t *cloned_tvb;

	guint8 *data = (guint8 *) g_malloc(len);

	tvb_memcpy(tvb, data, offset, len);

	cloned_tvb = tvb_new_real_data(data, len, len);
	tvb_set_free_cb(cloned_tvb, g_free);

	return cloned_tvb;
}

tvbuff_t *
tvb_clone_offset_len(tvbuff_t *tvb, guint offset, guint len)
{
	if (tvb->ops->tvb_clone) {
		tvbuff_t *cloned_tvb;

		cloned_tvb = tvb->ops->tvb_clone(tvb, offset, len);
		if (cloned_tvb)
			return cloned_tvb;
	}

	return tvb_generic_clone_offset_len(tvb, offset, len);
}

tvbuff_t *
tvb_clone(tvbuff_t *tvb)
{
	return tvb_clone_offset_len(tvb, 0, tvb->length);
}

guint
tvb_captured_length(const tvbuff_t *tvb)
{
	DISSECTOR_ASSERT(tvb && tvb->initialized);

	return tvb->length;
}

/* For tvbuff internal use */
static inline gint
_tvb_captured_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset, rem_length;
	int   exception = 0;

	COMPUTE_OFFSET_AND_REMAINING(tvb, offset, &abs_offset, rem_length, exception);
	if (exception)
		return 0;

	return rem_length;
}

gint
tvb_captured_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset, rem_length;
	int   exception = 0;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	COMPUTE_OFFSET_AND_REMAINING(tvb, offset, &abs_offset, rem_length, exception);
	if (exception)
		return 0;

	return rem_length;
}

guint
tvb_ensure_captured_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset, rem_length;
	int   exception = 0;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	COMPUTE_OFFSET_AND_REMAINING(tvb, offset, &abs_offset, rem_length, exception);
	if (exception)
		THROW(exception);

	if (rem_length == 0) {
		/*
		 * This routine ensures there's at least one byte available.
		 * There aren't any bytes available, so throw the appropriate
		 * exception.
		 */
		if (abs_offset >= tvb->reported_length) {
			if (tvb->flags & TVBUFF_FRAGMENT) {
				THROW(FragmentBoundsError);
			} else {
				THROW(ReportedBoundsError);
			}
		} else
			THROW(BoundsError);
	}
	return rem_length;
}




/* Validates that 'length' bytes are available starting from
 * offset (pos/neg). Does not throw an exception. */
gboolean
tvb_bytes_exist(const tvbuff_t *tvb, const gint offset, const gint length)
{
	guint abs_offset, abs_length;
	int   exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = check_offset_length_no_exception(tvb, offset, length, &abs_offset, &abs_length);
	if (exception)
		return FALSE;

	return TRUE;
}

/* Validates that 'length' bytes are available starting from
 * offset (pos/neg). Throws an exception if they aren't. */
void
tvb_ensure_bytes_exist(const tvbuff_t *tvb, const gint offset, const gint length)
{
	guint real_offset, end_offset;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	/*
	 * -1 doesn't mean "until end of buffer", as that's pointless
	 * for this routine.  We must treat it as a Really Large Positive
	 * Number, so that we throw an exception; we throw
	 * ReportedBoundsError, as if it were past even the end of a
	 * reassembled packet, and past the end of even the data we
	 * didn't capture.
	 *
	 * We do the same with other negative lengths.
	 */
	if (length < 0) {
		THROW(ReportedBoundsError);
	}

	/* XXX: Below this point could be replaced with a call to
	 * check_offset_length with no functional change, however this is a
	 * *very* hot path and check_offset_length is not well-optimized for
	 * this case, so we eat some code duplication for a lot of speedup. */

	if (offset >= 0) {
		/* Positive offset - relative to the beginning of the packet. */
		if ((guint) offset <= tvb->length) {
			real_offset = offset;
		} else if ((guint) offset <= tvb->reported_length) {
			THROW(BoundsError);
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			THROW(FragmentBoundsError);
		} else {
			THROW(ReportedBoundsError);
		}
	}
	else {
		/* Negative offset - relative to the end of the packet. */
		if ((guint) -offset <= tvb->length) {
			real_offset = tvb->length + offset;
		} else if ((guint) -offset <= tvb->reported_length) {
			THROW(BoundsError);
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			THROW(FragmentBoundsError);
		} else {
			THROW(ReportedBoundsError);
		}
	}

	/*
	 * Compute the offset of the first byte past the length.
	 */
	end_offset = real_offset + length;

	/*
	 * Check for an overflow
	 */
	if (end_offset < real_offset)
		THROW(BoundsError);

	if (G_LIKELY(end_offset <= tvb->length))
		return;
	else if (end_offset <= tvb->reported_length)
		THROW(BoundsError);
	else if (tvb->flags & TVBUFF_FRAGMENT)
		THROW(FragmentBoundsError);
	else
		THROW(ReportedBoundsError);
}

gboolean
tvb_offset_exists(const tvbuff_t *tvb, const gint offset)
{
	guint offset_ptr;
	int   exception = 0;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	COMPUTE_OFFSET(tvb, offset, &offset_ptr, exception);
	if (exception)
		return FALSE;

	/* compute_offset only throws an exception on >, not >= because of the
	 * comment above check_offset_length_no_exception, but here we want the
	 * opposite behaviour so we check ourselves... */
	if (offset_ptr < tvb->length) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

guint
tvb_reported_length(const tvbuff_t *tvb)
{
	DISSECTOR_ASSERT(tvb && tvb->initialized);

	return tvb->reported_length;
}

gint
tvb_reported_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint offset_ptr;
	int   exception = 0;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	COMPUTE_OFFSET(tvb, offset, &offset_ptr, exception);
	if (exception)
		return 0;

	if (tvb->reported_length >= offset_ptr)
		return tvb->reported_length - offset_ptr;
	else
		return 0;
}

/* Set the reported length of a tvbuff to a given value; used for protocols
 * whose headers contain an explicit length and where the calling
 * dissector's payload may include padding as well as the packet for
 * this protocol.
 * Also adjusts the data length. */
void
tvb_set_reported_length(tvbuff_t *tvb, const guint reported_length)
{
	DISSECTOR_ASSERT(tvb && tvb->initialized);

	if (reported_length > tvb->reported_length)
		THROW(ReportedBoundsError);

	tvb->reported_length = reported_length;
	if (reported_length < tvb->length)
		tvb->length = reported_length;
}

guint
tvb_offset_from_real_beginning_counter(const tvbuff_t *tvb, const guint counter)
{
	if (tvb->ops->tvb_offset)
		return tvb->ops->tvb_offset(tvb, counter);

	DISSECTOR_ASSERT_NOT_REACHED();
	return 0;
}

guint
tvb_offset_from_real_beginning(const tvbuff_t *tvb)
{
	return tvb_offset_from_real_beginning_counter(tvb, 0);
}

static inline const guint8*
ensure_contiguous_no_exception(tvbuff_t *tvb, const gint offset, const gint length, int *pexception)
{
	guint abs_offset, abs_length;
	int   exception;

	exception = check_offset_length_no_exception(tvb, offset, length, &abs_offset, &abs_length);
	if (exception) {
		if (pexception)
			*pexception = exception;
		return NULL;
	}

	/*
	 * We know that all the data is present in the tvbuff, so
	 * no exceptions should be thrown.
	 */
	if (tvb->real_data)
		return tvb->real_data + abs_offset;

	if (tvb->ops->tvb_get_ptr)
		return tvb->ops->tvb_get_ptr(tvb, abs_offset, abs_length);

	DISSECTOR_ASSERT_NOT_REACHED();
	return NULL;
}

static inline const guint8*
ensure_contiguous(tvbuff_t *tvb, const gint offset, const gint length)
{
	int           exception = 0;
	const guint8 *p;

	p = ensure_contiguous_no_exception(tvb, offset, length, &exception);
	if (p == NULL) {
		DISSECTOR_ASSERT(exception > 0);
		THROW(exception);
	}
	return p;
}

static inline const guint8*
fast_ensure_contiguous(tvbuff_t *tvb, const gint offset, const guint length)
{
	guint end_offset;
	guint u_offset;

	DISSECTOR_ASSERT(tvb && tvb->initialized);
	/* We don't check for overflow in this fast path so we only handle simple types */
	DISSECTOR_ASSERT(length <= 8);

	if (offset < 0 || !tvb->real_data) {
		return ensure_contiguous(tvb, offset, length);
	}

	u_offset = offset;
	end_offset = u_offset + length;

	if (end_offset <= tvb->length) {
		return tvb->real_data + u_offset;
	}

	if (end_offset > tvb->reported_length) {
		if (tvb->flags & TVBUFF_FRAGMENT) {
			THROW(FragmentBoundsError);
		} else {
			THROW(ReportedBoundsError);
		}
		/* not reached */
	}
	THROW(BoundsError);
	/* not reached */
	return NULL;
}

static inline const guint8*
guint8_pbrk(const guint8* haystack, size_t haystacklen, const guint8 *needles, guchar *found_needle)
{
	const guint8 *result = ws_mempbrk(haystack, haystacklen, needles);

	if (result && found_needle)
		*found_needle = *result;

	return result;
}



/************** ACCESSORS **************/

void *
tvb_memcpy(tvbuff_t *tvb, void *target, const gint offset, size_t length)
{
	guint	abs_offset, abs_length;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	/*
	 * XXX - we should eliminate the "length = -1 means 'to the end
	 * of the tvbuff'" convention, and use other means to achieve
	 * that; this would let us eliminate a bunch of checks for
	 * negative lengths in cases where the protocol has a 32-bit
	 * length field.
	 *
	 * Allowing -1 but throwing an assertion on other negative
	 * lengths is a bit more work with the length being a size_t;
	 * instead, we check for a length <= 2^31-1.
	 */
	DISSECTOR_ASSERT(length <= 0x7FFFFFFF);
	check_offset_length(tvb, offset, (gint) length, &abs_offset, &abs_length);

	if (tvb->real_data) {
		return memcpy(target, tvb->real_data + abs_offset, abs_length);
	}

	if (tvb->ops->tvb_memcpy)
		return tvb->ops->tvb_memcpy(tvb, target, abs_offset, abs_length);

	/* XXX, fallback to slower method */

	DISSECTOR_ASSERT_NOT_REACHED();
	return NULL;
}


/*
 * XXX - this doesn't treat a length of -1 as an error.
 * If it did, this could replace some code that calls
 * "tvb_ensure_bytes_exist()" and then allocates a buffer and copies
 * data to it.
 *
 * "composite_get_ptr()" depends on -1 not being
 * an error; does anything else depend on this routine treating -1 as
 * meaning "to the end of the buffer"?
 *
 * If scope is NULL, memory is allocated with g_malloc() and user must
 * explicitly free it with g_free().
 * If scope is not NULL, memory is allocated with the corresponding pool
 * lifetime.
 */
void *
tvb_memdup(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, size_t length)
{
	guint  abs_offset, abs_length;
	void  *duped;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	check_offset_length(tvb, offset, (gint) length, &abs_offset, &abs_length);

	duped = wmem_alloc(scope, abs_length);
	return tvb_memcpy(tvb, duped, abs_offset, abs_length);
}



const guint8*
tvb_get_ptr(tvbuff_t *tvb, const gint offset, const gint length)
{
	return ensure_contiguous(tvb, offset, length);
}

/* ---------------- */
guint8
tvb_get_guint8(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, sizeof(guint8));
	return *ptr;
}

guint16
tvb_get_ntohs(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, sizeof(guint16));
	return pntoh16(ptr);
}

guint32
tvb_get_ntoh24(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 3);
	return pntoh24(ptr);
}

guint32
tvb_get_ntohl(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, sizeof(guint32));
	return pntoh32(ptr);
}

guint64
tvb_get_ntoh40(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 5);
	return pntoh40(ptr);
}

gint64
tvb_get_ntohi40(tvbuff_t *tvb, const gint offset)
{
	guint64 ret;

	ret = ws_sign_ext64(tvb_get_ntoh40(tvb, offset), 40);

	return (gint64)ret;
}

guint64
tvb_get_ntoh48(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 6);
	return pntoh48(ptr);
}

gint64
tvb_get_ntohi48(tvbuff_t *tvb, const gint offset)
{
	guint64 ret;

	ret = ws_sign_ext64(tvb_get_ntoh48(tvb, offset), 48);

	return (gint64)ret;
}

guint64
tvb_get_ntoh56(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 7);
	return pntoh56(ptr);
}

gint64
tvb_get_ntohi56(tvbuff_t *tvb, const gint offset)
{
	guint64 ret;

	ret = ws_sign_ext64(tvb_get_ntoh56(tvb, offset), 56);

	return (gint64)ret;
}

guint64
tvb_get_ntoh64(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, sizeof(guint64));
	return pntoh64(ptr);
}

/*
 * Stuff for IEEE float handling on platforms that don't have IEEE
 * format as the native floating-point format.
 *
 * For now, we treat only the VAX as such a platform.
 *
 * XXX - other non-IEEE boxes that can run UNIX include some Crays,
 * and possibly other machines.
 *
 * It appears that the official Linux port to System/390 and
 * zArchitecture uses IEEE format floating point (not a
 * huge surprise).
 *
 * I don't know whether there are any other machines that
 * could run Wireshark and that don't use IEEE format.
 * As far as I know, all of the main commercial microprocessor
 * families on which OSes that support Wireshark can run
 * use IEEE format (x86, 68k, SPARC, MIPS, PA-RISC, Alpha,
 * IA-64, and so on).
 */

#if defined(vax)

#include <math.h>

/*
 * Single-precision.
 */
#define IEEE_SP_NUMBER_WIDTH	32	/* bits in number */
#define IEEE_SP_EXP_WIDTH	8	/* bits in exponent */
#define IEEE_SP_MANTISSA_WIDTH	23	/* IEEE_SP_NUMBER_WIDTH - 1 - IEEE_SP_EXP_WIDTH */

#define IEEE_SP_SIGN_MASK	0x80000000
#define IEEE_SP_EXPONENT_MASK	0x7F800000
#define IEEE_SP_MANTISSA_MASK	0x007FFFFF
#define IEEE_SP_INFINITY	IEEE_SP_EXPONENT_MASK

#define IEEE_SP_IMPLIED_BIT (1 << IEEE_SP_MANTISSA_WIDTH)
#define IEEE_SP_INFINITE ((1 << IEEE_SP_EXP_WIDTH) - 1)
#define IEEE_SP_BIAS ((1 << (IEEE_SP_EXP_WIDTH - 1)) - 1)

static int
ieee_float_is_zero(const guint32 w)
{
	return ((w & ~IEEE_SP_SIGN_MASK) == 0);
}

static gfloat
get_ieee_float(const guint32 w)
{
	long sign;
	long exponent;
	long mantissa;

	sign = w & IEEE_SP_SIGN_MASK;
	exponent = w & IEEE_SP_EXPONENT_MASK;
	mantissa = w & IEEE_SP_MANTISSA_MASK;

	if (ieee_float_is_zero(w)) {
		/* number is zero, unnormalized, or not-a-number */
		return 0.0;
	}
#if 0
	/*
	 * XXX - how to handle this?
	 */
	if (IEEE_SP_INFINITY == exponent) {
		/*
		 * number is positive or negative infinity, or a special value
		 */
		return (sign? MINUS_INFINITY: PLUS_INFINITY);
	}
#endif

	exponent = ((exponent >> IEEE_SP_MANTISSA_WIDTH) - IEEE_SP_BIAS) -
		IEEE_SP_MANTISSA_WIDTH;
	mantissa |= IEEE_SP_IMPLIED_BIT;

	if (sign)
		return -mantissa * pow(2, exponent);
	else
		return mantissa * pow(2, exponent);
}

/*
 * Double-precision.
 * We assume that if you don't have IEEE floating-point, you have a
 * compiler that understands 64-bit integral quantities.
 */
#define IEEE_DP_NUMBER_WIDTH	64	/* bits in number */
#define IEEE_DP_EXP_WIDTH	11	/* bits in exponent */
#define IEEE_DP_MANTISSA_WIDTH	52	/* IEEE_DP_NUMBER_WIDTH - 1 - IEEE_DP_EXP_WIDTH */

#define IEEE_DP_SIGN_MASK	G_GINT64_CONSTANT(0x8000000000000000)
#define IEEE_DP_EXPONENT_MASK	G_GINT64_CONSTANT(0x7FF0000000000000)
#define IEEE_DP_MANTISSA_MASK	G_GINT64_CONSTANT(0x000FFFFFFFFFFFFF)
#define IEEE_DP_INFINITY	IEEE_DP_EXPONENT_MASK

#define IEEE_DP_IMPLIED_BIT (G_GINT64_CONSTANT(1) << IEEE_DP_MANTISSA_WIDTH)
#define IEEE_DP_INFINITE ((1 << IEEE_DP_EXP_WIDTH) - 1)
#define IEEE_DP_BIAS ((1 << (IEEE_DP_EXP_WIDTH - 1)) - 1)

static int
ieee_double_is_zero(const guint64 w)
{
	return ((w & ~IEEE_SP_SIGN_MASK) == 0);
}

static gdouble
get_ieee_double(const guint64 w)
{
	gint64 sign;
	gint64 exponent;
	gint64 mantissa;

	sign = w & IEEE_DP_SIGN_MASK;
	exponent = w & IEEE_DP_EXPONENT_MASK;
	mantissa = w & IEEE_DP_MANTISSA_MASK;

	if (ieee_double_is_zero(w)) {
		/* number is zero, unnormalized, or not-a-number */
		return 0.0;
	}
#if 0
	/*
	 * XXX - how to handle this?
	 */
	if (IEEE_DP_INFINITY == exponent) {
		/*
		 * number is positive or negative infinity, or a special value
		 */
		return (sign? MINUS_INFINITY: PLUS_INFINITY);
	}
#endif

	exponent = ((exponent >> IEEE_DP_MANTISSA_WIDTH) - IEEE_DP_BIAS) -
		IEEE_DP_MANTISSA_WIDTH;
	mantissa |= IEEE_DP_IMPLIED_BIT;

	if (sign)
		return -mantissa * pow(2, exponent);
	else
		return mantissa * pow(2, exponent);
}
#endif

/*
 * Fetches an IEEE single-precision floating-point number, in
 * big-endian form, and returns a "float".
 *
 * XXX - should this be "double", in case there are IEEE single-
 * precision numbers that won't fit in some platform's native
 * "float" format?
 */
gfloat
tvb_get_ntohieee_float(tvbuff_t *tvb, const int offset)
{
#if defined(vax)
	return get_ieee_float(tvb_get_ntohl(tvb, offset));
#else
	union {
		gfloat	f;
		guint32 w;
	} ieee_fp_union;

	ieee_fp_union.w = tvb_get_ntohl(tvb, offset);
	return ieee_fp_union.f;
#endif
}

/*
 * Fetches an IEEE double-precision floating-point number, in
 * big-endian form, and returns a "double".
 */
gdouble
tvb_get_ntohieee_double(tvbuff_t *tvb, const int offset)
{
#if defined(vax)
	union {
		guint32 w[2];
		guint64 dw;
	} ieee_fp_union;
#else
	union {
		gdouble d;
		guint32 w[2];
	} ieee_fp_union;
#endif

#ifdef WORDS_BIGENDIAN
	ieee_fp_union.w[0] = tvb_get_ntohl(tvb, offset);
	ieee_fp_union.w[1] = tvb_get_ntohl(tvb, offset+4);
#else
	ieee_fp_union.w[0] = tvb_get_ntohl(tvb, offset+4);
	ieee_fp_union.w[1] = tvb_get_ntohl(tvb, offset);
#endif
#if defined(vax)
	return get_ieee_double(ieee_fp_union.dw);
#else
	return ieee_fp_union.d;
#endif
}

guint16
tvb_get_letohs(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, sizeof(guint16));
	return pletoh16(ptr);
}

guint32
tvb_get_letoh24(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 3);
	return pletoh24(ptr);
}

guint32
tvb_get_letohl(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, sizeof(guint32));
	return pletoh32(ptr);
}

guint64
tvb_get_letoh40(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 5);
	return pletoh40(ptr);
}

gint64
tvb_get_letohi40(tvbuff_t *tvb, const gint offset)
{
	guint64 ret;

	ret = ws_sign_ext64(tvb_get_letoh40(tvb, offset), 40);

	return (gint64)ret;
}

guint64
tvb_get_letoh48(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 6);
	return pletoh48(ptr);
}

gint64
tvb_get_letohi48(tvbuff_t *tvb, const gint offset)
{
	guint64 ret;

	ret = ws_sign_ext64(tvb_get_letoh48(tvb, offset), 48);

	return (gint64)ret;
}

guint64
tvb_get_letoh56(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 7);
	return pletoh56(ptr);
}

gint64
tvb_get_letohi56(tvbuff_t *tvb, const gint offset)
{
	guint64 ret;

	ret = ws_sign_ext64(tvb_get_letoh56(tvb, offset), 56);

	return (gint64)ret;
}

guint64
tvb_get_letoh64(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, sizeof(guint64));
	return pletoh64(ptr);
}

/*
 * Fetches an IEEE single-precision floating-point number, in
 * little-endian form, and returns a "float".
 *
 * XXX - should this be "double", in case there are IEEE single-
 * precision numbers that won't fit in some platform's native
 * "float" format?
 */
gfloat
tvb_get_letohieee_float(tvbuff_t *tvb, const int offset)
{
#if defined(vax)
	return get_ieee_float(tvb_get_letohl(tvb, offset));
#else
	union {
		gfloat f;
		guint32 w;
	} ieee_fp_union;

	ieee_fp_union.w = tvb_get_letohl(tvb, offset);
	return ieee_fp_union.f;
#endif
}

/*
 * Fetches an IEEE double-precision floating-point number, in
 * little-endian form, and returns a "double".
 */
gdouble
tvb_get_letohieee_double(tvbuff_t *tvb, const int offset)
{
#if defined(vax)
	union {
		guint32 w[2];
		guint64 dw;
	} ieee_fp_union;
#else
	union {
		gdouble d;
		guint32 w[2];
	} ieee_fp_union;
#endif

#ifdef WORDS_BIGENDIAN
	ieee_fp_union.w[0] = tvb_get_letohl(tvb, offset+4);
	ieee_fp_union.w[1] = tvb_get_letohl(tvb, offset);
#else
	ieee_fp_union.w[0] = tvb_get_letohl(tvb, offset);
	ieee_fp_union.w[1] = tvb_get_letohl(tvb, offset+4);
#endif
#if defined(vax)
	return get_ieee_double(ieee_fp_union.dw);
#else
	return ieee_fp_union.d;
#endif
}

static inline void
validate_single_byte_ascii_encoding(const guint encoding)
{
	const guint enc = encoding & ~ENC_STR_MASK;

	switch (enc) {
	    case ENC_UTF_16:
	    case ENC_UCS_2:
	    case ENC_UCS_4:
	    case ENC_3GPP_TS_23_038_7BITS:
	    case ENC_EBCDIC:
		REPORT_DISSECTOR_BUG("Invalid string encoding type passed to tvb_get_string_XXX");
		break;
	    default:
		break;
	}
	/* make sure something valid was set */
	if (enc == 0)
	    REPORT_DISSECTOR_BUG("No string encoding type passed to tvb_get_string_XXX");
}

GByteArray*
tvb_get_string_bytes(tvbuff_t *tvb, const gint offset, const gint length,
		     const guint encoding, GByteArray *bytes, gint *endoff)
{
	const gchar *ptr    = (gchar*) tvb_get_raw_string(wmem_packet_scope(), tvb, offset, length);
	const gchar *begin  = ptr;
	const gchar *end    = NULL;
	GByteArray  *retval = NULL;

	errno = EDOM;

	validate_single_byte_ascii_encoding(encoding);

	if (endoff) *endoff = 0;

	while (*begin == ' ') begin++;

	if (*begin && bytes) {
		if (hex_str_to_bytes_encoding(begin, bytes, &end, encoding, FALSE)) {
			if (bytes->len > 0) {
				if (endoff) *endoff = offset + (gint)(end - ptr);
				errno = 0;
				retval = bytes;
			}
		}
	}

	return retval;
}

/* support hex-encoded time values? */
nstime_t*
tvb_get_string_time(tvbuff_t *tvb, const gint offset, const gint length,
		    const guint encoding, nstime_t *ns, gint *endoff)
{
	const gchar *begin     = (gchar*) tvb_get_raw_string(wmem_packet_scope(), tvb, offset, length);
	const gchar *ptr       = begin;
	const gchar *end       = NULL;
	struct tm    tm;
	nstime_t*    retval    = NULL;
	char	     sign      = '+';
	int	     off_hr    = 0;
	int	     off_min   = 0;
	int	     num_chars = 0;
	gboolean     matched   = FALSE;

	errno = EDOM;

	validate_single_byte_ascii_encoding(encoding);

	DISSECTOR_ASSERT(ns);

	memset(&tm, 0, sizeof(tm));
	tm.tm_isdst = -1;
	ns->secs    = 0;
	ns->nsecs   = 0;

	while (*ptr == ' ') ptr++;

	if (*ptr) {
		/* note: sscanf is known to be inconsistent across platforms with respect
		   to whether a %n is counted as a return value or not, so we have to use
		   '>=' a lot */
		if ((encoding & ENC_ISO_8601_DATE_TIME) == ENC_ISO_8601_DATE_TIME) {
			/* TODO: using sscanf this many times is probably slow; might want
			   to parse it by hand in the future */
			/* 2014-04-07T05:41:56+00:00 */
			if (sscanf(ptr, "%d-%d-%d%*c%d:%d:%d%c%d:%d%n",
			    &tm.tm_year,
			    &tm.tm_mon,
			    &tm.tm_mday,
			    &tm.tm_hour,
			    &tm.tm_min,
			    &tm.tm_sec,
			    &sign,
			    &off_hr,
			    &off_min,
			    &num_chars) >= 9)
			{
				matched = TRUE;
			}
			/* no seconds is ok */
			else if (sscanf(ptr, "%d-%d-%d%*c%d:%d%c%d:%d%n",
			    &tm.tm_year,
			    &tm.tm_mon,
			    &tm.tm_mday,
			    &tm.tm_hour,
			    &tm.tm_min,
			    &sign,
			    &off_hr,
			    &off_min,
			    &num_chars) >= 8)
			{
				matched = TRUE;
			}
			/* 2007-04-05T14:30:56Z */
			else if (sscanf(ptr, "%d-%d-%d%*c%d:%d:%dZ%n",
			    &tm.tm_year,
			    &tm.tm_mon,
			    &tm.tm_mday,
			    &tm.tm_hour,
			    &tm.tm_min,
			    &tm.tm_sec,
			    &num_chars) >= 6)
			{
				matched = TRUE;
				off_hr = 0;
				off_min = 0;
			}
			/* 2007-04-05T14:30Z no seconds is ok */
			else if (sscanf(ptr, "%d-%d-%d%*c%d:%dZ%n",
			    &tm.tm_year,
			    &tm.tm_mon,
			    &tm.tm_mday,
			    &tm.tm_hour,
			    &tm.tm_min,
			    &num_chars) >= 5)
			{
				matched = TRUE;
				off_hr = 0;
				off_min = 0;
			}

			if (matched) {
				errno = 0;
				end = ptr + num_chars;
				tm.tm_mon--;
				if (tm.tm_year > 1900) tm.tm_year -= 1900;
				if (sign == '-') off_hr = -off_hr;
			}
		}
		else if (encoding & ENC_ISO_8601_DATE) {
			/* 2014-04-07 */
			if (sscanf(ptr, "%d-%d-%d%n",
			    &tm.tm_year,
			    &tm.tm_mon,
			    &tm.tm_mday,
			    &num_chars) >= 3)
			{
				errno = 0;
				end = ptr + num_chars;
				tm.tm_mon--;
				if (tm.tm_year > 1900) tm.tm_year -= 1900;
			}
		}
		else if (encoding & ENC_ISO_8601_TIME) {
			/* 2014-04-07 */
			if (sscanf(ptr, "%d:%d:%d%n",
			    &tm.tm_hour,
			    &tm.tm_min,
			    &tm.tm_sec,
			    &num_chars) >= 2)
			{
				/* what should we do about day/month/year? */
				/* setting it to "now" for now */
				time_t time_now = time(NULL);
				struct tm *tm_now = gmtime(&time_now);
				tm.tm_year = tm_now->tm_year;
				tm.tm_mon  = tm_now->tm_mon;
				tm.tm_mday = tm_now->tm_mday;
				end = ptr + num_chars;
				errno = 0;

			}
		}
		else if (encoding & ENC_RFC_822 || encoding & ENC_RFC_1123) {
			if (encoding & ENC_RFC_822) {
				/* this will unfortunately match ENC_RFC_1123 style
				   strings too, partially - probably need to do this the long way */
				end = strptime(ptr, "%a, %d %b %y %H:%M:%S", &tm);
				if (!end) end = strptime(ptr, "%a, %d %b %y %H:%M", &tm);
				if (!end) end = strptime(ptr, "%d %b %y %H:%M:%S", &tm);
				if (!end) end = strptime(ptr, "%d %b %y %H:%M", &tm);
			}
			else if (encoding & ENC_RFC_1123) {
				end = strptime(ptr, "%a, %d %b %Y %H:%M:%S", &tm);
				if (!end) end = strptime(ptr, "%a, %d %b %Y %H:%M", &tm);
				if (!end) end = strptime(ptr, "%d %b %Y %H:%M:%S", &tm);
				if (!end) end = strptime(ptr, "%d %b %Y %H:%M", &tm);
			}
			if (end) {
				errno = 0;
				if (*end == ' ') end++;
				if (g_ascii_strncasecmp(end, "UT", 2) == 0)
				{
					end += 2;
				}
				else if (g_ascii_strncasecmp(end, "GMT", 3) == 0)
				{
					end += 3;
				}
				else if (sscanf(end, "%c%2d%2d%n",
				    &sign,
				    &off_hr,
				    &off_min,
				    &num_chars) < 3)
				{
					errno = ERANGE;
				}
				if (sign == '-') off_hr = -off_hr;
			}
		}
	}

	if (errno == 0) {
		ns->secs = mktime_utc (&tm);
		if (off_hr > 0)
			ns->secs += (off_hr * 3600) + (off_min * 60);
		else if (off_hr < 0)
			ns->secs -= ((-off_hr) * 3600) + (off_min * 60);
		retval = ns;
		if (endoff)
		    *endoff = (gint)(offset + (end - begin));
	}

	return retval;
}

/* Fetch an IPv4 address, in network byte order.
 * We do *not* convert them to host byte order; we leave them in
 * network byte order. */
guint32
tvb_get_ipv4(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;
	guint32       addr;

	ptr = fast_ensure_contiguous(tvb, offset, sizeof(guint32));
	memcpy(&addr, ptr, sizeof addr);
	return addr;
}

/* Fetch an IPv6 address. */
void
tvb_get_ipv6(tvbuff_t *tvb, const gint offset, struct e_in6_addr *addr)
{
	const guint8 *ptr;

	ptr = ensure_contiguous(tvb, offset, sizeof(*addr));
	memcpy(addr, ptr, sizeof *addr);
}

/* Fetch a GUID. */
void
tvb_get_ntohguid(tvbuff_t *tvb, const gint offset, e_guid_t *guid)
{
	const guint8 *ptr = ensure_contiguous(tvb, offset, GUID_LEN);

	guid->data1 = pntoh32(ptr + 0);
	guid->data2 = pntoh16(ptr + 4);
	guid->data3 = pntoh16(ptr + 6);
	memcpy(guid->data4, ptr + 8, sizeof guid->data4);
}

void
tvb_get_letohguid(tvbuff_t *tvb, const gint offset, e_guid_t *guid)
{
	const guint8 *ptr = ensure_contiguous(tvb, offset, GUID_LEN);

	guid->data1 = pletoh32(ptr + 0);
	guid->data2 = pletoh16(ptr + 4);
	guid->data3 = pletoh16(ptr + 6);
	memcpy(guid->data4, ptr + 8, sizeof guid->data4);
}

/*
 * NOTE: to support code written when proto_tree_add_item() took a
 * gboolean as its last argument, with FALSE meaning "big-endian"
 * and TRUE meaning "little-endian", we treat any non-zero value of
 * "representation" as meaning "little-endian".
 */
void
tvb_get_guid(tvbuff_t *tvb, const gint offset, e_guid_t *guid, const guint representation)
{
	if (representation) {
		tvb_get_letohguid(tvb, offset, guid);
	} else {
		tvb_get_ntohguid(tvb, offset, guid);
	}
}

static const guint8 bit_mask8[] = {
	0x00,
	0x01,
	0x03,
	0x07,
	0x0f,
	0x1f,
	0x3f,
	0x7f,
	0xff
};

/* Get 1 - 8 bits */
guint8
tvb_get_bits8(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits)
{
	return (guint8)_tvb_get_bits64(tvb, bit_offset, no_of_bits);
}

/* Get 9 - 16 bits */
guint16
tvb_get_bits16(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits,const guint encoding _U_)
{
	/* note that encoding has no meaning here, as the tvb is considered to contain an octet array */
	return (guint16)_tvb_get_bits64(tvb, bit_offset, no_of_bits);
}

/* Get 1 - 32 bits */
guint32
tvb_get_bits32(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint encoding _U_)
{
	/* note that encoding has no meaning here, as the tvb is considered to contain an octet array */
	return (guint32)_tvb_get_bits64(tvb, bit_offset, no_of_bits);
}

/* Get 1 - 64 bits */
guint64
tvb_get_bits64(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint encoding _U_)
{
	/* note that encoding has no meaning here, as the tvb is considered to contain an octet array */
	return _tvb_get_bits64(tvb, bit_offset, no_of_bits);
}
/*
 * This function will dissect a sequence of bits that does not need to be byte aligned; the bits
 * set will be shown in the tree as ..10 10.. and the integer value returned if return_value is set.
 * Offset should be given in bits from the start of the tvb.
 * The function tolerates requests for more than 64 bits, but will only return the least significant 64 bits.
 */
static guint64
_tvb_get_bits64(tvbuff_t *tvb, guint bit_offset, const gint total_no_of_bits)
{
	guint64 value;
	guint	octet_offset = bit_offset >> 3;
	guint8	required_bits_in_first_octet = 8 - (bit_offset % 8);

	if(required_bits_in_first_octet > total_no_of_bits)
	{
		/* the required bits don't extend to the end of the first octet */
		guint8 right_shift = required_bits_in_first_octet - total_no_of_bits;
		value = (tvb_get_guint8(tvb, octet_offset) >> right_shift) & bit_mask8[total_no_of_bits % 8];
	}
	else
	{
		guint8 remaining_bit_length = total_no_of_bits;

		/* get the bits up to the first octet boundary */
		value = 0;
		required_bits_in_first_octet %= 8;
		if(required_bits_in_first_octet != 0)
		{
			value = tvb_get_guint8(tvb, octet_offset) & bit_mask8[required_bits_in_first_octet];
			remaining_bit_length -= required_bits_in_first_octet;
			octet_offset ++;
		}
		/* take the biggest words, shorts or octets that we can */
		while (remaining_bit_length > 7)
		{
			switch (remaining_bit_length >> 4)
			{
			case 0:
				/* 8 - 15 bits. (note that 0 - 7 would have dropped out of the while() loop) */
				value <<= 8;
				value += tvb_get_guint8(tvb, octet_offset);
				remaining_bit_length -= 8;
				octet_offset ++;
				break;

			case 1:
				/* 16 - 31 bits */
				value <<= 16;
				value += tvb_get_ntohs(tvb, octet_offset);
				remaining_bit_length -= 16;
				octet_offset += 2;
				break;

			case 2:
			case 3:
				/* 32 - 63 bits */
				value <<= 32;
				value += tvb_get_ntohl(tvb, octet_offset);
				remaining_bit_length -= 32;
				octet_offset += 4;
				break;

			default:
				/* 64 bits (or more???) */
				value = tvb_get_ntoh64(tvb, octet_offset);
				remaining_bit_length -= 64;
				octet_offset += 8;
				break;
			}
		}
		/* get bits from any partial octet at the tail */
		if(remaining_bit_length)
		{
			value <<= remaining_bit_length;
			value += (tvb_get_guint8(tvb, octet_offset) >> (8 - remaining_bit_length));
		}
	}
	return value;
}
/* Get 1 - 32 bits (should be deprecated as same as tvb_get_bits32??) */
guint32
tvb_get_bits(tvbuff_t *tvb, const guint bit_offset, const gint no_of_bits, const guint encoding _U_)
{
	/* note that encoding has no meaning here, as the tvb is considered to contain an octet array */
	return (guint32)_tvb_get_bits64(tvb, bit_offset, no_of_bits);
}

static gint
tvb_find_guint8_generic(tvbuff_t *tvb, guint abs_offset, guint limit, guint8 needle)
{
	const guint8 *ptr;
	const guint8 *result;

	ptr = ensure_contiguous(tvb, abs_offset, limit); /* tvb_get_ptr() */

	result = (const guint8 *) memchr(ptr, needle, limit);
	if (!result)
		return -1;

	return (gint) ((result - ptr) + abs_offset);
}

/* Find first occurrence of needle in tvbuff, starting at offset. Searches
 * at most maxlength number of bytes; if maxlength is -1, searches to
 * end of tvbuff.
 * Returns the offset of the found needle, or -1 if not found.
 * Will not throw an exception, even if maxlength exceeds boundary of tvbuff;
 * in that case, -1 will be returned if the boundary is reached before
 * finding needle. */
gint
tvb_find_guint8(tvbuff_t *tvb, const gint offset, const gint maxlength, const guint8 needle)
{
	const guint8 *result;
	guint	      abs_offset;
	guint	      tvbufflen;
	guint	      limit;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	check_offset_length(tvb, offset, -1, &abs_offset, &tvbufflen);

	/* Only search to end of tvbuff, w/o throwing exception. */
	if (maxlength == -1) {
		/* No maximum length specified; search to end of tvbuff. */
		limit = tvbufflen;
	}
	else if (tvbufflen < (guint) maxlength) {
		/* Maximum length goes past end of tvbuff; search to end
		   of tvbuff. */
		limit = tvbufflen;
	}
	else {
		/* Maximum length doesn't go past end of tvbuff; search
		   to that value. */
		limit = maxlength;
	}

	/* If we have real data, perform our search now. */
	if (tvb->real_data) {
		result = (const guint8 *)memchr(tvb->real_data + abs_offset, needle, limit);
		if (result == NULL) {
			return -1;
		}
		else {
			return (gint) (result - tvb->real_data);
		}
	}

	if (tvb->ops->tvb_find_guint8)
		return tvb->ops->tvb_find_guint8(tvb, abs_offset, limit, needle);

	return tvb_find_guint8_generic(tvb, offset, limit, needle);
}

static inline gint
tvb_pbrk_guint8_generic(tvbuff_t *tvb, guint abs_offset, guint limit, const guint8 *needles, guchar *found_needle)
{
	const guint8 *ptr;
	const guint8 *result;

	ptr = ensure_contiguous(tvb, abs_offset, limit); /* tvb_get_ptr */

	result = guint8_pbrk(ptr, limit, needles, found_needle);
	if (!result)
		return -1;

	return (gint) ((result - ptr) + abs_offset);
}

/* Find first occurrence of any of the needles in tvbuff, starting at offset.
 * Searches at most maxlength number of bytes; if maxlength is -1, searches
 * to end of tvbuff.
 * Returns the offset of the found needle, or -1 if not found.
 * Will not throw an exception, even if maxlength exceeds boundary of tvbuff;
 * in that case, -1 will be returned if the boundary is reached before
 * finding needle. */
gint
tvb_pbrk_guint8(tvbuff_t *tvb, const gint offset, const gint maxlength, const guint8 *needles, guchar *found_needle)
{
	const guint8 *result;
	guint	      abs_offset;
	guint	      tvbufflen;
	guint	      limit;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	check_offset_length(tvb, offset, -1, &abs_offset, &tvbufflen);

	/* Only search to end of tvbuff, w/o throwing exception. */
	if (maxlength == -1) {
		/* No maximum length specified; search to end of tvbuff. */
		limit = tvbufflen;
	}
	else if (tvbufflen < (guint) maxlength) {
		/* Maximum length goes past end of tvbuff; search to end
		   of tvbuff. */
		limit = tvbufflen;
	}
	else {
		/* Maximum length doesn't go past end of tvbuff; search
		   to that value. */
		limit = maxlength;
	}

	/* If we have real data, perform our search now. */
	if (tvb->real_data) {
		result = guint8_pbrk(tvb->real_data + abs_offset, limit, needles, found_needle);
		if (result == NULL) {
			return -1;
		}
		else {
			return (gint) (result - tvb->real_data);
		}
	}

	if (tvb->ops->tvb_pbrk_guint8)
		return tvb->ops->tvb_pbrk_guint8(tvb, abs_offset, limit, needles, found_needle);

	return tvb_pbrk_guint8_generic(tvb, abs_offset, limit, needles, found_needle);
}

/* Find size of stringz (NUL-terminated string) by looking for terminating
 * NUL.  The size of the string includes the terminating NUL.
 *
 * If the NUL isn't found, it throws the appropriate exception.
 */
guint
tvb_strsize(tvbuff_t *tvb, const gint offset)
{
	guint abs_offset, junk_length;
	gint  nul_offset;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	check_offset_length(tvb, offset, 0, &abs_offset, &junk_length);
	nul_offset = tvb_find_guint8(tvb, abs_offset, -1, 0);
	if (nul_offset == -1) {
		/*
		 * OK, we hit the end of the tvbuff, so we should throw
		 * an exception.
		 *
		 * Did we hit the end of the captured data, or the end
		 * of the actual data?	If there's less captured data
		 * than actual data, we presumably hit the end of the
		 * captured data, otherwise we hit the end of the actual
		 * data.
		 */
		if (tvb->length < tvb->reported_length) {
			THROW(BoundsError);
		} else {
			if (tvb->flags & TVBUFF_FRAGMENT) {
				THROW(FragmentBoundsError);
			} else {
				THROW(ReportedBoundsError);
			}
		}
	}
	return (nul_offset - abs_offset) + 1;
}

/* UTF-16/UCS-2 version of tvb_strsize */
/* Returns number of bytes including the (two-bytes) null terminator */
guint
tvb_unicode_strsize(tvbuff_t *tvb, const gint offset)
{
	guint     i = 0;
	gunichar2 uchar;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	do {
		/* Endianness doesn't matter when looking for null */
		uchar = tvb_get_ntohs(tvb, offset + i);
		i += 2;
	} while(uchar != 0);

	return i;
}

/* Find length of string by looking for end of string ('\0'), up to
 * 'maxlength' characters'; if 'maxlength' is -1, searches to end
 * of tvbuff.
 * Returns -1 if 'maxlength' reached before finding EOS. */
gint
tvb_strnlen(tvbuff_t *tvb, const gint offset, const guint maxlength)
{
	gint  result_offset;
	guint abs_offset, junk_length;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	check_offset_length(tvb, offset, 0, &abs_offset, &junk_length);

	result_offset = tvb_find_guint8(tvb, abs_offset, maxlength, 0);

	if (result_offset == -1) {
		return -1;
	}
	else {
		return result_offset - abs_offset;
	}
}

/*
 * Implement strneql etc
 */

/*
 * Call strncmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
gint
tvb_strneql(tvbuff_t *tvb, const gint offset, const gchar *str, const size_t size)
{
	const guint8 *ptr;

	ptr = ensure_contiguous_no_exception(tvb, offset, (gint)size, NULL);

	if (ptr) {
		int cmp = strncmp((const char *)ptr, str, size);

		/*
		 * Return 0 if equal, -1 otherwise.
		 */
		return (cmp == 0 ? 0 : -1);
	} else {
		/*
		 * Not enough characters in the tvbuff to match the
		 * string.
		 */
		return -1;
	}
}

/*
 * Call g_ascii_strncasecmp after checking if enough chars left, returning
 * 0 if it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
gint
tvb_strncaseeql(tvbuff_t *tvb, const gint offset, const gchar *str, const size_t size)
{
	const guint8 *ptr;

	ptr = ensure_contiguous_no_exception(tvb, offset, (gint)size, NULL);

	if (ptr) {
		int cmp = g_ascii_strncasecmp((const char *)ptr, str, size);

		/*
		 * Return 0 if equal, -1 otherwise.
		 */
		return (cmp == 0 ? 0 : -1);
	} else {
		/*
		 * Not enough characters in the tvbuff to match the
		 * string.
		 */
		return -1;
	}
}

/*
 * Call memcmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
gint
tvb_memeql(tvbuff_t *tvb, const gint offset, const guint8 *str, size_t size)
{
	const guint8 *ptr;

	ptr = ensure_contiguous_no_exception(tvb, offset, (gint) size, NULL);

	if (ptr) {
		int cmp = memcmp(ptr, str, size);

		/*
		 * Return 0 if equal, -1 otherwise.
		 */
		return (cmp == 0 ? 0 : -1);
	} else {
		/*
		 * Not enough characters in the tvbuff to match the
		 * string.
		 */
		return -1;
	}
}

/*
 * Format the data in the tvb from offset for length ...
 */
gchar *
tvb_format_text(tvbuff_t *tvb, const gint offset, const gint size)
{
	const guint8 *ptr;
	gint          len;

	len = (size > 0) ? size : 0;

	ptr = ensure_contiguous(tvb, offset, size);
	return format_text(ptr, len);
}

/*
 * Format the data in the tvb from offset for length ...
 */
gchar *
tvb_format_text_wsp(tvbuff_t *tvb, const gint offset, const gint size)
{
	const guint8 *ptr;
	gint          len;

	len = (size > 0) ? size : 0;

	ptr = ensure_contiguous(tvb, offset, size);
	return format_text_wsp(ptr, len);
}

/*
 * Like "tvb_format_text()", but for null-padded strings; don't show
 * the null padding characters as "\000".
 */
gchar *
tvb_format_stringzpad(tvbuff_t *tvb, const gint offset, const gint size)
{
	const guint8 *ptr, *p;
	gint          len;
	gint          stringlen;

	len = (size > 0) ? size : 0;

	ptr = ensure_contiguous(tvb, offset, size);
	for (p = ptr, stringlen = 0; stringlen < len && *p != '\0'; p++, stringlen++)
		;
	return format_text(ptr, stringlen);
}

/*
 * Like "tvb_format_text_wsp()", but for null-padded strings; don't show
 * the null padding characters as "\000".
 */
gchar *
tvb_format_stringzpad_wsp(tvbuff_t *tvb, const gint offset, const gint size)
{
	const guint8 *ptr, *p;
	gint          len;
	gint          stringlen;

	len = (size > 0) ? size : 0;

	ptr = ensure_contiguous(tvb, offset, size);
	for (p = ptr, stringlen = 0; stringlen < len && *p != '\0'; p++, stringlen++)
		;
	return format_text_wsp(ptr, stringlen);
}

/* Unicode REPLACEMENT CHARACTER */
#define UNREPL 0x00FFFD

/*
 * All string functions below take a scope as an argument.
 *
 *
 * If scope is NULL, memory is allocated with g_malloc() and user must
 * explicitly free it with g_free().
 * If scope is not NULL, memory is allocated with the corresponding pool
 * lifetime.
 *
 * All functions throw an exception if the tvbuff ends before the string
 * does.
 */

/*
 * Given a wmem scope, tvbuff, an offset, and a length, treat the string
 * of bytes referred to by the tvbuff, offset, and length as an ASCII string,
 * with all bytes with the high-order bit set being invalid, and return a
 * pointer to a UTF-8 string, allocated using the wmem scope.
 *
 * Octets with the highest bit set will be converted to the Unicode
 * REPLACEMENT CHARACTER.
 */
static guint8 *
tvb_get_ascii_string(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint length)
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_ascii_string(scope, ptr, length);
}

/*
 * Given a wmem scope, a tvbuff, an offset, and a length, treat the string
 * of bytes referred to by the tvbuff, the offset. and the length as a UTF-8
 * string, and return a pointer to that string, allocated using the wmem scope.
 *
 * XXX - should map invalid UTF-8 sequences to UNREPL.
 */
static guint8 *
tvb_get_utf_8_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint length)
{
	guint8 *strbuf;

	tvb_ensure_bytes_exist(tvb, offset, length); /* make sure length = -1 fails */
	strbuf = (guint8 *)wmem_alloc(scope, length + 1);
	tvb_memcpy(tvb, strbuf, offset, length);
	strbuf[length] = '\0';
	return strbuf;
}

/*
 * Given a wmem scope, tvbuff, an offset, and a length, treat the string
 * of bytes referred to by the tvbuff, the offset, and the length as a
 * raw string, and return a pointer to that string, allocated using the
 * wmem scope. This means a null is appended at the end, but no replacement
 * checking is done otherwise. Currently tvb_get_utf_8_string() does not
 * replace either, but it might in the future.
 *
 * Also, this one allows a length of -1 to mean get all, but does not
 * allow a negative offset.
 */
static inline guint8 *
tvb_get_raw_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint length)
{
	guint8 *strbuf;
	gint    abs_length = length;

	DISSECTOR_ASSERT(offset     >=  0);
	DISSECTOR_ASSERT(abs_length >= -1);

	if (abs_length < 0)
		abs_length = tvb->length - offset;

	tvb_ensure_bytes_exist(tvb, offset, abs_length);
	strbuf = (guint8 *)wmem_alloc(scope, abs_length + 1);
	tvb_memcpy(tvb, strbuf, offset, abs_length);
	strbuf[abs_length] = '\0';
	return strbuf;
}

/*
 * Given a wmem scope, a tvbuff, an offset, and a length, treat the string
 * of bytes referred to by the tvbuff, the offset, and the length as an
 * ISO 8859/1 string, and return a pointer to a UTF-8 string, allocated
 * using the wmem scope.
 */
static guint8 *
tvb_get_string_8859_1(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint length)
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_8859_1_string(scope, ptr, length);
}

/*
 * Given a wmem scope, a tvbuff, an offset, and a length, and a translation
 * table, treat the string of bytes referred to by the tvbuff, the offset,
 * and the length as a string encoded using one octet per character, with
 * octets with the high-order bit clear being ASCII and octets with the
 * high-order bit set being mapped by the translation table to 2-byte
 * Unicode Basic Multilingual Plane characters (including REPLACEMENT
 * CHARACTER), and return a pointer to a UTF-8 string, allocated with the
 * wmem scope.
 */
static guint8 *
tvb_get_string_unichar2(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint length, const gunichar2 table[0x80])
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_unichar2_string(scope, ptr, length, table);
}

/*
 * Given a wmem scope, a tvbuff, an offset, a length, and an encoding
 * giving the byte order, treat the string of bytes referred to by the
 * tvbuff, the offset, and the length as a UCS-2 encoded string in
 * the byte order in question, containing characters from the Basic
 * Multilingual Plane (plane 0) of Unicode, and return a pointer to a
 * UTF-8 string, allocated with the wmem scope.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN.
 *
 * Specify length in bytes.
 *
 * XXX - should map lead and trail surrogate values to REPLACEMENT
 * CHARACTERs (0xFFFD)?
 * XXX - if there are an odd number of bytes, should put a
 * REPLACEMENT CHARACTER at the end.
 */
static guint8 *
tvb_get_ucs_2_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint length, const guint encoding)
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_ucs_2_string(scope, ptr, length, encoding);
}

/*
 * Given a wmem scope, a tvbuff, an offset, a length, and an encoding
 * giving the byte order, treat the string of bytes referred to by the
 * tvbuff, the offset, and the length as a UTF-16 encoded string in
 * the byte order in question, and return a pointer to a UTF-8 string,
 * allocated with the wmem scope.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN.
 *
 * Specify length in bytes.
 *
 * XXX - should map surrogate errors to REPLACEMENT CHARACTERs (0xFFFD).
 * XXX - should map code points > 10FFFF to REPLACEMENT CHARACTERs.
 * XXX - if there are an odd number of bytes, should put a
 * REPLACEMENT CHARACTER at the end.
 */
static guint8 *
tvb_get_utf_16_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint length, const guint encoding)
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_utf_16_string(scope, ptr, length, encoding);
}

/*
 * Given a wmem scope, a tvbuff, an offset, a length, and an encoding
 * giving the byte order, treat the string of bytes referred to by the
 * tvbuff, the offset, and the length as a UCS-4 encoded string in
 * the byte order in question, and return a pointer to a UTF-8 string,
 * allocated with the wmem scope.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN
 *
 * Specify length in bytes
 *
 * XXX - should map lead and trail surrogate values to a "substitute"
 * UTF-8 character?
 * XXX - should map code points > 10FFFF to REPLACEMENT CHARACTERs.
 * XXX - if the number of bytes isn't a multiple of 4, should put a
 * REPLACEMENT CHARACTER at the end.
 */
static gchar *
tvb_get_ucs_4_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint length, const guint encoding)
{
	const guint8 *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_ucs_4_string(scope, ptr, length, encoding);
}

gchar *
tvb_get_ts_23_038_7bits_string(wmem_allocator_t *scope, tvbuff_t *tvb,
	const gint bit_offset, gint no_of_chars)
{
	gint           in_offset = bit_offset >> 3; /* Current pointer to the input buffer */
	gint           length = ((no_of_chars + 1) * 7 + (bit_offset & 0x07)) >> 3;
	const guint8  *ptr;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	ptr = ensure_contiguous(tvb, in_offset, length);
	return get_ts_23_038_7bits_string(scope, ptr, bit_offset, no_of_chars);
}

gchar *
tvb_get_ascii_7bits_string(wmem_allocator_t *scope, tvbuff_t *tvb,
	const gint bit_offset, gint no_of_chars)
{
	gint           in_offset = bit_offset >> 3; /* Current pointer to the input buffer */
	gint           length = ((no_of_chars + 1) * 7 + (bit_offset & 0x07)) >> 3;
	const guint8  *ptr;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	ptr = ensure_contiguous(tvb, in_offset, length);
	return get_ascii_7bits_string(scope, ptr, bit_offset, no_of_chars);
}

/*
 * Given a wmem scope, a tvbuff, an offset, and a length, treat the string
 * of bytes referred to by the tvbuff, offset, and length as a string encoded
 * in EBCDIC using one octet per character, and return a pointer to a
 * UTF-8 string, allocated using the wmem scope.
 */
static guint8 *
tvb_get_ebcdic_string(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint length)
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_ebcdic_string(scope, ptr, length);
}

/*
 * Given a tvbuff, an offset, a length, and an encoding, allocate a
 * buffer big enough to hold a non-null-terminated string of that length
 * at that offset, plus a trailing '\0', copy into the buffer the
 * string as converted from the appropriate encoding to UTF-8, and
 * return a pointer to the string.
 */
guint8 *
tvb_get_string_enc(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset,
			     const gint length, const guint encoding)
{
	guint8 *strptr;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	/* make sure length = -1 fails */
	if (length < 0) {
		THROW(ReportedBoundsError);
	}

	switch (encoding & ENC_CHARENCODING_MASK) {

	case ENC_ASCII:
	default:
		/*
		 * For now, we treat bogus values as meaning
		 * "ASCII" rather than reporting an error,
		 * for the benefit of old dissectors written
		 * when the last argument to proto_tree_add_item()
		 * was a gboolean for the byte order, not an
		 * encoding value, and passed non-zero values
		 * other than TRUE to mean "little-endian".
		 */
		strptr = tvb_get_ascii_string(scope, tvb, offset, length);
		break;

	case ENC_UTF_8:
		/*
		 * XXX - should map lead and trail surrogate value code
		 * points to a "substitute" UTF-8 character?
		 * XXX - should map code points > 10FFFF to REPLACEMENT
		 * CHARACTERs.
		 */
		strptr = tvb_get_utf_8_string(scope, tvb, offset, length);
		break;

	case ENC_UTF_16:
		strptr = tvb_get_utf_16_string(scope, tvb, offset, length,
		    encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_UCS_2:
		strptr = tvb_get_ucs_2_string(scope, tvb, offset, length,
		    encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_UCS_4:
		strptr = tvb_get_ucs_4_string(scope, tvb, offset, length,
		    encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_ISO_8859_1:
		/*
		 * ISO 8859-1 printable code point values are equal
		 * to the equivalent Unicode code point value, so
		 * no translation table is needed.
		 */
		strptr = tvb_get_string_8859_1(scope, tvb, offset, length);
		break;

	case ENC_ISO_8859_2:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_2);
		break;

	case ENC_ISO_8859_3:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_3);
		break;

	case ENC_ISO_8859_4:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_4);
		break;

	case ENC_ISO_8859_5:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_5);
		break;

	case ENC_ISO_8859_6:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_6);
		break;

	case ENC_ISO_8859_7:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_7);
		break;

	case ENC_ISO_8859_8:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_8);
		break;

	case ENC_ISO_8859_9:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_9);
		break;

	case ENC_ISO_8859_10:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_10);
		break;

	case ENC_ISO_8859_11:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_11);
		break;

	case ENC_ISO_8859_13:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_13);
		break;

	case ENC_ISO_8859_14:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_14);
		break;

	case ENC_ISO_8859_15:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_15);
		break;

	case ENC_ISO_8859_16:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_16);
		break;

	case ENC_WINDOWS_1250:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp1250);
		break;

	case ENC_MAC_ROMAN:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_mac_roman);
		break;

	case ENC_CP437:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp437);
		break;

	case ENC_3GPP_TS_23_038_7BITS:
		{
			gint bit_offset  = offset << 3;
			gint no_of_chars = (length << 3) / 7;
			strptr = tvb_get_ts_23_038_7bits_string(scope, tvb, bit_offset, no_of_chars);
		}
		break;

	case ENC_ASCII_7BITS:
		{
			gint bit_offset  = offset << 3;
			gint no_of_chars = (length << 3) / 7;
			strptr = tvb_get_ascii_7bits_string(scope, tvb, bit_offset, no_of_chars);
		}
		break;

	case ENC_EBCDIC:
		/*
		 * XXX - multiple "dialects" of EBCDIC?
		 */
		strptr = tvb_get_ebcdic_string(scope, tvb, offset, length);
		break;
	}
	return strptr;
}

/*
 * This is like tvb_get_string_enc(), except that it handles null-padded
 * strings.
 *
 * Currently, string values are stored as UTF-8 null-terminated strings,
 * so nothing needs to be done differently for null-padded strings; we
 * could save a little memory by not storing the null padding.
 *
 * If we ever store string values differently, in a fashion that doesn't
 * involve null termination, that might change.
 */
guint8 *
tvb_get_stringzpad(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset,
		   const gint length, const guint encoding)
{
	return tvb_get_string_enc(scope, tvb, offset, length, encoding);
}

/*
 * These routines are like the above routines, except that they handle
 * null-terminated strings.  They find the length of that string (and
 * throw an exception if the tvbuff ends before we find the null), and
 * also return through a pointer the length of the string, in bytes,
 * including the terminating null (the terminating null being 2 bytes
 * for UCS-2 and UTF-16, 4 bytes for UCS-4, and 1 byte for other
 * encodings).
 */
static guint8 *
tvb_get_ascii_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint *lengthp)
{
	guint	       size;
	const guint8  *ptr;

	size = tvb_strsize(tvb, offset);
	ptr  = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_ascii_string(scope, ptr, size);
}

static guint8 *
tvb_get_utf_8_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint *lengthp)
{
	guint   size;
	guint8 *strptr;

	size   = tvb_strsize(tvb, offset);
	strptr = (guint8 *)wmem_alloc(scope, size);
	tvb_memcpy(tvb, strptr, offset, size);
	if (lengthp)
		*lengthp = size;
	return strptr;
}

static guint8 *
tvb_get_stringz_8859_1(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint *lengthp)
{
	guint size;
	const guint8  *ptr;

	size = tvb_strsize(tvb, offset);
	ptr = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_8859_1_string(scope, ptr, size);
}

static guint8 *
tvb_get_stringz_unichar2(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint *lengthp, const gunichar2 table[0x80])
{
	guint size;
	const guint8  *ptr;

	size = tvb_strsize(tvb, offset);
	ptr = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_unichar2_string(scope, ptr, size, table);
}

/*
 * Given a tvbuff and an offset, with the offset assumed to refer to
 * a null-terminated string, find the length of that string (and throw
 * an exception if the tvbuff ends before we find the null), ensure that
 * the TVB is flat, and return a pointer to the string (in the TVB).
 * Also return the length of the string (including the terminating null)
 * through a pointer.
 *
 * As long as we aren't using composite TVBs, this saves the cycles used
 * (often unnecessariliy) in allocating a buffer and copying the string into
 * it.  (If we do start using composite TVBs, we may want to replace this
 * function with the _ephemeral version.)
 */
const guint8 *
tvb_get_const_stringz(tvbuff_t *tvb, const gint offset, gint *lengthp)
{
	guint         size;
	const guint8 *strptr;

	size   = tvb_strsize(tvb, offset);
	strptr = ensure_contiguous(tvb, offset, size);
	if (lengthp)
		*lengthp = size;
	return strptr;
}

static gchar *
tvb_get_ucs_2_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint *lengthp, const guint encoding)
{
	gint           size;    /* Number of bytes in string */
	const guint8  *ptr;

	size = tvb_unicode_strsize(tvb, offset);
	ptr = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_ucs_2_string(scope, ptr, size, encoding);
}

static gchar *
tvb_get_utf_16_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint *lengthp, const guint encoding)
{
	gint           size;
	const guint8  *ptr;

	size = tvb_unicode_strsize(tvb, offset);
	ptr = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_utf_16_string(scope, ptr, size, encoding);
}

static gchar *
tvb_get_ucs_4_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint *lengthp, const guint encoding)
{
	gint           size;
	gunichar       uchar;
	const guint8  *ptr;

	size = 0;
	do {
		/* Endianness doesn't matter when looking for null */
		uchar = tvb_get_ntohl(tvb, offset + size);
		size += 4;
	} while(uchar != 0);

	ptr = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_ucs_4_string(scope, ptr, size, encoding);
}

static guint8 *
tvb_get_ebcdic_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint *lengthp)
{
	guint	       size;
	const guint8  *ptr;

	size = tvb_strsize(tvb, offset);
	ptr  = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_ebcdic_string(scope, ptr, size);
}

guint8 *
tvb_get_stringz_enc(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint *lengthp, const guint encoding)
{
	guint8 *strptr;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	switch (encoding & ENC_CHARENCODING_MASK) {

	case ENC_ASCII:
	default:
		/*
		 * For now, we treat bogus values as meaning
		 * "ASCII" rather than reporting an error,
		 * for the benefit of old dissectors written
		 * when the last argument to proto_tree_add_item()
		 * was a gboolean for the byte order, not an
		 * encoding value, and passed non-zero values
		 * other than TRUE to mean "little-endian".
		 */
		strptr = tvb_get_ascii_stringz(scope, tvb, offset, lengthp);
		break;

	case ENC_UTF_8:
		/*
		 * XXX - should map all invalid UTF-8 sequences
		 * to a "substitute" UTF-8 character.
		 * XXX - should map code points > 10FFFF to REPLACEMENT
		 * CHARACTERs.
		 */
		strptr = tvb_get_utf_8_stringz(scope, tvb, offset, lengthp);
		break;

	case ENC_UTF_16:
		strptr = tvb_get_utf_16_stringz(scope, tvb, offset, lengthp,
		    encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_UCS_2:
		strptr = tvb_get_ucs_2_stringz(scope, tvb, offset, lengthp,
		    encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_UCS_4:
		strptr = tvb_get_ucs_4_stringz(scope, tvb, offset, lengthp,
		    encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_ISO_8859_1:
		/*
		 * ISO 8859-1 printable code point values are equal
		 * to the equivalent Unicode code point value, so
		 * no translation table is needed.
		 */
		strptr = tvb_get_stringz_8859_1(scope, tvb, offset, lengthp);
		break;

	case ENC_ISO_8859_2:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_2);
		break;

	case ENC_ISO_8859_3:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_3);
		break;

	case ENC_ISO_8859_4:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_4);
		break;

	case ENC_ISO_8859_5:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_5);
		break;

	case ENC_ISO_8859_6:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_6);
		break;

	case ENC_ISO_8859_7:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_7);
		break;

	case ENC_ISO_8859_8:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_8);
		break;

	case ENC_ISO_8859_9:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_9);
		break;

	case ENC_ISO_8859_10:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_10);
		break;

	case ENC_ISO_8859_11:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_11);
		break;

	case ENC_ISO_8859_13:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_13);
		break;

	case ENC_ISO_8859_14:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_14);
		break;

	case ENC_ISO_8859_15:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_15);
		break;

	case ENC_ISO_8859_16:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_16);
		break;

	case ENC_WINDOWS_1250:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_cp1250);
		break;

	case ENC_MAC_ROMAN:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_mac_roman);
		break;

	case ENC_CP437:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_cp437);
		break;

	case ENC_3GPP_TS_23_038_7BITS:
		REPORT_DISSECTOR_BUG("TS 23.038 7bits has no null character and doesn't support null-terminated strings");
		break;

	case ENC_ASCII_7BITS:
		REPORT_DISSECTOR_BUG("tvb_get_stringz_enc function with ENC_ASCII_7BITS not implemented yet");
		break;

	case ENC_EBCDIC:
		/*
		 * XXX - multiple "dialects" of EBCDIC?
		 */
		strptr = tvb_get_ebcdic_stringz(scope, tvb, offset, lengthp);
		break;
	}

	return strptr;
}

/* Looks for a stringz (NUL-terminated string) in tvbuff and copies
 * no more than bufsize number of bytes, including terminating NUL, to buffer.
 * Returns length of string (not including terminating NUL), or -1 if the string was
 * truncated in the buffer due to not having reached the terminating NUL.
 * In this way, it acts like g_snprintf().
 *
 * bufsize MUST be greater than 0.
 *
 * When processing a packet where the remaining number of bytes is less
 * than bufsize, an exception is not thrown if the end of the packet
 * is reached before the NUL is found. If no NUL is found before reaching
 * the end of the short packet, -1 is still returned, and the string
 * is truncated with a NUL, albeit not at buffer[bufsize - 1], but
 * at the correct spot, terminating the string.
 *
 * *bytes_copied will contain the number of bytes actually copied,
 * including the terminating-NUL.
 */
static gint
_tvb_get_nstringz(tvbuff_t *tvb, const gint offset, const guint bufsize, guint8* buffer, gint *bytes_copied)
{
	gint     stringlen;
	guint    abs_offset;
	gint     limit, len;
	gboolean decreased_max = FALSE;

	/* Only read to end of tvbuff, w/o throwing exception. */
	check_offset_length(tvb, offset, -1, &abs_offset, &len);

	/* There must at least be room for the terminating NUL. */
	DISSECTOR_ASSERT(bufsize != 0);

	/* If there's no room for anything else, just return the NUL. */
	if (bufsize == 1) {
		buffer[0] = 0;
		*bytes_copied = 1;
		return 0;
	}

	/* check_offset_length() won't throw an exception if we're
	 * looking at the byte immediately after the end of the tvbuff. */
	if (len == 0) {
		THROW(ReportedBoundsError);
	}

	/* This should not happen because check_offset_length() would
	 * have already thrown an exception if 'offset' were out-of-bounds.
	 */
	DISSECTOR_ASSERT(len != -1);

	/*
	 * If we've been passed a negative number, bufsize will
	 * be huge.
	 */
	DISSECTOR_ASSERT(bufsize <= G_MAXINT);

	if ((guint)len < bufsize) {
		limit = len;
		decreased_max = TRUE;
	}
	else {
		limit = bufsize;
	}

	stringlen = tvb_strnlen(tvb, abs_offset, limit - 1);
	/* If NUL wasn't found, copy the data and return -1 */
	if (stringlen == -1) {
		tvb_memcpy(tvb, buffer, abs_offset, limit);
		if (decreased_max) {
			buffer[limit] = 0;
			/* Add 1 for the extra NUL that we set at buffer[limit],
			 * pretending that it was copied as part of the string. */
			*bytes_copied = limit + 1;
		}
		else {
			*bytes_copied = limit;
		}
		return -1;
	}

	/* Copy the string to buffer */
	tvb_memcpy(tvb, buffer, abs_offset, stringlen + 1);
	*bytes_copied = stringlen + 1;
	return stringlen;
}

/* Looks for a stringz (NUL-terminated string) in tvbuff and copies
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
gint
tvb_get_nstringz(tvbuff_t *tvb, const gint offset, const guint bufsize, guint8 *buffer)
{
	gint bytes_copied;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	return _tvb_get_nstringz(tvb, offset, bufsize, buffer, &bytes_copied);
}

/* Like tvb_get_nstringz(), but never returns -1. The string is guaranteed to
 * have a terminating NUL. If the string was truncated when copied into buffer,
 * a NUL is placed at the end of buffer to terminate it.
 */
gint
tvb_get_nstringz0(tvbuff_t *tvb, const gint offset, const guint bufsize, guint8* buffer)
{
	gint	len, bytes_copied;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	len = _tvb_get_nstringz(tvb, offset, bufsize, buffer, &bytes_copied);

	if (len == -1) {
		buffer[bufsize - 1] = 0;
		return bytes_copied - 1;
	}
	else {
		return len;
	}
}

/*
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
 * terminator.	(It's not set if we return -1.)
 */
gint
tvb_find_line_end(tvbuff_t *tvb, const gint offset, int len, gint *next_offset, const gboolean desegment)
{
#ifdef WIN32
	static const char __declspec(align(16)) crlf[] = "\r\n" ;
#else
	static const char crlf[] __attribute__((aligned(16))) = "\r\n" ;
#endif

	gint   eob_offset;
	gint   eol_offset;
	int    linelen;
	guchar found_needle = 0;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	if (len == -1)
		len = _tvb_captured_length_remaining(tvb, offset);
	/*
	 * XXX - what if "len" is still -1, meaning "offset is past the
	 * end of the tvbuff"?
	 */
	eob_offset = offset + len;

	/*
	 * Look either for a CR or an LF.
	 */
	eol_offset = tvb_pbrk_guint8(tvb, offset, len, crlf, &found_needle);
	if (eol_offset == -1) {
		/*
		 * No CR or LF - line is presumably continued in next packet.
		 */
		if (desegment) {
			/*
			 * Tell our caller we saw no EOL, so they can
			 * try to desegment and get the entire line
			 * into one tvbuff.
			 */
			return -1;
		} else {
			/*
			 * Pretend the line runs to the end of the tvbuff.
			 */
			linelen = eob_offset - offset;
			if (next_offset)
				*next_offset = eob_offset;
		}
	} else {
		/*
		 * Find the number of bytes between the starting offset
		 * and the CR or LF.
		 */
		linelen = eol_offset - offset;

		/*
		 * Is it a CR?
		 */
		if (found_needle == '\r') {
			/*
			 * Yes - is it followed by an LF?
			 */
			if (eol_offset + 1 >= eob_offset) {
				/*
				 * Dunno - the next byte isn't in this
				 * tvbuff.
				 */
				if (desegment) {
					/*
					 * We'll return -1, although that
					 * runs the risk that if the line
					 * really *is* terminated with a CR,
					 * we won't properly dissect this
					 * tvbuff.
					 *
					 * It's probably more likely that
					 * the line ends with CR-LF than
					 * that it ends with CR by itself.
					 */
					return -1;
				}
			} else {
				/*
				 * Well, we can at least look at the next
				 * byte.
				 */
				if (tvb_get_guint8(tvb, eol_offset + 1) == '\n') {
					/*
					 * It's an LF; skip over the CR.
					 */
					eol_offset++;
				}
			}
		}

		/*
		 * Return the offset of the character after the last
		 * character in the line, skipping over the last character
		 * in the line terminator.
		 */
		if (next_offset)
			*next_offset = eol_offset + 1;
	}
	return linelen;
}

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
gint
tvb_find_line_end_unquoted(tvbuff_t *tvb, const gint offset, int len, gint *next_offset)
{
	gint     cur_offset, char_offset;
	gboolean is_quoted;
	guchar   c = 0;
	gint     eob_offset;
	int      linelen;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	if (len == -1)
		len = _tvb_captured_length_remaining(tvb, offset);
	/*
	 * XXX - what if "len" is still -1, meaning "offset is past the
	 * end of the tvbuff"?
	 */
	eob_offset = offset + len;

	cur_offset = offset;
	is_quoted  = FALSE;
	for (;;) {
			/*
		 * Is this part of the string quoted?
		 */
		if (is_quoted) {
			/*
			 * Yes - look only for the terminating quote.
			 */
			char_offset = tvb_find_guint8(tvb, cur_offset, len,
				'"');
		} else {
			/*
			 * Look either for a CR, an LF, or a '"'.
			 */
			char_offset = tvb_pbrk_guint8(tvb, cur_offset, len, "\r\n\"", &c);
		}
		if (char_offset == -1) {
			/*
			 * Not found - line is presumably continued in
			 * next packet.
			 * We pretend the line runs to the end of the tvbuff.
			 */
			linelen = eob_offset - offset;
			if (next_offset)
				*next_offset = eob_offset;
			break;
		}

		if (is_quoted) {
			/*
			 * We're processing a quoted string.
			 * We only looked for ", so we know it's a ";
			 * as we're processing a quoted string, it's a
			 * closing quote.
			 */
			is_quoted = FALSE;
		} else {
			/*
			 * OK, what is it?
			 */
			if (c == '"') {
				/*
				 * Un-quoted "; it begins a quoted
				 * string.
				 */
				is_quoted = TRUE;
			} else {
				/*
				 * It's a CR or LF; we've found a line
				 * terminator.
				 *
				 * Find the number of bytes between the
				 * starting offset and the CR or LF.
				 */
				linelen = char_offset - offset;

				/*
				 * Is it a CR?
				 */
				if (c == '\r') {
					/*
					 * Yes; is it followed by an LF?
					 */
					if (char_offset + 1 < eob_offset &&
						tvb_get_guint8(tvb, char_offset + 1)
						  == '\n') {
						/*
						 * Yes; skip over the CR.
						 */
						char_offset++;
					}
				}

				/*
				 * Return the offset of the character after
				 * the last character in the line, skipping
				 * over the last character in the line
				 * terminator, and quit.
				 */
				if (next_offset)
					*next_offset = char_offset + 1;
				break;
			}
		}

		/*
		 * Step past the character we found.
		 */
		cur_offset = char_offset + 1;
		if (cur_offset >= eob_offset) {
			/*
			 * The character we found was the last character
			 * in the tvbuff - line is presumably continued in
			 * next packet.
			 * We pretend the line runs to the end of the tvbuff.
			 */
			linelen = eob_offset - offset;
			if (next_offset)
				*next_offset = eob_offset;
			break;
		}
	}
	return linelen;
}

/*
 * Copied from the mgcp dissector. (This function should be moved to /epan )
 * tvb_skip_wsp - Returns the position in tvb of the first non-whitespace
 *				  character following offset or offset + maxlength -1 whichever
 *				  is smaller.
 *
 * Parameters:
 * tvb - The tvbuff in which we are skipping whitespace.
 * offset - The offset in tvb from which we begin trying to skip whitespace.
 * maxlength - The maximum distance from offset that we may try to skip
 * whitespace.
 *
 * Returns: The position in tvb of the first non-whitespace
 *			character following offset or offset + maxlength -1 whichever
 *			is smaller.
 */
gint
tvb_skip_wsp(tvbuff_t *tvb, const gint offset, const gint maxlength)
{
	gint   counter = offset;
	gint   end, tvb_len;
	guint8 tempchar;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	/* Get the length remaining */
	/*tvb_len = tvb_captured_length(tvb);*/
	tvb_len = tvb->length;

	end     = offset + maxlength;
	if (end >= tvb_len)
	{
		end = tvb_len;
	}

	/* Skip past spaces, tabs, CRs and LFs until run out or meet something else */
	for (counter = offset;
		 counter < end &&
		  ((tempchar = tvb_get_guint8(tvb,counter)) == ' ' ||
		  tempchar == '\t' || tempchar == '\r' || tempchar == '\n');
		 counter++);

	return (counter);
}

gint
tvb_skip_wsp_return(tvbuff_t *tvb, const gint offset) {
	gint   counter = offset;
	guint8 tempchar;

	for(counter = offset; counter > 0 &&
		((tempchar = tvb_get_guint8(tvb,counter)) == ' ' ||
		tempchar == '\t' || tempchar == '\n' || tempchar == '\r'); counter--);
	counter++;
	return (counter);
}

int
tvb_skip_guint8(tvbuff_t *tvb, int offset, const int maxlength, const guint8 ch)
{
	int end, tvb_len;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	/* Get the length remaining */
	/*tvb_len = tvb_captured_length(tvb);*/
	tvb_len = tvb->length;

	end     = offset + maxlength;
	if (end >= tvb_len)
		end = tvb_len;

	while (offset < end) {
		guint8 tempch = tvb_get_guint8(tvb, offset);

		if (tempch != ch)
			break;
		offset++;
	}

	return offset;
}

/*
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data, with "punct" as a byte
 * separator.
 */
gchar *
tvb_bytes_to_ep_str_punct(tvbuff_t *tvb, const gint offset, const gint len, const gchar punct)
{
	return bytes_to_ep_str_punct(ensure_contiguous(tvb, offset, len), len, punct);
}


/*
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset (which may be -1 for "all the way to the end of the
 * tvbuff"), fetch BCD encoded digits from a tvbuff starting from either
 * the low or high half byte, formating the digits according to an input digit set,
 * if NUll a default digit set of 0-9 returning "?" for overdecadic digits will be used.
 * A pointer to the packet scope allocated string will be returned.
 * Note a tvbuff content of 0xf is considered a 'filler' and will end the conversion.
 */
static dgt_set_t Dgt1_9_bcd = {
	{
		/*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e  f*/
		'0','1','2','3','4','5','6','7','8','9','?','?','?','?','?','?'
	}
};
const gchar *
tvb_bcd_dig_to_wmem_packet_str(tvbuff_t *tvb, const gint offset, const gint len, dgt_set_t *dgt, gboolean skip_first)
{
	int     length;
	guint8  octet;
	int     i        = 0;
	char   *digit_str;
	gint    t_offset = offset;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	if (!dgt)
		dgt = &Dgt1_9_bcd;

	if (len == -1) {
		/*length = tvb_captured_length(tvb);*/
		length = tvb->length;
		if (length < offset) {
			return "";
		}
	} else {
		length = offset + len;
	}
	digit_str = (char *)wmem_alloc(wmem_packet_scope(), (length - offset)*2+1);

	while (t_offset < length) {

		octet = tvb_get_guint8(tvb,t_offset);
		if (!skip_first) {
			digit_str[i] = dgt->out[octet & 0x0f];
			i++;
		}
		skip_first = FALSE;

		/*
		 * unpack second value in byte
		 */
		octet = octet >> 4;

		if (octet == 0x0f)	/* odd number bytes - hit filler */
			break;

		digit_str[i] = dgt->out[octet & 0x0f];
		i++;
		t_offset++;

	}
	digit_str[i]= '\0';
	return digit_str;

}

/*
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data.
 */
gchar *
tvb_bytes_to_ep_str(tvbuff_t *tvb, const gint offset, const gint len)
{
	return bytes_to_ep_str(ensure_contiguous(tvb, offset, len), len);
}

/* Find a needle tvbuff within a haystack tvbuff. */
gint
tvb_find_tvb(tvbuff_t *haystack_tvb, tvbuff_t *needle_tvb, const gint haystack_offset)
{
	guint	      haystack_abs_offset, haystack_abs_length;
	const guint8 *haystack_data;
	const guint8 *needle_data;
	const guint   needle_len = needle_tvb->length;
	const guint8 *location;

	DISSECTOR_ASSERT(haystack_tvb && haystack_tvb->initialized);

	if (haystack_tvb->length < 1 || needle_tvb->length < 1) {
		return -1;
	}

	/* Get pointers to the tvbuffs' data. */
	haystack_data = ensure_contiguous(haystack_tvb, 0, -1);
	needle_data   = ensure_contiguous(needle_tvb, 0, -1);

	check_offset_length(haystack_tvb, haystack_offset, -1,
			&haystack_abs_offset, &haystack_abs_length);

	location = epan_memmem(haystack_data + haystack_abs_offset, haystack_abs_length,
			needle_data, needle_len);

	if (location) {
		return (gint) (location - haystack_data);
	}

	return -1;
}

gint
tvb_raw_offset(tvbuff_t *tvb)
{
	return ((tvb->raw_offset==-1) ? (tvb->raw_offset = tvb_offset_from_real_beginning(tvb)) : tvb->raw_offset);
}

void
tvb_set_fragment(tvbuff_t *tvb)
{
	tvb->flags |= TVBUFF_FRAGMENT;
}

struct tvbuff *
tvb_get_ds_tvb(tvbuff_t *tvb)
{
	return(tvb->ds_tvb);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
