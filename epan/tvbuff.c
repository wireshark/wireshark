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
 * $Id$
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

#include "wsutil/pint.h"
#include "wsutil/sign_ext.h"
#include "tvbuff.h"
#include "tvbuff-int.h"
#include "strutil.h"
#include "to_str.h"
#include "charsets.h"
#include "proto.h"	/* XXX - only used for DISSECTOR_ASSERT, probably a new header file? */
#include "exceptions.h"

static guint64
_tvb_get_bits64(tvbuff_t *tvb, guint bit_offset, const gint total_no_of_bits);

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
		next_tvb=tvb->next;
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

/*
 * Check whether that offset goes more than one byte past the
 * end of the buffer.
 *
 * If not, return 0; otherwise, return exception
 */
static inline int
validate_offset(const tvbuff_t *tvb, const guint abs_offset)
{
	if (G_LIKELY(abs_offset <= tvb->length))
		return 0;
	else if (abs_offset <= tvb->reported_length)
		return BoundsError;
	else if (tvb->flags & TVBUFF_FRAGMENT)
		return FragmentBoundsError;
	else
		return ReportedBoundsError;
}

static int
compute_offset(const tvbuff_t *tvb, const gint offset, guint *offset_ptr)
{
	if (offset >= 0) {
		/* Positive offset - relative to the beginning of the packet. */
		if ((guint) offset <= tvb->length) {
			*offset_ptr = offset;
		} else if ((guint) offset <= tvb->reported_length) {
			return BoundsError;
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			return FragmentBoundsError;
		} else {
			return ReportedBoundsError;
		}
	}
	else {
		/* Negative offset - relative to the end of the packet. */
		if ((guint) -offset <= tvb->length) {
			*offset_ptr = tvb->length + offset;
		} else if ((guint) -offset <= tvb->reported_length) {
			return BoundsError;
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			return FragmentBoundsError;
		} else {
			return ReportedBoundsError;
		}
	}

	return 0;
}

static int
compute_offset_and_remaining(const tvbuff_t *tvb, const gint offset, guint *offset_ptr, guint *rem_len)
{
	int exception;

	exception = compute_offset(tvb, offset, offset_ptr);
	if (!exception)
		*rem_len = tvb->length - *offset_ptr;

	return exception;
}

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
static int
check_offset_length_no_exception(const tvbuff_t *tvb,
				 const gint offset, gint const length_val,
				 guint *offset_ptr, guint *length_ptr)
{
	guint end_offset;
	int exception;

	DISSECTOR_ASSERT(offset_ptr);
	DISSECTOR_ASSERT(length_ptr);

	/* Compute the offset */
	exception = compute_offset(tvb, offset, offset_ptr);
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

	return validate_offset(tvb, end_offset);
}

/* Checks (+/-) offset and length and throws an exception if
 * either is out of bounds. Sets integer ptrs to the new offset
 * and length. */
static void
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

	byte_offset = bit_offset >> 3;
	left = bit_offset % 8; /* for left-shifting */
	right = 8 - left; /* for right-shifting */

	if (no_of_bits == -1) {
		datalen = tvb_length_remaining(tvb, byte_offset);
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
	if (tvb_length_remaining(tvb, byte_offset) > datalen) {
		data = tvb_get_ptr(tvb, byte_offset, datalen + 1);

		/* Do this allocation AFTER tvb_get_ptr() (which could throw an exception) */
		buf = (guint8 *)g_malloc(datalen);

		/* shift tvb data bit_offset bits to the left */
		for (i = 0; i < datalen; i++)
			buf[i] = (data[i] << left) | (data[i+1] >> right);
	} else {
		data = tvb_get_ptr(tvb, byte_offset, datalen);

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
tvb_length(const tvbuff_t *tvb)
{
	DISSECTOR_ASSERT(tvb && tvb->initialized);

	return tvb->length;
}

gint
tvb_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset, rem_length;
	int exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset_and_remaining(tvb, offset, &abs_offset, &rem_length);
	if (exception)
		return 0;

	return rem_length;
}

guint
tvb_ensure_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset, rem_length;
	int   exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset_and_remaining(tvb, offset, &abs_offset, &rem_length);
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
	int exception;

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
	guint abs_offset;
	int exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset(tvb, offset, &abs_offset);
	if (exception)
		return FALSE;

	/* compute_offset only throws an exception on >, not >= because of the
	 * comment above check_offset_length_no_exception, but here we want the
	 * opposite behaviour so we check ourselves... */
	if (abs_offset < tvb->length) {
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
	guint abs_offset;
	int exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset(tvb, offset, &abs_offset);
	if (exception)
		return 0;

	if (tvb->reported_length >= abs_offset)
		return tvb->reported_length - abs_offset;
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

static const guint8*
ensure_contiguous_no_exception(tvbuff_t *tvb, const gint offset, const gint length, int *pexception)
{
	guint abs_offset, abs_length;
	int exception;

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

static const guint8*
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

static const guint8*
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

static const guint8*
guint8_pbrk(const guint8* haystack, size_t haystacklen, const guint8 *needles, guchar *found_needle)
{
	gchar         tmp[256] = { 0 };
	const guint8 *haystack_end;

	while (*needles)
		tmp[*needles++] = 1;

	haystack_end = haystack + haystacklen;
	while (haystack < haystack_end) {
		if (tmp[*haystack]) {
			if (found_needle)
				*found_needle = *haystack;
			return haystack;
		}
		haystack++;
	}

	return NULL;
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
 * explicitely free it with g_free().
 * If scope is not NULL, memory is allocated with the corresponding pool
 * lifetime.
 */
void *
tvb_memdup(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, size_t length)
{
	guint	abs_offset, abs_length;
	void	*duped;

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

#define IEEE_DP_SIGN_MASK	0x8000000000000000LL
#define IEEE_DP_EXPONENT_MASK	0x7FF0000000000000LL
#define IEEE_DP_MANTISSA_MASK	0x000FFFFFFFFFFFFFLL
#define IEEE_DP_INFINITY	IEEE_DP_EXPONENT_MASK

#define IEEE_DP_IMPLIED_BIT (1LL << IEEE_DP_MANTISSA_WIDTH)
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
		gfloat f;
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
	guint octet_offset = bit_offset >> 3;
	guint8 required_bits_in_first_octet = 8 - (bit_offset % 8);

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

	ptr = tvb_get_ptr(tvb, abs_offset, limit);

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

static gint
tvb_pbrk_guint8_generic(tvbuff_t *tvb, guint abs_offset, guint limit, const guint8 *needles, guchar *found_needle)
{
	const guint8 *ptr;
	const guint8 *result;

	ptr = tvb_get_ptr(tvb, abs_offset, limit);

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

/* Convert a string from Unicode to ASCII.	At the moment we fake it by
 * replacing all non-ASCII characters with a '.' )-:   The len parameter is
 * the number of guint16's to convert from Unicode.
 *
 * If scope is set to NULL, returned buffer is allocated by g_malloc()
 * and must be g_free by the caller. Otherwise memory is automatically
 * freed when the scope lifetime is reached.
 */
/* XXX: This has been replaced by tvb_get_string() */
char *
tvb_get_faked_unicode(wmem_allocator_t *scope, tvbuff_t *tvb, int offset,
                      const int len, const gboolean little_endian)
{
	char    *buffer;
	int      i;
	guint16  character;

	/* Make sure we have enough data before allocating the buffer,
	   so we don't blow up if the length is huge. */
	tvb_ensure_bytes_exist(tvb, offset, 2*len);

	/* We know we won't throw an exception, so we don't have to worry
	   about leaking this buffer. */
	buffer = (char *)wmem_alloc(scope, len + 1);

	for (i = 0; i < len; i++) {
		character = little_endian ? tvb_get_letohs(tvb, offset)
					  : tvb_get_ntohs(tvb, offset);
		buffer[i] = character < 256 ? character : '.';
		offset += 2;
	}

	buffer[len] = 0;

	return buffer;
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

/*
 * Given a tvbuff, an offset, and a length, allocate a buffer big enough
 * to hold a non-null-terminated string of that length at that offset,
 * plus a trailing '\0', copy the string into it, and return a pointer
 * to the string.
 * If scope is NULL, memory is allocated with g_malloc() and user must
 * explicitely free it with g_free().
 * If scope is not NULL, memory is allocated with the corresponding pool
 * lifetime.
 * Throws an exception if the tvbuff ends before the string does.
 */
guint8 *
tvb_get_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint length)
{
	guint8       *strbuf;

	tvb_ensure_bytes_exist(tvb, offset, length); /* make sure length = -1 fails */
	strbuf = (guint8 *)wmem_alloc(scope, length + 1);
	tvb_memcpy(tvb, strbuf, offset, length);
	strbuf[length] = '\0';
	return strbuf;
}

static guint8 *
tvb_get_string_8859_1(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint length)
{
	wmem_strbuf_t *str;

	str = wmem_strbuf_new(scope, "");

	while (length > 0) {
		guint8 ch = tvb_get_guint8(tvb, offset);

		if (ch < 0x80)
			wmem_strbuf_append_c(str, ch);
		else {
			/*
			 * Note: we assume here that the code points
			 * 0x80-0x9F are used for C1 control characters,
			 * and thus have the same value as the corresponding
			 * Unicode code points.
			 */
			wmem_strbuf_append_unichar(str, ch);
		}
		offset++;
		length--;
	}

	/* XXX, discarding constiness, should we have some function which "take-over" strbuf->str (like when strbuf is no longer needed) */
	return (guint8 *) wmem_strbuf_get_str(str);
}

static guint8 *
tvb_get_string_unichar2(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint length, const gunichar2 table[0x80])
{
	wmem_strbuf_t *str;

	str = wmem_strbuf_new(scope, "");

	while (length > 0) {
		guint8 ch = tvb_get_guint8(tvb, offset);

		if (ch < 0x80)
			wmem_strbuf_append_c(str, ch);
		else
			wmem_strbuf_append_unichar(str, table[ch-0x80]);
		offset++;
		length--;
	}

	/* XXX, discarding constiness, should we have some function which "take-over" strbuf->str (like when strbuf is no longer needed) */
	return (guint8 *) wmem_strbuf_get_str(str);
}

/*
 * Unicode (UTF-16) version of tvb_get_string()
 * XXX - this is UCS-2, not UTF-16, as it doesn't handle surrogate pairs
 *
 * Encoding paramter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN
 *
 * Specify length in bytes
 *
 * If scope is NULL, memory is allocated with g_malloc() and user must
 * explicitely free it with g_free().
 * If scope is not NULL, memory is allocated with the corresponding pool
 * lifetime.
 *
 * Returns an UTF-8 string
 */
gchar *
tvb_get_unicode_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint length, const guint encoding)
{
	gunichar2      uchar;
	gint           i;       /* Byte counter for tvbuff */
	wmem_strbuf_t *strbuf;

	tvb_ensure_bytes_exist(tvb, offset, length);

	strbuf = wmem_strbuf_new(scope, NULL);

	for(i = 0; i + 1 < length; i += 2) {
		if (encoding == ENC_BIG_ENDIAN)
			uchar = tvb_get_ntohs(tvb, offset + i);
		else
			uchar = tvb_get_letohs(tvb, offset + i);

		wmem_strbuf_append_unichar(strbuf, uchar);
	}

	/*
	 * XXX - if i < length, this means we were handed an odd
	 * number of bytes, so we're not a valid UCS-2 string.
	 */
	return (gchar*)wmem_strbuf_get_str(strbuf);
}

/*
 * Given a tvbuff, an offset, a length, and an encoding, allocate a
 * buffer big enough to hold a non-null-terminated string of that length
 * at that offset, plus a trailing '\0', copy into the buffer the
 * string as converted from the appropriate encoding to UTF-8, and
 * return a pointer to the string.
 *
 * Throws an exception if the tvbuff ends before the string does.
 *
 * If scope is NULL, memory is allocated with g_malloc() and user must
 * explicitely free it with g_free().
 * If scope is not NULL, memory is allocated with the corresponding pool
 * lifetime.
 */
guint8 *
tvb_get_string_enc(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset,
			     const gint length, const guint encoding)
{
	const guint8 *ptr;
	guint8       *strbuf;

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
		 *
		 * XXX - should map all octets with the 8th bit
		 * not set to a "substitute" UTF-8 character.
		 */
		strbuf = tvb_get_string(scope, tvb, offset, length);
		break;

	case ENC_WINDOWS_1250:
		strbuf = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp1250);
		break;

	case ENC_ISO_8859_1:
		/*
		 * ISO 8859-1 printable code point values are equal
		 * to the equivalent Unicode code point value, so
		 * no translation table is needed.
		 */
		strbuf = tvb_get_string_8859_1(scope, tvb, offset, length);
		break;

	case ENC_ISO_8859_2:
		strbuf = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_2);
		break;

	case ENC_ISO_8859_5:
		strbuf = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_iso_8859_5);
		break;

	case ENC_UTF_8:
		/*
		 * XXX - should map all invalid UTF-8 sequences
		 * to a "substitute" UTF-8 character.
		 */
		strbuf = tvb_get_string(scope, tvb, offset, length);
		break;

	case ENC_UTF_16:
		/*
		 * XXX - needs to handle surrogate pairs and to map
		 * invalid characters and sequences to a "substitute"
		 * UTF-8 character.
		 */
		strbuf = tvb_get_unicode_string(scope, tvb, offset, length,
		    encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_UCS_2:
		/*
		 * XXX - needs to map values that are not valid UCS-2
		 * characters (such as, I think, values used as the
		 * components of a UTF-16 surrogate pair) to a
		 * "substitute" UTF-8 character.
		 */
		strbuf = tvb_get_unicode_string(scope, tvb, offset, length,
		    encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_EBCDIC:
		/*
		 * XXX - do the copy and conversion in one pass.
		 *
		 * XXX - multiple "dialects" of EBCDIC?
		 */
		tvb_ensure_bytes_exist(tvb, offset, length); /* make sure length = -1 fails */
		strbuf = (guint8 *)wmem_alloc(scope, length + 1);
		if (length != 0) {
			ptr = ensure_contiguous(tvb, offset, length);
			memcpy(strbuf, ptr, length);
			EBCDIC_to_ASCII(strbuf, length);
		}
		strbuf[length] = '\0';
		break;
	}
	return strbuf;
}

/*
 * Given a tvbuff and an offset, with the offset assumed to refer to
 * a null-terminated string, find the length of that string (and throw
 * an exception if the tvbuff ends before we find the null), allocate
 * a buffer big enough to hold the string, copy the string into it,
 * and return a pointer to the string.	Also return the length of the
 * string (including the terminating null) through a pointer.
 *
 * If scope is NULL, memory is allocated with g_malloc() and user must
 * explicitely free it with g_free().
 * If scope is not NULL, memory is allocated with the corresponding pool
 * lifetime.
 */
guint8 *
tvb_get_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint *lengthp)
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

	/* XXX, convertion between signed/unsigned integer */
	*lengthp = size = tvb_strsize(tvb, offset);

	return tvb_get_string_8859_1(scope, tvb, offset, size);
}

static guint8 *
tvb_get_stringz_unichar2(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint *lengthp, const gunichar2 table[0x80])
{
	guint size;

	/* XXX, convertion between signed/unsigned integer */
	*lengthp = size = tvb_strsize(tvb, offset);

	return tvb_get_string_unichar2(scope, tvb, offset, size, table);
}

guint8 *
tvb_get_stringz_enc(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint *lengthp, const guint encoding)
{
	guint   size;
	guint8 *strptr;

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
		 *
		 * XXX - should map all octets with the 8th bit
		 * not set to a "substitute" UTF-8 character.
		 */
		strptr = tvb_get_stringz(scope, tvb, offset, lengthp);
		break;

	case ENC_WINDOWS_1250:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_cp1250);
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

	case ENC_ISO_8859_5:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_iso_8859_5);
		break;

	case ENC_UTF_8:
		/*
		 * XXX - should map all invalid UTF-8 sequences
		 * to a "substitute" UTF-8 character.
		 */
		strptr = tvb_get_stringz(scope, tvb, offset, lengthp);
		break;

	case ENC_UTF_16:
		/*
		 * XXX - needs to handle surrogate pairs and to map
		 * invalid characters and sequences to a "substitute"
		 * UTF-8 character.
		 */
		strptr = tvb_get_unicode_stringz(scope, tvb, offset, lengthp,
		    encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_UCS_2:
		/*
		 * XXX - needs to map values that are not valid UCS-2
		 * characters (such as, I think, values used as the
		 * components of a UTF-16 surrogate pair) to a
		 * "substitute" UTF-8 character.
		 */
		strptr = tvb_get_unicode_stringz(scope, tvb, offset, lengthp,
		    encoding & ENC_LITTLE_ENDIAN);
		break;

	case ENC_EBCDIC:
		/*
		 * XXX - do the copy and conversion in one pass.
		 *
		 * XXX - multiple "dialects" of EBCDIC?
		 */
		size = tvb_strsize(tvb, offset);
		strptr = (guint8 *)wmem_alloc(scope, size);
		tvb_memcpy(tvb, strptr, offset, size);
		EBCDIC_to_ASCII(strptr, size);
		if (lengthp)
			*lengthp = size;
		break;
	}

	return strptr;
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
 * function with the _ephemeral versoin.)
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

/*
 * Unicode (UTF-16) version of tvb_get_stringz()
 *
 * Encoding paramter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN
 *
 * Returns an allocated UTF-8 string and updates lengthp pointer with length of string (in bytes)
 */
gchar *
tvb_get_unicode_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint *lengthp, const guint encoding)
{
	gunichar2      uchar;
	gint           size;    /* Number of UTF-16 characters */
	gint           i;       /* Byte counter for tvbuff */
	wmem_strbuf_t *strbuf;

	size = tvb_unicode_strsize(tvb, offset);

	strbuf = wmem_strbuf_new(scope, NULL);

	for(i = 0; i < size; i += 2) {
		if (encoding == ENC_BIG_ENDIAN)
			uchar = tvb_get_ntohs(tvb, offset + i);
		else
			uchar = tvb_get_letohs(tvb, offset + i);

		wmem_strbuf_append_unichar(strbuf, uchar);
	}

	if (lengthp)
		*lengthp = i; /* Number of *bytes* processed */

	return (gchar*)wmem_strbuf_get_str(strbuf);
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
tvb_get_nstringz(tvbuff_t *tvb, const gint offset, const guint bufsize, guint8* buffer)
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
	gint   eob_offset;
	gint   eol_offset;
	int    linelen;
	guchar found_needle = 0;

	if (len == -1)
		len = tvb_length_remaining(tvb, offset);
	/*
	 * XXX - what if "len" is still -1, meaning "offset is past the
	 * end of the tvbuff"?
	 */
	eob_offset = offset + len;

	/*
	 * Look either for a CR or an LF.
	 */
	eol_offset = tvb_pbrk_guint8(tvb, offset, len, "\r\n", &found_needle);
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

	if (len == -1)
		len = tvb_length_remaining(tvb, offset);
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

	/* Get the length remaining */
	tvb_len = tvb_length(tvb);
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


/*
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data, with "punct" as a byte
 * separator.
 */
gchar *
tvb_bytes_to_str_punct(tvbuff_t *tvb, const gint offset, const gint len, const gchar punct)
{
	return bytes_to_str_punct(ensure_contiguous(tvb, offset, len), len, punct);
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
		/*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
		'0','1','2','3','4','5','6','7','8','9','?','?','?','?','?'
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

	if (!dgt)
		dgt = &Dgt1_9_bcd;

	if (len == -1) {
		length = tvb_length(tvb);
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
tvb_bytes_to_str(tvbuff_t *tvb, const gint offset, const gint len)
{
	return bytes_to_str(ensure_contiguous(tvb, offset, len), len);
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
	return ((tvb->raw_offset==-1)?(tvb->raw_offset = tvb_offset_from_real_beginning(tvb)):tvb->raw_offset);
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
