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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
#include <wsutil/ws_assert.h>
#include "tvbuff.h"
#include "tvbuff-int.h"
#include "strutil.h"
#include "to_str.h"
#include "charsets.h"
#include "proto.h"	/* XXX - only used for DISSECTOR_ASSERT, probably a new header file? */
#include "exceptions.h"

#include <time.h>

static guint64
_tvb_get_bits64(tvbuff_t *tvb, guint bit_offset, const gint total_no_of_bits);

static guint64
_tvb_get_bits64_le(tvbuff_t *tvb, guint bit_offset, const gint total_no_of_bits);

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

	ws_assert(size >= sizeof(*tvb));

	tvb = (tvbuff_t *) g_slice_alloc(size);

	tvb->next		 = NULL;
	tvb->ops		 = ops;
	tvb->initialized	 = FALSE;
	tvb->flags		 = 0;
	tvb->length		 = 0;
	tvb->reported_length	 = 0;
	tvb->contained_length	 = 0;
	tvb->real_data		 = NULL;
	tvb->raw_offset		 = -1;
	tvb->ds_tvb		 = NULL;

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

/*
 * Check whether that offset goes more than one byte past the
 * end of the buffer.
 *
 * If not, return 0; otherwise, return exception
 */
static inline int
validate_offset(const tvbuff_t *tvb, const guint abs_offset)
{
	if (G_LIKELY(abs_offset <= tvb->length)) {
		/* It's OK. */
		return 0;
	}

	/*
	 * It's not OK, but why?  Which boundaries is it
	 * past?
	 */
	if (abs_offset <= tvb->contained_length) {
		/*
		 * It's past the captured length, but not past
		 * the reported end of any parent tvbuffs from
		 * which this is constructed, or the reported
		 * end of this tvbuff, so it's out of bounds
		 * solely because we're past the end of the
		 * captured data.
		 */
		return BoundsError;
	}

	/*
	 * There's some actual packet boundary, not just the
	 * artificial boundary imposed by packet slicing, that
	 * we're past.
	 */

	if (tvb->flags & TVBUFF_FRAGMENT) {
		/*
		 * This tvbuff is the first fragment of a larger
		 * packet that hasn't been reassembled, so we
		 * assume that's the source of the problem - if
		 * we'd reassembled the packet, we wouldn't have
		 * gone past the end.
		 *
		 * That might not be true, but for at least
		 * some forms of reassembly, such as IP
		 * reassembly, you don't know how big the
		 * reassembled packet is unless you reassemble
		 * it, so, in those cases, we can't determine
		 * whether we would have gone past the end
		 * had we reassembled the packet.
		 */
		return FragmentBoundsError;
	}

	/* OK, we're not an unreassembled fragment (that we know of). */
	if (abs_offset <= tvb->reported_length) {
		/*
		 * We're within the bounds of what this tvbuff
		 * purportedly contains, based on some length
		 * value, but we're not within the bounds of
		 * something from which this tvbuff was
		 * extracted, so that length value ran past
		 * the end of some parent tvbuff.
		 */
		return ContainedBoundsError;
	}

	/*
	 * OK, it looks as if we ran past the claimed length
	 * of data.
	 */
	return ReportedBoundsError;
}

static inline int
compute_offset(const tvbuff_t *tvb, const gint offset, guint *offset_ptr)
{
	if (offset >= 0) {
		/* Positive offset - relative to the beginning of the packet. */
		if (G_LIKELY((guint) offset <= tvb->length)) {
			*offset_ptr = offset;
		} else if ((guint) offset <= tvb->contained_length) {
			return BoundsError;
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			return FragmentBoundsError;
		} else if ((guint) offset <= tvb->reported_length) {
			return ContainedBoundsError;
		} else {
			return ReportedBoundsError;
		}
	}
	else {
		/* Negative offset - relative to the end of the packet. */
		if (G_LIKELY((guint) -offset <= tvb->length)) {
			*offset_ptr = tvb->length + offset;
		} else if ((guint) -offset <= tvb->contained_length) {
			return BoundsError;
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			return FragmentBoundsError;
		} else if ((guint) -offset <= tvb->reported_length) {
			return ContainedBoundsError;
		} else {
			return ReportedBoundsError;
		}
	}

	return 0;
}

static inline int
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
 * not (exception number). The integer ptrs are modified with the new offset,
 * captured (available) length, and contained length (amount that's present
 * in the parent tvbuff based on its reported length).
 * No exception is thrown; on success, we return 0, otherwise we return an
 * exception for the caller to throw if appropriate.
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
	int   exception;

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
		return tvb_new_subset_length_caplen(tvb, byte_offset, datalen, datalen);
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

tvbuff_t *
tvb_new_octet_right_aligned(tvbuff_t *tvb, guint32 bit_offset, gint32 no_of_bits)
{
	tvbuff_t     *sub_tvb = NULL;
	guint32       byte_offset;
	gint          src_len, dst_len, i;
	guint8        left, right, remaining_bits, *buf;
	const guint8 *data;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	byte_offset = bit_offset / 8;
	/* right shift to put bits in place and discard least significant bits */
	right = bit_offset % 8;
	/* left shift to get most significant bits from next octet */
	left = 8 - right;

	if (no_of_bits == -1) {
		dst_len = _tvb_captured_length_remaining(tvb, byte_offset);
		remaining_bits = 0;
	} else {
		dst_len = no_of_bits / 8;
		remaining_bits = no_of_bits % 8;
		if (remaining_bits) {
			dst_len++;
		}
	}

	/* already aligned -> shortcut */
	if ((right == 0) && (remaining_bits == 0)) {
		return tvb_new_subset_length_caplen(tvb, byte_offset, dst_len, dst_len);
	}

	DISSECTOR_ASSERT(dst_len>0);

	if (_tvb_captured_length_remaining(tvb, byte_offset) > dst_len) {
		/* last octet will get data from trailing octet */
		src_len = dst_len + 1;
	} else {
		/* last octet will be zero padded */
		src_len = dst_len;
	}

	data = ensure_contiguous(tvb, byte_offset, src_len); /* tvb_get_ptr */

	/* Do this allocation AFTER tvb_get_ptr() (which could throw an exception) */
	buf = (guint8 *)g_malloc(dst_len);

	for (i = 0; i < (dst_len - 1); i++)
		buf[i] = (data[i] >> right) | (data[i+1] << left);

	/* Special handling for last octet */
	buf[i] = (data[i] >> right);
	/* Shift most significant bits from trailing octet if available */
	if (src_len > dst_len)
		buf[i] |= (data[i+1] << left);
	/* Preserve only remaining bits in last octet if not multiple of 8 */
	if (remaining_bits)
		buf[i] &= ((1 << remaining_bits) - 1);

	sub_tvb = tvb_new_child_real_data(tvb, buf, dst_len, dst_len);
	tvb_set_free_cb(sub_tvb, g_free);

	return sub_tvb;
}

static tvbuff_t *
tvb_generic_clone_offset_len(tvbuff_t *tvb, guint offset, guint len)
{
	tvbuff_t *cloned_tvb;
	guint8 *data;

	DISSECTOR_ASSERT(tvb_bytes_exist(tvb, offset, len));

	data = (guint8 *) g_malloc(len);

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
	guint abs_offset = 0, rem_length;
	int   exception;

	exception = compute_offset_and_remaining(tvb, offset, &abs_offset, &rem_length);
	if (exception)
		return 0;

	return rem_length;
}

gint
tvb_captured_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset = 0, rem_length;
	int   exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset_and_remaining(tvb, offset, &abs_offset, &rem_length);
	if (exception)
		return 0;

	return rem_length;
}

guint
tvb_ensure_captured_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset = 0, rem_length = 0;
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
		if (abs_offset < tvb->contained_length) {
			THROW(BoundsError);
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			THROW(FragmentBoundsError);
		} else if (abs_offset < tvb->reported_length) {
			THROW(ContainedBoundsError);
		} else {
			THROW(ReportedBoundsError);
		}
	}
	return rem_length;
}

/* Validates that 'length' bytes are available starting from
 * offset (pos/neg). Does not throw an exception. */
gboolean
tvb_bytes_exist(const tvbuff_t *tvb, const gint offset, const gint length)
{
	guint abs_offset = 0, abs_length;
	int   exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	/*
	 * Negative lengths are not possible and indicate a bug (e.g. arithmetic
	 * error or an overly large value from packet data).
	 */
	if (length < 0)
		return FALSE;

	exception = check_offset_length_no_exception(tvb, offset, length, &abs_offset, &abs_length);
	if (exception)
		return FALSE;

	return TRUE;
}

/* Validates that 'length' bytes, where 'length' is a 64-bit unsigned
 * integer, are available starting from offset (pos/neg). Throws an
 * exception if they aren't. */
void
tvb_ensure_bytes_exist64(const tvbuff_t *tvb, const gint offset, const guint64 length)
{
	/*
	 * Make sure the value fits in a signed integer; if not, assume
	 * that means that it's too big.
	 */
	if (length > G_MAXINT) {
		THROW(ReportedBoundsError);
	}

	/* OK, now cast it and try it with tvb_ensure_bytes_exist(). */
	tvb_ensure_bytes_exist(tvb, offset, (gint)length);
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
		if (G_LIKELY((guint) offset <= tvb->length)) {
			real_offset = offset;
		} else if ((guint) offset <= tvb->contained_length) {
			THROW(BoundsError);
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			THROW(FragmentBoundsError);
		} else if ((guint) offset <= tvb->reported_length) {
			THROW(ContainedBoundsError);
		} else {
			THROW(ReportedBoundsError);
		}
	}
	else {
		/* Negative offset - relative to the end of the packet. */
		if (G_LIKELY((guint) -offset <= tvb->length)) {
			real_offset = tvb->length + offset;
		} else if ((guint) -offset <= tvb->contained_length) {
			THROW(BoundsError);
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			THROW(FragmentBoundsError);
		} else if ((guint) -offset <= tvb->reported_length) {
			THROW(ContainedBoundsError);
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
	else if (end_offset <= tvb->contained_length)
		THROW(BoundsError);
	else if (tvb->flags & TVBUFF_FRAGMENT)
		THROW(FragmentBoundsError);
	else if (end_offset <= tvb->reported_length)
		THROW(ContainedBoundsError);
	else
		THROW(ReportedBoundsError);
}

gboolean
tvb_offset_exists(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset = 0;
	int   exception;

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
	guint abs_offset = 0;
	int   exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset(tvb, offset, &abs_offset);
	if (exception)
		return 0;

	if (tvb->reported_length >= abs_offset)
		return tvb->reported_length - abs_offset;
	else
		return 0;
}

guint
tvb_ensure_reported_length_remaining(const tvbuff_t *tvb, const gint offset)
{
	guint abs_offset = 0;
	int   exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset(tvb, offset, &abs_offset);
	if (exception)
		THROW(exception);

	if (tvb->reported_length >= abs_offset)
		return tvb->reported_length - abs_offset;
	else
		THROW(ReportedBoundsError);
}

/* Set the reported length of a tvbuff to a given value; used for protocols
 * whose headers contain an explicit length and where the calling
 * dissector's payload may include padding as well as the packet for
 * this protocol.
 * Also adjusts the available and contained length. */
void
tvb_set_reported_length(tvbuff_t *tvb, const guint reported_length)
{
	DISSECTOR_ASSERT(tvb && tvb->initialized);

	if (reported_length > tvb->reported_length)
		THROW(ReportedBoundsError);

	tvb->reported_length = reported_length;
	if (reported_length < tvb->length)
		tvb->length = reported_length;
	if (reported_length < tvb->contained_length)
		tvb->contained_length = reported_length;
}

/* Repair a tvbuff where the captured length is greater than the
 * reported length; such a tvbuff makes no sense, as it's impossible
 * to capture more data than is in the packet.
 */
void
tvb_fix_reported_length(tvbuff_t *tvb)
{
	DISSECTOR_ASSERT(tvb && tvb->initialized);
	DISSECTOR_ASSERT(tvb->reported_length < tvb->length);

	tvb->reported_length = tvb->length;
	if (tvb->contained_length < tvb->length)
		tvb->contained_length = tvb->length;
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
	guint abs_offset = 0, abs_length = 0;
	int   exception;

	exception = check_offset_length_no_exception(tvb, offset, length, &abs_offset, &abs_length);
	if (exception) {
		if (pexception)
			*pexception = exception;
		return NULL;
	}

	/*
	 * Special case: if the caller (e.g. tvb_get_ptr) requested no data,
	 * then it is acceptable to have an empty tvb (!tvb->real_data).
	 */
	if (length == 0) {
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
	if (p == NULL && length != 0) {
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

	if (G_LIKELY(end_offset <= tvb->length)) {
		return tvb->real_data + u_offset;
	} else if (end_offset <= tvb->contained_length) {
		THROW(BoundsError);
	} else if (tvb->flags & TVBUFF_FRAGMENT) {
		THROW(FragmentBoundsError);
	} else if (end_offset <= tvb->reported_length) {
		THROW(ContainedBoundsError);
	} else {
		THROW(ReportedBoundsError);
	}
	/* not reached */
	return NULL;
}



/************** ACCESSORS **************/

void *
tvb_memcpy(tvbuff_t *tvb, void *target, const gint offset, size_t length)
{
	guint	abs_offset = 0, abs_length = 0;

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

	if (target && tvb->real_data) {
		return memcpy(target, tvb->real_data + abs_offset, abs_length);
	}

	if (target && tvb->ops->tvb_memcpy)
		return tvb->ops->tvb_memcpy(tvb, target, abs_offset, abs_length);

	/*
	 * If the length is 0, there's nothing to do.
	 * (tvb->real_data could be null if it's allocated with
	 * a size of length.)
	 */
	if (length != 0) {
		/*
		 * XXX, fallback to slower method
		 */
		DISSECTOR_ASSERT_NOT_REACHED();
	}
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
	guint  abs_offset = 0, abs_length = 0;
	void  *duped;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	check_offset_length(tvb, offset, (gint) length, &abs_offset, &abs_length);

	if (abs_length == 0)
		return NULL;

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

	ptr = fast_ensure_contiguous(tvb, offset, 1);
	return *ptr;
}

gint8
tvb_get_gint8(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 1);
	return *ptr;
}

guint16
tvb_get_ntohs(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 2);
	return pntoh16(ptr);
}

gint16
tvb_get_ntohis(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 2);
	return pntoh16(ptr);
}

guint32
tvb_get_ntoh24(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 3);
	return pntoh24(ptr);
}

gint32
tvb_get_ntohi24(tvbuff_t *tvb, const gint offset)
{
	guint32 ret;

	ret = ws_sign_ext32(tvb_get_ntoh24(tvb, offset), 24);

	return (gint32)ret;
}

guint32
tvb_get_ntohl(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 4);
	return pntoh32(ptr);
}

gint32
tvb_get_ntohil(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 4);
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

	ptr = fast_ensure_contiguous(tvb, offset, 8);
	return pntoh64(ptr);
}

gint64
tvb_get_ntohi64(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 8);
	return pntoh64(ptr);
}

guint16
tvb_get_guint16(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letohs(tvb, offset);
	} else {
		return tvb_get_ntohs(tvb, offset);
	}
}

gint16
tvb_get_gint16(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letohis(tvb, offset);
	} else {
		return tvb_get_ntohis(tvb, offset);
	}
}

guint32
tvb_get_guint24(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letoh24(tvb, offset);
	} else {
		return tvb_get_ntoh24(tvb, offset);
	}
}

gint32
tvb_get_gint24(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letohi24(tvb, offset);
	} else {
		return tvb_get_ntohi24(tvb, offset);
	}
}

guint32
tvb_get_guint32(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letohl(tvb, offset);
	} else {
		return tvb_get_ntohl(tvb, offset);
	}
}

gint32
tvb_get_gint32(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letohil(tvb, offset);
	} else {
		return tvb_get_ntohil(tvb, offset);
	}
}

guint64
tvb_get_guint40(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letoh40(tvb, offset);
	} else {
		return tvb_get_ntoh40(tvb, offset);
	}
}

gint64
tvb_get_gint40(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letohi40(tvb, offset);
	} else {
		return tvb_get_ntohi40(tvb, offset);
	}
}

guint64
tvb_get_guint48(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letoh48(tvb, offset);
	} else {
		return tvb_get_ntoh48(tvb, offset);
	}
}

gint64
tvb_get_gint48(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letohi48(tvb, offset);
	} else {
		return tvb_get_ntohi48(tvb, offset);
	}
}

guint64
tvb_get_guint56(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letoh56(tvb, offset);
	} else {
		return tvb_get_ntoh56(tvb, offset);
	}
}

gint64
tvb_get_gint56(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letohi56(tvb, offset);
	} else {
		return tvb_get_ntohi56(tvb, offset);
	}
}

guint64
tvb_get_guint64(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letoh64(tvb, offset);
	} else {
		return tvb_get_ntoh64(tvb, offset);
	}
}

gint64
tvb_get_gint64(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letohi64(tvb, offset);
	} else {
		return tvb_get_ntohi64(tvb, offset);
	}
}

gfloat
tvb_get_ieee_float(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letohieee_float(tvb, offset);
	} else {
		return tvb_get_ntohieee_float(tvb, offset);
	}
}

gdouble
tvb_get_ieee_double(tvbuff_t *tvb, const gint offset, const guint encoding) {
	if (encoding & ENC_LITTLE_ENDIAN) {
		return tvb_get_letohieee_double(tvb, offset);
	} else {
		return tvb_get_ntohieee_double(tvb, offset);
	}
}

/*
 * Stuff for IEEE float handling on platforms that don't have IEEE
 * format as the native floating-point format.
 *
 * For now, we treat only the VAX as such a platform.
 *
 * XXX - other non-IEEE boxes that can run UN*X include some Crays,
 * and possibly other machines.  However, I don't know whether there
 * are any other machines that could run Wireshark and that don't use
 * IEEE format.  As far as I know, all of the main current and past
 * commercial microprocessor families on which OSes that support
 * Wireshark can run use IEEE format (x86, ARM, 68k, SPARC, MIPS,
 * PA-RISC, Alpha, IA-64, and so on), and it appears that the official
 * Linux port to System/390 and zArchitecture uses IEEE format floating-
 * point rather than IBM hex floating-point (not a huge surprise), so
 * I'm not sure that leaves any 32-bit or larger UN*X or Windows boxes,
 * other than VAXes, that don't use IEEE format.  If you're not running
 * UN*X or Windows, the floating-point format is probably going to be
 * the least of your problems in a port.
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

#if G_BYTE_ORDER == G_BIG_ENDIAN
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

	ptr = fast_ensure_contiguous(tvb, offset, 2);
	return pletoh16(ptr);
}

gint16
tvb_get_letohis(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 2);
	return pletoh16(ptr);
}

guint32
tvb_get_letoh24(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 3);
	return pletoh24(ptr);
}

gint32
tvb_get_letohi24(tvbuff_t *tvb, const gint offset)
{
	guint32 ret;

	ret = ws_sign_ext32(tvb_get_letoh24(tvb, offset), 24);

	return (gint32)ret;
}

guint32
tvb_get_letohl(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 4);
	return pletoh32(ptr);
}

gint32
tvb_get_letohil(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 4);
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

	ptr = fast_ensure_contiguous(tvb, offset, 8);
	return pletoh64(ptr);
}

gint64
tvb_get_letohi64(tvbuff_t *tvb, const gint offset)
{
	const guint8 *ptr;

	ptr = fast_ensure_contiguous(tvb, offset, 8);
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

#if G_BYTE_ORDER == G_BIG_ENDIAN
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

/* This function is a slight misnomer. It accepts all encodings that are
 * ASCII "enough", which means encodings that are the same as US-ASCII
 * for textual representations of dates and hex bytes; i.e., the same
 * for the hex digits and Z (in practice, all alphanumerics), and the
 * four separators ':' '-' '.' and ' '
 * That means that any encoding that keeps the ISO/IEC 646 invariant
 * characters the same (including the T.61 8 bit encoding and multibyte
 * encodings like EUC-KR and GB18030) are OK, even if they replace characters
 * like '$' '#' and '\' with national variants, but not encodings like UTF-16
 * that include extra null bytes.
 * For our current purposes, the unpacked GSM 7-bit default alphabet (but not
 * all National Language Shift Tables) also satisfies this requirement, but
 * note that it does *not* keep all ISO/IEC 646 invariant characters the same.
 * If this internal function gets used for additional purposes than currently,
 * the set of encodings that it accepts could change.
 * */
static inline void
validate_single_byte_ascii_encoding(const guint encoding)
{
	const guint enc = encoding & ~ENC_CHARENCODING_MASK;

	switch (enc) {
	    case ENC_UTF_16:
	    case ENC_UCS_2:
	    case ENC_UCS_4:
	    case ENC_3GPP_TS_23_038_7BITS_PACKED:
	    case ENC_ASCII_7BITS:
	    case ENC_EBCDIC:
	    case ENC_EBCDIC_CP037:
	    case ENC_BCD_DIGITS_0_9:
	    case ENC_KEYPAD_ABC_TBCD:
	    case ENC_KEYPAD_BC_TBCD:
	    case ENC_ETSI_TS_102_221_ANNEX_A:
	    case ENC_APN_STR:
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
	gchar *ptr;
	const gchar *begin;
	const gchar *end    = NULL;
	GByteArray  *retval = NULL;

	errno = EDOM;

	validate_single_byte_ascii_encoding(encoding);

	ptr = (gchar*) tvb_get_raw_string(NULL, tvb, offset, length);
	begin = ptr;

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

	wmem_free(NULL, ptr);

	return retval;
}

static gboolean
parse_month_name(const char *name, int *tm_mon)
{
	static const char months[][4] = { "Jan", "Feb", "Mar", "Apr", "May",
		"Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	for (int i = 0; i < 12; i++) {
		if (memcmp(months[i], name, 4) == 0) {
			*tm_mon = i;
			return TRUE;
		}
	}
	return FALSE;
}

/* support hex-encoded time values? */
nstime_t*
tvb_get_string_time(tvbuff_t *tvb, const gint offset, const gint length,
		    const guint encoding, nstime_t *ns, gint *endoff)
{
	gchar *begin;
	const gchar *ptr;
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

	begin = (gchar*) tvb_get_raw_string(NULL, tvb, offset, length);
	ptr = begin;

	while (*ptr == ' ') ptr++;

	if (*ptr) {
		if ((encoding & ENC_ISO_8601_DATE_TIME) == ENC_ISO_8601_DATE_TIME) {
			if ((num_chars = iso8601_to_nstime(ns, ptr, ISO8601_DATETIME))) {
				errno = 0;
				end = ptr + num_chars;
			}
		} else if ((encoding & ENC_ISO_8601_DATE_TIME_BASIC) == ENC_ISO_8601_DATE_TIME_BASIC) {
			if ((num_chars = iso8601_to_nstime(ns, ptr, ISO8601_DATETIME_BASIC))) {
				errno = 0;
				end = ptr + num_chars;
			}
		} else {
			memset(&tm, 0, sizeof(tm));
			tm.tm_isdst = -1;
			ns->secs    = 0;
			ns->nsecs   = 0;

			/* note: sscanf is known to be inconsistent across platforms with respect
			   to whether a %n is counted as a return value or not, so we have to use
			   '>=' a lot */
			if (encoding & ENC_ISO_8601_DATE) {
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
					if (tm_now != NULL) {
						tm.tm_year = tm_now->tm_year;
						tm.tm_mon  = tm_now->tm_mon;
						tm.tm_mday = tm_now->tm_mday;
					} else {
						/* The second before the Epoch */
						tm.tm_year = 69;
						tm.tm_mon = 12;
						tm.tm_mday = 31;
					}
					end = ptr + num_chars;
					errno = 0;

				}
			}
			else if (encoding & ENC_RFC_822 || encoding & ENC_RFC_1123) {
				/*
				 * Match [dow,] day month year hh:mm[:ss] with two-digit
				 * years (RFC 822) or four-digit years (RFC 1123). Skip
				 * the day of week since it is locale dependent and does
				 * not affect the resulting date anyway.
				 */
				if (g_ascii_isalpha(ptr[0]) && g_ascii_isalpha(ptr[1]) && g_ascii_isalpha(ptr[2]) && ptr[3] == ',')
					ptr += 4;   /* Skip day of week. */
				char month_name[4] = { 0 };
				if (sscanf(ptr, "%d %3s %d %d:%d%n:%d%n",
				    &tm.tm_mday,
				    month_name,
				    &tm.tm_year,
				    &tm.tm_hour,
				    &tm.tm_min,
				    &num_chars,
				    &tm.tm_sec,
				    &num_chars) >= 5)
				{
					if (encoding & ENC_RFC_822) {
						/* Match strptime behavior: years 00-68
						 * are in the 21th century. */
						if (tm.tm_year <= 68) {
							tm.tm_year += 100;
							matched = TRUE;
						} else if (tm.tm_year <= 99) {
							matched = TRUE;
						}
					} else if (encoding & ENC_RFC_1123) {
						tm.tm_year -= 1900;
						matched = TRUE;
					}
					if (!parse_month_name(month_name, &tm.tm_mon))
						matched = FALSE;
					if (matched)
						end = ptr + num_chars;
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
			if (errno == 0) {
				ns->secs = mktime_utc (&tm);
				if (off_hr > 0)
					ns->secs += (off_hr * 3600) + (off_min * 60);
				else if (off_hr < 0)
					ns->secs -= ((-off_hr) * 3600) + (off_min * 60);
			}
		}
	}

	if (errno == 0) {
		retval = ns;
		if (endoff)
		    *endoff = (gint)(offset + (end - begin));
	}

	wmem_free(NULL, begin);

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
tvb_get_ipv6(tvbuff_t *tvb, const gint offset, ws_in6_addr *addr)
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
 * "encoding" as meaning "little-endian".
 */
void
tvb_get_guid(tvbuff_t *tvb, const gint offset, e_guid_t *guid, const guint encoding)
{
	if (encoding) {
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


/* Get a variable ammount of bits
 *
 * Return a byte array with bit limited data.
 * When encoding is ENC_BIG_ENDIAN, the data is aligned to the left.
 * When encoding is ENC_LITTLE_ENDIAN, the data is aligned to the right.
 */
guint8 *
tvb_get_bits_array(wmem_allocator_t *scope, tvbuff_t *tvb, const gint bit_offset,
		   size_t no_of_bits, size_t *data_length, const guint encoding)
{
	tvbuff_t *sub_tvb;
	if (encoding & ENC_LITTLE_ENDIAN) {
		sub_tvb = tvb_new_octet_right_aligned(tvb, bit_offset, (gint32) no_of_bits);
	} else {
		sub_tvb = tvb_new_octet_aligned(tvb, bit_offset, (gint32) no_of_bits);
	}
	*data_length = tvb_reported_length(sub_tvb);
	return (guint8*)tvb_memdup(scope, sub_tvb, 0, *data_length);
}

/* Get 1 - 8 bits */
guint8
tvb_get_bits8(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits)
{
	return (guint8)_tvb_get_bits64(tvb, bit_offset, no_of_bits);
}

/* Get 1 - 16 bits */
guint16
tvb_get_bits16(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint encoding)
{
	return (guint16)tvb_get_bits64(tvb, bit_offset, no_of_bits, encoding);
}

/* Get 1 - 32 bits */
guint32
tvb_get_bits32(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint encoding)
{
	return (guint32)tvb_get_bits64(tvb, bit_offset, no_of_bits, encoding);
}

/* Get 1 - 64 bits */
guint64
tvb_get_bits64(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint encoding)
{
	/* encoding determines bit numbering within octet array */
	if (encoding & ENC_LITTLE_ENDIAN) {
		return _tvb_get_bits64_le(tvb, bit_offset, no_of_bits);
	} else {
		return _tvb_get_bits64(tvb, bit_offset, no_of_bits);
	}
}

/*
 * This function will dissect a sequence of bits that does not need to be byte aligned; the bits
 * set will be shown in the tree as ..10 10.. and the integer value returned if return_value is set.
 * Offset should be given in bits from the start of the tvb.
 * Bits within octet are numbered from MSB (0) to LSB (7). Bit at bit_offset is return value most significant bit.
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

/*
 * Offset should be given in bits from the start of the tvb.
 * Bits within octet are numbered from LSB (0) to MSB (7). Bit at bit_offset is return value least significant bit.
 * The function tolerates requests for more than 64 bits, but will only return the least significant 64 bits.
 */
static guint64
_tvb_get_bits64_le(tvbuff_t *tvb, guint bit_offset, const gint total_no_of_bits)
{
	guint64 value = 0;
	guint octet_offset = bit_offset / 8;
	gint remaining_bits = total_no_of_bits;
	gint shift = 0;

	if (remaining_bits > 64)
	{
		remaining_bits = 64;
	}

	if (bit_offset % 8)
	{
		/* not aligned, extract bits from first octet */
		shift = 8 - (bit_offset % 8);
		value = tvb_get_guint8(tvb, octet_offset) >> (bit_offset % 8);
		if (shift > total_no_of_bits)
		{
			/* keep only the requested bits */
			value &= (G_GUINT64_CONSTANT(1) << total_no_of_bits) - 1;
			remaining_bits = 0;
		}
		else
		{
			remaining_bits = total_no_of_bits - shift;
		}
		octet_offset++;
	}

	while (remaining_bits > 0)
	{
		/* take the biggest words, shorts or octets that we can */
		if (remaining_bits >= 32)
		{
			value |= ((guint64)tvb_get_letohl(tvb, octet_offset) << shift);
			shift += 32;
			remaining_bits -= 32;
			octet_offset += 4;
		}
		else if (remaining_bits >= 16)
		{
			value |= ((guint64)tvb_get_letohs(tvb, octet_offset) << shift);
			shift += 16;
			remaining_bits -= 16;
			octet_offset += 2;
		}
		else if (remaining_bits >= 8)
		{
			value |= ((guint64)tvb_get_guint8(tvb, octet_offset) << shift);
			shift += 8;
			remaining_bits -= 8;
			octet_offset += 1;
		}
		else
		{
			guint mask = (1 << remaining_bits) - 1;
			value |= (((guint64)tvb_get_guint8(tvb, octet_offset) & mask) << shift);
			shift += remaining_bits;
			remaining_bits = 0;
			octet_offset += 1;
		}
	}
	return value;
}

/* Get 1 - 32 bits (should be deprecated as same as tvb_get_bits32??) */
guint32
tvb_get_bits(tvbuff_t *tvb, const guint bit_offset, const gint no_of_bits, const guint encoding)
{
	return (guint32)tvb_get_bits64(tvb, bit_offset, no_of_bits, encoding);
}

static gint
tvb_find_guint8_generic(tvbuff_t *tvb, guint abs_offset, guint limit, guint8 needle)
{
	const guint8 *ptr;
	const guint8 *result;

	ptr = ensure_contiguous(tvb, abs_offset, limit); /* tvb_get_ptr() */
	if (!ptr)
		return -1;

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
	guint	      abs_offset = 0;
	guint	      limit = 0;
	int           exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset_and_remaining(tvb, offset, &abs_offset, &limit);
	if (exception)
		THROW(exception);

	/* Only search to end of tvbuff, w/o throwing exception. */
	if (maxlength >= 0 && limit > (guint) maxlength) {
		/* Maximum length doesn't go past end of tvbuff; search
		   to that value. */
		limit = (guint) maxlength;
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

/* Same as tvb_find_guint8() with 16bit needle. */
gint
tvb_find_guint16(tvbuff_t *tvb, const gint offset, const gint maxlength,
		 const guint16 needle)
{
	guint	      abs_offset = 0;
	guint	      limit = 0;
	int           exception;

	exception = compute_offset_and_remaining(tvb, offset, &abs_offset, &limit);
	if (exception)
		THROW(exception);

	/* Only search to end of tvbuff, w/o throwing exception. */
	if (maxlength >= 0 && limit > (guint) maxlength) {
		/* Maximum length doesn't go past end of tvbuff; search
		   to that value. */
		limit = (guint) maxlength;
	}

	const guint8 needle1 = ((needle & 0xFF00) >> 8);
	const guint8 needle2 = ((needle & 0x00FF) >> 0);
	guint searched_bytes = 0;
	guint pos = abs_offset;

	do {
		gint offset1 =
			tvb_find_guint8(tvb, pos, limit - searched_bytes, needle1);
		gint offset2 = -1;

		if (offset1 == -1) {
			return -1;
		}

		searched_bytes = (guint)offset1 - abs_offset + 1;

		if (searched_bytes >= limit) {
			return -1;
		}

		offset2 = tvb_find_guint8(tvb, offset1 + 1, 1, needle2);

		searched_bytes += 1;

		if (offset2 != -1) {
			if (searched_bytes > limit) {
				return -1;
			}
			return offset1;
		}

		pos = offset1 + 1;
	} while (searched_bytes < limit);

	return -1;
}

static inline gint
tvb_ws_mempbrk_guint8_generic(tvbuff_t *tvb, guint abs_offset, guint limit, const ws_mempbrk_pattern* pattern, guchar *found_needle)
{
	const guint8 *ptr;
	const guint8 *result;

	ptr = ensure_contiguous(tvb, abs_offset, limit); /* tvb_get_ptr */
	if (!ptr)
		return -1;

	result = ws_mempbrk_exec(ptr, limit, pattern, found_needle);
	if (!result)
		return -1;

	return (gint) ((result - ptr) + abs_offset);
}


/* Find first occurrence of any of the pattern chars in tvbuff, starting at offset.
 * Searches at most maxlength number of bytes; if maxlength is -1, searches
 * to end of tvbuff.
 * Returns the offset of the found needle, or -1 if not found.
 * Will not throw an exception, even if maxlength exceeds boundary of tvbuff;
 * in that case, -1 will be returned if the boundary is reached before
 * finding needle. */
gint
tvb_ws_mempbrk_pattern_guint8(tvbuff_t *tvb, const gint offset, const gint maxlength,
			const ws_mempbrk_pattern* pattern, guchar *found_needle)
{
	const guint8 *result;
	guint	      abs_offset = 0;
	guint	      limit = 0;
	int           exception;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	exception = compute_offset_and_remaining(tvb, offset, &abs_offset, &limit);
	if (exception)
		THROW(exception);

	/* Only search to end of tvbuff, w/o throwing exception. */
	if (limit > (guint) maxlength) {
		/* Maximum length doesn't go past end of tvbuff; search
		   to that value. */
		limit = maxlength;
	}

	/* If we have real data, perform our search now. */
	if (tvb->real_data) {
		result = ws_mempbrk_exec(tvb->real_data + abs_offset, limit, pattern, found_needle);
		if (result == NULL) {
			return -1;
		}
		else {
			return (gint) (result - tvb->real_data);
		}
	}

	if (tvb->ops->tvb_ws_mempbrk_pattern_guint8)
		return tvb->ops->tvb_ws_mempbrk_pattern_guint8(tvb, abs_offset, limit, pattern, found_needle);

	return tvb_ws_mempbrk_guint8_generic(tvb, abs_offset, limit, pattern, found_needle);
}

/* Find size of stringz (NUL-terminated string) by looking for terminating
 * NUL.  The size of the string includes the terminating NUL.
 *
 * If the NUL isn't found, it throws the appropriate exception.
 */
guint
tvb_strsize(tvbuff_t *tvb, const gint offset)
{
	guint abs_offset = 0, junk_length;
	gint  nul_offset;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	check_offset_length(tvb, offset, 0, &abs_offset, &junk_length);
	nul_offset = tvb_find_guint8(tvb, abs_offset, -1, 0);
	if (nul_offset == -1) {
		/*
		 * OK, we hit the end of the tvbuff, so we should throw
		 * an exception.
		 */
		if (tvb->length < tvb->contained_length) {
			THROW(BoundsError);
		} else if (tvb->flags & TVBUFF_FRAGMENT) {
			THROW(FragmentBoundsError);
		} else if (tvb->length < tvb->reported_length) {
			THROW(ContainedBoundsError);
		} else {
			THROW(ReportedBoundsError);
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
	guint abs_offset = 0, junk_length;

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
 * Check that the tvbuff contains at least size bytes, starting at
 * offset, and that those bytes are equal to str. Return 0 for success
 * and -1 for error. This function does not throw an exception.
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

/**
 * Format the data in the tvb from offset for size.  Returned string is
 * wmem packet_scoped so call must be in that scope.
 */
gchar *
tvb_format_text(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint size)
{
	const guint8 *ptr;
	gint          len;

	len = (size > 0) ? size : 0;

	ptr = ensure_contiguous(tvb, offset, size);
	return format_text(scope, ptr, len);
}

/*
 * Format the data in the tvb from offset for length ...
 */
gchar *
tvb_format_text_wsp(wmem_allocator_t* allocator, tvbuff_t *tvb, const gint offset, const gint size)
{
	const guint8 *ptr;
	gint          len;

	len = (size > 0) ? size : 0;

	ptr = ensure_contiguous(tvb, offset, size);
	return format_text_wsp(allocator, ptr, len);
}

/**
 * Like "tvb_format_text()", but for null-padded strings; don't show
 * the null padding characters as "\000".  Returned string is wmem packet_scoped
 * so call must be in that scope.
 */
gchar *
tvb_format_stringzpad(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint size)
{
	const guint8 *ptr, *p;
	gint          len;
	gint          stringlen;

	len = (size > 0) ? size : 0;

	ptr = ensure_contiguous(tvb, offset, size);
	for (p = ptr, stringlen = 0; stringlen < len && *p != '\0'; p++, stringlen++)
		;
	return format_text(scope, ptr, stringlen);
}

/*
 * Like "tvb_format_text_wsp()", but for null-padded strings; don't show
 * the null padding characters as "\000".
 */
gchar *
tvb_format_stringzpad_wsp(wmem_allocator_t* allocator, tvbuff_t *tvb, const gint offset, const gint size)
{
	const guint8 *ptr, *p;
	gint          len;
	gint          stringlen;

	len = (size > 0) ? size : 0;

	ptr = ensure_contiguous(tvb, offset, size);
	for (p = ptr, stringlen = 0; stringlen < len && *p != '\0'; p++, stringlen++)
		;
	return format_text_wsp(allocator, ptr, stringlen);
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
 * Given a wmem scope, a tvbuff, an offset, and a length, treat the string
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
 * Given a wmem scope, a tvbuff, an offset, a length, and a translation table,
 * treat the string of bytes referred to by the tvbuff, offset, and length
 * as a string encoded using one octet per character, with octets with the
 * high-order bit clear being mapped by the translation table to 2-byte
 * Unicode Basic Multilingual Plane characters (including REPLACEMENT
 * CHARACTER) and octets with the high-order bit set being mapped to
 * REPLACEMENT CHARACTER, and return a pointer to a UTF-8 string,
 * allocated using the wmem scope.
 *
 * Octets with the highest bit set will be converted to the Unicode
 * REPLACEMENT CHARACTER.
 */
static guint8 *
tvb_get_iso_646_string(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint length, const gunichar2 table[0x80])
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_iso_646_string(scope, ptr, length, table);
}

/*
 * Given a wmem scope, a tvbuff, an offset, and a length, treat the string
 * of bytes referred to by the tvbuff, the offset. and the length as a UTF-8
 * string, and return a pointer to a UTF-8 string, allocated using the wmem
 * scope, with all ill-formed sequences replaced with the Unicode REPLACEMENT
 * CHARACTER according to the recommended "best practices" given in the Unicode
 * Standard and specified by W3C/WHATWG.
 *
 * Note that in conformance with the Unicode Standard, this treats three
 * byte sequences corresponding to UTF-16 surrogate halves (paired or unpaired)
 * and two byte overlong encodings of 7-bit ASCII characters as invalid and
 * substitutes REPLACEMENT CHARACTER for them. Explicit support for nonstandard
 * derivative encoding formats (e.g. CESU-8, Java Modified UTF-8, WTF-8) could
 * be added later.
 */
static guint8 *
tvb_get_utf_8_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint length)
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_utf_8_string(scope, ptr, length);
}

/*
 * Given a wmem scope, a tvbuff, an offset, and a length, treat the string
 * of bytes referred to by the tvbuff, the offset, and the length as a
 * raw string, and return a pointer to that string, allocated using the
 * wmem scope. This means a null is appended at the end, but no replacement
 * checking is done otherwise, unlike tvb_get_utf_8_string().
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
 * Given a wmem scope, a tvbuff, an offset, a length, and a translation
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
tvb_get_ts_23_038_7bits_string_packed(wmem_allocator_t *scope, tvbuff_t *tvb,
	const gint bit_offset, gint no_of_chars)
{
	gint           in_offset = bit_offset >> 3; /* Current pointer to the input buffer */
	gint           length = ((no_of_chars + 1) * 7 + (bit_offset & 0x07)) >> 3;
	const guint8  *ptr;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	ptr = ensure_contiguous(tvb, in_offset, length);
	return get_ts_23_038_7bits_string_packed(scope, ptr, bit_offset, no_of_chars);
}

gchar *
tvb_get_ts_23_038_7bits_string_unpacked(wmem_allocator_t *scope, tvbuff_t *tvb,
	const gint offset, gint length)
{
	const guint8  *ptr;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	ptr = ensure_contiguous(tvb, offset, length);
	return get_ts_23_038_7bits_string_unpacked(scope, ptr, length);
}

gchar *
tvb_get_etsi_ts_102_221_annex_a_string(wmem_allocator_t *scope, tvbuff_t *tvb,
	const gint offset, gint length)
{
	const guint8  *ptr;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	ptr = ensure_contiguous(tvb, offset, length);
	return get_etsi_ts_102_221_annex_a_string(scope, ptr, length);
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
 * Given a wmem scope, a tvbuff, an offset, a length, and a translation
 * table, treat the string of bytes referred to by the tvbuff, the offset,
 * and the length as a string encoded using one octet per character, with
 * octets being mapped by the translation table to 2-byte Unicode Basic
 * Multilingual Plane characters (including REPLACEMENT CHARACTER), and
 * return a pointer to a UTF-8 string, allocated with the wmem scope.
 */
static guint8 *
tvb_get_nonascii_unichar2_string(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint length, const gunichar2 table[256])
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_nonascii_unichar2_string(scope, ptr, length, table);
}

/*
 * Given a wmem scope, a tvbuff, an offset, and a length, treat the bytes
 * referred to by the tvbuff, offset, and length as a GB18030 encoded string,
 * and return a pointer to a UTF-8 string, allocated with the wmem scope,
 * converted having substituted REPLACEMENT CHARACTER according to the
 * Unicode Standard 5.22 U+FFFD Substitution for Conversion.
 * ( https://www.unicode.org/versions/Unicode13.0.0/ch05.pdf )
 *
 * As expected, this will also decode GBK and GB2312 strings.
 */
static guint8 *
tvb_get_gb18030_string(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint length)
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_gb18030_string(scope, ptr, length);
}

/*
 * Given a wmem scope, a tvbuff, an offset, and a length, treat the bytes
 * referred to by the tvbuff, offset, and length as a EUC-KR encoded string,
 * and return a pointer to a UTF-8 string, allocated with the wmem scope,
 * converted having substituted REPLACEMENT CHARACTER according to the
 * Unicode Standard 5.22 U+FFFD Substitution for Conversion.
 * ( https://www.unicode.org/versions/Unicode13.0.0/ch05.pdf )
 */
static guint8 *
tvb_get_euc_kr_string(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint length)
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_euc_kr_string(scope, ptr, length);
}

static guint8 *
tvb_get_t61_string(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint length)
{
	const guint8  *ptr;

	ptr = ensure_contiguous(tvb, offset, length);
	return get_t61_string(scope, ptr, length);
}

/*
 * Encoding tables for BCD strings.
 */
static const dgt_set_t Dgt0_9_bcd = {
	{
		/*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e  f */
		   '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?','?'
	}
};

static const dgt_set_t Dgt_keypad_abc_tbcd = {
	{
		/*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e  f */
		   '0','1','2','3','4','5','6','7','8','9','*','#','a','b','c','?'
	}
};

static const dgt_set_t Dgt_ansi_tbcd = {
	{
		/*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e  f */
		   '0','1','2','3','4','5','6','7','8','9','?','B','C','*','#','?'
	}
};

static guint8 *
tvb_get_apn_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset,
			     gint length)
{
	wmem_strbuf_t *str;

	/*
	 * This is a domain name.
	 *
	 * 3GPP TS 23.003, section 19.4.2 "Fully Qualified Domain Names
	 * (FQDNs)", subsection 19.4.2.1 "General", says:
	 *
	 *    The encoding of any identifier used as part of a Fully
	 *    Qualifed Domain Name (FQDN) shall follow the Name Syntax
	 *    defined in IETF RFC 2181 [18], IETF RFC 1035 [19] and
	 *    IETF RFC 1123 [20].  An FQDN consists of one or more
	 *    labels. Each label is coded as a one octet length field
	 *    followed by that number of octets coded as 8 bit ASCII
	 *    characters.
	 *
	 * so this does not appear to use full-blown DNS compression -
	 * the upper 2 bits of the length don't indicate that it's a
	 * pointer or an extended label (RFC 2673).
	 */
	str = wmem_strbuf_sized_new(scope, length + 1, 0);
	if (length > 0) {
		const guint8 *ptr;

		ptr = ensure_contiguous(tvb, offset, length);

		for (;;) {
			guint label_len;

			/*
			 * Process this label.
			 */
			label_len = *ptr;
			ptr++;
			length--;

			while (label_len != 0) {
				guint8 ch;

				if (length == 0)
					goto end;

				ch = *ptr;
				if (ch < 0x80)
					wmem_strbuf_append_c(str, ch);
				else
					wmem_strbuf_append_unichar(str, UNREPL);
				ptr++;
				label_len--;
				length--;
			}

			if (length == 0)
				goto end;

			wmem_strbuf_append_c(str, '.');
		}
	}

end:
	return (guint8 *) wmem_strbuf_finalize(str);
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
	gboolean odd, skip_first;

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

	case ENC_WINDOWS_1251:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp1251);
		break;

	case ENC_WINDOWS_1252:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp1252);
		break;

	case ENC_MAC_ROMAN:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_mac_roman);
		break;

	case ENC_CP437:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp437);
		break;

	case ENC_CP855:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp855);
		break;

	case ENC_CP866:
		strptr = tvb_get_string_unichar2(scope, tvb, offset, length, charset_table_cp866);
		break;

	case ENC_ISO_646_BASIC:
		strptr = tvb_get_iso_646_string(scope, tvb, offset, length, charset_table_iso_646_basic);
		break;

	case ENC_3GPP_TS_23_038_7BITS_PACKED:
		{
			gint bit_offset  = offset << 3;
			gint no_of_chars = (length << 3) / 7;
			strptr = tvb_get_ts_23_038_7bits_string_packed(scope, tvb, bit_offset, no_of_chars);
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
		 * "Common" EBCDIC, covering all characters with the
		 * same code point in all Roman-alphabet EBCDIC code
		 * pages.
		 */
		strptr = tvb_get_nonascii_unichar2_string(scope, tvb, offset, length, charset_table_ebcdic);
		break;

	case ENC_EBCDIC_CP037:
		/*
		 * EBCDIC code page 037.
		 */
		strptr = tvb_get_nonascii_unichar2_string(scope, tvb, offset, length, charset_table_ebcdic_cp037);
		break;

	case ENC_T61:
		strptr = tvb_get_t61_string(scope, tvb, offset, length);
		break;

	case ENC_BCD_DIGITS_0_9:
		/*
		 * Packed BCD, with digits 0-9.
		 */
		odd = (encoding & ENC_BCD_ODD_NUM_DIG) >> 16;
		skip_first = (encoding & ENC_BCD_SKIP_FIRST) >> 17;
		strptr = tvb_get_bcd_string(scope, tvb, offset, length, &Dgt0_9_bcd, skip_first, odd, FALSE);
		break;

	case ENC_KEYPAD_ABC_TBCD:
		/*
		 * Keypad-with-a/b/c "telephony BCD" - packed BCD, with
		 * digits 0-9 and symbols *, #, a, b, and c.
		 */
		odd = (encoding & ENC_BCD_ODD_NUM_DIG) >> 16;
		skip_first = (encoding & ENC_BCD_SKIP_FIRST) >> 17;
		strptr = tvb_get_bcd_string(scope, tvb, offset, length, &Dgt_keypad_abc_tbcd, skip_first, odd, FALSE);
		break;

	case ENC_KEYPAD_BC_TBCD:
		/*
		 * Keypad-with-B/C "telephony BCD" - packed BCD, with
		 * digits 0-9 and symbols B, C, *, and #.
		 */
		odd = (encoding & ENC_BCD_ODD_NUM_DIG) >> 16;
		skip_first = (encoding & ENC_BCD_SKIP_FIRST) >> 17;
		strptr = tvb_get_bcd_string(scope, tvb, offset, length, &Dgt_ansi_tbcd, skip_first, odd, FALSE);
		break;

	case ENC_3GPP_TS_23_038_7BITS_UNPACKED:
		strptr = tvb_get_ts_23_038_7bits_string_unpacked(scope, tvb, offset, length);
		break;

	case ENC_ETSI_TS_102_221_ANNEX_A:
		strptr = tvb_get_etsi_ts_102_221_annex_a_string(scope, tvb, offset, length);
		break;

	case ENC_GB18030:
		strptr = tvb_get_gb18030_string(scope, tvb, offset, length);
		break;

	case ENC_EUC_KR:
		strptr = tvb_get_euc_kr_string(scope, tvb, offset, length);
		break;

	case ENC_APN_STR:
		strptr = tvb_get_apn_string(scope, tvb, offset, length);
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
tvb_get_iso_646_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint *lengthp, const gunichar2 table[0x80])
{
	guint	       size;
	const guint8  *ptr;

	size = tvb_strsize(tvb, offset);
	ptr  = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_iso_646_string(scope, ptr, size, table);
}

static guint8 *
tvb_get_utf_8_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint *lengthp)
{
	guint   size;
	const guint8  *ptr;

	size   = tvb_strsize(tvb, offset);
	ptr = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_utf_8_string(scope, ptr, size);
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
tvb_get_nonascii_unichar2_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint *lengthp, const gunichar2 table[256])
{
	guint	       size;
	const guint8  *ptr;

	size = tvb_strsize(tvb, offset);
	ptr  = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_nonascii_unichar2_string(scope, ptr, size, table);
}

static guint8 *
tvb_get_t61_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint *lengthp)
{
	guint	       size;
	const guint8  *ptr;

	size = tvb_strsize(tvb, offset);
	ptr  = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_t61_string(scope, ptr, size);
}

static guint8 *
tvb_get_gb18030_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint *lengthp)
{
	guint          size;
	const guint8  *ptr;

	size = tvb_strsize(tvb, offset);
	ptr  = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_gb18030_string(scope, ptr, size);
}

static guint8 *
tvb_get_euc_kr_stringz(wmem_allocator_t *scope, tvbuff_t *tvb, gint offset, gint  *lengthp)
{
	guint          size;
	const guint8  *ptr;

	size = tvb_strsize(tvb, offset);
	ptr  = ensure_contiguous(tvb, offset, size);
	/* XXX, conversion between signed/unsigned integer */
	if (lengthp)
		*lengthp = size;
	return get_euc_kr_string(scope, ptr, size);
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

	case ENC_WINDOWS_1251:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_cp1251);
		break;

	case ENC_WINDOWS_1252:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_cp1252);
		break;

	case ENC_MAC_ROMAN:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_mac_roman);
		break;

	case ENC_CP437:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_cp437);
		break;

	case ENC_CP855:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_cp855);
		break;

	case ENC_CP866:
		strptr = tvb_get_stringz_unichar2(scope, tvb, offset, lengthp, charset_table_cp866);
		break;

	case ENC_ISO_646_BASIC:
		strptr = tvb_get_iso_646_stringz(scope, tvb, offset, lengthp, charset_table_iso_646_basic);
		break;

	case ENC_3GPP_TS_23_038_7BITS_PACKED:
	case ENC_3GPP_TS_23_038_7BITS_UNPACKED:
	case ENC_ETSI_TS_102_221_ANNEX_A:
		REPORT_DISSECTOR_BUG("TS 23.038 7bits has no null character and doesn't support null-terminated strings");
		break;

	case ENC_ASCII_7BITS:
		REPORT_DISSECTOR_BUG("tvb_get_stringz_enc function with ENC_ASCII_7BITS not implemented yet");
		break;

	case ENC_EBCDIC:
		/*
		 * "Common" EBCDIC, covering all characters with the
		 * same code point in all Roman-alphabet EBCDIC code
		 * pages.
		 */
		strptr = tvb_get_nonascii_unichar2_stringz(scope, tvb, offset, lengthp, charset_table_ebcdic);
		break;

	case ENC_EBCDIC_CP037:
		/*
		 * EBCDIC code page 037.
		 */
		strptr = tvb_get_nonascii_unichar2_stringz(scope, tvb, offset, lengthp, charset_table_ebcdic_cp037);
		break;

	case ENC_T61:
		strptr = tvb_get_t61_stringz(scope, tvb, offset, lengthp);
		break;

	case ENC_GB18030:
		strptr = tvb_get_gb18030_stringz(scope, tvb, offset, lengthp);
		break;

	case ENC_EUC_KR:
		strptr = tvb_get_euc_kr_stringz(scope, tvb, offset, lengthp);
		break;
	}

	return strptr;
}

/* Looks for a stringz (NUL-terminated string) in tvbuff and copies
 * no more than bufsize number of bytes, including terminating NUL, to buffer.
 * Returns length of string (not including terminating NUL), or -1 if the string was
 * truncated in the buffer due to not having reached the terminating NUL.
 * In this way, it acts like snprintf().
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
	guint    abs_offset = 0;
	gint     limit, len = 0;
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
 * In this way, it acts like snprintf().
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
 * Given a tvbuff, an offset into the tvbuff, a buffer, and a buffer size,
 * extract as many raw bytes from the tvbuff, starting at the offset,
 * as 1) are available in the tvbuff and 2) will fit in the buffer, leaving
 * room for a terminating NUL.
 */
gint
tvb_get_raw_bytes_as_string(tvbuff_t *tvb, const gint offset, char *buffer, size_t bufsize)
{
	gint     len = 0;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	/* There must be room for the string and the terminating NUL. */
	DISSECTOR_ASSERT(bufsize > 0);

	DISSECTOR_ASSERT(bufsize - 1 < G_MAXINT);

	len = tvb_captured_length_remaining(tvb, offset);
	if (len <= 0) {
		buffer[0] = '\0';
		return 0;
	}
	if (len > (gint)(bufsize - 1))
		len = (gint)(bufsize - 1);

	/* Copy the string to buffer */
	tvb_memcpy(tvb, buffer, offset, len);
	buffer[len] = '\0';
	return len;
}

gboolean tvb_ascii_isprint(tvbuff_t *tvb, const gint offset, const gint length)
{
	const guint8* buf = tvb_get_ptr(tvb, offset, length);
	guint abs_offset, abs_length = length;

	if (length == -1) {
		/* tvb_get_ptr has already checked for exceptions. */
		compute_offset_and_remaining(tvb, offset, &abs_offset, &abs_length);
	}
	for (guint i = 0; i < abs_length; i++, buf++)
		if (!g_ascii_isprint(*buf))
			return FALSE;

	return TRUE;
}

gboolean tvb_utf_8_isprint(tvbuff_t *tvb, const gint offset, const gint length)
{
	const guint8* buf = tvb_get_ptr(tvb, offset, length);
	guint abs_offset, abs_length = length;

	if (length == -1) {
		/* tvb_get_ptr has already checked for exceptions. */
		compute_offset_and_remaining(tvb, offset, &abs_offset, &abs_length);
	}

	return isprint_utf8_string(buf, abs_length);
}

static ws_mempbrk_pattern pbrk_crlf;
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
 * if "desegment" is true, return -1;
 *
 * if "desegment" is false, return the amount of data remaining in
 * the buffer.
 *
 * If "next_offset" is not NULL, set "*next_offset" to the offset of the
 * character past the line terminator, or past the end of the buffer if
 * we don't find a line terminator.  (It's not set if we return -1.)
 */
gint
tvb_find_line_end(tvbuff_t *tvb, const gint offset, int len, gint *next_offset, const gboolean desegment)
{
	gint   eob_offset;
	gint   eol_offset;
	int    linelen;
	guchar found_needle = 0;
	static gboolean compiled = FALSE;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	if (len == -1) {
		len = _tvb_captured_length_remaining(tvb, offset);
		/* if offset is past the end of the tvbuff, len is now 0 */
	}

	eob_offset = offset + len;

	if (!compiled) {
		ws_mempbrk_compile(&pbrk_crlf, "\r\n");
		compiled = TRUE;
	}

	/*
	 * Look either for a CR or an LF.
	 */
	eol_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset, len, &pbrk_crlf, &found_needle);
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

static ws_mempbrk_pattern pbrk_crlf_dquote;
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
 * If "next_offset" is not NULL, set "*next_offset" to the offset of the
 * character past the line terminator, or past the end of the buffer if
 * we don't find a line terminator.
 */
gint
tvb_find_line_end_unquoted(tvbuff_t *tvb, const gint offset, int len, gint *next_offset)
{
	gint     cur_offset, char_offset;
	gboolean is_quoted;
	guchar   c = 0;
	gint     eob_offset;
	int      linelen;
	static gboolean compiled = FALSE;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	if (len == -1)
		len = _tvb_captured_length_remaining(tvb, offset);

	if (!compiled) {
		ws_mempbrk_compile(&pbrk_crlf_dquote, "\r\n\"");
		compiled = TRUE;
	}

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
			char_offset = tvb_ws_mempbrk_pattern_guint8(tvb, cur_offset, len, &pbrk_crlf_dquote, &c);
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
tvb_skip_wsp_return(tvbuff_t *tvb, const gint offset)
{
	gint   counter = offset;
	guint8 tempchar;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	for (counter = offset; counter > 0 &&
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

static ws_mempbrk_pattern pbrk_whitespace;

int tvb_get_token_len(tvbuff_t *tvb, const gint offset, int len, gint *next_offset, const gboolean desegment)
{
	gint   eob_offset;
	gint   eot_offset;
	int    tokenlen;
	guchar found_needle = 0;
	static gboolean compiled = FALSE;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	if (len == -1) {
		len = _tvb_captured_length_remaining(tvb, offset);
		/* if offset is past the end of the tvbuff, len is now 0 */
	}

	eob_offset = offset + len;

	if (!compiled) {
		ws_mempbrk_compile(&pbrk_whitespace, " \r\n");
		compiled = TRUE;
	}

	/*
	* Look either for a space, CR, or LF.
	*/
	eot_offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset, len, &pbrk_whitespace, &found_needle);
	if (eot_offset == -1) {
		/*
		* No space, CR or LF - token is presumably continued in next packet.
		*/
		if (desegment) {
			/*
			* Tell our caller we saw no whitespace, so they can
			* try to desegment and get the entire line
			* into one tvbuff.
			*/
			return -1;
		}
		else {
			/*
			* Pretend the token runs to the end of the tvbuff.
			*/
			tokenlen = eob_offset - offset;
			if (next_offset)
				*next_offset = eob_offset;
		}
	}
	else {
		/*
		* Find the number of bytes between the starting offset
		* and the space, CR or LF.
		*/
		tokenlen = eot_offset - offset;

		/*
		* Return the offset of the character after the last
		* character in the line, skipping over the last character
		* in the line terminator.
		*/
		if (next_offset)
			*next_offset = eot_offset + 1;
	}
	return tokenlen;
}

/*
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data, with "punct" as a byte
 * separator.
 */
gchar *
tvb_bytes_to_str_punct(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint len, const gchar punct)
{
	DISSECTOR_ASSERT(len > 0);
	return bytes_to_str_punct(scope, ensure_contiguous(tvb, offset, len), len, punct);
}

/*
 * Given a wmem scope, a tvbuff, an offset, a length, an input digit
 * set, and a boolean indicator, fetch BCD-encoded digits from a
 * tvbuff starting from either the low or high half byte of the
 * first byte depending on the boolean indicator (TRUE means "start
 * with the high half byte, ignoring the low half byte", and FALSE
 * means "start with the low half byte and proceed to the high half
 * byte), formating the digits into characters according to the
 * input digit set, and return a pointer to a UTF-8 string, allocated
 * using the wmem scope.  A high-order nibble of 0xf is considered a
 * 'filler' and will end the conversion. Similarrily if odd is set the last
 * high nibble will be omitted.
 */
gchar *
tvb_get_bcd_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, gint len, const dgt_set_t *dgt, gboolean skip_first, gboolean odd, gboolean bigendian)
{
	const guint8 *ptr;
	int           i = 0;
	char         *digit_str;
	guint8        octet;

	DISSECTOR_ASSERT(tvb && tvb->initialized);

	if (len == -1) {
		/*
		 * Run to the end of the captured data.
		 *
		 * XXX - captured, or total?
		 */
		/*length = tvb_captured_length(tvb);*/
		len = tvb->length;
		if (len < offset) {
			return (char *)"";
		}
		len -= offset;
	}

	ptr = ensure_contiguous(tvb, offset, len);

	/*
	 * XXX - map illegal digits (digits that map to 0) to REPLACEMENT
	 * CHARACTER, and have all the tables in epan/tvbuff.c use 0 rather
	 * than '?'?
	 */
	digit_str = (char *)wmem_alloc(scope, len*2 + 1);

	while (len > 0) {
		octet = *ptr;
		if (!skip_first) {
			if (bigendian) {
				digit_str[i] = dgt->out[(octet >> 4) & 0x0f];
			} else {
				digit_str[i] = dgt->out[octet & 0x0f];
			}
			i++;
		}
		skip_first = FALSE;

		/*
		 * unpack second value in byte
		 */
		if (!bigendian) {
			octet = octet >> 4;
		}

		if (octet == 0x0f) {
			/*
			 * This is the stop digit or a filler digit.  Ignore
			 * it.
			 */
			break;
		}
		if ((len == 1) && (odd == TRUE )){
			/* Last octet, skipp last high nibble incase of odd number of digits*/
			break;
		}
		digit_str[i] = dgt->out[octet & 0x0f];
		i++;

		ptr++;
		len--;
	}
	digit_str[i] = '\0';
	return digit_str;
}

/* XXXX Fix me - needs odd indicator added */
const gchar *
tvb_bcd_dig_to_str(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint len, const dgt_set_t *dgt, gboolean skip_first)
{
	if (!dgt)
		dgt = &Dgt0_9_bcd;

	return tvb_get_bcd_string(scope, tvb, offset, len, dgt, skip_first, FALSE, FALSE);
}

const gchar *
tvb_bcd_dig_to_str_be(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint len, const dgt_set_t *dgt, gboolean skip_first)
{
	if (!dgt)
		dgt = &Dgt0_9_bcd;

	return tvb_get_bcd_string(scope, tvb, offset, len, dgt, skip_first, FALSE, TRUE);
}

/*
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data.
 */
gchar *tvb_bytes_to_str(wmem_allocator_t *allocator, tvbuff_t *tvb,
    const gint offset, const gint len)
{
	DISSECTOR_ASSERT(len > 0);
	return bytes_to_str(allocator, ensure_contiguous(tvb, offset, len), len);
}

/* Find a needle tvbuff within a haystack tvbuff. */
gint
tvb_find_tvb(tvbuff_t *haystack_tvb, tvbuff_t *needle_tvb, const gint haystack_offset)
{
	guint	      haystack_abs_offset = 0, haystack_abs_length = 0;
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

	location = ws_memmem(haystack_data + haystack_abs_offset, haystack_abs_length,
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

guint
tvb_get_varint(tvbuff_t *tvb, guint offset, guint maxlen, guint64 *value, const guint encoding)
{
	*value = 0;

	switch (encoding & ENC_VARINT_MASK) {
	case ENC_VARINT_PROTOBUF:
	{
		guint i;
		guint64 b; /* current byte */

		for (i = 0; ((i < FT_VARINT_MAX_LEN) && (i < maxlen)); ++i) {
			b = tvb_get_guint8(tvb, offset++);
			*value |= ((b & 0x7F) << (i * 7)); /* add lower 7 bits to val */

			if (b < 0x80) {
				/* end successfully becauseof last byte's msb(most significant bit) is zero */
				return i + 1;
			}
		}
		break;
	}

	case ENC_VARINT_ZIGZAG:
	{
		guint i;
		guint64 b; /* current byte */

		for (i = 0; ((i < FT_VARINT_MAX_LEN) && (i < maxlen)); ++i) {
			b = tvb_get_guint8(tvb, offset++);
			*value |= ((b & 0x7F) << (i * 7)); /* add lower 7 bits to val */

			if (b < 0x80) {
				/* end successfully becauseof last byte's msb(most significant bit) is zero */
				*value = (*value >> 1) ^ ((*value & 1) ? -1 : 0);
				return i + 1;
			}
		}
		break;
	}

	case ENC_VARINT_QUIC:
	{
		/* calculate variable length */
		*value = tvb_get_guint8(tvb, offset);
		switch((*value) >> 6) {
		case 0: /* 0b00 => 1 byte length (6 bits Usable) */
			(*value) &= 0x3F;
			return 1;
		case 1: /* 0b01 => 2 bytes length (14 bits Usable) */
			*value = tvb_get_ntohs(tvb, offset) & 0x3FFF;
			return 2;
		case 2: /* 0b10 => 4 bytes length (30 bits Usable) */
			*value = tvb_get_ntohl(tvb, offset) & 0x3FFFFFFF;
			return 4;
		case 3: /* 0b11 => 8 bytes length (62 bits Usable) */
			*value = tvb_get_ntoh64(tvb, offset) & G_GUINT64_CONSTANT(0x3FFFFFFFFFFFFFFF);
			return 8;
		default: /* No Possible */
			ws_assert_not_reached();
			break;
		}
		break;
	}

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
	}

	return 0; /* 10 bytes scanned, but no bytes' msb is zero */
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
