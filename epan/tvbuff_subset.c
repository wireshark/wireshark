/* tvbuff_subset.c
 *
 * Copyright (c) 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "tvbuff.h"
#include "tvbuff-int.h"
#include "proto.h"	/* XXX - only used for DISSECTOR_ASSERT, probably a new header file? */
#include "exceptions.h"

typedef struct {
	/** The backing tvbuff_t */
	struct tvbuff	*tvb;

	/** The offset of 'tvb' to which I'm privy */
	unsigned		offset;
	/** The length of 'tvb' to which I'm privy */
	unsigned		length;

} tvb_backing_t;

struct tvb_subset {
	struct tvbuff tvb;

	tvb_backing_t	subset;
};

static unsigned
subset_offset(const tvbuff_t *tvb, const unsigned counter)
{
	const struct tvb_subset *subset_tvb = (const struct tvb_subset *) tvb;
	const tvbuff_t *member = subset_tvb->subset.tvb;

	return tvb_offset_from_real_beginning_counter(member, counter + subset_tvb->subset.offset);
}

static void *
subset_memcpy(tvbuff_t *tvb, void *target, unsigned abs_offset, unsigned abs_length)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_memcpy(subset_tvb->subset.tvb, target, subset_tvb->subset.offset + abs_offset, abs_length);
}

static const uint8_t *
subset_get_ptr(tvbuff_t *tvb, unsigned abs_offset, unsigned abs_length)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_get_ptr(subset_tvb->subset.tvb, subset_tvb->subset.offset + abs_offset, abs_length);
}

static bool
subset_find_uint8(tvbuff_t *tvb, unsigned abs_offset, unsigned limit, uint8_t needle, unsigned *found_offset)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;
	bool result;

	result = tvb_find_uint8_length(subset_tvb->subset.tvb, subset_tvb->subset.offset + abs_offset, limit, needle, found_offset);

	/*
	 * Make the result relative to the beginning of the tvbuff we
	 * were handed, *not* relative to the beginning of its parent
	 * tvbuff.
	 */
	if (found_offset) {
		*found_offset -= subset_tvb->subset.offset;
	}
	return result;
}

static bool
subset_pbrk_uint8(tvbuff_t *tvb, unsigned abs_offset, unsigned limit, const ws_mempbrk_pattern* pattern, unsigned *found_offset, unsigned char *found_needle)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;
	bool result;

	result = tvb_ws_mempbrk_uint8_length(subset_tvb->subset.tvb, subset_tvb->subset.offset + abs_offset, limit, pattern, found_offset, found_needle);

	/*
	 * Make the result relative to the beginning of the tvbuff we
	 * were handed, *not* relative to the beginning of its parent
	 * tvbuff.
	 */
	if (found_offset) {
		*found_offset -= subset_tvb->subset.offset;
	}
	return result;
}

static tvbuff_t *
subset_clone(tvbuff_t *tvb, unsigned abs_offset, unsigned abs_length)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_clone_offset_len(subset_tvb->subset.tvb, subset_tvb->subset.offset + abs_offset, abs_length);
}

static const struct tvb_ops tvb_subset_ops = {
	sizeof(struct tvb_subset), /* size */

	NULL,                 /* free */
	subset_offset,        /* offset */
	subset_get_ptr,       /* get_ptr */
	subset_memcpy,        /* memcpy */
	subset_find_uint8,    /* find_uint8 */
	subset_pbrk_uint8,    /* pbrk_uint8 */
	subset_clone,         /* clone */
};

static tvbuff_t *
tvb_new_with_subset(tvbuff_t *backing, const unsigned reported_length,
    const unsigned subset_tvb_offset, const unsigned subset_tvb_length)
{
	tvbuff_t *tvb = tvb_new(&tvb_subset_ops);
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	subset_tvb->subset.offset = subset_tvb_offset;
	subset_tvb->subset.length = subset_tvb_length;

	subset_tvb->subset.tvb	     = backing;
	tvb->length		     = subset_tvb_length;
	/*
	 * The contained length must not exceed what remains in the
	 * backing tvbuff.
	 */
	tvb->contained_length        = MIN(reported_length, backing->contained_length - subset_tvb_offset);
	tvb->flags		     = backing->flags;

	tvb->reported_length	     = reported_length;
	tvb->initialized	     = true;

	/* Optimization. If the backing buffer has a pointer to contiguous, real data,
	 * then we can point directly to our starting offset in that buffer */
	if (backing->real_data != NULL) {
		tvb->real_data = backing->real_data + subset_tvb_offset;
	}

	if (backing->flags & TVBUFF_RAW_OFFSET) {
		tvb->raw_offset = backing->raw_offset + subset_tvb_offset;
	}

	/*
	 * The top-level data source of this tvbuff is the top-level
	 * data source of its parent.
	 */
	tvb->ds_tvb = backing->ds_tvb;

	return tvb;
}

tvbuff_t *
tvb_new_subset_length_caplen(tvbuff_t *backing, const unsigned backing_offset, const unsigned backing_length, const unsigned reported_length)
{
	tvbuff_t *tvb;
	unsigned	  subset_tvb_length;

	DISSECTOR_ASSERT(backing && backing->initialized);

	tvb_validate_offset_length(backing, backing_offset, backing_length);

	subset_tvb_length = backing_length;

	/*
	 * Cut the captured length short, so it doesn't go past the subset's
	 * reported length.
	 */
	if (subset_tvb_length > reported_length)
		subset_tvb_length = reported_length;

	tvb = tvb_new_with_subset(backing, reported_length,
	    backing_offset, subset_tvb_length);

	tvb_add_to_chain(backing, tvb);

	return tvb;
}

tvbuff_t *
tvb_new_subset_length(tvbuff_t *backing, const unsigned backing_offset, const unsigned reported_length)
{
	tvbuff_t *tvb;
	unsigned	  subset_tvb_length;

	DISSECTOR_ASSERT(backing && backing->initialized);

	tvb_validate_offset_and_remaining(backing, backing_offset, &subset_tvb_length);
	/*
	 * Cut the captured length short, so it doesn't go past the subset's
	 * reported length.
	 */
	if (subset_tvb_length > reported_length)
		subset_tvb_length = reported_length;

	tvb = tvb_new_with_subset(backing, reported_length,
	    backing_offset, subset_tvb_length);

	tvb_add_to_chain(backing, tvb);

	return tvb;
}

tvbuff_t *
tvb_new_subset_remaining(tvbuff_t *backing, const unsigned backing_offset)
{
	tvbuff_t *tvb;
	unsigned	  subset_tvb_length;
	unsigned	  reported_length;

	DISSECTOR_ASSERT(backing && backing->initialized);

	tvb_validate_offset_and_remaining(backing, backing_offset, &subset_tvb_length);

	THROW_ON(backing->reported_length < backing_offset, ReportedBoundsError);
	reported_length = backing->reported_length - backing_offset;

	tvb = tvb_new_with_subset(backing, reported_length,
	    backing_offset, subset_tvb_length);

	tvb_add_to_chain(backing, tvb);

	return tvb;
}

tvbuff_t *
tvb_new_proxy(tvbuff_t *backing)
{
	tvbuff_t *tvb;

	if (backing)
		tvb = tvb_new_with_subset(backing, backing->reported_length, 0, backing->length);
	else
		tvb = tvb_new_real_data(NULL, 0, 0);

	tvb->ds_tvb = tvb;

	return tvb;
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
