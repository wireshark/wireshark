/* tvbuff_real.c
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

#include "config.h"

#include <epan/emem.h>

#include "tvbuff.h"
#include "tvbuff-int.h"
#include "proto.h"	/* XXX - only used for DISSECTOR_ASSERT, probably a new header file? */
#include "exceptions.h"

typedef struct {
	/** The backing tvbuff_t */
	struct tvbuff	*tvb;

	/** The offset of 'tvb' to which I'm privy */
	guint		offset;
	/** The length of 'tvb' to which I'm privy */
	guint		length;

} tvb_backing_t;

struct tvb_subset {
	struct tvbuff tvb;

	tvb_backing_t	subset;
};

static guint
subset_offset(const tvbuff_t *tvb, const guint counter)
{
	const struct tvb_subset *subset_tvb = (const struct tvb_subset *) tvb;
	const tvbuff_t *member = subset_tvb->subset.tvb;

	return tvb_offset_from_real_beginning_counter(member, counter + subset_tvb->subset.offset);
}

static void *
subset_memcpy(tvbuff_t *tvb, void *target, guint abs_offset, guint abs_length)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_memcpy(subset_tvb->subset.tvb, target, subset_tvb->subset.offset + abs_offset, abs_length);
}

static const guint8 *
subset_get_ptr(tvbuff_t *tvb, guint abs_offset, guint abs_length)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_get_ptr(subset_tvb->subset.tvb, subset_tvb->subset.offset + abs_offset, abs_length);
}

static gint
subset_find_guint8(tvbuff_t *tvb, guint abs_offset, guint limit, guint8 needle)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_find_guint8(subset_tvb->subset.tvb, subset_tvb->subset.offset + abs_offset, limit, needle);
}

static gint
subset_pbrk_guint8(tvbuff_t *tvb, guint abs_offset, guint limit, const guint8 *needles, guchar *found_needle)
{
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	return tvb_pbrk_guint8(subset_tvb->subset.tvb, subset_tvb->subset.offset + abs_offset, limit, needles, found_needle);
}

static tvbuff_t *
subset_clone(tvbuff_t *tvb, guint abs_offset, guint abs_length)
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
	subset_find_guint8,   /* find_guint8 */
	subset_pbrk_guint8,   /* pbrk_guint8 */
	subset_clone,         /* clone */
};

static tvbuff_t *
tvb_new_with_subset(tvbuff_t *backing, const gint reported_length,
    const guint subset_tvb_offset, const guint subset_tvb_length)
{
	tvbuff_t *tvb = tvb_new(&tvb_subset_ops);
	struct tvb_subset *subset_tvb = (struct tvb_subset *) tvb;

	subset_tvb->subset.offset = subset_tvb_offset;
	subset_tvb->subset.length = subset_tvb_length;

	subset_tvb->subset.tvb	     = backing;
	tvb->length		     = subset_tvb_length;
	tvb->flags		     = backing->flags;

	if (reported_length == -1) {
		tvb->reported_length = backing->reported_length - subset_tvb_offset;
	}
	else {
		tvb->reported_length = reported_length;
	}
	tvb->initialized	     = TRUE;

	/* Optimization. If the backing buffer has a pointer to contiguous, real data,
	 * then we can point directly to our starting offset in that buffer */
	if (backing->real_data != NULL) {
		tvb->real_data = backing->real_data + subset_tvb_offset;
	}

	/*
	 * The top-level data source of this tvbuff is the top-level
	 * data source of its parent.
	 */
	tvb->ds_tvb = backing->ds_tvb;

	return tvb;
}

tvbuff_t *
tvb_new_subset(tvbuff_t *backing, const gint backing_offset, const gint backing_length, const gint reported_length)
{
	tvbuff_t *tvb;
	guint	  subset_tvb_offset;
	guint	  subset_tvb_length;

	DISSECTOR_ASSERT(backing && backing->initialized);

	THROW_ON(reported_length < -1, ReportedBoundsError);

	tvb_check_offset_length(backing, backing_offset, backing_length,
			        &subset_tvb_offset,
			        &subset_tvb_length);

	tvb = tvb_new_with_subset(backing, reported_length,
	    subset_tvb_offset, subset_tvb_length);

	tvb_add_to_chain(backing, tvb);

	return tvb;
}

tvbuff_t *
tvb_new_subset_length(tvbuff_t *backing, const gint backing_offset, const gint backing_length)
{
	gint	  captured_length;
	tvbuff_t *tvb;
	guint	  subset_tvb_offset;
	guint	  subset_tvb_length;

	DISSECTOR_ASSERT(backing && backing->initialized);

	THROW_ON(backing_length < 0, ReportedBoundsError);

	/*
	 * Give the next dissector only captured_length bytes.
	 */
	captured_length = tvb_length_remaining(backing, backing_offset);
	THROW_ON(captured_length < 0, BoundsError);
	if (captured_length > backing_length)
		captured_length = backing_length;

	tvb_check_offset_length(backing, backing_offset, captured_length,
			        &subset_tvb_offset,
			        &subset_tvb_length);

	tvb = tvb_new_with_subset(backing, backing_length,
	    subset_tvb_offset, subset_tvb_length);

	tvb_add_to_chain(backing, tvb);

	return tvb;
}

tvbuff_t *
tvb_new_subset_remaining(tvbuff_t *backing, const gint backing_offset)
{
	tvbuff_t *tvb;
	guint	  subset_tvb_offset;
	guint	  subset_tvb_length;

	tvb_check_offset_length(backing, backing_offset, -1 /* backing_length */,
			        &subset_tvb_offset,
			        &subset_tvb_length);

	tvb = tvb_new_with_subset(backing, -1 /* reported_length */,
	    subset_tvb_offset, subset_tvb_length);

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
