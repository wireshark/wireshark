/* tvbuff_composite.c
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

#include "tvbuff.h"
#include "tvbuff-int.h"
#include "proto.h"	/* XXX - only used for DISSECTOR_ASSERT, probably a new header file? */

typedef struct {
	GSList		*tvbs;

	/* Used for quick testing to see if this
	 * is the tvbuff that a COMPOSITE is
	 * interested in. */
	guint		*start_offsets;
	guint		*end_offsets;

} tvb_comp_t;

struct tvb_composite {
	struct tvbuff tvb;

	tvb_comp_t	composite;
};

static void
composite_free(tvbuff_t *tvb)
{
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;
	tvb_comp_t *composite = &composite_tvb->composite;

	g_slist_free(composite->tvbs);

	g_free(composite->start_offsets);
	g_free(composite->end_offsets);
	if (tvb->real_data) {
		/*
		 * XXX - do this with a union?
		 */
		g_free((gpointer)tvb->real_data);
	}
}

static guint
composite_offset(const tvbuff_t *tvb, const guint counter)
{
	const struct tvb_composite *composite_tvb = (const struct tvb_composite *) tvb;
	const tvbuff_t *member = (const tvbuff_t *)composite_tvb->composite.tvbs->data;

	return tvb_offset_from_real_beginning_counter(member, counter);
}

static const guint8*
composite_get_ptr(tvbuff_t *tvb, guint abs_offset, guint abs_length)
{
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;
	guint	    i, num_members;
	tvb_comp_t *composite;
	tvbuff_t   *member_tvb = NULL;
	guint	    member_offset;
	GSList	   *slist;

	/* DISSECTOR_ASSERT(tvb->ops == &tvb_composite_ops); */

	/* Maybe the range specified by offset/length
	 * is contiguous inside one of the member tvbuffs */
	composite = &composite_tvb->composite;
	num_members = g_slist_length(composite->tvbs);

	for (i = 0; i < num_members; i++) {
		if (abs_offset <= composite->end_offsets[i]) {
			slist = g_slist_nth(composite->tvbs, i);
			member_tvb = (tvbuff_t *)slist->data;
			break;
		}
	}

	/* special case */
	if (!member_tvb) {
		DISSECTOR_ASSERT(abs_offset == tvb->length && abs_length == 0);
		return "";
	}

	member_offset = abs_offset - composite->start_offsets[i];

	if (tvb_bytes_exist(member_tvb, member_offset, abs_length)) {
		/*
		 * The range is, in fact, contiguous within member_tvb.
		 */
		DISSECTOR_ASSERT(!tvb->real_data);
		return tvb_get_ptr(member_tvb, member_offset, abs_length);
	}
	else {
		/* Use a temporary variable as tvb_memcpy is also checking tvb->real_data pointer */
		void *real_data = g_malloc(tvb->length);
		tvb_memcpy(tvb, real_data, 0, tvb->length);
		tvb->real_data = (const guint8 *)real_data;
		return tvb->real_data + abs_offset;
	}

	DISSECTOR_ASSERT_NOT_REACHED();
}

static void *
composite_memcpy(tvbuff_t *tvb, void* _target, guint abs_offset, guint abs_length)
{
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;
	guint8 *target = (guint8 *) _target;

	guint	    i, num_members;
	tvb_comp_t *composite;
	tvbuff_t   *member_tvb = NULL;
	guint	    member_offset, member_length;
	GSList	   *slist;

	/* DISSECTOR_ASSERT(tvb->ops == &tvb_composite_ops); */

	/* Maybe the range specified by offset/length
	 * is contiguous inside one of the member tvbuffs */
	composite   = &composite_tvb->composite;
	num_members = g_slist_length(composite->tvbs);

	for (i = 0; i < num_members; i++) {
		if (abs_offset <= composite->end_offsets[i]) {
			slist = g_slist_nth(composite->tvbs, i);
			member_tvb = (tvbuff_t *)slist->data;
			break;
		}
	}

	/* special case */
	if (!member_tvb) {
		DISSECTOR_ASSERT(abs_offset == tvb->length && abs_length == 0);
		return target;
	}

	member_offset = abs_offset - composite->start_offsets[i];

	if (tvb_bytes_exist(member_tvb, member_offset, abs_length)) {
		DISSECTOR_ASSERT(!tvb->real_data);
		return tvb_memcpy(member_tvb, target, member_offset, abs_length);
	}
	else {
		/* The requested data is non-contiguous inside
		 * the member tvb. We have to memcpy() the part that's in the member tvb,
		 * then iterate across the other member tvb's, copying their portions
		 * until we have copied all data.
		 */
		member_length = tvb_captured_length_remaining(member_tvb, member_offset);

		/* composite_memcpy() can't handle a member_length of zero. */
		DISSECTOR_ASSERT(member_length > 0);

		tvb_memcpy(member_tvb, target, member_offset, member_length);
		abs_offset	+= member_length;
		abs_length	-= member_length;

		/* Recurse */
		if (abs_length > 0) {
			composite_memcpy(tvb, target + member_length, abs_offset, abs_length);
		}

		return target;
	}

	DISSECTOR_ASSERT_NOT_REACHED();
}

static const struct tvb_ops tvb_composite_ops = {
	sizeof(struct tvb_composite), /* size */

	composite_free,       /* free */
	composite_offset,     /* offset */
	composite_get_ptr,    /* get_ptr */
	composite_memcpy,     /* memcpy */
	NULL,                 /* find_guint8 XXX */
	NULL,                 /* pbrk_guint8 XXX */
	NULL,                 /* clone */
};

/*
 * Composite tvb
 *
 *   1. A composite tvb is automatically chained to its first member when the
 *      tvb is finalized.
 *      This means that composite tvb members must all be in the same chain.
 *      ToDo: enforce this: By searching the chain?
 */
tvbuff_t *
tvb_new_composite(void)
{
	tvbuff_t *tvb = tvb_new(&tvb_composite_ops);
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;
	tvb_comp_t *composite = &composite_tvb->composite;

	composite->tvbs		 = NULL;
	composite->start_offsets = NULL;
	composite->end_offsets	 = NULL;

	return tvb;
}

void
tvb_composite_append(tvbuff_t *tvb, tvbuff_t *member)
{
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;
	tvb_comp_t *composite;

	DISSECTOR_ASSERT(tvb && !tvb->initialized);
	DISSECTOR_ASSERT(tvb->ops == &tvb_composite_ops);

	/* Don't allow zero-length TVBs: composite_memcpy() can't handle them
	 * and anyway it makes no sense.
	 */
	DISSECTOR_ASSERT(member->length);

	composite       = &composite_tvb->composite;
	composite->tvbs = g_slist_append(composite->tvbs, member);
}

void
tvb_composite_prepend(tvbuff_t *tvb, tvbuff_t *member)
{
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;
	tvb_comp_t *composite;

	DISSECTOR_ASSERT(tvb && !tvb->initialized);
	DISSECTOR_ASSERT(tvb->ops == &tvb_composite_ops);

	/* Don't allow zero-length TVBs: composite_memcpy() can't handle them
	 * and anyway it makes no sense.
	 */
	DISSECTOR_ASSERT(member->length);

	composite       = &composite_tvb->composite;
	composite->tvbs = g_slist_prepend(composite->tvbs, member);
}

void
tvb_composite_finalize(tvbuff_t *tvb)
{
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;
	GSList	   *slist;
	guint	    num_members;
	tvbuff_t   *member_tvb;
	tvb_comp_t *composite;
	int	    i = 0;

	DISSECTOR_ASSERT(tvb && !tvb->initialized);
	DISSECTOR_ASSERT(tvb->ops == &tvb_composite_ops);
	DISSECTOR_ASSERT(tvb->length == 0);
	DISSECTOR_ASSERT(tvb->reported_length == 0);

	composite   = &composite_tvb->composite;
	num_members = g_slist_length(composite->tvbs);

	/* Dissectors should not create composite TVBs if they're not going to
	 * put at least one TVB in them.
	 * (Without this check--or something similar--we'll seg-fault below.)
	 */
	DISSECTOR_ASSERT(num_members);

	composite->start_offsets = g_new(guint, num_members);
	composite->end_offsets = g_new(guint, num_members);

	for (slist = composite->tvbs; slist != NULL; slist = slist->next) {
		DISSECTOR_ASSERT((guint) i < num_members);
		member_tvb = (tvbuff_t *)slist->data;
		composite->start_offsets[i] = tvb->length;
		tvb->length += member_tvb->length;
		tvb->reported_length += member_tvb->reported_length;
		composite->end_offsets[i] = tvb->length - 1;
		i++;
	}

	DISSECTOR_ASSERT(composite->tvbs);

	tvb_add_to_chain((tvbuff_t *)composite->tvbs->data, tvb); /* chain composite tvb to first member */
	tvb->initialized = TRUE;
	tvb->ds_tvb = tvb;
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
