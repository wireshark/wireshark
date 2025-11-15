/* tvbuff_composite.c
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

typedef struct {
	tvbuff_t *tvb;
	/* Used for quick testing to see if this
	 * is the tvbuff that a COMPOSITE is
	 * interested in. */
	unsigned start_offset;
	unsigned end_offset;
} tvb_comp_member_t;

static int
tvb_comp_off_compare(const void *a, const void *b, void *user_data)
{
	tvb_comp_member_t* off_a = (tvb_comp_member_t*)a;
	tvb_comp_member_t* off_b = (tvb_comp_member_t*)b;
	tvb_comp_member_t* key = (tvb_comp_member_t*)user_data;

	if (off_a->end_offset < off_b->end_offset)
		return -1;
	else if (off_a->end_offset > off_b->end_offset)
		return 1;

	/* This is a hack to ensure that in cases of ties, key is always
	 * sorted first. This ensures that g_sequence_search returns an
	 * iterator pointing to the tvb in the sequence with a matching
	 * offset instead of the node after it. (It would be simpler but
	 * somewhat slower to have the natural comparison function and
	 * call g_sequence_lookup followed by g_sequence_search in case
	 * of failure.)
	 *
	 * If we allowed zero length TVBs to be part of the composite,
	 * we might have to search through all the TVBs with the same
	 * end_offset to find the right one. (Or maybe we could just
	 * no-op and not add the zero length TVBs?)
	 */
	if (off_a == key) {
		return -1;
	} else if (off_b == key) {
		return 1;
	}
	return 0;
}

typedef struct {
	GSequence	*tvbs;

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

	g_sequence_free(composite->tvbs);

	g_free((void *)tvb->real_data);
}

static unsigned
composite_offset(const tvbuff_t *tvb _U_, const unsigned counter)
{
	return counter;
}

static const uint8_t*
composite_get_ptr(tvbuff_t *tvb, unsigned abs_offset, unsigned abs_length)
{
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;
	tvb_comp_t *composite;
	tvb_comp_member_t *member = NULL;
	tvbuff_t   *member_tvb = NULL;
	unsigned	member_offset;

	/* DISSECTOR_ASSERT(tvb->ops == &tvb_composite_ops); */

	/* Maybe the range specified by offset/length
	 * is contiguous inside one of the member tvbuffs */
	composite = &composite_tvb->composite;

	tvb_comp_member_t key = { .end_offset = abs_offset };
	GSequenceIter *iter = g_sequence_search(composite->tvbs, &key, tvb_comp_off_compare, &key);

	/* special case */
	if (g_sequence_iter_is_end(iter)) {
		DISSECTOR_ASSERT(abs_offset == tvb->length && abs_length == 0);
		return "";
	}

	member = (tvb_comp_member_t *)g_sequence_get(iter);
	member_tvb = member->tvb;
	member_offset = abs_offset - member->start_offset;

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
		tvb->real_data = (const uint8_t *)real_data;
		return tvb->real_data + abs_offset;
	}

	DISSECTOR_ASSERT_NOT_REACHED();
}

static void *
composite_memcpy(tvbuff_t *tvb, void* _target, unsigned abs_offset, unsigned abs_length)
{
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;
	uint8_t *target = (uint8_t *) _target;

	tvb_comp_t *composite;
	tvb_comp_member_t *member = NULL;
	tvbuff_t   *member_tvb = NULL;
	unsigned	    member_offset, member_length;

	/* DISSECTOR_ASSERT(tvb->ops == &tvb_composite_ops); */

	/* Maybe the range specified by offset/length
	 * is contiguous inside one of the member tvbuffs */
	composite   = &composite_tvb->composite;

	tvb_comp_member_t key = { .end_offset = abs_offset };
	GSequenceIter *iter = g_sequence_search(composite->tvbs, &key, tvb_comp_off_compare, &key);

	/* special case */
	if (g_sequence_iter_is_end(iter)) {
		DISSECTOR_ASSERT(abs_offset == tvb->length && abs_length == 0);
		return target;
	}

	member = (tvb_comp_member_t *)g_sequence_get(iter);
	member_tvb = member->tvb;
	member_offset = abs_offset - member->start_offset;

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

		unsigned target_offset = 0;
		while (abs_length) {

			member_length = tvb_captured_length_remaining(member_tvb, member_offset);

			/* composite_memcpy() can't handle a member_length of zero. */
			DISSECTOR_ASSERT(member_length > 0);

			member_length = MIN(member_length, abs_length);

			tvb_memcpy(member_tvb, target + target_offset, member_offset, member_length);
			target_offset   += member_length;
			abs_offset	+= member_length;
			abs_length	-= member_length;

			if (!abs_length)
				break;
			iter = g_sequence_iter_next(iter);
			/* tvb_memcpy calls check_offset_length and so there
			 * should be enough captured length to copy. */
			DISSECTOR_ASSERT(!g_sequence_iter_is_end(iter));

			member = (tvb_comp_member_t *)g_sequence_get(iter);
			member_tvb = member->tvb;
			member_offset = 0;
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
	NULL,                 /* find_uint8 XXX */
	NULL,                 /* pbrk_uint8 XXX */
	NULL,                 /* clone */
};

/*
 * Composite tvb
 *
 * A composite TVB references the concatenation of one or more TVBs, each of
 * them MUST be part of the same chain (the same memory "scope"). The
 * caller of tvb_new_composite MUST immediately call tvb_composite_append or
 * tvb_composite_prepend to ensure that the composite TVB is properly freed as
 * needed.
 *
 * Failure to satisfy the same chain requirement can result in memory-safety
 * issues such as use-after-free or double-free.
 */
tvbuff_t *
tvb_new_composite(void)
{
	tvbuff_t *tvb = tvb_new(&tvb_composite_ops);
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;
	tvb_comp_t *composite = &composite_tvb->composite;

	composite->tvbs		 = g_sequence_new(g_free);

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
	if (member && member->length) {
		composite       = &composite_tvb->composite;
		/* Attach the composite TVB to the first TVB only. */
		if (g_sequence_is_empty(composite->tvbs)) {
			tvb_add_to_chain(member, tvb);
		}
		tvb_comp_member_t *new_member = g_new(tvb_comp_member_t, 1);
		new_member->tvb = member;
		new_member->start_offset = 0;
		new_member->end_offset = 0;
		g_sequence_append(composite->tvbs, new_member);
	}
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
	if (member && member->length) {
		composite       = &composite_tvb->composite;
		/* Attach the composite TVB to the first TVB only. */
		if (g_sequence_is_empty(composite->tvbs)) {
			tvb_add_to_chain(member, tvb);
		}
		tvb_comp_member_t *new_member = g_new(tvb_comp_member_t, 1);
		new_member->tvb = member;
		new_member->start_offset = 0;
		new_member->end_offset = 0;
		g_sequence_prepend(composite->tvbs, new_member);
	}
}

void
tvb_composite_finalize(tvbuff_t *tvb)
{
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;

	unsigned	num_members;
	tvb_comp_member_t *member;
	tvbuff_t   *member_tvb;
	tvb_comp_t *composite;
	unsigned	i;

	DISSECTOR_ASSERT(tvb && !tvb->initialized);
	DISSECTOR_ASSERT(tvb->ops == &tvb_composite_ops);
	DISSECTOR_ASSERT(tvb->length == 0);
	DISSECTOR_ASSERT(tvb->reported_length == 0);
	DISSECTOR_ASSERT(tvb->contained_length == 0);

	composite   = &composite_tvb->composite;

	num_members = g_sequence_get_length(composite->tvbs);

	/* Dissectors should not create composite TVBs if they're not going to
	 * put at least one TVB in them.
	 * (Without this check--or something similar--we'll seg-fault below.)
	 * (XXX - Now with a GSequence we shouldn't segfault, we'll get the
	 * end iterator and it should work, so we could remove this and some
	 * checks in dissectors to simplify their code.)
	 */
	DISSECTOR_ASSERT(num_members);

	/* Record the offsets - we have to do that now because it's possible
	 * to prepend TVBs. Note that the GSequence is already sorted according
	 * to these offsets, we're just noting them, so we don't need to sort.
	 */
	GSequenceIter *iter = g_sequence_get_begin_iter(composite->tvbs);
	for (i=0; i < num_members; i++, iter=g_sequence_iter_next(iter)) {
		member = (tvb_comp_member_t *)g_sequence_get(iter);
		member_tvb = member->tvb;
		member->start_offset = tvb->length;
		tvb->length += member_tvb->length;
		/* XXX - What does it mean to make a composite TVB out of
		 * TVBs with length shorter than their reported length?
		 */
		tvb->reported_length += member_tvb->reported_length;
		tvb->contained_length += member_tvb->contained_length;
		member->end_offset = tvb->length - 1;
	}

	tvb->initialized = true;
	tvb->ds_tvb = tvb;
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
