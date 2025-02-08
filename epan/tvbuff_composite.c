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
	GQueue		*tvbs;

	/* Used for quick testing to see if this
	 * is the tvbuff that a COMPOSITE is
	 * interested in. */
	unsigned		*start_offsets;
	unsigned		*end_offsets;

	unsigned	recursion_depth;

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

	g_queue_free(composite->tvbs);

	g_free(composite->start_offsets);
	g_free(composite->end_offsets);
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
	unsigned	    i;
	tvb_comp_t *composite;
	tvbuff_t   *member_tvb = NULL;
	unsigned	member_offset;

	/* DISSECTOR_ASSERT(tvb->ops == &tvb_composite_ops); */

	/* Maybe the range specified by offset/length
	 * is contiguous inside one of the member tvbuffs */
	composite = &composite_tvb->composite;
	GList *item = (GList*)composite->tvbs->head;


	for (i = 0; i < g_queue_get_length(composite->tvbs); i++, item=item->next) {
		if (abs_offset <= composite->end_offsets[i]) {
			member_tvb = (tvbuff_t *)item->data;
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
		tvb->real_data = (const uint8_t *)real_data;
		return tvb->real_data + abs_offset;
	}

	DISSECTOR_ASSERT_NOT_REACHED();
}

#define MAX_RECURSION_DEPTH 500 // Arbitrary; matches prefs.gui_max_tree_depth
static void *
// NOLINTNEXTLINE(misc-no-recursion)
composite_memcpy(tvbuff_t *tvb, void* _target, unsigned abs_offset, unsigned abs_length)
{
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;
	uint8_t *target = (uint8_t *) _target;

	unsigned	    i;
	tvb_comp_t *composite;
	tvbuff_t   *member_tvb = NULL;
	unsigned	    member_offset, member_length;

	/* DISSECTOR_ASSERT(tvb->ops == &tvb_composite_ops); */

	/* Maybe the range specified by offset/length
	 * is contiguous inside one of the member tvbuffs */
	composite   = &composite_tvb->composite;

	GList *item = (GList*)composite->tvbs->head;
	for (i = 0; i < g_queue_get_length(composite->tvbs); i++, item=item->next) {
		if (abs_offset <= composite->end_offsets[i]) {
			member_tvb = (tvbuff_t *)item->data;
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
		/* make sure we don't underflow below */
		DISSECTOR_ASSERT(member_length <= abs_length);

		tvb_memcpy(member_tvb, target, member_offset, member_length);
		abs_offset	+= member_length;
		abs_length	-= member_length;

		/* Recurse */
		if (abs_length > 0) {
			composite->recursion_depth++;
			DISSECTOR_ASSERT(composite->recursion_depth < MAX_RECURSION_DEPTH);
			composite_memcpy(tvb, target + member_length, abs_offset, abs_length);
			composite->recursion_depth--;
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

	composite->tvbs		 = g_queue_new();
	composite->start_offsets = NULL;
	composite->end_offsets	 = NULL;
	composite->recursion_depth = 0;

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
		g_queue_push_tail(composite->tvbs, member);

		/* Attach the composite TVB to the first TVB only. */
		if (g_queue_get_length(composite->tvbs) == 1) {
			tvb_add_to_chain((tvbuff_t *)g_queue_peek_head(composite->tvbs), tvb);
		}
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
		g_queue_push_head(composite->tvbs, member);

		/* Attach the composite TVB to the first TVB only. */
		if (g_queue_get_length(composite->tvbs) == 1) {
			tvb_add_to_chain((tvbuff_t *)g_queue_peek_head(composite->tvbs), tvb);
		}
	}
}

void
tvb_composite_finalize(tvbuff_t *tvb)
{
	struct tvb_composite *composite_tvb = (struct tvb_composite *) tvb;

	unsigned	num_members;
	tvbuff_t   *member_tvb;
	tvb_comp_t *composite;
	unsigned	i;

	DISSECTOR_ASSERT(tvb && !tvb->initialized);
	DISSECTOR_ASSERT(tvb->ops == &tvb_composite_ops);
	DISSECTOR_ASSERT(tvb->length == 0);
	DISSECTOR_ASSERT(tvb->reported_length == 0);
	DISSECTOR_ASSERT(tvb->contained_length == 0);

	composite   = &composite_tvb->composite;

	num_members = g_queue_get_length(composite->tvbs);

	/* Dissectors should not create composite TVBs if they're not going to
	 * put at least one TVB in them.
	 * (Without this check--or something similar--we'll seg-fault below.)
	 */
	DISSECTOR_ASSERT(num_members);

	composite->start_offsets = g_new(unsigned, num_members);
	composite->end_offsets = g_new(unsigned, num_members);

	GList *item = (GList*)composite->tvbs->head;
	for (i=0; i < num_members; i++, item=item->next) {
		member_tvb = (tvbuff_t *)item->data;
		composite->start_offsets[i] = tvb->length;
		tvb->length += member_tvb->length;
		tvb->reported_length += member_tvb->reported_length;
		tvb->contained_length += member_tvb->contained_length;
		composite->end_offsets[i] = tvb->length - 1;
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
