/* tvbuff.c
 *
 * Testy, Virtual(-izable) Buffer of guint8*'s
 * 
 * "Testy" -- the buffer gets mad when an attempt to access data
 * 		beyond the bounds of the buffer. An exception is thrown.
 *
 * "Virtual" -- the buffer can have its own data, can use a subset of
 * 		the data of a backing tvbuff, or can be a composite of
 * 		other tvbuffs.
 *
 * $Id: tvbuff.c,v 1.4 2000/05/29 08:57:42 guy Exp $
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
#include "tvbuff.h"
#endif

#include <string.h>

/* Pointer versions of ntohs and ntohl.  Given a pointer to a member of a
 * byte array, returns the value of the two or four bytes at the pointer.
 * The pletoh[sl] versions return the little-endian representation.
 */

#define pntohs(p)  ((guint16)                       \
                    ((guint16)*((guint8 *)p+0)<<8|  \
                     (guint16)*((guint8 *)p+1)<<0))

#define pntohl(p)  ((guint32)*((guint8 *)p+0)<<24|  \
                    (guint32)*((guint8 *)p+1)<<16|  \
                    (guint32)*((guint8 *)p+2)<<8|   \
                    (guint32)*((guint8 *)p+3)<<0)

#define pntoh24(p) ((guint32)*((guint8 *)p+0)<<16|  \
                    (guint32)*((guint8 *)p+1)<<8|  \
                    (guint32)*((guint8 *)p+2)<<0)

#define pletohs(p) ((guint16)                       \
                    ((guint16)*((guint8 *)p+1)<<8|  \
                     (guint16)*((guint8 *)p+0)<<0))

#define pletohl(p) ((guint32)*((guint8 *)p+3)<<24|  \
                    (guint32)*((guint8 *)p+2)<<16|  \
                    (guint32)*((guint8 *)p+1)<<8|   \
                    (guint32)*((guint8 *)p+0)<<0)

#define pletoh24(p) ((guint32)*((guint8 *)p+2)<<16|  \
                     (guint32)*((guint8 *)p+1)<<8|  \
                     (guint32)*((guint8 *)p+0)<<0)


typedef struct {
	/* The backing tvbuff_t */
	tvbuff_t	*tvb;

	/* The offset/length of 'tvb' to which I'm privy */
	guint		offset;
	guint		length;

} tvb_backing_t;

typedef struct {
	GSList		*tvbs;

	/* Used for quick testing to see if this
	 * is the tvbuff that a COMPOSITE is
	 * interested in. */
	guint		*start_offsets;
	guint		*end_offsets;

} tvb_comp_t;

struct tvbuff {
	/* Record-keeping */
	tvbuff_type		type;
	gboolean		initialized;
	guint			usage_count;

	/* The tvbuffs in which this tvbuff is a member
	 * (that is, a backing tvbuff for a TVBUFF_SUBSET
	 * or a member for a TVB_COMPOSITE) */
	GSList			*used_in;

	/* TVBUFF_SUBSET and TVBUFF_COMPOSITE keep track
	 * of the other tvbuff's they use */
	union {
		tvb_backing_t	subset;
		tvb_comp_t	composite;
	} tvbuffs;

	/* We're either a TVBUFF_REAL_DATA or a
	 * TVBUFF_SUBSET that has a backing buffer that
	 * has real_data != NULL, or a TVBUFF_COMPOSITE
	 * which has flattened its data due to a call
	 * to tvb_get_ptr().
	 */
	guint8			*real_data;

	/* Length of virtual buffer (and/or real_data). */
	guint			length;

	/* Reported length. */
	guint			reported_length;

	/* Offset from beginning of first TVBUFF_REAL. */
	gint			raw_offset;

	/* Func to call when actually freed */
	tvbuff_free_cb_t	free_cb;
};

static guint8*
ensure_contiguous(tvbuff_t *tvb, gint offset, gint length);

/* We dole out tvbuff's from this memchunk. */
GMemChunk *tvbuff_mem_chunk = NULL;

void
tvbuff_init(void)
{
	if (!tvbuff_mem_chunk)
		tvbuff_mem_chunk = g_mem_chunk_create(tvbuff_t, 20, G_ALLOC_AND_FREE);
}

void
tvbuff_cleanup(void)
{
	if (tvbuff_mem_chunk)
		g_mem_chunk_destroy(tvbuff_mem_chunk);

	tvbuff_mem_chunk = NULL;
}




static void
tvb_init(tvbuff_t *tvb, tvbuff_type type)
{
	tvb_backing_t	*backing;
	tvb_comp_t	*composite;

	tvb->type		= type;
	tvb->initialized	= FALSE;
	tvb->usage_count	= 1;
	tvb->length		= 0;
	tvb->reported_length	= 0;
	tvb->free_cb		= NULL;
	tvb->real_data		= NULL;
	tvb->raw_offset		= -1;
	tvb->used_in		= NULL;

	switch(type) {
		case TVBUFF_REAL_DATA:
			/* Nothing */
			break;

		case TVBUFF_SUBSET:
			backing = &tvb->tvbuffs.subset;
			backing->tvb	= NULL;
			backing->offset	= 0;
			backing->length	= 0;
			break;

		case TVBUFF_COMPOSITE:
			composite = &tvb->tvbuffs.composite;
			composite->tvbs			= NULL;
			composite->start_offsets	= NULL;
			composite->end_offsets		= NULL;
			break;
	}
}


tvbuff_t*
tvb_new(tvbuff_type type)
{
	tvbuff_t	*tvb;

	tvb = g_chunk_new(tvbuff_t, tvbuff_mem_chunk);
	g_assert(tvb);

	tvb_init(tvb, type);

	return tvb;
}

void
tvb_free(tvbuff_t* tvb)
{
	tvbuff_t	*member_tvb;
	tvb_comp_t	*composite;
	GSList		*slist;

	tvb->usage_count--;

	if (tvb->usage_count == 0) {
		switch (tvb->type) {
		case TVBUFF_REAL_DATA:
			if (tvb->free_cb) {
				tvb->free_cb(tvb->real_data);
			}
			break;

		case TVBUFF_SUBSET:
			tvb_decrement_usage_count(tvb->tvbuffs.subset.tvb, 1);
			break;

		case TVBUFF_COMPOSITE:
			composite = &tvb->tvbuffs.composite;
			for (slist = composite->tvbs; slist != NULL ; slist = slist->next) {
				member_tvb = slist->data;
				tvb_decrement_usage_count(member_tvb, 1);
			}

			g_slist_free(composite->tvbs);

			if (composite->start_offsets)
				g_free(composite->start_offsets);
			if (composite->end_offsets)
				g_free(composite->end_offsets);
			if (tvb->real_data)
				g_free(tvb->real_data);

			break;
		}

		if (tvb->used_in) {
			g_slist_free(tvb->used_in);
		}

		g_chunk_free(tvb, tvbuff_mem_chunk);
	}
}

guint
tvb_increment_usage_count(tvbuff_t* tvb, guint count)
{
	tvb->usage_count += count;

	return tvb->usage_count;
}

guint
tvb_decrement_usage_count(tvbuff_t* tvb, guint count)
{
	if (tvb->usage_count <= count) {
		tvb->usage_count = 1;
		tvb_free(tvb);
		return 0;
	}
	else {
		tvb->usage_count -= count;
		return tvb->usage_count;
	}

}

void
tvb_free_chain(tvbuff_t* tvb)
{
	GSList		*slist;

	/* Recursively call tvb_free_chain() */
	for (slist = tvb->used_in; slist != NULL ; slist = slist->next) {
		tvb_free_chain( (tvbuff_t*)slist->data );
	}

	/* Stop the recursion */
	tvb_free(tvb);
}



void
tvb_set_free_cb(tvbuff_t* tvb, tvbuff_free_cb_t func)
{
	g_assert(tvb->type == TVBUFF_REAL_DATA);
	tvb->free_cb = func;
}

void
tvb_set_real_data(tvbuff_t* tvb, const guint8* data, guint length, gint reported_length)
{
	g_assert(tvb->type == TVBUFF_REAL_DATA);
	g_assert(!tvb->initialized);
	g_assert(reported_length >= -1);

	tvb->real_data		= (gpointer) data;
	tvb->length		= length;
	tvb->reported_length	= reported_length;
	tvb->initialized	= TRUE;
}

tvbuff_t*
tvb_new_real_data(const guint8* data, guint length, gint reported_length)
{
	tvbuff_t	*tvb;

	tvb = tvb_new(TVBUFF_REAL_DATA);
	tvb_set_real_data(tvb, data, length, reported_length);

	return tvb;
}

/* Computes the absolute offset and length based on a possibly-negative offset
 * and a length that is possible -1 (which means "to the end of the data").
 * Returns TRUE/FALSE indicating whether the offset is in bounds or
 * not. The integer ptrs are modified with the new offset and length.
 * No exception is thrown.
 *
 * XXX - we return TRUE, not FALSE, if the offset is positive and right
 * after the end of the tvbuff (i.e., equal to the length).  We do this
 * so that a dissector constructing a subset tvbuff for the next protocol
 * will get a zero-length tvbuff, not an exception, if there's no data
 * left for the next protocol - we want the next protocol to be the one
 * that gets an exception, so the error is reported as an error in that
 * protocol rather than the containing protocol.  */
static gboolean
compute_offset_length(tvbuff_t *tvb, gint offset, gint length,
		guint *offset_ptr, guint *length_ptr, int *exception)
{
	g_assert(offset_ptr);
	g_assert(length_ptr);

	/* Compute the offset */
	if (offset >= 0) {
		/* Positive offset - relative to the beginning of the packet. */
		if (offset > tvb->reported_length) {
			if (exception) {
				*exception = ReportedBoundsError;
			}
			return FALSE;
		}
		else if (offset > tvb->length) {
			if (exception) {
				*exception = BoundsError;
			}
			return FALSE;
		}
		else {
			*offset_ptr = offset;
		}
	}
	else {
		/* Negative offset - relative to the end of the packet. */
		if (-offset > tvb->reported_length) {
			if (exception) {
				*exception = ReportedBoundsError;
			}
			return FALSE;
		}
		else if (-offset > tvb->length) {
			if (exception) {
				*exception = BoundsError;
			}
			return FALSE;
		}
		else {
			*offset_ptr = tvb->length + offset;
		}
	}

	/* Compute the length */
	g_assert(length >= -1);
	if (length == -1) {
		*length_ptr = tvb->length - *offset_ptr;
	}
	else {
		*length_ptr = length;
	}

	return TRUE;
}


static gboolean
check_offset_length_no_exception(tvbuff_t *tvb, gint offset, gint length,
		guint *offset_ptr, guint *length_ptr, int *exception)
{
	g_assert(tvb->initialized);

	if (!compute_offset_length(tvb, offset, length, offset_ptr, length_ptr, exception)) {
		return FALSE;
	}

	if (*offset_ptr + *length_ptr <= tvb->length) {
		return TRUE;
	}
	else if (*offset_ptr + *length_ptr <= tvb->reported_length) {
		if (exception) {
			*exception = BoundsError;
		}
		return FALSE;
	}
	else {
		if (exception) {
			*exception = ReportedBoundsError;
		}
		return FALSE;
	}

	g_assert_not_reached();
}

/* Checks (+/-) offset and length and throws BoundsError if
 * either is out of bounds. Sets integer ptrs to the new offset
 * and length. */
static void
check_offset_length(tvbuff_t *tvb, gint offset, gint length,
		guint *offset_ptr, guint *length_ptr)
{
	int exception = 0;

	if (!check_offset_length_no_exception(tvb, offset, length, offset_ptr, length_ptr, &exception)) {
		g_assert(exception > 0);
		THROW(exception);
	}
	return;
}

static void
add_to_used_in_list(tvbuff_t *tvb, tvbuff_t *used_in)
{
	tvb->used_in = g_slist_prepend(tvb->used_in, used_in);
}

void
tvb_set_subset(tvbuff_t *tvb, tvbuff_t *backing,
		gint backing_offset, gint backing_length, gint reported_length)
{
	g_assert(tvb->type == TVBUFF_SUBSET);
	g_assert(!tvb->initialized);

	check_offset_length(backing, backing_offset, backing_length,
			&tvb->tvbuffs.subset.offset,
			&tvb->tvbuffs.subset.length);

	tvb_increment_usage_count(backing, 1);
	tvb->tvbuffs.subset.tvb		= backing;
	tvb->length			= tvb->tvbuffs.subset.length;
	g_assert(reported_length >= -1);
	if (reported_length == -1) {
		tvb->reported_length	= backing->reported_length - tvb->tvbuffs.subset.offset;
	}
	else {
		tvb->reported_length	= reported_length;
	}
	tvb->initialized		= TRUE;
	add_to_used_in_list(backing, tvb);

	/* Optimization. If the backing buffer has a pointer to contiguous, real data,
	 * then we can point directly to our starting offset in that buffer */
	if (backing->real_data != NULL) {
		tvb->real_data = backing->real_data + tvb->tvbuffs.subset.offset;
	}
}


tvbuff_t*
tvb_new_subset(tvbuff_t *backing, gint backing_offset, gint backing_length, gint reported_length)
{
	tvbuff_t	*tvb;

	tvb = tvb_new(TVBUFF_SUBSET);
	tvb_set_subset(tvb, backing, backing_offset, backing_length, reported_length);

	return tvb;
}

void
tvb_composite_append(tvbuff_t* tvb, tvbuff_t* member)
{
	tvb_comp_t	*composite;

	g_assert(!tvb->initialized);
	composite = &tvb->tvbuffs.composite;
	composite->tvbs = g_slist_append( composite->tvbs, member );
}

void
tvb_composite_prepend(tvbuff_t* tvb, tvbuff_t* member)
{
	tvb_comp_t	*composite;

	g_assert(!tvb->initialized);
	composite = &tvb->tvbuffs.composite;
	composite->tvbs = g_slist_prepend( composite->tvbs, member );
}

tvbuff_t*
tvb_new_composite(void)
{
	return tvb_new(TVBUFF_COMPOSITE);
}

void
tvb_composite_finalize(tvbuff_t* tvb)
{
	GSList		*slist;
	guint		num_members;
	tvbuff_t	*member_tvb;
	tvb_comp_t	*composite;
	int		i = 0;

	g_assert(!tvb->initialized);
	g_assert(tvb->length == 0);

	composite = &tvb->tvbuffs.composite;
	num_members = g_slist_length(composite->tvbs);

	composite->start_offsets = g_new(guint, num_members);
	composite->end_offsets = g_new(guint, num_members);

	for (slist = composite->tvbs; slist != NULL; slist = slist->next) {
		g_assert(i < num_members);
		member_tvb = slist->data;
		composite->start_offsets[i] = tvb->length;
		tvb->length += member_tvb->length;
		composite->end_offsets[i] = tvb->length - 1;
		i++;
	}

	tvb->initialized = TRUE;
}



guint
tvb_length(tvbuff_t* tvb)
{
	g_assert(tvb->initialized);

	return tvb->length;
}

guint
tvb_length_remaining(tvbuff_t *tvb, gint offset)
{
	guint	abs_offset, abs_length;

	g_assert(tvb->initialized);

	if (compute_offset_length(tvb, offset, -1, &abs_offset, &abs_length, NULL)) {
		return abs_length;
	}
	else {
		return -1;
	}
}



/* Validates that 'length' bytes are available starting from
 * offset (pos/neg). Does not throw BoundsError exception. */
gboolean
tvb_bytes_exist(tvbuff_t *tvb, gint offset, gint length)
{
	guint		abs_offset, abs_length;

	g_assert(tvb->initialized);

	if (!compute_offset_length(tvb, offset, length, &abs_offset, &abs_length, NULL))
		return FALSE;

	if (abs_offset + abs_length <= tvb->length) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

gboolean
tvb_offset_exists(tvbuff_t *tvb, gint offset)
{
	guint		abs_offset, abs_length;

	g_assert(tvb->initialized);
	if (!compute_offset_length(tvb, offset, -1, &abs_offset, &abs_length, NULL))
		return FALSE;

	if (abs_offset < tvb->length) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

guint
tvb_reported_length(tvbuff_t* tvb)
{
	g_assert(tvb->initialized);

	return tvb->reported_length;
}




guint8*
first_real_data_ptr(tvbuff_t *tvb)
{
	tvbuff_t	*member;

	switch(tvb->type) {
		case TVBUFF_REAL_DATA:
			return tvb->real_data;
		case TVBUFF_SUBSET:
			member = tvb->tvbuffs.subset.tvb;
			return first_real_data_ptr(member);
		case TVBUFF_COMPOSITE:
			member = tvb->tvbuffs.composite.tvbs->data;
			return first_real_data_ptr(member);
	}

	g_assert_not_reached();
	return NULL;
}

int
offset_from_real_beginning(tvbuff_t *tvb, int counter)
{
	tvbuff_t	*member;

	switch(tvb->type) {
		case TVBUFF_REAL_DATA:
			return counter;
		case TVBUFF_SUBSET:
			member = tvb->tvbuffs.subset.tvb;
			return offset_from_real_beginning(member, counter + tvb->tvbuffs.subset.offset);
		case TVBUFF_COMPOSITE:
			member = tvb->tvbuffs.composite.tvbs->data;
			return offset_from_real_beginning(member, counter);
	}

	g_assert_not_reached();
	return 0;
}

gint
tvb_raw_offset(tvbuff_t *tvb)
{
	if (tvb->raw_offset == -1) {
		tvb->raw_offset = offset_from_real_beginning(tvb, 0);
	}
	return tvb->raw_offset;
}

void
tvb_compat(tvbuff_t *tvb, const guint8 **pd, int *offset)
{
	g_assert(tvb->initialized);
	*pd = first_real_data_ptr(tvb);
	*offset = tvb_raw_offset(tvb);
}


static guint8*
composite_ensure_contiguous(tvbuff_t *tvb, guint abs_offset, guint abs_length)
{
	guint		i, num_members;
	tvb_comp_t	*composite;
	tvbuff_t	*member_tvb = NULL;
	guint		member_offset, member_length;
	GSList		*slist;

	g_assert(tvb->type == TVBUFF_COMPOSITE);

	/* Maybe the range specified by offset/length
	 * is contiguous inside one of the member tvbuffs */
	composite = &tvb->tvbuffs.composite;
	num_members = g_slist_length(composite->tvbs);

	for (i = 0; i < num_members; i++) {
		if (abs_offset <= composite->end_offsets[i]) {
			slist = g_slist_nth(composite->tvbs, i);
			member_tvb = slist->data;
			break;
		}
	}
	g_assert(member_tvb);

	if (check_offset_length_no_exception(member_tvb, abs_offset - composite->start_offsets[i],
				abs_length, &member_offset, &member_length, NULL)) {

		g_assert(!tvb->real_data);
		return ensure_contiguous(member_tvb, member_offset, member_length);
	}
	else {
		tvb->real_data = tvb_memdup(tvb, 0, -1);
		return tvb->real_data + abs_offset;
	}

	g_assert_not_reached();
	return NULL;
}

static guint8*
ensure_contiguous(tvbuff_t *tvb, gint offset, gint length)
{
	guint	abs_offset, abs_length;

	check_offset_length(tvb, offset, length, &abs_offset, &abs_length);

	if (tvb->real_data) {
		return tvb->real_data + abs_offset;
	}
	else {
		switch(tvb->type) {
			case TVBUFF_REAL_DATA:
				g_assert_not_reached();
			case TVBUFF_SUBSET:
				return ensure_contiguous(tvb->tvbuffs.subset.tvb,
						abs_offset - tvb->tvbuffs.subset.offset,
						abs_length);
			case TVBUFF_COMPOSITE:
				return composite_ensure_contiguous(tvb, abs_offset, abs_length);
		}
	}

	g_assert_not_reached();
	return NULL;
}


/************** ACCESSORS **************/

static guint8*
composite_memcpy(tvbuff_t *tvb, guint8* target, guint abs_offset, guint abs_length)
{
	guint		i, num_members;
	tvb_comp_t	*composite;
	tvbuff_t	*member_tvb = NULL;
	guint		member_offset, member_length;
	gboolean	retval;
	GSList		*slist;

	g_assert(tvb->type == TVBUFF_COMPOSITE);

	/* Maybe the range specified by offset/length
	 * is contiguous inside one of the member tvbuffs */
	composite = &tvb->tvbuffs.composite;
	num_members = g_slist_length(composite->tvbs);

	for (i = 0; i < num_members; i++) {
		if (abs_offset <= composite->end_offsets[i]) {
			slist = g_slist_nth(composite->tvbs, i);
			member_tvb = slist->data;
			break;
		}
	}
	g_assert(member_tvb);

	if (check_offset_length_no_exception(member_tvb, abs_offset - composite->start_offsets[i],
				abs_length, &member_offset, &member_length, NULL)) {

		g_assert(!tvb->real_data);
		return tvb_memcpy(member_tvb, target, member_offset, member_length);
	}
	else {
		/* The requested data is non-contiguous inside
		 * the member tvb. We have to memcpy() the part that's in the member tvb,
		 * then iterate across the other member tvb's, copying their portions
		 * until we have copied all data.
		 */
		retval = compute_offset_length(member_tvb, abs_offset - composite->start_offsets[i], -1,
				&member_offset, &member_length, NULL);
		g_assert(retval);

		tvb_memcpy(member_tvb, target, member_offset, member_length);
		abs_offset	+= member_length;
		abs_length	-= member_length;

		/* Recurse */
		if (abs_length > 0) {
			composite_memcpy(tvb, target + member_length, abs_offset, abs_length);
		}

		return target;
	}

	g_assert_not_reached();
	return NULL;
}

guint8*
tvb_memcpy(tvbuff_t *tvb, guint8* target, gint offset, gint length)
{
	guint	abs_offset, abs_length;

	check_offset_length(tvb, offset, length, &abs_offset, &abs_length);

	if (tvb->real_data) {
		return (guint8*) memcpy(target, tvb->real_data + abs_offset, abs_length);
	}

	switch(tvb->type) {
		case TVBUFF_REAL_DATA:
			g_assert_not_reached();

		case TVBUFF_SUBSET:
			return tvb_memcpy(tvb->tvbuffs.subset.tvb, target,
					abs_offset - tvb->tvbuffs.subset.offset,
					abs_length);

		case TVBUFF_COMPOSITE:
			return composite_memcpy(tvb, target, offset, length);
	}

	g_assert_not_reached();
	return NULL;
}


guint8*
tvb_memdup(tvbuff_t *tvb, gint offset, gint length)
{
	guint	abs_offset, abs_length;
	guint8	*duped;

	check_offset_length(tvb, offset, length, &abs_offset, &abs_length);

	duped = g_malloc(abs_length);
	return tvb_memcpy(tvb, duped, abs_offset, abs_length);
}


	
guint8*
tvb_get_ptr(tvbuff_t *tvb, gint offset, gint length)
{
	return ensure_contiguous(tvb, offset, length);
}

guint8
tvb_get_guint8(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, sizeof(guint8));
	return *ptr;
}

guint16
tvb_get_ntohs(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, sizeof(guint16));
	return pntohs(ptr);
}

guint32
tvb_get_ntohl(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, sizeof(guint32));
	return pntohl(ptr);
}

guint32
tvb_get_ntoh24(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, 3);
	return pntoh24(ptr);
}

guint16
tvb_get_letohs(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, sizeof(guint16));
	return pletohs(ptr);
}

guint32
tvb_get_letohl(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, sizeof(guint32));
	return pletohl(ptr);
}

guint32
tvb_get_letoh24(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, 3);
	return pletoh24(ptr);
}
