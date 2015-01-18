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

#include "tvbuff.h"
#include "tvbuff-int.h"
#include "proto.h"	/* XXX - only used for DISSECTOR_ASSERT, probably a new header file? */
#include "exceptions.h"

struct tvb_real {
	struct tvbuff tvb;

	/** Func to call when actually freed */
	tvbuff_free_cb_t	free_cb;
};

static void
real_free(tvbuff_t *tvb)
{
	struct tvb_real *real_tvb = (struct tvb_real *) tvb;

	if (real_tvb->free_cb) {
		/*
		 * XXX - do this with a union?
		 */
		real_tvb->free_cb((gpointer)tvb->real_data);
	}
}

static guint
real_offset(const tvbuff_t *tvb _U_, const guint counter)
{
	return counter;
}

static const struct tvb_ops tvb_real_ops = {
	sizeof(struct tvb_real), /* size */

	real_free,            /* free */
	real_offset,          /* offset */
	NULL,                 /* get_ptr */
	NULL,                 /* memcpy */
	NULL,                 /* find_guint8 */
	NULL,                 /* pbrk_guint8 */
	NULL,                 /* clone */
};

tvbuff_t *
tvb_new_real_data(const guint8* data, const guint length, const gint reported_length)
{
	tvbuff_t *tvb;
	struct tvb_real *real_tvb;

	THROW_ON(reported_length < -1, ReportedBoundsError);

	tvb = tvb_new(&tvb_real_ops);

	tvb->real_data       = data;
	tvb->length          = length;
	tvb->reported_length = reported_length;
	tvb->initialized     = TRUE;

	/*
	 * This is the top-level real tvbuff for this data source,
	 * so its data source tvbuff is itself.
	 */
	tvb->ds_tvb = tvb;

	real_tvb = (struct tvb_real *) tvb;
	real_tvb->free_cb = NULL;

	return tvb;
}

void
tvb_set_free_cb(tvbuff_t *tvb, const tvbuff_free_cb_t func)
{
	struct tvb_real *real_tvb = (struct tvb_real *) tvb;

	DISSECTOR_ASSERT(tvb);
	DISSECTOR_ASSERT(tvb->ops == &tvb_real_ops);
	real_tvb->free_cb = func;
}

void
tvb_set_child_real_data_tvbuff(tvbuff_t *parent, tvbuff_t *child)
{
	DISSECTOR_ASSERT(parent && child);
	DISSECTOR_ASSERT(parent->initialized);
	DISSECTOR_ASSERT(child->initialized);
	DISSECTOR_ASSERT(child->ops == &tvb_real_ops);
	tvb_add_to_chain(parent, child);
}

tvbuff_t *
tvb_new_child_real_data(tvbuff_t *parent, const guint8* data, const guint length, const gint reported_length)
{
	tvbuff_t *tvb = tvb_new_real_data(data, length, reported_length);

	tvb_set_child_real_data_tvbuff(parent, tvb);

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
