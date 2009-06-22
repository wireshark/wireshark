/*
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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

/* The ideas in this code came from Ed Warnicke's original implementation
 * of dranges for the old display filter code (Ethereal 0.8.15 and before).
 * The code is different, but definitely inspired by his code.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/proto.h>
#include "drange.h"
#include "sttype-range.h"

typedef struct {
	guint32			magic;
	header_field_info	*hfinfo;
	drange			*drange;
} range_t;

#define RANGE_MAGIC	0xec0990ce

static gpointer
range_new(gpointer junk)
{
	range_t		*range;

	g_assert(junk == NULL);

	range = g_new(range_t, 1);

	range->magic = RANGE_MAGIC;
	range->hfinfo = NULL;
	range->drange = NULL;

	return (gpointer) range;
}

static void
range_free(gpointer value)
{
	range_t	*range = value;
	assert_magic(range, RANGE_MAGIC);

	if (range->drange)
		drange_free(range->drange);

	g_free(range);
}

void
sttype_range_remove_drange(stnode_t *node)
{
	range_t		*range;

	range = stnode_data(node);
	assert_magic(range, RANGE_MAGIC);

	range->drange = NULL;
}


/* Set a range */
void
sttype_range_set(stnode_t *node, stnode_t *field, GSList* drange_list)
{
	range_t		*range;

	range = stnode_data(node);
	assert_magic(range, RANGE_MAGIC);

	range->hfinfo = stnode_data(field);
	stnode_free(field);

	range->drange = drange_new_from_list(drange_list);
}

void
sttype_range_set1(stnode_t *node, stnode_t *field, drange_node *rn)
{
	sttype_range_set(node, field, g_slist_append(NULL, rn));
}

STTYPE_ACCESSOR(header_field_info*, range, hfinfo, RANGE_MAGIC)
STTYPE_ACCESSOR(drange*, range, drange, RANGE_MAGIC)


void
sttype_register_range(void)
{
	static sttype_t range_type = {
		STTYPE_RANGE,
		"RANGE",
		range_new,
		range_free,
	};

	sttype_register(&range_type);
}
