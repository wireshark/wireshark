/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* The ideas in this code came from Ed Warnicke's original implementation
 * of dranges for the old display filter code (Ethereal 0.8.15 and before).
 * The code is different, but definitely inspired by his code.
 */

#include "config.h"

#include <glib.h>

#include <epan/proto.h>
#include "drange.h"
#include "sttype-range.h"

typedef struct {
	guint32	   magic;
	stnode_t  *entity;
	drange_t  *drange;
} range_t;

#define RANGE_MAGIC	0xec0990ce

static gpointer
range_new(gpointer junk)
{
	range_t		*range;

	g_assert(junk == NULL);

	range = g_new(range_t, 1);

	range->magic = RANGE_MAGIC;
	range->entity = NULL;
	range->drange = NULL;

	return (gpointer) range;
}

static gpointer
range_dup(gconstpointer data)
{
	const range_t *org = (const range_t *)data;
	range_t       *range;

	range = (range_t *)range_new(NULL);
	range->entity = stnode_dup(org->entity);
	range->drange = drange_dup(org->drange);

	return (gpointer) range;
}

static void
range_free(gpointer value)
{
	range_t	*range = (range_t*)value;
	assert_magic(range, RANGE_MAGIC);

	if (range->drange)
		drange_free(range->drange);

	if (range->entity)
		stnode_free(range->entity);

	g_free(range);
}

void
sttype_range_remove_drange(stnode_t *node)
{
	range_t		*range;

	range = (range_t*)stnode_data(node);
	assert_magic(range, RANGE_MAGIC);

	range->drange = NULL;
}


/* Set a range */
void
sttype_range_set(stnode_t *node, stnode_t *entity, GSList* drange_list)
{
	range_t		*range;

	range = (range_t*)stnode_data(node);
	assert_magic(range, RANGE_MAGIC);

	range->entity = entity;

	range->drange = drange_new_from_list(drange_list);
}

void
sttype_range_set1(stnode_t *node, stnode_t *entity, drange_node *rn)
{
	sttype_range_set(node, entity, g_slist_append(NULL, rn));
}

STTYPE_ACCESSOR(stnode_t*, range, entity, RANGE_MAGIC)
STTYPE_ACCESSOR(drange_t*, range, drange, RANGE_MAGIC)


void
sttype_register_range(void)
{
	static sttype_t range_type = {
		STTYPE_RANGE,
		"RANGE",
		range_new,
		range_free,
		range_dup
	};

	sttype_register(&range_type);
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
