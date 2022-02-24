/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
#include <wsutil/ws_assert.h>

typedef struct {
	guint32	   magic;
	stnode_t  *entity;
	drange_t  *drange;
} range_t;

#define RANGE_MAGIC	0xec0990ce

static gpointer
range_new(gpointer junk _U_)
{
	range_t		*range;

	ws_assert(junk == NULL);

	range = g_new(range_t, 1);

	range->magic = RANGE_MAGIC;
	range->entity = NULL;
	range->drange = NULL;

	return range;
}

static gpointer
range_dup(gconstpointer data)
{
	const range_t *org = data;
	range_t       *range;

	range = range_new(NULL);
	range->entity = stnode_dup(org->entity);
	range->drange = drange_dup(org->drange);

	return range;
}

static void
range_free(gpointer value)
{
	range_t *range = value;
	ws_assert_magic(range, RANGE_MAGIC);

	if (range->drange)
		drange_free(range->drange);

	if (range->entity)
		stnode_free(range->entity);

	g_free(range);
}

static char *
range_tostr(const void *data, gboolean pretty)
{
	const range_t *range = data;
	ws_assert_magic(range, RANGE_MAGIC);

	char *repr, *drange_str;

	drange_str = drange_tostr(range->drange);
	repr = ws_strdup_printf("%s[%s]",
			stnode_tostr(range->entity, pretty),
			drange_str);
	g_free(drange_str);

	return repr;
}

void
sttype_range_remove_drange(stnode_t *node)
{
	range_t		*range;

	range = stnode_data(node);
	ws_assert_magic(range, RANGE_MAGIC);

	range->drange = NULL;
}


/* Set a range */
void
sttype_range_set(stnode_t *node, stnode_t *entity, GSList* drange_list)
{
	range_t		*range;

	range = stnode_data(node);
	ws_assert_magic(range, RANGE_MAGIC);

	range->entity = entity;

	range->drange = drange_new_from_list(drange_list);
}

void
sttype_range_set1(stnode_t *node, stnode_t *entity, drange_node *rn)
{
	sttype_range_set(node, entity, g_slist_append(NULL, rn));
}

stnode_t *
sttype_range_entity(stnode_t *node)
{
	range_t *range = node->data;
	ws_assert_magic(range, RANGE_MAGIC);
	return range->entity;
}

drange_t *
sttype_range_drange(stnode_t *node)
{
	range_t *range = node->data;
	ws_assert_magic(range, RANGE_MAGIC);
	return range->drange;
}

void
sttype_register_range(void)
{
	static sttype_t range_type = {
		STTYPE_RANGE,
		"RANGE",
		range_new,
		range_free,
		range_dup,
		range_tostr
	};

	sttype_register(&range_type);
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
