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
#include "sttype-slice.h"
#include <wsutil/ws_assert.h>

typedef struct {
	guint32	   magic;
	stnode_t  *entity;
	drange_t  *drange;
} slice_t;

#define SLICE_MAGIC	0xec0990ce

static gpointer
slice_new(gpointer junk _U_)
{
	slice_t		*slice;

	ws_assert(junk == NULL);

	slice = g_new(slice_t, 1);

	slice->magic = SLICE_MAGIC;
	slice->entity = NULL;
	slice->drange = NULL;

	return slice;
}

static gpointer
slice_dup(gconstpointer data)
{
	const slice_t *org = data;
	slice_t       *slice;

	slice = slice_new(NULL);
	slice->entity = stnode_dup(org->entity);
	slice->drange = drange_dup(org->drange);

	return slice;
}

static void
slice_free(gpointer value)
{
	slice_t *slice = value;
	ws_assert_magic(slice, SLICE_MAGIC);

	if (slice->drange)
		drange_free(slice->drange);

	if (slice->entity)
		stnode_free(slice->entity);

	g_free(slice);
}

static char *
slice_tostr(const void *data, gboolean pretty)
{
	const slice_t *slice = data;
	ws_assert_magic(slice, SLICE_MAGIC);

	char *repr, *drange_str;

	drange_str = drange_tostr(slice->drange);
	repr = ws_strdup_printf("%s[%s]",
			stnode_tostr(slice->entity, pretty),
			drange_str);
	g_free(drange_str);

	return repr;
}

void
sttype_slice_remove_drange(stnode_t *node)
{
	slice_t		*slice;

	slice = stnode_data(node);
	ws_assert_magic(slice, SLICE_MAGIC);

	slice->drange = NULL;
}

drange_t *
sttype_slice_drange_steal(stnode_t *node)
{
	slice_t		*slice;
	drange_t	*dr;

	slice = stnode_data(node);
	ws_assert_magic(slice, SLICE_MAGIC);
	dr = slice->drange;
	slice->drange = NULL;
	return dr;
}

/* Set a slice */
void
sttype_slice_set(stnode_t *node, stnode_t *entity, GSList* drange_list)
{
	slice_t		*slice;

	slice = stnode_data(node);
	ws_assert_magic(slice, SLICE_MAGIC);

	slice->entity = entity;

	slice->drange = drange_new_from_list(drange_list);
}

void
sttype_slice_set1(stnode_t *node, stnode_t *entity, drange_node *rn)
{
	sttype_slice_set(node, entity, g_slist_append(NULL, rn));
}

void
sttype_slice_set_drange(stnode_t *node, stnode_t *field, drange_t *dr)
{
	slice_t		*slice;

	slice = stnode_data(node);
	ws_assert_magic(slice, SLICE_MAGIC);

	slice->entity = field;

	slice->drange = dr;
}

stnode_t *
sttype_slice_entity(stnode_t *node)
{
	slice_t *slice = node->data;
	ws_assert_magic(slice, SLICE_MAGIC);
	return slice->entity;
}

drange_t *
sttype_slice_drange(stnode_t *node)
{
	slice_t *slice = node->data;
	ws_assert_magic(slice, SLICE_MAGIC);
	return slice->drange;
}

void
sttype_register_slice(void)
{
	static sttype_t slice_type = {
		STTYPE_SLICE,
		"SLICE",
		slice_new,
		slice_free,
		slice_dup,
		slice_tostr
	};

	sttype_register(&slice_type);
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
