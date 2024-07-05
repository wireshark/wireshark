/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "syntax-tree.h"
#include "sttype-set.h"
#include <wsutil/ws_assert.h>

/*
 * The GSList stores a list of elements of the set. Each element is represented
 * by two list items: (lower, upper) in case of a value range or (value, NULL)
 * if the element is not a range value.
 */

static void
slist_stnode_free(void *data)
{
	if (data) {
		stnode_free(data);
	}
}

void
set_nodelist_free(GSList *params)
{
	g_slist_free_full(params, slist_stnode_free);
}

static void
sttype_set_free(void *value)
{
	/* If the data was not claimed with stnode_steal_data(), free it. */
	if (value) {
		set_nodelist_free(value);
	}
}

static char *
sttype_set_tostr(const void *data, bool pretty)
{
	const GSList* nodelist = data;
	stnode_t *lower, *upper;
	GString *repr = g_string_new("");

	while (nodelist) {
		lower = nodelist->data;
		g_string_append(repr, stnode_tostr(lower, pretty));

		/* Set elements are always in pairs; upper may be null. */
		nodelist = g_slist_next(nodelist);
		ws_assert(nodelist);
		upper = nodelist->data;
		if (upper != NULL) {
			g_string_append(repr, "..");
			g_string_append(repr, stnode_tostr(upper, pretty));
		}

		nodelist = g_slist_next(nodelist);
		if (nodelist != NULL) {
			g_string_append_c(repr, ' ');
		}
	}

	return g_string_free(repr, FALSE);
}

void
sttype_register_set(void)
{
	static sttype_t set_type = {
		STTYPE_SET,
		NULL,
		sttype_set_free,
		NULL,
		sttype_set_tostr
	};

	sttype_register(&set_type);
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
