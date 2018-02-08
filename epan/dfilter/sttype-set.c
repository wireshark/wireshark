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

static void
slist_stnode_free(gpointer data, gpointer user_data _U_)
{
	stnode_free((stnode_t *)data);
}

void
set_nodelist_free(GSList *params)
{
	g_slist_foreach(params, slist_stnode_free, NULL);
	g_slist_free(params);
}

void
sttype_set_replace_element(stnode_t *node, stnode_t *oldnode, stnode_t *newnode)
{
	GSList	*nodelist = (GSList*)stnode_data(node);

	while (nodelist) {
		if (nodelist->data == oldnode) {
			nodelist->data = newnode;
			break;
		}
		nodelist = g_slist_next(nodelist);
	}
}

void
sttype_register_set(void)
{
	static sttype_t set_type = {
		STTYPE_SET,
		"SET",
		NULL,
		NULL,
		NULL
	};

	sttype_register(&set_type);
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
