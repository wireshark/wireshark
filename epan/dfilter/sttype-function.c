/*
 * $Id$
 *
 * Copyright (c) 2006 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
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

#include "syntax-tree.h"
#include "sttype-function.h"

typedef struct {
	guint32		magic;
    df_func_def_t *funcdef;
    GSList *params;
} function_t;

#define FUNCTION_MAGIC	0xe10f0f99

static gpointer
function_new(gpointer funcdef)
{
	function_t		*stfuncrec;

	g_assert(funcdef != NULL);

	stfuncrec = g_new(function_t, 1);

	stfuncrec->magic = FUNCTION_MAGIC;
	stfuncrec->funcdef = (df_func_def_t *)funcdef;
	stfuncrec->params = NULL;

	return (gpointer) stfuncrec;
}

static gpointer
function_dup(gconstpointer data)
{
	const function_t *org = data;
	function_t		 *stfuncrec;
	GSList *p;

	stfuncrec = function_new(org->funcdef);

	for (p = org->params; p; p = p->next) {
		const stnode_t *param = p->data;
		stfuncrec->params = g_slist_append(stfuncrec->params, stnode_dup(param));
	}
	return (gpointer) stfuncrec;
}

static void
slist_stnode_free(gpointer data, gpointer user_data _U_)
{
    stnode_free((stnode_t *)data);
}

void
st_funcparams_free(GSList *params)
{
    g_slist_foreach(params, slist_stnode_free, NULL);
    g_slist_free(params);
}

static void
function_free(gpointer value)
{
	function_t	*stfuncrec = (function_t*)value;
	assert_magic(stfuncrec, FUNCTION_MAGIC);
    st_funcparams_free(stfuncrec->params);
	g_free(stfuncrec);
}


/* Set the parameters for a function stnode_t. */
void
sttype_function_set_params(stnode_t *node, GSList *params)
{

	function_t	*stfuncrec;

	stfuncrec = (function_t*)stnode_data(node);
	assert_magic(stfuncrec, FUNCTION_MAGIC);

	stfuncrec->params = params;
}

/* Get the function-definition record for a function stnode_t. */
df_func_def_t*
sttype_function_funcdef(stnode_t *node)
{
	function_t	*stfuncrec;

	stfuncrec = (function_t*)stnode_data(node);
	assert_magic(stfuncrec, FUNCTION_MAGIC);
    return stfuncrec->funcdef;
}

/* Get the parameters for a function stnode_t. */
GSList*
sttype_function_params(stnode_t *node)
{
	function_t	*stfuncrec;

	stfuncrec = (function_t*)stnode_data(node);
	assert_magic(stfuncrec, FUNCTION_MAGIC);
    return stfuncrec->params;
}


void
sttype_register_function(void)
{
	static sttype_t function_type = {
		STTYPE_FUNCTION,
		"FUNCTION",
		function_new,
		function_free,
		function_dup
	};

	sttype_register(&function_type);
}

