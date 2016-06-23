/* filter_expressions.c
 * Submitted by Edwin Groothuis <wireshark@mavetju.org>
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

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <epan/prefs.h>

#include "epan/filter_expressions.h"

static struct filter_expression *_filter_expression_head = NULL;
struct filter_expression **pfilter_expression_head = &_filter_expression_head;

/*
 * Create a new filter_expression and add it to the end of the list
 * of filter_expressions.
 */
struct filter_expression *
filter_expression_new(const gchar *label, const gchar *expr,
		      const gboolean enabled)
{
	struct filter_expression *expression;
	struct filter_expression *prev;

	expression = (struct filter_expression *)g_malloc0(sizeof(struct filter_expression));
	expression->label = g_strdup(label);
	expression->expression = g_strdup(expr);
	expression->enabled = enabled;

	/* Add it at the end so the button order is always the same*/
	if (*pfilter_expression_head == NULL) {
		_filter_expression_head = expression;
	} else {
		prev = *pfilter_expression_head;
		while (prev->next != NULL)
			prev = prev->next;
		prev->next = expression;
		expression->filter_index = prev->filter_index + 1;
	}

	return(expression);
}

void
filter_expression_init(void)
{
	prefs.filter_expressions = pfilter_expression_head;
}

void
filter_expression_free(struct filter_expression *list_head)
{
	if (list_head == NULL)
		return;
	filter_expression_free(list_head->next);
	g_free(list_head->label);
	g_free(list_head->expression);
	g_free(list_head);
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
