/* filter_expressions.c
 * Submitted by Edwin Groothuis <wireshark@mavetju.org>
 *
 * $Id$
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

	expression = (struct filter_expression *)g_malloc(sizeof(struct filter_expression));
	memset(expression, '\0', sizeof(struct filter_expression));
	expression->button = NULL;
	expression->label = g_strdup(label);
	expression->expression = g_strdup(expr);
	expression->enabled = enabled;
	expression->deleted = FALSE;
	expression->index = 0;

	expression->next = NULL;

	/* Add it at the end so the button order is always the same*/
	if (*pfilter_expression_head == NULL) {
		_filter_expression_head = expression;
	} else {
		prev = *pfilter_expression_head;
		while (prev->next != NULL)
			prev = prev->next;
		prev->next = expression;
		expression->index = prev->index + 1;
	}

	return(expression);
}

void
filter_expression_init(gboolean enable_prefs)
{
	if (enable_prefs)
		prefs.filter_expressions = pfilter_expression_head;
}
