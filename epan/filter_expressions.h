/* filter_expressions.h
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

#ifndef __FILTER_EXPRESSIONS_H__
#define __FILTER_EXPRESSIONS_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Filter expressions.
 */

struct filter_expression {
	gpointer button;	/* Filter toolbar */
	gchar	*label;
	gchar	*expression;

	gint	 filter_index;
	gboolean enabled;	/* Can be set to FALSE by Preferences Dialog */
	gboolean deleted;	/* Can be set to TRUE by Preferences Dialog (GTK+ only) */

	struct filter_expression *next;
};

WS_DLL_PUBLIC struct filter_expression **pfilter_expression_head;

/** Create a filter expression
 *
 * @param label Label (button) text for the expression.
 * @param expr The display filter for the expression.
 * @param enabled Determines if the expression is shown in the UI.
 * @return A newly allocated and initialized struct filter_expression.
 */
WS_DLL_PUBLIC
struct filter_expression *filter_expression_new(const gchar *label,
    const gchar *expr, const gboolean enabled);

void filter_expression_init(void);

/** Clear the filter expression list.
 * Frees each item in the list. Caller should set list_head to NULL afterward.
 */
WS_DLL_PUBLIC
void filter_expression_free(struct filter_expression *list_head);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILTER_EXPRESSIONS_H__ */
