/* filter_expressions.c
 * Submitted by Edwin Groothuis <wireshark@mavetju.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/uat-int.h>

#include "epan/filter_expressions.h"

/* UAT variables */
static uat_t            *display_filter_macro_uat = NULL;
static filter_expression_t *display_filter_macros = NULL;
static guint             num_display_filter_macros = 0;

/* Field callbacks. */
UAT_BOOL_CB_DEF(display_filter_macro_uat, enabled, filter_expression_t)
UAT_CSTRING_CB_DEF(display_filter_macro_uat, label, filter_expression_t)
UAT_DISPLAY_FILTER_CB_DEF(display_filter_macro_uat, expression, filter_expression_t)
UAT_CSTRING_CB_DEF(display_filter_macro_uat, comment, filter_expression_t)

/*
 * Create a new filter_expression and add it to the end of the list
 * of filter_expressions.
 */
filter_expression_t*
filter_expression_new(const gchar *label, const gchar *expr,
		      const gchar *comment, const gboolean enabled)
{
	filter_expression_t expression;

	// UAT allocates its own memory and then deep-copies this structure in.
	memset(&expression, 0, sizeof(expression));
	expression.label = (gchar *)label;
	expression.expression = (gchar *)expr;
	expression.comment = (gchar *)comment;
	expression.enabled = enabled;

	/* XXX - This is just returned to make GTK GUI work. */
	return (filter_expression_t*)uat_add_record(display_filter_macro_uat, &expression, TRUE);
}

void filter_expression_iterate_expressions(wmem_foreach_func func, void* user_data)
{
	guint i;

	for (i = 0; i < num_display_filter_macros; i++)
	{
		func(NULL, &display_filter_macros[i], user_data);
	}
}

static void display_filter_free_cb(void*r) {
	filter_expression_t* rec = (filter_expression_t*)r;

	g_free(rec->label);
	g_free(rec->expression);
	g_free(rec->comment);
}

static void* display_filter_copy_cb(void* n, const void* o, size_t siz _U_) {
	filter_expression_t* new_record = (filter_expression_t*)n;
	const filter_expression_t* old_record = (const filter_expression_t*)o;

	new_record->label = g_strdup(old_record->label);
	new_record->expression = g_strdup(old_record->expression);
	new_record->comment = g_strdup(old_record->comment);

	new_record->enabled = old_record->enabled;

	return new_record;
}

static uat_field_t display_filter_uat_flds[] = {
	UAT_FLD_BOOL(display_filter_macro_uat, enabled, "Show in toolbar",
		"Checked to add display filter button to toolbar"),
	UAT_FLD_CSTRING(display_filter_macro_uat, label, "Button Label",
		"Name of the display filter button"),
	UAT_FLD_DISPLAY_FILTER(display_filter_macro_uat, expression, "Filter Expression",
		"Filter expression to be applied by the button"),
	UAT_FLD_CSTRING(display_filter_macro_uat, comment, "Comment",
		"Comment describing filter expression"),
	UAT_END_FIELDS
};

void filter_expression_register_uat(module_t* pref_module)
{
	display_filter_macro_uat = uat_new("Display expressions",
			sizeof(filter_expression_t),   /* record size */
			"dfilter_buttons",          /* filename */
			TRUE,                       /* from_profile */
			&display_filter_macros,     /* data_ptr */
			&num_display_filter_macros, /* numitems_ptr */
			0,                          /* Doesn't not explicitly effect dissection */
			NULL,                       /* help */
			display_filter_copy_cb,     /* copy callback */
			NULL,                       /* update callback */
			display_filter_free_cb,     /* free callback */
			NULL,                       /* post update callback */
			NULL,                       /* reset callback */
			display_filter_uat_flds);   /* UAT field definitions */

	prefs_register_uat_preference(pref_module, "expressions",
			"Display filter expressions",
			"Macros for display filters",
			display_filter_macro_uat);
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
