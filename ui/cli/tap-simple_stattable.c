/* tap-simpletable.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <epan/packet.h>
#include <epan/timestamp.h>
#include <epan/stat_tap_ui.h>
#include <ui/cmdarg_err.h>
#include <ui/cli/tshark-tap.h>

typedef struct _table_stat_t {
	const char *filter;
	stat_data_t stats;
} table_stat_t;

static void
simple_draw(void *arg)
{
	stat_data_t* stat_data = (stat_data_t*)arg;
	table_stat_t* stats = (table_stat_t*)stat_data->user_data;
	size_t i;
	guint table_index, element, field_index;
	stat_tap_table_item* field;
	stat_tap_table* table;
	stat_tap_table_item_type* field_data;
	gchar fmt_string[250];

	/* printing results */
	printf("\n");
	printf("=====================================================================================================\n");
	printf("%s:\n", stat_data->stat_tap_data->title);
	printf("Filter for statistics: %s\n", stats->filter ? stats->filter : "");

	for (i = 0, field = stat_data->stat_tap_data->fields; i < stat_data->stat_tap_data->nfields; i++, field++)
	{
		printf("%s |", field->column_name);
	}
	printf("\n");

	/* To iterate is human, and to recurse is divine.  I am human */
	for (table_index = 0; table_index < stat_data->stat_tap_data->tables->len; table_index++)
	{
		table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, table_index);
		printf("%s\n", table->title);
		for (element = 0; element < table->num_elements; element++)
		{
			for (field_index = 0, field = stat_data->stat_tap_data->fields; field_index < table->num_fields; field_index++, field++)
			{
				field_data = stat_tap_get_field_data(table, element, field_index);
				if (field_data->type == TABLE_ITEM_NONE) /* Nothing for us here */
					break;

				g_snprintf(fmt_string, sizeof(fmt_string), "%s |", field->field_format);
				switch(field->type)
				{
				case TABLE_ITEM_UINT:
					printf(fmt_string, field_data->value.uint_value);
					break;
				case TABLE_ITEM_INT:
					printf(fmt_string, field_data->value.int_value);
					break;
				case TABLE_ITEM_STRING:
					printf(fmt_string, field_data->value.string_value);
					break;
				case TABLE_ITEM_FLOAT:
					printf(fmt_string, field_data->value.float_value);
					break;
				case TABLE_ITEM_ENUM:
					printf(fmt_string, field_data->value.enum_value);
					break;
				case TABLE_ITEM_NONE:
					break;
				}
			}
			printf("\n");
		}
	}
	printf("=====================================================================================================\n");
}

static void
init_stat_table(stat_tap_table_ui *stat_tap, const char *filter)
{
	GString *error_string;
	table_stat_t* ui;

	ui = g_new0(table_stat_t, 1);
	ui->filter = g_strdup(filter);
	ui->stats.stat_tap_data = stat_tap;
	ui->stats.user_data = ui;

	stat_tap->stat_tap_init_cb(stat_tap);

	error_string = register_tap_listener(stat_tap->tap_name, &ui->stats, filter, 0, NULL, stat_tap->packet_func, simple_draw, NULL);
	if (error_string) {
/*		free_rtd_table(&ui->rtd.stat_table); */
		cmdarg_err("Couldn't register tap: %s", error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static void
simple_stat_init(const char *opt_arg, void* userdata)
{
	stat_tap_table_ui *stat_tap = (stat_tap_table_ui*)userdata;
	const char *filter=NULL;
	char* err = NULL;

	stat_tap_get_filter(stat_tap, opt_arg, &filter, &err);
	if (err != NULL)
	{
		cmdarg_err("%s", err);
		g_free(err);
		exit(1);
	}

	init_stat_table(stat_tap, filter);
}

gboolean
register_simple_stat_tables(const void *key, void *value, void *userdata _U_)
{
	stat_tap_table_ui *stat_tap = (stat_tap_table_ui*)value;
	stat_tap_ui ui_info;

	ui_info.group = stat_tap->group;
	ui_info.title = stat_tap->title;   /* construct this from the protocol info? */
	ui_info.cli_string = (const char *)key;
	ui_info.tap_init_cb = simple_stat_init;
	ui_info.nparams = stat_tap->nparams;
	ui_info.params = stat_tap->params;

	register_stat_tap_ui(&ui_info, stat_tap);
	return FALSE;
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
