/* simple_stattable.c
 *
 * Based on response_time_delay_table.c
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

#include <gtk/gtk.h>

#include "epan/packet_info.h"
#include "epan/proto.h"
#include <epan/stat_tap_ui.h>

#include "ui/simple_dialog.h"
#include <wsutil/utf8_entities.h>

#include "ui/gtk/filter_utils.h"
#include "ui/gtk/gui_stat_util.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/simple_stattable.h"
#include "ui/gtk/tap_param_dlg.h"
#include "ui/gtk/main.h"

#include "ui/gtk/old-gtk-compat.h"

typedef struct _gtk_simplestat_t {
	GtkWidget *vbox;
	GtkWidget *win;
	GtkTreeView  *table;        /**< Tree view */
	GtkWidget *scrolled_window; /**< window widget */
	GtkWidget *menu;            /**< context menu */
} gtk_simplestat_t_t;

typedef struct _simple_stat_t {
	const char *filter;
	gtk_simplestat_t_t gtk_data;
	stat_tap_table_ui *new_stat_tap;
	new_stat_data_t data;
} simple_stat_t;

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	simple_stat_t *ss = (simple_stat_t*)data;

	remove_tap_listener(&ss->data);

    free_stat_tables(ss->new_stat_tap, NULL, NULL);

	g_free(ss);
}

static void
init_gtk_simple_stat_table(stat_tap_table* stat_table, void* gui_data)
{
	guint i;
	new_stat_data_t* stat_data = (new_stat_data_t*)gui_data;
	simple_stat_t *ss = (simple_stat_t*)stat_data->user_data;
	stat_column *start_columns = g_new(stat_column, stat_table->num_fields),
				*columns;
	stat_tap_table_item* field;
	GType gtk_type;

	/* XXX - Use # columns/fields, etc to compute a better value */
	gtk_window_set_default_size(GTK_WINDOW(ss->gtk_data.win), 600, 300);

	for (i = 0, columns = start_columns, field = stat_data->stat_tap_data->fields;
			i < stat_table->num_fields;
			i++, columns++, field++)
	{
		switch(field->type)
		{
		case TABLE_ITEM_UINT:
			gtk_type = G_TYPE_UINT;
			break;
		case TABLE_ITEM_INT:
			gtk_type = G_TYPE_INT;
			break;
		case TABLE_ITEM_STRING:
			gtk_type = G_TYPE_STRING;
			break;
		case TABLE_ITEM_FLOAT:
			gtk_type = G_TYPE_FLOAT;
			break;
		case TABLE_ITEM_ENUM:
			gtk_type = G_TYPE_ENUM;
			break;
		default:
			g_assert(FALSE);
			return;
		}
		columns->type = gtk_type;
		columns->align = field->align;
		columns->title = field->column_name;
	}

	ss->gtk_data.table = create_stat_table(ss->gtk_data.scrolled_window, ss->gtk_data.vbox, stat_table->num_fields, start_columns);
	g_free(start_columns);
}

static void
simple_stat_draw(void *arg)
{
	GtkListStore *store;
	new_stat_data_t *stats = (new_stat_data_t*)arg;
	simple_stat_t *ss = (simple_stat_t*)stats->user_data;
	stat_tap_table* table;
	stat_tap_table_item* field;
	stat_tap_table_item_type* field_data;
	GtkTreeIter iter;
	guint table_index = 0, element, field_index;

	/* clear list before printing */
	store = GTK_LIST_STORE(gtk_tree_view_get_model(ss->gtk_data.table));
	gtk_list_store_clear(store);

	/* XXX - Only support a single table at the moment */
	table = g_array_index(stats->stat_tap_data->tables, stat_tap_table*, table_index);

	for (element = 0; element < table->num_elements; element++)
	{
		field_index = 0;
		field_data = new_stat_tap_get_field_data(table, element, field_index);
		if (field_data->type == TABLE_ITEM_NONE) /* Nothing for us here */
			continue;

		gtk_list_store_append(store, &iter);

		for (field = stats->stat_tap_data->fields; field_index < table->num_fields; field_index++, field++)
		{
			field_data = new_stat_tap_get_field_data(table, element, field_index);

			switch(field_data->type)
			{
			case TABLE_ITEM_UINT:
				gtk_list_store_set(store, &iter, field_index, field_data->value.uint_value, -1);
				break;
			case TABLE_ITEM_INT:
				gtk_list_store_set(store, &iter, field_index, field_data->value.int_value, -1);
				break;
			case TABLE_ITEM_STRING:
				gtk_list_store_set(store, &iter, field_index, field_data->value.string_value, -1);
				break;
			case TABLE_ITEM_FLOAT:
				gtk_list_store_set(store, &iter, field_index, field_data->value.float_value, -1);
				break;
			case TABLE_ITEM_ENUM:
				gtk_list_store_set(store, &iter, field_index, field_data->value.enum_value, -1);
				break;
			case TABLE_ITEM_NONE:
				break;
			}
		}
	}
}

static void
reset_table_data(stat_tap_table* table _U_, void* gui_data)
{
	GtkListStore *store;
	gtk_simplestat_t_t* gtk_data = (gtk_simplestat_t_t*)gui_data;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(gtk_data->table));
	gtk_list_store_clear(store);
}

static void
simple_stat_reset(void *arg)
{
	new_stat_data_t *stats = (new_stat_data_t*)arg;
	simple_stat_t *ss = (simple_stat_t*)stats->user_data;

	reset_stat_table(stats->stat_tap_data, reset_table_data, &ss->gtk_data);

	set_window_title(ss->gtk_data.win, ss->new_stat_tap->title);
}

static void
init_simple_stat_tables(stat_tap_table_ui *new_stat_tap, const char *filter)
{
	simple_stat_t *ss;
	GString *error_string;
	GtkWidget *bbox;
	GtkWidget *close_bt;

	ss = g_new0(simple_stat_t, 1);

	ss->gtk_data.win=dlg_window_new(new_stat_tap->title);  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(ss->gtk_data.win), TRUE);

	ss->gtk_data.vbox=ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);

	init_main_stat_window(ss->gtk_data.win, ss->gtk_data.vbox, new_stat_tap->title, filter);

	/* init a scrolled window*/
	ss->gtk_data.scrolled_window = scrolled_window_new(NULL, NULL);

	ss->filter = g_strdup(filter);
	ss->new_stat_tap = new_stat_tap;
	ss->data.stat_tap_data = new_stat_tap;
	ss->data.user_data = ss;

	new_stat_tap->stat_tap_init_cb(new_stat_tap, init_gtk_simple_stat_table, &ss->data);

	error_string = register_tap_listener(new_stat_tap->tap_name, &ss->data, filter, 0, simple_stat_reset, new_stat_tap->packet_func, simple_stat_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		free_stat_tables(ss->new_stat_tap, NULL, NULL);
		g_free(ss);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(ss->gtk_data.vbox), bbox, FALSE, FALSE, 0);

	close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(ss->gtk_data.win, close_bt, window_cancel_button_cb);

	g_signal_connect(ss->gtk_data.win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(ss->gtk_data.win, "destroy", G_CALLBACK(win_destroy_cb), ss);

	gtk_widget_show_all(ss->gtk_data.win);
	window_present(ss->gtk_data.win);

	cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(ss->gtk_data.win));
}

static void
gtk_simple_stat_init(const char *opt_arg, void *userdata)
{
	stat_tap_table_ui *new_stat_tap = (stat_tap_table_ui*)userdata;
	const char *filter=NULL;
	char* err;

	new_stat_tap_get_filter(new_stat_tap, opt_arg, &filter, &err);

	if (err != NULL)
	{
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
		g_free(err);
		return;
	}

	init_simple_stat_tables(new_stat_tap, filter);
}

void register_simple_stat_tables(gpointer data, gpointer user_data _U_)
{
	stat_tap_table_ui *new_stat_tap = (stat_tap_table_ui*)data;
	tap_param_dlg* stat_dlg;

	stat_dlg = g_new(tap_param_dlg, 1);

	stat_dlg->win_title = new_stat_tap->title;
	stat_dlg->init_string = new_stat_tap->cli_string;
	stat_dlg->tap_init_cb = gtk_simple_stat_init;
	stat_dlg->index = -1;

	stat_dlg->nparams = new_stat_tap->nparams;
	stat_dlg->params = new_stat_tap->params;

	stat_dlg->user_data = new_stat_tap;

	register_param_stat(stat_dlg, new_stat_tap->title, new_stat_tap->group);
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
