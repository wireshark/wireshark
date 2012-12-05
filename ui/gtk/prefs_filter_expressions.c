/* prefs_filter_expressions.c
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

#include <string.h>

#include <gtk/gtk.h>

#include <epan/prefs.h>
#include <epan/column_info.h>
#include <epan/column.h>
#include <epan/strutil.h>
#include <epan/filter_expressions.h>

#include "../globals.h"

#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/packet_list.h"
#include "ui/gtk/filter_dlg.h"
#include "ui/gtk/filter_autocomplete.h"
#include "ui/gtk/filter_expression_save_dlg.h"
#include "ui/gtk/old-gtk-compat.h"

static void filter_expressions_list_new_cb(GtkWidget *, gpointer);
static void filter_expressions_list_remove_cb(GtkWidget *, gpointer);
static gboolean filter_expressions_label_changed_cb(GtkCellRendererText *, const gchar *, const gchar *, gpointer);
static gboolean filter_expressions_expression_changed_cb(GtkCellRendererText *, const gchar *, const gchar *, gpointer);

#define E_FILTER_EXPRESSION_COLUMNL     "filter_expression_columnl"
#define E_FILTER_EXPRESSION_STORE       "filter_expression_store"

enum {
    ENABLED_COLUMN,
    LABEL_COLUMN,
    EXPRESSION_COLUMN,
    DATA_COLUMN,
    N_COLUMN /* The number of columns */
};

/* Visible toggled */
static void
enable_toggled(GtkCellRendererToggle *cell _U_, gchar *path_str, gpointer data)
{
    GtkTreeModel    *model = (GtkTreeModel *)data;
    GtkTreeIter      iter;
    GtkTreePath     *path = gtk_tree_path_new_from_string(path_str);
    struct filter_expression *fe;

    gtk_tree_model_get_iter(model, &iter, path);
    gtk_tree_model_get(model, &iter, DATA_COLUMN, &fe, -1);

    fe->enabled = !fe->enabled;

    gtk_list_store_set(GTK_LIST_STORE(model), &iter, ENABLED_COLUMN,
	fe->enabled, -1);

    gtk_tree_path_free(path);
} /* visible_toggled */

/*
 * Create and display the column selection widgets.
 * Called as part of the creation of the Preferences notebook ( Edit ! Preferences )
 */
GtkWidget *
filter_expressions_prefs_show(void) {
    GtkWidget         *main_vb, *bottom_hb, *column_l, *add_bt, *remove_bt;
    GtkWidget         *list_vb, *list_lb, *list_sc;
    GtkWidget         *add_remove_hb;
    GtkListStore      *store;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *column;
    GtkTreeSelection  *sel;
    GtkTreeIter        iter;
    GtkTreeIter        first_iter;
    gint               first_row = TRUE;
    struct filter_expression *fe;
    const gchar       *column_titles[] = {"Enabled", "Label",
					  "Filter Expression"};

    /* Container for each row of widgets */
    main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 5, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_widget_show(main_vb);

    list_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(list_vb), 5);
    gtk_widget_show(list_vb);
    gtk_box_pack_start(GTK_BOX(main_vb), list_vb, TRUE, TRUE, 0);

    list_lb = gtk_label_new(("[The first list entry will be displayed as the "
	"first button right of the Save button - Drag and drop entries to "
	"change column order]"));
    gtk_widget_show(list_lb);
    gtk_box_pack_start(GTK_BOX(list_vb), list_lb, FALSE, FALSE, 0);

    list_sc = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(list_sc),
	GTK_SHADOW_IN);
    gtk_box_pack_start(GTK_BOX(list_vb), list_sc, TRUE, TRUE, 0);
    gtk_widget_show(list_sc);

    store = gtk_list_store_new(N_COLUMN,
			       G_TYPE_BOOLEAN, G_TYPE_STRING, G_TYPE_STRING,
			       G_TYPE_POINTER);

    column_l = tree_view_new(GTK_TREE_MODEL(store));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(column_l), TRUE);
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(column_l), FALSE);
    gtk_tree_view_set_reorderable(GTK_TREE_VIEW(column_l), TRUE);
    gtk_widget_set_tooltip_text(column_l, "Click on a label or expression to "
	"change its name.\nDrag an item to change its order.\nTick 'Enable' "
	"to enable the filter in the buttons.");

    /* Enabled button */
    renderer = gtk_cell_renderer_toggle_new();
    g_signal_connect(renderer, "toggled", G_CALLBACK(enable_toggled), store);
    column = gtk_tree_view_column_new_with_attributes(
	column_titles[ENABLED_COLUMN], renderer, "active", ENABLED_COLUMN,
	NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(column_l), column);

    /* Label editor */
    renderer = gtk_cell_renderer_text_new();
    g_object_set(G_OBJECT(renderer), "editable", TRUE, NULL);
    g_signal_connect(renderer, "edited",
	G_CALLBACK(filter_expressions_label_changed_cb), GTK_TREE_MODEL(store));
    column = gtk_tree_view_column_new_with_attributes(
	column_titles[LABEL_COLUMN], renderer, "text", LABEL_COLUMN, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(column_l), column);

    /* Expression editor */
    renderer = gtk_cell_renderer_text_new();
    g_object_set(G_OBJECT(renderer), "editable", TRUE, NULL);
    g_signal_connect(renderer, "edited",
	G_CALLBACK(filter_expressions_expression_changed_cb),
	GTK_TREE_MODEL(store));
    column = gtk_tree_view_column_new_with_attributes(
	column_titles[EXPRESSION_COLUMN], renderer, "text", EXPRESSION_COLUMN,
	NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(column_l), column);

    /* XXX - make this match the packet list prefs? */
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(column_l));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);

    gtk_container_add(GTK_CONTAINER(list_sc), column_l);
    gtk_widget_show(column_l);

    fe = *pfilter_expression_head;
    while (fe != NULL) {
	fe->index = -1;
        gtk_list_store_insert_with_values(store, &iter, G_MAXINT,
	    ENABLED_COLUMN, fe->enabled,
	    LABEL_COLUMN, fe->label,
	    EXPRESSION_COLUMN, fe->expression,
	    DATA_COLUMN, fe,
	    -1);

        if (first_row) {
            first_iter = iter;
            first_row = FALSE;
        }
	fe = fe->next;
    }
    g_object_unref(G_OBJECT(store));

    /* Bottom row: Add/remove buttons */
    bottom_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5, FALSE);
    gtk_box_pack_start(GTK_BOX(main_vb), bottom_hb, FALSE, TRUE, 0);
    gtk_widget_show(bottom_hb);

    /* Add button */
    add_remove_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0, TRUE);
    gtk_container_set_border_width(GTK_CONTAINER(add_remove_hb), 5);
    gtk_box_pack_start(GTK_BOX(bottom_hb), add_remove_hb, FALSE, FALSE, 0);
    gtk_widget_show(add_remove_hb);

    add_bt = gtk_button_new_from_stock(GTK_STOCK_ADD);
    g_signal_connect(add_bt, "clicked",
	G_CALLBACK(filter_expressions_list_new_cb), column_l);
    gtk_box_pack_start(GTK_BOX(add_remove_hb), add_bt, FALSE, FALSE, 0);
    gtk_widget_set_tooltip_text(add_bt,
	"Add a new row at the end of the list.");
    gtk_widget_show(add_bt);

    /* Remove button */
    remove_bt = gtk_button_new_from_stock(GTK_STOCK_REMOVE);
    g_signal_connect(remove_bt, "clicked",
	G_CALLBACK(filter_expressions_list_remove_cb), column_l);
    gtk_box_pack_start(GTK_BOX(add_remove_hb), remove_bt, FALSE, FALSE, 0);
    gtk_widget_set_tooltip_text(remove_bt, "Remove the selected row.");
    gtk_widget_show(remove_bt);

    /* select the first menu list row.             */
    /*  Triggers call to column_list_select_cb().  */
    if (first_row == FALSE)
	gtk_tree_selection_select_iter(sel, &first_iter);

    g_object_set_data(G_OBJECT(main_vb), E_FILTER_EXPRESSION_COLUMNL,
	column_l);
    g_object_set_data(G_OBJECT(main_vb), E_FILTER_EXPRESSION_STORE,
	store);

    return(main_vb);
}

static void
filter_expressions_list_remove_cb(GtkWidget *w _U_, gpointer data)
{
    GtkTreeView      *column_l = GTK_TREE_VIEW(data);
    GtkTreeSelection *sel;
    GtkTreeModel     *model;
    GtkTreeIter       iter;
    struct filter_expression *fe;

    sel = gtk_tree_view_get_selection(column_l);
    if (!gtk_tree_selection_get_selected(sel, &model, &iter))
	return;

    gtk_tree_model_get(model, &iter, DATA_COLUMN, &fe, -1);
    fe->deleted = TRUE;

    gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
}

static void
filter_expressions_list_new_cb(GtkWidget *w _U_, gpointer data _U_)
{
    const gchar       *label = "New Label";
    const gchar       *expression = "New Expression";
    GtkTreeView       *fe_l = GTK_TREE_VIEW(data);
    GtkTreeModel      *model;
    GtkTreeIter        iter;
    GtkTreePath       *path;
    GtkTreeViewColumn *label_column;
    struct filter_expression *fe;

    fe = filter_expression_new(label, expression, TRUE);

    model = gtk_tree_view_get_model(fe_l);
    gtk_list_store_insert_with_values(GTK_LIST_STORE(model), &iter, G_MAXINT,
	ENABLED_COLUMN, fe->enabled,
	LABEL_COLUMN, fe->label,
	EXPRESSION_COLUMN, fe->expression,
	DATA_COLUMN, fe,
	-1);

    /* Triggers call to column_list_select_cb()   */
    gtk_tree_selection_select_iter(gtk_tree_view_get_selection(fe_l), &iter);

    /* Set the cursor to the 'Title' column of the newly added row and enable
     * editing
     * XXX: If displaying the new title ["New column"] widens the title column
     * of the treeview, then the set_cursor below doesn't properly generate an
     * entry box around the title text. The width of the box appears to be the
     * column width before the treeview title column was widened. Seems like a
     * bug...
     *
     *      I haven't found a work-around.
     */
    path = gtk_tree_model_get_path(model, &iter);
    label_column = gtk_tree_view_get_column(fe_l, 2);
    gtk_tree_view_set_cursor(fe_l, path, label_column, TRUE);
    gtk_tree_path_free(path);
}


static gboolean
filter_expressions_expression_changed_cb(GtkCellRendererText *cell _U_, const gchar *str_path, const gchar *new_expression, gpointer data)
{
    struct filter_expression *fe;
    GtkTreeModel *model = (GtkTreeModel *)data;
    GtkTreePath  *path = gtk_tree_path_new_from_string(str_path);
    GtkTreeIter   iter;

    gtk_tree_model_get_iter(model, &iter, path);
    gtk_list_store_set(GTK_LIST_STORE(model), &iter, EXPRESSION_COLUMN,
	new_expression, -1);

    gtk_tree_model_get(model, &iter, DATA_COLUMN, &fe, -1);
    if (fe != NULL) {
        g_free(fe->expression);
        fe->expression = g_strdup(new_expression);
    }

    gtk_tree_path_free(path);
    return(TRUE);
}

static gboolean
filter_expressions_label_changed_cb(GtkCellRendererText *cell _U_, const gchar *str_path, const gchar *new_label, gpointer data)
{
    struct filter_expression *fe;
    GtkTreeModel *model = (GtkTreeModel *)data;
    GtkTreePath  *path = gtk_tree_path_new_from_string(str_path);
    GtkTreeIter   iter;

    gtk_tree_model_get_iter(model, &iter, path);
    gtk_list_store_set(GTK_LIST_STORE(model), &iter, LABEL_COLUMN, new_label,
	-1);

    gtk_tree_model_get(model, &iter, DATA_COLUMN, &fe, -1);
    if (fe != NULL) {
        g_free(fe->label);
        fe->label = g_strdup(new_label);
    }

    gtk_tree_path_free(path);
    return TRUE;
}


void
filter_expressions_prefs_fetch(GtkWidget *w)
{
    gboolean      items_left;
    GtkTreeModel *model;
    GtkTreeView  *column_l;
    GtkTreeIter   iter;
    GtkListStore *store;
    struct filter_expression *fe;
    gint          first_row = TRUE;
    gint	  indx = 0;

    column_l = (GtkTreeView *)g_object_get_data(G_OBJECT(w),
	E_FILTER_EXPRESSION_COLUMNL);
    model = gtk_tree_view_get_model(column_l);
    store = (GtkListStore *)g_object_get_data(G_OBJECT(w),
	E_FILTER_EXPRESSION_STORE);

    /* Record the order of the items in the list.  */
    items_left = gtk_tree_model_get_iter_first(model, &iter);
    while (items_left) {
        gtk_tree_model_get(model, &iter, DATA_COLUMN, &fe, -1);
        if (fe != NULL)
	    fe->index = indx++;
	items_left = gtk_tree_model_iter_next (model, &iter);
    }

    filter_expression_reinit(FILTER_EXPRESSION_REINIT_DESTROY | FILTER_EXPRESSION_REINIT_CREATE);

    gtk_list_store_clear(store);
    fe = *pfilter_expression_head;
    while (fe != NULL) {
	fe->index = -1;
        gtk_list_store_insert_with_values(store, &iter, G_MAXINT,
	    ENABLED_COLUMN, fe->enabled,
	    LABEL_COLUMN, fe->label,
	    EXPRESSION_COLUMN, fe->expression,
	    DATA_COLUMN, fe,
	    -1);

        if (first_row) {
            first_row = FALSE;
        }
	fe = fe->next;
    }
}
