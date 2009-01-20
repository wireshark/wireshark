/* column_prefs.c
 * Dialog box for column preferences
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gtk/gtk.h>

#include <epan/prefs.h>
#include <epan/column_info.h>
#include <epan/column.h>

#include "../globals.h"

#include "gtk/prefs_column.h"
#include "gtk/gtkglobals.h"
#include "gtk/gui_utils.h"
#include "gtk/main_packet_list.h"
#include "gtk/filter_dlg.h"
#include "gtk/filter_autocomplete.h"


static GtkWidget *remove_bt, *field_te, *field_lb, *fmt_cmb;
static gint       cur_fmt, cur_row;

static void column_list_select_cb(GtkTreeSelection *, gpointer);
static void column_field_changed_cb(GtkEditable *, gpointer);
static void column_list_new_cb(GtkWidget *, gpointer);
static void column_menu_changed_cb(GtkWidget *, gpointer);
static void column_list_delete_cb(GtkWidget *, gpointer);
static void column_dnd_row_deleted_cb(GtkTreeModel *, GtkTreePath *, gpointer);
static gboolean column_title_changed_cb(GtkCellRendererText *, const gchar *, const gchar *, gpointer);

#define E_COL_NAME_KEY "column_name"
#define E_COL_LBL_KEY  "column_label"
#define E_COL_CM_KEY   "in_col_cancel_mode"

/* Create and display the column selection widgets. */
/* Called when the 'Columns' preference notebook page is selected. */
GtkWidget *
column_prefs_show(GtkWidget *prefs_window) {
  GtkWidget         *main_vb, *bottom_hb, *column_l, *add_bt,
                    *tb, *lb;
  GtkWidget         *list_vb, *list_lb, *list_sc;
  GtkWidget         *add_remove_vb;
  GtkWidget         *props_fr, *props_hb;
  GList             *clp = NULL;
  fmt_data          *cfmt;
  gint               i;
  gchar             *fmt;
  const gchar       *column_titles[] = {"Title", "Format"};
  GtkListStore      *store;
  GtkCellRenderer   *renderer;
  GtkTreeViewColumn *column;
  GtkTreeSelection  *sel;
  GtkTreeIter        iter;
  GtkTreeIter        first_iter;
  gint               first_row = TRUE;

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_widget_show(main_vb);
  g_object_set_data(G_OBJECT(GTK_OBJECT(main_vb)), E_COL_CM_KEY, (gpointer)FALSE);

  /* Top row: Columns list frame */
  //list_fr = gtk_frame_new("Columns");
  //gtk_box_pack_start (GTK_BOX (main_vb), list_fr, TRUE, TRUE, 0);
  //gtk_widget_show(list_fr);

  list_vb = gtk_vbox_new (FALSE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (list_vb), 5);
  gtk_widget_show (list_vb);
  gtk_box_pack_start (GTK_BOX (main_vb), list_vb, TRUE, TRUE, 0);
  //gtk_container_add(GTK_CONTAINER(list_fr), list_vb);

  list_lb = gtk_label_new (("[First list entry will be displayed left]"));
  gtk_widget_show (list_lb);
  gtk_box_pack_start (GTK_BOX (list_vb), list_lb, FALSE, FALSE, 0);

  list_sc = scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(list_sc), 
                                   GTK_SHADOW_IN);
  gtk_container_add(GTK_CONTAINER(list_vb), list_sc);
  gtk_widget_show(list_sc);

  store = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);
  g_signal_connect(GTK_TREE_MODEL(store), "row-deleted", G_CALLBACK(column_dnd_row_deleted_cb), NULL);

  column_l = tree_view_new(GTK_TREE_MODEL(store));
  gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(column_l), TRUE);
  gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(column_l), FALSE);
  gtk_tree_view_set_reorderable(GTK_TREE_VIEW(column_l), TRUE);
  renderer = gtk_cell_renderer_text_new();
  g_object_set(G_OBJECT(renderer), "editable", TRUE, NULL);
  g_signal_connect (renderer, "edited", G_CALLBACK(column_title_changed_cb), GTK_TREE_MODEL(store));
  column = gtk_tree_view_column_new_with_attributes(column_titles[0], renderer,
                                                    "text", 0, NULL);
  gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
  gtk_tree_view_append_column(GTK_TREE_VIEW(column_l), column);
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes(column_titles[1], renderer,
                                                    "text", 1, NULL);
  gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
  gtk_tree_view_append_column(GTK_TREE_VIEW(column_l), column);
  /* XXX - make this match the packet list prefs? */
  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(column_l));
  gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
  g_signal_connect(sel, "changed", G_CALLBACK(column_list_select_cb), column_l);

  gtk_container_add(GTK_CONTAINER(list_sc), column_l);
  gtk_widget_show(column_l);

  clp = g_list_first(prefs.col_list);
  while (clp) {
    cfmt    = (fmt_data *) clp->data;
    cur_fmt = get_column_format_from_str(cfmt->fmt);
    if (cur_fmt == COL_CUSTOM) {
      fmt = g_strdup_printf("%s (%s)", col_format_desc(cur_fmt), cfmt->custom_field);
    } else {
      fmt = g_strdup_printf("%s", col_format_desc(cur_fmt));
    }
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, 0, cfmt->title, 1, fmt, 2, clp, -1);
    if (first_row) {
        first_iter = iter;
        first_row = FALSE;
    }
    clp = clp->next;
    g_free (fmt);
  }
  g_object_unref(G_OBJECT(store));

  
  /* Bottom row: Add/remove buttons and properties */
  bottom_hb = gtk_hbox_new(FALSE, 5);
  gtk_box_pack_start (GTK_BOX (main_vb), bottom_hb, FALSE, TRUE, 0);
  //gtk_container_add(GTK_CONTAINER(main_vb), bottom_hb);
  gtk_widget_show(bottom_hb);


  /* Add / remove buttons */
  add_remove_vb = gtk_vbox_new (FALSE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (add_remove_vb), 5);
  gtk_box_pack_start (GTK_BOX (bottom_hb), add_remove_vb, FALSE, TRUE, 0);
  //gtk_container_add(GTK_CONTAINER(bottom_hb), add_remove_vb);
  gtk_widget_show(add_remove_vb);

  add_bt = gtk_button_new_from_stock(GTK_STOCK_ADD);
  g_signal_connect(add_bt, "clicked", G_CALLBACK(column_list_new_cb), column_l);
  gtk_box_pack_start (GTK_BOX (add_remove_vb), add_bt, FALSE, FALSE, 5);
  gtk_widget_show(add_bt);

  remove_bt = gtk_button_new_from_stock(GTK_STOCK_REMOVE);
  gtk_widget_set_sensitive(remove_bt, FALSE);
  g_signal_connect(remove_bt, "clicked", G_CALLBACK(column_list_delete_cb), column_l);
  gtk_box_pack_start (GTK_BOX (add_remove_vb), remove_bt, FALSE, FALSE, 5);
  gtk_widget_show(remove_bt);
  
  /* properties frame */
  props_fr = gtk_frame_new("Properties");
  gtk_box_pack_start (GTK_BOX (bottom_hb), props_fr, TRUE, TRUE, 0);
  gtk_widget_show(props_fr);

  /* Column name entry and format selection */
  tb = gtk_table_new(1, 4, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(tb), 5);
  gtk_container_add(GTK_CONTAINER(props_fr), tb);
  gtk_table_set_row_spacings(GTK_TABLE(tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(tb), 15);
  gtk_widget_show(tb);

  lb = gtk_label_new("Format:");
  gtk_misc_set_alignment(GTK_MISC(lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(tb), lb, 0, 1, 0, 1);
  gtk_widget_show(lb);

  props_hb = gtk_hbox_new(FALSE, 5);
  gtk_table_attach(GTK_TABLE(tb), props_hb, 1, 2, 0, 1, GTK_FILL,
                   GTK_SHRINK, 0, 0);
  gtk_widget_show(props_hb);

  field_lb = gtk_label_new("Field name:");
  gtk_misc_set_alignment(GTK_MISC(field_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(tb), field_lb, 2, 3, 0, 1);
  gtk_widget_hide(field_lb);

  field_te = gtk_entry_new();
  g_object_set_data (G_OBJECT(field_te), E_FILT_FIELD_NAME_ONLY_KEY, "");
  g_signal_connect(field_te, "changed", G_CALLBACK(filter_te_syntax_check_cb), NULL);
  g_object_set_data(G_OBJECT(main_vb), E_FILT_AUTOCOMP_PTR_KEY, NULL);
  g_signal_connect(field_te, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
  g_signal_connect(prefs_window, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);
  colorize_filter_te_as_empty(field_te);
  gtk_table_attach_defaults(GTK_TABLE(tb), field_te, 3, 4, 0, 1);
  gtk_widget_set_sensitive(field_te, FALSE);
  gtk_widget_hide(field_te);

  fmt_cmb = gtk_combo_box_new_text();

  for (i = 0; i < NUM_COL_FMTS; i++)
    gtk_combo_box_append_text(GTK_COMBO_BOX(fmt_cmb), col_format_desc(i));

  g_signal_connect(fmt_cmb, "changed", G_CALLBACK(column_menu_changed_cb), column_l);

  cur_fmt = 0;
  gtk_combo_box_set_active(GTK_COMBO_BOX(fmt_cmb), cur_fmt);
  gtk_widget_set_sensitive(fmt_cmb, FALSE);
  gtk_box_pack_start(GTK_BOX(props_hb), fmt_cmb, FALSE, FALSE, 0);
  gtk_widget_show(fmt_cmb);

  /* select the first row */
  gtk_tree_selection_select_iter(sel, &first_iter);

  return(main_vb);
}

/* For each selection, set the entry and option menu widgets to match
   the currently selected item.  Set the up/down button sensitivity.
   Draw focus to the entry widget. */
static void
column_list_select_cb(GtkTreeSelection *sel, gpointer data)
{
    GtkTreeView  *column_l = GTK_TREE_VIEW(data);
    fmt_data     *cfmt;
    GList        *clp;
    GtkTreeModel *model;
    GtkTreeIter   iter;
    GtkTreePath  *path;
    gchar        *str_path;

    /* if something was selected */
    if (gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        gtk_tree_model_get(model, &iter, 2, &clp, -1);
        g_assert(clp != NULL);
        cfmt   = (fmt_data *) clp->data;
        cur_fmt = get_column_format_from_str(cfmt->fmt);
        g_assert(cur_fmt != -1);     /* It should always be valid */

        path = gtk_tree_model_get_path(model, &iter);
        str_path = gtk_tree_path_to_string(path);
        cur_row = atoi(str_path);
        g_free(str_path);
        gtk_tree_path_free(path);

        if (cur_fmt == COL_CUSTOM) {
            gtk_entry_set_text(GTK_ENTRY(field_te), cfmt->custom_field);
            gtk_widget_show(field_lb);
            gtk_widget_show(field_te);
        } else {
            gtk_widget_hide(field_lb);
            gtk_widget_hide(field_te);
        }
        g_signal_connect(field_te, "changed", G_CALLBACK(column_field_changed_cb), column_l);

        gtk_combo_box_set_active(GTK_COMBO_BOX(fmt_cmb), cur_fmt);

        gtk_widget_set_sensitive(remove_bt, TRUE);
        gtk_widget_set_sensitive(field_te, TRUE);
        gtk_widget_set_sensitive(fmt_cmb, TRUE);
    }
    else
    {
        cur_row = -1;
        gtk_editable_delete_text(GTK_EDITABLE(field_te), 0, -1);

        gtk_widget_set_sensitive(remove_bt, FALSE);
        gtk_widget_set_sensitive(field_te, FALSE);
        gtk_widget_set_sensitive(fmt_cmb, FALSE);
    }
}

/* To do: add input checking to each of these callbacks */

static void
column_list_new_cb(GtkWidget *w _U_, gpointer data) {
    fmt_data          *cfmt;
    const gchar       *title = "New Column";
    GtkTreeView       *column_l = GTK_TREE_VIEW(data);
    GtkTreeModel      *model;
    GtkTreeIter        iter;
    GtkTreePath       *path;
    GtkTreeViewColumn *title_column;
    gchar             *str_path;

    cur_fmt        = COL_NUMBER;
    cfmt           = (fmt_data *) g_malloc(sizeof(fmt_data));
    cfmt->title    = g_strdup(title);
    cfmt->fmt      = g_strdup(col_format_to_string(cur_fmt));
    cfmt->custom_field = NULL;
    prefs.col_list = g_list_append(prefs.col_list, cfmt);

    model = gtk_tree_view_get_model(column_l);
    gtk_list_store_append(GTK_LIST_STORE(model), &iter);
    gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, title, 1,
                       col_format_desc(cur_fmt), 2, g_list_last(prefs.col_list),
                       -1);

    path = gtk_tree_model_get_path(model, &iter);
    str_path = gtk_tree_path_to_string(path);
    cur_row = atoi(str_path);

    gtk_tree_selection_select_iter(gtk_tree_view_get_selection(column_l),
                                   &iter);
    title_column = gtk_tree_view_get_column(column_l, 0);
    gtk_tree_view_set_cursor(column_l, path, title_column, TRUE);

    g_free(str_path);
    gtk_tree_path_free(path);
    cfile.cinfo.columns_changed = TRUE;
}

static void
column_list_delete_cb(GtkWidget *w _U_, gpointer data) {
    GtkTreeView      *column_l = GTK_TREE_VIEW(data);
    GList            *clp;
    fmt_data         *cfmt;
    GtkTreeSelection *sel;
    GtkTreeModel     *model;
    GtkTreeIter       iter;

    sel = gtk_tree_view_get_selection(column_l);
    if (gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        gtk_tree_model_get(model, &iter, 2, &clp, -1);

        cfmt = (fmt_data *) clp->data;
        g_free(cfmt->title);
        g_free(cfmt->fmt);
        if (cfmt->custom_field) {
          g_free (cfmt->custom_field);
        }
        g_free(cfmt);
        prefs.col_list = g_list_remove_link(prefs.col_list, clp);

        gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
    }
    cfile.cinfo.columns_changed = TRUE;
}

static gboolean
column_title_changed_cb(GtkCellRendererText *cell _U_, const gchar *str_path, const gchar *new_title, gpointer data) {
  fmt_data     *cfmt;
  GList        *clp;
  GtkTreeModel *model = (GtkTreeModel *)data;
  GtkTreePath  *path = gtk_tree_path_new_from_string (str_path);
  GtkTreeIter   iter;

  gtk_tree_model_get_iter(model, &iter, path); 
  
  gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, new_title, -1);

  gtk_tree_model_get(model, &iter, 2, &clp, -1);
  if (clp) {    
    cfmt  = (fmt_data *) clp->data;
    g_free(cfmt->title);
    cfmt->title = g_strdup(new_title);
  }

  gtk_tree_path_free (path);
  cfile.cinfo.columns_changed = TRUE; 
  return TRUE;  
}

/* The user changed the custom field entry box. */
static void
column_field_changed_cb(GtkEditable *te, gpointer data) {
    fmt_data         *cfmt;
    GList            *clp;
    gchar            *field, *fmt;
    GtkTreeView      *tree = (GtkTreeView *)data;
    GtkTreeSelection *sel;
    GtkTreeModel     *model;
    GtkTreeIter       iter;

    sel = gtk_tree_view_get_selection(tree);
    if (gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        field = gtk_editable_get_chars(te, 0, -1);
        gtk_tree_model_get(model, &iter, 2, &clp, -1);
        cfmt  = (fmt_data *) clp->data;
        fmt = g_strdup_printf("%s (%s)", col_format_desc(cur_fmt), field);
        gtk_list_store_set(GTK_LIST_STORE(model), &iter, 1, fmt, -1);
	g_free(fmt);
        if (cfmt->custom_field) {
          g_free(cfmt->custom_field);
        }
        cfmt->custom_field = field;
    }
    cfile.cinfo.columns_changed = TRUE;
}

/* The user changed the format menu. */
static void
column_menu_changed_cb(GtkWidget *w, gpointer data) {
    GtkTreeView      *column_l = GTK_TREE_VIEW(data);
    fmt_data         *cfmt;
    GList            *clp;
    const gchar      *fmt;
    GtkTreeSelection *sel;
    GtkTreeModel     *model;
    GtkTreeIter       iter;

    sel = gtk_tree_view_get_selection(column_l);
    if (gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        cur_fmt = gtk_combo_box_get_active(GTK_COMBO_BOX(w));
        gtk_tree_model_get(model, &iter, 2, &clp, -1);
        cfmt    = (fmt_data *) clp->data;

        if (cur_fmt == COL_CUSTOM) {
          if (cfmt->custom_field == NULL) {
            cfmt->custom_field = g_strdup("");
          }
          gtk_entry_set_text(GTK_ENTRY(field_te), cfmt->custom_field);
          fmt = g_strdup_printf("%s (%s)", col_format_desc(cur_fmt), cfmt->custom_field);
          gtk_widget_show(field_lb);
          gtk_widget_show(field_te);
        } else {
          fmt = g_strdup_printf("%s", col_format_desc(cur_fmt));
          gtk_widget_hide(field_lb);
          gtk_widget_hide(field_te);
        }

        gtk_list_store_set(GTK_LIST_STORE(model), &iter, 1, fmt, -1);
        g_free(cfmt->fmt);
        cfmt->fmt = g_strdup(col_format_to_string(cur_fmt));
    }
    cfile.cinfo.columns_changed = TRUE;
}

/*
 * Callback for the "row-deleted" signal emitted when a list item is dragged.
 * http://library.gnome.org/devel/gtk/stable/GtkTreeModel.html#GtkTreeModel-rows-reordered
 * says that DND deletes, THEN inserts the row. If this isn't the case, we'll
 * have to find another way to do this (e.g. by rebuilding prefs.col_list by
 * iterating over the tree model.
 */
static void
column_dnd_row_deleted_cb(GtkTreeModel *model, GtkTreePath *path _U_, gpointer data _U_) {
  GtkTreeIter       iter;
  /* gpointer          cfmt; */
  GList            *clp, *new_col_list = NULL;
  gchar            *title, *format;
  gboolean     items_left;

  /*
   * XXX - This rebuilds prefs.col_list based on the current model. We
   * might just want to do this when the prefs are applied
   */
  for (items_left = gtk_tree_model_get_iter_first (model, &iter);
       items_left;
       items_left = gtk_tree_model_iter_next (model, &iter)) {

    gtk_tree_model_get(model, &iter, 0, &title, 1, &format, 2, &clp, -1);
    if (clp) {
      prefs.col_list = g_list_remove_link(prefs.col_list, clp);
      new_col_list = g_list_concat(new_col_list, clp);
    }
  }
  if (prefs.col_list) {
    g_warning("column_dnd_row_deleted_cb: prefs.col_list has %d leftover data",
      g_list_length(prefs.col_list));
    g_list_free(prefs.col_list);
  }
  prefs.col_list = new_col_list;
  cfile.cinfo.columns_changed = TRUE;
}

void
column_prefs_fetch(GtkWidget *w _U_) {
}

void
column_prefs_apply(GtkWidget *w _U_)
{
    /* Redraw the packet list if the columns were changed */
    if(cfile.cinfo.columns_changed) {
        packet_list_recreate();
        cfile.cinfo.columns_changed = FALSE; /* Reset value */
    }
}

void
column_prefs_destroy(GtkWidget *w) {
    /* Let the list cb know we're about to destroy the widget tree, so it */
    /* doesn't operate on widgets that don't exist. */
    g_object_set_data(G_OBJECT(w), E_COL_CM_KEY, (gpointer)TRUE);
}
