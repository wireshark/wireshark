/* column_prefs.c
 * Dialog box for column preferences
 *
 * $Id: column_prefs.c,v 1.14 2002/11/03 17:38:33 oabad Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "globals.h"
#include "column_prefs.h"
#include "gtkglobals.h"
#include "prefs.h"
#include "column.h"

#if GTK_MAJOR_VERSION >= 2
#include "ui_util.h"
#endif

static GtkWidget *column_l, *del_bt, *title_te, *fmt_m, *up_bt, *dn_bt;
static gint       cur_fmt, cur_row;

#if GTK_MAJOR_VERSION < 2
static void   column_list_select_cb(GtkCList *clist, gint row, gint column,
                                    GdkEvent *event, gpointer user_data);
static void   column_list_unselect_cb(GtkCList *clist, gint row, gint column,
                                      GdkEvent *event, gpointer user_data);
#else
static void   column_list_select_cb(GtkTreeSelection *, gpointer);
#endif
static void   column_list_new_cb(GtkWidget *, gpointer);
static void   column_entry_changed_cb(GtkEditable *, gpointer);
static void   column_menu_changed_cb(GtkWidget *, gpointer);
static void   column_list_delete_cb(GtkWidget *, gpointer);
static void   column_arrow_cb(GtkWidget *, gpointer);
void          column_set_arrow_button_sensitivity(GList *);

#if GTK_MAJOR_VERSION >= 2
#define E_COL_NAME_KEY "column_name"
#define E_COL_LBL_KEY  "column_label"
#endif
#define E_COL_CM_KEY   "in_col_cancel_mode"

/* Create and display the column selection widgets. */
/* Called when the 'Columns' preference notebook page is selected. */
GtkWidget *
column_prefs_show() {
  GtkWidget         *main_vb, *top_hb, *list_bb, *new_bt, *column_sc,
                    *tb, *lb, *menu, *mitem, *arrow_hb;
  GList             *clp = NULL;
  fmt_data          *cfmt;
  gint               i;
  gchar             *column_titles[] = {"Title", "Format"};
#if GTK_MAJOR_VERSION < 2
  gchar             *col_ent[2];
  gint               row;
#else
  GtkListStore      *store;
  GtkCellRenderer   *renderer;
  GtkTreeViewColumn *column;
  GtkTreeSelection  *sel;
  GtkTreeIter        iter;
#endif

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_widget_show(main_vb);
  gtk_object_set_data(GTK_OBJECT(main_vb), E_COL_CM_KEY, (gpointer)FALSE);

  /* Top row: Column list and buttons */
  top_hb = gtk_hbox_new(FALSE, 5);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);

  list_bb = gtk_vbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (list_bb), GTK_BUTTONBOX_START);
  gtk_container_add(GTK_CONTAINER(top_hb), list_bb);
  gtk_widget_show(list_bb);

#if GTK_MAJOR_VERSION < 2
  new_bt = gtk_button_new_with_label ("Add New");
  gtk_signal_connect(GTK_OBJECT(new_bt), "clicked",
                     GTK_SIGNAL_FUNC(column_list_new_cb), NULL);
#else
  new_bt = gtk_button_new_from_stock(GTK_STOCK_NEW);
  g_signal_connect(G_OBJECT(new_bt), "clicked",
                   G_CALLBACK(column_list_new_cb), NULL);
#endif
  gtk_container_add(GTK_CONTAINER(list_bb), new_bt);
  gtk_widget_show(new_bt);

#if GTK_MAJOR_VERSION < 2
  del_bt = gtk_button_new_with_label ("Delete");
  gtk_widget_set_sensitive(del_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(del_bt), "clicked",
                     GTK_SIGNAL_FUNC(column_list_delete_cb), NULL);
#else
  del_bt = gtk_button_new_from_stock(GTK_STOCK_DELETE);
  gtk_widget_set_sensitive(del_bt, FALSE);
  g_signal_connect(G_OBJECT(del_bt), "clicked",
                   G_CALLBACK(column_list_delete_cb), NULL);
#endif
  gtk_container_add(GTK_CONTAINER(list_bb), del_bt);
  gtk_widget_show(del_bt);

  arrow_hb = gtk_hbox_new(TRUE, 3);
  gtk_container_add(GTK_CONTAINER(list_bb), arrow_hb);
  gtk_widget_show(arrow_hb);

#if GTK_MAJOR_VERSION < 2
  up_bt = gtk_button_new_with_label("Up");
  gtk_widget_set_sensitive(up_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(up_bt), "clicked",
                     GTK_SIGNAL_FUNC(column_arrow_cb), NULL);
#else
  up_bt = gtk_button_new_from_stock(GTK_STOCK_GO_UP);
  gtk_widget_set_sensitive(up_bt, FALSE);
  g_signal_connect(G_OBJECT(up_bt), "clicked",
                   G_CALLBACK(column_arrow_cb), NULL);
#endif
  gtk_box_pack_start(GTK_BOX(arrow_hb), up_bt, TRUE, TRUE, 0);
  gtk_widget_show(up_bt);

#if GTK_MAJOR_VERSION < 2
  dn_bt = gtk_button_new_with_label("Down");
  gtk_widget_set_sensitive(dn_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(dn_bt), "clicked",
                     GTK_SIGNAL_FUNC(column_arrow_cb), NULL);
#else
  dn_bt = gtk_button_new_from_stock(GTK_STOCK_GO_DOWN);
  gtk_widget_set_sensitive(dn_bt, FALSE);
  g_signal_connect(G_OBJECT(dn_bt), "clicked",
                   G_CALLBACK(column_arrow_cb), NULL);
#endif
  gtk_box_pack_start(GTK_BOX(arrow_hb), dn_bt, TRUE, TRUE, 0);
  gtk_widget_show(dn_bt);

  column_sc = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(column_sc),
                                 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
#if GTK_MAJOR_VERSION < 2
  gtk_widget_set_usize(column_sc, 250, 150);
#else
  gtk_widget_set_size_request(column_sc, 250, 150);
#endif
  gtk_container_add(GTK_CONTAINER(top_hb), column_sc);
  gtk_widget_show(column_sc);

#if GTK_MAJOR_VERSION < 2
  column_l = gtk_clist_new_with_titles(2, column_titles);
  /* XXX - make this match the packet list prefs? */
  gtk_clist_set_selection_mode(GTK_CLIST(column_l), GTK_SELECTION_SINGLE);
  gtk_clist_column_titles_passive(GTK_CLIST(column_l));
  gtk_clist_column_titles_show(GTK_CLIST(column_l));
  gtk_clist_set_column_auto_resize(GTK_CLIST(column_l), 0, TRUE);
  gtk_clist_set_column_auto_resize(GTK_CLIST(column_l), 1, TRUE);

  gtk_signal_connect(GTK_OBJECT(column_l), "select-row",
                     GTK_SIGNAL_FUNC(column_list_select_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(column_l), "unselect-row",
                     GTK_SIGNAL_FUNC(column_list_unselect_cb), NULL);
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(column_sc),
                                        column_l);
#else
  store = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);
  column_l = tree_view_new(GTK_TREE_MODEL(store));
  gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(column_l), TRUE);
  gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(column_l), FALSE);
  renderer = gtk_cell_renderer_text_new();
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

  g_signal_connect(G_OBJECT(sel), "changed", G_CALLBACK(column_list_select_cb),
                   NULL);
  gtk_container_add(GTK_CONTAINER(column_sc), column_l);
#endif
  gtk_widget_show(column_l);

  clp = g_list_first(prefs.col_list);
  while (clp) {
    cfmt    = (fmt_data *) clp->data;
#if GTK_MAJOR_VERSION < 2
    col_ent[0] = cfmt->title;
    col_ent[1] = col_format_desc(get_column_format_from_str(cfmt->fmt));
    row = gtk_clist_append(GTK_CLIST(column_l), col_ent);
    gtk_clist_set_row_data(GTK_CLIST(column_l), row, clp);
#else
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, 0, cfmt->title, 1,
                       col_format_desc(get_column_format_from_str(cfmt->fmt)),
                       2, clp, -1);
#endif
    clp = clp->next;
  }
#if GTK_MAJOR_VERSION >= 2
  g_object_unref(G_OBJECT(store));
#endif
  /* Colunm name entry and format selection */
  tb = gtk_table_new(2, 2, FALSE);
  gtk_container_add(GTK_CONTAINER(main_vb), tb);
  gtk_table_set_row_spacings(GTK_TABLE(tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(tb), 15);
  gtk_widget_show(tb);

  lb = gtk_label_new("Column title:");
  gtk_misc_set_alignment(GTK_MISC(lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(tb), lb, 0, 1, 0, 1);
  gtk_widget_show(lb);

  title_te = gtk_entry_new();
  gtk_table_attach_defaults(GTK_TABLE(tb), title_te, 1, 2, 0, 1);
#if GTK_MAJOR_VERSION < 2
  gtk_signal_connect(GTK_OBJECT(title_te), "changed",
                     GTK_SIGNAL_FUNC(column_entry_changed_cb), column_l);
#else
  g_signal_connect(G_OBJECT(title_te), "changed",
                   G_CALLBACK(column_entry_changed_cb), column_l);
#endif
  gtk_widget_set_sensitive(title_te, FALSE);
  gtk_widget_show(title_te);

  lb = gtk_label_new("Column format:");
  gtk_misc_set_alignment(GTK_MISC(lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(tb), lb, 0, 1, 1, 2);
  gtk_widget_show(lb);

  top_hb = gtk_hbox_new(FALSE, 5);
  gtk_table_attach(GTK_TABLE(tb), top_hb, 1, 2, 1, 2, GTK_FILL,
                   GTK_SHRINK, 0, 0);
  gtk_widget_show(top_hb);

  fmt_m = gtk_option_menu_new();
  menu  = gtk_menu_new();
  for (i = 0; i < NUM_COL_FMTS; i++) {
    mitem = gtk_menu_item_new_with_label(col_format_desc(i));
    gtk_menu_append(GTK_MENU(menu), mitem);
#if GTK_MAJOR_VERSION < 2
    gtk_signal_connect(GTK_OBJECT(mitem), "activate",
                       GTK_SIGNAL_FUNC(column_menu_changed_cb), (gpointer) i);
#else
    g_signal_connect(G_OBJECT(mitem), "activate",
                     G_CALLBACK(column_menu_changed_cb), (gpointer) i);
#endif
    gtk_widget_show(mitem);
  }
  gtk_option_menu_set_menu(GTK_OPTION_MENU(fmt_m), menu);
  cur_fmt = 0;
  gtk_option_menu_set_history(GTK_OPTION_MENU(fmt_m), cur_fmt);
  gtk_widget_set_sensitive(fmt_m, FALSE);
  gtk_box_pack_start(GTK_BOX(top_hb), fmt_m, FALSE, FALSE, 0);
  gtk_widget_show(fmt_m);

  return(main_vb);
}

/* For each selection, set the entry and option menu widgets to match
   the currently selected item.  Set the up/down button sensitivity.
   Draw focus to the entry widget. */
#if GTK_MAJOR_VERSION < 2
static void
column_list_select_cb(GtkCList *clist,
                   gint      row,
                   gint      column _U_,
                   GdkEvent *event _U_,
                   gpointer  user_data _U_) {
  fmt_data   *cfmt;
  GList      *clp;

  clp = gtk_clist_get_row_data(clist, row);
  g_assert(clp != NULL);
  cfmt   = (fmt_data *) clp->data;
  cur_fmt = get_column_format_from_str(cfmt->fmt);
  g_assert(cur_fmt != -1);	/* It should always be valid */
  cur_row = row;

  gtk_entry_set_text(GTK_ENTRY(title_te), cfmt->title);
  gtk_editable_select_region(GTK_EDITABLE(title_te), 0, -1);
  gtk_widget_grab_focus(title_te);

  gtk_option_menu_set_history(GTK_OPTION_MENU(fmt_m), cur_fmt);

  gtk_widget_set_sensitive(del_bt, TRUE);
  gtk_widget_set_sensitive(title_te, TRUE);
  gtk_widget_set_sensitive(fmt_m, TRUE);
  column_set_arrow_button_sensitivity(clp);
}

/* A row was deselected.  Clear the text entry box and disable various widgets. */
static void
column_list_unselect_cb(GtkCList *clist _U_,
                   gint      row _U_,
                   gint      column _U_,
                   GdkEvent *event _U_,
                   gpointer  user_data _U_) {

  cur_row = -1;
  gtk_editable_delete_text(GTK_EDITABLE(title_te), 0, -1);

  gtk_widget_set_sensitive(del_bt, FALSE);
  gtk_widget_set_sensitive(title_te, FALSE);
  gtk_widget_set_sensitive(fmt_m, FALSE);
  gtk_widget_set_sensitive(up_bt, FALSE);
  gtk_widget_set_sensitive(dn_bt, FALSE);
}
#else
static void
column_list_select_cb(GtkTreeSelection *sel, gpointer  user_data _U_)
{
    fmt_data     *cfmt;
    GList        *clp;
    GtkTreeModel *model;
    GtkTreeIter   iter;
    GtkTreePath  *path;
    gchar        *str_path;
    gchar        *title;

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

        title = g_strdup(cfmt->title);
        gtk_entry_set_text(GTK_ENTRY(title_te), title);
        g_free(title);

        gtk_editable_select_region(GTK_EDITABLE(title_te), 0, -1);
        gtk_widget_grab_focus(title_te);

        gtk_option_menu_set_history(GTK_OPTION_MENU(fmt_m), cur_fmt);

        gtk_widget_set_sensitive(del_bt, TRUE);
        gtk_widget_set_sensitive(title_te, TRUE);
        gtk_widget_set_sensitive(fmt_m, TRUE);
        column_set_arrow_button_sensitivity(clp);
    }
    else
    {
        cur_row = -1;
        gtk_editable_delete_text(GTK_EDITABLE(title_te), 0, -1);

        gtk_widget_set_sensitive(del_bt, FALSE);
        gtk_widget_set_sensitive(title_te, FALSE);
        gtk_widget_set_sensitive(fmt_m, FALSE);
        gtk_widget_set_sensitive(up_bt, FALSE);
        gtk_widget_set_sensitive(dn_bt, FALSE);
    }
}
#endif

/* To do: add input checking to each of these callbacks */

static void
column_list_new_cb(GtkWidget *w _U_, gpointer data _U_) {
    fmt_data     *cfmt;
    gchar        *title = "New Column";
#if GTK_MAJOR_VERSION < 2
    gchar        *col_ent[2];
#else
    GtkTreeModel *model;
    GtkTreeIter   iter;
    GtkTreePath  *path;
    gchar        *str_path;
#endif

    cur_fmt        = 0;
    cfmt           = (fmt_data *) g_malloc(sizeof(fmt_data));
    cfmt->title    = g_strdup(title);
    cfmt->fmt      = g_strdup(col_format_to_string(cur_fmt));
    prefs.col_list = g_list_append(prefs.col_list, cfmt);

#if GTK_MAJOR_VERSION < 2
    col_ent[0] = title;
    col_ent[1] = col_format_desc(cur_fmt);
    cur_row = gtk_clist_append(GTK_CLIST(column_l), col_ent);
    gtk_clist_set_row_data(GTK_CLIST(column_l), cur_row,
                           g_list_last(prefs.col_list));

    gtk_clist_select_row(GTK_CLIST(column_l), cur_row, 0);
#else
    model = gtk_tree_view_get_model(GTK_TREE_VIEW(column_l));
    gtk_list_store_append(GTK_LIST_STORE(model), &iter);
    gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, title, 1,
                       col_format_desc(cur_fmt), 2, g_list_last(prefs.col_list),
                       -1);

    path = gtk_tree_model_get_path(model, &iter);
    str_path = gtk_tree_path_to_string(path);
    cur_row = atoi(str_path);
    g_free(str_path);
    gtk_tree_path_free(path);

    gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(column_l)),
                                   &iter);
#endif
}

static void
column_list_delete_cb(GtkWidget *w _U_, gpointer data _U_) {
    GList            *clp;
    fmt_data         *cfmt;
#if GTK_MAJOR_VERSION >= 2
    GtkTreeSelection *sel;
    GtkTreeModel     *model;
    GtkTreeIter       iter;

    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(column_l));
    if (gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        gtk_tree_model_get(model, &iter, 2, &clp, -1);

        cfmt = (fmt_data *) clp->data;
        g_free(cfmt->title);
        g_free(cfmt->fmt);
        g_free(cfmt);
        prefs.col_list = g_list_remove_link(prefs.col_list, clp);

        gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
    }
#else
    g_assert(cur_row >= 0);
    clp = gtk_clist_get_row_data(GTK_CLIST(column_l), cur_row);

    cfmt = (fmt_data *) clp->data;
    g_free(cfmt->title);
    g_free(cfmt->fmt);
    g_free(cfmt);
    prefs.col_list = g_list_remove_link(prefs.col_list, clp);

    gtk_clist_remove(GTK_CLIST(column_l), cur_row);
#endif
}

/* The user changed the column title entry box. */
static void
column_entry_changed_cb(GtkEditable *te, gpointer data) {
    fmt_data         *cfmt;
    GList            *clp;
    gchar            *title;
#if GTK_MAJOR_VERSION < 2
    GtkCList         *cl = data;

    if (cur_row >= 0) {
        title = gtk_editable_get_chars(te, 0, -1);
        clp   = gtk_clist_get_row_data(cl, cur_row);
        cfmt  = (fmt_data *) clp->data;

        gtk_clist_set_text(cl, cur_row, 0, title);
        g_free(cfmt->title);
        cfmt->title = title;
    }
#else
    GtkTreeView      *tree = (GtkTreeView *)data;
    GtkTreeSelection *sel;
    GtkTreeModel     *model;
    GtkTreeIter       iter;

    sel = gtk_tree_view_get_selection(tree);
    if (gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        title = gtk_editable_get_chars(te, 0, -1);
        gtk_tree_model_get(model, &iter, 2, &clp, -1);
        cfmt  = (fmt_data *) clp->data;

        gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, title, -1);
        g_free(cfmt->title);
        cfmt->title = title;
    }
#endif
}

/* The user changed the format menu. */
static void
column_menu_changed_cb(GtkWidget *w _U_, gpointer data) {
    fmt_data         *cfmt;
    GList            *clp;
#if GTK_MAJOR_VERSION >= 2
    GtkTreeSelection *sel;
    GtkTreeModel     *model;
    GtkTreeIter       iter;

    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(column_l));
    if (gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        cur_fmt = (gint) data;
        gtk_tree_model_get(model, &iter, 2, &clp, -1);
        cfmt    = (fmt_data *) clp->data;

        gtk_list_store_set(GTK_LIST_STORE(model), &iter, 1,
                           col_format_desc(cur_fmt), -1);
        g_free(cfmt->fmt);
        cfmt->fmt = g_strdup(col_format_to_string(cur_fmt));
    }
#else

    if (cur_row >= 0) {
        cur_fmt = (gint) data;
        clp     = gtk_clist_get_row_data(GTK_CLIST(column_l), cur_row);
        cfmt    = (fmt_data *) clp->data;

        gtk_clist_set_text(GTK_CLIST(column_l), cur_row, 1,
                           col_format_desc(cur_fmt));
        g_free(cfmt->fmt);
        cfmt->fmt = g_strdup(col_format_to_string(cur_fmt));
    }
#endif
}

static void
column_arrow_cb(GtkWidget *w, gpointer data _U_) {
    fmt_data         *cfmt;
#if GTK_MAJOR_VERSION < 2
    GList            *clp;
    gint              inc = 1;

    g_assert(cur_row >= 0);

    if (w == up_bt)
        inc = -1;

    /* This would end up appending to the list.  We shouldn't have to check for
       appending past the end of the list. */
    g_assert((cur_row + inc) >= 0);

    clp = gtk_clist_get_row_data(GTK_CLIST(column_l), cur_row);
    cfmt = (fmt_data *) clp->data;
    prefs.col_list = g_list_remove(prefs.col_list, cfmt);
    prefs.col_list = g_list_insert(prefs.col_list, cfmt, cur_row + inc);

    gtk_clist_row_move(GTK_CLIST(column_l), cur_row, cur_row + inc);
    clp = g_list_find(prefs.col_list, cfmt);
    cur_row += inc;
    gtk_clist_set_row_data(GTK_CLIST(column_l), cur_row, clp);

    column_set_arrow_button_sensitivity(clp);
#else
    GList            *clp1, *clp2;
    GtkTreeSelection *sel;
    GtkTreeModel     *model;
    GtkTreeIter       iter1, iter2;
    GtkTreePath      *path;
    gchar            *title1, *format1, *title2, *format2;

    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(column_l));
    if (gtk_tree_selection_get_selected(sel, &model, &iter1))
    {
        gtk_tree_model_get(model, &iter1, 0, &title1,
                           1, &format1, 2, &clp1, -1);
        cfmt = (fmt_data *)clp1->data;
        prefs.col_list = g_list_remove(prefs.col_list, cfmt);

        if (w == up_bt)
        {
            cur_row--;
            prefs.col_list = g_list_insert(prefs.col_list, cfmt, cur_row);
            path = gtk_tree_model_get_path(model, &iter1);
            gtk_tree_path_prev(path);
            if (!gtk_tree_model_get_iter(model, &iter2, path))
            {
                gtk_tree_path_free(path);
                return;
            }
            gtk_tree_path_free(path);
        }
        else
        {
            cur_row++;
            prefs.col_list = g_list_insert(prefs.col_list, cfmt, cur_row);
            iter2 = iter1;
            if (!gtk_tree_model_iter_next(model, &iter2))
            {
                return;
            }
        }
        gtk_tree_model_get(model, &iter2, 0, &title2, 1, &format2, 2,
                           &clp2, -1);
        gtk_list_store_set(GTK_LIST_STORE(model), &iter2, 0, title1, 1,
                           format1, 2, clp1, -1);
        gtk_list_store_set(GTK_LIST_STORE(model), &iter1, 0, title2, 1,
                           format2, 2, clp2, -1);
        gtk_tree_selection_select_iter(sel, &iter2);
        /* clp1 = g_list_find(prefs.col_list, cfmt); */
        column_set_arrow_button_sensitivity(clp1);

        /* free strings read from the TreeModel */
        g_free(title1);
        g_free(format1);
        g_free(title2);
        g_free(format2);
    }
#endif
}

void
column_set_arrow_button_sensitivity(GList *clp) {
    gint up_sens = FALSE, dn_sens = FALSE;

    if (clp != g_list_first(prefs.col_list))
        up_sens = TRUE;
    if (clp != g_list_last(prefs.col_list))
        dn_sens = TRUE;

    gtk_widget_set_sensitive(up_bt, up_sens);
    gtk_widget_set_sensitive(dn_bt, dn_sens);
}

void
column_prefs_fetch(GtkWidget *w _U_) {
}

void
column_prefs_apply(GtkWidget *w _U_) {
}

void
column_prefs_destroy(GtkWidget *w) {
    /* Let the list cb know we're about to destroy the widget tree, so it */
    /* doesn't operate on widgets that don't exist. */
    gtk_object_set_data(GTK_OBJECT(w), E_COL_CM_KEY, (gpointer)TRUE);
    gtk_widget_destroy(GTK_WIDGET(w));
}
