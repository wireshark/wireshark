/* column_prefs.c
 * Dialog box for column preferences
 *
 * $Id: column_prefs.c,v 1.13 2002/09/05 18:47:45 jmayer Exp $
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

static GtkWidget *column_l, *del_bt, *title_te, *fmt_m, *up_bt, *dn_bt;
static gint       cur_fmt, cur_row;

static void   column_list_select_cb(GtkCList *clist, gint row, gint column,
				 GdkEvent *event, gpointer user_data);
static void   column_list_unselect_cb(GtkCList *clist, gint row, gint column,
				 GdkEvent *event, gpointer user_data);
static void   column_list_new_cb(GtkWidget *, gpointer);
static void   column_entry_changed_cb(GtkEditable *, gpointer);
static void   column_menu_changed_cb(GtkWidget *, gpointer);
static void   column_list_delete_cb(GtkWidget *, gpointer);
static void   column_arrow_cb(GtkWidget *, gpointer);
void          column_set_arrow_button_sensitivity(GList *);

#define E_COL_CM_KEY   "in_col_cancel_mode"

/* Create and display the column selection widgets. */
/* Called when the 'Columns' preference notebook page is selected. */
GtkWidget *
column_prefs_show() {
  GtkWidget   *main_vb, *top_hb, *list_bb, *new_bt, *column_sc,
              *tb, *lb, *menu, *mitem, *arrow_hb;
  GList       *clp = NULL;
  fmt_data    *cfmt;
  gint         i, row;
  gchar       *column_titles[] = {"Title", "Format"}, *col_ent[2];

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

  new_bt = gtk_button_new_with_label ("Add New");
  gtk_signal_connect(GTK_OBJECT(new_bt), "clicked",
    GTK_SIGNAL_FUNC(column_list_new_cb), NULL);
  gtk_container_add(GTK_CONTAINER(list_bb), new_bt);
  gtk_widget_show(new_bt);

  del_bt = gtk_button_new_with_label ("Delete");
  gtk_widget_set_sensitive(del_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(del_bt), "clicked",
    GTK_SIGNAL_FUNC(column_list_delete_cb), NULL);
  gtk_container_add(GTK_CONTAINER(list_bb), del_bt);
  gtk_widget_show(del_bt);

  arrow_hb = gtk_hbox_new(TRUE, 3);
  gtk_container_add(GTK_CONTAINER(list_bb), arrow_hb);
  gtk_widget_show(arrow_hb);

  up_bt = gtk_button_new_with_label("Up");
  gtk_widget_set_sensitive(up_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(up_bt), "clicked",
    GTK_SIGNAL_FUNC(column_arrow_cb), NULL);
  gtk_box_pack_start(GTK_BOX(arrow_hb), up_bt, TRUE, TRUE, 0);
  gtk_widget_show(up_bt);

  dn_bt = gtk_button_new_with_label("Down");
  gtk_widget_set_sensitive(dn_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(dn_bt), "clicked",
    GTK_SIGNAL_FUNC(column_arrow_cb), NULL);
  gtk_box_pack_start(GTK_BOX(arrow_hb), dn_bt, TRUE, TRUE, 0);
  gtk_widget_show(dn_bt);

  column_sc = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(column_sc),
    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_widget_set_usize(column_sc, 250, 150);
  gtk_container_add(GTK_CONTAINER(top_hb), column_sc);
  gtk_widget_show(column_sc);

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
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(column_sc), column_l);
  gtk_widget_show(column_l);

  clp = g_list_first(prefs.col_list);
  while (clp) {
    cfmt    = (fmt_data *) clp->data;
    col_ent[0] = cfmt->title;
    col_ent[1] = col_format_desc(get_column_format_from_str(cfmt->fmt));
    row = gtk_clist_append(GTK_CLIST(column_l), col_ent);
    gtk_clist_set_row_data(GTK_CLIST(column_l), row, clp);
    clp = clp->next;
  }

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
  gtk_signal_connect(GTK_OBJECT(title_te), "changed",
    GTK_SIGNAL_FUNC(column_entry_changed_cb), column_l);
  gtk_widget_set_sensitive(title_te, FALSE);
  gtk_widget_show(title_te);

  lb = gtk_label_new("Column format:");
  gtk_misc_set_alignment(GTK_MISC(lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(tb), lb, 0, 1, 1, 2);
  gtk_widget_show(lb);

  top_hb = gtk_hbox_new(FALSE, 5);
  gtk_table_attach(GTK_TABLE(tb), top_hb, 1, 2, 1, 2, GTK_FILL, GTK_SHRINK, 0, 0);
  gtk_widget_show(top_hb);

  fmt_m = gtk_option_menu_new();
  menu  = gtk_menu_new();
  for (i = 0; i < NUM_COL_FMTS; i++) {
    mitem = gtk_menu_item_new_with_label(col_format_desc(i));
    gtk_menu_append(GTK_MENU(menu), mitem);
    gtk_signal_connect( GTK_OBJECT(mitem), "activate",
      GTK_SIGNAL_FUNC(column_menu_changed_cb), (gpointer) i);
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

/* To do: add input checking to each of these callbacks */

static void
column_list_new_cb(GtkWidget *w _U_, gpointer data _U_) {
  fmt_data   *cfmt;
  gchar      *title = "New Column", *col_ent[2];

  cur_fmt        = 0;
  cfmt           = (fmt_data *) g_malloc(sizeof(fmt_data));
  cfmt->title    = g_strdup(title);
  cfmt->fmt      = g_strdup(col_format_to_string(cur_fmt));
  prefs.col_list = g_list_append(prefs.col_list, cfmt);

  col_ent[0] = title;
  col_ent[1] = col_format_desc(cur_fmt);
  cur_row = gtk_clist_append(GTK_CLIST(column_l), col_ent);
  gtk_clist_set_row_data(GTK_CLIST(column_l), cur_row, g_list_last(prefs.col_list));

  gtk_clist_select_row(GTK_CLIST(column_l), cur_row, 0);
}

static void
column_list_delete_cb(GtkWidget *w _U_, gpointer data _U_) {
  GList      *clp;
  fmt_data   *cfmt;

  g_assert(cur_row >= 0);
  clp = gtk_clist_get_row_data(GTK_CLIST(column_l), cur_row);

  cfmt = (fmt_data *) clp->data;
  g_free(cfmt->title);
  g_free(cfmt->fmt);
  g_free(cfmt);
  prefs.col_list = g_list_remove_link(prefs.col_list, clp);

  gtk_clist_remove(GTK_CLIST(column_l), cur_row);
}

/* The user changed the column title entry box. */
static void
column_entry_changed_cb(GtkEditable *te, gpointer data) {
  fmt_data   *cfmt;
  GList      *clp;
  GtkCList   *cl = data;
  gchar      *title;

  if (cur_row >= 0) {
    title = gtk_editable_get_chars(te, 0, -1);
    clp   = gtk_clist_get_row_data(cl, cur_row);
    cfmt  = (fmt_data *) clp->data;

    gtk_clist_set_text(cl, cur_row, 0, title);
    g_free(cfmt->title);
    cfmt->title = title;
  }
}

/* The user changed the format menu. */
static void
column_menu_changed_cb(GtkWidget *w _U_, gpointer data) {
  fmt_data   *cfmt;
  GList      *clp;

  if (cur_row >= 0) {
    cur_fmt = (gint) data;
    clp     = gtk_clist_get_row_data(GTK_CLIST(column_l), cur_row);
    cfmt    = (fmt_data *) clp->data;

    gtk_clist_set_text(GTK_CLIST(column_l), cur_row, 1, col_format_desc(cur_fmt));
    g_free(cfmt->fmt);
    cfmt->fmt = g_strdup(col_format_to_string(cur_fmt));
  }
}

static void
column_arrow_cb(GtkWidget *w, gpointer data _U_) {
  GList      *clp;
  fmt_data   *cfmt;
  gint        inc = 1;

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
}

void
column_set_arrow_button_sensitivity(GList *clp) {
  gint        up_sens = FALSE, dn_sens = FALSE;

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
