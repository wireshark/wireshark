/* color_dlg.c
 * Definitions for dialog boxes for color filters
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
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <string.h>

#include "gtk/main.h"
#include <epan/packet.h>
#include "color.h"
#include "colors.h"
#include "color_filters.h"
#include "color_dlg.h"
#include "file.h"
#include <epan/dfilter/dfilter.h>
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "dfilter_expr_dlg.h"
#include "compat_macros.h"
#include "filter_dlg.h"
#include "capture_file_dlg.h"
#include "gtkglobals.h"
#include <epan/prefs.h>
#include "help_dlg.h"

#include "color_edit_dlg.h"

/* XXX - ugly workaround for bug #699 */
/* the "Up"/"Down" buttons of the GTK2.x version doesn't work properly */
/* simply use the GTK1.x version of this dialog for now ... */
#if GTK_MAJOR_VERSION >= 2
#undef GTK_MAJOR_VERSION
#define GTK_MAJOR_VERSION 1
#define BUTTON_SIZE_X -1
#define BUTTON_SIZE_Y -1
#else
#define BUTTON_SIZE_X 50
#define BUTTON_SIZE_Y 20
#endif
/* XXX - ugly workaround for bug #699 */


static GtkWidget* colorize_dialog_new(char *filter);
static void add_filter_to_list(gpointer filter_arg, gpointer list_arg);
static void color_filter_up_cb(GtkButton *button, gpointer user_data);
static void color_filter_down_cb(GtkButton *button, gpointer user_data);
#if GTK_MAJOR_VERSION < 2
static void remember_selected_row(GtkCList *clist, gint row, gint column,
                                  GdkEvent *event, gpointer user_data);
static void unremember_selected_row(GtkCList *clist, gint row, gint column,
                                    GdkEvent *event, gpointer user_data);
#else
static void remember_selected_row(GtkTreeSelection *sel, gpointer list);
#endif
static void color_destroy_cb(GtkButton *button, gpointer user_data);
static void destroy_edit_dialog_cb(gpointer filter_arg, gpointer dummy);
static void create_new_color_filter(GtkButton *button, const char *filter);
static void color_new_cb(GtkButton *button, gpointer user_data);
static void color_edit_cb(GtkButton *button, gpointer user_data);
static void color_delete_cb(GtkWidget *widget, gpointer user_data);
static void color_save_cb(GtkButton *button, gpointer user_data);
static void color_ok_cb(GtkButton *button, gpointer user_data);
static void color_cancel_cb(GtkWidget *widget, gpointer user_data);
static void color_apply_cb(GtkButton *button, gpointer user_data);
static void color_clear_cb(GtkWidget *button, gpointer user_data);
static void color_export_cb(GtkButton *button, gpointer user_data );
static void color_import_cb(GtkButton *button, gpointer user_data );

static GtkWidget* color_sel_win_new(color_filter_t *colorf, gboolean);
static void color_sel_ok_cb(GtkButton *button, gpointer user_data);
static void color_sel_cancel_cb(GtkObject *object, gpointer user_data);


static GtkWidget *colorize_win;
gint	  num_of_filters;  /* number of filters being displayed */
gint	  row_selected;	   /* row in color_filters that is selected */

/* This is a list of all current color filters in the dialog
 * (copied from color_filters.c and edited with the dialog).
 * The color filter items are not identical to the ones used for the 
 * packet list display, so they can be safely edited.
 *
 * XXX - use the existing GTK list for this purpose and build temporary copies
 * e.g. for the save/export functions.
 * Problem: Don't know when able to safely throw away, e.g. while exporting.
 */
static GSList *color_filter_edit_list = NULL;


#define COLOR_UP_LB		"color_up_lb"
#define COLOR_DOWN_LB		"color_down_lb"
#define COLOR_EDIT_LB		"color_edit_lb"
#define COLOR_DELETE_LB		"color_delete_lb"
#define COLOR_FILTERS_CL	"color_filters_cl"
#define COLOR_FILTER_LIST       "color_filter_list"


/* Callback for the "Display:Coloring Rules" menu item. */
void
color_display_cb(GtkWidget *w _U_, gpointer d _U_)
{
  if (colorize_win != NULL) {
    /* There's already a color dialog box active; reactivate it. */
    reactivate_window(colorize_win);
  } else {
    /* Create a new "Colorize Display" dialog. */
    colorize_win = colorize_dialog_new(NULL);
  }
}

/* this opens the color dialog and presets the filter string */
void
color_display_with_filter(char *filter)
{
  if (colorize_win != NULL) {
    /* There's already a color dialog box active; reactivate it. */
    reactivate_window(colorize_win);
  } else {
    /* Create a new "Colorize Display" dialog. */
    colorize_win = colorize_dialog_new(filter);
  }
}

/* if this filter is selected - count it in the given int* */
static void
count_this_select(gpointer filter_arg, gpointer counter_arg)
{
  color_filter_t *colorf = filter_arg;
  int * cnt = counter_arg;

  if (colorf->selected)
    (*cnt)++;
}

/* TODO: implement count of selected filters. Plug in to file_dlg update of "export selected" checkbox. */
int color_selected_count(void)
{
  int count = 0;

  g_slist_foreach(color_filter_edit_list, count_this_select, &count);

  return count;
}

/* Create the "Coloring Rules" dialog. */
static GtkWidget*
colorize_dialog_new (char *filter)
{
  GtkWidget *color_win;
  GtkWidget *dlg_vbox;
  GtkWidget *main_hbox;
  GtkWidget *ctrl_vbox;
  GtkTooltips *tooltips;

  GtkWidget *order_fr;
  GtkWidget *order_vbox;
  GtkWidget *color_filter_up;
  GtkWidget *order_move_label;
  GtkWidget *color_filter_down;

  GtkWidget *list_fr;
  GtkWidget *list_vbox;
  GtkWidget *scrolledwindow1;
  GtkWidget *color_filters;
  GtkWidget *list_label;

  GtkWidget *edit_fr;
  GtkWidget *edit_vbox;
  GtkWidget *color_new;
  GtkWidget *color_edit;
  GtkWidget *color_delete;

  GtkWidget *manage_fr;
  GtkWidget *manage_vbox;
  GtkWidget *color_export;
  GtkWidget *color_import;
  GtkWidget *color_clear;

  GtkWidget *button_ok_hbox;
  GtkWidget *color_ok;
  GtkWidget *color_apply;
  GtkWidget *color_save;
  GtkWidget *color_cancel;
  GtkWidget *color_help;

#if GTK_MAJOR_VERSION >= 2
  GtkListStore      *store;
  GtkCellRenderer   *renderer;
  GtkTreeViewColumn *column;
  GtkTreeSelection  *selection;
#endif
  const gchar *titles[] = { "Name", "String" };



  num_of_filters = 0;
  row_selected = -1; /* no row selected */
  tooltips = gtk_tooltips_new ();

  /* Resizing of the dialog window is now reasonably done.
   * Default size is set so that it should fit into every usual screen resolution.
   * All other widgets are always packed depending on the current window size. */
  color_win = dlg_window_new ("Wireshark: Coloring Rules");
  OBJECT_SET_DATA(color_win, "color_win", color_win);
  gtk_window_set_default_size(GTK_WINDOW(color_win), DEF_WIDTH, DEF_HEIGHT * 2/3);
  dlg_vbox = gtk_vbox_new (FALSE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (dlg_vbox), 5);
  gtk_container_add (GTK_CONTAINER (color_win), dlg_vbox);

  main_hbox = gtk_hbox_new (FALSE, 0);
  gtk_box_pack_start (GTK_BOX (dlg_vbox), main_hbox, TRUE, TRUE, 0);

  ctrl_vbox = gtk_vbox_new (FALSE, 0);
  gtk_box_pack_start (GTK_BOX (main_hbox), ctrl_vbox, FALSE, FALSE, 0);

  /* edit buttons frame */
  edit_fr = gtk_frame_new("Edit");
  gtk_box_pack_start (GTK_BOX (ctrl_vbox), edit_fr, TRUE, TRUE, 0);

  /* edit_vbox is first button column (containing: new, edit and such) */
  edit_vbox = gtk_vbutton_box_new();
  gtk_button_box_set_child_size(GTK_BUTTON_BOX(edit_vbox), BUTTON_SIZE_X, BUTTON_SIZE_Y);
  gtk_container_set_border_width  (GTK_CONTAINER (edit_vbox), 5);
  gtk_container_add(GTK_CONTAINER(edit_fr), edit_vbox);

  color_new = BUTTON_NEW_FROM_STOCK(GTK_STOCK_NEW);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_new, BUTTON_SIZE_X, BUTTON_SIZE_Y);
#endif
  gtk_box_pack_start (GTK_BOX (edit_vbox), color_new, FALSE, FALSE, 5);
  gtk_tooltips_set_tip (tooltips, color_new, ("Create a new filter at the end of the list"), NULL);

  color_edit = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_EDIT);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_edit, BUTTON_SIZE_X, BUTTON_SIZE_Y);
#endif
  gtk_box_pack_start (GTK_BOX (edit_vbox), color_edit, FALSE, FALSE, 5);
  gtk_tooltips_set_tip (tooltips, color_edit, ("Edit the properties of the selected filter."
      " If more than one filter is selected, edit the first selected one"), NULL);
  gtk_widget_set_sensitive (color_edit, FALSE);

  color_delete = BUTTON_NEW_FROM_STOCK(GTK_STOCK_DELETE);
  gtk_box_pack_start (GTK_BOX (edit_vbox), color_delete, FALSE, FALSE, 5);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_delete, BUTTON_SIZE_X, BUTTON_SIZE_Y);
#endif
  gtk_tooltips_set_tip (tooltips, color_delete, ("Delete the selected filter(s)"), NULL);
  gtk_widget_set_sensitive (color_delete, FALSE);
  /* End edit buttons frame */


  /* manage buttons frame */
  manage_fr = gtk_frame_new("Manage");
  gtk_box_pack_start (GTK_BOX (ctrl_vbox), manage_fr, FALSE, FALSE, 0);
  
  manage_vbox = gtk_vbox_new (FALSE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (manage_vbox), 5);
  gtk_container_add(GTK_CONTAINER(manage_fr), manage_vbox);

  color_export = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_EXPORT);
  gtk_box_pack_start (GTK_BOX (manage_vbox), color_export, FALSE, FALSE, 5);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_export, BUTTON_SIZE_X, BUTTON_SIZE_Y);
#endif
  gtk_tooltips_set_tip(tooltips, color_export, ("Save all/selected filters to a file"), NULL);

  color_import = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_IMPORT);
  gtk_box_pack_start (GTK_BOX (manage_vbox), color_import, FALSE, FALSE, 5);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_import, BUTTON_SIZE_X, BUTTON_SIZE_Y);
#endif
  gtk_tooltips_set_tip(tooltips, color_import, ("Load filters from a file and append them to the list"), NULL);

  color_clear = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLEAR);
  gtk_box_pack_start(GTK_BOX (manage_vbox), color_clear, FALSE, FALSE, 5);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_clear, BUTTON_SIZE_X, BUTTON_SIZE_Y);
#endif
  gtk_tooltips_set_tip(tooltips, color_clear, ("Clear the filter list and revert to system-wide default filter set"), NULL);


  /* filter list frame */
  list_fr = gtk_frame_new("Filter");
  gtk_box_pack_start (GTK_BOX (main_hbox), list_fr, TRUE, TRUE, 0);

  list_vbox = gtk_vbox_new (FALSE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (list_vbox), 5);
  gtk_container_add(GTK_CONTAINER(list_fr), list_vbox);

  list_label = gtk_label_new (("List is processed in order until match is found"));
  gtk_box_pack_start (GTK_BOX (list_vbox), list_label, FALSE, FALSE, 0);

  /* create the list of filters */
  scrolledwindow1 = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow1), 
                                   GTK_SHADOW_IN);
#endif
  gtk_box_pack_start (GTK_BOX (list_vbox), scrolledwindow1, TRUE, TRUE, 0);

#if GTK_MAJOR_VERSION < 2
  color_filters = gtk_clist_new_with_titles(2, (gchar **) titles);
#else
  /* the list store contains : filter name, filter string, foreground
   * color, background color, pointer to color filter */
  store = gtk_list_store_new(5, G_TYPE_STRING, G_TYPE_STRING,
                             G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);
  color_filters = tree_view_new(GTK_TREE_MODEL(store));
  g_object_unref(store);
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes(titles[0], renderer, "text",
                                                    0, "foreground", 2,
                                                    "background", 3, NULL);
  gtk_tree_view_column_set_fixed_width(column, 80);
  gtk_tree_view_append_column(GTK_TREE_VIEW(color_filters), column);
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes(titles[1], renderer, "text",
                                                    1, "foreground", 2,
                                                    "background", 3, NULL);
  gtk_tree_view_column_set_fixed_width(column, 300);
  gtk_tree_view_append_column(GTK_TREE_VIEW(color_filters), column);
  gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(color_filters), TRUE);
  gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(color_filters), FALSE);
#endif

#if GTK_MAJOR_VERSION < 2
  gtk_clist_set_selection_mode    (GTK_CLIST (color_filters),GTK_SELECTION_EXTENDED);
#else
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
  gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
#endif

  gtk_container_add (GTK_CONTAINER (scrolledwindow1), color_filters);
#if GTK_MAJOR_VERSION < 2
  gtk_clist_set_column_width (GTK_CLIST (color_filters), 0, 80);
  gtk_clist_set_column_width (GTK_CLIST (color_filters), 1, 300);
  gtk_clist_column_titles_show (GTK_CLIST (color_filters));
#endif


  /* order frame */
  order_fr = gtk_frame_new("Order");
  gtk_box_pack_start (GTK_BOX (main_hbox), order_fr, FALSE, FALSE, 0);

  order_vbox = gtk_vbox_new (TRUE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (order_vbox), 5);
  gtk_container_add(GTK_CONTAINER(order_fr), order_vbox);

  color_filter_up = BUTTON_NEW_FROM_STOCK(GTK_STOCK_GO_UP);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_filter_up, BUTTON_SIZE_X, BUTTON_SIZE_Y);
#endif
  gtk_box_pack_start (GTK_BOX (order_vbox), color_filter_up, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_filter_up, ("Move filter higher in list"), NULL);
  gtk_widget_set_sensitive (color_filter_up, FALSE);

  order_move_label = gtk_label_new (("Move\nselected filter\nup or down"));
  gtk_box_pack_start (GTK_BOX (order_vbox), order_move_label, FALSE, FALSE, 0);

  color_filter_down = BUTTON_NEW_FROM_STOCK(GTK_STOCK_GO_DOWN);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_filter_down, BUTTON_SIZE_X, BUTTON_SIZE_Y);
#endif
  gtk_box_pack_start (GTK_BOX (order_vbox), color_filter_down, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_filter_down, ("Move filter lower in list"), NULL);
  gtk_widget_set_sensitive (color_filter_down, FALSE);


  /* Button row: OK and cancel buttons */
  if(topic_available(HELP_COLORING_RULES_DIALOG)) {
    button_ok_hbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  } else {
    button_ok_hbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, NULL);
  }
  gtk_box_pack_start (GTK_BOX (dlg_vbox), button_ok_hbox, FALSE, FALSE, 5);

  color_ok = OBJECT_GET_DATA(button_ok_hbox, GTK_STOCK_OK);
  gtk_tooltips_set_tip (tooltips, color_ok, ("Apply the color filters to the display and close this dialog"), NULL);

  color_apply = OBJECT_GET_DATA(button_ok_hbox, GTK_STOCK_APPLY);
  gtk_tooltips_set_tip (tooltips, color_apply, ("Apply the color filters to the display and keep this dialog open"), NULL);

  color_save = OBJECT_GET_DATA(button_ok_hbox, GTK_STOCK_SAVE);
  gtk_tooltips_set_tip (tooltips, color_save, ("Save the color filters permanently and keep this dialog open"), NULL);

  color_cancel = OBJECT_GET_DATA(button_ok_hbox, GTK_STOCK_CANCEL);
  window_set_cancel_button(color_win, color_cancel, color_cancel_cb);
  gtk_tooltips_set_tip (tooltips, color_cancel, ("Cancel changes done (since last \"Apply\") and close this dialog"), NULL);

  if(topic_available(HELP_COLORING_RULES_DIALOG)) {
      color_help = OBJECT_GET_DATA(button_ok_hbox, GTK_STOCK_HELP);
      gtk_tooltips_set_tip (tooltips, color_help, ("Get help about this dialog"), NULL);
      SIGNAL_CONNECT(color_help, "clicked", topic_cb, HELP_COLORING_RULES_DIALOG);
  }

  gtk_widget_grab_default(color_ok);

  /* signals and such */
  SIGNAL_CONNECT(color_win, "destroy", color_destroy_cb, NULL);
  OBJECT_SET_DATA(color_filter_up, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_filter_up, "clicked", color_filter_up_cb, NULL);
  OBJECT_SET_DATA(color_filter_down, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_filter_down, "clicked", color_filter_down_cb, NULL);
#if GTK_MAJOR_VERSION < 2
  SIGNAL_CONNECT(color_filters, "select_row", remember_selected_row, NULL);
  SIGNAL_CONNECT(color_filters, "unselect_row", unremember_selected_row, NULL);
#else
  SIGNAL_CONNECT(selection, "changed", remember_selected_row, color_filters);
#endif
  OBJECT_SET_DATA(color_filters, COLOR_UP_LB, color_filter_up);
  OBJECT_SET_DATA(color_filters, COLOR_DOWN_LB, color_filter_down);
  OBJECT_SET_DATA(color_filters, COLOR_EDIT_LB, color_edit);
  OBJECT_SET_DATA(color_filters, COLOR_DELETE_LB, color_delete);
  OBJECT_SET_DATA(color_new, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_new, "clicked", color_new_cb, NULL);
  OBJECT_SET_DATA(color_edit, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_edit, "clicked", color_edit_cb, NULL);
  OBJECT_SET_DATA(color_delete, COLOR_EDIT_LB, color_edit);
  OBJECT_SET_DATA(color_delete, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_delete, "clicked", color_delete_cb, NULL);
  SIGNAL_CONNECT(color_export, "clicked", color_export_cb, NULL);
  OBJECT_SET_DATA(color_import, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_import, "clicked", color_import_cb, NULL);
  OBJECT_SET_DATA(color_clear, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_clear, "clicked", color_clear_cb, NULL);
  SIGNAL_CONNECT(color_ok, "clicked", color_ok_cb, NULL);
  SIGNAL_CONNECT(color_apply, "clicked", color_apply_cb, NULL);
  SIGNAL_CONNECT(color_save, "clicked", color_save_cb, NULL);

  SIGNAL_CONNECT(color_win, "delete_event", window_delete_event_cb, NULL);

  gtk_widget_grab_focus(color_filters);

  /* prepare filter list content */
  color_filters_clone(color_filters);
  OBJECT_SET_DATA(color_win, COLOR_FILTER_LIST, &color_filter_edit_list);

  gtk_widget_show_all(color_win);
  window_present(color_win);

  if(filter){
    /* if we specified a preset filter string, open the new dialog and
       set the filter */
    create_new_color_filter(GTK_BUTTON(color_new), filter);
  }

  return color_win;
}

/* move a row in the list +/- one position up/down */
static void move_this_row (GtkWidget   *color_filters, 
                     gint         filter_number,
                     gint         amount)            /* only tested with +1(down) and -1(up) */
{
  color_filter_t *colorf;
#if GTK_MAJOR_VERSION < 2
  gint            lower, higher;
#else
  GtkTreeModel   *model;
  GtkTreeIter     iter1, iter2;
  gchar          *name, *string, *fg_str, *bg_str;
#endif

  g_assert(amount == +1 || amount == -1);
  g_assert(amount == +1 || filter_number > 0);
  g_assert(amount == -1 || filter_number < num_of_filters - 1);

#if GTK_MAJOR_VERSION < 2
  if (amount > 0)
  {
    lower = filter_number;
    higher = filter_number + amount;
  }
  else
  {
    higher = filter_number;
    lower = filter_number + amount;
  }

  colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), filter_number);
  gtk_clist_swap_rows(GTK_CLIST(color_filters), higher, lower);

  /*
   * That row is still selected, but it's now moved.
   */
  remember_selected_row(GTK_CLIST(color_filters), filter_number + amount, 0, NULL, NULL);
#else

  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  gtk_tree_model_iter_nth_child(model, &iter1, NULL, filter_number);
  gtk_tree_model_iter_nth_child(model, &iter2, NULL, filter_number + amount);
  
  gtk_tree_model_get(model, &iter1, 0, &name, 1, &string,
                     2, &fg_str, 3, &bg_str, 4, &colorf, -1);
  gtk_list_store_remove(GTK_LIST_STORE(model), &iter1);
  if (amount < 0)
    gtk_list_store_insert_before(GTK_LIST_STORE(model), &iter1, &iter2);
  else
    gtk_list_store_insert_after(GTK_LIST_STORE(model), &iter1, &iter2);
  gtk_list_store_set(GTK_LIST_STORE(model), &iter1, 0, name, 1, string,
                     2, fg_str, 3, bg_str, 4, colorf, -1);
  g_free(name);
  g_free(string);
  g_free(fg_str);
  g_free(bg_str);

  /*
   * re-select the initial row
   */
  gtk_widget_grab_focus(color_filters);
  gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters)), &iter1);
  
#endif

  color_filter_edit_list = g_slist_remove(color_filter_edit_list, colorf);
  color_filter_edit_list = g_slist_insert(color_filter_edit_list, colorf, filter_number + amount);
}

/* User pressed the "Up" button: Move the selected filters up in the list */
static void
color_filter_up_cb(GtkButton *button, gpointer user_data _U_)
{
  gint amount;
  gint filter_number;
  GtkWidget * color_filters;
  color_filter_t *colorf;
#if GTK_MAJOR_VERSION < 2
#else
  GtkTreeIter       iter;
  GtkTreeModel     *model;
  GtkTreeSelection *sel;
#endif

  amount = -1;
  color_filters = (GtkWidget *)OBJECT_GET_DATA(button, COLOR_FILTERS_CL);

#if GTK_MAJOR_VERSION < 2
  colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), 0);
  if (colorf->selected)
    return;
#endif

  for (filter_number = 0; filter_number < num_of_filters; filter_number++)
  {
#if GTK_MAJOR_VERSION < 2
    colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), filter_number);
    if (colorf->selected)
      move_this_row (color_filters, filter_number, amount);
#else
    model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
    gtk_tree_model_iter_nth_child(model, &iter, NULL, filter_number);
    gtk_tree_model_get(model, &iter, 4, &colorf, -1);
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
    if (gtk_tree_selection_iter_is_selected(sel, &iter))
      move_this_row (color_filters, filter_number, amount);
#endif
  }
}

/* User pressed the "Down" button: Move the selected filters down in the list */
static void
color_filter_down_cb(GtkButton *button, gpointer user_data _U_)
{
  gint amount;
  gint filter_number;
  GtkWidget * color_filters;
  color_filter_t *colorf;
#if GTK_MAJOR_VERSION < 2
#else
  GtkTreeIter     iter;
  GtkTreeModel   *model;
#endif

  amount = +1;
  color_filters = (GtkWidget *)OBJECT_GET_DATA(button, COLOR_FILTERS_CL);

#if GTK_MAJOR_VERSION < 2
    colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), num_of_filters - 1);
    if (colorf->selected)
      return;
#endif

  for (filter_number = num_of_filters - 1; filter_number >= 0; filter_number--)
  {
#if GTK_MAJOR_VERSION < 2
    colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), filter_number);
#else
    model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
    gtk_tree_model_iter_nth_child(model, &iter, NULL, filter_number);
    gtk_tree_model_get(model, &iter, 4, &colorf, -1);
#endif
    if (colorf->selected)
      move_this_row (color_filters, filter_number, amount);
  }
}
 
/* A row was selected; remember its row number */
#if GTK_MAJOR_VERSION < 2
static void
remember_selected_row(GtkCList *clist, gint row, gint column _U_,
                      GdkEvent *event _U_, gpointer user_data _U_)
{
    GtkWidget    *button;
    color_filter_t *colorf;

    row_selected = row;

    colorf = gtk_clist_get_row_data(clist, row);
    colorf->selected = TRUE;
    
    /*
     * A row is selected, so we can move it up *if* it's not at the top
     * and move it down *if* it's not at the bottom.
     */
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_UP_LB);
    gtk_widget_set_sensitive (button, row > 0);
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_DOWN_LB);
    gtk_widget_set_sensitive(button, row < num_of_filters - 1);

    /*
     * A row is selected, so we can operate on it.
     */
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_EDIT_LB);
    gtk_widget_set_sensitive (button, TRUE);
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_DELETE_LB);
    gtk_widget_set_sensitive(button, TRUE);
    
}
#else

struct remember_data
{
    gint count;               /* count of selected filters */
    gboolean first_selected;  /* true if the first filter in the list is selected */
    gboolean last_selected;   /* true if the last filter in the list is selected */
    gpointer color_filters;
};
/* called for each selected row in the tree.
*/
static void remember_this_row (GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer arg)
{
    gint         *path_index;
    color_filter_t *colorf;
    struct remember_data *data = arg;
    
    gtk_tree_model_get(model, iter, 4, &colorf, -1);
    colorf->selected = TRUE;
        
    path_index = gtk_tree_path_get_indices(path);   /* not to be freed */
    if (path_index == NULL)       /* can return NULL according to API doc.*/
    {
      return;
    }
    row_selected = path_index[0];

    if (row_selected == 0)
      data->first_selected = TRUE;
    if (row_selected == num_of_filters - 1)
      data->last_selected = TRUE;

    data->count++;
}

/* clear the selection flag of this filter */
static void
clear_select_flag(gpointer filter_arg, gpointer arg _U_)
{
  color_filter_t *colorf = filter_arg;

  colorf->selected = FALSE;
}

/* The gtk+2.0 version gets called for, (maybe multiple,) changes in the selection. */
static void
remember_selected_row(GtkTreeSelection *sel, gpointer color_filters)
{
    GtkWidget    *button;
    struct remember_data data;

    data.first_selected = data.last_selected = FALSE;
    data.count = 0; 
    data.color_filters = color_filters;

    g_slist_foreach(color_filter_edit_list, clear_select_flag, NULL);
    gtk_tree_selection_selected_foreach(sel,remember_this_row, &data);
                                      
    if (data.count > 0)
    {
      /*
       * One or more rows are selected, so we can operate on them.
      */
       
      /* We can only edit if there is exactly one filter selected */
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_EDIT_LB);
      gtk_widget_set_sensitive (button, data.count == 1);
      
      /* We can delete any number of filters */
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_DELETE_LB);
      gtk_widget_set_sensitive (button, TRUE);
      /*
       * We can move them up *if* one of them isn't the top row,
       * and move them down *if* one of them isn't the bottom row.
      */
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_UP_LB);
      gtk_widget_set_sensitive(button, !data.first_selected);
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_DOWN_LB);
      gtk_widget_set_sensitive(button, !data.last_selected);
    }
    else
    {
      row_selected = -1;

      /*
       * No row is selected, so we can't do operations that affect the
       * selected row.
      */
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_UP_LB);
      gtk_widget_set_sensitive (button, FALSE);
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_DOWN_LB);
      gtk_widget_set_sensitive (button, FALSE);
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_EDIT_LB);
      gtk_widget_set_sensitive (button, FALSE);
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_DELETE_LB);
      gtk_widget_set_sensitive (button, FALSE);
    }
}
#endif

#if GTK_MAJOR_VERSION < 2
/* A row was unselected; un-remember its row number */
static void
unremember_selected_row                 (GtkCList        *clist,
                                         gint             row _U_,
                                         gint             column _U_,
                                         GdkEvent        *event _U_,
                                         gpointer         user_data _U_)
{
  GtkWidget *button;
  color_filter_t *colorf;

  row_selected = -1;

  colorf = gtk_clist_get_row_data(clist, row);
  colorf->selected = FALSE;

  if (color_selected_count() == 0)
  {
    /*
     * No row is selected, so we can't do operations that affect the
     * selected row.
     */
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_UP_LB);
    gtk_widget_set_sensitive (button, FALSE);
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_DOWN_LB);
    gtk_widget_set_sensitive (button, FALSE);
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_EDIT_LB);
    gtk_widget_set_sensitive (button, FALSE);
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_DELETE_LB);
    gtk_widget_set_sensitive(button, FALSE);
  }
}
#endif



/* destroy a single color edit dialog */
static void
destroy_edit_dialog_cb(gpointer filter_arg, gpointer dummy _U_)
{
  color_filter_t *colorf = (color_filter_t *)filter_arg;

  if (colorf->edit_dialog != NULL)
    window_destroy(colorf->edit_dialog);
}

/* Called when the dialog box is being destroyed; destroy any edit
 * dialogs opened from this dialog.
 */
static void
color_destroy_cb                       (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
  /* Destroy any edit dialogs we have open. */
  g_slist_foreach(color_filter_edit_list, destroy_edit_dialog_cb, NULL);

  /* destroy the filter list itself */
  color_filter_list_delete(&color_filter_edit_list);

  colorize_win = NULL;
}


static void
select_row(GtkWidget *color_filters, int row)
{
#if GTK_MAJOR_VERSION < 2
#else
  GtkTreeModel     *model;
  gint              num_filters;
  GtkTreeIter       iter;
  GtkTreeSelection *sel;
#endif

#if GTK_MAJOR_VERSION < 2
  /* select the new row */
  gtk_clist_select_row(GTK_CLIST(color_filters), row, -1);
#else
  /* select the new row */
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  num_filters = gtk_tree_model_iter_n_children(model, NULL);
  gtk_tree_model_iter_nth_child(model, &iter, NULL, row);
  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
  gtk_tree_selection_select_iter(sel, &iter);
#endif
}



/* add a single color filter to the list */
static void
add_filter_to_list(gpointer filter_arg, gpointer list_arg)
{
  color_filter_t *colorf = filter_arg;
#if GTK_MAJOR_VERSION < 2
  GtkWidget      *color_filters = list_arg;
  gchar          *data[2];
  gint            row;
  GdkColor        bg, fg;

  data[0] = colorf->filter_name;
  data[1] = colorf->filter_text;
  row = gtk_clist_append(GTK_CLIST(color_filters), data);
  color_t_to_gdkcolor(&fg, &colorf->fg_color);
  color_t_to_gdkcolor(&bg, &colorf->bg_color);
  gtk_clist_set_row_data(GTK_CLIST(color_filters), row, colorf);
  gtk_clist_set_foreground(GTK_CLIST(color_filters), row, &fg);
  gtk_clist_set_background(GTK_CLIST(color_filters), row, &bg);
#else
  gchar           fg_str[14], bg_str[14];
  GtkListStore   *store;
  GtkTreeIter     iter;

  store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list_arg)));
  gtk_list_store_append(store, &iter);
  g_snprintf(fg_str, 14, "#%04X%04X%04X",
          colorf->fg_color.red, colorf->fg_color.green, colorf->fg_color.blue);
  g_snprintf(bg_str, 14, "#%04X%04X%04X",
          colorf->bg_color.red, colorf->bg_color.green, colorf->bg_color.blue);
  gtk_list_store_set(store, &iter, 0, colorf->filter_name,
                     1, colorf->filter_text, 2, fg_str, 3, bg_str,
                     4, colorf, -1);
#endif
  color_filter_edit_list = g_slist_append(color_filter_edit_list, colorf);

  num_of_filters++;
}


/* a new color filter was read in from a filter file */
void
color_filter_add_cb(color_filter_t *colorf, gpointer user_data)
{
  GtkWidget        *color_filters = user_data;

  add_filter_to_list(colorf, color_filters);

#if GTK_MAJOR_VERSION >= 2
  gtk_widget_grab_focus(color_filters);
#endif
}

/* Create a new filter, add it to the list, and pop up an 
   "Edit color filter" dialog box to edit it. */
static void
create_new_color_filter(GtkButton *button, const char *filter)
{
  color_filter_t   *colorf;
  GtkStyle         *style;
  color_t          bg_color, fg_color;
  GtkWidget        *color_filters;
#if GTK_MAJOR_VERSION >= 2
  GtkTreeSelection *sel;
#endif

  color_filters = (GtkWidget *)OBJECT_GET_DATA(button, COLOR_FILTERS_CL);

  /* unselect all filters */
#if GTK_MAJOR_VERSION >= 2
  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
  gtk_tree_selection_unselect_all (sel);
#else
  gtk_clist_unselect_all (GTK_CLIST(color_filters));
#endif

  /* Use the default background and foreground colors as the colors. */
  style = gtk_widget_get_style(packet_list);
  gdkcolor_to_color_t(&bg_color, &style->base[GTK_STATE_NORMAL]);
  gdkcolor_to_color_t(&fg_color, &style->text[GTK_STATE_NORMAL]);

  colorf = color_filter_new("name", filter, &bg_color, &fg_color);

  add_filter_to_list(colorf, color_filters);

  select_row(color_filters, num_of_filters-1);

  /* open the edit dialog */
  edit_color_filter_dialog(color_filters, TRUE /* is a new filter */);
  
#if GTK_MAJOR_VERSION >= 2
  gtk_widget_grab_focus(color_filters);
#endif
}

/* User pressed the "New" button: Create a new filter in the list, 
   and pop up an "Edit color filter" dialog box to edit it. */
static void
color_new_cb(GtkButton *button, gpointer user_data _U_)
{
  create_new_color_filter(button, "filter");
}

/* User pressed the "Edit" button: Pop up an "Edit color filter" dialog box 
   to edit an existing filter. */
static void
color_edit_cb(GtkButton *button, gpointer user_data _U_)
{
  GtkWidget *color_filters;

  color_filters = (GtkWidget *)OBJECT_GET_DATA(button, COLOR_FILTERS_CL);
  g_assert(row_selected != -1);
  edit_color_filter_dialog(color_filters, FALSE /* is not a new filter */);
}

/* Delete a single color filter from the list and elsewhere. */
void
color_delete(gint row, GtkWidget *color_filters)
{
    color_filter_t *colorf;
    
#if GTK_MAJOR_VERSION >= 2
    GtkTreeModel     *model;
    GtkTreeIter       iter;

    
    model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
    gtk_tree_model_iter_nth_child(model, &iter, NULL, row);
    gtk_tree_model_get(model, &iter, 4, &colorf, -1);
    
    /* Remove this color filter from the CList displaying the
    color filters. */
    gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
    num_of_filters--;
    
    /* Destroy any "Edit color filter" dialog boxes editing it. */
    if (colorf->edit_dialog != NULL)
    window_destroy(colorf->edit_dialog);
    
    /* Delete the color filter from the list of color filters. */
    color_filter_edit_list = g_slist_remove(color_filter_edit_list, colorf);
    color_filter_delete(colorf);

    /* If we grab the focus after updating the selection, the first
    * row is always selected, so we do it before */
    gtk_widget_grab_focus(color_filters);
#else
    colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), row);

    /* Remove this color filter from the CList displaying the
       color filters. */
    gtk_clist_remove(GTK_CLIST(color_filters), row);
    num_of_filters--;

    /* Destroy any "Edit color filter" dialog boxes editing it. */
    if (colorf->edit_dialog != NULL)
        window_destroy(colorf->edit_dialog);

    /* Delete the color filter from the list of color filters. */
    color_filter_edit_list = g_slist_remove(color_filter_edit_list, colorf);
    color_filter_delete(colorf);
#endif
}

/* User pressed the "Delete" button: Delete the selected filters from the list.*/
static void
color_delete_cb(GtkWidget *widget, gpointer user_data _U_)
{
  GtkWidget  *color_filters;
  gint row, num_filters;
#if GTK_MAJOR_VERSION < 2
  color_filter_t *colorf;
#else
    GtkTreeModel     *model;
    GtkTreeIter       iter;
    GtkTreeSelection *sel;
#endif

  color_filters = (GtkWidget *)OBJECT_GET_DATA(widget, COLOR_FILTERS_CL);

  /* get the number of filters in the list */
#if GTK_MAJOR_VERSION < 2
  num_filters = num_of_filters;
#else
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  num_filters = gtk_tree_model_iter_n_children(model, NULL);
  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
#endif

  /* iterate through the list and delete the selected ones */
  for (row = num_filters - 1; row >= 0; row--)
  {
#if GTK_MAJOR_VERSION < 2
    colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), row);
    if (colorf->selected)
      color_delete (row, color_filters);
#else
    gtk_tree_model_iter_nth_child(model, &iter, NULL, row);
    if (gtk_tree_selection_iter_is_selected(sel, &iter))
      color_delete (row, color_filters);
#endif
  }
}

/* User pressed "Export": Pop up an "Export color filter" dialog box. */
static void
color_export_cb(GtkButton *button, gpointer data _U_)
{
  GtkWidget        *color_filters;
#if GTK_MAJOR_VERSION >= 2
  GtkTreeSelection *sel;
#endif

  color_filters = (GtkWidget *)OBJECT_GET_DATA(button, COLOR_FILTERS_CL);

  file_color_export_cmd_cb(color_filters, &color_filter_edit_list);
}

/* User pressed "Import": Pop up an "Import color filter" dialog box. */
static void
color_import_cb(GtkButton *button, gpointer data _U_)
{
  GtkWidget        *color_filters;
#if GTK_MAJOR_VERSION >= 2
  GtkTreeSelection *sel;
#endif

  color_filters = (GtkWidget *)OBJECT_GET_DATA(button, COLOR_FILTERS_CL);

#if GTK_MAJOR_VERSION >= 2
  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
  gtk_tree_selection_unselect_all (sel);
#else
  gtk_clist_unselect_all (GTK_CLIST(color_filters));
#endif

  file_color_import_cmd_cb(color_filters, &color_filter_edit_list);
}

/* User confirmed the clear operation: Remove all user defined color filters and 
   revert to the global file. */
static void
color_clear_cmd(GtkWidget *widget)
{
    GtkWidget * color_filters;
    
    color_filters = (GtkWidget *)OBJECT_GET_DATA(widget, COLOR_FILTERS_CL);
    
    while (num_of_filters > 0)
    {
        color_delete (num_of_filters-1, color_filters);
    }

    /* try to read the global filters */
    color_filters_read_globals(color_filters);
}

/* Clear button: user responded to question */
static void color_clear_answered_cb(gpointer dialog _U_, gint btn, gpointer data)
{
    switch(btn) {
    case(ESD_BTN_CLEAR):
        color_clear_cmd(data);
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}

/* User pressed "clear" button: ask user before really doing it */
void
color_clear_cb(GtkWidget *widget, gpointer data _U_) {
    gpointer  dialog;

    /* ask user, if he/she is really sure */
    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTN_CLEAR | ESD_BTN_CANCEL, 
                PRIMARY_TEXT_START "Remove all your personal color settings?" PRIMARY_TEXT_END "\n\n"
                "This will revert the color settings to global defaults.\n\n"
                "Are you really sure?");

    simple_dialog_set_cb(dialog, color_clear_answered_cb, widget);
}



/* User pressed "Ok" button: Exit dialog and apply new list of 
   color filters to the capture. */
static void
color_ok_cb(GtkButton *button _U_, gpointer user_data _U_)
{
  color_filters_apply(color_filter_edit_list);

  /* colorize list */
  cf_colorize_packets(&cfile);

  /* Destroy the dialog box. */
  window_destroy(colorize_win);
}

/* User pressed "Apply" button: apply the new list of color filters 
   to the capture. */
static void
color_apply_cb(GtkButton *button _U_, gpointer user_data _U_)
{
  color_filters_apply(color_filter_edit_list);

  cf_colorize_packets(&cfile);
}

/* User pressed the "Save" button: save the color filters to the 
   color filter file. */
static void
color_save_cb(GtkButton *button _U_, gpointer user_data _U_)
{

  if (!color_filters_write(color_filter_edit_list))
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	    "Could not open filter file: %s", strerror(errno));
}

/* User pressed "Cancel" button (or "ESC" or the 'X'): 
   Exit dialog without colorizing packets with the new list. */
static void
color_cancel_cb(GtkWidget *widget _U_, gpointer user_data _U_)
{
  /* Destroy the dialog box. */
  window_destroy(colorize_win);
}

