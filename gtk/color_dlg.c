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

#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/dfilter/dfilter.h>
#include <epan/prefs.h>

#include "../color.h"
#include "../color_filters.h"
#include "../file.h"
#include "../simple_dialog.h"

#include "gtk/main.h"
#include "gtk/color_utils.h"
#include "gtk/color_dlg.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_utils.h"
#include "gtk/dfilter_expr_dlg.h"
#include "gtk/stock_icons.h"
#include "gtk/filter_dlg.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/gtkglobals.h"
#include "gtk/help_dlg.h"
#include "gtk/color_edit_dlg.h"
#include "gtk/new_packet_list.h"


#define BUTTON_SIZE_X -1
#define BUTTON_SIZE_Y -1


static GtkWidget* colorize_dialog_new(char *filter);
static void add_filter_to_list(gpointer filter_arg, gpointer list_arg);
static void color_filter_up_cb(GtkButton *button, gpointer user_data);
static void color_filter_down_cb(GtkButton *button, gpointer user_data);
static void remember_selected_row(GtkTreeSelection *sel, gpointer list);
static void color_destroy_cb(GtkButton *button, gpointer user_data);
static void destroy_edit_dialog_cb(gpointer filter_arg, gpointer dummy);
static void create_new_color_filter(GtkButton *button, const char *filter);
static void color_new_cb(GtkButton *button, gpointer user_data);
static void color_edit_cb(GtkButton *button, gpointer user_data);
static gboolean color_filters_button_cb(GtkWidget *, GdkEventButton *, gpointer);
static void color_disable_cb(GtkWidget *widget, gboolean user_data);
static void color_delete_cb(GtkWidget *widget, gpointer user_data);
static void color_save_cb(GtkButton *button, gpointer user_data);
static void color_ok_cb(GtkButton *button, gpointer user_data);
static void color_cancel_cb(GtkWidget *widget, gpointer user_data);
static void color_apply_cb(GtkButton *button, gpointer user_data);
static void color_clear_cb(GtkWidget *button, gpointer user_data);
static void color_import_cb(GtkButton *button, gpointer user_data );
static void color_export_cb(GtkButton *button, gpointer user_data );


static GtkWidget *colorize_win;
gint      color_dlg_num_of_filters;  /* number of filters being displayed */
gint      color_dlg_row_selected;    /* row in color_filters that is selected */

static gboolean  row_is_moving = FALSE;

/* This is a list of all current color filters in the dialog
 * (copied from color_filters.c and edited with the dialog).
 * The color filter items are not identical to the ones used for the
 * packet list display, so they can be safely edited.
 *
 * Keep the temporary filters in a separate list so that they are
 * not shown in the edit-dialog
 *
 * XXX - use the existing GTK list for this purpose and build temporary copies
 * e.g. for the save/export functions.
 * Problem: Don't know when able to safely throw away, e.g. while exporting.
 */
static GSList *color_filter_edit_list = NULL;
static GSList *color_filter_tmp_list = NULL;


#define COLOR_UP_LB             "color_up_lb"
#define COLOR_DOWN_LB           "color_down_lb"
#define COLOR_EDIT_LB           "color_edit_lb"
#define COLOR_ENABLE_LB         "color_enable_lb"
#define COLOR_DISABLE_LB        "color_disable_lb"
#define COLOR_DELETE_LB         "color_delete_lb"
#define COLOR_FILTERS_CL        "color_filters_cl"
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
#if GTK_CHECK_VERSION(2,12,0)
#else
  GtkTooltips *tooltips;
#endif
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
  GtkWidget *color_enable;
  GtkWidget *color_disable;
  GtkWidget *color_delete;

  GtkWidget *manage_fr;
  GtkWidget *manage_vbox;
  GtkWidget *color_import;
  GtkWidget *color_export;
  GtkWidget *color_clear;

  GtkWidget *button_ok_hbox;
  GtkWidget *color_ok;
  GtkWidget *color_apply;
  GtkWidget *color_save;
  GtkWidget *color_cancel;
  GtkWidget *color_help;

  GtkListStore      *store;
  GtkCellRenderer   *renderer;
  GtkTreeViewColumn *column;
  GtkTreeSelection  *selection;
  const gchar *titles[] = { "Name", "String" };



  color_dlg_num_of_filters = 0;
  color_dlg_row_selected = -1; /* no row selected */
#if GTK_CHECK_VERSION(2,12,0)
#else
  tooltips = gtk_tooltips_new ();
#endif
  /* Resizing of the dialog window is now reasonably done.
   * Default size is set so that it should fit into every usual screen resolution.
   * All other widgets are always packed depending on the current window size. */
  color_win = dlg_conf_window_new ("Wireshark: Coloring Rules");
  g_object_set_data(G_OBJECT(color_win), "color_win", color_win);
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
  edit_vbox = gtk_vbox_new(TRUE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (edit_vbox), 5);
  gtk_container_add(GTK_CONTAINER(edit_fr), edit_vbox);

  color_new = gtk_button_new_from_stock(GTK_STOCK_NEW);
  gtk_box_pack_start (GTK_BOX (edit_vbox), color_new, FALSE, FALSE, 5);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_new, "Create a new filter at the end of the list");
#else
  gtk_tooltips_set_tip (tooltips, color_new, ("Create a new filter at the end of the list"), NULL);
#endif                

  color_edit = gtk_button_new_from_stock(WIRESHARK_STOCK_EDIT);
  gtk_box_pack_start (GTK_BOX (edit_vbox), color_edit, FALSE, FALSE, 5);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_edit, " If more than one filter is selected, edit the first selected one");
#else
  gtk_tooltips_set_tip (tooltips, color_edit, ("Edit the properties of the selected filter."
      " If more than one filter is selected, edit the first selected one"), NULL);
#endif
  gtk_widget_set_sensitive (color_edit, FALSE);

  color_enable = gtk_button_new_from_stock(WIRESHARK_STOCK_ENABLE);
  gtk_box_pack_start (GTK_BOX (edit_vbox), color_enable, FALSE, FALSE, 5);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_enable, "Enable the selected filter(s)");
#else
  gtk_tooltips_set_tip (tooltips, color_enable, ("Enable the selected filter(s)"), NULL);
#endif
  gtk_widget_set_sensitive (color_enable, FALSE);

  color_disable = gtk_button_new_from_stock(WIRESHARK_STOCK_DISABLE);
  gtk_box_pack_start (GTK_BOX (edit_vbox), color_disable, FALSE, FALSE, 5);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_disable, "Disable the selected filter(s)");
#else
  gtk_tooltips_set_tip (tooltips, color_disable, ("Disable the selected filter(s)"), NULL);
#endif
  gtk_widget_set_sensitive (color_disable, FALSE);

  color_delete = gtk_button_new_from_stock(GTK_STOCK_DELETE);
  gtk_box_pack_start (GTK_BOX (edit_vbox), color_delete, FALSE, FALSE, 5);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_delete, "Delete the selected filter(s)");
#else
  gtk_tooltips_set_tip (tooltips, color_delete, ("Delete the selected filter(s)"), NULL);
#endif
  gtk_widget_set_sensitive (color_delete, FALSE);
  /* End edit buttons frame */


  /* manage buttons frame */
  manage_fr = gtk_frame_new("Manage");
  gtk_box_pack_start (GTK_BOX (ctrl_vbox), manage_fr, TRUE, TRUE, 0);

  manage_vbox = gtk_vbox_new (TRUE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (manage_vbox), 5);
  gtk_container_add(GTK_CONTAINER(manage_fr), manage_vbox);

  color_import = gtk_button_new_from_stock(WIRESHARK_STOCK_IMPORT);
  gtk_box_pack_start (GTK_BOX (manage_vbox), color_import, FALSE, FALSE, 5);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_import, "Load filters from a file and append them to the list");
#else
  gtk_tooltips_set_tip(tooltips, color_import, ("Load filters from a file and append them to the list"), NULL);
#endif
  color_export = gtk_button_new_from_stock(WIRESHARK_STOCK_EXPORT);
  gtk_box_pack_start (GTK_BOX (manage_vbox), color_export, FALSE, FALSE, 5);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_export, "Save all/selected filters to a file");
#else
  gtk_tooltips_set_tip(tooltips, color_export, ("Save all/selected filters to a file"), NULL);
#endif
  color_clear = gtk_button_new_from_stock(GTK_STOCK_CLEAR);
  gtk_box_pack_start(GTK_BOX (manage_vbox), color_clear, FALSE, FALSE, 5);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_clear, "Clear the filter list and revert to system-wide default filter set");
#else
  gtk_tooltips_set_tip(tooltips, color_clear, ("Clear the filter list and revert to system-wide default filter set"), NULL);
#endif

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
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolledwindow1),
                                   GTK_SHADOW_IN);
  gtk_box_pack_start (GTK_BOX (list_vbox), scrolledwindow1, TRUE, TRUE, 0);

  /* the list store contains : filter name, filter string, foreground
   * color, background color, pointer to color filter */
  store = gtk_list_store_new(6,
                                 G_TYPE_STRING,
                                 G_TYPE_STRING,
                                 G_TYPE_STRING,
                                 G_TYPE_STRING,
                                 G_TYPE_BOOLEAN,
                                 G_TYPE_POINTER);
  color_filters = tree_view_new(GTK_TREE_MODEL(store));
  g_object_unref(store);
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes(titles[0], renderer,
                                                    "text", 0,
                                                    "foreground", 2,
                                                    "background", 3,
                                                    "strikethrough", 4,
                                                    NULL);
  gtk_tree_view_column_set_fixed_width(column, 80);
  gtk_tree_view_append_column(GTK_TREE_VIEW(color_filters), column);
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes(titles[1], renderer,
                                                    "text", 1,
                                                    "foreground", 2,
                                                    "background", 3,
                                                    "strikethrough", 4,
                                                    NULL);
  gtk_tree_view_column_set_fixed_width(column, 300);
  gtk_tree_view_append_column(GTK_TREE_VIEW(color_filters), column);
  gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(color_filters), TRUE);
  gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(color_filters), FALSE);

  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
  gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);

  gtk_container_add (GTK_CONTAINER (scrolledwindow1), color_filters);


  /* order frame */
  order_fr = gtk_frame_new("Order");
  gtk_box_pack_start (GTK_BOX (main_hbox), order_fr, FALSE, FALSE, 0);

  order_vbox = gtk_vbox_new (TRUE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (order_vbox), 5);
  gtk_container_add(GTK_CONTAINER(order_fr), order_vbox);

  color_filter_up = gtk_button_new_from_stock(GTK_STOCK_GO_UP);
  gtk_box_pack_start (GTK_BOX (order_vbox), color_filter_up, FALSE, FALSE, 0);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_filter_up, "Move filter higher in list");
#else  
  gtk_tooltips_set_tip (tooltips, color_filter_up, ("Move filter higher in list"), NULL);
#endif
  gtk_widget_set_sensitive (color_filter_up, FALSE);

  order_move_label = gtk_label_new (("Move\nselected filter\nup or down"));
  gtk_box_pack_start (GTK_BOX (order_vbox), order_move_label, FALSE, FALSE, 0);

  color_filter_down = gtk_button_new_from_stock(GTK_STOCK_GO_DOWN);
  gtk_box_pack_start (GTK_BOX (order_vbox), color_filter_down, FALSE, FALSE, 0);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_filter_down, "Move filter lower in list");
#else  
  gtk_tooltips_set_tip (tooltips, color_filter_down, ("Move filter lower in list"), NULL);
#endif
  gtk_widget_set_sensitive (color_filter_down, FALSE);


  /* Button row: OK, cancel and help buttons */
  button_ok_hbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  gtk_box_pack_start (GTK_BOX (dlg_vbox), button_ok_hbox, FALSE, FALSE, 5);

  color_ok = g_object_get_data(G_OBJECT(button_ok_hbox), GTK_STOCK_OK);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_ok, "Apply the color filters to the display and close this dialog");
#else 
  gtk_tooltips_set_tip (tooltips, color_ok, ("Apply the color filters to the display and close this dialog"), NULL);
#endif
  color_apply = g_object_get_data(G_OBJECT(button_ok_hbox), GTK_STOCK_APPLY);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_apply, "Apply the color filters to the display and keep this dialog open");
#else   
  gtk_tooltips_set_tip (tooltips, color_apply, ("Apply the color filters to the display and keep this dialog open"), NULL);
#endif

  color_save = g_object_get_data(G_OBJECT(button_ok_hbox), GTK_STOCK_SAVE);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_save, "Save the color filters permanently and keep this dialog open");
#else 
  gtk_tooltips_set_tip (tooltips, color_save, ("Save the color filters permanently and keep this dialog open"), NULL);
#endif
  color_cancel = g_object_get_data(G_OBJECT(button_ok_hbox), GTK_STOCK_CANCEL);
  window_set_cancel_button(color_win, color_cancel, color_cancel_cb);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_cancel, "Cancel changes done (since last \"Apply\") and close this dialog");
#else 
  gtk_tooltips_set_tip (tooltips, color_cancel, ("Cancel changes done (since last \"Apply\") and close this dialog"), NULL);
#endif

  color_help = g_object_get_data(G_OBJECT(button_ok_hbox), GTK_STOCK_HELP);
#if GTK_CHECK_VERSION(2,12,0)
  gtk_widget_set_tooltip_text(color_help, "Get help about this dialog");
#else   
  gtk_tooltips_set_tip (tooltips, color_help, ("Get help about this dialog"), NULL);
#endif
  g_signal_connect(color_help, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_COLORING_RULES_DIALOG);

  gtk_widget_grab_default(color_ok);

  /* signals and such */
  g_signal_connect(color_win, "destroy", G_CALLBACK(color_destroy_cb), NULL);
  g_object_set_data(G_OBJECT(color_filter_up), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(color_filter_up, "clicked", G_CALLBACK(color_filter_up_cb), NULL);
  g_object_set_data(G_OBJECT(color_filter_down), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(color_filter_down, "clicked", G_CALLBACK(color_filter_down_cb), NULL);
  g_signal_connect(selection, "changed", G_CALLBACK(remember_selected_row), color_filters);
  g_signal_connect(color_filters, "button_press_event", G_CALLBACK(color_filters_button_cb), NULL);
  g_object_set_data(G_OBJECT(color_filters), COLOR_UP_LB, color_filter_up);
  g_object_set_data(G_OBJECT(color_filters), COLOR_DOWN_LB, color_filter_down);
  g_object_set_data(G_OBJECT(color_filters), COLOR_EDIT_LB, color_edit);
  g_object_set_data(G_OBJECT(color_filters), COLOR_ENABLE_LB, color_enable);
  g_object_set_data(G_OBJECT(color_filters), COLOR_DISABLE_LB, color_disable);
  g_object_set_data(G_OBJECT(color_filters), COLOR_DELETE_LB, color_delete);
  g_object_set_data(G_OBJECT(color_new), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(color_new, "clicked", G_CALLBACK(color_new_cb), NULL);
  g_object_set_data(G_OBJECT(color_edit), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(color_edit, "clicked", G_CALLBACK(color_edit_cb), NULL);
  g_object_set_data(G_OBJECT(color_enable), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(color_enable, "clicked", G_CALLBACK(color_disable_cb), FALSE);
  g_object_set_data(G_OBJECT(color_disable), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(color_disable, "clicked", G_CALLBACK(color_disable_cb), (gpointer)TRUE);
  g_object_set_data(G_OBJECT(color_delete), COLOR_EDIT_LB, color_edit);
  g_object_set_data(G_OBJECT(color_delete), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(color_delete, "clicked", G_CALLBACK(color_delete_cb), NULL);
  g_object_set_data(G_OBJECT(color_import), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(color_import, "clicked", G_CALLBACK(color_import_cb), NULL);
  g_signal_connect(color_export, "clicked", G_CALLBACK(color_export_cb), NULL);
  g_object_set_data(G_OBJECT(color_clear), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(color_clear, "clicked", G_CALLBACK(color_clear_cb), NULL);
  g_signal_connect(color_ok, "clicked", G_CALLBACK(color_ok_cb), NULL);
  g_signal_connect(color_apply, "clicked", G_CALLBACK(color_apply_cb), NULL);
  g_signal_connect(color_save, "clicked", G_CALLBACK(color_save_cb), NULL);

  g_signal_connect(color_win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);

  gtk_widget_grab_focus(color_filters);

  /* prepare filter list content */
  color_filters_clone(color_filters);
  g_object_set_data(G_OBJECT(color_win), COLOR_FILTER_LIST, &color_filter_edit_list);

  gtk_widget_show_all(color_win);

  /* hide the Save button if the user uses implicit save */
  if(!prefs.gui_use_pref_save) {
    gtk_widget_hide(color_save);
  }

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
  GtkTreeModel   *model;
  GtkTreeIter     iter1, iter2;
  gchar          *name, *string, *fg_str, *bg_str;
  gboolean        disabled;

  g_assert(amount == +1 || amount == -1);
  g_assert(amount == +1 || filter_number > 0);
  g_assert(amount == -1 || filter_number < color_dlg_num_of_filters - 1);

  row_is_moving = TRUE;
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  gtk_tree_model_iter_nth_child(model, &iter1, NULL, filter_number);
  gtk_tree_model_iter_nth_child(model, &iter2, NULL, filter_number + amount);

  gtk_tree_model_get(model, &iter1, 0, &name, 1, &string,
                     2, &fg_str, 3, &bg_str, 4, &disabled, 5, &colorf, -1);
  gtk_list_store_remove(GTK_LIST_STORE(model), &iter1);
  if (amount < 0)
    gtk_list_store_insert_before(GTK_LIST_STORE(model), &iter1, &iter2);
  else
    gtk_list_store_insert_after(GTK_LIST_STORE(model), &iter1, &iter2);

  gtk_list_store_set(GTK_LIST_STORE(model), &iter1,
          0, name,
          1, string,
          2, fg_str,
          3, bg_str,
          4, disabled,
          5, colorf, -1);

  g_free(name);
  g_free(string);
  g_free(fg_str);
  g_free(bg_str);
  row_is_moving = FALSE;

  /*
   * re-select the initial row
   */
  gtk_widget_grab_focus(color_filters);
  gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters)), &iter1);

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
  GtkTreeIter       iter;
  GtkTreeModel     *model;
  GtkTreeSelection *sel;

  amount = -1;
  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button), COLOR_FILTERS_CL);

  for (filter_number = 0; filter_number < color_dlg_num_of_filters; filter_number++)
  {
    model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
    gtk_tree_model_iter_nth_child(model, &iter, NULL, filter_number);
    gtk_tree_model_get(model, &iter, 5, &colorf, -1);
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
    if (gtk_tree_selection_iter_is_selected(sel, &iter))
      move_this_row (color_filters, filter_number, amount);
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
  GtkTreeIter     iter;
  GtkTreeModel   *model;

  amount = +1;
  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button), COLOR_FILTERS_CL);

  for (filter_number = color_dlg_num_of_filters - 1; filter_number >= 0; filter_number--)
  {
    model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
    gtk_tree_model_iter_nth_child(model, &iter, NULL, filter_number);
    gtk_tree_model_get(model, &iter, 5, &colorf, -1);
    if (colorf->selected)
      move_this_row (color_filters, filter_number, amount);
  }
}


struct remember_data
{
  gint count;               /* count of selected filters */
  gboolean first_selected;  /* true if the first filter in the list is selected */
  gboolean last_selected;   /* true if the last filter in the list is selected */
  gboolean all_enabled;     /* true if all selected coloring rules are enabled */
  gboolean all_disabled;    /* true if all selected coloring rules are disabled */
  gpointer color_filters;
};
/* called for each selected row in the tree.
 */
static void remember_this_row (GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer arg)
{
  gint         *path_index;
  color_filter_t *colorf;
  struct remember_data *data = arg;

  gtk_tree_model_get(model, iter, 5, &colorf, -1);
  colorf->selected = TRUE;

  data->all_enabled  &= (!colorf->disabled);
  data->all_disabled &= colorf->disabled;

  path_index = gtk_tree_path_get_indices(path);   /* not to be freed */
  if (path_index == NULL)       /* can return NULL according to API doc.*/
  {
    return;
  }
  color_dlg_row_selected = path_index[0];

  if (color_dlg_row_selected == 0)
    data->first_selected = TRUE;
  if (color_dlg_row_selected == color_dlg_num_of_filters - 1)
    data->last_selected = TRUE;

  data->count++;

  gtk_tree_view_scroll_to_cell(data->color_filters, path, NULL, FALSE, 0.0f, 0.0f);
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
  data.all_enabled = data.all_disabled = TRUE;
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
    button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_EDIT_LB);
    gtk_widget_set_sensitive (button, data.count == 1);

    /* We can enable any number of filters */
    button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_ENABLE_LB);
    gtk_widget_set_sensitive (button, !data.all_enabled);

    /* We can disable any number of filters */
    button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_DISABLE_LB);
    gtk_widget_set_sensitive (button, !data.all_disabled);

    /* We can delete any number of filters */
    button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_DELETE_LB);
    gtk_widget_set_sensitive (button, TRUE);

    /*
     * We can move them up *if* one of them isn't the top row,
     * and move them down *if* one of them isn't the bottom row.
     */
    button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_UP_LB);
    gtk_widget_set_sensitive(button, !data.first_selected);
    button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_DOWN_LB);
    gtk_widget_set_sensitive(button, !data.last_selected);
  }
  else
  {
    color_dlg_row_selected = -1;

    /*
     * No row is selected, so we can't do operations that affect the
     * selected row.
     */
    if (!row_is_moving) {
      button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_UP_LB);
      gtk_widget_set_sensitive (button, FALSE);
      button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_DOWN_LB);
      gtk_widget_set_sensitive (button, FALSE);
    }
    button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_EDIT_LB);
    gtk_widget_set_sensitive (button, FALSE);
    button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_ENABLE_LB);
    gtk_widget_set_sensitive (button, FALSE);
    button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_DISABLE_LB);
    gtk_widget_set_sensitive (button, FALSE);
    button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_DELETE_LB);
    gtk_widget_set_sensitive (button, FALSE);
  }
}



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
  color_filter_list_delete(&color_filter_tmp_list);

  colorize_win = NULL;
}


static void
select_row(GtkWidget *color_filters, int row)
{
  GtkTreeModel     *model;
  GtkTreeIter       iter;
  GtkTreeSelection *sel;

  /* select the new row */
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  gtk_tree_model_iter_nth_child(model, &iter, NULL, row);
  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
  gtk_tree_selection_select_iter(sel, &iter);
}


/* add a single color filter to the list */
static void
add_filter_to_list(gpointer filter_arg, gpointer list_arg)
{
  color_filter_t *colorf = filter_arg;
    gchar           fg_str[14], bg_str[14];
    GtkListStore   *store;
    GtkTreeIter     iter;

  if( strstr(colorf->filter_name,TEMP_COLOR_PREFIX)==NULL) {
    store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list_arg)));
    gtk_list_store_append(store, &iter);
    g_snprintf(fg_str, sizeof(fg_str), "#%04X%04X%04X",
            colorf->fg_color.red, colorf->fg_color.green, colorf->fg_color.blue);
    g_snprintf(bg_str, sizeof(bg_str), "#%04X%04X%04X",
            colorf->bg_color.red, colorf->bg_color.green, colorf->bg_color.blue);
    gtk_list_store_set(store, &iter,
                0, colorf->filter_name,
        1, colorf->filter_text,
                2, fg_str,
                3, bg_str,
                4, colorf->disabled,
                5, colorf, -1);
    color_filter_edit_list = g_slist_append(color_filter_edit_list, colorf);
    color_dlg_num_of_filters++;
  } else {
    /* But keep the temporary ones too, so they can be added again
     * when the user is done editing */
    color_filter_tmp_list = g_slist_append(color_filter_tmp_list, colorf);
  }
}


/* a new color filter was read in from a filter file */
void
color_filter_add_cb(color_filter_t *colorf, gpointer user_data)
{
  GtkWidget        *color_filters = user_data;

  add_filter_to_list(colorf, color_filters);

  gtk_widget_grab_focus(color_filters);
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
  GtkTreeSelection *sel;

  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button), COLOR_FILTERS_CL);

  /* unselect all filters */
  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
  gtk_tree_selection_unselect_all (sel);

  /* Use the default background and foreground colors as the colors. */
  style = gtk_widget_get_style(new_packet_list_get_widget());
  gdkcolor_to_color_t(&bg_color, &style->base[GTK_STATE_NORMAL]);
  gdkcolor_to_color_t(&fg_color, &style->text[GTK_STATE_NORMAL]);

  colorf = color_filter_new("name", filter, &bg_color, &fg_color, FALSE);
  add_filter_to_list(colorf, color_filters);
  select_row(color_filters, color_dlg_num_of_filters-1);

  /* open the edit dialog */
  edit_color_filter_dialog(color_filters, TRUE /* is a new filter */);

  gtk_widget_grab_focus(color_filters);
}

/* User pressed the "New" button: Create a new filter in the list,
   and pop up an "Edit color filter" dialog box to edit it. */
static void
color_new_cb(GtkButton *button, gpointer user_data _U_)
{
  create_new_color_filter(button, "filter");
}

/* User pressed the "Edit" button: Pop up an "Edit color filter" dialog box
 * to edit an existing filter. */
static void
color_edit_cb(GtkButton *button, gpointer user_data _U_)
{
  GtkWidget *color_filters;

  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button), COLOR_FILTERS_CL);
  g_assert(color_dlg_row_selected != -1);
  edit_color_filter_dialog(color_filters, FALSE /* is not a new filter */);
}

/* User double-clicked on the coloring rule */
static gboolean
color_filters_button_cb(GtkWidget *list, GdkEventButton *event,
                          gpointer data _U_)
{
  if (event->type == GDK_2BUTTON_PRESS) {
    edit_color_filter_dialog(list, FALSE);
  }

  return FALSE;
}

/* action_disable==TRUE  ==> User pressed the "Disable" button:
 *                           Disable the selected filters in the list.
 * action_disable==FALSE ==> User pressed the "Enable" button:
 *                           Enable the selected filters in the list.
 */
static void
color_disable_cb(GtkWidget *widget, gboolean action_disable)
{
  gint filter_number;
  GtkWidget *button;
  GtkWidget * color_filters;
  color_filter_t *colorf;
  GtkTreeIter       iter;
  GtkTreeModel     *model;
  GtkTreeSelection *sel;

  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(widget), COLOR_FILTERS_CL);

  for (filter_number = 0; filter_number < color_dlg_num_of_filters; filter_number++)
  {
    model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
    gtk_tree_model_iter_nth_child(model, &iter, NULL, filter_number);
    gtk_tree_model_get(model, &iter, 5, &colorf, -1);
    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
    if (gtk_tree_selection_iter_is_selected(sel, &iter)) {
      colorf->disabled = action_disable;
      gtk_list_store_set(GTK_LIST_STORE(model), &iter,
                  4, action_disable, -1);
    }
  }
  button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_ENABLE_LB);
  gtk_widget_set_sensitive(button, action_disable);
  button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters), COLOR_DISABLE_LB);
  gtk_widget_set_sensitive(button, !action_disable);
}

/* Delete a single color filter from the list and elsewhere. */
void
color_delete_single(gint row, GtkWidget *color_filters)
{
  color_filter_t *colorf;

  GtkTreeModel     *model;
  GtkTreeIter       iter;


  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  gtk_tree_model_iter_nth_child(model, &iter, NULL, row);
  gtk_tree_model_get(model, &iter, 5, &colorf, -1);

  /* Remove this color filter from the CList displaying the
     color filters. */
  gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
  color_dlg_num_of_filters--;

  /* Destroy any "Edit color filter" dialog boxes editing it. */
  if (colorf->edit_dialog != NULL)
    window_destroy(colorf->edit_dialog);

  /* Delete the color filter from the list of color filters. */
  color_filter_edit_list = g_slist_remove(color_filter_edit_list, colorf);
  color_filter_delete(colorf);

  /* If we grab the focus after updating the selection, the first
   * row is always selected, so we do it before */
  gtk_widget_grab_focus(color_filters);
}

/* User pressed the "Delete" button: Delete the selected filters from the list.*/
static void
color_delete_cb(GtkWidget *widget, gpointer user_data _U_)
{
  GtkWidget  *color_filters;
  gint row, num_filters;
  GtkTreeModel     *model;
  GtkTreeIter       iter;
  GtkTreeSelection *sel;

  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(widget), COLOR_FILTERS_CL);

  /* get the number of filters in the list */
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  num_filters = gtk_tree_model_iter_n_children(model, NULL);
  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));

  /* iterate through the list and delete the selected ones */
  for (row = num_filters - 1; row >= 0; row--)
  {
    gtk_tree_model_iter_nth_child(model, &iter, NULL, row);
    if (gtk_tree_selection_iter_is_selected(sel, &iter))
      color_delete_single (row, color_filters);
  }
}

/* User pressed "Import": Pop up an "Import color filter" dialog box. */
static void
color_import_cb(GtkButton *button, gpointer data _U_)
{
  GtkWidget        *color_filters;
  GtkTreeSelection *sel;

  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button), COLOR_FILTERS_CL);

  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
  gtk_tree_selection_unselect_all (sel);

  file_color_import_cmd_cb(color_filters, &color_filter_edit_list);
}

/* User pressed "Export": Pop up an "Export color filter" dialog box. */
static void
color_export_cb(GtkButton *button, gpointer data _U_)
{
  GtkWidget        *color_filters;

  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button), COLOR_FILTERS_CL);

  file_color_export_cmd_cb(color_filters, color_filter_edit_list);
}

/* User confirmed the clear operation: Remove all user defined color filters and
   revert to the global file. */
static void
color_clear_cmd(GtkWidget *widget)
{
  GtkWidget * color_filters;

  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(widget), COLOR_FILTERS_CL);

  while (color_dlg_num_of_filters > 0)
  {
    color_delete_single (color_dlg_num_of_filters-1, color_filters);
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
                         "%sRemove all your personal color settings?%s\n\n"
                         "This will revert the color settings to global defaults.\n\n"
                         "Are you really sure?",
                         simple_dialog_primary_start(), simple_dialog_primary_end());

  simple_dialog_set_cb(dialog, color_clear_answered_cb, widget);
}



/* User pressed "Ok" button: Exit dialog and apply new list of
   color filters to the capture. */
static void
color_ok_cb(GtkButton *button _U_, gpointer user_data _U_)
{
  /* Apply the new coloring rules... */
  color_apply_cb(button,user_data);

  /* ... and destroy the dialog box. */
  window_destroy(colorize_win);
}

/* User pressed "Apply" button: apply the new list of color filters
   to the capture. */
static void
color_apply_cb(GtkButton *button _U_, gpointer user_data _U_)
{
  /* if we don't have a Save button, just save the settings now */
  if (!prefs.gui_use_pref_save) {
      if (!color_filters_write(color_filter_edit_list))
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "Could not open filter file: %s", strerror(errno));
  }

  /* Apply the coloring rules, both the temporary ones in
   * color_filter_tmp_list as the permanent ones in color_filter_edit_list
   * */
  color_filters_apply(color_filter_tmp_list, color_filter_edit_list);

  /* colorize list */
  new_packet_list_colorize_packets();
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

