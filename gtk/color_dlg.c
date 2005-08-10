/* color_dlg.c
 * Definitions for dialog boxes for color filters
 *
 * $Id$
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
#include "ui_util.h"
#include "dfilter_expr_dlg.h"
#include "compat_macros.h"
#include "filter_dlg.h"
#include "file_dlg.h"
#include "gtkglobals.h"
#include <epan/prefs.h>
#include "help_dlg.h"

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
static void color_props_cb(GtkButton *button, gpointer user_data);
static void color_delete_cb(GtkWidget *widget, gpointer user_data);
static void color_save_cb(GtkButton *button, gpointer user_data);
static void color_ok_cb(GtkButton *button, gpointer user_data);
static void color_cancel_cb(GtkWidget *widget, gpointer user_data);
static void color_apply_cb(GtkButton *button, gpointer user_data);
static void color_clear_cb(GtkWidget *button, gpointer user_data);
static void color_import_cb(GtkButton *button, gpointer user_data );

static void edit_color_filter_dialog(GtkWidget *color_filters,
                                     GtkWidget **colorize_filter_name,
                                     GtkWidget **colorize_filter_text,
                                     guchar is_new_filter);

#if GTK_MAJOR_VERSION < 2
static void edit_color_filter_destroy_cb(GtkObject *object, gpointer user_data);
#else
static void edit_color_filter_destroy_cb(GObject *object, gpointer user_data);
#endif
static void edit_color_filter_fg_cb(GtkButton *button, gpointer user_data);
static void edit_color_filter_bg_cb(GtkButton *button, gpointer user_data);
static void edit_color_filter_ok_cb(GtkButton *button, gpointer user_data);
static void edit_new_color_filter_cancel_cb(GtkButton *button, gpointer user_data);

static GtkWidget* color_sel_win_new(color_filter_t *colorf, gboolean);
static void color_sel_ok_cb(GtkButton *button, gpointer user_data);
static void color_sel_cancel_cb(GtkObject *object, gpointer user_data);

static GtkWidget *colorize_win;
static gint	  num_of_filters;  /* number of filters being displayed */
static gint	  row_selected;	   /* row in color_filters that is selected */

#define COLOR_UP_LB		"color_up_lb"
#define COLOR_DOWN_LB		"color_down_lb"
#define COLOR_PROPS_LB		"color_props_lb"
#define COLOR_DELETE_LB		"color_delete_lb"
#define COLOR_FILTERS_CL	"color_filters_cl"
#define COLOR_FILTER		"color_filter"
#define COLOR_SELECTION_FG	"color_selection_fg"
#define COLOR_SELECTION_BG	"color_selection_bg"
#define COLOR_SELECTION_PARENT	"color_selection_parent"

static void
filter_expr_cb(GtkWidget *w _U_, gpointer filter_te)
{

        dfilter_expr_dlg_new(GTK_WIDGET(filter_te));
}


/* Callback for the "Display:Colorize Display" menu item. */
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

/* this opens the colorize dialogue and presets the filter string */
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

/* if this filter is marked count it in the given int* */
static void
count_this_mark(gpointer filter_arg, gpointer counter_arg)
{
  color_filter_t *colorf = filter_arg;
  int * cnt = counter_arg;

  if (colorf->marked)
    (*cnt)++;
}

/* TODO: implement count of selected filters. Plug in to file_dlg update of "export selected" checkbox. */
int color_marked_count(void)
{
  int count = 0;

  g_slist_foreach(color_filter_list, count_this_mark, &count);

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
  GtkWidget *color_props;
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


  row_selected = -1; /* no row selected */
  tooltips = gtk_tooltips_new ();

  /* Resizing of the dialog window is now reasonably done.
   * Default size is set so that it should fit into every usual screen resolution.
   * All other widgets are always packed depending on the current window size. */
  color_win = dlg_window_new ("Ethereal: Coloring Rules");
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
  gtk_button_box_set_child_size(GTK_BUTTON_BOX(edit_vbox), 50, 20);
  gtk_container_set_border_width  (GTK_CONTAINER (edit_vbox), 5);
  gtk_container_add(GTK_CONTAINER(edit_fr), edit_vbox);

  color_new = BUTTON_NEW_FROM_STOCK(GTK_STOCK_NEW);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_new, 50, 20);
#endif
  gtk_box_pack_start (GTK_BOX (edit_vbox), color_new, FALSE, FALSE, 5);
  gtk_tooltips_set_tip (tooltips, color_new, ("Create a new filter at the end of the list"), NULL);

  color_props = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_EDIT);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_props, 50, 20);
#endif
  gtk_box_pack_start (GTK_BOX (edit_vbox), color_props, FALSE, FALSE, 5);
  gtk_tooltips_set_tip (tooltips, color_props, ("Edit the properties of the selected filter"), NULL);
  gtk_widget_set_sensitive (color_props, FALSE);

  color_delete = BUTTON_NEW_FROM_STOCK(GTK_STOCK_DELETE);
  gtk_box_pack_start (GTK_BOX (edit_vbox), color_delete, FALSE, FALSE, 5);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_delete, 50, 20);
#endif
  gtk_tooltips_set_tip (tooltips, color_delete, ("Delete the selected filter"), NULL);
  gtk_widget_set_sensitive (color_delete, FALSE);
  /* End edit buttons frame */


  /* manage buttons frame */
  manage_fr = gtk_frame_new("Manage");
  gtk_box_pack_start (GTK_BOX (ctrl_vbox), manage_fr, FALSE, FALSE, 0);
  
  manage_vbox = gtk_vbox_new (FALSE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (manage_vbox), 5);
  gtk_container_add(GTK_CONTAINER(manage_fr), manage_vbox);

  color_export = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_EXPORT);
  gtk_box_pack_start (GTK_BOX (manage_vbox), color_export, FALSE, FALSE, 5);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_export, 50, 20);
#endif
  gtk_tooltips_set_tip(tooltips, color_export, ("Save all/marked filters to a file"), NULL);

  color_import = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_IMPORT);
  gtk_box_pack_start (GTK_BOX (manage_vbox), color_import, FALSE, FALSE, 5);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_import, 50, 20);
#endif
  gtk_tooltips_set_tip(tooltips, color_import, ("Load filters from a file"), NULL);

  color_clear = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLEAR);
  gtk_box_pack_start(GTK_BOX (manage_vbox), color_clear, FALSE, FALSE, 5);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_clear, 50, 20);
#endif
  gtk_tooltips_set_tip(tooltips, color_clear, ("Clear all filters in the user's colorfilters file and revert to system-wide default filter set"), NULL);


  /* filter list frame */
  list_fr = gtk_frame_new("Filter");
  gtk_box_pack_start (GTK_BOX (main_hbox), list_fr, TRUE, TRUE, 0);

  list_vbox = gtk_vbox_new (FALSE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (list_vbox), 5);
  gtk_container_add(GTK_CONTAINER(list_fr), list_vbox);

  list_label = gtk_label_new (("[List is processed in order until match is found]"));
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

  num_of_filters = 0;
  g_slist_foreach(color_filter_list, add_filter_to_list, color_filters);

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
  WIDGET_SET_SIZE(color_filter_up, 50, 20);
#endif
  gtk_box_pack_start (GTK_BOX (order_vbox), color_filter_up, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_filter_up, ("Move filter higher in list"), NULL);
  gtk_widget_set_sensitive (color_filter_up, FALSE);

  order_move_label = gtk_label_new (("Move\nselected filter\nup or down"));
  gtk_box_pack_start (GTK_BOX (order_vbox), order_move_label, FALSE, FALSE, 0);

  color_filter_down = BUTTON_NEW_FROM_STOCK(GTK_STOCK_GO_DOWN);
#if GTK_MAJOR_VERSION < 2
  WIDGET_SET_SIZE(color_filter_down, 50, 20);
#endif
  gtk_box_pack_start (GTK_BOX (order_vbox), color_filter_down, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_filter_down, ("Move filter lower in list"), NULL);
  gtk_widget_set_sensitive (color_filter_down, FALSE);


  /* Button row: OK and cancel buttons */
  if(topic_available(HELP_COLORING_RULES_DIALOG)) {
    button_ok_hbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
  } else {
    button_ok_hbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_SAVE, GTK_STOCK_CLOSE/*, GTK_STOCK_CANCEL*/, NULL);
  }
  gtk_box_pack_start (GTK_BOX (dlg_vbox), button_ok_hbox, FALSE, FALSE, 5);

  color_ok = OBJECT_GET_DATA(button_ok_hbox, GTK_STOCK_OK);
  gtk_tooltips_set_tip (tooltips, color_ok, ("Apply the color filters to the display and close this dialog"), NULL);

  color_apply = OBJECT_GET_DATA(button_ok_hbox, GTK_STOCK_APPLY);
  gtk_tooltips_set_tip (tooltips, color_apply, ("Apply the color filters to the display but keep this dialog open"), NULL);

  color_save = OBJECT_GET_DATA(button_ok_hbox, GTK_STOCK_SAVE);
  gtk_tooltips_set_tip (tooltips, color_save, ("Save the color filters permanently and keep this dialog open"), NULL);

  color_cancel = OBJECT_GET_DATA(button_ok_hbox, GTK_STOCK_CLOSE);
  window_set_cancel_button(color_win, color_cancel, color_cancel_cb);
  gtk_tooltips_set_tip (tooltips, color_cancel, ("Close this dialog but don't apply the color filter changes to the display"), NULL);

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
  OBJECT_SET_DATA(color_filters, COLOR_PROPS_LB, color_props);
  OBJECT_SET_DATA(color_filters, COLOR_DELETE_LB, color_delete);
  OBJECT_SET_DATA(color_new, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_new, "clicked", color_new_cb, NULL);
  OBJECT_SET_DATA(color_props, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_props, "clicked", color_props_cb, NULL);
  OBJECT_SET_DATA(color_delete, COLOR_PROPS_LB, color_props);
  OBJECT_SET_DATA(color_delete, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_delete, "clicked", color_delete_cb, NULL);
  SIGNAL_CONNECT(color_save, "clicked", color_save_cb, NULL);
  SIGNAL_CONNECT(color_export, "clicked", file_color_export_cmd_cb, NULL);
  OBJECT_SET_DATA(color_import, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_import, "clicked", color_import_cb, color_filters);
  OBJECT_SET_DATA(color_clear, COLOR_FILTERS_CL, color_filters);
  SIGNAL_CONNECT(color_clear, "clicked", color_clear_cb, NULL);
  SIGNAL_CONNECT(color_ok, "clicked", color_ok_cb, NULL);
  SIGNAL_CONNECT(color_apply, "clicked", color_apply_cb, NULL);

  SIGNAL_CONNECT(color_win, "delete_event", window_delete_event_cb, NULL);

  gtk_widget_grab_focus(color_filters);

  gtk_widget_show_all(color_win);
  window_present(color_win);

  if(filter){
    /* if we specified a preset filter string, open the new dialog and
       set the filter */
    create_new_color_filter(GTK_BUTTON(color_new), filter);
  }

  return color_win;
}

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
  num_of_filters++;
}

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

  color_filter_list = g_slist_remove(color_filter_list, colorf);
  color_filter_list = g_slist_insert(color_filter_list, colorf, filter_number + amount);
}

/* Move the selected filters up in the list */
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
  if (colorf->marked)
    return;
#endif

  for (filter_number = 0; filter_number < num_of_filters; filter_number++)
  {
#if GTK_MAJOR_VERSION < 2
    colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), filter_number);
    if (colorf->marked)
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

/* Move the selected filters down in the list */
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
    if (colorf->marked)
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
    if (colorf->marked)
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
    colorf->marked = TRUE;
    
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
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_PROPS_LB);
    gtk_widget_set_sensitive (button, TRUE);
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_DELETE_LB);
    gtk_widget_set_sensitive(button, TRUE);
    
}
#else

struct remember_data
{
    gint count;               /* count of selected filters */
    gboolean first_marked;    /* true if the first filter in the list is marked */
    gboolean last_marked;     /* true if the last filter in the list is marked */
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
    colorf->marked = TRUE;
        
    path_index = gtk_tree_path_get_indices(path);   /* not to be freed */
    if (path_index == NULL)       /* can return NULL according to API doc.*/
    {
      return;
    }
    row_selected = path_index[0];

    if (row_selected == 0)
      data->first_marked = TRUE;
    if (row_selected == num_of_filters - 1)
      data->last_marked = TRUE;

    data->count++;
}

/* clear the mark on this filter */
static void
clear_mark(gpointer filter_arg, gpointer arg _U_)
{
  color_filter_t *colorf = filter_arg;

  colorf->marked = FALSE;
}

/* The gtk+2.0 version gets called for, (maybe multiple,) changes in the selection. */
static void
remember_selected_row(GtkTreeSelection *sel, gpointer color_filters)
{
    GtkWidget    *button;
    struct remember_data data;

    data.first_marked = data.last_marked = FALSE;
    data.count = 0; 
    data.color_filters = color_filters;

    g_slist_foreach(color_filter_list, clear_mark, NULL);
    gtk_tree_selection_selected_foreach(sel,remember_this_row, &data);
                                      
    if (data.count > 0)
    {
      /*
       * One or more rows are selected, so we can operate on them.
      */
       
      /* We can only edit if there is exactly one filter selected */
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_PROPS_LB);
      gtk_widget_set_sensitive (button, data.count == 1);
      
      /* We can delete any number of filters */
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_DELETE_LB);
      gtk_widget_set_sensitive (button, TRUE);
      /*
       * We can move them up *if* one of them isn't the top row,
       * and move them down *if* one of them isn't the bottom row.
      */
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_UP_LB);
      gtk_widget_set_sensitive(button, !data.first_marked);
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_DOWN_LB);
      gtk_widget_set_sensitive(button, !data.last_marked);
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
      button = (GtkWidget *)OBJECT_GET_DATA(color_filters, COLOR_PROPS_LB);
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
  colorf->marked = FALSE;

  if (color_marked_count() == 0)
  {
    /*
     * No row is selected, so we can't do operations that affect the
     * selected row.
     */
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_UP_LB);
    gtk_widget_set_sensitive (button, FALSE);
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_DOWN_LB);
    gtk_widget_set_sensitive (button, FALSE);
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_PROPS_LB);
    gtk_widget_set_sensitive (button, FALSE);
    button = (GtkWidget *)OBJECT_GET_DATA(clist, COLOR_DELETE_LB);
    gtk_widget_set_sensitive(button, FALSE);
  }
}
#endif

/* Called when the dialog box is being destroyed; destroy any edit
 * dialogs opened from this dialog, and null out the pointer to this
 * dialog.
 jjj*/
static void
color_destroy_cb                       (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
  /* Destroy any edit dialogs we have open. */
  g_slist_foreach(color_filter_list, destroy_edit_dialog_cb, NULL);

  colorize_win = NULL;
}

static void
destroy_edit_dialog_cb(gpointer filter_arg, gpointer dummy _U_)
{
  color_filter_t *colorf = (color_filter_t *)filter_arg;

  if (colorf->edit_dialog != NULL)
    window_destroy(colorf->edit_dialog);
}

/* XXX - we don't forbid having more than one "Edit color filter" dialog
   open, so these shouldn't be static. */
static GtkWidget *filt_name_entry;
static GtkWidget *filt_text_entry;

static void
color_add_colorf(GtkWidget *color_filters, color_filter_t *colorf)
{
#if GTK_MAJOR_VERSION < 2
#else
  GtkTreeModel     *model;
  gint              num_filters;
  GtkTreeIter       iter;
  GtkTreeSelection *sel;
#endif

  add_filter_to_list(colorf, color_filters);

#if GTK_MAJOR_VERSION < 2

  /* select the new row */
  gtk_clist_select_row(GTK_CLIST(color_filters), num_of_filters - 1, -1);
#else
  /* select the new row */
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  num_filters = gtk_tree_model_iter_n_children(model, NULL);
  gtk_tree_model_iter_nth_child(model, &iter, NULL, num_filters - 1);
  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
  gtk_tree_selection_select_iter(sel, &iter);
#endif
}

void
color_filter_add_cb(color_filter_t *colorf, gpointer arg)
{
  GtkWidget        *color_filters = arg;

  color_add_colorf(color_filters, colorf);
#if GTK_MAJOR_VERSION >= 2
  gtk_widget_grab_focus(color_filters);
#endif
}

/* Pop up an "Export color filter" dialog box. */
static void
color_import_cb(GtkButton *button, gpointer user_data )
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

  file_color_import_cmd_cb(GTK_WIDGET(button), user_data);
}

/* Create a new filter in the list, and pop up an "Edit color filter"
   dialog box to edit it. */
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
  colorf = color_filter_new("name", filter, &bg_color, &fg_color); /* Adds at end! */

  color_add_colorf(color_filters, colorf);

  edit_color_filter_dialog(color_filters, &filt_name_entry, &filt_text_entry, TRUE);
  
  /* Show the (in)validity of the default filter string */
  filter_te_syntax_check_cb(filt_text_entry);



#if GTK_MAJOR_VERSION >= 2
  gtk_widget_grab_focus(color_filters);
#endif
}

/* Create a new filter in the list, and pop up an "Edit color filter"
   dialog box to edit it. */
static void
color_new_cb(GtkButton *button, gpointer user_data _U_)
{
  create_new_color_filter(button, "filter");
}

/* Pop up an "Edit color filter" dialog box to edit an existing filter. */
static void
color_props_cb(GtkButton *button, gpointer user_data _U_)
{
  GtkWidget *color_filters;

  color_filters = (GtkWidget *)OBJECT_GET_DATA(button, COLOR_FILTERS_CL);
  g_assert(row_selected != -1);
  edit_color_filter_dialog(color_filters, &filt_name_entry, &filt_text_entry, FALSE);
}

/* Delete a color from the list. */
static void
color_delete(gint row, GtkWidget  *color_filters)
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
    
    /* Remove the color filter from the list of color filters. */
    color_filter_remove(colorf);
    
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

    /* Remove the color filter from the list of color filters. */
    color_filter_remove(colorf);

#endif
}
/* Delete the selected color from the list.*/
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
    
#if GTK_MAJOR_VERSION < 2
  num_filters = num_of_filters;
#else
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  num_filters = gtk_tree_model_iter_n_children(model, NULL);
  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
#endif

  for (row = num_filters - 1; row >= 0; row--)
  {
#if GTK_MAJOR_VERSION < 2
    colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), row);
    if (colorf->marked)
      color_delete (row, color_filters);
#else
    gtk_tree_model_iter_nth_child(model, &iter, NULL, row);
    if (gtk_tree_selection_iter_is_selected(sel, &iter))
      color_delete (row, color_filters);
#endif
  }
}

/* Save color filters to the color filter file. */
static void
color_save_cb(GtkButton *button _U_, gpointer user_data _U_)
{
  if (!color_filters_write())
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	    "Could not open filter file: %s", strerror(errno));
}

/* Remove all user defined color filters and revert to the global file. */
static void
color_clear_cmd(GtkWidget *widget)
{
    GtkWidget * color_filters;
    
    color_filters = (GtkWidget *)OBJECT_GET_DATA(widget, COLOR_FILTERS_CL);
    
    while (num_of_filters > 0)
    {
        color_delete (num_of_filters-1, color_filters);
    }

    if (!color_filters_revert())
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Could not delete filter file: %s", strerror(errno));

    /* colorize list */
    cf_colorize_packets(&cfile);

    /* Destroy the dialog box. */
    /* XXX: is this useful? user might want to continue with editing new colors */
    window_destroy(colorize_win);
}

/* clear button: user responded to question */
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

/* clear button: ask user before really doing it */
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

/* Exit dialog and apply new list of color filters to the capture. */
static void
color_ok_cb(GtkButton *button _U_, gpointer user_data _U_)
{
  /* colorize list */
  cf_colorize_packets(&cfile);

  /* Destroy the dialog box. */
  window_destroy(colorize_win);
}

/* Exit dialog without colorizing packets with the new list.
   XXX - should really undo any changes to the list.... */
static void
color_cancel_cb(GtkWidget *widget _U_, gpointer user_data _U_)
{
  /* Destroy the dialog box. */
  window_destroy(colorize_win);
}

/* Apply new list of color filters to the capture. */
static void
color_apply_cb(GtkButton *button _U_, gpointer user_data _U_)
{
  cf_colorize_packets(&cfile);
}

/* Create an "Edit Color Filter" dialog for a given color filter, and
   associate it with that color filter. */
static void
edit_color_filter_dialog(GtkWidget *color_filters,
                         GtkWidget **colorize_filter_name,
                         GtkWidget **colorize_filter_text,
                         guchar is_new_filter)
{
    color_filter_t *colorf;
    GtkWidget      *edit_dialog;
    GtkWidget      *dialog_vbox;
    GtkTooltips    *tooltips;
    GtkStyle       *style;

    GtkWidget *filter_fr;
    GtkWidget *filter_fr_vbox;
    GtkWidget *filter_name_hbox;
    GtkWidget *color_filter_name;
    GtkWidget *filter_string_hbox;
    GtkWidget *add_expression_bt;
    GtkWidget *color_filter_text;

    GtkWidget *colorize_fr;
    GtkWidget *colorize_hbox;
    GtkWidget *colorize_filter_fg;
    GtkWidget *colorize_filter_bg;

    GtkWidget *bbox;
    GtkWidget *edit_color_filter_ok;
    GtkWidget *edit_color_filter_cancel;

#if GTK_MAJOR_VERSION >= 2
    GtkTreeModel     *model;
    GtkTreeIter       iter;
#endif

#if GTK_MAJOR_VERSION >= 2
    model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));

    gtk_tree_model_iter_nth_child(model, &iter, NULL, row_selected);
    gtk_tree_model_get(model, &iter, 4, &colorf, -1);

#else
    colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), row_selected);
#endif
    if (colorf->edit_dialog != NULL) {
        /* There's already an edit box open for this filter; reactivate it. */
        reactivate_window(colorf->edit_dialog);
        return;
    }

    tooltips = gtk_tooltips_new ();

    /* dialog window */
    edit_dialog = dlg_window_new ("Ethereal: Edit Color Filter");
    gtk_window_set_default_size(GTK_WINDOW(edit_dialog), 500, -1);  
    OBJECT_SET_DATA(edit_dialog, "edit_dialog", edit_dialog);
    colorf->edit_dialog = edit_dialog;

    dialog_vbox = gtk_vbox_new (FALSE, 0);
    gtk_container_set_border_width  (GTK_CONTAINER (dialog_vbox), 5);
    gtk_container_add (GTK_CONTAINER (edit_dialog), dialog_vbox);

    /* Filter frame */
    filter_fr = gtk_frame_new("Filter");
    gtk_box_pack_start (GTK_BOX (dialog_vbox), filter_fr, FALSE, FALSE, 0);

    filter_fr_vbox = gtk_vbox_new (FALSE, 0);
    gtk_container_set_border_width  (GTK_CONTAINER (filter_fr_vbox), 5);
    gtk_container_add(GTK_CONTAINER(filter_fr), filter_fr_vbox);

    /* filter name hbox */
    filter_name_hbox = gtk_hbox_new (FALSE, 0);
    gtk_box_pack_start (GTK_BOX (filter_fr_vbox), filter_name_hbox, TRUE, FALSE, 3);

    color_filter_name = gtk_label_new (("Name: "));
    gtk_box_pack_start (GTK_BOX (filter_name_hbox), color_filter_name, FALSE, FALSE, 0);

    *colorize_filter_name = gtk_entry_new ();
    gtk_entry_set_text(GTK_ENTRY(*colorize_filter_name), colorf->filter_name);

    style = gtk_style_copy(gtk_widget_get_style(*colorize_filter_name));
    color_t_to_gdkcolor(&style->base[GTK_STATE_NORMAL], &colorf->bg_color);
#if GTK_MAJOR_VERSION < 2
    color_t_to_gdkcolor(&style->fg[GTK_STATE_NORMAL], &colorf->fg_color);
#else
    color_t_to_gdkcolor(&style->text[GTK_STATE_NORMAL], &colorf->fg_color);
#endif
    gtk_widget_set_style(*colorize_filter_name, style);

    gtk_box_pack_start (GTK_BOX (filter_name_hbox), *colorize_filter_name, TRUE, TRUE, 0);
    gtk_tooltips_set_tip (tooltips, *colorize_filter_name, ("This is the editable name of the filter. (No @ characters allowed.)"), NULL);


    /* filter string hbox */
    filter_string_hbox = gtk_hbox_new (FALSE, 0);
    gtk_box_pack_start (GTK_BOX (filter_fr_vbox), filter_string_hbox, TRUE, FALSE, 3);

    color_filter_text = gtk_label_new (("String: "));
    gtk_box_pack_start (GTK_BOX (filter_string_hbox), color_filter_text, FALSE, FALSE, 0);

    *colorize_filter_text = gtk_entry_new ();
    SIGNAL_CONNECT(*colorize_filter_text, "changed", filter_te_syntax_check_cb, NULL);
    gtk_entry_set_text(GTK_ENTRY(*colorize_filter_text), colorf->filter_text);

#if 0
    style = gtk_style_copy(gtk_widget_get_style(*colorize_filter_text));
    style->base[GTK_STATE_NORMAL] = colorf->bg_color;
    style->fg[GTK_STATE_NORMAL]   = colorf->fg_color;
#endif
    gtk_widget_set_style(*colorize_filter_text, style);
    gtk_style_unref(style);
    gtk_box_pack_start (GTK_BOX (filter_string_hbox), *colorize_filter_text, TRUE, TRUE, 0);
    gtk_tooltips_set_tip (tooltips, *colorize_filter_text, ("This is the editable text of the filter"), NULL);

    /* Create the "Add Expression..." button, to pop up a dialog
       for constructing filter comparison expressions. */
    add_expression_bt = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_ADD_EXPRESSION);
    SIGNAL_CONNECT(add_expression_bt, "clicked", filter_expr_cb, *colorize_filter_text);
    gtk_box_pack_start (GTK_BOX(filter_string_hbox), add_expression_bt, FALSE, FALSE, 3);
    gtk_tooltips_set_tip (tooltips, add_expression_bt, ("Add an expression to the filter string"), NULL);


    /* choose color frame */
    colorize_fr = gtk_frame_new("Display Colors");
    gtk_box_pack_start (GTK_BOX (dialog_vbox), colorize_fr, FALSE, FALSE, 0);

    colorize_hbox = gtk_hbox_new (FALSE, 0);
    gtk_container_set_border_width  (GTK_CONTAINER (colorize_hbox), 5);
    gtk_container_add(GTK_CONTAINER(colorize_fr), colorize_hbox);

    colorize_filter_fg = gtk_button_new_with_label (("Foreground Color..."));
    gtk_box_pack_start (GTK_BOX (colorize_hbox), colorize_filter_fg, TRUE, FALSE, 0);
    gtk_tooltips_set_tip (tooltips, colorize_filter_fg, ("Select foreground color for data display"), NULL);

    colorize_filter_bg = gtk_button_new_with_label (("Background Color..."));
    gtk_box_pack_start (GTK_BOX (colorize_hbox), colorize_filter_bg, TRUE, FALSE, 0);
    gtk_tooltips_set_tip (tooltips, colorize_filter_bg, ("Select background color for data display"), NULL);


    /* button box */
    bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CANCEL, NULL);
	gtk_box_pack_start(GTK_BOX(dialog_vbox), bbox, FALSE, FALSE, 0);
    gtk_container_set_border_width  (GTK_CONTAINER (bbox), 0);

    edit_color_filter_ok = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
    gtk_tooltips_set_tip (tooltips, edit_color_filter_ok, ("Accept filter color change"), NULL);

    edit_color_filter_cancel = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
    gtk_tooltips_set_tip (tooltips, edit_color_filter_cancel, ("Reject filter color change"), NULL);

    gtk_widget_grab_default(edit_color_filter_ok);

    /* signals and such */
    OBJECT_SET_DATA(edit_dialog, COLOR_FILTER, colorf);
    SIGNAL_CONNECT(edit_dialog, "destroy", edit_color_filter_destroy_cb, NULL);
    OBJECT_SET_DATA(colorize_filter_fg, COLOR_FILTER, colorf);
    SIGNAL_CONNECT(colorize_filter_fg, "clicked", edit_color_filter_fg_cb, NULL);
    OBJECT_SET_DATA(colorize_filter_bg, COLOR_FILTER, colorf);
    SIGNAL_CONNECT(colorize_filter_bg, "clicked", edit_color_filter_bg_cb, NULL);
    OBJECT_SET_DATA(edit_color_filter_ok, COLOR_FILTERS_CL, color_filters);
    OBJECT_SET_DATA(edit_color_filter_ok, COLOR_FILTER, colorf);
    SIGNAL_CONNECT(edit_color_filter_ok, "clicked", edit_color_filter_ok_cb, edit_dialog);

    /* set callback to delete new filters if cancel chosen */
    if (is_new_filter)
    {
        OBJECT_SET_DATA(edit_color_filter_cancel, COLOR_FILTERS_CL, color_filters);
        SIGNAL_CONNECT(edit_color_filter_cancel, "clicked",
                       edit_new_color_filter_cancel_cb, edit_dialog);
    }
    /* escape will select cancel */
    window_set_cancel_button(edit_dialog, edit_color_filter_cancel, window_cancel_button_cb);

    SIGNAL_CONNECT(edit_dialog, "delete_event", window_delete_event_cb, NULL);

    gtk_widget_show_all(edit_dialog);
    window_present(edit_dialog);
}

/* Called when the dialog box is being destroyed; destroy any color
   selection dialogs opened from this dialog, and null out the pointer
   to this dialog. */
#if GTK_MAJOR_VERSION < 2
static void
edit_color_filter_destroy_cb(GtkObject *object, gpointer user_data _U_)
#else
static void
edit_color_filter_destroy_cb(GObject *object, gpointer user_data _U_)
#endif
{
  color_filter_t *colorf;
  GtkWidget *color_sel;

  colorf = (color_filter_t *)OBJECT_GET_DATA(object, COLOR_FILTER);
  colorf->edit_dialog = NULL;

  /* Destroy any color selection dialogs this dialog had open. */
  color_sel = (GtkWidget *)OBJECT_GET_DATA(object, COLOR_SELECTION_FG);
  if (color_sel != NULL)
    window_destroy(color_sel);
  color_sel = (GtkWidget *)OBJECT_GET_DATA(object, COLOR_SELECTION_BG);
  if (color_sel != NULL)
    window_destroy(color_sel);
}

/* Pop up a color selection box to choose the foreground color. */
static void
edit_color_filter_fg_cb(GtkButton *button, gpointer user_data _U_)
{
  color_filter_t *colorf;
  GtkWidget *color_selection_fg;

  colorf = (color_filter_t *)OBJECT_GET_DATA(button, COLOR_FILTER);
  /* Do we already have one open for this dialog? */
  color_selection_fg = OBJECT_GET_DATA(colorf->edit_dialog, COLOR_SELECTION_FG);
  if (color_selection_fg != NULL) {
    /* Yes.  Just reactivate it. */
    reactivate_window(color_selection_fg);
  } else {
    /* No.  Create a new color selection box, and associate it with
       this dialog. */
    color_selection_fg = color_sel_win_new(colorf, FALSE);
    OBJECT_SET_DATA(colorf->edit_dialog, COLOR_SELECTION_FG, color_selection_fg);
    OBJECT_SET_DATA(color_selection_fg, COLOR_SELECTION_PARENT, colorf->edit_dialog);
  }
}

/* Pop up a color selection box to choose the background color. */
static void
edit_color_filter_bg_cb                (GtkButton       *button,
                                        gpointer         user_data _U_)
{
  color_filter_t *colorf;
  GtkWidget *color_selection_bg;

  colorf = (color_filter_t *)OBJECT_GET_DATA(button, COLOR_FILTER);
  /* Do we already have one open for this dialog? */
  color_selection_bg = OBJECT_GET_DATA(colorf->edit_dialog, COLOR_SELECTION_BG);
  if (color_selection_bg != NULL) {
    /* Yes.  Just reactivate it. */
    reactivate_window(color_selection_bg);
  } else {
    /* No.  Create a new color selection box, and associate it with
       this dialog. */
    color_selection_bg = color_sel_win_new(colorf, TRUE);
    OBJECT_SET_DATA(colorf->edit_dialog, COLOR_SELECTION_BG, color_selection_bg);
    OBJECT_SET_DATA(color_selection_bg, COLOR_SELECTION_PARENT, colorf->edit_dialog);
  }
}

/* accept color (and potential content) change */
static void
edit_color_filter_ok_cb                (GtkButton       *button,
                                        gpointer         user_data)
{
    GtkWidget      *dialog;
    GtkStyle       *style;
    GdkColor        new_fg_color;
    GdkColor        new_bg_color;
    gchar          *filter_name;
    gchar          *filter_text;
    color_filter_t *colorf;
    dfilter_t      *compiled_filter;
    GtkWidget      *color_filters;
#if GTK_MAJOR_VERSION >= 2
    GtkTreeModel   *model;
    GtkTreeIter     iter;
    gchar           fg_str[14], bg_str[14];
#endif

    dialog = (GtkWidget *)user_data;

    style = gtk_widget_get_style(filt_name_entry);
    new_bg_color = style->base[GTK_STATE_NORMAL];
#if GTK_MAJOR_VERSION < 2
    new_fg_color = style->fg[GTK_STATE_NORMAL];
#else
    new_fg_color = style->text[GTK_STATE_NORMAL];
#endif

    filter_name = g_strdup(gtk_entry_get_text(GTK_ENTRY(filt_name_entry)));
    filter_text = g_strdup(gtk_entry_get_text(GTK_ENTRY(filt_text_entry)));

    if(strchr(filter_name,'@') || strchr(filter_text,'@')){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Filter names and strings must not"
                      " use the '@' character. Filter unchanged.");
        g_free(filter_name);
        g_free(filter_text);
        return;
    }

    if(!dfilter_compile(filter_text, &compiled_filter)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Filter \"%s\" didn't compile correctly.\n"
                      " Please try again. Filter unchanged.\n%s\n", filter_name,
                      dfilter_error_msg);
    } else {
        color_filters = (GtkWidget *)OBJECT_GET_DATA(button, COLOR_FILTERS_CL);
        colorf = (color_filter_t *)OBJECT_GET_DATA(button, COLOR_FILTER);

        if (colorf->filter_name != NULL)
            g_free(colorf->filter_name);
        colorf->filter_name = filter_name;
        if (colorf->filter_text != NULL)
            g_free(colorf->filter_text);
        colorf->filter_text = filter_text;
        gdkcolor_to_color_t(&colorf->fg_color, &new_fg_color);
        gdkcolor_to_color_t(&colorf->bg_color, &new_bg_color);
#if GTK_MAJOR_VERSION < 2
        gtk_clist_set_foreground(GTK_CLIST(color_filters), row_selected,
                                 &new_fg_color);
        gtk_clist_set_background(GTK_CLIST(color_filters), row_selected,
                                 &new_bg_color);
#else
        g_snprintf(fg_str, 14, "#%04X%04X%04X",
                new_fg_color.red, new_fg_color.green, new_fg_color.blue);
        g_snprintf(bg_str, 14, "#%04X%04X%04X",
                new_bg_color.red, new_bg_color.green, new_bg_color.blue);
        model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
        gtk_tree_model_iter_nth_child(model, &iter, NULL, row_selected);
        gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, filter_name,
                           1, filter_text, 2, fg_str, 3, bg_str, -1);
#endif
        if(colorf->c_colorfilter != NULL)
            dfilter_free(colorf->c_colorfilter);
        colorf->c_colorfilter = compiled_filter;
#if GTK_MAJOR_VERSION < 2
        /* gtk_clist_set_text frees old text (if any) and allocates new space */
        gtk_clist_set_text(GTK_CLIST(color_filters), row_selected, 0,
                           filter_name);
        gtk_clist_set_text(GTK_CLIST(color_filters), row_selected, 1,
                           filter_text);
#endif

        /* Destroy the dialog box. */
        window_destroy(dialog);
    }
}

/* reject new color filter addition */
static void
edit_new_color_filter_cancel_cb(GtkButton *button, gpointer user_data _U_)
{
    /* Delete the entry.  N.B. this already destroys the edit_dialog window. */
    color_delete(num_of_filters-1, (GtkWidget*)OBJECT_GET_DATA(button, COLOR_FILTERS_CL));
}

static GtkWidget*
color_sel_win_new(color_filter_t *colorf, gboolean is_bg)
{
  gchar *title;
  GtkWidget *color_sel_win;
  color_t   *color;
#if GTK_MAJOR_VERSION >= 2
  GdkColor   gcolor;
#endif
  GtkWidget *color_sel_ok;
  GtkWidget *color_sel_cancel;
  GtkWidget *color_sel_help;

  if (is_bg) {
    color = &colorf->bg_color;
    title = g_strdup_printf("Ethereal: Choose background color for \"%s\"",
        colorf->filter_name);
  } else {
    color = &colorf->fg_color;
    title = g_strdup_printf("Ethereal: Choose foreground color for \"%s\"", 
        colorf->filter_name);
  }
  color_sel_win = gtk_color_selection_dialog_new(title);
  g_free(title);
  OBJECT_SET_DATA(color_sel_win, "color_sel_win", color_sel_win);
  gtk_container_set_border_width (GTK_CONTAINER (color_sel_win), 10);

  if (color != NULL) {
#if GTK_MAJOR_VERSION < 2
    gdouble cols[3];

    cols[0] = (gdouble)color->red / 65536.0;
    cols[1] = (gdouble)color->green / 65536.0;
    cols[2] = (gdouble)color->blue / 65536.0;

    gtk_color_selection_set_color(
		    GTK_COLOR_SELECTION(
			    GTK_COLOR_SELECTION_DIALOG(color_sel_win)->colorsel), cols);
#else
    color_t_to_gdkcolor(&gcolor, color);
    gtk_color_selection_set_current_color(
		    GTK_COLOR_SELECTION(
			    GTK_COLOR_SELECTION_DIALOG(color_sel_win)->colorsel), &gcolor);
#endif
  }

  color_sel_ok = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->ok_button;
  OBJECT_SET_DATA(color_sel_win, "color_sel_ok", color_sel_ok);
  GTK_WIDGET_SET_FLAGS (color_sel_ok, GTK_CAN_DEFAULT);

  color_sel_cancel = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->cancel_button;
  OBJECT_SET_DATA(color_sel_win, "color_sel_cancel", color_sel_cancel);
  GTK_WIDGET_SET_FLAGS (color_sel_cancel, GTK_CAN_DEFAULT);


  color_sel_help = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->help_button;
  OBJECT_SET_DATA(color_sel_win, "color_sel_help", color_sel_help);


  GTK_WIDGET_SET_FLAGS (color_sel_help, GTK_CAN_DEFAULT);

  SIGNAL_CONNECT(color_sel_ok, "clicked", color_sel_ok_cb, color_sel_win);
  SIGNAL_CONNECT(color_sel_cancel, "clicked", color_sel_cancel_cb, color_sel_win);

  gtk_widget_show_all(color_sel_win);
  return color_sel_win;
}

static void
color_sel_win_destroy(GtkWidget *sel_win)
{
  GtkWidget *parent;
  GtkWidget *color_selection_fg, *color_selection_bg;

  /* Find the "Edit color filter" dialog box with which this is associated. */
  parent = (GtkWidget *)OBJECT_GET_DATA(sel_win, COLOR_SELECTION_PARENT);

  /* Find that dialog box's foreground and background color selection
     boxes, if any. */
  color_selection_fg = OBJECT_GET_DATA(parent, COLOR_SELECTION_FG);
  color_selection_bg = OBJECT_GET_DATA(parent, COLOR_SELECTION_BG);

  if (sel_win == color_selection_fg) {
    /* This was its foreground color selection box; it isn't, anymore. */
    OBJECT_SET_DATA(parent, COLOR_SELECTION_FG, NULL);
  }
  if (sel_win == color_selection_bg) {
    /* This was its background color selection box; it isn't, anymore. */
    OBJECT_SET_DATA(parent, COLOR_SELECTION_BG, NULL);
  }

  /* Now destroy it. */
  window_destroy(sel_win);
}

/* Retrieve selected color */
static void
color_sel_ok_cb                        (GtkButton       *button _U_,
                                        gpointer         user_data)
{
  GdkColor new_color; /* Color from color selection dialog */
#if GTK_MAJOR_VERSION < 2
  gdouble new_colors[3];
#endif
  GtkWidget *color_dialog;
  GtkStyle  *style;
  GtkWidget *parent;
  GtkWidget *color_selection_fg, *color_selection_bg;
  gboolean is_bg;

  color_dialog = (GtkWidget *)user_data;

#if GTK_MAJOR_VERSION < 2
  gtk_color_selection_get_color(GTK_COLOR_SELECTION(
   GTK_COLOR_SELECTION_DIALOG(color_dialog)->colorsel), new_colors);

  new_color.red   = (guint16)(new_colors[0]*65535.0);
  new_color.green = (guint16)(new_colors[1]*65535.0);
  new_color.blue  = (guint16)(new_colors[2]*65535.0);
#else
  gtk_color_selection_get_current_color(GTK_COLOR_SELECTION(
   GTK_COLOR_SELECTION_DIALOG(color_dialog)->colorsel), &new_color);
#endif

  if ( ! get_color(&new_color) ){
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	              "Could not allocate color.  Try again.");
  } else {
	/* Find the "Edit color filter" dialog box with which this is
	   associated. */
	parent = (GtkWidget *)OBJECT_GET_DATA(color_dialog, COLOR_SELECTION_PARENT);

	/* Find that dialog box's foreground and background color selection
	   boxes, if any. */
	color_selection_fg = OBJECT_GET_DATA(parent, COLOR_SELECTION_FG);
	color_selection_bg = OBJECT_GET_DATA(parent, COLOR_SELECTION_BG);
	is_bg = (color_dialog == color_selection_bg);

	color_sel_win_destroy(color_dialog);

	/* now apply the change to the fore/background */

	style = gtk_style_copy(gtk_widget_get_style(filt_name_entry));
	if (is_bg)
	  style->base[GTK_STATE_NORMAL] = new_color;
#if GTK_MAJOR_VERSION < 2
	else
	  style->fg[GTK_STATE_NORMAL] = new_color;
#else
        else
	  style->text[GTK_STATE_NORMAL] = new_color;
#endif
	gtk_widget_set_style(filt_name_entry, style);
	gtk_widget_set_style(filt_text_entry, style);
	gtk_style_unref(style);
  }
}

/* Don't choose the selected color as the foreground or background
   color for the filter. */
static void
color_sel_cancel_cb                    (GtkObject       *object _U_,
                                        gpointer         user_data)
{
  GtkWidget *color_dialog;
  color_dialog = (GtkWidget *)user_data;
  /* nothing to change here.  Just get rid of the dialog box. */

  color_sel_win_destroy(color_dialog);
}
