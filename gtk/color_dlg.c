/* color_dlg.c
 * Definitions for dialog boxes for color filters
 *
 * $Id: color_dlg.c,v 1.20 2002/11/03 17:38:32 oabad Exp $
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
#include "colors.h"
#include "color_dlg.h"
#include "color_utils.h"
#include "file.h"
#include <epan/dfilter/dfilter.h>
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "ui_util.h"
#include "dfilter_expr_dlg.h"


static GtkWidget* colorize_dialog_new(void);
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
static void color_new_cb(GtkButton *button, gpointer user_data);
static void color_edit_cb(GtkButton *button, gpointer user_data);
static void color_delete_cb(GtkWidget *widget, gpointer user_data);
static void color_save_cb(GtkButton *button, gpointer user_data);
static void color_ok_cb(GtkButton *button, gpointer user_data);
static void color_cancel_cb(GtkWidget *widget, gpointer user_data);
static void color_apply_cb(GtkButton *button, gpointer user_data);

static void edit_color_filter_dialog_new(GtkWidget *color_filters,
                                         GtkWidget **colorize_filter_name,
                                         GtkWidget **colorize_filter_text);
#if GTK_MAJOR_VERSION < 2
static void edit_color_filter_destroy_cb(GtkObject *object, gpointer user_data);
#else
static void edit_color_filter_destroy_cb(GObject *object, gpointer user_data);
#endif
static void edit_color_filter_fg_cb(GtkButton *button, gpointer user_data);
static void edit_color_filter_bg_cb(GtkButton *button, gpointer user_data);
static void edit_color_filter_ok_cb(GtkButton *button, gpointer user_data);
static void edit_color_filter_cancel_cb(GtkObject *object, gpointer user_data);

static GtkWidget* color_sel_win_new(color_filter_t *colorf, gboolean);
static void color_sel_ok_cb(GtkButton *button, gpointer user_data);
static void color_sel_cancel_cb(GtkObject *object, gpointer user_data);

static GtkWidget *colorize_win;
static gint	  num_of_filters;  /* number of filters being displayed */
static gint	  row_selected;	   /* row in color_filters that is selected */

static gchar *titles[2] = { "Name", "String" };

#define COLOR_UP_LB		"color_up_lb"
#define COLOR_DOWN_LB		"color_down_lb"
#define COLOR_EDIT_LB		"color_edit_lb"
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
    colorize_win = colorize_dialog_new();
  }
}

/* Create the "Apply Color Filters" dialog. */
static GtkWidget*
colorize_dialog_new (void)
{
  GtkWidget *color_win;
  GtkWidget *dlg_vbox;
  GtkWidget *main_hbox;
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
  GtkWidget *button_edit_vbox;
  GtkWidget *color_new;
  GtkWidget *color_edit;
  GtkWidget *color_delete;

  GtkWidget *button_ok_hbox;
  GtkWidget *color_ok;
  GtkWidget *color_apply;
  GtkWidget *color_save;
  GtkWidget *color_cancel;

#if GTK_MAJOR_VERSION >= 2
  GtkListStore      *store;
  GtkCellRenderer   *renderer;
  GtkTreeViewColumn *column;
  GtkTreeSelection  *selection;
#endif

  row_selected = -1; /* no row selected */
  tooltips = gtk_tooltips_new ();

  /* Resizing of the dialog window is now reasonably done.
   * Default size is set so that it should fit into every usual screen resolution.
   * All other widgets are always packed depending on the current window size. */
  color_win = dlg_window_new ("Ethereal: Apply Color Filters");
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data(GTK_OBJECT(color_win), "color_win", color_win);
#else
  g_object_set_data(G_OBJECT(color_win), "color_win", color_win);
#endif
  gtk_window_set_default_size(GTK_WINDOW(color_win), 600, 350);  
  dlg_vbox = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (dlg_vbox);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "dlg_vbox", dlg_vbox,
                           (GtkDestroyNotify) gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "dlg_vbox", dlg_vbox,
                         (GtkDestroyNotify) gtk_widget_unref);
#endif
  gtk_container_set_border_width  (GTK_CONTAINER (dlg_vbox), 5);
  gtk_widget_show (dlg_vbox);
  gtk_container_add (GTK_CONTAINER (color_win), dlg_vbox);

  main_hbox = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (main_hbox);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "main_hbox", main_hbox,
                           (GtkDestroyNotify) gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "main_hbox", main_hbox,
                         (GtkDestroyNotify) gtk_widget_unref);
#endif
  gtk_widget_show (main_hbox);
  gtk_box_pack_start (GTK_BOX (dlg_vbox), main_hbox, TRUE, TRUE, 0);

  /* order frame */
  order_fr = gtk_frame_new("Order");
  gtk_box_pack_start (GTK_BOX (main_hbox), order_fr, FALSE, FALSE, 0);
  gtk_widget_show(order_fr);

  order_vbox = gtk_vbox_new (TRUE, 0);
  gtk_widget_ref (order_vbox);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "order_vbox", order_vbox,
                           (GtkDestroyNotify) gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "order_vbox", order_vbox,
                         (GtkDestroyNotify) gtk_widget_unref);
#endif
  gtk_container_set_border_width  (GTK_CONTAINER (order_vbox), 5);
  gtk_widget_show (order_vbox);
  gtk_container_add(GTK_CONTAINER(order_fr), order_vbox);

  color_filter_up = gtk_button_new_with_label (("Up"));
  gtk_widget_ref (color_filter_up);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "color_filter_up",
                           color_filter_up, (GtkDestroyNotify)gtk_widget_unref);
  gtk_widget_set_usize (color_filter_up, -1, 20);
#else
  g_object_set_data_full(G_OBJECT(color_win), "color_filter_up",
                         color_filter_up, (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (color_filter_up);
  gtk_box_pack_start (GTK_BOX (order_vbox), color_filter_up, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_filter_up, ("Move filter higher in list"), NULL);
  gtk_widget_set_sensitive (color_filter_up, FALSE);

  order_move_label = gtk_label_new (("Move\nselected filter\nup or down"));
  gtk_widget_ref (order_move_label);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "order_move_label",
                           order_move_label,
                           (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "order_move_label",
                         order_move_label, (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (order_move_label);
  gtk_box_pack_start (GTK_BOX (order_vbox), order_move_label, FALSE, FALSE, 0);

  color_filter_down = gtk_button_new_with_label (("Down"));
  gtk_widget_ref (color_filter_down);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "color_filter_down",
                           color_filter_down,
                           (GtkDestroyNotify)gtk_widget_unref);
  gtk_widget_set_usize(color_filter_down, -1, 20);
#else
  g_object_set_data_full(G_OBJECT(color_win), "color_filter_down",
                         color_filter_down, (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (color_filter_down);
  gtk_box_pack_start (GTK_BOX (order_vbox), color_filter_down, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_filter_down, ("Move filter lower in list"), NULL);
  gtk_widget_set_sensitive (color_filter_down, FALSE);
  /* End order_frame */

  /* list frame */
  list_fr = gtk_frame_new("Filter");
  gtk_box_pack_start (GTK_BOX (main_hbox), list_fr, TRUE, TRUE, 0);
  gtk_widget_show(list_fr);

  list_vbox = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (list_vbox);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "list_vbox", list_vbox,
                           (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "list_vbox", list_vbox,
                         (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_container_set_border_width  (GTK_CONTAINER (list_vbox), 5);
  gtk_widget_show (list_vbox);
  gtk_container_add(GTK_CONTAINER(list_fr), list_vbox);

  /* create the list of filters */
  scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow1),
                                 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
#endif
  gtk_widget_ref (scrolledwindow1);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "scrolledwindow1",
                           scrolledwindow1, (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "scrolledwindow1",
                         scrolledwindow1, (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (scrolledwindow1);
  gtk_box_pack_start (GTK_BOX (list_vbox), scrolledwindow1, TRUE, TRUE, 0);

#if GTK_MAJOR_VERSION < 2
  color_filters = gtk_clist_new_with_titles(2, titles);
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
  g_slist_foreach(filter_list, add_filter_to_list, color_filters);
#if GTK_MAJOR_VERSION >= 2
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
  gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);
#endif

  gtk_widget_show (color_filters);
  gtk_container_add (GTK_CONTAINER (scrolledwindow1), color_filters);
#if GTK_MAJOR_VERSION < 2
  gtk_clist_set_column_width (GTK_CLIST (color_filters), 0, 80);
  gtk_clist_set_column_width (GTK_CLIST (color_filters), 1, 300);
  gtk_clist_column_titles_show (GTK_CLIST (color_filters));
#endif

  list_label = gtk_label_new (("[List is processed in order until match is found]"));
  gtk_widget_ref (list_label);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "list_label", list_label,
                           (GtkDestroyNotify) gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "list_label", list_label,
                         (GtkDestroyNotify) gtk_widget_unref);
#endif
  gtk_widget_show (list_label);
  gtk_box_pack_start (GTK_BOX (list_vbox), list_label, FALSE, FALSE, 0);
  /* end list_frame */

  /* edit buttons frame */
  edit_fr = gtk_frame_new("Edit");
  gtk_box_pack_start (GTK_BOX (main_hbox), edit_fr, FALSE, FALSE, 0);
  gtk_widget_show(edit_fr);

  /* button_edit_vbox is first button column (containing: new, edit and such) */
  button_edit_vbox = gtk_vbutton_box_new();
  gtk_widget_ref (button_edit_vbox);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "button_edit_vbox",
                           button_edit_vbox,
                           (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "button_edit_vbox",
                         button_edit_vbox, (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_button_box_set_child_size(GTK_BUTTON_BOX(button_edit_vbox), 50, 20);
  gtk_container_set_border_width  (GTK_CONTAINER (button_edit_vbox), 5);
  gtk_widget_show (button_edit_vbox);
  gtk_container_add(GTK_CONTAINER(edit_fr), button_edit_vbox);

#if GTK_MAJOR_VERSION < 2
  color_new = gtk_button_new_with_label (("New..."));
#else
  color_new = gtk_button_new_from_stock(GTK_STOCK_NEW);
#endif
  gtk_widget_ref (color_new);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "color_new", color_new,
                           (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "color_new", color_new,
                         (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (color_new);
#if GTK_MAJOR_VERSION < 2
  gtk_widget_set_usize (color_new, 50, 20);
#endif
  gtk_box_pack_start (GTK_BOX (button_edit_vbox), color_new, FALSE, FALSE, 5);
  gtk_tooltips_set_tip (tooltips, color_new, ("Create a new filter after the selected filter"), NULL);

  color_edit = gtk_button_new_with_label (("Edit..."));
  gtk_widget_ref (color_edit);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "color_edit", color_edit,
                           (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "color_edit", color_edit,
                         (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (color_edit);
#if GTK_MAJOR_VERSION < 2
  gtk_widget_set_usize(color_edit, 50, 20);
#endif
  gtk_box_pack_start (GTK_BOX (button_edit_vbox), color_edit, FALSE, FALSE, 5);
  gtk_tooltips_set_tip (tooltips, color_edit, ("Edit the selected filter"), NULL);
  gtk_widget_set_sensitive (color_edit, FALSE);

#if GTK_MAJOR_VERSION < 2
  color_delete = gtk_button_new_with_label (("Delete"));
#else
  color_delete = gtk_button_new_from_stock(GTK_STOCK_DELETE);
#endif
  gtk_widget_ref (color_delete);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "color_delete", color_delete,
                           (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "color_delete", color_delete,
                         (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (color_delete);
  gtk_box_pack_start (GTK_BOX (button_edit_vbox), color_delete, FALSE, FALSE, 5);
#if GTK_MAJOR_VERSION < 2
  gtk_widget_set_usize (color_delete, 50, 20);
#endif
  gtk_tooltips_set_tip (tooltips, color_delete, ("Delete the selected filter"), NULL);
  gtk_widget_set_sensitive (color_delete, FALSE);
  /* End edit buttons frame */

  /* button_ok_hbox is bottom button row */
  button_ok_hbox = gtk_hbutton_box_new();
  gtk_widget_ref (button_ok_hbox);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "button_ok_hbox",
                           button_ok_hbox, (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "button_ok_hbox",
                         button_ok_hbox, (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (button_ok_hbox);
  gtk_box_pack_start (GTK_BOX (dlg_vbox), button_ok_hbox, FALSE, FALSE, 5);

#if GTK_MAJOR_VERSION < 2
  color_ok = gtk_button_new_with_label (("OK"));
#else
  color_ok = gtk_button_new_from_stock(GTK_STOCK_OK);
#endif
  gtk_widget_ref (color_ok);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "color_ok", color_ok,
                           (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "color_ok", color_ok,
                         (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (color_ok);
  gtk_box_pack_start (GTK_BOX (button_ok_hbox), color_ok, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_ok, ("Accept filter list; apply changes"), NULL);

#if GTK_MAJOR_VERSION < 2
  color_apply = gtk_button_new_with_label (("Apply"));
#else
  color_apply = gtk_button_new_from_stock(GTK_STOCK_APPLY);
#endif
  gtk_widget_ref (color_apply);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "color_apply", color_apply,
                           (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "color_apply", color_apply,
                         (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (color_apply);
  gtk_box_pack_start (GTK_BOX (button_ok_hbox), color_apply, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_apply, ("Apply filters in list"), NULL);

#if GTK_MAJOR_VERSION < 2
  color_save = gtk_button_new_with_label (("Save"));
#else
  color_save = gtk_button_new_from_stock(GTK_STOCK_SAVE);
#endif
  gtk_widget_ref (color_save);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "color_save", color_save,
                           (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "color_save", color_save,
                         (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (color_save);
  gtk_box_pack_start (GTK_BOX (button_ok_hbox), color_save, FALSE, FALSE, 5);
  gtk_tooltips_set_tip (tooltips, color_save, ("Save all filters to disk"), NULL);

#if GTK_MAJOR_VERSION < 2
  color_cancel = gtk_button_new_with_label (("Cancel"));
#else
  color_cancel = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
#endif
  gtk_widget_ref (color_cancel);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data_full(GTK_OBJECT(color_win), "color_cancel", color_cancel,
                           (GtkDestroyNotify)gtk_widget_unref);
#else
  g_object_set_data_full(G_OBJECT(color_win), "color_cancel", color_cancel,
                         (GtkDestroyNotify)gtk_widget_unref);
#endif
  gtk_widget_show (color_cancel);
  gtk_box_pack_start (GTK_BOX (button_ok_hbox), color_cancel, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_cancel, ("No more filter changes; don't apply"), NULL);

  /* signals and such */
#if GTK_MAJOR_VERSION < 2
  gtk_signal_connect(GTK_OBJECT (color_win), "destroy",
                     GTK_SIGNAL_FUNC (color_destroy_cb), NULL);
  gtk_object_set_data(GTK_OBJECT (color_filter_up), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect(GTK_OBJECT (color_filter_up), "clicked",
                     GTK_SIGNAL_FUNC (color_filter_up_cb), NULL);
  gtk_object_set_data(GTK_OBJECT (color_filter_down), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect(GTK_OBJECT (color_filter_down), "clicked",
                     GTK_SIGNAL_FUNC (color_filter_down_cb), NULL);
  gtk_signal_connect(GTK_OBJECT (color_filters), "select_row",
                     GTK_SIGNAL_FUNC (remember_selected_row), NULL);
  gtk_signal_connect(GTK_OBJECT (color_filters), "unselect_row",
                     GTK_SIGNAL_FUNC (unremember_selected_row), NULL);
  gtk_object_set_data(GTK_OBJECT (color_filters), COLOR_UP_LB,
                      color_filter_up);
  gtk_object_set_data(GTK_OBJECT (color_filters), COLOR_DOWN_LB,
                      color_filter_down);
  gtk_object_set_data(GTK_OBJECT (color_filters), COLOR_EDIT_LB,
                      color_edit);
  gtk_object_set_data(GTK_OBJECT (color_filters), COLOR_DELETE_LB,
                      color_delete);
  gtk_object_set_data(GTK_OBJECT (color_new), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect(GTK_OBJECT (color_new), "clicked",
                     GTK_SIGNAL_FUNC (color_new_cb), NULL);
  gtk_object_set_data(GTK_OBJECT (color_edit), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect(GTK_OBJECT (color_edit), "clicked",
                     GTK_SIGNAL_FUNC (color_edit_cb), NULL);
  gtk_object_set_data(GTK_OBJECT (color_delete), COLOR_EDIT_LB,
                      color_edit);
  gtk_object_set_data(GTK_OBJECT (color_delete), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect(GTK_OBJECT (color_delete), "clicked",
                     GTK_SIGNAL_FUNC (color_delete_cb), NULL);
  gtk_signal_connect(GTK_OBJECT (color_save), "clicked",
                     GTK_SIGNAL_FUNC (color_save_cb), NULL);
  gtk_signal_connect(GTK_OBJECT (color_ok), "clicked",
                     GTK_SIGNAL_FUNC (color_ok_cb), NULL);
  gtk_signal_connect(GTK_OBJECT (color_apply), "clicked",
                     GTK_SIGNAL_FUNC (color_apply_cb), NULL);
  gtk_signal_connect(GTK_OBJECT (color_cancel), "clicked",
                     GTK_SIGNAL_FUNC (color_cancel_cb), NULL);
#else
  g_signal_connect(G_OBJECT(color_win), "destroy", G_CALLBACK(color_destroy_cb),
                   NULL);
  g_object_set_data(G_OBJECT(color_filter_up), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(G_OBJECT(color_filter_up), "clicked",
                   G_CALLBACK(color_filter_up_cb), NULL);
  g_object_set_data(G_OBJECT(color_filter_down), COLOR_FILTERS_CL,
                    color_filters);
  g_signal_connect(G_OBJECT(color_filter_down), "clicked",
                   G_CALLBACK(color_filter_down_cb), NULL);
  g_signal_connect(G_OBJECT(selection), "changed",
                   G_CALLBACK(remember_selected_row), color_filters);
  g_object_set_data(G_OBJECT(color_filters), COLOR_UP_LB, color_filter_up);
  g_object_set_data(G_OBJECT(color_filters), COLOR_DOWN_LB, color_filter_down);
  g_object_set_data(G_OBJECT(color_filters), COLOR_EDIT_LB, color_edit);
  g_object_set_data(G_OBJECT(color_filters), COLOR_DELETE_LB, color_delete);
  g_object_set_data(G_OBJECT(color_new), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(G_OBJECT(color_new), "clicked",
                   G_CALLBACK(color_new_cb), NULL);
  g_object_set_data(G_OBJECT(color_edit), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(G_OBJECT(color_edit), "clicked",
                   G_CALLBACK(color_edit_cb), NULL);
  g_object_set_data(G_OBJECT(color_delete), COLOR_EDIT_LB, color_edit);
  g_object_set_data(G_OBJECT(color_delete), COLOR_FILTERS_CL, color_filters);
  g_signal_connect(G_OBJECT(color_delete), "clicked",
                   G_CALLBACK(color_delete_cb), NULL);
  g_signal_connect (G_OBJECT(color_save), "clicked",
                      G_CALLBACK (color_save_cb), NULL);
  g_signal_connect(G_OBJECT(color_ok), "clicked",
                   G_CALLBACK(color_ok_cb), NULL);
  g_signal_connect(G_OBJECT(color_apply), "clicked",
                   G_CALLBACK(color_apply_cb), NULL);
  g_signal_connect(G_OBJECT(color_cancel), "clicked",
                   G_CALLBACK(color_cancel_cb), NULL);
#endif

  gtk_widget_grab_focus(color_filters);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data(GTK_OBJECT (color_win), "tooltips", tooltips);
#else
  g_object_set_data(G_OBJECT (color_win), "tooltips", tooltips);
#endif
  gtk_widget_show (color_win);

  dlg_set_cancel(color_win, color_cancel);

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
  sprintf(fg_str, "#%04X%04X%04X",
          colorf->fg_color.red, colorf->fg_color.green, colorf->fg_color.blue);
  sprintf(bg_str, "#%04X%04X%04X",
          colorf->bg_color.red, colorf->bg_color.green, colorf->bg_color.blue);
  gtk_list_store_set(store, &iter, 0, colorf->filter_name,
                     1, colorf->filter_text, 2, fg_str, 3, bg_str,
                     4, colorf, -1);
#endif
  num_of_filters++;
}

/* Move the selected filter up in the list */
static void
color_filter_up_cb(GtkButton *button, gpointer user_data _U_)
{
  gint            filter_number;
  GtkWidget      *color_filters;
  color_filter_t *colorf;
#if GTK_MAJOR_VERSION >= 2
  GtkTreeModel   *model;
  GtkTreeIter     iter1, iter2;
  gchar          *name, *string, *fg_str, *bg_str;
#endif

  filter_number = row_selected;
  g_assert(filter_number > 0);

#if GTK_MAJOR_VERSION < 2
  color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
  colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), filter_number);
  gtk_clist_swap_rows(GTK_CLIST(color_filters), filter_number, filter_number-1);

  /*
   * That row is still selected, but it's now row N-1.
   */
  remember_selected_row(GTK_CLIST(color_filters), filter_number-1, 0, NULL,
      NULL);
#else
  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button),
                                                 COLOR_FILTERS_CL);
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  gtk_tree_model_iter_nth_child(model, &iter1, NULL, row_selected);
  gtk_tree_model_iter_nth_child(model, &iter2, NULL, row_selected-1);
  gtk_tree_model_get(model, &iter1, 0, &name, 1, &string,
                     2, &fg_str, 3, &bg_str, 4, &colorf, -1);
  gtk_list_store_remove(GTK_LIST_STORE(model), &iter1);
  gtk_list_store_insert_before(GTK_LIST_STORE(model), &iter1, &iter2);
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

  filter_list = g_slist_remove(filter_list, colorf);
  filter_list = g_slist_insert(filter_list, colorf, filter_number-1);
}

/* Move the selected filter down in the list */
static void
color_filter_down_cb(GtkButton *button, gpointer user_data _U_)
{
  gint            filter_number;
  GtkWidget      *color_filters;
  color_filter_t *colorf;
#if GTK_MAJOR_VERSION >= 2
  GtkTreeModel   *model;
  GtkTreeIter     iter1, iter2;
  gchar          *name, *string, *fg_str, *bg_str;
#endif

  filter_number = row_selected;
  g_assert(filter_number < num_of_filters - 1);

#if GTK_MAJOR_VERSION < 2
  color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
  colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), filter_number);
  gtk_clist_swap_rows(GTK_CLIST(color_filters), filter_number+1, filter_number);

  /*
   * That row is still selected, but it's now row N+1.
   */
  remember_selected_row(GTK_CLIST(color_filters), filter_number+1, 0, NULL,
      NULL);
#else
  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button),
                                                 COLOR_FILTERS_CL);
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  gtk_tree_model_iter_nth_child(model, &iter1, NULL, row_selected);
  gtk_tree_model_iter_nth_child(model, &iter2, NULL, row_selected+1);
  gtk_tree_model_get(model, &iter1, 0, &name, 1, &string,
                     2, &fg_str, 3, &bg_str, 4, &colorf, -1);
  gtk_list_store_remove(GTK_LIST_STORE(model), &iter1);
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

  filter_list = g_slist_remove(filter_list, colorf);
  filter_list = g_slist_insert(filter_list, colorf, filter_number+1);
}

/* A row was selected; remember its row number */
#if GTK_MAJOR_VERSION < 2
static void
remember_selected_row(GtkCList *clist, gint row, gint column _U_,
                      GdkEvent *event _U_, gpointer user_data _U_)
{
    GtkWidget    *button;

    row_selected = row;

    /*
     * A row is selected, so we can move it up *if* it's not at the top
     * and move it down *if* it's not at the bottom.
     */
    button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(clist),
                                               COLOR_UP_LB);
    gtk_widget_set_sensitive (button, row > 0);
    button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(clist),
                                               COLOR_DOWN_LB);
    gtk_widget_set_sensitive (button, row < num_of_filters - 1);

    /*
     * A row is selected, so we can operate on it.
     */
    button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(clist),
                                               COLOR_EDIT_LB);
    gtk_widget_set_sensitive (button, TRUE);
    button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(clist),
                                               COLOR_DELETE_LB);
    gtk_widget_set_sensitive (button, TRUE);
}
#else
static void
remember_selected_row(GtkTreeSelection *sel, gpointer color_filters)
{
    GtkWidget    *button;
    GtkTreeModel *model;
    GtkTreeIter   iter;
    GtkTreePath  *path;
    gchar        *path_str;

    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        path = gtk_tree_model_get_path(model, &iter);
        path_str = gtk_tree_path_to_string(path);
        row_selected = atoi(path_str);
        g_free(path_str);
        gtk_tree_path_free(path);

        /*
         * A row is selected, so we can move it up *if* it's not at the top
         * and move it down *if* it's not at the bottom.
         */
        button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters),
                                                COLOR_UP_LB);
        gtk_widget_set_sensitive(button, row_selected > 0);
        button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters),
                                                COLOR_DOWN_LB);
        gtk_widget_set_sensitive(button, row_selected < num_of_filters - 1);

        /*
         * A row is selected, so we can operate on it.
         */
        button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters),
                                                COLOR_EDIT_LB);
        gtk_widget_set_sensitive (button, TRUE);
        button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters),
                                                COLOR_DELETE_LB);
        gtk_widget_set_sensitive (button, TRUE);
    }
    /* A row was unselected; un-remember its row number */
    else
    {
        row_selected = -1;

        /*
         * No row is selected, so we can't do operations that affect the
         * selected row.
         */
        button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters),
                                                COLOR_UP_LB);
        gtk_widget_set_sensitive (button, FALSE);
        button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters),
                                                COLOR_DOWN_LB);
        gtk_widget_set_sensitive (button, FALSE);
        button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters),
                                                COLOR_EDIT_LB);
        gtk_widget_set_sensitive (button, FALSE);
        button = (GtkWidget *)g_object_get_data(G_OBJECT(color_filters),
                                                COLOR_DELETE_LB);
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

  row_selected = -1;

  /*
   * No row is selected, so we can't do operations that affect the
   * selected row.
   */
  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(clist),
					    COLOR_UP_LB);
  gtk_widget_set_sensitive (button, FALSE);
  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(clist),
					    COLOR_DOWN_LB);
  gtk_widget_set_sensitive (button, FALSE);
  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(clist),
					    COLOR_EDIT_LB);
  gtk_widget_set_sensitive (button, FALSE);
  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(clist),
					    COLOR_DELETE_LB);
  gtk_widget_set_sensitive (button, FALSE);
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
  g_slist_foreach(filter_list, destroy_edit_dialog_cb, NULL);

  colorize_win = NULL;
}

static void
destroy_edit_dialog_cb(gpointer filter_arg, gpointer dummy _U_)
{
  color_filter_t *colorf = (color_filter_t *)filter_arg;

  if (colorf->edit_dialog != NULL)
    gtk_widget_destroy(colorf->edit_dialog);
}

/* XXX - we don't forbid having more than one "Edit color filter" dialog
   open, so these shouldn't be static. */
static GtkWidget *filt_name_entry;
static GtkWidget *filt_text_entry;

/* Create a new filter in the list, and pop up an "Edit color filter"
   dialog box to edit it. */
static void
color_new_cb(GtkButton *button, gpointer user_data _U_)
{
  color_filter_t   *colorf;
  GtkWidget        *color_filters;
#if GTK_MAJOR_VERSION < 2
  gchar            *data[2];
  gint              row;
#else
  GtkTreeModel     *model;
  gint              num_filters;
  GtkTreeIter       iter;
  GtkTreeSelection *sel;
#endif

  colorf = new_color_filter("name", "filter"); /* Adds at end! */

#if GTK_MAJOR_VERSION < 2
  color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
  data[0] = colorf->filter_name;
  data[1] = colorf->filter_text;
  row = gtk_clist_append(GTK_CLIST(color_filters), data);
  gtk_clist_set_row_data(GTK_CLIST(color_filters), row, colorf);
  num_of_filters++;

  /* select the new row */
  gtk_clist_select_row(GTK_CLIST(color_filters), row, -1);
  edit_color_filter_dialog_new(color_filters, &filt_name_entry,
                               &filt_text_entry);
#else
  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button),
                                                 COLOR_FILTERS_CL);
  add_filter_to_list(colorf, color_filters);

  /* select the new row */
  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
  num_filters = gtk_tree_model_iter_n_children(model, NULL);
  gtk_tree_model_iter_nth_child(model, &iter, NULL, num_filters - 1);
  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
  gtk_tree_selection_select_iter(sel, &iter);
  edit_color_filter_dialog_new(color_filters, &filt_name_entry,
                               &filt_text_entry);
  gtk_widget_grab_focus(color_filters);
#endif
}

/* Pop up an "Edit color filter" dialog box to edit an existing filter. */
static void
color_edit_cb(GtkButton *button, gpointer user_data _U_)
{
  GtkWidget *color_filters;

#if GTK_MAJOR_VERSION < 2
  color_filters = (GtkWidget *)gtk_object_get_data(GTK_OBJECT(button),
                                                   COLOR_FILTERS_CL);
#else
  color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button),
                                                 COLOR_FILTERS_CL);
#endif
  g_assert(row_selected != -1);
  edit_color_filter_dialog_new(color_filters, &filt_name_entry,
                               &filt_text_entry);
}

/* Delete a color from the list. */
static void
color_delete_cb(GtkWidget *widget, gpointer user_data _U_)
{
    GtkWidget        *color_filters;
    color_filter_t   *colorf;
#if GTK_MAJOR_VERSION >= 2
    GtkTreeModel     *model;
    GtkTreeIter       iter;
    gint              row;
    GtkTreeSelection *sel;

    if(row_selected != -1) {
        /* The "selection changed" callback is called when the row is
         * removed, so we must remember the selected row. */
        row = row_selected;
        color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(widget),
                                                       COLOR_FILTERS_CL);
        model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
        gtk_tree_model_iter_nth_child(model, &iter, NULL, row);
        gtk_tree_model_get(model, &iter, 4, &colorf, -1);

        /* Remove this color filter from the CList displaying the
           color filters. */
        gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
        num_of_filters--;

        /* Destroy any "Edit color filter" dialog boxes editing it. */
        if (colorf->edit_dialog != NULL)
            gtk_widget_destroy(colorf->edit_dialog);

        /* Remove the color filter from the list of color filters. */
        delete_color_filter(colorf);

        /* If we grab the focus after updating the selection, the first
         * row is always selected, so we do it before */
        gtk_widget_grab_focus(color_filters);
        /* Update the selection */
        if (row <= (num_of_filters-1)) {
            sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
            gtk_tree_model_iter_nth_child(model, &iter, NULL, row);
            gtk_tree_selection_select_iter(sel, &iter);
        }
        else if (num_of_filters > 0) {
            sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
            gtk_tree_model_iter_nth_child(model, &iter, NULL, num_of_filters-1);
            gtk_tree_selection_select_iter(sel, &iter);
        }
    }
#else
    if(row_selected != -1){
        color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(widget),
                                                          COLOR_FILTERS_CL);
        colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters), row_selected);

        /* Remove this color filter from the CList displaying the
           color filters. */
        gtk_clist_remove(GTK_CLIST(color_filters), row_selected);
        num_of_filters--;

        /* Destroy any "Edit color filter" dialog boxes editing it. */
        if (colorf->edit_dialog != NULL)
            gtk_widget_destroy(colorf->edit_dialog);

        /* Remove the color filter from the list of color filters. */
        delete_color_filter(colorf);

        /* Select the previous row, if there is one. */
        if (row_selected > 0) {
            row_selected--;
            gtk_clist_select_row(GTK_CLIST(color_filters), row_selected, 0);
        }
    }
#endif
}

/* Save color filters to the color filter file. */
static void
color_save_cb(GtkButton *button _U_, gpointer user_data _U_)
{
  if (!write_filters())
	simple_dialog(ESD_TYPE_CRIT, NULL, "Could not open filter file: %s",
	    strerror(errno));

}

/* Exit dialog and apply new list of color filters to the capture. */
static void
color_ok_cb(GtkButton *button _U_, gpointer user_data _U_)
{
  /* colorize list */
  colorize_packets(&cfile);

  /* Destroy the dialog box. */
  gtk_widget_destroy(colorize_win);
}

/* Exit dialog without colorizing packets with the new list.
   XXX - should really undo any changes to the list.... */
static void
color_cancel_cb(GtkWidget *widget _U_, gpointer user_data _U_)
{
  /* Destroy the dialog box. */
  gtk_widget_destroy(colorize_win);
}

/* Apply new list of color filters to the capture. */
static void
color_apply_cb(GtkButton *button _U_, gpointer user_data _U_)
{
  colorize_packets(&cfile);
}

/* Create an "Edit Color Filter" dialog for a given color filter, and
   associate it with that color filter. */
static void
edit_color_filter_dialog_new(GtkWidget *color_filters,
                             GtkWidget **colorize_filter_name,
                             GtkWidget **colorize_filter_text)
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

    GtkWidget *button_hbox;
    GtkWidget *edit_color_filter_ok;
    GtkWidget *edit_color_filter_cancel;

#if GTK_MAJOR_VERSION >= 2
    GtkTreeSelection *sel;
    GtkTreeModel     *model;
    GtkTreeIter       iter;

    sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(color_filters));
    /* should never happen */
    if (!gtk_tree_selection_get_selected(sel, &model, &iter))
        return;
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
    /*  gtk_window_set_position(GTK_WINDOW(edit_dialog), GTK_WIN_POS_MOUSE); */
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data(GTK_OBJECT (edit_dialog), "edit_dialog", edit_dialog);
#else
    g_object_set_data(G_OBJECT (edit_dialog), "edit_dialog", edit_dialog);
#endif
    colorf->edit_dialog = edit_dialog;

    dialog_vbox = gtk_vbox_new (FALSE, 0);
    gtk_widget_ref (dialog_vbox);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "dialog_vbox",
                             dialog_vbox, (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "dialog_vbox",
                           dialog_vbox, (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_container_set_border_width  (GTK_CONTAINER (dialog_vbox), 5);
    gtk_widget_show (dialog_vbox);
    gtk_container_add (GTK_CONTAINER (edit_dialog), dialog_vbox);

    /* Filter frame */
    filter_fr = gtk_frame_new("Filter");
    gtk_box_pack_start (GTK_BOX (dialog_vbox), filter_fr, FALSE, FALSE, 0);
    gtk_widget_show(filter_fr);

    filter_fr_vbox = gtk_vbox_new (FALSE, 0);
    gtk_widget_ref (filter_fr_vbox);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "filter_fr_vbox",
                             filter_fr_vbox,
                             (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "filter_fr_vbox",
                           filter_fr_vbox, (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_container_set_border_width  (GTK_CONTAINER (filter_fr_vbox), 5);
    gtk_widget_show (filter_fr_vbox);
    gtk_container_add(GTK_CONTAINER(filter_fr), filter_fr_vbox);

    /* filter name hbox */
    filter_name_hbox = gtk_hbox_new (FALSE, 0);
    gtk_widget_ref (filter_name_hbox);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "filter_name_hbox",
                             filter_name_hbox,
                             (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "filter_name_hbox",
                           filter_name_hbox,
                           (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_widget_show (filter_name_hbox);
    gtk_box_pack_start (GTK_BOX (filter_fr_vbox), filter_name_hbox, TRUE, FALSE, 3);

    color_filter_name = gtk_label_new (("Name: "));
    gtk_widget_ref (color_filter_name);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "color_filter_name",
                             color_filter_name,
                             (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "color_filter_name",
                           color_filter_name,
                           (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_widget_show (color_filter_name);
    gtk_box_pack_start (GTK_BOX (filter_name_hbox), color_filter_name, FALSE, FALSE, 0);

    *colorize_filter_name = gtk_entry_new ();
    gtk_widget_ref (*colorize_filter_name);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "*colorize_filter_name",
                             *colorize_filter_name,
                             (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "*colorize_filter_name",
                           *colorize_filter_name,
                           (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_entry_set_text(GTK_ENTRY(*colorize_filter_name), colorf->filter_name);

    style = gtk_style_copy(gtk_widget_get_style(*colorize_filter_name));
    color_t_to_gdkcolor(&style->base[GTK_STATE_NORMAL], &colorf->bg_color);
#if GTK_MAJOR_VERSION < 2
    color_t_to_gdkcolor(&style->fg[GTK_STATE_NORMAL], &colorf->fg_color);
#else
    color_t_to_gdkcolor(&style->text[GTK_STATE_NORMAL], &colorf->fg_color);
#endif
    gtk_widget_set_style(*colorize_filter_name, style);

    gtk_widget_show (*colorize_filter_name);
    gtk_box_pack_start (GTK_BOX (filter_name_hbox), *colorize_filter_name, TRUE, TRUE, 0);
    gtk_tooltips_set_tip (tooltips, *colorize_filter_name, ("This is the editable name of the filter. (No @ characters allowed.)"), NULL);


    /* filter string hbox */
    filter_string_hbox = gtk_hbox_new (FALSE, 0);
    gtk_widget_ref (filter_string_hbox);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "filter_string_hbox",
                             filter_string_hbox,
                             (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "filter_string_hbox",
                           filter_string_hbox,
                           (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_widget_show (filter_string_hbox);
    gtk_box_pack_start (GTK_BOX (filter_fr_vbox), filter_string_hbox, TRUE, FALSE, 3);

    color_filter_text = gtk_label_new (("String: "));
    gtk_widget_ref (color_filter_text);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "color_filter_text",
                             color_filter_text,
                             (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "color_filter_text",
                           color_filter_text,
                           (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_widget_show (color_filter_text);
    gtk_box_pack_start (GTK_BOX (filter_string_hbox), color_filter_text, FALSE, FALSE, 0);

    *colorize_filter_text = gtk_entry_new ();
    gtk_widget_ref (*colorize_filter_text);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "*colorize_filter_text",
                             *colorize_filter_text,
                             (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "*colorize_filter_text",
                           *colorize_filter_text,
                           (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_entry_set_text(GTK_ENTRY(*colorize_filter_text), colorf->filter_text);


#if 0
    style = gtk_style_copy(gtk_widget_get_style(*colorize_filter_text));
    style->base[GTK_STATE_NORMAL] = colorf->bg_color;
    style->fg[GTK_STATE_NORMAL]   = colorf->fg_color;
#endif
    gtk_widget_set_style(*colorize_filter_text, style);
    gtk_widget_show (*colorize_filter_text);
    gtk_box_pack_start (GTK_BOX (filter_string_hbox), *colorize_filter_text, TRUE, TRUE, 0);
    gtk_tooltips_set_tip (tooltips, *colorize_filter_text, ("This is the editable text of the filter"), NULL);

    /* Create the "Add Expression..." button, to pop up a dialog
       for constructing filter comparison expressions. */
    add_expression_bt = gtk_button_new_with_label("Add Expression...");
#if GTK_MAJOR_VERSION < 2
    gtk_signal_connect(GTK_OBJECT(add_expression_bt), "clicked",
                       GTK_SIGNAL_FUNC(filter_expr_cb), *colorize_filter_text);
#else
    g_signal_connect(G_OBJECT(add_expression_bt), "clicked",
                     G_CALLBACK(filter_expr_cb), *colorize_filter_text);
#endif
    gtk_box_pack_start (GTK_BOX(filter_string_hbox), add_expression_bt, FALSE, FALSE, 3);
    gtk_widget_show(add_expression_bt);
    gtk_tooltips_set_tip (tooltips, add_expression_bt, ("Add an expression to the filter string"), NULL);


    /* choose color frame */
    colorize_fr = gtk_frame_new("Display Colors");
    gtk_box_pack_start (GTK_BOX (dialog_vbox), colorize_fr, FALSE, FALSE, 0);
    gtk_widget_show(colorize_fr);

    colorize_hbox = gtk_hbox_new (FALSE, 0);
    gtk_widget_ref (colorize_hbox);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "colorize_hbox",
                             colorize_hbox,
                             (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "colorize_hbox",
                           colorize_hbox, (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_container_set_border_width  (GTK_CONTAINER (colorize_hbox), 5);
    gtk_widget_show (colorize_hbox);
    gtk_container_add(GTK_CONTAINER(colorize_fr), colorize_hbox);

    colorize_filter_fg = gtk_button_new_with_label (("Foreground Color..."));
    gtk_widget_ref (colorize_filter_fg);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "colorize_filter_fg",
                             colorize_filter_fg,
                             (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "colorize_filter_fg",
                           colorize_filter_fg,
                           (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_widget_show (colorize_filter_fg);
    gtk_box_pack_start (GTK_BOX (colorize_hbox), colorize_filter_fg, TRUE, FALSE, 0);
    gtk_tooltips_set_tip (tooltips, colorize_filter_fg, ("Select foreground color for data display"), NULL);

    colorize_filter_bg = gtk_button_new_with_label (("Background Color..."));
    gtk_widget_ref (colorize_filter_bg);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "colorize_filter_bg",
                             colorize_filter_bg,
                             (GtkDestroyNotify) gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "colorize_filter_bg",
                           colorize_filter_bg,
                           (GtkDestroyNotify) gtk_widget_unref);
#endif
    gtk_widget_show (colorize_filter_bg);
    gtk_box_pack_start (GTK_BOX (colorize_hbox), colorize_filter_bg, TRUE, FALSE, 0);
    gtk_tooltips_set_tip (tooltips, colorize_filter_bg, ("Select background color for data display"), NULL);


    /* button hbox (placement defaults coming from main.c) */
    button_hbox = gtk_hbutton_box_new();
    gtk_widget_ref (button_hbox);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "button_hbox",
                             button_hbox, (GtkDestroyNotify) gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "button_hbox",
                           button_hbox, (GtkDestroyNotify) gtk_widget_unref);
#endif
    gtk_container_set_border_width  (GTK_CONTAINER (button_hbox), 0);
    gtk_widget_show (button_hbox);
    gtk_box_pack_start (GTK_BOX (dialog_vbox), button_hbox, FALSE, FALSE, 5);

    edit_color_filter_ok = gtk_button_new_with_label (("OK"));
    gtk_widget_ref (edit_color_filter_ok);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog), "edit_color_filter_ok",
                             edit_color_filter_ok,
                             (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "edit_color_filter_ok",
                           edit_color_filter_ok,
                           (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_widget_show (edit_color_filter_ok);
    gtk_box_pack_start (GTK_BOX (button_hbox), edit_color_filter_ok, TRUE, FALSE, 0);
    gtk_tooltips_set_tip (tooltips, edit_color_filter_ok, ("Accept filter color change"), NULL);

    edit_color_filter_cancel = gtk_button_new_with_label (("Cancel"));
    gtk_widget_ref (edit_color_filter_cancel);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data_full(GTK_OBJECT(edit_dialog),
                             "edit_color_filter_cancel",
                             edit_color_filter_cancel,
                             (GtkDestroyNotify)gtk_widget_unref);
#else
    g_object_set_data_full(G_OBJECT(edit_dialog), "edit_color_filter_cancel",
                           edit_color_filter_cancel,
                           (GtkDestroyNotify)gtk_widget_unref);
#endif
    gtk_widget_show (edit_color_filter_cancel);
    gtk_box_pack_start (GTK_BOX (button_hbox), edit_color_filter_cancel, TRUE, FALSE, 0);
    gtk_tooltips_set_tip (tooltips, edit_color_filter_cancel, ("Reject filter color change"), NULL);


    /* signals and such */
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data(GTK_OBJECT(edit_dialog), COLOR_FILTER, colorf);
    gtk_signal_connect(GTK_OBJECT(edit_dialog), "destroy",
                       GTK_SIGNAL_FUNC(edit_color_filter_destroy_cb), NULL);
    gtk_object_set_data(GTK_OBJECT(colorize_filter_fg), COLOR_FILTER, colorf);
    gtk_signal_connect(GTK_OBJECT(colorize_filter_fg), "clicked",
                       GTK_SIGNAL_FUNC(edit_color_filter_fg_cb), NULL);
    gtk_object_set_data(GTK_OBJECT(colorize_filter_bg), COLOR_FILTER, colorf);
    gtk_signal_connect(GTK_OBJECT(colorize_filter_bg), "clicked",
                       GTK_SIGNAL_FUNC(edit_color_filter_bg_cb), NULL);
    gtk_object_set_data(GTK_OBJECT(edit_color_filter_ok), COLOR_FILTERS_CL,
                        color_filters);
    gtk_object_set_data(GTK_OBJECT(edit_color_filter_ok), COLOR_FILTER,
                        colorf);
    gtk_signal_connect(GTK_OBJECT(edit_color_filter_ok), "clicked",
                       GTK_SIGNAL_FUNC(edit_color_filter_ok_cb), edit_dialog);
    gtk_signal_connect(GTK_OBJECT(edit_color_filter_cancel), "clicked",
                       GTK_SIGNAL_FUNC(edit_color_filter_cancel_cb),
                       edit_dialog);

    gtk_object_set_data (GTK_OBJECT (edit_dialog), "tooltips", tooltips);
#else
    g_object_set_data(G_OBJECT(edit_dialog), COLOR_FILTER, colorf);
    g_signal_connect(G_OBJECT(edit_dialog), "destroy",
                     G_CALLBACK(edit_color_filter_destroy_cb), NULL);
    g_object_set_data(G_OBJECT(colorize_filter_fg), COLOR_FILTER, colorf);
    g_signal_connect(G_OBJECT(colorize_filter_fg), "clicked",
                     G_CALLBACK(edit_color_filter_fg_cb), NULL);
    g_object_set_data(G_OBJECT(colorize_filter_bg), COLOR_FILTER, colorf);
    g_signal_connect(G_OBJECT(colorize_filter_bg), "clicked",
                     G_CALLBACK(edit_color_filter_bg_cb), NULL);
    g_object_set_data(G_OBJECT(edit_color_filter_ok), COLOR_FILTERS_CL,
                      color_filters);
    g_object_set_data(G_OBJECT(edit_color_filter_ok), COLOR_FILTER, colorf);
    g_signal_connect(G_OBJECT(edit_color_filter_ok), "clicked",
                     G_CALLBACK(edit_color_filter_ok_cb), edit_dialog);
    g_signal_connect(G_OBJECT(edit_color_filter_cancel), "clicked",
                     G_CALLBACK(edit_color_filter_cancel_cb), edit_dialog);

    g_object_set_data(G_OBJECT(edit_dialog), "tooltips", tooltips);
#endif

    dlg_set_cancel(edit_dialog, edit_color_filter_cancel);

    gtk_widget_show (edit_dialog);
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

#if GTK_MAJOR_VERSION < 2
  colorf = (color_filter_t *)gtk_object_get_data(GTK_OBJECT(object),
                                                 COLOR_FILTER);
#else
  colorf = (color_filter_t *)g_object_get_data(G_OBJECT(object), COLOR_FILTER);
#endif

  colorf->edit_dialog = NULL;

  /* Destroy any color selection dialogs this dialog had open. */
#if GTK_MAJOR_VERSION < 2
  color_sel = (GtkWidget *)gtk_object_get_data(object, COLOR_SELECTION_FG);
#else
  color_sel = (GtkWidget *)g_object_get_data(object, COLOR_SELECTION_FG);
#endif
  if (color_sel != NULL)
    gtk_widget_destroy(color_sel);
#if GTK_MAJOR_VERSION < 2
  color_sel = (GtkWidget *)gtk_object_get_data(object, COLOR_SELECTION_BG);
#else
  color_sel = (GtkWidget *)g_object_get_data(object, COLOR_SELECTION_BG);
#endif
  if (color_sel != NULL)
    gtk_widget_destroy(color_sel);
}

/* Pop up a color selection box to choose the foreground color. */
static void
edit_color_filter_fg_cb(GtkButton *button, gpointer user_data _U_)
{
  color_filter_t *colorf;
  GtkWidget *color_selection_fg;

#if GTK_MAJOR_VERSION < 2
  colorf = (color_filter_t *)gtk_object_get_data(GTK_OBJECT(button),
                                                 COLOR_FILTER);
  /* Do we already have one open for this dialog? */
  color_selection_fg = gtk_object_get_data(GTK_OBJECT(colorf->edit_dialog),
                                           COLOR_SELECTION_FG);
#else
  colorf = (color_filter_t *)g_object_get_data(G_OBJECT(button), COLOR_FILTER);
  /* Do we already have one open for this dialog? */
  color_selection_fg = g_object_get_data(G_OBJECT (colorf->edit_dialog),
                                         COLOR_SELECTION_FG);
#endif
  if (color_selection_fg != NULL) {
    /* Yes.  Just reactivate it. */
    reactivate_window(color_selection_fg);
  } else {
    /* No.  Create a new color selection box, and associate it with
       this dialog. */
    color_selection_fg = color_sel_win_new(colorf, FALSE);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data(GTK_OBJECT(colorf->edit_dialog), COLOR_SELECTION_FG,
                        color_selection_fg);
    gtk_object_set_data(GTK_OBJECT(color_selection_fg),
                        COLOR_SELECTION_PARENT, colorf->edit_dialog);
#else
    g_object_set_data(G_OBJECT(colorf->edit_dialog), COLOR_SELECTION_FG,
                      color_selection_fg);
    g_object_set_data(G_OBJECT(color_selection_fg),
                      COLOR_SELECTION_PARENT, colorf->edit_dialog);
#endif
  }
}

/* Pop up a color selection box to choose the background color. */
static void
edit_color_filter_bg_cb                (GtkButton       *button,
                                        gpointer         user_data _U_)
{
  color_filter_t *colorf;
  GtkWidget *color_selection_bg;

#if GTK_MAJOR_VERSION < 2
  colorf = (color_filter_t *)gtk_object_get_data(GTK_OBJECT(button),
                                                 COLOR_FILTER);
  /* Do we already have one open for this dialog? */
  color_selection_bg = gtk_object_get_data(GTK_OBJECT(colorf->edit_dialog),
                                           COLOR_SELECTION_BG);
#else
  colorf = (color_filter_t *)g_object_get_data(G_OBJECT(button), COLOR_FILTER);
  /* Do we already have one open for this dialog? */
  color_selection_bg = g_object_get_data(G_OBJECT(colorf->edit_dialog),
                                         COLOR_SELECTION_BG);
#endif
  if (color_selection_bg != NULL) {
    /* Yes.  Just reactivate it. */
    reactivate_window(color_selection_bg);
  } else {
    /* No.  Create a new color selection box, and associate it with
       this dialog. */
    color_selection_bg = color_sel_win_new(colorf, TRUE);
#if GTK_MAJOR_VERSION < 2
    gtk_object_set_data(GTK_OBJECT(colorf->edit_dialog), COLOR_SELECTION_BG,
                        color_selection_bg);
    gtk_object_set_data(GTK_OBJECT(color_selection_bg),
                        COLOR_SELECTION_PARENT, colorf->edit_dialog);
#else
    g_object_set_data(G_OBJECT(colorf->edit_dialog), COLOR_SELECTION_BG,
                      color_selection_bg);
    g_object_set_data(G_OBJECT(color_selection_bg),
                      COLOR_SELECTION_PARENT, colorf->edit_dialog);
#endif
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
        simple_dialog(ESD_TYPE_CRIT, NULL, "Filter names and strings must not"
                      " use the '@' character. Filter unchanged.");
        g_free(filter_name);
        g_free(filter_text);
        return;
    }

    if(!dfilter_compile(filter_text, &compiled_filter)) {
        simple_dialog(ESD_TYPE_CRIT, NULL, "Filter \"%s\" did not compile correctly.\n"
                      " Please try again. Filter unchanged.\n%s\n", filter_name,
                      dfilter_error_msg);
    } else {
#if GTK_MAJOR_VERSION < 2
        color_filters = (GtkWidget *)gtk_object_get_data(GTK_OBJECT(button),
                                                         COLOR_FILTERS_CL);
        colorf = (color_filter_t *)gtk_object_get_data(GTK_OBJECT(button),
                                                       COLOR_FILTER);
#else
        color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button),
                                                       COLOR_FILTERS_CL);
        colorf = (color_filter_t *)g_object_get_data(G_OBJECT(button),
                                                     COLOR_FILTER);
#endif

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
        sprintf(fg_str, "#%04X%04X%04X",
                new_fg_color.red, new_fg_color.green, new_fg_color.blue);
        sprintf(bg_str, "#%04X%04X%04X",
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
        gtk_widget_destroy(dialog);
    }
}

/* Exit dialog and do not process list */
static void
edit_color_filter_cancel_cb(GtkObject *object _U_, gpointer user_data)
{
  GtkWidget *dialog;

  dialog = (GtkWidget *)user_data;

  /* Destroy the dialog box. */
  gtk_widget_destroy(dialog);
}

static GtkWidget*
color_sel_win_new(color_filter_t *colorf, gboolean is_bg)
{
  gint title_len;
  gchar *title;
  static const gchar fg_title_format[] = "Ethereal: Choose foreground color for \"%s\"";
  static const gchar bg_title_format[] = "Ethereal: Choose background color for \"%s\"";
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
    title_len = strlen(bg_title_format) + strlen(colorf->filter_name);
    title = g_malloc(title_len + 1);
    sprintf(title, bg_title_format, colorf->filter_name);
  } else {
    color = &colorf->fg_color;
    title_len = strlen(fg_title_format) + strlen(colorf->filter_name);
    title = g_malloc(title_len + 1);
    sprintf(title, fg_title_format, colorf->filter_name);
  }
  color_sel_win = gtk_color_selection_dialog_new(title);
  g_free(title);
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data(GTK_OBJECT(color_sel_win), "color_sel_win",
                      color_sel_win);
#else
  g_object_set_data(G_OBJECT(color_sel_win), "color_sel_win", color_sel_win);
#endif
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
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data(GTK_OBJECT(color_sel_win), "color_sel_ok", color_sel_ok);
#else
  g_object_set_data(G_OBJECT(color_sel_win), "color_sel_ok", color_sel_ok);
#endif
  gtk_widget_show (color_sel_ok);
  GTK_WIDGET_SET_FLAGS (color_sel_ok, GTK_CAN_DEFAULT);

  color_sel_cancel = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->cancel_button;
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data(GTK_OBJECT(color_sel_win), "color_sel_cancel",
                      color_sel_cancel);
#else
  g_object_set_data(G_OBJECT(color_sel_win), "color_sel_cancel",
                    color_sel_cancel);
#endif
  gtk_widget_show (color_sel_cancel);
  GTK_WIDGET_SET_FLAGS (color_sel_cancel, GTK_CAN_DEFAULT);


  color_sel_help = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->help_button;
#if GTK_MAJOR_VERSION < 2
  gtk_object_set_data(GTK_OBJECT(color_sel_win), "color_sel_help",
                      color_sel_help);
#else
  g_object_set_data(G_OBJECT(color_sel_win), "color_sel_help", color_sel_help);
#endif
  gtk_widget_show (color_sel_help);


  GTK_WIDGET_SET_FLAGS (color_sel_help, GTK_CAN_DEFAULT);
#if GTK_MAJOR_VERSION < 2
  gtk_signal_connect(GTK_OBJECT (color_sel_win), "destroy",
                     GTK_SIGNAL_FUNC (color_sel_cancel_cb), color_sel_win);

  gtk_signal_connect(GTK_OBJECT (color_sel_ok), "clicked",
                     GTK_SIGNAL_FUNC (color_sel_ok_cb), color_sel_win);
  gtk_signal_connect(GTK_OBJECT (color_sel_cancel), "clicked",
                     GTK_SIGNAL_FUNC (color_sel_cancel_cb), color_sel_win);
#else
  g_signal_connect(G_OBJECT (color_sel_win), "destroy",
                   G_CALLBACK(color_sel_cancel_cb), color_sel_win);

  g_signal_connect(G_OBJECT(color_sel_ok), "clicked",
                   G_CALLBACK(color_sel_ok_cb), color_sel_win);
  g_signal_connect(G_OBJECT(color_sel_cancel), "clicked",
                   G_CALLBACK(color_sel_cancel_cb), color_sel_win);
#endif

  gtk_widget_show(color_sel_win);
  return color_sel_win;
}

static void
color_sel_win_destroy(GtkWidget *sel_win)
{
  GtkWidget *parent;
  GtkWidget *color_selection_fg, *color_selection_bg;

#if GTK_MAJOR_VERSION < 2
  /* Find the "Edit color filter" dialog box with which this is associated. */
  parent = (GtkWidget *)gtk_object_get_data(GTK_OBJECT (sel_win),
                                            COLOR_SELECTION_PARENT);

  /* Find that dialog box's foreground and background color selection
     boxes, if any. */
  color_selection_fg = gtk_object_get_data(GTK_OBJECT (parent),
                                           COLOR_SELECTION_FG);
  color_selection_bg = gtk_object_get_data(GTK_OBJECT (parent),
                                           COLOR_SELECTION_BG);

  if (sel_win == color_selection_fg) {
    /* This was its foreground color selection box; it isn't, anymore. */
    gtk_object_set_data(GTK_OBJECT(parent), COLOR_SELECTION_FG, NULL);
  }
  if (sel_win == color_selection_bg) {
    /* This was its background color selection box; it isn't, anymore. */
    gtk_object_set_data(GTK_OBJECT(parent), COLOR_SELECTION_BG, NULL);
  }
#else
  /* Find the "Edit color filter" dialog box with which this is associated. */
  parent = (GtkWidget *)g_object_get_data(G_OBJECT (sel_win),
                                          COLOR_SELECTION_PARENT);

  /* Find that dialog box's foreground and background color selection
     boxes, if any. */
  color_selection_fg = g_object_get_data(G_OBJECT (parent),
                                         COLOR_SELECTION_FG);
  color_selection_bg = g_object_get_data(G_OBJECT (parent),
                                         COLOR_SELECTION_BG);

  if (sel_win == color_selection_fg) {
    /* This was its foreground color selection box; it isn't, anymore. */
    g_object_set_data(G_OBJECT(parent), COLOR_SELECTION_FG, NULL);
  }
  if (sel_win == color_selection_bg) {
    /* This was its background color selection box; it isn't, anymore. */
    g_object_set_data(G_OBJECT(parent), COLOR_SELECTION_BG, NULL);
  }
#endif

  /* Now destroy it. */
  gtk_widget_destroy(sel_win);
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
	simple_dialog(ESD_TYPE_CRIT, NULL, "Could not allocate color.  Try again.");
  } else {
#if GTK_MAJOR_VERSION < 2
	/* Find the "Edit color filter" dialog box with which this is
	   associated. */
	parent = (GtkWidget *)gtk_object_get_data(GTK_OBJECT (color_dialog),
                                                  COLOR_SELECTION_PARENT);

	/* Find that dialog box's foreground and background color selection
	   boxes, if any. */
	color_selection_fg = gtk_object_get_data(GTK_OBJECT (parent),
                                                 COLOR_SELECTION_FG);
	color_selection_bg = gtk_object_get_data(GTK_OBJECT (parent),
                                                 COLOR_SELECTION_BG);
#else
	/* Find the "Edit color filter" dialog box with which this is
	   associated. */
	parent = (GtkWidget *)g_object_get_data(G_OBJECT (color_dialog),
                                                COLOR_SELECTION_PARENT);

	/* Find that dialog box's foreground and background color selection
	   boxes, if any. */
	color_selection_fg = g_object_get_data(G_OBJECT (parent),
                                               COLOR_SELECTION_FG);
        color_selection_bg = g_object_get_data(G_OBJECT (parent),
                                               COLOR_SELECTION_BG);
#endif
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
