/* color_edit_dlg.c
 * Definitions for single color filter edit dialog boxes
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet.h>

#include "../color.h"
#include "../color_filters.h"
#include "../simple_dialog.h"

#include "gtk/color_dlg.h"
#include "gtk/color_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_utils.h"
#include "gtk/stock_icons.h"
#include "gtk/filter_dlg.h"
#include "gtk/dfilter_expr_dlg.h"
#include "gtk/color_edit_dlg.h"
#include "gtk/filter_autocomplete.h"


#define BUTTON_SIZE_X -1
#define BUTTON_SIZE_Y -1


static void edit_color_filter_destroy_cb(GObject *object, gpointer user_data);
static void edit_color_filter_fg_cb(GtkButton *button, gpointer user_data);
static void edit_color_filter_bg_cb(GtkButton *button, gpointer user_data);
/*
  static void edit_disabled_cb_cb(GtkButton *button, gpointer user_data);
*/
static void edit_color_filter_ok_cb(GtkButton *button, gpointer user_data);
static void edit_new_color_filter_cancel_cb(GtkButton *button, gpointer user_data);

static GtkWidget* color_sel_win_new(color_filter_t *colorf, gboolean);
static void color_sel_ok_cb(GtkButton *button, gpointer user_data);
static void color_sel_cancel_cb(GObject *object, gpointer user_data);


#define COLOR_FILTERS_CL        "color_filters_cl"
#define COLOR_FILTER            "color_filter"
#define COLOR_FILTER_NAME_TE    "color_filter_name_te"
#define COLOR_FILTER_TEXT_TE    "color_filter_text_te"
#define COLOR_SELECTION_FG      "color_selection_fg"
#define COLOR_SELECTION_BG      "color_selection_bg"
#define COLOR_SELECTION_PARENT  "color_selection_parent"

/* XXX - we don't forbid having more than one "Edit color filter" dialog
   open, so these shouldn't be global. */
static GtkWidget *filt_name_entry;
static GtkWidget *filt_text_entry;
static GtkWidget *disabled_cb;


static void
filter_expr_cb(GtkWidget *w _U_, gpointer filter_te)
{

  dfilter_expr_dlg_new(GTK_WIDGET(filter_te));
}


/* Create an "Edit Color Filter" dialog for a given color filter, and
   associate it with that color filter. */
void
edit_color_filter_dialog(GtkWidget *color_filters,
                         gboolean is_new_filter)
{
  color_filter_t *colorf;
  GtkWidget      *edit_dialog;
  GtkWidget      *dialog_vbox;
  GdkColor       bg_color, fg_color;

  GtkWidget *filter_fr;
  GtkWidget *filter_fr_vbox;
  GtkWidget *filter_name_hbox;
  GtkWidget *color_filter_name;
  GtkWidget *filter_string_hbox;
  GtkWidget *add_expression_bt;
  GtkWidget *color_filter_text;

  GtkWidget *settings_hbox;

  GtkWidget *colorize_fr;
  GtkWidget *colorize_hbox;
  GtkWidget *colorize_filter_fg;
  GtkWidget *colorize_filter_bg;

  GtkWidget *status_fr;
  GtkWidget *status_vbox;

  GtkWidget *bbox;
  GtkWidget *edit_color_filter_ok;
  GtkWidget *edit_color_filter_cancel;

  GtkTreeModel     *model;
  GtkTreeIter       iter;

  model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));

  gtk_tree_model_iter_nth_child(model, &iter, NULL, color_dlg_row_selected);
  gtk_tree_model_get(model, &iter, 5, &colorf, -1);

  if (colorf->edit_dialog != NULL) {
    /* There's already an edit box open for this filter; reactivate it. */
    reactivate_window(colorf->edit_dialog);
    return;
  }

  /* dialog window */
  edit_dialog = dlg_conf_window_new ("Wireshark: Edit Color Filter");
  gtk_window_set_default_size(GTK_WINDOW(edit_dialog), 500, -1);
  g_object_set_data(G_OBJECT(edit_dialog), "edit_dialog", edit_dialog);
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

  filt_name_entry = gtk_entry_new ();
  gtk_entry_set_text(GTK_ENTRY(filt_name_entry), colorf->filter_name);

  color_t_to_gdkcolor(&bg_color, &colorf->bg_color);
  color_t_to_gdkcolor(&fg_color, &colorf->fg_color);

  gtk_widget_modify_base(filt_name_entry, GTK_STATE_NORMAL, &bg_color);
  gtk_widget_modify_text(filt_name_entry, GTK_STATE_NORMAL, &fg_color);

  gtk_box_pack_start (GTK_BOX (filter_name_hbox), filt_name_entry, TRUE, TRUE, 0);
  gtk_widget_set_tooltip_text(filt_name_entry, "This is the editable name of the filter. (No @ characters allowed.)");

  /* filter string hbox */
  filter_string_hbox = gtk_hbox_new (FALSE, 0);
  gtk_box_pack_start (GTK_BOX (filter_fr_vbox), filter_string_hbox, TRUE, FALSE, 3);

  color_filter_text = gtk_label_new (("String: "));
  gtk_box_pack_start (GTK_BOX (filter_string_hbox), color_filter_text, FALSE, FALSE, 0);

  filt_text_entry = gtk_entry_new ();
  g_signal_connect(filt_text_entry, "changed", G_CALLBACK(filter_te_syntax_check_cb), NULL);
  g_object_set_data(G_OBJECT(filter_string_hbox), E_FILT_AUTOCOMP_PTR_KEY, NULL);
  g_signal_connect(filt_text_entry, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
  g_signal_connect(edit_dialog, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);
  gtk_entry_set_text(GTK_ENTRY(filt_text_entry), colorf->filter_text);

  gtk_box_pack_start (GTK_BOX (filter_string_hbox), filt_text_entry, TRUE, TRUE, 0);
  gtk_widget_set_tooltip_text(filt_text_entry, "This is the editable text of the filter");

  /* Create the "Add Expression..." button, to pop up a dialog
     for constructing filter comparison expressions. */
  add_expression_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_ADD_EXPRESSION);
  g_signal_connect(add_expression_bt, "clicked", G_CALLBACK(filter_expr_cb), filt_text_entry);
  gtk_box_pack_start (GTK_BOX(filter_string_hbox), add_expression_bt, FALSE, FALSE, 3);
  gtk_widget_set_tooltip_text(add_expression_bt, "Add an expression to the filter string");

  /* Show the (in)validity of the default filter string */
  filter_te_syntax_check_cb(filt_text_entry, NULL);

  /* settings-hbox for "choose color frame" and "status frame" */
  settings_hbox = gtk_hbox_new (FALSE, 0);
  gtk_box_pack_start (GTK_BOX (dialog_vbox), settings_hbox, FALSE, FALSE, 0);

  /* choose color frame */
  colorize_fr = gtk_frame_new("Display Colors");
  gtk_box_pack_start (GTK_BOX (settings_hbox), colorize_fr, TRUE, TRUE, 0);

  colorize_hbox = gtk_hbox_new (FALSE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (colorize_hbox), 5);
  gtk_container_add(GTK_CONTAINER(colorize_fr), colorize_hbox);

  colorize_filter_fg = gtk_button_new_with_label (("Foreground Color..."));
  gtk_box_pack_start (GTK_BOX (colorize_hbox), colorize_filter_fg, TRUE, FALSE, 0);
  gtk_widget_set_tooltip_text(colorize_filter_fg, "Select foreground color for data display");

  colorize_filter_bg = gtk_button_new_with_label (("Background Color..."));
  gtk_box_pack_start (GTK_BOX (colorize_hbox), colorize_filter_bg, TRUE, FALSE, 0);
  gtk_widget_set_tooltip_text(colorize_filter_bg, "Select background color for data display");

  /* status frame */
  status_fr = gtk_frame_new("Status");
  gtk_box_pack_start (GTK_BOX (settings_hbox), status_fr, TRUE, TRUE, 0);

  status_vbox = gtk_vbox_new (FALSE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (status_vbox), 5);
  gtk_container_add(GTK_CONTAINER(status_fr), status_vbox);

  disabled_cb = gtk_check_button_new_with_label("Disabled");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(disabled_cb), colorf->disabled);
  gtk_box_pack_start (GTK_BOX (status_vbox), disabled_cb, TRUE, FALSE, 0);
  gtk_widget_set_tooltip_text(disabled_cb, "Color rule won't be checked if this box is selected");

  /* button box */
  bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CANCEL, NULL);
  gtk_box_pack_start(GTK_BOX(dialog_vbox), bbox, FALSE, FALSE, 0);
  gtk_container_set_border_width  (GTK_CONTAINER (bbox), 0);

  edit_color_filter_ok = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
  gtk_widget_set_tooltip_text(edit_color_filter_ok, "Accept filter color change");

  edit_color_filter_cancel = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
  gtk_widget_set_tooltip_text(edit_color_filter_cancel, "Reject filter color change");

  gtk_widget_grab_default(edit_color_filter_ok);

  /* signals and such */
  g_object_set_data(G_OBJECT(edit_dialog), COLOR_FILTER, colorf);
  g_signal_connect(edit_dialog, "destroy", G_CALLBACK(edit_color_filter_destroy_cb), NULL);
  g_object_set_data(G_OBJECT(colorize_filter_fg), COLOR_FILTER, colorf);
  g_signal_connect(colorize_filter_fg, "clicked", G_CALLBACK(edit_color_filter_fg_cb), NULL);
  g_object_set_data(G_OBJECT(colorize_filter_bg), COLOR_FILTER, colorf);
  g_signal_connect(colorize_filter_bg, "clicked", G_CALLBACK(edit_color_filter_bg_cb), NULL);
  g_object_set_data(G_OBJECT(disabled_cb), COLOR_FILTER, colorf);
/*    g_signal_connect(disabled_cb, "clicked", G_CALLBACK(edit_disabled_cb_cb), NULL);*/
  g_object_set_data(G_OBJECT(edit_color_filter_ok), COLOR_FILTERS_CL, color_filters);
  g_object_set_data(G_OBJECT(edit_color_filter_ok), COLOR_FILTER, colorf);
  g_signal_connect(edit_color_filter_ok, "clicked", G_CALLBACK(edit_color_filter_ok_cb), edit_dialog);

  /* set callback to delete new filters if cancel chosen */
  if (is_new_filter)
  {
    g_object_set_data(G_OBJECT(edit_color_filter_cancel), COLOR_FILTERS_CL, color_filters);
    g_signal_connect(edit_color_filter_cancel, "clicked",
                     G_CALLBACK(edit_new_color_filter_cancel_cb), edit_dialog);
  }
  /* escape will select cancel */
  window_set_cancel_button(edit_dialog, edit_color_filter_cancel, window_cancel_button_cb);

  g_signal_connect(edit_dialog, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);

  gtk_widget_show_all(edit_dialog);
  window_present(edit_dialog);
}

/* Called when the dialog box is being destroyed; destroy any color
   selection dialogs opened from this dialog, and null out the pointer
   to this dialog. */
static void
edit_color_filter_destroy_cb(GObject *object, gpointer user_data _U_)
{
  color_filter_t *colorf;
  GtkWidget *color_sel;

  colorf = (color_filter_t *)g_object_get_data(G_OBJECT(object), COLOR_FILTER);
  colorf->edit_dialog = NULL;

  /* Destroy any color selection dialogs this dialog had open. */
  color_sel = (GtkWidget *)g_object_get_data(G_OBJECT(object), COLOR_SELECTION_FG);
  if (color_sel != NULL)
    window_destroy(color_sel);
  color_sel = (GtkWidget *)g_object_get_data(G_OBJECT(object), COLOR_SELECTION_BG);
  if (color_sel != NULL)
    window_destroy(color_sel);
}

/* Pop up a color selection box to choose the foreground color. */
static void
edit_color_filter_fg_cb(GtkButton *button, gpointer user_data _U_)
{
  color_filter_t *colorf;
  GtkWidget *color_selection_fg;

  colorf = (color_filter_t *)g_object_get_data(G_OBJECT(button), COLOR_FILTER);
  /* Do we already have one open for this dialog? */
  color_selection_fg = g_object_get_data(G_OBJECT(colorf->edit_dialog), COLOR_SELECTION_FG);
  if (color_selection_fg != NULL) {
    /* Yes.  Just reactivate it. */
    reactivate_window(color_selection_fg);
  } else {
    /* No.  Create a new color selection box, and associate it with
       this dialog. */
    color_selection_fg = color_sel_win_new(colorf, FALSE);
    g_object_set_data(G_OBJECT(colorf->edit_dialog), COLOR_SELECTION_FG, color_selection_fg);
    g_object_set_data(G_OBJECT(color_selection_fg), COLOR_SELECTION_PARENT, colorf->edit_dialog);
  }
}

/* Pop up a color selection box to choose the background color. */
static void
edit_color_filter_bg_cb                (GtkButton       *button,
                                        gpointer         user_data _U_)
{
  color_filter_t *colorf;
  GtkWidget *color_selection_bg;

  colorf = (color_filter_t *)g_object_get_data(G_OBJECT(button), COLOR_FILTER);
  /* Do we already have one open for this dialog? */
  color_selection_bg = g_object_get_data(G_OBJECT(colorf->edit_dialog), COLOR_SELECTION_BG);
  if (color_selection_bg != NULL) {
    /* Yes.  Just reactivate it. */
    reactivate_window(color_selection_bg);
  } else {
    /* No.  Create a new color selection box, and associate it with
       this dialog. */
    color_selection_bg = color_sel_win_new(colorf, TRUE);
    g_object_set_data(G_OBJECT(colorf->edit_dialog), COLOR_SELECTION_BG, color_selection_bg);
    g_object_set_data(G_OBJECT(color_selection_bg), COLOR_SELECTION_PARENT, colorf->edit_dialog);
  }
}

/* Toggle the disabled flag */
#if 0
static void
edit_disabled_cb_cb                    (GtkButton       *button,
                                        gpointer         user_data _U_)
{
  color_filter_t *colorf;

  colorf = (color_filter_t *)g_object_get_data(G_OBJECT(button), COLOR_FILTER);
  colorf->disabled = GTK_TOGGLE_BUTTON (button)->active;

  printf("Colorfilter %s is now %s\n",colorf->filter_name,colorf->disabled?"disabled":"enabled");
}
#endif

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
  gboolean        filter_disabled;
  color_filter_t *colorf;
  dfilter_t      *compiled_filter;
  GtkWidget      *color_filters;
  GtkTreeModel   *model;
  GtkTreeIter     iter;
  gchar           fg_str[14], bg_str[14];

  dialog = (GtkWidget *)user_data;

  style = gtk_widget_get_style(filt_name_entry);
  new_bg_color = style->base[GTK_STATE_NORMAL];
  new_fg_color = style->text[GTK_STATE_NORMAL];

  filter_name = g_strdup(gtk_entry_get_text(GTK_ENTRY(filt_name_entry)));
  filter_text = g_strdup(gtk_entry_get_text(GTK_ENTRY(filt_text_entry)));
  filter_disabled = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(disabled_cb));

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
    color_filters = (GtkWidget *)g_object_get_data(G_OBJECT(button), COLOR_FILTERS_CL);
    colorf = (color_filter_t *)g_object_get_data(G_OBJECT(button), COLOR_FILTER);

    g_free(colorf->filter_name);
    colorf->filter_name = filter_name;

    g_free(colorf->filter_text);
    colorf->filter_text = filter_text;

    colorf->disabled = filter_disabled;
    gdkcolor_to_color_t(&colorf->fg_color, &new_fg_color);
    gdkcolor_to_color_t(&colorf->bg_color, &new_bg_color);
    g_snprintf(fg_str, sizeof(fg_str), "#%04X%04X%04X",
               new_fg_color.red, new_fg_color.green, new_fg_color.blue);
    g_snprintf(bg_str, sizeof(bg_str), "#%04X%04X%04X",
               new_bg_color.red, new_bg_color.green, new_bg_color.blue);
    model = gtk_tree_view_get_model(GTK_TREE_VIEW(color_filters));
    gtk_tree_model_iter_nth_child(model, &iter, NULL, color_dlg_row_selected);
    gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, filter_name,
                       1, filter_text, 2, fg_str, 3, bg_str,
                       4, filter_disabled, -1);
    if(colorf->c_colorfilter != NULL)
      dfilter_free(colorf->c_colorfilter);
    colorf->c_colorfilter = compiled_filter;

    /* Destroy the dialog box. */
    window_destroy(dialog);
  }
}

/* reject new color filter addition */
static void
edit_new_color_filter_cancel_cb(GtkButton *button, gpointer user_data _U_)
{
  /* Delete the entry. As a side effect this destroys the edit_dialog window. */
  color_delete_single(color_dlg_num_of_filters-1, (GtkWidget*)g_object_get_data(G_OBJECT(button), COLOR_FILTERS_CL));
}

static GtkWidget*
color_sel_win_new(color_filter_t *colorf, gboolean is_bg)
{
  gchar *title;
  GtkWidget *color_sel_win;
  color_t   *color;
  GdkColor   gcolor;
  GtkWidget *color_sel_ok;
  GtkWidget *color_sel_cancel;
  GtkWidget *color_sel_help;

  if (is_bg) {
    color = &colorf->bg_color;
    title = g_strdup_printf("Wireshark: Choose background color for \"%s\"",
                            colorf->filter_name);
  } else {
    color = &colorf->fg_color;
    title = g_strdup_printf("Wireshark: Choose foreground color for \"%s\"",
                            colorf->filter_name);
  }
  color_sel_win = gtk_color_selection_dialog_new(title);
  g_free(title);
  g_object_set_data(G_OBJECT(color_sel_win), "color_sel_win", color_sel_win);
  gtk_container_set_border_width (GTK_CONTAINER (color_sel_win), 10);

  if (color != NULL) {
    color_t_to_gdkcolor(&gcolor, color);
#if GTK_CHECK_VERSION(2,14,0)
    gtk_color_selection_set_current_color(GTK_COLOR_SELECTION(gtk_color_selection_dialog_get_color_selection(GTK_COLOR_SELECTION_DIALOG(color_sel_win))), &gcolor);
#else
    gtk_color_selection_set_current_color(GTK_COLOR_SELECTION(GTK_COLOR_SELECTION_DIALOG(color_sel_win)->colorsel), &gcolor);
#endif
  }

  g_object_get(color_sel_win, "ok-button", &color_sel_ok, NULL);
  g_object_set_data(G_OBJECT(color_sel_win), "color_sel_ok", color_sel_ok);
#if GTK_CHECK_VERSION(2,18,0)
  gtk_widget_set_can_default(color_sel_ok, TRUE);
#else
  GTK_WIDGET_SET_FLAGS (color_sel_ok, GTK_CAN_DEFAULT);
#endif

  g_object_get(color_sel_win, "cancel-button", &color_sel_cancel, NULL);
  g_object_set_data(G_OBJECT(color_sel_win), "color_sel_cancel", color_sel_cancel);
#if GTK_CHECK_VERSION(2,18,0)
  gtk_widget_set_can_default(color_sel_cancel, TRUE);
#else
  GTK_WIDGET_SET_FLAGS (color_sel_cancel, GTK_CAN_DEFAULT);
#endif
  window_set_cancel_button(color_sel_win, color_sel_cancel, NULL); /* ensure esc does req'd local cxl action.    */
  /* esc as handled by the                      */
  /* gtk_color_selection_dialog widget          */
  /*  doesn't result in this happening.         */

  g_object_get(color_sel_win, "help-button", &color_sel_help, NULL);
  g_object_set_data(G_OBJECT(color_sel_win), "color_sel_help", color_sel_help);
#if GTK_CHECK_VERSION(2,18,0)
  gtk_widget_set_can_default(color_sel_help, TRUE);
#else
  GTK_WIDGET_SET_FLAGS (color_sel_help, GTK_CAN_DEFAULT);
#endif

  g_signal_connect(color_sel_ok, "clicked", G_CALLBACK(color_sel_ok_cb), color_sel_win);
  g_signal_connect(color_sel_cancel, "clicked", G_CALLBACK(color_sel_cancel_cb), color_sel_win);

  gtk_widget_show_all(color_sel_win);
  return color_sel_win;
}

static void
color_sel_win_destroy(GtkWidget *sel_win)
{
  GtkWidget *parent;
  GtkWidget *color_selection_fg, *color_selection_bg;

  /* Find the "Edit color filter" dialog box with which this is associated. */
  parent = (GtkWidget *)g_object_get_data(G_OBJECT(sel_win), COLOR_SELECTION_PARENT);

  /* Find that dialog box's foreground and background color selection
     boxes, if any. */
  color_selection_fg = g_object_get_data(G_OBJECT(parent), COLOR_SELECTION_FG);
  color_selection_bg = g_object_get_data(G_OBJECT(parent), COLOR_SELECTION_BG);

  if (sel_win == color_selection_fg) {
    /* This was its foreground color selection box; it isn't, anymore. */
    g_object_set_data(G_OBJECT(parent), COLOR_SELECTION_FG, NULL);
  }
  if (sel_win == color_selection_bg) {
    /* This was its background color selection box; it isn't, anymore. */
    g_object_set_data(G_OBJECT(parent), COLOR_SELECTION_BG, NULL);
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
  GtkWidget *color_dialog;
  GtkWidget *parent;
  GtkWidget *color_selection_bg;
  gboolean is_bg;

  color_dialog = (GtkWidget *)user_data;

#if GTK_CHECK_VERSION(2,14,0)
  gtk_color_selection_get_current_color(GTK_COLOR_SELECTION(gtk_color_selection_dialog_get_color_selection(GTK_COLOR_SELECTION_DIALOG(color_dialog))), &new_color);
#else
  gtk_color_selection_get_current_color(GTK_COLOR_SELECTION(GTK_COLOR_SELECTION_DIALOG(color_dialog)->colorsel), &new_color);
#endif

  if ( ! get_color(&new_color) ){
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                  "Could not allocate color.  Try again.");
  } else {
    /* Find the "Edit color filter" dialog box with which this is
       associated. */
    parent = (GtkWidget *)g_object_get_data(G_OBJECT(color_dialog), COLOR_SELECTION_PARENT);

    /* Find that dialog box's foreground and background color selection
       boxes, if any. */
    color_selection_bg = g_object_get_data(G_OBJECT(parent), COLOR_SELECTION_BG);
    is_bg = (color_dialog == color_selection_bg);

    color_sel_win_destroy(color_dialog);

    /* now apply the change to the fore/background */
    if (is_bg)
      gtk_widget_modify_base(filt_name_entry, GTK_STATE_NORMAL, &new_color);
    else
      gtk_widget_modify_text(filt_name_entry, GTK_STATE_NORMAL, &new_color);
  }
}

/* Don't choose the selected color as the foreground or background
   color for the filter. */
static void
color_sel_cancel_cb                    (GObject        *object _U_,
                                        gpointer         user_data)
{
  GtkWidget *color_dialog;
  color_dialog = (GtkWidget *)user_data;
  /* nothing to change here.  Just get rid of the dialog box. */

  color_sel_win_destroy(color_dialog);
}
