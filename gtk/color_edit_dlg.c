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

#include <epan/packet.h>
#include "color.h"
#include "colors.h"
#include "color_filters.h"

#include "dlg_utils.h"
#include "gui_utils.h"
#include "compat_macros.h"
#include "filter_dlg.h"
#include "dfilter_expr_dlg.h"
#include "simple_dialog.h"

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


#define COLOR_FILTERS_CL	"color_filters_cl"
#define COLOR_FILTER		"color_filter"
#define COLOR_FILTER_NAME_TE	"color_filter_name_te"
#define COLOR_FILTER_TEXT_TE	"color_filter_text_te"
#define COLOR_SELECTION_FG	"color_selection_fg"
#define COLOR_SELECTION_BG	"color_selection_bg"
#define COLOR_SELECTION_PARENT	"color_selection_parent"

/* XXX - we don't forbid having more than one "Edit color filter" dialog
   open, so these shouldn't be global. */
static GtkWidget *filt_name_entry;
static GtkWidget *filt_text_entry;


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
    edit_dialog = dlg_window_new ("Wireshark: Edit Color Filter");
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

    filt_name_entry = gtk_entry_new ();
    gtk_entry_set_text(GTK_ENTRY(filt_name_entry), colorf->filter_name);

    style = gtk_style_copy(gtk_widget_get_style(filt_name_entry));
    color_t_to_gdkcolor(&style->base[GTK_STATE_NORMAL], &colorf->bg_color);
#if GTK_MAJOR_VERSION < 2
    color_t_to_gdkcolor(&style->fg[GTK_STATE_NORMAL], &colorf->fg_color);
#else
    color_t_to_gdkcolor(&style->text[GTK_STATE_NORMAL], &colorf->fg_color);
#endif
    gtk_widget_set_style(filt_name_entry, style);

    gtk_box_pack_start (GTK_BOX (filter_name_hbox), filt_name_entry, TRUE, TRUE, 0);
    gtk_tooltips_set_tip (tooltips, filt_name_entry, ("This is the editable name of the filter. (No @ characters allowed.)"), NULL);


    /* filter string hbox */
    filter_string_hbox = gtk_hbox_new (FALSE, 0);
    gtk_box_pack_start (GTK_BOX (filter_fr_vbox), filter_string_hbox, TRUE, FALSE, 3);

    color_filter_text = gtk_label_new (("String: "));
    gtk_box_pack_start (GTK_BOX (filter_string_hbox), color_filter_text, FALSE, FALSE, 0);

    filt_text_entry = gtk_entry_new ();
    SIGNAL_CONNECT(filt_text_entry, "changed", filter_te_syntax_check_cb, NULL);
    gtk_entry_set_text(GTK_ENTRY(filt_text_entry), colorf->filter_text);

#if 0
    style = gtk_style_copy(gtk_widget_get_style(filt_text_entry));
    style->base[GTK_STATE_NORMAL] = colorf->bg_color;
    style->fg[GTK_STATE_NORMAL]   = colorf->fg_color;
#endif
    gtk_widget_set_style(filt_text_entry, style);
    gtk_style_unref(style);
    gtk_box_pack_start (GTK_BOX (filter_string_hbox), filt_text_entry, TRUE, TRUE, 0);
    gtk_tooltips_set_tip (tooltips, filt_text_entry, ("This is the editable text of the filter"), NULL);

    /* Create the "Add Expression..." button, to pop up a dialog
       for constructing filter comparison expressions. */
    add_expression_bt = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_ADD_EXPRESSION);
    SIGNAL_CONNECT(add_expression_bt, "clicked", filter_expr_cb, filt_text_entry);
    gtk_box_pack_start (GTK_BOX(filter_string_hbox), add_expression_bt, FALSE, FALSE, 3);
    gtk_tooltips_set_tip (tooltips, add_expression_bt, ("Add an expression to the filter string"), NULL);

    /* Show the (in)validity of the default filter string */
    filter_te_syntax_check_cb(filt_text_entry);

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
    /* Delete the entry. As a side effect this destroys the edit_dialog window. */
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
    title = g_strdup_printf("Wireshark: Choose background color for \"%s\"",
        colorf->filter_name);
  } else {
    color = &colorf->fg_color;
    title = g_strdup_printf("Wireshark: Choose foreground color for \"%s\"", 
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
