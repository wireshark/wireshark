/* color_dlg.c
 * Definitions for dialog boxes for color filters
 *
 * $Id: color_dlg.c,v 1.7 2000/08/23 06:55:21 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#include <stdlib.h>
#include <string.h>

#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "gtk/main.h"
#include "packet.h"
#include "colors.h"
#include "color_dlg.h"
#include "file.h"
#include "dfilter.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "ui_util.h"
		
static GtkWidget* colorize_dialog_new(colfilter *filter);
static void add_filter_to_clist(gpointer filter_arg, gpointer clist_arg);
static void color_filter_up_cb(GtkButton *button, gpointer user_data);
static void color_filter_down_cb(GtkButton *button, gpointer user_data);
static void remember_selected_row(GtkCList *clist, gint row, gint column,
				 GdkEvent *event, gpointer user_data);
static void color_destroy_cb(GtkButton *button, gpointer user_data);
static void destroy_edit_dialog_cb(gpointer filter_arg, gpointer dummy);
static void color_new_cb(GtkButton *button, gpointer user_data);
static void color_edit_cb(GtkButton *button, gpointer user_data);
static void color_delete_cb(GtkWidget *widget, gpointer user_data);
static void color_save_cb(GtkButton *button, gpointer user_data);
static void color_ok_cb(GtkButton *button, gpointer user_data);
static void color_cancel_cb(GtkWidget *widget, gpointer user_data);
static void color_apply_cb(GtkButton *button, gpointer user_data);

static void edit_color_filter_dialog_new(colfilter *filter,
				 GtkWidget *color_filters,
				 GtkWidget **colorize_filter_name,
				 GtkWidget **colorize_filter_text);
static void edit_color_filter_destroy_cb(GtkObject *object,
				 gpointer user_data);
static void edit_color_filter_fg_cb(GtkButton *button, gpointer user_data);
static void edit_color_filter_bg_cb(GtkButton *button, gpointer user_data);
static void edit_color_filter_ok_cb(GtkButton *button, gpointer user_data);
static void edit_color_filter_cancel_cb(GtkObject *object, gpointer user_data);

static GtkWidget* color_sel_win_new(color_filter_t *colorf, gboolean);
static void color_sel_ok_cb(GtkButton *button, gpointer user_data);
static void color_sel_cancel_cb(GtkObject *object, gpointer user_data);

static GtkWidget *colorize_win;

static gchar *titles[2] = { "Name", "Filter String" };

#define COLOR_EDIT_LB		"color_edit_lb"
#define COLOR_FILTERS_CL	"color_filters_cl"
#define COLOR_FILTER		"color_filter"
#define COLOR_SELECTION_FG	"color_selection_fg"
#define COLOR_SELECTION_BG	"color_selection_bg"
#define COLOR_SELECTION_PARENT	"color_selection_parent"

/* Callback for the "Display:Colorize Display" menu item. */
void
color_display_cb(GtkWidget *w, gpointer d)
{
  if (colorize_win != NULL) {
    /* There's already a color dialog box active; reactivate it. */
    reactivate_window(colorize_win);
  } else {
    /* Create a new "Colorize Display" dialog. */
    colorize_win = colorize_dialog_new(cfile.colors);
  }
}

/* Create the "Add color to protocols" dialog. */
static GtkWidget*
colorize_dialog_new (colfilter *filter)
{
  GtkWidget *color_win;
  GtkWidget *vbox1;
  GtkWidget *hbox1;
  GtkWidget *vbox2;
  GtkWidget *color_filter_up;
  GtkWidget *label4;
  GtkWidget *color_filter_down;
  GtkWidget *scrolledwindow1;
  GtkWidget *color_filters;
  GtkWidget *hbox2;
  GtkWidget *color_new;
  GtkWidget *color_edit;
  GtkWidget *color_delete;
  GtkWidget *color_save;
  GtkWidget *hbox3;
  GtkWidget *color_ok;
  GtkWidget *color_apply;
  GtkWidget *color_cancel;
  GtkTooltips *tooltips;

  filter->row_selected = -1; /* no row selected */
  tooltips = gtk_tooltips_new ();

  color_win = dlg_window_new ("Add color to protocols");
  gtk_object_set_data (GTK_OBJECT (color_win), "color_win", color_win);

  vbox1 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox1);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "vbox1", vbox1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox1);
  gtk_container_add (GTK_CONTAINER (color_win), vbox1);

  hbox1 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox1);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "hbox1", hbox1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox1);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox1, TRUE, TRUE, 0);

  vbox2 = gtk_vbox_new (TRUE, 0);
  gtk_widget_ref (vbox2);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "vbox2", vbox2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox2);
  gtk_box_pack_start (GTK_BOX (hbox1), vbox2, FALSE, TRUE, 0);
  gtk_widget_set_usize (vbox2, 150, -2);

  color_filter_up = gtk_button_new_with_label (("Up"));
  gtk_widget_ref (color_filter_up);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_filter_up", color_filter_up,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_filter_up);
  gtk_box_pack_start (GTK_BOX (vbox2), color_filter_up, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_filter_up, ("Move filter higher in list"), NULL);

  label4 = gtk_label_new (("Move filter\nup or down\n[List is processed \n"
			  "in order until\nmatch is found]"));
  gtk_widget_ref (label4);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "label4", label4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (label4);
  gtk_box_pack_start (GTK_BOX (vbox2), label4, FALSE, FALSE, 0);

  color_filter_down = gtk_button_new_with_label (("Down"));
  gtk_widget_ref (color_filter_down);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_filter_down", color_filter_down,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_filter_down);
  gtk_box_pack_start (GTK_BOX (vbox2), color_filter_down, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, color_filter_down, ("Move filter lower in list"), NULL);

  scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_ref (scrolledwindow1);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "scrolledwindow1", scrolledwindow1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (scrolledwindow1);
  gtk_box_pack_start (GTK_BOX (hbox1), scrolledwindow1, TRUE, TRUE, 0);

  color_filters = gtk_clist_new_with_titles(2, titles);

#if 0
  /* I don't seem to need this, but just in case, I'll if0 it */
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_filters",
                            color_filters,
                            (GtkDestroyNotify) gtk_widget_unref);
#endif
  g_slist_foreach(filter_list, add_filter_to_clist, color_filters);

  gtk_widget_show (color_filters);
  gtk_container_add (GTK_CONTAINER (scrolledwindow1), color_filters);
  gtk_widget_set_usize (color_filters, 300, -2);
  gtk_clist_set_column_width (GTK_CLIST (color_filters), 0, 80);
  gtk_clist_set_column_width (GTK_CLIST (color_filters), 1, 80);
  gtk_clist_column_titles_show (GTK_CLIST (color_filters));

  hbox2 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox2);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "hbox2", hbox2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox2);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox2, TRUE, FALSE, 5);
  gtk_widget_set_usize (hbox2, -2, 40);

  color_new = gtk_button_new_with_label (("New"));
  gtk_widget_ref (color_new);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_new", color_new,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_new);
  gtk_box_pack_start (GTK_BOX (hbox2), color_new, TRUE, FALSE, 5);
  gtk_widget_set_usize (color_new, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_new, ("Create a new colorization filter after selected filter"), NULL);

  color_edit = gtk_button_new_with_label (("Edit"));
  gtk_widget_ref (color_edit);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_edit", color_edit,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_edit);
  gtk_widget_set_usize(color_edit, 50, 30);
  gtk_box_pack_start (GTK_BOX (hbox2), color_edit, TRUE, FALSE, 5);
  gtk_tooltips_set_tip (tooltips, color_edit, ("Change color of selected filter"), NULL);
  gtk_widget_set_sensitive (color_edit,
      (filter->num_of_filters != 0));

  color_delete = gtk_button_new_with_label (("Delete"));
  gtk_widget_ref (color_delete);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_delete", color_delete,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_delete);
  gtk_box_pack_start (GTK_BOX (hbox2), color_delete, TRUE, FALSE, 5);
  gtk_widget_set_usize (color_delete, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_delete, ("Delete selected colorization filter"), NULL);

  color_save = gtk_button_new_with_label (("Save"));
  gtk_widget_ref (color_save);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_save", color_save,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_save);
  gtk_box_pack_start (GTK_BOX (hbox2), color_save, TRUE, FALSE, 5);
  gtk_widget_set_usize (color_save, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_save, ("Save all filters to disk"), NULL);

  hbox3 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox3);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "hbox3", hbox3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox3);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox3, TRUE, FALSE, 5);
  gtk_widget_set_usize (hbox3, 177, 40);

  color_ok = gtk_button_new_with_label (("OK"));
  gtk_widget_ref (color_ok);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_ok", color_ok,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_ok);
  gtk_box_pack_start (GTK_BOX (hbox3), color_ok, TRUE, FALSE, 0);
  gtk_widget_set_usize (color_ok, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_ok, ("Accept filter list; apply changes"), NULL);

  color_apply = gtk_button_new_with_label (("Apply"));
  gtk_widget_ref (color_apply);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_apply", color_apply,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_apply);
  gtk_box_pack_start (GTK_BOX (hbox3), color_apply, TRUE, FALSE, 0);
  gtk_widget_set_usize (color_apply, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_apply, ("Apply filters in list"), NULL);

  color_cancel = gtk_button_new_with_label (("Cancel"));
  gtk_widget_ref (color_cancel);
  gtk_object_set_data_full (GTK_OBJECT (color_win), "color_cancel", color_cancel,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_cancel);
  gtk_box_pack_start (GTK_BOX (hbox3), color_cancel, TRUE, FALSE, 0);
  gtk_widget_set_usize (color_cancel, 50, 30);
  gtk_tooltips_set_tip (tooltips, color_cancel, ("No more filter changes; don't apply"), NULL);

  gtk_signal_connect (GTK_OBJECT (color_win), "destroy",
                      GTK_SIGNAL_FUNC (color_destroy_cb),
                      NULL);
  gtk_object_set_data(GTK_OBJECT (color_filter_up), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (color_filter_up), "clicked",
                      GTK_SIGNAL_FUNC (color_filter_up_cb),
                      filter);
  gtk_object_set_data(GTK_OBJECT (color_filter_down), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (color_filter_down), "clicked",
                      GTK_SIGNAL_FUNC (color_filter_down_cb),
                      filter);
  gtk_signal_connect (GTK_OBJECT (color_filters), "select_row",
                      GTK_SIGNAL_FUNC (remember_selected_row),
                      filter);
  gtk_object_set_data(GTK_OBJECT (color_new), COLOR_EDIT_LB,
                      color_edit);
  gtk_object_set_data(GTK_OBJECT (color_new), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (color_new), "clicked",
                      GTK_SIGNAL_FUNC (color_new_cb),
                      filter);
  gtk_object_set_data(GTK_OBJECT (color_edit), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (color_edit), "clicked",
                      GTK_SIGNAL_FUNC (color_edit_cb),
                      filter);
  gtk_object_set_data(GTK_OBJECT (color_delete), COLOR_EDIT_LB,
                      color_edit);
  gtk_object_set_data(GTK_OBJECT (color_delete), COLOR_FILTERS_CL,
                      color_filters);
  gtk_signal_connect (GTK_OBJECT (color_delete), "clicked",
                      GTK_SIGNAL_FUNC (color_delete_cb),
                      filter);
  gtk_signal_connect (GTK_OBJECT (color_save), "clicked",
                      GTK_SIGNAL_FUNC (color_save_cb),
                      filter);
  gtk_signal_connect (GTK_OBJECT (color_ok), "clicked",
                      GTK_SIGNAL_FUNC (color_ok_cb),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (color_apply), "clicked",
                      GTK_SIGNAL_FUNC (color_apply_cb),
                      filter);
  gtk_signal_connect (GTK_OBJECT (color_cancel), "clicked",
                      GTK_SIGNAL_FUNC (color_cancel_cb),
                      NULL);

  gtk_widget_grab_focus (color_filters);
  gtk_object_set_data (GTK_OBJECT (color_win), "tooltips", tooltips);
  gtk_widget_show (color_win);

  return color_win;
}

static void
add_filter_to_clist(gpointer filter_arg, gpointer clist_arg)
{
  color_filter_t *colorf = filter_arg;
  GtkWidget *color_filters = clist_arg;
  gchar *data[2];
  gint row;

  data[0] = colorf->filter_name;
  data[1] = colorf->filter_text;
  row = gtk_clist_append(GTK_CLIST(color_filters), data);
  gtk_clist_set_row_data(GTK_CLIST(color_filters), row, colorf);
  gtk_clist_set_foreground(GTK_CLIST(color_filters), row, &colorf->fg_color);
  gtk_clist_set_background(GTK_CLIST(color_filters), row, &colorf->bg_color);
}

/* Move the selected filter up in the list */
static void
color_filter_up_cb                     (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  gint filter_number;
  GtkWidget *color_filters;
  color_filter_t *colorf;

  filter = (colfilter *)user_data;
  filter_number = filter->row_selected;

  /* If it is filter number 0, it cannot be moved, as it's already
     at the top of the filter.
     If there's only one filter in the list, it cannot be moved,
     as there's no place to move it. */
  if (filter_number != 0 && filter->num_of_filters >= 2) {
  	color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
        colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters),
	   filter_number);
	gtk_clist_swap_rows(GTK_CLIST(color_filters), filter_number,
			filter_number-1);
	filter_list = g_slist_remove(filter_list, colorf);
	filter_list = g_slist_insert(filter_list, colorf, filter_number-1);
	filter->row_selected--;
  }
}

/* Move the selected filter down in the list */
static void
color_filter_down_cb                   (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  gint filter_number;
  GtkWidget *color_filters;
  color_filter_t *colorf;

  filter = (colfilter *)user_data;
  filter_number = filter->row_selected;

  /* If it is the last filter in the list, it cannot be moved, as it's
     already at the bottom of the filter.
     If there's only one filter in the list, it cannot be moved,
     as there's no place to move it. */
  if (filter_number != filter->num_of_filters-1
    && filter->num_of_filters >= 2) {
  	color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
        colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters),
	   filter_number);
	gtk_clist_swap_rows(GTK_CLIST(color_filters), filter_number+1,
			filter_number);
	filter_list = g_slist_remove(filter_list, colorf);
	filter_list = g_slist_insert(filter_list, colorf, filter_number+1);
	filter->row_selected++;
  }
}

/* Set selected row in cf */
static void
remember_selected_row                 (GtkCList        *clist,
                                        gint             row,
                                        gint             column,
                                        GdkEvent        *event,
                                        gpointer         user_data)
{
  colfilter *filter = (colfilter *)user_data;

  filter->row_selected = row;
}

/* Called when the dialog box is being destroyed; destroy any edit
   dialogs opened from this dialog, and null out the pointer to this
   dialog. */
static void
color_destroy_cb                       (GtkButton       *button,
                                        gpointer         user_data)
{
  /* Destroy any edit dialogs we have open. */
  g_slist_foreach(filter_list, destroy_edit_dialog_cb, NULL);

  colorize_win = NULL;
}

static void
destroy_edit_dialog_cb(gpointer filter_arg, gpointer dummy)
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
color_new_cb                          (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  color_filter_t *colorf;
  GtkWidget *color_filters;
  gchar *data[2];
  gint row;
  GtkWidget *color_edit;

  filter = (colfilter *)user_data;
  colorf = new_color_filter(filter, "name", "filter"); /* Adds at end! */

  color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
  data[0] = colorf->filter_name;
  data[1] = colorf->filter_text;
  row = gtk_clist_append(GTK_CLIST(color_filters), data);
  gtk_clist_set_row_data(GTK_CLIST(color_filters), row, colorf);

  /* A row has been added, so we can edit it. */
  color_edit = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
					COLOR_EDIT_LB);
  gtk_widget_set_sensitive (color_edit, TRUE);

  /* select the new (last) row */
  filter->row_selected = filter->num_of_filters;
  filter->num_of_filters++;
  gtk_clist_select_row(GTK_CLIST(color_filters), filter->row_selected, -1);
  edit_color_filter_dialog_new(filter, color_filters, &filt_name_entry,
				&filt_text_entry);
}

/* Pop up an "Edit color filter" dialog box to edit an existing filter. */
static void
color_edit_cb                        (GtkButton       *button,
                                      gpointer         user_data)
{
  colfilter *filter;
  GtkWidget *color_filters;

  filter = (colfilter *)user_data;
  color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
  if(filter->row_selected == -1){
	/* select the first row */
	filter->row_selected = 0;
	gtk_clist_select_row(GTK_CLIST(color_filters), filter->row_selected,
				-1);
  }
  edit_color_filter_dialog_new(filter, color_filters, &filt_name_entry,
				&filt_text_entry);
}

/* Delete a color from the list. */
static void
color_delete_cb(GtkWidget *widget, gpointer user_data)
{
  colfilter *filter;
  GtkWidget *color_filters;
  color_filter_t *colorf;
  GtkWidget *color_edit;

  filter = (colfilter *)user_data;
  if(filter->row_selected != -1){
  	color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(widget),
		      COLOR_FILTERS_CL);
  	colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters),
	   filter->row_selected);

	/* Remove this color filter from the CList displaying the
	   color filters. */
	gtk_clist_remove(GTK_CLIST(color_filters), filter->row_selected);

	/* Destroy any "Edit color filter" dialog boxes editing it. */
	if (colorf->edit_dialog != NULL)
		gtk_widget_destroy(colorf->edit_dialog);

	/* Remove the color filter from the list of color filters. */
	delete_color_filter(colorf);
	filter->num_of_filters--;
        if(!filter->num_of_filters){
        	/* No filters any more, so none can be selected... */
		filter->row_selected = -1;
		color_edit =
		    (GtkWidget *) gtk_object_get_data(GTK_OBJECT(widget),
		      COLOR_EDIT_LB);

		/* ...and none can be edited. */
		gtk_widget_set_sensitive (color_edit, FALSE);
	} else {
		filter->row_selected--;
		if(filter->row_selected < 0)
			filter->row_selected = 0;
		gtk_clist_select_row(GTK_CLIST(color_filters),
		    filter->row_selected, 0);
	}
  }
}

/* Save color filters to the color filter file. */
static void
color_save_cb                          (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter = (colfilter *)user_data;

  if (!write_filters(filter))
	simple_dialog(ESD_TYPE_CRIT, NULL, "Could not open filter file: %s",
	    strerror(errno));

}

/* Exit dialog and apply new list of color filters to the capture. */
static void
color_ok_cb                            (GtkButton       *button,
                                        gpointer         user_data)
{
  /* colorize list */
  colorize_packets(&cfile);

  /* Destroy the dialog box. */
  gtk_widget_destroy(colorize_win);
}

/* Exit dialog without colorizing packets with the new list.
   XXX - should really undo any changes to the list.... */
static void
color_cancel_cb                        (GtkWidget       *widget,
                                        gpointer         user_data)
{
  /* Destroy the dialog box. */
  gtk_widget_destroy(colorize_win);
}

/* Apply new list of color filters to the capture. */
static void
color_apply_cb                         (GtkButton       *button,
                                        gpointer         user_data)
{
  colorize_packets(&cfile);
}

/* Create an "Edit color filter" dialog for a given color filter, and
   associate it with that color filter. */
static void
edit_color_filter_dialog_new (colfilter *filter,
	GtkWidget *color_filters,
	GtkWidget **colorize_filter_name,
	GtkWidget **colorize_filter_text)
{
  color_filter_t *colorf;
  GtkWidget *edit_dialog;
  GtkWidget *vbox3;
  GtkWidget *hbox6;
  GtkWidget *color_filter_name;
  GtkWidget *hbox7;
  GtkWidget *color_filter_text;
  GtkWidget *hbox5;
  GtkWidget *colorize_filter_fg;
  GtkWidget *colorize_filter_bg;
  GtkWidget *hbox4;
  GtkWidget *edit_color_filter_ok;
  GtkWidget *edit_color_filter_cancel;
  GtkTooltips *tooltips;
  GtkStyle  *style;

  colorf = gtk_clist_get_row_data(GTK_CLIST(color_filters),
	   filter->row_selected);
  if (colorf->edit_dialog != NULL) {
    /* There's already an edit box open for this filter; reactivate it. */
    reactivate_window(colorf->edit_dialog);
    return;
  }

  tooltips = gtk_tooltips_new ();

  edit_dialog = dlg_window_new ("Edit color filter");
  gtk_object_set_data (GTK_OBJECT (edit_dialog), "edit_dialog", edit_dialog);
  colorf->edit_dialog = edit_dialog;

  vbox3 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox3);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "vbox3", vbox3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox3);
  gtk_container_add (GTK_CONTAINER (edit_dialog), vbox3);

  hbox6 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox6);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "hbox6", hbox6,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox6);
  gtk_box_pack_start (GTK_BOX (vbox3), hbox6, TRUE, FALSE, 5);

  color_filter_name = gtk_label_new (("Name: "));
  gtk_widget_ref (color_filter_name);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "color_filter_name", color_filter_name,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_filter_name);
  gtk_box_pack_start (GTK_BOX (hbox6), color_filter_name, FALSE, FALSE, 0);

  *colorize_filter_name = gtk_entry_new ();
  gtk_widget_ref (*colorize_filter_name);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "*colorize_filter_name", *colorize_filter_name,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_entry_set_text(GTK_ENTRY(*colorize_filter_name), colorf->filter_name);

  style = gtk_style_copy(gtk_widget_get_style(*colorize_filter_name));
  style->base[GTK_STATE_NORMAL] = colorf->bg_color;
  style->fg[GTK_STATE_NORMAL]   = colorf->fg_color;
  gtk_widget_set_style(*colorize_filter_name, style);

  gtk_widget_show (*colorize_filter_name);
  gtk_box_pack_start (GTK_BOX (hbox6), *colorize_filter_name, TRUE, TRUE, 0);
  gtk_tooltips_set_tip (tooltips, *colorize_filter_name, ("This is the editable name of the filter. (No @ characters allowed.)"), NULL);

  hbox7 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox7);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "hbox7", hbox7,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox7);
  gtk_box_pack_start (GTK_BOX (vbox3), hbox7, TRUE, FALSE, 5);

  color_filter_text = gtk_label_new (("Filter text:"));
  gtk_widget_ref (color_filter_text);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "color_filter_text", color_filter_text,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (color_filter_text);
  gtk_box_pack_start (GTK_BOX (hbox7), color_filter_text, FALSE, FALSE, 0);

  *colorize_filter_text = gtk_entry_new ();
  gtk_widget_ref (*colorize_filter_text);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "*colorize_filter_text", *colorize_filter_text,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_entry_set_text(GTK_ENTRY(*colorize_filter_text), colorf->filter_text);
#if 0
  style = gtk_style_copy(gtk_widget_get_style(*colorize_filter_text));
  style->base[GTK_STATE_NORMAL] = colorf->bg_color;
  style->fg[GTK_STATE_NORMAL]   = colorf->fg_color;
#endif
  gtk_widget_set_style(*colorize_filter_text, style);
  gtk_widget_show (*colorize_filter_text);
  gtk_box_pack_start (GTK_BOX (hbox7), *colorize_filter_text, TRUE, TRUE, 0);
  gtk_tooltips_set_tip (tooltips, *colorize_filter_text, ("This is the editable text of the filter"), NULL);

  hbox5 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox5);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "hbox5", hbox5,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox5);
  gtk_box_pack_start (GTK_BOX (vbox3), hbox5, FALSE, FALSE, 5);
  gtk_widget_set_usize (hbox5, -2, 60);

  colorize_filter_fg = gtk_button_new_with_label (("Choose \nforeground\ncolor"));
  gtk_widget_ref (colorize_filter_fg);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "colorize_filter_fg", colorize_filter_fg,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (colorize_filter_fg);
  gtk_box_pack_start (GTK_BOX (hbox5), colorize_filter_fg, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, colorize_filter_fg, ("Select color for data display"), NULL);

  colorize_filter_bg = gtk_button_new_with_label (("Choose\nbackground\ncolor"));
  gtk_widget_ref (colorize_filter_bg);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "colorize_filter_bg", colorize_filter_bg,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (colorize_filter_bg);
  gtk_box_pack_start (GTK_BOX (hbox5), colorize_filter_bg, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, colorize_filter_bg, ("Select color for data display"), NULL);

  hbox4 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox4);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "hbox4", hbox4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox4);
  gtk_box_pack_start (GTK_BOX (vbox3), hbox4, TRUE, FALSE, 5);
  gtk_widget_set_usize (hbox4, -2, 40);

  edit_color_filter_ok = gtk_button_new_with_label (("OK"));
  gtk_widget_ref (edit_color_filter_ok);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "edit_color_filter_ok", edit_color_filter_ok,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_set_usize (edit_color_filter_ok, 50, 30);
  gtk_widget_show (edit_color_filter_ok);
  gtk_box_pack_start (GTK_BOX (hbox4), edit_color_filter_ok, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, edit_color_filter_ok, ("Accept filter color change"), NULL);

  edit_color_filter_cancel = gtk_button_new_with_label (("Cancel"));
  gtk_widget_ref (edit_color_filter_cancel);
  gtk_object_set_data_full (GTK_OBJECT (edit_dialog), "edit_color_filter_cancel", edit_color_filter_cancel,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_set_usize (edit_color_filter_cancel, 50, 30);
  gtk_widget_show (edit_color_filter_cancel);
  gtk_box_pack_start (GTK_BOX (hbox4), edit_color_filter_cancel, TRUE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, edit_color_filter_cancel, ("Reject filter color change"), NULL);
  gtk_object_set_data(GTK_OBJECT (edit_dialog), COLOR_FILTER,
                      colorf);
  gtk_signal_connect (GTK_OBJECT (edit_dialog), "destroy",
                      GTK_SIGNAL_FUNC (edit_color_filter_destroy_cb),
                      NULL);
  gtk_object_set_data(GTK_OBJECT (colorize_filter_fg), COLOR_FILTER,
                      colorf);
  gtk_signal_connect (GTK_OBJECT (colorize_filter_fg), "clicked",
                      GTK_SIGNAL_FUNC (edit_color_filter_fg_cb),
                      filter);
  gtk_object_set_data(GTK_OBJECT (colorize_filter_bg), COLOR_FILTER,
                      colorf);
  gtk_signal_connect (GTK_OBJECT (colorize_filter_bg), "clicked",
                      GTK_SIGNAL_FUNC (edit_color_filter_bg_cb),
                      filter);
  gtk_object_set_data(GTK_OBJECT (edit_color_filter_ok), COLOR_FILTERS_CL,
                      color_filters);
  gtk_object_set_data(GTK_OBJECT (edit_color_filter_ok), COLOR_FILTER,
                      colorf);
  gtk_signal_connect (GTK_OBJECT (edit_color_filter_ok), "clicked",
                      GTK_SIGNAL_FUNC (edit_color_filter_ok_cb),
                      edit_dialog);
  gtk_signal_connect (GTK_OBJECT (edit_color_filter_cancel), "clicked",
                      GTK_SIGNAL_FUNC (edit_color_filter_cancel_cb),
                      edit_dialog);

  gtk_object_set_data (GTK_OBJECT (edit_dialog), "tooltips", tooltips);
  gtk_widget_show (edit_dialog);
}

/* Called when the dialog box is being destroyed; destroy any color
   selection dialogs opened from this dialog, and null out the pointer
   to this dialog. */
static void
edit_color_filter_destroy_cb           (GtkObject       *object,
                                        gpointer         user_data)
{
  color_filter_t *colorf;
  GtkWidget *color_sel;

  colorf = (color_filter_t *) gtk_object_get_data(GTK_OBJECT(object),
		      COLOR_FILTER);

  colorf->edit_dialog = NULL;

  /* Destroy any color selection dialogs this dialog had open. */
  color_sel = (GtkWidget *) gtk_object_get_data(object, COLOR_SELECTION_FG);
  if (color_sel != NULL)
    gtk_widget_destroy(color_sel);
  color_sel = (GtkWidget *) gtk_object_get_data(object, COLOR_SELECTION_BG);
  if (color_sel != NULL)
    gtk_widget_destroy(color_sel);
}

/* Pop up a color selection box to choose the foreground color. */
static void
edit_color_filter_fg_cb                (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  color_filter_t *colorf;
  GtkWidget *color_selection_fg;

  filter = (colfilter *)user_data;
  colorf = (color_filter_t *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTER);
  /* Do we already have one open for this dialog? */
  color_selection_fg = gtk_object_get_data(GTK_OBJECT (colorf->edit_dialog),
      COLOR_SELECTION_FG);
  if (color_selection_fg != NULL) {
    /* Yes.  Just reactivate it. */
    reactivate_window(color_selection_fg);
  } else {
    /* No.  Create a new color selection box, and associate it with
       this dialog. */
    color_selection_fg = color_sel_win_new(colorf, FALSE);
    gtk_object_set_data(GTK_OBJECT (colorf->edit_dialog), COLOR_SELECTION_FG,
                      color_selection_fg);
    gtk_object_set_data(GTK_OBJECT (color_selection_fg),
		COLOR_SELECTION_PARENT, colorf->edit_dialog);
  }
}

/* Pop up a color selection box to choose the background color. */
static void
edit_color_filter_bg_cb                (GtkButton       *button,
                                        gpointer         user_data)
{
  colfilter *filter;
  color_filter_t *colorf;
  GtkWidget *color_selection_bg;

  filter = (colfilter *)user_data;
  colorf = (color_filter_t *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTER);

  /* Do we already have one open for this dialog? */
  color_selection_bg = gtk_object_get_data(GTK_OBJECT (colorf->edit_dialog),
      COLOR_SELECTION_BG);
  if (color_selection_bg != NULL) {
    /* Yes.  Just reactivate it. */
    reactivate_window(color_selection_bg);
  } else {
    /* No.  Create a new color selection box, and associate it with
       this dialog. */
    color_selection_bg = color_sel_win_new(colorf, TRUE);
    gtk_object_set_data(GTK_OBJECT (colorf->edit_dialog), COLOR_SELECTION_BG,
                      color_selection_bg);
    gtk_object_set_data(GTK_OBJECT (color_selection_bg),
		COLOR_SELECTION_PARENT, colorf->edit_dialog);
  }
}

/* accept color (and potential content) change */
static void
edit_color_filter_ok_cb                (GtkButton       *button,
                                        gpointer         user_data)
{
  GtkWidget *dialog;
  GtkStyle *style;
  GdkColor new_fg_color;
  GdkColor new_bg_color;
  gchar *filter_name;
  gchar *filter_text;
  color_filter_t *colorf;
  dfilter *compiled_filter;
  GtkWidget *color_filters;

  dialog = (GtkWidget *)user_data;

  style = gtk_widget_get_style(filt_name_entry);
  new_bg_color = style->base[GTK_STATE_NORMAL];
  new_fg_color = style->fg[GTK_STATE_NORMAL];

  filter_name = g_strdup(gtk_entry_get_text(GTK_ENTRY(filt_name_entry)));
  filter_text = g_strdup(gtk_entry_get_text(GTK_ENTRY(filt_text_entry)));

  if(strchr(filter_name,'@') || strchr(filter_text,'@')){
	simple_dialog(ESD_TYPE_CRIT, NULL, "Filter names and strings must not"
	  " use the '@' character. Filter unchanged.");
	g_free(filter_name);
  	g_free(filter_text);
	return;
  }

  if(dfilter_compile(filter_text, &compiled_filter) != 0 ){
	simple_dialog(ESD_TYPE_CRIT, NULL, "Filter \"%s\" did not compile correctly.\n"
		" Please try again. Filter unchanged.\n%s\n", filter_name,
		dfilter_error_msg);
  } else {
	color_filters = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTERS_CL);
        colorf = (color_filter_t *) gtk_object_get_data(GTK_OBJECT(button),
		      COLOR_FILTER);

	if (colorf->filter_name != NULL)
	    g_free(colorf->filter_name);
	colorf->filter_name = filter_name;
	if (colorf->filter_text != NULL)
	    g_free(colorf->filter_text);
	colorf->filter_text = filter_text;
	colorf->fg_color = new_fg_color;
	colorf->bg_color = new_bg_color;
	gtk_clist_set_foreground(GTK_CLIST(color_filters),
	    cfile.colors->row_selected, &new_fg_color);
	gtk_clist_set_background(GTK_CLIST(color_filters),
	    cfile.colors->row_selected, &new_bg_color);
	if(colorf->c_colorfilter != NULL)
	    dfilter_destroy(colorf->c_colorfilter);
	colorf->c_colorfilter = compiled_filter;
	/* gtk_clist_set_text frees old text (if any) and allocates new space */
	gtk_clist_set_text(GTK_CLIST(color_filters),
		cfile.colors->row_selected, 0, filter_name);
	gtk_clist_set_text(GTK_CLIST(color_filters),
		cfile.colors->row_selected, 1, filter_text);

	/* Destroy the dialog box. */
	gtk_widget_destroy(dialog);
  }
}

/* Exit dialog and do not process list */
static void
edit_color_filter_cancel_cb            (GtkObject       *object,
                                        gpointer         user_data)
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
  static const gchar fg_title_format[] = "Choose foreground color for \"%s\"";
  static const gchar bg_title_format[] = "Choose background color for \"%s\"";
  GtkWidget *color_sel_win;
  GdkColor *color;
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
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_sel_win", color_sel_win);
  gtk_container_set_border_width (GTK_CONTAINER (color_sel_win), 10);

  if (color != NULL) {
    gdouble cols[3];

    cols[0] = (gdouble)color->red / 65536.0;
    cols[1] = (gdouble)color->green / 65536.0;
    cols[2] = (gdouble)color->blue / 65536.0;

    gtk_color_selection_set_color(
		    GTK_COLOR_SELECTION(
			    GTK_COLOR_SELECTION_DIALOG(color_sel_win)->colorsel), cols);
  }

  color_sel_ok = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->ok_button;
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_sel_ok", color_sel_ok);
  gtk_widget_show (color_sel_ok);
  GTK_WIDGET_SET_FLAGS (color_sel_ok, GTK_CAN_DEFAULT);

  color_sel_cancel = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->cancel_button;
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_sel_cancel", color_sel_cancel);
  gtk_widget_show (color_sel_cancel);
  GTK_WIDGET_SET_FLAGS (color_sel_cancel, GTK_CAN_DEFAULT);


  color_sel_help = GTK_COLOR_SELECTION_DIALOG (color_sel_win)->help_button;
  gtk_object_set_data (GTK_OBJECT (color_sel_win), "color_sel_help", color_sel_help);
  gtk_widget_show (color_sel_help);


  GTK_WIDGET_SET_FLAGS (color_sel_help, GTK_CAN_DEFAULT);
  gtk_signal_connect (GTK_OBJECT (color_sel_win), "destroy",
                      GTK_SIGNAL_FUNC (color_sel_cancel_cb),
                      color_sel_win);

  gtk_signal_connect (GTK_OBJECT (color_sel_ok), "clicked",
                      GTK_SIGNAL_FUNC (color_sel_ok_cb),
                      color_sel_win);
  gtk_signal_connect (GTK_OBJECT (color_sel_cancel), "clicked",
                      GTK_SIGNAL_FUNC (color_sel_cancel_cb),
                      color_sel_win);

  gtk_widget_show(color_sel_win);
  return color_sel_win;
}

static void
color_sel_win_destroy(GtkWidget *sel_win)
{
  GtkWidget *parent;
  GtkWidget *color_selection_fg, *color_selection_bg;

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
    gtk_object_set_data(GTK_OBJECT (parent), COLOR_SELECTION_FG, NULL);
  }
  if (sel_win == color_selection_bg) {
    /* This was its background color selection box; it isn't, anymore. */
    gtk_object_set_data(GTK_OBJECT (parent), COLOR_SELECTION_BG, NULL);
  }

  /* Now destroy it. */
  gtk_widget_destroy(sel_win);
}

/* Retrieve selected color */
static void
color_sel_ok_cb                        (GtkButton       *button,
                                        gpointer         user_data)
{
  GdkColor new_color; /* Color from color selection dialog */
  gdouble new_colors[3];
  GtkWidget *color_dialog;
  GtkStyle  *style;
  GtkWidget *parent;
  GtkWidget *color_selection_fg, *color_selection_bg;
  gboolean is_bg;

  color_dialog = (GtkWidget *)user_data;

  gtk_color_selection_get_color(GTK_COLOR_SELECTION(
   GTK_COLOR_SELECTION_DIALOG(color_dialog)->colorsel), new_colors);

  new_color.red   = (guint16)(new_colors[0]*65535.0);
  new_color.green = (guint16)(new_colors[1]*65535.0);
  new_color.blue  = (guint16)(new_colors[2]*65535.0);

  if ( ! get_color(&new_color) ){
	simple_dialog(ESD_TYPE_CRIT, NULL, "Could not allocate color.  Try again.");
  } else {
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
	is_bg = (color_dialog == color_selection_bg);

	color_sel_win_destroy(color_dialog);

	/* now apply the change to the fore/background */
	
	style = gtk_style_copy(gtk_widget_get_style(filt_name_entry));
	if (is_bg)
	  style->base[GTK_STATE_NORMAL] = new_color;
	else
	  style->fg[GTK_STATE_NORMAL] = new_color;
	gtk_widget_set_style(filt_name_entry, style);
	gtk_widget_set_style(filt_text_entry, style);	
  }
}

/* Don't choose the selected color as the foreground or background
   color for the filter. */
static void
color_sel_cancel_cb                    (GtkObject       *object,
                                        gpointer         user_data)
{
  GtkWidget *color_dialog;
  color_dialog = (GtkWidget *)user_data;
  /* nothing to change here.  Just get rid of the dialog box. */

  color_sel_win_destroy(color_dialog);
}
