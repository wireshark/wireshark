/* find_dlg.c
 * Routines for "find frame" window
 *
 * $Id: find_dlg.c,v 1.7 2000/03/15 08:54:24 guy Exp $
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef __G_LIB_H__
#include <glib.h>
#endif

#include "proto.h"
#include "dfilter.h"
#include "globals.h"

#include "find_dlg.h"
#include "filter_prefs.h"
#include "simple_dialog.h"

/* Capture callback data keys */
#define E_FIND_FILT_KEY     "find_filter_te"
#define E_FIND_BACKWARD_KEY "find_backward"

static void
find_frame_ok_cb(GtkWidget *ok_bt, gpointer parent_w);

static void
find_frame_close_cb(GtkWidget *close_bt, gpointer parent_w);

void
find_frame_cb(GtkWidget *w, gpointer d)
{
  GtkWidget     *find_frame_w, *main_vb, *filter_hb, *filter_bt, *filter_te,
                *direction_hb, *forward_rb, *backward_rb,
                *bbox, *ok_bt, *cancel_bt;

  find_frame_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(find_frame_w), "Ethereal: Find Frame");
  
  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(find_frame_w), main_vb);
  gtk_widget_show(main_vb);
  
  /* Filter row */
  filter_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), filter_hb);
  gtk_widget_show(filter_hb);
  
  filter_bt = gtk_button_new_with_label("Filter:");
  gtk_signal_connect(GTK_OBJECT(filter_bt), "clicked",
    GTK_SIGNAL_FUNC(filter_dialog_cb), NULL);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);
  
  filter_te = gtk_entry_new();
  if (cf.sfilter) gtk_entry_set_text(GTK_ENTRY(filter_te), cf.sfilter);
  gtk_object_set_data(GTK_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_te, TRUE, TRUE, 0);
  gtk_widget_show(filter_te);
  
  /* Misc row: Forward and reverse radio buttons */
  direction_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), direction_hb);
  gtk_widget_show(direction_hb);

  forward_rb = gtk_radio_button_new_with_label(NULL, "Forward");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(forward_rb), !cf.sbackward);
  gtk_box_pack_start(GTK_BOX(direction_hb), forward_rb, TRUE, TRUE, 0);
  gtk_widget_show(forward_rb);

  backward_rb = gtk_radio_button_new_with_label(
               gtk_radio_button_group(GTK_RADIO_BUTTON(forward_rb)),
               "Backward");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(backward_rb), cf.sbackward);
  gtk_box_pack_start(GTK_BOX(direction_hb), backward_rb, TRUE, TRUE, 0);
  gtk_widget_show(backward_rb);

  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(find_frame_ok_cb), GTK_OBJECT(find_frame_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(find_frame_close_cb), GTK_OBJECT(find_frame_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  /* Attach pointers to needed widgets to the capture prefs window/object */
  gtk_object_set_data(GTK_OBJECT(find_frame_w), E_FIND_FILT_KEY, filter_te);
  gtk_object_set_data(GTK_OBJECT(find_frame_w), E_FIND_BACKWARD_KEY, backward_rb);

  /* Give the initial focus to the "Filter" entry box. */
  gtk_widget_grab_focus(filter_te);

  gtk_widget_show(find_frame_w);
}

static void
find_frame_ok_cb(GtkWidget *ok_bt, gpointer parent_w)
{
  GtkWidget *filter_te, *backward_rb;
  gchar *filter_text;
  dfilter *sfcode;

  filter_te = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_FIND_FILT_KEY);
  backward_rb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_FIND_BACKWARD_KEY);

  filter_text = gtk_entry_get_text(GTK_ENTRY(filter_te));

  /*
   * Try to compile the filter.
   */
  if (dfilter_compile(filter_text, &sfcode) != 0) {
    /* The attempt failed; report an error. */
    simple_dialog(ESD_TYPE_WARN, NULL, dfilter_error_msg);
    return;
  }

  /* Was it empty? */
  if (sfcode == NULL) {
    /* Yes - complain. */
    simple_dialog(ESD_TYPE_WARN, NULL,
       "You didn't specify a filter to use when searching for a frame.");
    return;
  }

  /*
   * Remember the filter.
   */
  if (cf.sfilter)
    g_free(cf.sfilter);
  cf.sfilter = g_strdup(filter_text);

  cf.sbackward = GTK_TOGGLE_BUTTON (backward_rb)->active;

  if (!find_packet(&cf, sfcode)) {
    /* We didn't find the packet. */
    simple_dialog(ESD_TYPE_WARN, NULL, "No packet matched that filter.");
    return;
  }

  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
find_frame_close_cb(GtkWidget *close_bt, gpointer parent_w)
{
  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}
