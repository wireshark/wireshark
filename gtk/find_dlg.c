/* find_dlg.c
 * Routines for "find frame" window
 *
 * $Id: find_dlg.c,v 1.28 2003/04/24 23:18:07 guy Exp $
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

#include <epan/proto.h>
#include <epan/dfilter/dfilter.h>
#include "globals.h"

#include "ui_util.h"
#include "find_dlg.h"
#include "filter_prefs.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "compat_macros.h"

/* Capture callback data keys */
#define E_FIND_FILT_KEY     "find_filter_te"
#define E_FIND_BACKWARD_KEY "find_backward"

static void
find_frame_ok_cb(GtkWidget *ok_bt, gpointer parent_w);

static void
find_frame_close_cb(GtkWidget *close_bt, gpointer parent_w);

static void
find_frame_destroy_cb(GtkWidget *win, gpointer user_data);

/*
 * Keep a static pointer to the current "Find Frame" window, if any, so
 * that if somebody tries to do "Find Frame" while there's already a
 * "Find Frame" window up, we just pop up the existing one, rather than
 * creating a new one.
 */
static GtkWidget *find_frame_w;

void
find_frame_cb(GtkWidget *w _U_, gpointer d _U_)
{
  GtkWidget     *main_vb, *filter_hb, *filter_bt, *filter_te,
                *direction_hb, *forward_rb, *backward_rb,
                *bbox, *ok_bt, *cancel_bt;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif
  /* No Apply button, but "OK" not only sets our text widget, it
     activates it (i.e., it causes us to do the search). */
  static construct_args_t args = {
  	"Ethereal: Search Filter",
  	FALSE,
  	TRUE
  };

  if (find_frame_w != NULL) {
    /* There's already a "Find Frame" dialog box; reactivate it. */
    reactivate_window(find_frame_w);
    return;
  }

  find_frame_w = dlg_window_new("Ethereal: Find Frame");
  SIGNAL_CONNECT(find_frame_w, "destroy", find_frame_destroy_cb, NULL);

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(find_frame_w), accel_group);
#endif

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
  SIGNAL_CONNECT(filter_bt, "clicked", display_filter_construct_cb, &args);
  SIGNAL_CONNECT(filter_bt, "destroy", filter_button_destroy_cb, NULL);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);

  filter_te = gtk_entry_new();
  if (cfile.sfilter) gtk_entry_set_text(GTK_ENTRY(filter_te), cfile.sfilter);
  OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_te, TRUE, TRUE, 0);
  gtk_widget_show(filter_te);

  /* Misc row: Forward and reverse radio buttons */
  direction_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), direction_hb);
  gtk_widget_show(direction_hb);

#if GTK_MAJOR_VERSION < 2
  forward_rb = dlg_radio_button_new_with_label_with_mnemonic(NULL, "_Forward",
                                                             accel_group);
#else
  forward_rb = gtk_radio_button_new_with_mnemonic(NULL, "_Forward");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(forward_rb), !cfile.sbackward);
  gtk_box_pack_start(GTK_BOX(direction_hb), forward_rb, TRUE, TRUE, 0);
  gtk_widget_show(forward_rb);

#if GTK_MAJOR_VERSION < 2
  backward_rb = dlg_radio_button_new_with_label_with_mnemonic(
               gtk_radio_button_group(GTK_RADIO_BUTTON(forward_rb)),
               "_Backward", accel_group);
#else
  backward_rb = gtk_radio_button_new_with_mnemonic_from_widget(
               GTK_RADIO_BUTTON(forward_rb), "_Backward");
#endif
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(backward_rb), cfile.sbackward);
  gtk_box_pack_start(GTK_BOX(direction_hb), backward_rb, TRUE, TRUE, 0);
  gtk_widget_show(backward_rb);

  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

#if GTK_MAJOR_VERSION < 2
  ok_bt = gtk_button_new_with_label ("OK");
#else
  ok_bt = gtk_button_new_from_stock(GTK_STOCK_OK);
#endif
  SIGNAL_CONNECT(ok_bt, "clicked", find_frame_ok_cb, find_frame_w);
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

#if GTK_MAJOR_VERSION < 2
  cancel_bt = gtk_button_new_with_label ("Cancel");
#else
  cancel_bt = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
#endif
  SIGNAL_CONNECT(cancel_bt, "clicked", find_frame_close_cb, find_frame_w);
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  /* Attach pointers to needed widgets to the capture prefs window/object */
  OBJECT_SET_DATA(find_frame_w, E_FIND_FILT_KEY, filter_te);
  OBJECT_SET_DATA(find_frame_w, E_FIND_BACKWARD_KEY, backward_rb);

  /* Catch the "activate" signal on the filter text entry, so that
     if the user types Return there, we act as if the "OK" button
     had been selected, as happens if Return is typed if some widget
     that *doesn't* handle the Return key has the input focus. */
  dlg_set_activate(filter_te, ok_bt);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(find_frame_w, cancel_bt);

  /* Give the initial focus to the "Filter" entry box. */
  gtk_widget_grab_focus(filter_te);

  gtk_widget_show(find_frame_w);
}

static void
find_frame_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w)
{
  GtkWidget *filter_te, *backward_rb;
  gchar     *filter_text;
  dfilter_t *sfcode;

  filter_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_FIND_FILT_KEY);
  backward_rb = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_FIND_BACKWARD_KEY);

  filter_text = gtk_entry_get_text(GTK_ENTRY(filter_te));

  /*
   * Try to compile the filter.
   */
  if (!dfilter_compile(filter_text, &sfcode)) {
    /* The attempt failed; report an error. */
    simple_dialog(ESD_TYPE_CRIT, NULL, dfilter_error_msg);
    return;
  }

  /* Was it empty? */
  if (sfcode == NULL) {
    /* Yes - complain. */
    simple_dialog(ESD_TYPE_CRIT, NULL,
       "You didn't specify a filter to use when searching for a frame.");
    return;
  }

  /*
   * Remember the filter.
   */
  if (cfile.sfilter)
    g_free(cfile.sfilter);
  cfile.sfilter = g_strdup(filter_text);

  cfile.sbackward = GTK_TOGGLE_BUTTON (backward_rb)->active;

  if (!find_packet(&cfile, sfcode)) {
    /* We didn't find the packet. */
    simple_dialog(ESD_TYPE_CRIT, NULL, "No packet matched that filter.");
    return;
  }

  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
find_frame_close_cb(GtkWidget *close_bt _U_, gpointer parent_w)
{
  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
find_frame_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "Find Frame" dialog box. */
  find_frame_w = NULL;
}

static void
find_previous_next(GtkWidget *w, gpointer d, gboolean sens)
{
  dfilter_t *sfcode;

  if (cfile.sfilter) {
     if (!dfilter_compile(cfile.sfilter, &sfcode))
        return;
     if (sfcode == NULL)
        return;
     cfile.sbackward = sens;
     find_packet(&cfile, sfcode);
  } else
     find_frame_cb(w, d);
}

void
find_next_cb(GtkWidget *w , gpointer d)
{
  find_previous_next(w, d, FALSE);
}

void
find_previous_cb(GtkWidget *w , gpointer d)
{
  find_previous_next(w, d, TRUE);
}
