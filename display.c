/* display.c
 * Routines for packet display windows
 *
 * $Id: display.c,v 1.7 1999/06/24 05:37:04 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>
#include <pcap.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <signal.h>
#include <errno.h>

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif

#include "timestamp.h"
#include "packet.h"
#include "file.h"
#include "display.h"

extern capture_file  cf;
extern GtkWidget *packet_list;

/* Display callback data keys */
#define E_DISPLAY_TIME_ABS_KEY   "display_time_abs"
#define E_DISPLAY_TIME_REL_KEY   "display_time_rel"
#define E_DISPLAY_TIME_DELTA_KEY "display_time_delta"

static void display_opt_ok_cb(GtkWidget *, gpointer);
static void display_opt_apply_cb(GtkWidget *, gpointer);
static void display_opt_close_cb(GtkWidget *, gpointer);

/*
 * Keep track of whether the "Display Options" window is active, so that,
 * if it is, selecting "Display/Options" doesn't pop up another such
 * window.
 */
static int display_opt_window_active;
static ts_type prev_timestamp_type;

void
display_opt_cb(GtkWidget *w, gpointer d) {
  GtkWidget     *display_opt_w, *button, *main_vb, *bbox, *ok_bt, *apply_bt, *cancel_bt;

  /* If there's already a "Display Options" window active, don't pop
     up another one.

     XXX - this should arguably give the input focus to the active
     "Display Options" window, if possible. */
  if (display_opt_window_active)
    return;

  /* Save the current timestamp type, so that "Cancel" can put it back
     if we've changed it with "Apply". */
  prev_timestamp_type = timestamp_type;

  display_opt_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(display_opt_w), "Ethereal: Display Options");
  
  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(display_opt_w), main_vb);
  gtk_widget_show(main_vb);
  
  button = gtk_radio_button_new_with_label(NULL, "Time of day");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
               (timestamp_type == ABSOLUTE));
  gtk_object_set_data(GTK_OBJECT(display_opt_w), E_DISPLAY_TIME_ABS_KEY,
               button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  button = gtk_radio_button_new_with_label(
               gtk_radio_button_group(GTK_RADIO_BUTTON(button)),
               "Seconds since beginning of capture");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
               (timestamp_type == RELATIVE));
  gtk_object_set_data(GTK_OBJECT(display_opt_w), E_DISPLAY_TIME_REL_KEY,
               button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  button = gtk_radio_button_new_with_label(
               gtk_radio_button_group(GTK_RADIO_BUTTON(button)),
               "Seconds since previous frame");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
               (timestamp_type == DELTA));
  gtk_object_set_data(GTK_OBJECT(display_opt_w), E_DISPLAY_TIME_DELTA_KEY,
		button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
  
  /* Button row: OK, Apply, and Cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(display_opt_ok_cb), GTK_OBJECT(display_opt_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  apply_bt = gtk_button_new_with_label ("Apply");
  gtk_signal_connect(GTK_OBJECT(apply_bt), "clicked",
    GTK_SIGNAL_FUNC(display_opt_apply_cb), GTK_OBJECT(display_opt_w));
  GTK_WIDGET_SET_FLAGS(apply_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), apply_bt, TRUE, TRUE, 0);
  gtk_widget_show(apply_bt);

  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(display_opt_close_cb), GTK_OBJECT(display_opt_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  display_opt_window_active = TRUE;
  gtk_widget_show(display_opt_w);
}

static void
display_opt_ok_cb(GtkWidget *ok_bt, gpointer parent_w) {
  GtkWidget *button;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
                                              E_DISPLAY_TIME_ABS_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    timestamp_type = ABSOLUTE;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
                                              E_DISPLAY_TIME_REL_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    timestamp_type = RELATIVE;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
                                              E_DISPLAY_TIME_DELTA_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    timestamp_type = DELTA;

  gtk_widget_destroy(GTK_WIDGET(parent_w));
  display_opt_window_active = FALSE;

  change_time_formats(&cf);
}

static void
display_opt_apply_cb(GtkWidget *ok_bt, gpointer parent_w) {
  GtkWidget *button;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
                                              E_DISPLAY_TIME_ABS_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    timestamp_type = ABSOLUTE;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
                                              E_DISPLAY_TIME_REL_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    timestamp_type = RELATIVE;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
                                              E_DISPLAY_TIME_DELTA_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    timestamp_type = DELTA;

  change_time_formats(&cf);
}

static void
display_opt_close_cb(GtkWidget *close_bt, gpointer parent_w) {

  if (timestamp_type != prev_timestamp_type) {
    timestamp_type = prev_timestamp_type;
    change_time_formats(&cf);
  }

  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
  display_opt_window_active = FALSE;
}
