/* display_opts.c
 * Routines for packet display windows
 *
 * $Id: display_opts.c,v 1.24 2002/01/13 20:35:11 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <time.h>

#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "globals.h"
#include "resolv.h"
#include "timestamp.h"
#include "packet.h"
#include "file.h"
#include "display_opts.h"
#include "ui_util.h"
#include "dlg_utils.h"

extern capture_file  cfile;

/* Display callback data keys */
#define E_DISPLAY_TIME_ABS_KEY          "display_time_abs"
#define E_DISPLAY_DATE_TIME_ABS_KEY     "display_date_time_abs"
#define E_DISPLAY_TIME_REL_KEY          "display_time_rel"
#define E_DISPLAY_TIME_DELTA_KEY        "display_time_delta"
#ifdef HAVE_LIBPCAP
#define E_DISPLAY_AUTO_SCROLL_KEY       "display_auto_scroll"
#endif
#define E_DISPLAY_M_NAME_RESOLUTION_KEY "display_mac_name_resolution"
#define E_DISPLAY_N_NAME_RESOLUTION_KEY "display_network_name_resolution"
#define E_DISPLAY_T_NAME_RESOLUTION_KEY "display_transport_name_resolution"

static void display_opt_ok_cb(GtkWidget *, gpointer);
static void display_opt_apply_cb(GtkWidget *, gpointer);
static void get_display_options(GtkWidget *);
static void update_display(void);
static void display_opt_close_cb(GtkWidget *, gpointer);
static void display_opt_destroy_cb(GtkWidget *, gpointer);

/*
 * Keep a static pointer to the current "Display Options" window, if any,
 * so that if somebody tries to do "Display:Options" while there's already
 * a "Display Options" window up, we just pop up the existing one, rather
 * than creating a new one.
 */
static GtkWidget *display_opt_w;

static ts_type initial_timestamp_type;
static ts_type current_timestamp_type;

void
display_opt_cb(GtkWidget *w, gpointer d) {
  GtkWidget     *button, *main_vb, *bbox, *ok_bt, *apply_bt, *cancel_bt;
  GtkAccelGroup *accel_group;

  if (display_opt_w != NULL) {
    /* There's already a "Display Options" dialog box; reactivate it. */
    reactivate_window(display_opt_w);
    return;
  }

  /* Save the timestamp type value as of when the dialog box was first popped
     up, so that "Cancel" can put it back if we've changed it with "Apply". */
  initial_timestamp_type = timestamp_type;

  /* Save the current timestamp type so that we know whether it has changed;
     we don't want to redisplay the time fields unless we've changed the way 
     they should be displayed (as redisplaying the time fields could be 
     expensive - we have to scan through all the packets and rebuild the 
     packet list).*/
  current_timestamp_type = timestamp_type;

  display_opt_w = dlg_window_new("Ethereal: Display Options");
  gtk_signal_connect(GTK_OBJECT(display_opt_w), "destroy",
	GTK_SIGNAL_FUNC(display_opt_destroy_cb), NULL);

  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(display_opt_w), accel_group);

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(display_opt_w), main_vb);
  gtk_widget_show(main_vb);
  
  button = dlg_radio_button_new_with_label_with_mnemonic(NULL, "_Time of day",
							accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
               (timestamp_type == ABSOLUTE));
  gtk_object_set_data(GTK_OBJECT(display_opt_w), E_DISPLAY_TIME_ABS_KEY,
               button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  
  gtk_widget_show(button);

  button = dlg_radio_button_new_with_label_with_mnemonic(
               gtk_radio_button_group(GTK_RADIO_BUTTON(button)),
               "_Date and time of day", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
               (timestamp_type == ABSOLUTE_WITH_DATE));
  gtk_object_set_data(GTK_OBJECT(display_opt_w), E_DISPLAY_DATE_TIME_ABS_KEY,
               button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  button = dlg_radio_button_new_with_label_with_mnemonic(
               gtk_radio_button_group(GTK_RADIO_BUTTON(button)),
               "Seconds since _beginning of capture", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
               (timestamp_type == RELATIVE));
  gtk_object_set_data(GTK_OBJECT(display_opt_w), E_DISPLAY_TIME_REL_KEY,
               button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  button = dlg_radio_button_new_with_label_with_mnemonic(
               gtk_radio_button_group(GTK_RADIO_BUTTON(button)),
               "Seconds since _previous frame", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
               (timestamp_type == DELTA));
  gtk_object_set_data(GTK_OBJECT(display_opt_w), E_DISPLAY_TIME_DELTA_KEY,
		button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

#ifdef HAVE_LIBPCAP
  button = dlg_check_button_new_with_label_with_mnemonic(
		"_Automatic scrolling in live capture", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), auto_scroll_live);
  gtk_object_set_data(GTK_OBJECT(display_opt_w), E_DISPLAY_AUTO_SCROLL_KEY,
		      button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
#endif

  button = dlg_check_button_new_with_label_with_mnemonic(
  		"Enable _MAC name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
		g_resolv_flags & RESOLV_MAC);
  gtk_object_set_data(GTK_OBJECT(display_opt_w), E_DISPLAY_M_NAME_RESOLUTION_KEY,
		      button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
    
  button = dlg_check_button_new_with_label_with_mnemonic(
  		"Enable _network name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
		g_resolv_flags & RESOLV_NETWORK);
  gtk_object_set_data(GTK_OBJECT(display_opt_w), E_DISPLAY_N_NAME_RESOLUTION_KEY,
		      button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
    
  button = dlg_check_button_new_with_label_with_mnemonic(
  		"Enable _transport name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
		g_resolv_flags & RESOLV_TRANSPORT);
  gtk_object_set_data(GTK_OBJECT(display_opt_w), E_DISPLAY_T_NAME_RESOLUTION_KEY,
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

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(display_opt_w, cancel_bt);

  gtk_widget_show(display_opt_w);
}

static void
display_opt_ok_cb(GtkWidget *ok_bt, gpointer parent_w) {
  get_display_options(GTK_WIDGET(parent_w));

  gtk_widget_destroy(GTK_WIDGET(parent_w));

  update_display();
}

static void
display_opt_apply_cb(GtkWidget *ok_bt, gpointer parent_w) {
  get_display_options(GTK_WIDGET(parent_w));

  update_display();
}

static void
get_display_options(GtkWidget *parent_w)
{
  GtkWidget *button;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
                                              E_DISPLAY_TIME_ABS_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    timestamp_type = ABSOLUTE;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
                                              E_DISPLAY_DATE_TIME_ABS_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    timestamp_type = ABSOLUTE_WITH_DATE;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
                                              E_DISPLAY_TIME_REL_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    timestamp_type = RELATIVE;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
                                              E_DISPLAY_TIME_DELTA_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    timestamp_type = DELTA;

#ifdef HAVE_LIBPCAP
  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
					     E_DISPLAY_AUTO_SCROLL_KEY);
  auto_scroll_live = (GTK_TOGGLE_BUTTON (button)->active);
#endif

  g_resolv_flags = RESOLV_NONE;
  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
					     E_DISPLAY_M_NAME_RESOLUTION_KEY);
  g_resolv_flags |= (GTK_TOGGLE_BUTTON (button)->active ? RESOLV_MAC : RESOLV_NONE);
  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
					     E_DISPLAY_N_NAME_RESOLUTION_KEY);
  g_resolv_flags |= (GTK_TOGGLE_BUTTON (button)->active ? RESOLV_NETWORK : RESOLV_NONE);
  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w),
					     E_DISPLAY_T_NAME_RESOLUTION_KEY);
  g_resolv_flags |= (GTK_TOGGLE_BUTTON (button)->active ? RESOLV_TRANSPORT : RESOLV_NONE);

}

static void
update_display(void)
{
  if (timestamp_type != current_timestamp_type) {
      /* Time stamp format changed; update the display.

         XXX - redissecting the packets could actually be faster;
	 we have to find the row number for each frame, in order to
	 update the time stamp columns, and doing that is linear in
	 the row number, which means the whole process is N^2 in
	 the number of rows, whilst redissecting the packets is only
	 linear in the number of rows (assuming you're using our
	 CList code, or the GTK+ 1.2.8 CList code, or other CList
	 code which doesn't have to scan the entire list to find the
	 last element), even though the latter involves doing more work
	 per packet. */
    current_timestamp_type = timestamp_type;
    change_time_formats(&cfile);
  }
}

static void
display_opt_close_cb(GtkWidget *close_bt, gpointer parent_w)
{
  /* Revert the timestamp type to the value it has when we started. */
  timestamp_type = initial_timestamp_type;

  /* Update the display if either of those changed. */
  update_display();

  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
display_opt_destroy_cb(GtkWidget *win, gpointer user_data)
{
  /* Note that we no longer have a "Display Options" dialog box. */
  display_opt_w = NULL;
}
