/* display_opts.c
 * Routines for packet display windows
 *
 * $Id: display_opts.c,v 1.35 2004/01/19 03:46:42 ulfl Exp $
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

#include "globals.h"
#include <epan/resolv.h>
#include <epan/timestamp.h>
#include <epan/packet.h>
#include "file.h"
#include "display_opts.h"
#include "ui_util.h"
#include "dlg_utils.h"
#include "compat_macros.h"

extern capture_file  cfile;

/* Display callback data keys */
#ifdef HAVE_LIBPCAP
#define E_DISPLAY_AUTO_SCROLL_KEY       "display_auto_scroll"
#endif
#define E_DISPLAY_M_NAME_RESOLUTION_KEY "display_mac_name_resolution"
#define E_DISPLAY_N_NAME_RESOLUTION_KEY "display_network_name_resolution"
#define E_DISPLAY_T_NAME_RESOLUTION_KEY "display_transport_name_resolution"

static void display_opt_ok_cb(GtkWidget *, gpointer);
static void display_opt_apply_cb(GtkWidget *, gpointer);
static void get_display_options(GtkWidget *);
static void display_opt_close_cb(GtkWidget *, gpointer);
static void display_opt_destroy_cb(GtkWidget *, gpointer);

/*
 * Keep a static pointer to the current "View Options" window, if any,
 * so that if somebody tries to do "Display:Options" while there's already
 * a "View Options" window up, we just pop up the existing one, rather
 * than creating a new one.
 */
static GtkWidget *display_opt_w;

void
display_opt_cb(GtkWidget *w _U_, gpointer d _U_) {
  GtkWidget     *button, *main_vb, *bbox, *ok_bt, *apply_bt, *cancel_bt;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif

  if (display_opt_w != NULL) {
    /* There's already a "View Options" dialog box; reactivate it. */
    reactivate_window(display_opt_w);
    return;
  }

  display_opt_w = dlg_window_new("Ethereal: View Options");
  SIGNAL_CONNECT(display_opt_w, "destroy", display_opt_destroy_cb, NULL);

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(display_opt_w), accel_group);
#endif

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(display_opt_w), main_vb);
  gtk_widget_show(main_vb);

#ifdef HAVE_LIBPCAP
  button = CHECK_BUTTON_NEW_WITH_MNEMONIC(
		"_Automatic scrolling in live capture", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), auto_scroll_live);
  OBJECT_SET_DATA(display_opt_w, E_DISPLAY_AUTO_SCROLL_KEY, button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);
#endif

  button = CHECK_BUTTON_NEW_WITH_MNEMONIC(
  		"Enable _MAC name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
		g_resolv_flags & RESOLV_MAC);
  OBJECT_SET_DATA(display_opt_w, E_DISPLAY_M_NAME_RESOLUTION_KEY, button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  button = CHECK_BUTTON_NEW_WITH_MNEMONIC(
  		"Enable _network name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
		g_resolv_flags & RESOLV_NETWORK);
  OBJECT_SET_DATA(display_opt_w, E_DISPLAY_N_NAME_RESOLUTION_KEY, button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  button = CHECK_BUTTON_NEW_WITH_MNEMONIC(
  		"Enable _transport name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button),
		g_resolv_flags & RESOLV_TRANSPORT);
  OBJECT_SET_DATA(display_opt_w, E_DISPLAY_T_NAME_RESOLUTION_KEY, button);
  gtk_box_pack_start(GTK_BOX(main_vb), button, TRUE, TRUE, 0);
  gtk_widget_show(button);

  /* Button row: OK, Apply, and Cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_OK);
  SIGNAL_CONNECT(ok_bt, "clicked", display_opt_ok_cb, display_opt_w);
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  apply_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_APPLY);
  SIGNAL_CONNECT(apply_bt, "clicked", display_opt_apply_cb, display_opt_w);
  GTK_WIDGET_SET_FLAGS(apply_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), apply_bt, TRUE, TRUE, 0);
  gtk_widget_show(apply_bt);

  cancel_bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CANCEL);
  SIGNAL_CONNECT(cancel_bt, "clicked", display_opt_close_cb, display_opt_w);
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
display_opt_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w) {
  get_display_options(GTK_WIDGET(parent_w));

  gtk_widget_destroy(GTK_WIDGET(parent_w));

}

static void
display_opt_apply_cb(GtkWidget *ok_bt _U_, gpointer parent_w) {
  get_display_options(GTK_WIDGET(parent_w));

}

static void
get_display_options(GtkWidget *parent_w)
{
  GtkWidget *button;

#ifdef HAVE_LIBPCAP
  button = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_DISPLAY_AUTO_SCROLL_KEY);
  auto_scroll_live = (GTK_TOGGLE_BUTTON (button)->active);
#endif

  g_resolv_flags = RESOLV_NONE;
  button = (GtkWidget *)OBJECT_GET_DATA(parent_w,
                                        E_DISPLAY_M_NAME_RESOLUTION_KEY);
  g_resolv_flags |= (GTK_TOGGLE_BUTTON (button)->active ? RESOLV_MAC :
                                                          RESOLV_NONE);
  button = (GtkWidget *)OBJECT_GET_DATA(parent_w,
                                        E_DISPLAY_N_NAME_RESOLUTION_KEY);
  g_resolv_flags |= (GTK_TOGGLE_BUTTON (button)->active ? RESOLV_NETWORK :
                                                          RESOLV_NONE);
  button = (GtkWidget *)OBJECT_GET_DATA(parent_w,
                                        E_DISPLAY_T_NAME_RESOLUTION_KEY);
  g_resolv_flags |= (GTK_TOGGLE_BUTTON (button)->active ? RESOLV_TRANSPORT :
                                                          RESOLV_NONE);

}

static void
display_opt_close_cb(GtkWidget *close_bt _U_, gpointer parent_w)
{
  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
display_opt_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "View Options" dialog box. */
  display_opt_w = NULL;
}
