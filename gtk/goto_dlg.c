/* goto_dlg.c
 * Routines for "go to frame" window
 *
 * $Id: goto_dlg.c,v 1.9 2000/07/20 05:09:59 guy Exp $
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef __G_LIB_H__
#include <glib.h>
#endif

#include "proto.h"
#include "dfilter.h"
#include "globals.h"

#include "goto_dlg.h"
#include "prefs_dlg.h"
#include "simple_dialog.h"
#include "dlg_utils.h"

/* Capture callback data keys */
#define E_GOTO_FNUMBER_KEY     "goto_fnumber_te"

static void
goto_frame_ok_cb(GtkWidget *ok_bt, gpointer parent_w);

static void
goto_frame_close_cb(GtkWidget *close_bt, gpointer parent_w);

void
goto_frame_cb(GtkWidget *w, gpointer d)
{
  GtkWidget     *goto_frame_w, *main_vb, *fnumber_hb, *fnumber_lb, *fnumber_te,
                *bbox, *ok_bt, *cancel_bt;

  goto_frame_w = dlg_window_new();
  gtk_window_set_title(GTK_WINDOW(goto_frame_w), "Ethereal: Go To Frame");
  
  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(goto_frame_w), main_vb);
  gtk_widget_show(main_vb);
  
  /* Frame number row */
  fnumber_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), fnumber_hb);
  gtk_widget_show(fnumber_hb);
  
  fnumber_lb = gtk_label_new("Frame number:");
  gtk_box_pack_start(GTK_BOX(fnumber_hb), fnumber_lb, FALSE, FALSE, 0);
  gtk_widget_show(fnumber_lb);
  
  fnumber_te = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(fnumber_hb), fnumber_te, FALSE, FALSE, 0);
  gtk_widget_show(fnumber_te);

  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(goto_frame_ok_cb), GTK_OBJECT(goto_frame_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(goto_frame_close_cb), GTK_OBJECT(goto_frame_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  /* Attach pointers to needed widgets to the capture prefs window/object */
  gtk_object_set_data(GTK_OBJECT(goto_frame_w), E_GOTO_FNUMBER_KEY, fnumber_te);

  /* Catch the "activate" signal on the frame number text entry, so that
     if the user types Return there, we act as if the "OK" button
     had been selected, as happens if Return is typed if some widget
     that *doesn't* handle the Return key has the input focus. */
  dlg_set_activate(fnumber_te, ok_bt);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(goto_frame_w, cancel_bt);

  /* Give the initial focus to the "Frame number" entry box. */
  gtk_widget_grab_focus(fnumber_te);

  gtk_widget_show(goto_frame_w);
}

static void
goto_frame_ok_cb(GtkWidget *ok_bt, gpointer parent_w)
{
  GtkWidget *fnumber_te;
  gchar *fnumber_text;
  guint fnumber;
  char *p;

  fnumber_te = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_GOTO_FNUMBER_KEY);

  fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
  fnumber = strtoul(fnumber_text, &p, 10);
  if (p == fnumber_text || *p != '\0') {
    /* Illegal number.
       XXX - what about negative numbers (which "strtoul()" allows)?
       Can we hack up signal handlers for the widget to make it
       reject attempts to type in characters other than digits? */
    simple_dialog(ESD_TYPE_CRIT, NULL,
		"The frame number you entered isn't a valid number.");
    return;
  }

  switch (goto_frame(&cfile, fnumber)) {

  case NO_SUCH_FRAME:
    simple_dialog(ESD_TYPE_CRIT, NULL, "There is no frame with that frame number.");
    return;

  case FRAME_NOT_DISPLAYED:
    /* XXX - add it to the display filter? */
    simple_dialog(ESD_TYPE_CRIT, NULL, "The frame with that frame number is not currently being displayed.");
    return;

  case FOUND_FRAME:
    gtk_widget_destroy(GTK_WIDGET(parent_w));
    break;
  }
}

static void
goto_frame_close_cb(GtkWidget *close_bt, gpointer parent_w)
{
  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}
