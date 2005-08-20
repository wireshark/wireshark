/* goto_dlg.c
 * Routines for "go to packet" window
 *
 * $Id$
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
#include "globals.h"

#include "goto_dlg.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "compat_macros.h"
#include "gui_utils.h"
#include "help_dlg.h"

/* Capture callback data keys */
#define E_GOTO_FNUMBER_KEY     "goto_fnumber_te"

static void
goto_frame_ok_cb(GtkWidget *ok_bt, gpointer parent_w);

void
goto_frame_cb(GtkWidget *w _U_, gpointer d _U_)
{
  GtkWidget     *goto_frame_w, *main_vb, *fnumber_hb, *fnumber_lb, *fnumber_te,
                *bbox, *ok_bt, *cancel_bt, *help_bt;

  goto_frame_w = dlg_window_new("Ethereal: Go To Packet");

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(goto_frame_w), main_vb);
  gtk_widget_show(main_vb);

  /* Frame number row */
  fnumber_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), fnumber_hb);
  gtk_widget_show(fnumber_hb);

  fnumber_lb = gtk_label_new("Packet number:");
  gtk_box_pack_start(GTK_BOX(fnumber_hb), fnumber_lb, FALSE, FALSE, 0);
  gtk_widget_show(fnumber_lb);

  fnumber_te = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(fnumber_hb), fnumber_te, FALSE, FALSE, 0);
  gtk_widget_show(fnumber_te);

  /* Button row: OK and cancel buttons */
  if(topic_available(HELP_GOTO_DIALOG)) {
    bbox = dlg_button_row_new(GTK_STOCK_JUMP_TO, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  } else {
    bbox = dlg_button_row_new(GTK_STOCK_JUMP_TO, GTK_STOCK_CANCEL, NULL);
  }
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_JUMP_TO);
  SIGNAL_CONNECT(ok_bt, "clicked", goto_frame_ok_cb, goto_frame_w);

  cancel_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
  window_set_cancel_button(goto_frame_w, cancel_bt, window_cancel_button_cb);

  if(topic_available(HELP_GOTO_DIALOG)) {
      help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
      SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_GOTO_DIALOG);
  }

  gtk_widget_grab_default(ok_bt);

  /* Catch the "activate" signal on the frame number text entry, so that
     if the user types Return there, we act as if the "OK" button
     had been selected, as happens if Return is typed if some widget
     that *doesn't* handle the Return key has the input focus. */
  dlg_set_activate(fnumber_te, ok_bt);

  /* Give the initial focus to the "Packet number" entry box. */
  gtk_widget_grab_focus(fnumber_te);

  /* Attach pointers to needed widgets to the capture prefs window/object */
  OBJECT_SET_DATA(goto_frame_w, E_GOTO_FNUMBER_KEY, fnumber_te);

  SIGNAL_CONNECT(goto_frame_w, "delete_event", window_delete_event_cb, NULL);

  gtk_widget_show(goto_frame_w);
  window_present(goto_frame_w);
}

static void
goto_frame_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w)
{
  GtkWidget   *fnumber_te;
  const gchar *fnumber_text;
  guint        fnumber;
  char        *p;

  fnumber_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, E_GOTO_FNUMBER_KEY);

  fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
  fnumber = strtoul(fnumber_text, &p, 10);
  if (p == fnumber_text || *p != '\0') {
    /* Illegal number.
       XXX - what about negative numbers (which "strtoul()" allows)?
       Can we hack up signal handlers for the widget to make it
       reject attempts to type in characters other than digits? */
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"The packet number you entered isn't a valid number.");
    return;
  }

  if (cf_goto_frame(&cfile, fnumber)) {
    /* We succeeded in going to that frame; we're done. */
    window_destroy(GTK_WIDGET(parent_w));
  }
}

/*
 * Go to frame specified by currently selected protocol tree item.
 */
void
goto_framenum_cb(GtkWidget *w _U_, gpointer data _U_)
{
    cf_goto_framenum(&cfile);
}

void
goto_top_frame_cb(GtkWidget *w _U_, gpointer d _U_)
{
    cf_goto_top_frame(&cfile);
}

void
goto_bottom_frame_cb(GtkWidget *w _U_, gpointer d _U_)
{
    cf_goto_bottom_frame(&cfile);
}


