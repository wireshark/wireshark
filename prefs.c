/* prefs.c
 * Routines for handling preferences
 *
 * $Id: prefs.c,v 1.1 1998/09/25 23:24:04 gerald Exp $
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
#include <sys/types.h>
#endif

#include <gtk/gtk.h>

#include <packet.h>
#include <file.h>
#include <prefs.h>

extern capture_file  cf;

void
prefs_cb() {
  GtkWidget *prefs_w, *main_vb, *top_hb, *bbox, *prefs_nb,
            *ok_bt, *cancel_bt;
  GtkWidget *checkbutton, *label;

  prefs_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(prefs_w), "Ethereal: Preferences");
  
  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
/*  gtk_container_border_width(GTK_CONTAINER(main_vb), 5); */
  gtk_container_add(GTK_CONTAINER(prefs_w), main_vb);
  gtk_widget_show(main_vb);
  
  /* Top row: Preferences notebook */
  top_hb = gtk_hbox_new(FALSE, 1);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);
  
  prefs_nb = gtk_notebook_new();
  gtk_container_add(GTK_CONTAINER(main_vb), prefs_nb);
  gtk_widget_show(prefs_nb);
  
  checkbutton = gtk_check_button_new_with_label ("Check me please!");
  gtk_widget_show (checkbutton);

  label = gtk_label_new ("Add spot");
  gtk_container_add (GTK_CONTAINER (checkbutton), label);
  gtk_widget_show (label);
  label = gtk_label_new ("General");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), checkbutton, label);
    
  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);
  
  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect_object(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_ok_cb), GTK_OBJECT(prefs_w));
  gtk_container_add(GTK_CONTAINER(bbox), ok_bt);
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect_object(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_cancel_cb), GTK_OBJECT(prefs_w));
  gtk_container_add(GTK_CONTAINER(bbox), cancel_bt);
  gtk_widget_show(cancel_bt);
  
  gtk_widget_show(prefs_w);
}

void
prefs_main_ok_cb(GtkWidget *w, gpointer win) {

  gtk_widget_destroy(GTK_WIDGET(win));
}

void
prefs_main_cancel_cb(GtkWidget *w, gpointer win) {

  gtk_widget_destroy(GTK_WIDGET(win));
}

