/* prefs.c
 * Routines for handling preferences
 *
 * $Id: prefs.c,v 1.5 1998/10/12 01:40:55 gerald Exp $
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

#include "ethereal.h"
#include "packet.h"
#include "file.h"
#include "print.h"
#include "filter.h"
#include "prefs.h"

extern capture_file  cf;

void
prefs_cb(GtkWidget *w, gpointer sp) {
  GtkWidget *prefs_w, *main_vb, *top_hb, *bbox, *prefs_nb,
            *ok_bt, *save_bt, *cancel_bt;
  GtkWidget *print_pg, *filter_pg;
  GtkWidget *nlabel, *label;
  gint       start_page = (gint) sp;

  prefs_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(prefs_w), "Ethereal: Preferences");
  
  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(prefs_w), main_vb);
  gtk_widget_show(main_vb);
  
  /* Top row: Preferences notebook */
  top_hb = gtk_hbox_new(FALSE, 1);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);
  
  prefs_nb = gtk_notebook_new();
  gtk_container_add(GTK_CONTAINER(main_vb), prefs_nb);
  gtk_widget_show(prefs_nb);
  
  /* General prefs */
/*   nlabel = gtk_label_new("Nothing here yet...");
  gtk_widget_show (nlabel);

  label = gtk_label_new ("General");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), nlabel, label);
 */  
  /* Printing prefs */
  print_pg = printer_prefs_show();
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_PRINT_PAGE_KEY, print_pg);
  label = gtk_label_new ("Printing");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), print_pg, label);
    
  /* Filter prefs */
  filter_pg = filter_prefs_show();
  /* Pass along the entry widget pointer from the calling widget */
  gtk_object_set_data(GTK_OBJECT(filter_pg), E_FILT_TE_PTR_KEY,
    gtk_object_get_data(GTK_OBJECT(w), E_FILT_TE_PTR_KEY));
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_FILTER_PAGE_KEY, filter_pg);
  label = gtk_label_new ("Filters");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), filter_pg, label);

  /* Jump to the specified page, if it was supplied */
  if (start_page > E_PR_PG_NONE)
    gtk_notebook_set_page(GTK_NOTEBOOK(prefs_nb), start_page);
    
  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);
  
  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect_object(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_ok_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  save_bt = gtk_button_new_with_label ("Save");
  gtk_signal_connect_object(GTK_OBJECT(save_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_save_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(save_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), save_bt, TRUE, TRUE, 0);
  gtk_widget_show(save_bt);
  
  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect_object(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_cancel_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  gtk_widget_show(prefs_w);
}

void
prefs_main_ok_cb(GtkWidget *w, gpointer win) {
  
  printer_prefs_ok(gtk_object_get_data(GTK_OBJECT(win), E_PRINT_PAGE_KEY));
  filter_prefs_ok(gtk_object_get_data(GTK_OBJECT(win), E_FILTER_PAGE_KEY));
  gtk_widget_destroy(GTK_WIDGET(win));
}

void
prefs_main_save_cb(GtkWidget *w, gpointer win) {
  filter_prefs_save(gtk_object_get_data(GTK_OBJECT(win), E_FILTER_PAGE_KEY));
}

void
prefs_main_cancel_cb(GtkWidget *w, gpointer win) {

  printer_prefs_cancel(gtk_object_get_data(GTK_OBJECT(win), E_PRINT_PAGE_KEY));
  filter_prefs_cancel(gtk_object_get_data(GTK_OBJECT(win), E_FILTER_PAGE_KEY));
  gtk_widget_destroy(GTK_WIDGET(win));
}

