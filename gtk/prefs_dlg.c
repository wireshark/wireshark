/* prefs_dlg.c
 * Routines for handling preferences
 *
 * $Id: prefs_dlg.c,v 1.4 1999/12/10 06:28:24 guy Exp $
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

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/stat.h>

#include "main.h"
#include "packet.h"
#include "file.h"
#include "prefs.h"
#include "column.h"
#include "print.h"
#include "prefs_dlg.h"
#include "print_prefs.h"
#include "stream_prefs.h"
#include "util.h"

e_prefs prefs;

static void     prefs_main_ok_cb(GtkWidget *, gpointer);
static void     prefs_main_save_cb(GtkWidget *, gpointer);
static void     prefs_main_cancel_cb(GtkWidget *, gpointer);
static gboolean prefs_main_delete_cb(GtkWidget *, gpointer);


#define E_PRINT_PAGE_KEY  "printer_options_page"
#define E_COLUMN_PAGE_KEY "column_options_page"
#define E_STREAM_PAGE_KEY "tcp_stream_options_page"

void
prefs_cb(GtkWidget *w, gpointer sp) {
  GtkWidget *prefs_w, *main_vb, *top_hb, *bbox, *prefs_nb,
            *ok_bt, *save_bt, *cancel_bt;
  GtkWidget *print_pg, *column_pg, *stream_pg, *label;

/*  GtkWidget *nlabel; */
  gint       start_page = (gint) sp;


  prefs_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(prefs_w), "Ethereal: Preferences");
  gtk_signal_connect(GTK_OBJECT(prefs_w), "delete-event",
    GTK_SIGNAL_FUNC(prefs_main_delete_cb), NULL);
  
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
  
  /* Printing prefs */
  print_pg = printer_prefs_show();
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_PRINT_PAGE_KEY, print_pg);
  label = gtk_label_new ("Printing");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), print_pg, label);
    
  /* Column prefs */
  column_pg = column_prefs_show();
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_COLUMN_PAGE_KEY, column_pg);
  label = gtk_label_new ("Columns");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), column_pg, label);
  
  /* Column prefs */
  stream_pg = stream_prefs_show();
  gtk_object_set_data(GTK_OBJECT(prefs_w), E_STREAM_PAGE_KEY, stream_pg);
  label = gtk_label_new ("TCP Streams");
  gtk_notebook_append_page (GTK_NOTEBOOK(prefs_nb), stream_pg, label);

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
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_ok_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  save_bt = gtk_button_new_with_label ("Save");
  gtk_signal_connect(GTK_OBJECT(save_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_save_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(save_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), save_bt, TRUE, TRUE, 0);
  gtk_widget_show(save_bt);
  
  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_main_cancel_cb), GTK_OBJECT(prefs_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  gtk_widget_show(prefs_w);
}

static void
prefs_main_ok_cb(GtkWidget *ok_bt, gpointer parent_w)
{
  printer_prefs_ok(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_ok(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_ok(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
prefs_main_save_cb(GtkWidget *save_bt, gpointer parent_w)
{
  printer_prefs_save(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_save(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_save(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  write_prefs();
}

static void
prefs_main_cancel_cb(GtkWidget *cancel_bt, gpointer parent_w)
{
  printer_prefs_cancel(gtk_object_get_data(GTK_OBJECT(parent_w), E_PRINT_PAGE_KEY));
  column_prefs_cancel(gtk_object_get_data(GTK_OBJECT(parent_w), E_COLUMN_PAGE_KEY));
  stream_prefs_cancel(gtk_object_get_data(GTK_OBJECT(parent_w), E_STREAM_PAGE_KEY));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static gboolean
prefs_main_delete_cb(GtkWidget *prefs_w, gpointer dummy)
{
  printer_prefs_delete(gtk_object_get_data(GTK_OBJECT(prefs_w), E_PRINT_PAGE_KEY));
  column_prefs_delete(gtk_object_get_data(GTK_OBJECT(prefs_w), E_COLUMN_PAGE_KEY));
  stream_prefs_delete(gtk_object_get_data(GTK_OBJECT(prefs_w), E_STREAM_PAGE_KEY));
  return FALSE;
}
