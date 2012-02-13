/* edit_packet_comment_dlg.c
 * Dialog box for editing or adding packet comments.
 * Copyright 2012 Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <string.h>

#include <gtk/gtk.h>

#include "ui/simple_dialog.h"

#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/main.h"
#include "ui/gtk/menus.h"
#include "ui/gtk/new_packet_list.h"
#include "ui/gtk/edit_packet_comment_dlg.h"
#include "ui/gtk/old-gtk-compat.h"

GtkWidget *edit_or_add_pkt_comment_dlg = NULL;


static void
pkt_comment_text_buff_clear_cb(GtkWidget *w _U_, GtkWidget *view)
{
  GtkTextBuffer *buffer;

  buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));
  gtk_text_buffer_set_text (buffer, "", -1);

}

static void
pkt_comment_text_buff_save_cb(GtkWidget *w, GtkWidget *view)
{
  GtkTextBuffer *buffer;
  GtkTextIter start_iter;
  GtkTextIter end_iter;
  gchar *new_packet_comment = NULL;

  buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));
  gtk_text_buffer_get_start_iter (buffer, &start_iter);
  gtk_text_buffer_get_end_iter (buffer, &end_iter);

  new_packet_comment = gtk_text_buffer_get_text (buffer, &start_iter, &end_iter, FALSE /* whether to include invisible text */);  

  /*g_warning("The new comment is '%s'",new_packet_comment);*/

  new_packet_list_update_packet_comment(new_packet_comment);

  /*window_destroy(w);*/

}

void
edit_packet_comment_dlg (GtkAction *action _U_, gpointer data _U_)
{

  GtkWidget *vbox;
  GtkWidget *view;
  GtkWidget *bbox;
  GtkWidget *save_bt, *clear_bt, *close_bt, *help_bt;
  GtkTextBuffer *buffer = NULL;
  gchar *opt_comment;
  const gchar *buf_str;

  edit_or_add_pkt_comment_dlg = dlg_window_new ("Edit or Add Packet Comments(Not working yet)");
  gtk_widget_set_size_request (edit_or_add_pkt_comment_dlg, 400, 80);
  gtk_window_set_resizable (GTK_WINDOW (edit_or_add_pkt_comment_dlg), TRUE); 
  gtk_container_set_border_width (GTK_CONTAINER (edit_or_add_pkt_comment_dlg), 0);

  vbox = gtk_vbox_new (FALSE, 0);
  gtk_container_add (GTK_CONTAINER (edit_or_add_pkt_comment_dlg), vbox);
  gtk_widget_show (vbox);
  
  view = gtk_text_view_new ();
  buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));

  /* Get the comment */
  opt_comment = new_packet_list_get_packet_comment();
  /*g_warning("Fetched comment '%s'",opt_comment);*/

  if(opt_comment){
	  buf_str = g_strdup_printf("%s", opt_comment);
	  gtk_text_buffer_set_text (buffer, buf_str, -1);
  }
  gtk_container_add(GTK_CONTAINER(vbox), view);
  gtk_widget_show (view);

  /* Button row. */
  bbox = dlg_button_row_new (GTK_STOCK_SAVE, GTK_STOCK_CLEAR, GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
  gtk_box_pack_end (GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

  save_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_SAVE);
  g_signal_connect (save_bt, "clicked", G_CALLBACK(pkt_comment_text_buff_save_cb), view);
  gtk_widget_set_sensitive (save_bt, TRUE);

  clear_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLEAR);
  g_signal_connect(clear_bt, "clicked", G_CALLBACK(pkt_comment_text_buff_clear_cb), view);

  close_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_CLOSE);
  window_set_cancel_button (edit_or_add_pkt_comment_dlg, close_bt, window_cancel_button_cb);

  help_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_HELP);
  g_signal_connect (help_bt, "clicked",/* G_CALLBACK(topic_cb)*/NULL, /*(gpointer)HELP_MANUAL_ADDR_RESOLVE_DIALOG*/NULL);
  gtk_widget_set_sensitive (help_bt, FALSE);

  gtk_widget_grab_default (save_bt);
  g_signal_connect (edit_or_add_pkt_comment_dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);


  gtk_widget_show (edit_or_add_pkt_comment_dlg);


}
