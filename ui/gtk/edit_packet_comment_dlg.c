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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <gtk/gtk.h>

#include <epan/epan.h>
#include <epan/filesystem.h>

#include "../cfile.h"
#include "../file.h"

#include "ui/main_statusbar.h"
#include "ui/simple_dialog.h"

#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/expert_comp_dlg.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/main.h"
#include "ui/gtk/packet_list.h"
#include "ui/gtk/edit_packet_comment_dlg.h"
#include "ui/gtk/old-gtk-compat.h"

static GtkWidget *edit_or_add_pkt_comment_dlg = NULL;
static GtkWidget *edit_or_add_capture_comment_dlg = NULL;

static void
pkt_comment_text_buff_ok_cb(GtkWidget *w _U_, GtkWidget *view)
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

  packet_list_update_packet_comment(new_packet_comment);
  expert_comp_packet_comment_updated();

  window_destroy(edit_or_add_pkt_comment_dlg);

}


static void
capture_comment_text_buff_ok_cb(GtkWidget *w _U_, GtkWidget *view)
{
  GtkTextBuffer *buffer;
  GtkTextIter start_iter;
  GtkTextIter end_iter;
  gchar *new_capture_comment = NULL;

  buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));
  gtk_text_buffer_get_start_iter (buffer, &start_iter);
  gtk_text_buffer_get_end_iter (buffer, &end_iter);

  new_capture_comment = gtk_text_buffer_get_text (buffer, &start_iter, &end_iter, FALSE /* whether to include invisible text */);

  /*g_warning("The new comment is '%s'",new_capture_comment);*/
  cf_update_capture_comment(&cfile, new_capture_comment);

  /* Update the main window as appropriate */
  main_update_for_unsaved_changes(&cfile);

  status_capture_comment_update();

  window_destroy(edit_or_add_capture_comment_dlg);

}

void
edit_packet_comment_dlg (GtkAction *action _U_, gpointer data _U_)
{

  GtkWidget *vbox;
  GtkWidget *view;
  GtkWidget *scroll;
  GtkWidget *bbox;
  GtkWidget *ok_bt, *cancel_bt, *help_bt;
  GtkTextBuffer *buffer = NULL;
  gchar *opt_comment;
  gchar *buf_str;

  edit_or_add_pkt_comment_dlg = dlg_window_new ("Edit or Add Packet Comments");
  gtk_widget_set_size_request (edit_or_add_pkt_comment_dlg, 500, 160);
  gtk_window_set_resizable (GTK_WINDOW (edit_or_add_pkt_comment_dlg), TRUE);
  gtk_container_set_border_width (GTK_CONTAINER (edit_or_add_pkt_comment_dlg), DLG_OUTER_MARGIN);

  vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, DLG_UNRELATED_SPACING, FALSE);
  gtk_container_add (GTK_CONTAINER (edit_or_add_pkt_comment_dlg), vbox);
  gtk_widget_show (vbox);

  view = gtk_text_view_new ();
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD);
  buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));
  gtk_widget_show (view);

  scroll = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                  GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
  gtk_container_add(GTK_CONTAINER(scroll), view);
  gtk_widget_show(scroll);
  gtk_box_pack_start(GTK_BOX (vbox), scroll, TRUE, TRUE, 0);

  /* Get the comment */
  opt_comment = packet_list_get_packet_comment();
  /*g_warning("Fetched comment '%s'",opt_comment);*/

  if(opt_comment){
    buf_str = g_strdup_printf("%s", opt_comment);
    gtk_text_buffer_set_text (buffer, buf_str, -1);
    g_free(buf_str);
  }

  /* Button row. */
  bbox = dlg_button_row_new (GTK_STOCK_OK, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  gtk_box_pack_end (GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

  ok_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_OK);
  g_signal_connect (ok_bt, "clicked", G_CALLBACK(pkt_comment_text_buff_ok_cb), view);
  gtk_widget_set_sensitive (ok_bt, TRUE);

  cancel_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_CANCEL);
  window_set_cancel_button (edit_or_add_pkt_comment_dlg, cancel_bt, window_cancel_button_cb);

  help_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_HELP);
#if 0
  g_signal_connect (help_bt, "clicked",/* G_CALLBACK(topic_cb)*/NULL, /*(gpointer)HELP_MANUAL_ADDR_RESOLVE_DIALOG*/NULL);
#endif
  gtk_widget_set_sensitive (help_bt, FALSE);

  gtk_widget_grab_default (ok_bt);
  g_signal_connect (edit_or_add_pkt_comment_dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);


  gtk_widget_show (edit_or_add_pkt_comment_dlg);
}

static void
edit_capture_comment_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have an "Edit Capture Comment" dialog box. */
  edit_or_add_capture_comment_dlg = NULL;
}

void
edit_capture_dlg_launch (void)
{

  GtkWidget *vbox;
  GtkWidget *view;
  GtkWidget *scroll;
  GtkWidget *bbox;
  GtkWidget *ok_bt, *cancel_bt, *help_bt;
  GtkTextBuffer *buffer = NULL;
  const gchar *comment_str = NULL;
  gchar *buf_str;

  if (edit_or_add_capture_comment_dlg != NULL) {
    /* There's already an "Edit Capture Comment" dialog box; reactivate it. */
    reactivate_window(edit_or_add_capture_comment_dlg);
    return;
  }

  edit_or_add_capture_comment_dlg = dlg_window_new ("Edit or Add Capture Comments");
  gtk_widget_set_size_request (edit_or_add_capture_comment_dlg, 500, 160);
  gtk_window_set_resizable (GTK_WINDOW (edit_or_add_capture_comment_dlg), TRUE);
  gtk_container_set_border_width (GTK_CONTAINER (edit_or_add_capture_comment_dlg), DLG_OUTER_MARGIN);

  g_signal_connect(edit_or_add_capture_comment_dlg, "destroy",
                   G_CALLBACK(edit_capture_comment_destroy_cb), NULL);

  vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, DLG_UNRELATED_SPACING, FALSE);
  gtk_container_add (GTK_CONTAINER (edit_or_add_capture_comment_dlg), vbox);
  gtk_widget_show (vbox);

  view = gtk_text_view_new ();
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD);
  buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));
  gtk_widget_show (view);

  scroll = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                  GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
  gtk_container_add(GTK_CONTAINER(scroll), view);
  gtk_widget_show(scroll);
  gtk_box_pack_start(GTK_BOX (vbox), scroll, TRUE, TRUE, 0);

  /* Get the comment */
  comment_str = cf_read_shb_comment(&cfile);
  /*g_warning("Fetched comment '%s'",opt_comment);*/

  if(comment_str != NULL){
    buf_str = g_strdup_printf("%s", comment_str);
    gtk_text_buffer_set_text (buffer, buf_str, -1);
    g_free(buf_str);
  }

  /* Button row. */
  bbox = dlg_button_row_new (GTK_STOCK_OK, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  gtk_box_pack_end (GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

  ok_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_OK);
  g_signal_connect (ok_bt, "clicked", G_CALLBACK(capture_comment_text_buff_ok_cb), view);
  gtk_widget_set_sensitive (ok_bt, TRUE);

  cancel_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_CANCEL);
  window_set_cancel_button (edit_or_add_capture_comment_dlg, cancel_bt, window_cancel_button_cb);

  help_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_HELP);
#if 0
  g_signal_connect (help_bt, "clicked",/* G_CALLBACK(topic_cb)*/NULL, /*(gpointer)HELP_MANUAL_ADDR_RESOLVE_DIALOG*/NULL);
#endif
  gtk_widget_set_sensitive (help_bt, FALSE);

  gtk_widget_grab_default (ok_bt);
  g_signal_connect (edit_or_add_capture_comment_dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);


  gtk_widget_show (edit_or_add_capture_comment_dlg);

}
