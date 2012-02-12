/* edit_packet_comment_dlg.c
 * Dialog box for editing or adding packet comments.
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
#include "ui/gtk/edit_packet_comment_dlg.h"
#include "ui/gtk/old-gtk-compat.h"

GtkWidget *edit_or_add_pkt_comment_dlg = NULL;



void
edit_packet_comment_dlg (GtkAction *action _U_, gpointer data)
{

  GtkWidget *box1;
  GtkWidget *view;
  GtkTextBuffer *buffer;
  gchar *opt_comment;
  const gchar *buf_str;

  edit_or_add_pkt_comment_dlg = dlg_window_new ("Edit or Add Packet Comments(Not working yet)");
  gtk_widget_set_size_request (edit_or_add_pkt_comment_dlg, 310, 80);
  gtk_window_set_resizable (GTK_WINDOW (edit_or_add_pkt_comment_dlg), TRUE); 
  gtk_container_set_border_width (GTK_CONTAINER (edit_or_add_pkt_comment_dlg), 0);

  box1 = gtk_vbox_new (FALSE, 0);
  gtk_container_add (GTK_CONTAINER (edit_or_add_pkt_comment_dlg), box1);
  gtk_widget_show (box1);
  
  view = gtk_text_view_new ();
  buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));

  /* Get the comment */
  opt_comment = get_packet_comment_from_packet_list_row(data);
  /*g_warning("Fetched comment '%s'",opt_comment);*/

  buf_str = g_strdup_printf(opt_comment);
  
  gtk_text_buffer_set_text (buffer, buf_str, -1);
  gtk_container_add(GTK_CONTAINER(box1), view);
  gtk_widget_show (view);

  gtk_widget_show (edit_or_add_pkt_comment_dlg);


}
