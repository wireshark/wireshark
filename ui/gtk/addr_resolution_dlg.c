/* addr_resolution_dlg.c
 * Show current addres resolution as a hosts file
 *
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
#include <epan/addr_resolv.h>

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
#include "ui/gtk/old-gtk-compat.h"


/* Needed for addrinfo */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif

#if defined(_WIN32) && defined(INET6)
# include <ws2tcpip.h>
#endif

#ifdef NEED_INET_V6DEFS_H
# include "wsutil/inet_v6defs.h"
#endif


static GtkWidget *addr_resolution_dlg_w = NULL;

#if 0
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

  window_destroy(addr_resolution_dlg_w);

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

static void
comment_summary_copy_to_clipboard_cb(GtkWidget *w _U_, GtkWidget *view)
{
  GtkTextBuffer *buffer;
  GtkTextIter start_iter, end_iter;
  GtkClipboard *clipboard;

  buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));

  gtk_text_buffer_get_bounds(buffer, &start_iter, &end_iter);

  gtk_text_buffer_select_range(buffer, &start_iter, &end_iter);

  clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);     /* Get the default clipboard */
  gtk_text_buffer_copy_clipboard (buffer, clipboard);

  gtk_text_buffer_select_range(buffer, &end_iter, &end_iter);

}
#endif

#define HOSTNAME_POS 48
#define ADDRSTRLEN 46 /* Covers IPv4 & IPv6 */
#define ADDRESS_STR_MAX     1024

static void
addres_resolution_to_texbuff(GtkTextBuffer *buffer)
{
	struct addrinfo *ai;
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
	char   addr_str[ADDRSTRLEN];
	int i, tab_count;
	gchar string_buff[ADDRESS_STR_MAX];

	g_snprintf(string_buff, ADDRESS_STR_MAX, "# Hosts information in Wireshark \n#\n");
	gtk_text_buffer_insert_at_cursor (buffer, string_buff, -1);
	g_snprintf(string_buff, ADDRESS_STR_MAX, "# Host data gathered from %s\n\n", cfile.filename);
	gtk_text_buffer_insert_at_cursor (buffer, string_buff, -1);

	/* Dump the v4 addresses first, then v6 */
	for (ai = get_addrinfo_list(); ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET) {
			continue;
		}

		sa4 = (struct sockaddr_in *)(void *)ai->ai_addr;
		if (inet_ntop(AF_INET, &(sa4->sin_addr.s_addr), addr_str, ADDRSTRLEN)) {
			tab_count = (HOSTNAME_POS - (int)strlen(addr_str)) / 8;
			g_snprintf(string_buff, ADDRESS_STR_MAX, "%s", addr_str);
			gtk_text_buffer_insert_at_cursor (buffer, string_buff, -1);
			for (i = 0; i < tab_count; i++){
				g_snprintf(string_buff, ADDRESS_STR_MAX, "\t");
				gtk_text_buffer_insert_at_cursor (buffer, string_buff, -1);
			}
			g_snprintf(string_buff, ADDRESS_STR_MAX, "%s\n", ai->ai_canonname);
			gtk_text_buffer_insert_at_cursor (buffer, string_buff, -1);
		}
	}


	for (ai = get_addrinfo_list(); ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET6) {
			continue;
		}

		sa6 = (struct sockaddr_in6 *)(void *)ai->ai_addr;
		if (inet_ntop(AF_INET6, sa6->sin6_addr.s6_addr, addr_str, ADDRSTRLEN)) {
			tab_count = (HOSTNAME_POS - (int)strlen(addr_str)) / 8;
			g_snprintf(string_buff, ADDRESS_STR_MAX, "%s", addr_str);
			for (i = 0; i < tab_count; i++){
				g_snprintf(string_buff, ADDRESS_STR_MAX, "\t");
				gtk_text_buffer_insert_at_cursor (buffer, string_buff, -1);
			}
			g_snprintf(string_buff, ADDRESS_STR_MAX, "%s\n", ai->ai_canonname);
			gtk_text_buffer_insert_at_cursor (buffer, string_buff, -1);
		}
	}

}
void
addr_resolution_dlg (GtkAction *action _U_, gpointer data _U_)
{

  GtkWidget *vbox;
  GtkWidget *view;
  GtkWidget *scroll;
  GtkWidget *bbox;
  GtkWidget *ok_bt, *cancel_bt, *help_bt;
  GtkTextBuffer *buffer = NULL;

  addr_resolution_dlg_w = dlg_window_new ("Address Resolution");
  gtk_widget_set_size_request (addr_resolution_dlg_w, 500, 160);
  gtk_window_set_resizable (GTK_WINDOW (addr_resolution_dlg_w), TRUE);
  gtk_container_set_border_width (GTK_CONTAINER (addr_resolution_dlg_w), DLG_OUTER_MARGIN);

  vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, DLG_UNRELATED_SPACING, FALSE);
  gtk_container_add (GTK_CONTAINER (addr_resolution_dlg_w), vbox);
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

  /* Get the address list */
  addres_resolution_to_texbuff(buffer);

  /* Button row. */
  bbox = dlg_button_row_new (GTK_STOCK_OK, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  gtk_box_pack_end (GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

  ok_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_OK);
  /*g_signal_connect (ok_bt, "clicked", G_CALLBACK(pkt_comment_text_buff_ok_cb), view);*/
  gtk_widget_set_sensitive (ok_bt, TRUE);

  cancel_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_CANCEL);
  window_set_cancel_button (addr_resolution_dlg_w, cancel_bt, window_cancel_button_cb);

  help_bt = g_object_get_data (G_OBJECT(bbox), GTK_STOCK_HELP);
#if 0
  g_signal_connect (help_bt, "clicked",/* G_CALLBACK(topic_cb)*/NULL, /*(gpointer)HELP_MANUAL_ADDR_RESOLVE_DIALOG*/NULL);
#endif
  gtk_widget_set_sensitive (help_bt, FALSE);

  gtk_widget_grab_default (ok_bt);
  /*g_signal_connect (addr_resolution_dlg_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);*/


  gtk_widget_show (addr_resolution_dlg_w);
}

