/* follow_stream.h
 * Common routines for following data streams
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __FOLLOW_STREAM_H__
#define __FOLLOW_STREAM_H__

#include <gtk/gtk.h>
#include <epan/follow.h>


typedef struct _gtk_follow_info {
    show_type_t     show_type;
    GtkWidget       *text;
    GtkWidget       *ascii_bt;
    GtkWidget       *ebcdic_bt;
    GtkWidget       *hexdump_bt;
    GtkWidget       *carray_bt;
    GtkWidget       *raw_bt;
    GtkWidget       *find_dlg_w;
    GtkWidget       *filter_te;
    GtkWidget       *streamwindow;
    follow_read_stream_func read_stream;
} gtk_follow_info_t;

#define E_FOLLOW_INFO_KEY "follow_info_key"

/** Redraw the text in all "Follow TCP Stream" windows. */
extern void follow_stream_redraw_all(void);

/** User requested the "Follow TCP Stream" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void follow_tcp_stream_cb( GtkWidget *widget, gpointer data);

/* Follow the UDP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void follow_udp_stream_cb(GtkWidget * w, gpointer data _U_);

/* Follow the HTTP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void follow_http_stream_cb(GtkWidget * w, gpointer data _U_);

/* Follow the SSL stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void follow_ssl_stream_cb(GtkWidget * w, gpointer data _U_);


#endif /* __FOLLOW_STREAM_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
