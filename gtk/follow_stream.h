/* follow_stream.h
 * Common routines for following data streams
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __FOLLOW_STREAM_H__
#define __FOLLOW_STREAM_H__

#include <gtk/gtk.h>

/* Type of follow we are doing */
typedef enum {
	FOLLOW_TCP,
	FOLLOW_SSL,
	FOLLOW_UDP
} follow_type_t;

/* Show Stream */
typedef enum {
	FROM_CLIENT,
	FROM_SERVER,
	BOTH_HOSTS
} show_stream_t;

/* Show Type */
typedef enum {
	SHOW_ASCII,
	SHOW_EBCDIC,
	SHOW_HEXDUMP,
	SHOW_CARRAY,
	SHOW_RAW
} show_type_t;

typedef enum {
        FRS_OK,
        FRS_OPEN_ERROR,
        FRS_READ_ERROR,
        FRS_PRINT_ERROR
} frs_return_t;

typedef struct {
	gboolean is_server;
	GByteArray *data;
} follow_record_t;

typedef struct {
	follow_type_t   follow_type;
	show_stream_t	show_stream;
	show_type_t	show_type;
	char		*data_out_filename;
	GtkWidget	*text;
	GtkWidget	*ascii_bt;
	GtkWidget	*ebcdic_bt;
	GtkWidget	*hexdump_bt;
	GtkWidget	*carray_bt;
	GtkWidget	*raw_bt;
	GtkWidget	*follow_save_as_w;
	GtkWidget	*find_dlg_w;
	gboolean        is_ipv6;
	char		*filter_out_filter;
	GtkWidget	*filter_te;
	GtkWidget	*streamwindow;
        GList           *payload;
        guint           bytes_written[2];
        guint           client_port;
        address         client_ip;
} follow_info_t;

#define E_FOLLOW_INFO_KEY "follow_info_key"

/* List of "follow_info_t" structures for all "Follow TCP Stream" windows,
   so we can redraw them all if the colors or font changes. */
extern GList *follow_infos;

void follow_load_text(follow_info_t *follow_info);
void follow_filter_out_stream(GtkWidget * w, gpointer parent_w);
void follow_stream(gchar *title, follow_info_t *follow_info,
		   gchar *both_directions_string,
		   gchar *server_to_client_string,
		   gchar *client_to_server_string);
frs_return_t follow_show(follow_info_t *follow_info,
			 gboolean (*print_line)(char *, size_t, gboolean,
						void *),
			 char *buffer, size_t nchars, gboolean is_server,
			 void *arg, guint32 *global_pos,
			 guint32 *server_packet_count,
			 guint32 *client_packet_count);
gboolean follow_add_to_gtk_text(char *buffer, size_t nchars, gboolean is_server,
		       void *arg);

frs_return_t follow_read_tcp_stream(follow_info_t *follow_info, gboolean (*print_line)(char *, size_t, gboolean, void *), void *arg);
frs_return_t follow_read_udp_stream(follow_info_t *follow_info, gboolean (*print_line)(char *, size_t, gboolean, void *), void *arg);
frs_return_t follow_read_ssl_stream(follow_info_t *follow_info, gboolean (*print_line)(char *, size_t, gboolean, void *), void *arg);

#endif /* __FOLLOW_STREAM_H__ */
