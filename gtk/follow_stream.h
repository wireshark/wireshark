/* follow_stream.c
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

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
	char		data_out_filename[128 + 1];
	GtkWidget	*text;
	GtkWidget	*ascii_bt;
	GtkWidget	*ebcdic_bt;
	GtkWidget	*hexdump_bt;
	GtkWidget	*carray_bt;
	GtkWidget	*raw_bt;
	GtkWidget	*follow_save_as_w;
#if GTK_CHECK_VERSION(2,4,0)
	GtkWidget	*find_dlg_w;
#endif
	gboolean        is_ipv6;
	char		*filter_out_filter;
	GtkWidget	*filter_te;
	GtkWidget	*streamwindow;
        GList           *payload;
        guint           bytes_written[2];
        guint           client_port;
        char            client_ip[MAX_IPADDR_LEN];
} follow_info_t;

#define E_FOLLOW_INFO_KEY "follow_info_key"

/* List of "follow_info_t" structures for all "Follow TCP Stream" windows,
   so we can redraw them all if the colors or font changes. */
extern GList *follow_infos;

void follow_charset_toggle_cb(GtkWidget * w, gpointer parent_w);
void follow_load_text(follow_info_t *follow_info);
void follow_filter_out_stream(GtkWidget * w, gpointer parent_w);
#if GTK_CHECK_VERSION(2,4,0)
void follow_find_cb(GtkWidget * w, gpointer data);
void follow_find_button_cb(GtkWidget * w _U_, gpointer parent_w);
void follow_find_destroy_cb(GtkWidget * win _U_, gpointer data);
#endif
void follow_print_stream(GtkWidget * w, gpointer parent_w);
void follow_save_as_cmd_cb(GtkWidget * w, gpointer data);
void follow_save_as_ok_cb(GtkWidget * w, gpointer fs);
void follow_save_as_destroy_cb(GtkWidget * win, gpointer user_data);
void follow_stream_om_both(GtkWidget * w, gpointer data);
void follow_stream_om_client(GtkWidget * w, gpointer data);
void follow_stream_om_server(GtkWidget * w, gpointer data);
void remember_follow_info(follow_info_t *follow_info);
void forget_follow_info(follow_info_t *follow_info);
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

frs_return_t follow_read_tcp_stream(follow_info_t *follow_info, gboolean (*print_line)(char *, size_t, gboolean, void *), void *arg);
frs_return_t follow_read_udp_stream(follow_info_t *follow_info, gboolean (*print_line)(char *, size_t, gboolean, void *), void *arg);
frs_return_t follow_read_ssl_stream(follow_info_t *follow_info, gboolean (*print_line)(char *, size_t, gboolean, void *), void *arg);
