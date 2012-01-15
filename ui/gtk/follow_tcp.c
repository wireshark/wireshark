/* follow_tcp.c
 * TCP specific routines for following traffic streams
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

#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>

#include <gtk/gtk.h>

#include <epan/follow.h>
#include <epan/dissectors/packet-ipv6.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/charsets.h>
#include <epan/epan_dissect.h>
#include <epan/filesystem.h>
#include <epan/ipproto.h>
#include <epan/charsets.h>

#include "../file.h"
#include "../alert_box.h"
#include "../simple_dialog.h"
#include "../tempfile.h"
#include <wsutil/file_util.h>

#include "gtkglobals.h"
#include "ui/gtk/color_utils.h"
#include "ui/gtk/follow_tcp.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/file_dlg.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/main.h"
#include "ui/gtk/gui_utils.h"
#include "win32/print_win32.h"
#include "ui/gtk/font_utils.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/follow_stream.h"
#include "ui/gtk/utf8_entities.h"

/* With MSVC and a libwireshark.dll, we need a special declaration. */
WS_VAR_IMPORT FILE *data_out_file;

static void
follow_redraw(gpointer data, gpointer user_data _U_)
{
	follow_load_text((follow_info_t *)data);
}

/* Redraw the text in all "Follow TCP Stream" windows. */
void
follow_tcp_redraw_all(void)
{
	g_list_foreach(follow_infos, follow_redraw, NULL);
}

/* Follow the TCP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
follow_tcp_stream_cb(GtkWidget * w _U_, gpointer data _U_)
{
	GtkWidget *filter_cm;
	GtkWidget	*filter_te;
	int		tmp_fd;
	gchar		*follow_filter;
	const gchar	*previous_filter;
	int		filter_out_filter_len;
	const char	*hostname0, *hostname1;
	char		*port0, *port1;
	gchar		*server_to_client_string = NULL;
	gchar		*client_to_server_string = NULL;
	gchar		*both_directions_string = NULL;
	follow_stats_t stats;
	follow_info_t	*follow_info;
	tcp_stream_chunk sc;
	size_t              nchars;
	gchar           *data_out_filename;

	/* we got tcp so we can follow */
	if (cfile.edt->pi.ipproto != IP_PROTO_TCP) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			      "Error following stream.  Please make\n"
			      "sure you have a TCP packet selected.");
		return;
	}

	follow_info = g_new0(follow_info_t, 1);
	follow_info->follow_type = FOLLOW_TCP;

	/* Create a new filter that matches all packets in the TCP stream,
	   and set the display filter entry accordingly */
	reset_tcp_reassembly();
	follow_filter = build_follow_filter(&cfile.edt->pi);
	if (!follow_filter) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			      "Error creating filter for this stream.\n"
			      "A transport or network layer header is needed");
		g_free(follow_info);
		return;
	}

	/* Create a temporary file into which to dump the reassembled data
	   from the TCP stream, and set "data_out_file" to refer to it, so
	   that the TCP code will write to it.

	   XXX - it might be nicer to just have the TCP code directly
	   append stuff to the text widget for the TCP stream window,
	   if we can arrange that said window not pop up until we're
	   done. */
	tmp_fd = create_tempfile(&data_out_filename, "follow");
	follow_info->data_out_filename = g_strdup(data_out_filename);

	if (tmp_fd == -1) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			  "Could not create temporary file %s: %s",
			  follow_info->data_out_filename, g_strerror(errno));
	    g_free(follow_info->data_out_filename);
	    g_free(follow_info);
	    g_free(follow_filter);
	    return;
	}

	data_out_file = fdopen(tmp_fd, "w+b");
	if (data_out_file == NULL) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			  "Could not create temporary file %s: %s",
			  follow_info->data_out_filename, g_strerror(errno));
	    ws_close(tmp_fd);
	    ws_unlink(follow_info->data_out_filename);
	    g_free(follow_info->data_out_filename);
	    g_free(follow_info);
	    g_free(follow_filter);
	    return;
	}

	/* Set the display filter entry accordingly */
	filter_cm = g_object_get_data(G_OBJECT(top_level), E_DFILTER_CM_KEY);
	filter_te = gtk_bin_get_child(GTK_BIN(filter_cm));

	/* needed in follow_filter_out_stream(), is there a better way? */
	follow_info->filter_te = filter_te;

	/* save previous filter, const since we're not supposed to alter */
	previous_filter =
	    (const gchar *)gtk_entry_get_text(GTK_ENTRY(filter_te));

	/* allocate our new filter. API claims g_malloc terminates program on failure */
	/* my calc for max alloc needed is really +10 but when did a few extra bytes hurt ? */
	filter_out_filter_len = (int)(strlen(follow_filter) + strlen(previous_filter) + 16);
	follow_info->filter_out_filter = (gchar *)g_malloc(filter_out_filter_len);

	/* append the negation */
	if(strlen(previous_filter)) {
	    g_snprintf(follow_info->filter_out_filter, filter_out_filter_len,
            "%s and !(%s)", previous_filter, follow_filter);
	} else {
	    g_snprintf(follow_info->filter_out_filter, filter_out_filter_len,
            "!(%s)", follow_filter);
	}

	gtk_entry_set_text(GTK_ENTRY(filter_te), follow_filter);

	/* Run the display filter so it goes in effect - even if it's the
	   same as the previous display filter. */
	main_filter_packets(&cfile, follow_filter, TRUE);

	/* Free the filter string, as we're done with it. */
	g_free(follow_filter);

	/* Check whether we got any data written to the file. */
	if (empty_tcp_stream) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			  "The packets in the capture file for that stream have no data.");
	    ws_close(tmp_fd);
	    ws_unlink(follow_info->data_out_filename);
	    g_free(follow_info->data_out_filename);
	    g_free(follow_info->filter_out_filter);
	    g_free(follow_info);
	    return;
	}

	/* Go back to the top of the file and read the first tcp_stream_chunk
	 * to ensure that the IP addresses and port numbers in the drop-down
	 * list are tied to the correct lines displayed by follow_read_stream()
	 * later on (which also reads from this file).  Close the file when
	 * we're done.
	 *
	 * We read the data now, before we pop up a window, in case the
	 * read fails.  We use the data later.
	 */

	rewind(data_out_file);
	nchars=fread(&sc, 1, sizeof(sc), data_out_file);
	if (nchars != sizeof(sc)) {
	    if (ferror(data_out_file)) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			      "Could not read from temporary file %s: %s",
			      follow_info->data_out_filename, g_strerror(errno));
	    } else {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			      "Short read from temporary file %s: expected %lu, got %lu",
			      follow_info->data_out_filename,
			      (unsigned long)sizeof(sc),
			      (unsigned long)nchars);
	    }
	    ws_close(tmp_fd);
	    ws_unlink(follow_info->data_out_filename);
	    g_free(follow_info->data_out_filename);
	    g_free(follow_info->filter_out_filter);
	    g_free(follow_info);
	    return;
	}
	fclose(data_out_file);

	/* The data_out_filename file now has all the text that was in the
	   session (this is dumped to file by the TCP dissector). */

	/* Stream to show */
	follow_stats(&stats);

	if (stats.is_ipv6) {
		struct e_in6_addr ipaddr;
		memcpy(&ipaddr, stats.ip_address[0], 16);
		hostname0 = get_hostname6(&ipaddr);
		memcpy(&ipaddr, stats.ip_address[0], 16);
		hostname1 = get_hostname6(&ipaddr);
	} else {
		guint32 ipaddr;
		memcpy(&ipaddr, stats.ip_address[0], 4);
		hostname0 = get_hostname(ipaddr);
		memcpy(&ipaddr, stats.ip_address[1], 4);
		hostname1 = get_hostname(ipaddr);
	}

        follow_info->is_ipv6 = stats.is_ipv6;

	port0 = get_tcp_port(stats.port[0]);
	port1 = get_tcp_port(stats.port[1]);

	/* Host 0 --> Host 1 */
	if(sc.src_port == stats.port[0]) {
		server_to_client_string =
			g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
					hostname0, port0,
					hostname1, port1,
					stats.bytes_written[0]);
	} else {
		server_to_client_string =
			g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
					hostname1, port1,
					hostname0,port0,
					stats.bytes_written[0]);
	}

	/* Host 1 --> Host 0 */
	if(sc.src_port == stats.port[1]) {
		client_to_server_string =
			g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
					hostname0, port0,
					hostname1, port1,
					stats.bytes_written[1]);
	} else {
		client_to_server_string =
			g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
					hostname1, port1,
					hostname0, port0,
					stats.bytes_written[1]);
	}

	/* Both Stream Directions */
	both_directions_string = g_strdup_printf("Entire conversation (%u bytes)", stats.bytes_written[0] + stats.bytes_written[1]);

	follow_stream("Follow TCP Stream", follow_info, both_directions_string,
		      server_to_client_string, client_to_server_string);

	g_free(both_directions_string);
	g_free(server_to_client_string);
	g_free(client_to_server_string);

	data_out_file = NULL;
}

#define FLT_BUF_SIZE 1024

/*
 * XXX - the routine pointed to by "print_line_fcn_p" doesn't get handed lines,
 * it gets handed bufferfuls.  That's fine for "follow_write_raw()"
 * and "follow_add_to_gtk_text()", but, as "follow_print_text()" calls
 * the "print_line()" routine from "print.c", and as that routine might
 * genuinely expect to be handed a line (if, for example, it's using
 * some OS or desktop environment's printing API, and that API expects
 * to be handed lines), "follow_print_text()" should probably accumulate
 * lines in a buffer and hand them "print_line()".  (If there's a
 * complete line in a buffer - i.e., there's nothing of the line in
 * the previous buffer or the next buffer - it can just hand that to
 * "print_line()" after filtering out non-printables, as an
 * optimization.)
 *
 * This might or might not be the reason why C arrays display
 * correctly but get extra blank lines very other line when printed.
 */
frs_return_t
follow_read_tcp_stream(follow_info_t *follow_info,
		       gboolean (*print_line_fcn_p)(char *, size_t, gboolean, void *),
		       void *arg)
{
    tcp_stream_chunk	sc;
    size_t		bcount;
    size_t		bytes_read;
    int			iplen;
    guint8		client_addr[MAX_IPADDR_LEN];
    guint16		client_port = 0;
    gboolean		is_server;
    guint32		global_client_pos = 0, global_server_pos = 0;
    guint32		server_packet_count = 0;
    guint32		client_packet_count = 0;
    guint32		*global_pos;
    gboolean		skip;
    char                buffer[FLT_BUF_SIZE+1]; /* +1 to fix ws bug 1043 */
    size_t              nchars;
    frs_return_t        frs_return;

    iplen = (follow_info->is_ipv6) ? 16 : 4;

    data_out_file = ws_fopen(follow_info->data_out_filename, "rb");
    if (data_out_file == NULL) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		      "Could not open temporary file %s: %s", follow_info->data_out_filename,
		      g_strerror(errno));
	return FRS_OPEN_ERROR;
    }

    while ((nchars=fread(&sc, 1, sizeof(sc), data_out_file))) {
    	if (nchars != sizeof(sc)) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			  "Short read from temporary file %s: expected %lu, got %lu",
			  follow_info->data_out_filename,
			  (unsigned long)sizeof(sc),
			  (unsigned long)nchars);
	    fclose(data_out_file);
	    data_out_file = NULL;
	    return FRS_READ_ERROR;
	}
	if (client_port == 0) {
	    memcpy(client_addr, sc.src_addr, iplen);
	    client_port = sc.src_port;
	}
	skip = FALSE;
	if (memcmp(client_addr, sc.src_addr, iplen) == 0 &&
	    client_port == sc.src_port) {
	    is_server = FALSE;
	    global_pos = &global_client_pos;
	    if (follow_info->show_stream == FROM_SERVER) {
		skip = TRUE;
	    }
	}
	else {
	    is_server = TRUE;
	    global_pos = &global_server_pos;
	    if (follow_info->show_stream == FROM_CLIENT) {
		skip = TRUE;
	    }
	}

        bytes_read = 0;
	while (bytes_read < sc.dlen) {
	    bcount = ((sc.dlen-bytes_read) < FLT_BUF_SIZE) ? (sc.dlen-bytes_read) : FLT_BUF_SIZE;
	    nchars = fread(buffer, 1, bcount, data_out_file);
	    if (nchars == 0)
		break;
	    /* XXX - if we don't get "bcount" bytes, is that an error? */
            bytes_read += nchars;

	    if (!skip) {
		    frs_return = follow_show(follow_info, print_line_fcn_p, buffer,
					     nchars, is_server, arg, global_pos,
					     &server_packet_count,
					     &client_packet_count);
		    if(frs_return == FRS_PRINT_ERROR) {
			    fclose(data_out_file);
			    data_out_file = NULL;
			    return frs_return;

		    }
	    }
	}
    }

    if (ferror(data_out_file)) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		      "Error reading temporary file %s: %s", follow_info->data_out_filename,
		      g_strerror(errno));
	fclose(data_out_file);
	data_out_file = NULL;
	return FRS_READ_ERROR;
    }

    fclose(data_out_file);
    data_out_file = NULL;
    return FRS_OK;
}
