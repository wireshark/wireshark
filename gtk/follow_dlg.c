/* follow_dlg.c
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <stdio.h>
#include <string.h>


#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>

#include "isprint.h"

#include "file_util.h"
#include "color.h"
#include "colors.h"
#include "file.h"
#include "follow_dlg.h"
#include <epan/follow.h>
#include "dlg_utils.h"
#include "file_dlg.h"
#include "keys.h"
#include "globals.h"
#include "main.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include <epan/dissectors/packet-ipv6.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/charsets.h>
#include "tempfile.h"
#include "gui_utils.h"
#include <epan/epan_dissect.h>
#include <epan/filesystem.h>
#include "compat_macros.h"
#include <epan/ipproto.h>
#include "print_mswin.h"
#include "font_utils.h"
#include "help_dlg.h"

#include "follow_stream.h"

/* This is backwards-compatibility code for old versions of GTK+ (2.2.1 and
 * earlier).  It defines the new wrap behavior (unknown in earlier versions)
 * as the old (slightly buggy) wrap behavior.
 */
#ifndef GTK_WRAP_WORD_CHAR
#define GTK_WRAP_WORD_CHAR GTK_WRAP_WORD
#endif

static void follow_destroy_cb(GtkWidget * win, gpointer data);

/* With MSVC and a libwireshark.dll, we need a special declaration. */
WS_VAR_IMPORT FILE *data_out_file;

static void
follow_redraw(gpointer data, gpointer user_data _U_)
{
	follow_load_text((follow_info_t *)data);
}

/* Redraw the text in all "Follow TCP Stream" windows. */
void
follow_redraw_all(void)
{
	g_list_foreach(follow_infos, follow_redraw, NULL);
}

/* Follow the TCP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
follow_stream_cb(GtkWidget * w, gpointer data _U_)
{
	GtkWidget	*streamwindow, *vbox, *txt_scrollw, *text, *filter_te;
	GtkWidget	*hbox, *bbox, *button, *radio_bt;
	GtkWidget	*stream_fr, *stream_vb;
	GtkWidget	*stream_om, *stream_menu, *stream_mi;
	GtkTooltips	*tooltips;
	int		tmp_fd;
	gchar		*follow_filter;
	const gchar	*previous_filter;
	int		filter_out_filter_len;
	const char	*hostname0, *hostname1;
	char		*port0, *port1;
	char		string[128];
	follow_tcp_stats_t stats;
	follow_info_t	*follow_info;
	tcp_stream_chunk sc;
	size_t              nchars;

	/* we got tcp so we can follow */
	if (cfile.edt->pi.ipproto != IP_PROTO_TCP) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			      "Error following stream.  Please make\n"
			      "sure you have a TCP packet selected.");
		return;
	}

	follow_info = g_new0(follow_info_t, 1);
	follow_info->follow_type = FOLLOW_TCP;

	/* Create a temporary file into which to dump the reassembled data
	   from the TCP stream, and set "data_out_file" to refer to it, so
	   that the TCP code will write to it.

	   XXX - it might be nicer to just have the TCP code directly
	   append stuff to the text widget for the TCP stream window,
	   if we can arrange that said window not pop up until we're
	   done. */
	tmp_fd = create_tempfile(follow_info->data_out_filename,
			sizeof follow_info->data_out_filename, "follow");

	if (tmp_fd == -1) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			  "Could not create temporary file %s: %s",
			  follow_info->data_out_filename, strerror(errno));
	    g_free(follow_info);
	    return;
	}

	data_out_file = fdopen(tmp_fd, "w+b");
	if (data_out_file == NULL) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			  "Could not create temporary file %s: %s",
			  follow_info->data_out_filename, strerror(errno));
	    eth_close(tmp_fd);
	    unlink(follow_info->data_out_filename);
	    g_free(follow_info);
	    return;
	}

	/* Create a new filter that matches all packets in the TCP stream,
	   and set the display filter entry accordingly */
	reset_tcp_reassembly();
	follow_filter = build_follow_filter(&cfile.edt->pi);

	/* Set the display filter entry accordingly */
	filter_te = OBJECT_GET_DATA(w, E_DFILTER_TE_KEY);

	/* needed in follow_filter_out_stream(), is there a better way? */
	follow_info->filter_te = filter_te;

	/* save previous filter, const since we're not supposed to alter */
	previous_filter =
	    (const gchar *)gtk_entry_get_text(GTK_ENTRY(filter_te));

	/* allocate our new filter. API claims g_malloc terminates program on failure */
	/* my calc for max alloc needed is really +10 but when did a few extra bytes hurt ? */
	filter_out_filter_len = strlen(follow_filter) + strlen(previous_filter) + 16;
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
	    eth_close(tmp_fd);
	    unlink(follow_info->data_out_filename);
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
			      follow_info->data_out_filename, strerror(errno));
	    } else {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			      "Short read from temporary file %s: expected %lu, got %lu",
			      follow_info->data_out_filename,
			      (unsigned long)sizeof(sc),
			      (unsigned long)nchars);
	    }
	    eth_close(tmp_fd);
	    unlink(follow_info->data_out_filename);
	    g_free(follow_info);
	    return;
	}
	fclose(data_out_file);

	/* The data_out_filename file now has all the text that was in the session */
	streamwindow = dlg_window_new("Follow TCP Stream");

	/* needed in follow_filter_out_stream(), is there a better way? */
	follow_info->streamwindow = streamwindow;

	gtk_widget_set_name(streamwindow, "TCP stream window");
	gtk_window_set_default_size(GTK_WINDOW(streamwindow), DEF_WIDTH, DEF_HEIGHT);
	gtk_container_border_width(GTK_CONTAINER(streamwindow), 6);

	/* setup the container */
	tooltips = gtk_tooltips_new ();

	vbox = gtk_vbox_new(FALSE, 6);
	gtk_container_add(GTK_CONTAINER(streamwindow), vbox);

	/* content frame */
	if (incomplete_tcp_stream) {
		stream_fr = gtk_frame_new("Stream Content (incomplete)");
	} else {
		stream_fr = gtk_frame_new("Stream Content");
	}
  	gtk_container_add(GTK_CONTAINER(vbox), stream_fr);
  	gtk_widget_show(stream_fr);

	stream_vb = gtk_vbox_new(FALSE, 6);
	gtk_container_set_border_width( GTK_CONTAINER(stream_vb) , 6);
	gtk_container_add(GTK_CONTAINER(stream_fr), stream_vb);

	/* create a scrolled window for the text */
	txt_scrollw = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(txt_scrollw),
					    GTK_SHADOW_IN);
#endif
	gtk_box_pack_start(GTK_BOX(stream_vb), txt_scrollw, TRUE, TRUE, 0);

	/* create a text box */
#if GTK_MAJOR_VERSION < 2
	text = gtk_text_new(NULL, NULL);
	gtk_text_set_editable(GTK_TEXT(text), FALSE);
#else
        text = gtk_text_view_new();
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text), GTK_WRAP_WORD_CHAR);
#endif
	gtk_container_add(GTK_CONTAINER(txt_scrollw), text);
	follow_info->text = text;


	/* stream hbox */
	hbox = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(stream_vb), hbox, FALSE, FALSE, 0);

#if GTK_CHECK_VERSION(2,4,0)
	/* Create Find Button */
	button = BUTTON_NEW_FROM_STOCK(GTK_STOCK_FIND);
	SIGNAL_CONNECT(button, "clicked", follow_find_cb, follow_info);
	gtk_tooltips_set_tip (tooltips, button, "Find text in the displayed content", NULL);
	gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 0);
#endif

	/* Create Save As Button */
	button = BUTTON_NEW_FROM_STOCK(GTK_STOCK_SAVE_AS);
	SIGNAL_CONNECT(button, "clicked", follow_save_as_cmd_cb, follow_info);
	gtk_tooltips_set_tip (tooltips, button, "Save the content as currently displayed ", NULL);
	gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 0);

	/* Create Print Button */
	button = BUTTON_NEW_FROM_STOCK(GTK_STOCK_PRINT);
	SIGNAL_CONNECT(button, "clicked", follow_print_stream, follow_info);
	gtk_tooltips_set_tip (tooltips, button, "Print the content as currently displayed", NULL);
	gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 0);

	/* Stream to show */
	follow_tcp_stats(&stats);

	if (stats.is_ipv6) {
	  struct e_in6_addr ipaddr;
	  memcpy(&ipaddr, stats.ip_address[0], 16);
	  hostname0 = get_hostname6(&ipaddr);
	  memcpy(&ipaddr, stats.ip_address[1], 16);
	  hostname1 = get_hostname6(&ipaddr);
	} else {
	  guint32 ipaddr;
	  memcpy(&ipaddr, stats.ip_address[0], 4);
	  hostname0 = get_hostname(ipaddr);
	  memcpy(&ipaddr, stats.ip_address[1], 4);
	  hostname1 = get_hostname(ipaddr);
	}

	port0 = get_tcp_port(stats.tcp_port[0]);
	port1 = get_tcp_port(stats.tcp_port[1]);

	follow_info->is_ipv6 = stats.is_ipv6;

	stream_om = gtk_option_menu_new();
	stream_menu = gtk_menu_new();

	/* Both Stream Directions */
	g_snprintf(string, sizeof(string),
		 "Entire conversation (%u bytes)",
		 stats.bytes_written[0] + stats.bytes_written[1]);
	stream_mi = gtk_menu_item_new_with_label(string);
	SIGNAL_CONNECT(stream_mi, "activate", follow_stream_om_both,
                       follow_info);
	gtk_menu_append(GTK_MENU(stream_menu), stream_mi);
	gtk_widget_show(stream_mi);
	follow_info->show_stream = BOTH_HOSTS;

	/* Host 0 --> Host 1 */
	if(sc.src_port == strtol(port0, NULL, 10)) {
		g_snprintf(string, sizeof(string), "%s:%s --> %s:%s (%u bytes)",
			   hostname0, port0, hostname1, port1,
			   stats.bytes_written[0]);
	} else {
		g_snprintf(string, sizeof(string), "%s:%s --> %s:%s (%u bytes)",
			   hostname1, port1, hostname0, port0,
			   stats.bytes_written[0]);
	}

	stream_mi = gtk_menu_item_new_with_label(string);
	SIGNAL_CONNECT(stream_mi, "activate", follow_stream_om_client,
                       follow_info);
	gtk_menu_append(GTK_MENU(stream_menu), stream_mi);
	gtk_widget_show(stream_mi);

	/* Host 1 --> Host 0 */
	if(sc.src_port == strtol(port0, NULL, 10)) {
		g_snprintf(string, sizeof(string), "%s:%s --> %s:%s (%u bytes)",
			   hostname1, port1, hostname0, port0,
			   stats.bytes_written[1]);
	} else {
		g_snprintf(string, sizeof(string), "%s:%s --> %s:%s (%u bytes)",
			   hostname0, port0, hostname1, port1,
			   stats.bytes_written[1]);
	}

	stream_mi = gtk_menu_item_new_with_label(string);
	SIGNAL_CONNECT(stream_mi, "activate", follow_stream_om_server,
                       follow_info);
	gtk_menu_append(GTK_MENU(stream_menu), stream_mi);
	gtk_widget_show(stream_mi);

	gtk_option_menu_set_menu(GTK_OPTION_MENU(stream_om), stream_menu);
	/* Set history to 0th item, i.e., the first item. */
	gtk_option_menu_set_history(GTK_OPTION_MENU(stream_om), 0);
	gtk_tooltips_set_tip (tooltips, stream_om,
	    "Select the stream direction to display", NULL);
	gtk_box_pack_start(GTK_BOX(hbox), stream_om, FALSE, FALSE, 0);

	/* ASCII radio button */
	radio_bt = gtk_radio_button_new_with_label(NULL, "ASCII");
	gtk_tooltips_set_tip (tooltips, radio_bt, "Stream data output in \"ASCII\" format", NULL);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), TRUE);
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
	SIGNAL_CONNECT(radio_bt, "toggled", follow_charset_toggle_cb,
                       follow_info);
	follow_info->ascii_bt = radio_bt;
	follow_info->show_type = SHOW_ASCII;

	/* EBCDIC radio button */
	radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_group
					    (GTK_RADIO_BUTTON(radio_bt)),
					    "EBCDIC");
	gtk_tooltips_set_tip (tooltips, radio_bt, "Stream data output in \"EBCDIC\" format", NULL);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), FALSE);
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
	SIGNAL_CONNECT(radio_bt, "toggled", follow_charset_toggle_cb,
                       follow_info);
	follow_info->ebcdic_bt = radio_bt;

	/* HEX DUMP radio button */
	radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_group
					    (GTK_RADIO_BUTTON(radio_bt)),
					    "Hex Dump");
	gtk_tooltips_set_tip (tooltips, radio_bt, "Stream data output in \"Hexdump\" format", NULL);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), FALSE);
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
	SIGNAL_CONNECT(radio_bt, "toggled", follow_charset_toggle_cb,
                       follow_info);
	follow_info->hexdump_bt = radio_bt;

	/* C Array radio button */
	radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_group
					    (GTK_RADIO_BUTTON(radio_bt)),
					    "C Arrays");
	gtk_tooltips_set_tip (tooltips, radio_bt, "Stream data output in \"C Array\" format", NULL);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), FALSE);
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
	SIGNAL_CONNECT(radio_bt, "toggled", follow_charset_toggle_cb,
                       follow_info);
	follow_info->carray_bt = radio_bt;

	/* Raw radio button */
	radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_group
					    (GTK_RADIO_BUTTON(radio_bt)),
					    "Raw");
	gtk_tooltips_set_tip (tooltips, radio_bt, "Stream data output in \"Raw\" (binary) format. "
        "As this contains non printable characters, the screen output will be in ASCII format", NULL);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), FALSE);
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
	SIGNAL_CONNECT(radio_bt, "toggled", follow_charset_toggle_cb,
                       follow_info);
	follow_info->raw_bt = radio_bt;

    /* Button row: (help), filter out, close button */
    if(topic_available(HELP_FILESET_DIALOG)) {
      bbox = dlg_button_row_new(WIRESHARK_STOCK_FILTER_OUT_STREAM, GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    } else {
      bbox = dlg_button_row_new(WIRESHARK_STOCK_FILTER_OUT_STREAM, GTK_STOCK_CLOSE, NULL);
    }
    gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 5);


    button = OBJECT_GET_DATA(bbox, WIRESHARK_STOCK_FILTER_OUT_STREAM);
	gtk_tooltips_set_tip (tooltips, button,
        "Build a display filter which cuts this stream from the capture", NULL);
	SIGNAL_CONNECT(button, "clicked", follow_filter_out_stream, follow_info);

    button = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
	window_set_cancel_button(streamwindow, button, window_cancel_button_cb);
	gtk_tooltips_set_tip (tooltips, button,
	    "Close the dialog and keep the current display filter", NULL);
    gtk_widget_grab_default(button);

    if(topic_available(HELP_FILESET_DIALOG)) {
      button = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
      SIGNAL_CONNECT(button, "clicked", topic_cb, HELP_FOLLOW_TCP_STREAM_DIALOG);
    }

	/* Tuck away the follow_info object into the window */
	OBJECT_SET_DATA(streamwindow, E_FOLLOW_INFO_KEY, follow_info);

	follow_load_text(follow_info);
	remember_follow_info(follow_info);

	data_out_file = NULL;

	SIGNAL_CONNECT(streamwindow, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(streamwindow, "destroy", follow_destroy_cb, NULL);

	/* Make sure this widget gets destroyed if we quit the main loop,
	   so that if we exit, we clean up any temporary files we have
	   for "Follow TCP Stream" windows. */
	gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(streamwindow));

	gtk_widget_show_all(streamwindow);
	window_present(streamwindow);
}

/* The destroy call back has the responsibility of
 * unlinking the temporary file
 * and freeing the filter_out_filter */
static void
follow_destroy_cb(GtkWidget *w, gpointer data _U_)
{
	follow_info_t	*follow_info;
	int i;

	follow_info = OBJECT_GET_DATA(w, E_FOLLOW_INFO_KEY);
	i = unlink(follow_info->data_out_filename);
	if(i != 0) {
		g_warning("Follow: Couldn't remove temporary file: \"%s\", errno: %s (%u)", 
		    follow_info->data_out_filename, strerror(errno), errno);        
	}
	g_free(follow_info->filter_out_filter);
	forget_follow_info(follow_info);
	g_free(follow_info);
}

#define FLT_BUF_SIZE 1024

/*
 * XXX - the routine pointed to by "print_line" doesn't get handed lines,
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
		       gboolean (*print_line)(char *, size_t, gboolean, void *),
		       void *arg)
{
    tcp_stream_chunk	sc;
    int			bcount, iplen;
    guint8		client_addr[MAX_IPADDR_LEN];
    guint16		client_port = 0;
    gboolean		is_server;
    guint32		current_pos, global_client_pos = 0, global_server_pos = 0;
    guint32		*global_pos;
    gboolean		skip;
    gchar               initbuf[256];
    guint32             server_packet_count = 0;
    guint32             client_packet_count = 0;
    char                buffer[FLT_BUF_SIZE+1]; /* +1 to fix ws bug 1043 */
    size_t              nchars;
    static const gchar	hexchars[16] = "0123456789abcdef";

    iplen = (follow_info->is_ipv6) ? 16 : 4;

    data_out_file = eth_fopen(follow_info->data_out_filename, "rb");
    if (data_out_file == NULL) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		      "Could not open temporary file %s: %s", follow_info->data_out_filename,
		      strerror(errno));
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

	while (sc.dlen > 0) {
	    bcount = (sc.dlen < FLT_BUF_SIZE) ? sc.dlen : FLT_BUF_SIZE;
	    nchars = fread(buffer, 1, bcount, data_out_file);
	    if (nchars == 0)
		break;
	    /* XXX - if we don't get "bcount" bytes, is that an error? */
	    sc.dlen -= nchars;

	    if (!skip) {
		switch (follow_info->show_type) {

		case SHOW_EBCDIC:
		    /* If our native arch is ASCII, call: */
		    EBCDIC_to_ASCII(buffer, nchars);
		    if (!(*print_line) (buffer, nchars, is_server, arg))
			goto print_error;
		    break;

		case SHOW_ASCII:
		    /* If our native arch is EBCDIC, call:
		     * ASCII_TO_EBCDIC(buffer, nchars);
		     */
		    if (!(*print_line) (buffer, nchars, is_server, arg))
			goto print_error;
		    break;

		case SHOW_RAW:
		    /* Don't translate, no matter what the native arch
		     * is.
		     */
		    if (!(*print_line) (buffer, nchars, is_server, arg))
			goto print_error;
		    break;

		case SHOW_HEXDUMP:
		    current_pos = 0;
		    while (current_pos < nchars) {
			gchar hexbuf[256];
			int i;
			gchar *cur = hexbuf, *ascii_start;

			/* is_server indentation : put 78 spaces at the
			 * beginning of the string */
			if (is_server && follow_info->show_stream == BOTH_HOSTS) {
			    memset(cur, ' ', 78);
			    cur += 78;
			}
			cur += g_snprintf(cur, 20, "%08X  ", *global_pos);
			/* 49 is space consumed by hex chars */
			ascii_start = cur + 49;
			for (i = 0; i < 16 && current_pos + i < nchars; i++) {
			    *cur++ =
				hexchars[(buffer[current_pos + i] & 0xf0) >> 4];
			    *cur++ =
				hexchars[buffer[current_pos + i] & 0x0f];
			    *cur++ = ' ';
			    if (i == 7)
				*cur++ = ' ';
			}
			/* Fill it up if column isn't complete */
			while (cur < ascii_start)  
			    *cur++ = ' ';

			/* Now dump bytes as text */
			for (i = 0; i < 16 && current_pos + i < nchars; i++) {
			    *cur++ =
			        (isprint((guchar)buffer[current_pos + i]) ?
			        buffer[current_pos + i] : '.' );
			    if (i == 7) {
				*cur++ = ' ';
			    }
			}
			current_pos += i;
			(*global_pos) += i;
			*cur++ = '\n';
			*cur = 0;
			if (!(*print_line) (hexbuf, strlen(hexbuf), is_server, arg))
			    goto print_error;
		    }
		    break;

		case SHOW_CARRAY:
		    current_pos = 0;
		    g_snprintf(initbuf, sizeof(initbuf), "char peer%d_%d[] = {\n", 
			    is_server ? 1 : 0, 
			    is_server ? server_packet_count++ : client_packet_count++);
		    if (!(*print_line) (initbuf, strlen(initbuf), is_server, arg))
			goto print_error;
		    while (current_pos < nchars) {
			gchar hexbuf[256];
			int i, cur;

			cur = 0;
			for (i = 0; i < 8 && current_pos + i < nchars; i++) {
			  /* Prepend entries with "0x" */
			  hexbuf[cur++] = '0';
			  hexbuf[cur++] = 'x';
			    hexbuf[cur++] =
				hexchars[(buffer[current_pos + i] & 0xf0) >> 4];
			    hexbuf[cur++] =
				hexchars[buffer[current_pos + i] & 0x0f];

			    /* Delimit array entries with a comma */
			    if (current_pos + i + 1 < nchars)
			      hexbuf[cur++] = ',';

			    hexbuf[cur++] = ' ';
			}

			/* Terminate the array if we are at the end */
			if (current_pos + i == nchars) {
			    hexbuf[cur++] = '}';
			    hexbuf[cur++] = ';';
			}

			current_pos += i;
			(*global_pos) += i;
			hexbuf[cur++] = '\n';
			hexbuf[cur] = 0;
			if (!(*print_line) (hexbuf, strlen(hexbuf), is_server, arg))
			    goto print_error;
		    }
		    break;
		}
	    }
	}
    }
    if (ferror(data_out_file)) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		      "Error reading temporary file %s: %s", follow_info->data_out_filename,
		      strerror(errno));
	fclose(data_out_file);
	data_out_file = NULL;
	return FRS_READ_ERROR;
    }

    fclose(data_out_file);
    data_out_file = NULL;
    return FRS_OK;

print_error:
    fclose(data_out_file);
    data_out_file = NULL;
    return FRS_PRINT_ERROR;
}
