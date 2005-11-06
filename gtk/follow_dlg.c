/* follow_dlg.c
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include "keys.h"
#include "globals.h"
#include "main.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include <epan/dissectors/packet-ipv6.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/charsets.h>
#include "util.h"
#include "gui_utils.h"
#include <epan/epan_dissect.h>
#include <epan/filesystem.h>
#include "compat_macros.h"
#include <epan/ipproto.h>
#include "print_mswin.h"
#include "font_utils.h"

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

typedef struct {
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
	gboolean        is_ipv6;
	char		*filter_out_filter;
	GtkWidget	*filter_te;
	GtkWidget	*streamwindow;
} follow_info_t;

static void follow_destroy_cb(GtkWidget * win, gpointer data);
static void follow_charset_toggle_cb(GtkWidget * w, gpointer parent_w);
static void follow_load_text(follow_info_t *follow_info);
static void follow_filter_out_stream(GtkWidget * w, gpointer parent_w);
static void follow_print_stream(GtkWidget * w, gpointer parent_w);
static void follow_save_as_cmd_cb(GtkWidget * w, gpointer data);
static void follow_save_as_ok_cb(GtkWidget * w, gpointer fs);
static void follow_save_as_destroy_cb(GtkWidget * win, gpointer user_data);
static void follow_stream_om_both(GtkWidget * w, gpointer data);
static void follow_stream_om_client(GtkWidget * w, gpointer data);
static void follow_stream_om_server(GtkWidget * w, gpointer data);


/* With MSVC and a libethereal.dll, we need a special declaration. */
ETH_VAR_IMPORT FILE *data_out_file;

#define E_FOLLOW_INFO_KEY "follow_info_key"

/* List of "follow_info_t" structures for all "Follow TCP Stream" windows,
   so we can redraw them all if the colors or font changes. */
static GList *follow_infos;

/* Add a "follow_info_t" structure to the list. */
static void
remember_follow_info(follow_info_t *follow_info)
{
  follow_infos = g_list_append(follow_infos, follow_info);
}

/* Remove a "follow_info_t" structure from the list. */
static void
forget_follow_info(follow_info_t *follow_info)
{
  follow_infos = g_list_remove(follow_infos, follow_info);
}

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
	GtkWidget	*hbox, *button_hbox, *button, *radio_bt;
    GtkWidget   *stream_fr, *stream_vb;
	GtkWidget	*stream_om, *stream_menu, *stream_mi;
	GtkTooltips *tooltips;
	int		    tmp_fd;
	gchar		*follow_filter;
	const gchar	*previous_filter;
    int		    filter_out_filter_len;
	const char	*hostname0, *hostname1;
	char		*port0, *port1;
	char		string[128];
	follow_tcp_stats_t stats;
	follow_info_t	*follow_info;

	/* we got tcp so we can follow */
	if (cfile.edt->pi.ipproto != 6) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			      "Error following stream.  Please make\n"
			      "sure you have a TCP packet selected.");
		return;
	}

	follow_info = g_new0(follow_info_t, 1);

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

	data_out_file = fdopen(tmp_fd, "wb");
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

	/* The data_out_file should now be full of the streams information */
	fclose(data_out_file);

	/* The data_out_filename file now has all the text that was in the session */
	streamwindow = dlg_window_new("Follow TCP stream");

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
#endif
	gtk_container_add(GTK_CONTAINER(txt_scrollw), text);
	follow_info->text = text;


	/* stream hbox */
	hbox = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(stream_vb), hbox, FALSE, FALSE, 0);

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
	  memcpy(&ipaddr, stats.ip_address[0], 16);
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
	g_snprintf(string, sizeof(string), "%s:%s --> %s:%s (%u bytes)",
		 hostname0, port0, hostname1, port1,
		 stats.bytes_written[0]);
	stream_mi = gtk_menu_item_new_with_label(string);
	SIGNAL_CONNECT(stream_mi, "activate", follow_stream_om_client,
                       follow_info);
	gtk_menu_append(GTK_MENU(stream_menu), stream_mi);
	gtk_widget_show(stream_mi);

	/* Host 1 --> Host 0 */
	g_snprintf(string, sizeof(string), "%s:%s --> %s:%s (%u bytes)",
		 hostname1, port1, hostname0, port0,
		 stats.bytes_written[1]);
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

	/* button hbox */
	button_hbox = gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(vbox), button_hbox, FALSE, FALSE, 0);
	gtk_button_box_set_layout (GTK_BUTTON_BOX(button_hbox), GTK_BUTTONBOX_END);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX(button_hbox), 5);

	/* Create exclude stream button */
	button = gtk_button_new_with_label("Filter out this stream");
	SIGNAL_CONNECT(button, "clicked", follow_filter_out_stream, follow_info);
	gtk_tooltips_set_tip (tooltips, button,
        "Build a display filter which cuts this stream from the capture", NULL);
	gtk_box_pack_start(GTK_BOX(button_hbox), button, FALSE, FALSE, 0);

	/* Create Close Button */
	button = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_tooltips_set_tip (tooltips, button,
	    "Close the dialog and keep the current display filter", NULL);
	gtk_box_pack_start(GTK_BOX(button_hbox), button, FALSE, FALSE, 0);
	GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);

	window_set_cancel_button(streamwindow, button, window_cancel_button_cb);

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

/* XXX - can I emulate follow_charset_toggle_cb() instead of having
 * 3 different functions here?
 * That might not be a bad idea, as it might mean we only reload
 * the window once, not twice - see follow_charset_toggle_cb()
 * for an explanation. */
static void
follow_stream_om_both(GtkWidget *w _U_, gpointer data)
{
	follow_info_t	*follow_info = data;
	follow_info->show_stream = BOTH_HOSTS;
	follow_load_text(follow_info);
}

static void
follow_stream_om_client(GtkWidget *w _U_, gpointer data)
{
	follow_info_t	*follow_info = data;
	follow_info->show_stream = FROM_CLIENT;
	follow_load_text(follow_info);
}

static void
follow_stream_om_server(GtkWidget *w _U_, gpointer data)
{
	follow_info_t	*follow_info = data;
	follow_info->show_stream = FROM_SERVER;
	follow_load_text(follow_info);
}


/* Handles the display style toggling */
static void
follow_charset_toggle_cb(GtkWidget * w _U_, gpointer data)
{
	follow_info_t	*follow_info = data;

	/*
	 * A radio button toggles when it goes on and when it goes
	 * off, so when you click a radio button two signals are
	 * delivered.  We only want to reprocess the display once,
	 * so we do it only when the button goes on.
	 */
	if (GTK_TOGGLE_BUTTON(w)->active) {
		if (w == follow_info->ebcdic_bt)
			follow_info->show_type = SHOW_EBCDIC;
		else if (w == follow_info->hexdump_bt)
			follow_info->show_type = SHOW_HEXDUMP;
		else if (w == follow_info->carray_bt)
			follow_info->show_type = SHOW_CARRAY;
		else if (w == follow_info->ascii_bt)
			follow_info->show_type = SHOW_ASCII;
		else if (w == follow_info->raw_bt)
			follow_info->show_type = SHOW_RAW;
		follow_load_text(follow_info);
	}
}

#define FLT_BUF_SIZE 1024

typedef enum {
	FRS_OK,
	FRS_OPEN_ERROR,
	FRS_READ_ERROR,
	FRS_PRINT_ERROR
} frs_return_t;

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
static frs_return_t
follow_read_stream(follow_info_t *follow_info,
		   gboolean (*print_line) (char *, size_t, gboolean, void *),
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
    char                buffer[FLT_BUF_SIZE];
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

    while (fread(&sc, 1, sizeof(sc), data_out_file)) {
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

/*
 * XXX - for text printing, we probably want to wrap lines at 80 characters;
 * (PostScript printing is doing this already), and perhaps put some kind of 
 * dingbat (to use the technical term) to indicate a wrapped line, along the 
 * lines of what's done when displaying this in a window, as per Warren Young's 
 * suggestion.
 */
static gboolean
follow_print_text(char *buffer, size_t nchars, gboolean is_server _U_, void *arg)
{
    print_stream_t *stream = arg;
    size_t i;
    char *str;

    /* convert non printable characters */
    for (i = 0; i < nchars; i++) {
        if (buffer[i] == '\n' || buffer[i] == '\r')
            continue;
        if (! isprint((guchar)buffer[i])) {
            buffer[i] = '.';
        }
    }

    /* convert unterminated char array to a zero terminated string */
    str = g_malloc(nchars + 1);
    memcpy(str, buffer, nchars);
    str[nchars] = 0;
    print_line(stream, /*indent*/ 0, str);
    g_free(str);

    return TRUE;
}

static gboolean
follow_write_raw(char *buffer, size_t nchars, gboolean is_server _U_, void *arg)
{
    FILE *fh = arg;
    size_t nwritten;

    nwritten = fwrite(buffer, 1, nchars, fh);
    if (nwritten != nchars)
	return FALSE;

    return TRUE;
}

static void
follow_filter_out_stream(GtkWidget * w _U_, gpointer data)
{
    follow_info_t	*follow_info = data;

    /* Lock out user from messing with us. (ie. don't free our data!) */
    gtk_widget_set_sensitive(follow_info->streamwindow, FALSE);

    /* Set the display filter. */
    gtk_entry_set_text(GTK_ENTRY(follow_info->filter_te), follow_info->filter_out_filter);

    /* Run the display filter so it goes in effect. */
    main_filter_packets(&cfile, follow_info->filter_out_filter, FALSE);

    /* we force a subsequent close */
    window_destroy(follow_info->streamwindow);

    return;
}

static void
follow_print_stream(GtkWidget * w _U_, gpointer data)
{
    print_stream_t	*stream;
    gboolean		to_file;
    char		*print_dest;
    follow_info_t	*follow_info = data;
#ifdef _WIN32
    gboolean win_printer = FALSE;
#endif

    switch (prefs.pr_dest) {
    case PR_DEST_CMD:
#ifdef _WIN32
        win_printer = TRUE;
        /*XXX should use temp file stuff in util routines */
        print_dest = g_strdup(tmpnam(NULL));
        to_file = TRUE;
#else
        print_dest = prefs.pr_cmd;
        to_file = FALSE;
#endif
        break;
    case PR_DEST_FILE:
        print_dest = prefs.pr_file;
        to_file = TRUE;
        break;
    default:			/* "Can't happen" */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Couldn't figure out where to send the print "
            "job. Check your preferences.");
        return;
    }

    switch (prefs.pr_format) {

    case PR_FMT_TEXT:
      stream = print_stream_text_new(to_file, print_dest);
      break;

    case PR_FMT_PS:
      stream = print_stream_ps_new(to_file, print_dest);
      break;

    default:
      g_assert_not_reached();
      stream = NULL;
    }
    if (stream == NULL) {
        if (to_file) {
            open_failure_alert_box(prefs.pr_file, errno, TRUE);
        } else {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	              "Couldn't run print command %s.", prefs.pr_cmd);
        }
        return;
    }

    if (!print_preamble(stream, cfile.filename))
        goto print_error;

    switch (follow_read_stream(follow_info, follow_print_text, stream)) {
    case FRS_OK:
    	break;
    case FRS_OPEN_ERROR:
    case FRS_READ_ERROR:
	    /* XXX - cancel printing? */
	    destroy_print_stream(stream);
	    return;
    case FRS_PRINT_ERROR:
	    goto print_error;
    }

    if (!print_finale(stream))
	    goto print_error;

    if (!destroy_print_stream(stream)) {
        if (to_file) {
          write_failure_alert_box(prefs.pr_file, errno);
        } else {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			  "Error closing print destination.");
        }
    }
#ifdef _WIN32
    if (win_printer) {
        print_mswin(print_dest);

        /* trash temp file */
        eth_remove(print_dest);
    }
#endif
    return;

print_error:
    if (to_file) {
        write_failure_alert_box(prefs.pr_file, errno);
    } else {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
          "Error writing to print command: %s", strerror(errno));
    }
    /* XXX - cancel printing? */
    destroy_print_stream(stream);

#ifdef _WIN32
    if (win_printer) {
        /* trash temp file */
        eth_remove(print_dest);
    }
#endif
}

/* static variable declarations to speed up the performance
 * of follow_load_text and follow_add_to_gtk_text
 */
static GdkColor server_fg, server_bg;
static GdkColor client_fg, client_bg;
#if GTK_MAJOR_VERSION >= 2
static GtkTextTag *server_tag, *client_tag;
#endif

static gboolean
follow_add_to_gtk_text(char *buffer, size_t nchars, gboolean is_server,
		       void *arg)
{
    GtkWidget *text = arg;
#if GTK_MAJOR_VERSION >= 2
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text));
    GtkTextIter    iter;
#endif

#if GTK_MAJOR_VERSION >= 2 || GTK_MINOR_VERSION >= 3
    /* While our isprint() hack is in place, we
     * have to use convert some chars to '.' in order
     * to be able to see the data we *should* see
     * in the GtkText widget.
     */
    size_t i;

    for (i = 0; i < nchars; i++) {
        if (buffer[i] == '\n' || buffer[i] == '\r')
            continue;
        if (! isprint(buffer[i])) {
            buffer[i] = '.';
        }
    }
#endif

#if GTK_MAJOR_VERSION < 2
    if (is_server) {
	gtk_text_insert(GTK_TEXT(text), user_font_get_regular(), &server_fg, 
			&server_bg, buffer, nchars);
    } else {
	gtk_text_insert(GTK_TEXT(text), user_font_get_regular(), &client_fg, 
			&client_bg, buffer, nchars);
    }
#else
    gtk_text_buffer_get_end_iter(buf, &iter);
    if (is_server) {
	gtk_text_buffer_insert_with_tags(buf, &iter, buffer, nchars, 
					server_tag, NULL);
    } else {
	gtk_text_buffer_insert_with_tags(buf, &iter, buffer, nchars, 
					client_tag, NULL);
    }
#endif
    return TRUE;
}

static void
follow_load_text(follow_info_t *follow_info)
{
#if GTK_MAJOR_VERSION < 2
    int bytes_already;
#else
    GtkTextBuffer *buf;

    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(follow_info->text));
#endif

    /* prepare colors one time for repeated use by follow_add_to_gtk_text */
    color_t_to_gdkcolor(&server_fg, &prefs.st_server_fg);
    color_t_to_gdkcolor(&server_bg, &prefs.st_server_bg);
    color_t_to_gdkcolor(&client_fg, &prefs.st_client_fg);
    color_t_to_gdkcolor(&client_bg, &prefs.st_client_bg);

    /* Delete any info already in text box */
#if GTK_MAJOR_VERSION < 2
    bytes_already = gtk_text_get_length(GTK_TEXT(follow_info->text));
    if (bytes_already > 0) {
	gtk_text_set_point(GTK_TEXT(follow_info->text), 0);
	gtk_text_forward_delete(GTK_TEXT(follow_info->text), bytes_already);
    }

    /* stop the updates while we fill the text box */
    gtk_text_freeze(GTK_TEXT(follow_info->text));
#else
    /* prepare tags one time for repeated use by follow_add_to_gtk_text */
    server_tag = gtk_text_buffer_create_tag(buf, NULL, "foreground-gdk", &server_fg,
                                     "background-gdk", &server_bg, "font-desc",
                                     user_font_get_regular(), NULL);
    client_tag = gtk_text_buffer_create_tag(buf, NULL, "foreground-gdk", &client_fg,
                                     "background-gdk", &client_bg, "font-desc",
                                     user_font_get_regular(), NULL);

    gtk_text_buffer_set_text(buf, "", -1);
#endif
    follow_read_stream(follow_info, follow_add_to_gtk_text, follow_info->text);
#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(GTK_TEXT(follow_info->text));
#endif
}


/*
 * Keep a static pointer to the current "Save TCP Follow Stream As" window, if
 * any, so that if somebody tries to do "Save"
 * while there's already a "Save TCP Follow Stream" window up, we just pop
 * up the existing one, rather than creating a new one.
 */
static void
follow_save_as_cmd_cb(GtkWidget *w _U_, gpointer data)
{
    GtkWidget		*new_win;
    follow_info_t	*follow_info = data;

    if (follow_info->follow_save_as_w != NULL) {
	/* There's already a dialog box; reactivate it. */
	reactivate_window(follow_info->follow_save_as_w);
	return;
    }

    new_win = file_selection_new("Ethereal: Save TCP Follow Stream As",
                                 FILE_SELECTION_SAVE);
    follow_info->follow_save_as_w = new_win;

    /* Tuck away the follow_info object into the window */
    OBJECT_SET_DATA(new_win, E_FOLLOW_INFO_KEY, follow_info);

    SIGNAL_CONNECT(new_win, "destroy", follow_save_as_destroy_cb, follow_info);

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
    if (gtk_dialog_run(GTK_DIALOG(new_win)) == GTK_RESPONSE_ACCEPT)
    {
        follow_save_as_ok_cb(new_win, new_win);
    } else {
        window_destroy(new_win);
    }
#else
    /* Connect the ok_button to file_save_as_ok_cb function and pass along a
       pointer to the file selection box widget */
    SIGNAL_CONNECT(GTK_FILE_SELECTION(new_win)->ok_button, 
        "clicked", follow_save_as_ok_cb, new_win);

    window_set_cancel_button(new_win, 
        GTK_FILE_SELECTION(new_win)->cancel_button, window_cancel_button_cb);

    gtk_file_selection_set_filename(GTK_FILE_SELECTION(new_win), "");

    SIGNAL_CONNECT(new_win, "delete_event", window_delete_event_cb, NULL);

    gtk_widget_show_all(new_win);
    window_present(new_win);
#endif
}


static void
follow_save_as_ok_cb(GtkWidget * w _U_, gpointer fs)
{
    gchar		*to_name;
    follow_info_t	*follow_info;
    FILE		*fh;
    print_stream_t	*stream = NULL;
    gchar		*dirname;

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
    to_name = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs)));
#else
    to_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
#endif

    /* Perhaps the user specified a directory instead of a file.
       Check whether they did. */
    if (test_for_directory(to_name) == EISDIR) {
        /* It's a directory - set the file selection box to display that
           directory, and leave the selection box displayed. */
        set_last_open_dir(to_name);
        g_free(to_name);
        file_selection_set_current_folder(fs, get_last_open_dir());
        return;
    }

    follow_info = OBJECT_GET_DATA(fs, E_FOLLOW_INFO_KEY);
    if (follow_info->show_type == SHOW_RAW) {
        /* Write the data out as raw binary data */
        fh = eth_fopen(to_name, "wb");
    } else {
        /* Write it out as text */
        fh = eth_fopen(to_name, "w");
    }
    if (fh == NULL) {
        open_failure_alert_box(to_name, errno, TRUE);
        g_free(to_name);
        return;
    }

    gtk_widget_hide(GTK_WIDGET(fs));
    window_destroy(GTK_WIDGET(fs));

    if (follow_info->show_type == SHOW_RAW) {
        switch (follow_read_stream(follow_info, follow_write_raw, fh)) {
        case FRS_OK:
            if (fclose(fh) == EOF)
                write_failure_alert_box(to_name, errno);
            break;

        case FRS_OPEN_ERROR:
        case FRS_READ_ERROR:
            fclose(fh);
            break;

        case FRS_PRINT_ERROR:
            write_failure_alert_box(to_name, errno);
            fclose(fh);
            break;
        }
    } else {
	stream = print_stream_text_stdio_new(fh);
	switch (follow_read_stream(follow_info, follow_print_text, stream)) {
        case FRS_OK:
            if (!destroy_print_stream(stream))
                write_failure_alert_box(to_name, errno);
            break;

        case FRS_OPEN_ERROR:
        case FRS_READ_ERROR:
            destroy_print_stream(stream);
            break;

        case FRS_PRINT_ERROR:
            write_failure_alert_box(to_name, errno);
            destroy_print_stream(stream);
            break;
        }
    }

    /* Save the directory name for future file dialogs. */
    dirname = get_dirname(to_name);  /* Overwrites to_name */
    set_last_open_dir(dirname);
    g_free(to_name);
}

static void
follow_save_as_destroy_cb(GtkWidget * win _U_, gpointer data)
{
	follow_info_t	*follow_info = data;

	/* Note that we no longer have a dialog box. */
	follow_info->follow_save_as_w = NULL;
}
