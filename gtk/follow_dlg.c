/* follow_dlg.c
 *
 * $Id: follow_dlg.c,v 1.5 2000/08/11 22:18:22 deniel Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_IO_H
#include <io.h>			/* open/close on win32 */
#endif

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "file.h"
#include "follow_dlg.h"
#include "follow.h"
#include "dlg_utils.h"
#include "keys.h"
#include "globals.h"
#include "gtkglobals.h"
#include "main.h"
#include "simple_dialog.h"
#include "packet-ipv6.h"
#include "prefs.h"
#include "resolv.h"
#include "util.h"
#include "ui_util.h"

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
	SHOW_HEXDUMP
} show_type_t;

typedef struct {
	show_stream_t	show_stream;
	show_type_t	show_type;
	char		data_out_filename[128 + 1];
	GtkWidget	*text;
	GtkWidget	*ascii_bt;
	GtkWidget	*ebcdic_bt;
	GtkWidget	*hexdump_bt;
	GtkWidget	*follow_save_as_w;
	gboolean        is_ipv6;
} follow_info_t;

static void follow_destroy_cb(GtkWidget * win, gpointer data);
static void follow_charset_toggle_cb(GtkWidget * w, gpointer parent_w);
static void follow_load_text(follow_info_t *follow_info);
static void follow_print_stream(GtkWidget * w, gpointer parent_w);
static void follow_save_as_cmd_cb(GtkWidget * w, gpointer data);
static void follow_save_as_ok_cb(GtkWidget * w, GtkFileSelection * fs);
static void follow_save_as_destroy_cb(GtkWidget * win, gpointer user_data);
static void follow_stream_om_both(GtkWidget * w, gpointer data);
static void follow_stream_om_client(GtkWidget * w, gpointer data);
static void follow_stream_om_server(GtkWidget * w, gpointer data);


FILE *data_out_file = NULL;


#define E_FOLLOW_INFO_KEY "follow_info_key"

/* Follow the TCP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
follow_stream_cb(GtkWidget * w, gpointer data)
{
	GtkWidget	*streamwindow, *vbox, *txt_scrollw, *text, *filter_te;
	GtkWidget	*hbox, *button, *radio_bt;
	GtkWidget	*stream_om, *stream_menu, *stream_mi;
	int		tmp_fd;
	gchar		*follow_filter;
	char		*hostname0, *hostname1;
	char		*port0, *port1;
	char		string[128];
	follow_tcp_stats_t stats;
	follow_info_t	*follow_info;

	/* we got tcp so we can follow */
	if (pi.ipproto != 6) {
		simple_dialog(ESD_TYPE_CRIT, NULL,
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
	    simple_dialog(ESD_TYPE_WARN, NULL,
			  "Could not create temporary file %s: %s",
			  follow_info->data_out_filename, strerror(errno));
	    g_free(follow_info);
	    return;
	}

	data_out_file = fdopen(tmp_fd, "wb");
	if (data_out_file == NULL) {
	    simple_dialog(ESD_TYPE_WARN, NULL,
			  "Could not create temporary file %s: %s",
			  follow_info->data_out_filename, strerror(errno));
	    close(tmp_fd);
	    unlink(follow_info->data_out_filename);
	    g_free(follow_info);
	    return;
	}

	/* Create a new filter that matches all packets in the TCP stream,
	   and set the display filter entry accordingly */
	reset_tcp_reassembly();
	follow_filter = build_follow_filter(&pi);

	/* Set the display filter entry accordingly */
	filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);
	gtk_entry_set_text(GTK_ENTRY(filter_te), follow_filter);

	/* Run the display filter so it goes in effect. */
	filter_packets(&cfile, follow_filter);

	/* The data_out_file should now be full of the streams information */
	fclose(data_out_file);

	/* The data_out_filename file now has all the text that was in the session */
	streamwindow = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_widget_set_name(streamwindow, "TCP stream window");

	gtk_signal_connect(GTK_OBJECT(streamwindow), "destroy",
			   GTK_SIGNAL_FUNC(follow_destroy_cb), NULL);

	if (incomplete_tcp_stream) {
	    gtk_window_set_title(GTK_WINDOW(streamwindow),
				 "Contents of TCP stream (incomplete)");
	} else {
	    gtk_window_set_title(GTK_WINDOW(streamwindow),
				 "Contents of TCP stream");
	}
	gtk_widget_set_usize(GTK_WIDGET(streamwindow), DEF_WIDTH,
			     DEF_HEIGHT);
	gtk_container_border_width(GTK_CONTAINER(streamwindow), 2);

	/* setup the container */
	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(streamwindow), vbox);

	/* create a scrolled window for the text */
	txt_scrollw = gtk_scrolled_window_new(NULL, NULL);
	gtk_box_pack_start(GTK_BOX(vbox), txt_scrollw, TRUE, TRUE, 0);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
				       GTK_POLICY_NEVER,
				       GTK_POLICY_ALWAYS);
	set_scrollbar_placement_scrollw(txt_scrollw,
					prefs.gui_scrollbar_on_right);
	remember_scrolled_window(txt_scrollw);

	/* create a text box */
	text = gtk_text_new(NULL, NULL);
	gtk_text_set_editable(GTK_TEXT(text), FALSE);
	gtk_container_add(GTK_CONTAINER(txt_scrollw), text);
	follow_info->text = text;

	/* Create hbox */
	hbox = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);


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

	/* Both Hosts */
	snprintf(string, sizeof(string),
		 "Entire conversation (%u bytes)",
		 stats.bytes_written[0] + stats.bytes_written[1]);
	stream_mi = gtk_menu_item_new_with_label(string);
	gtk_signal_connect(GTK_OBJECT(stream_mi), "activate",
			   GTK_SIGNAL_FUNC(follow_stream_om_both), follow_info);
	gtk_menu_append(GTK_MENU(stream_menu), stream_mi);
	gtk_widget_show(stream_mi);
	follow_info->show_stream = BOTH_HOSTS;

	/* Host 0 --> Host 1 */
	snprintf(string, sizeof(string), "%s:%s --> %s:%s (%u bytes)",
		 hostname0, port0, hostname1, port1,
		 stats.bytes_written[0]);
	stream_mi = gtk_menu_item_new_with_label(string);
	gtk_signal_connect(GTK_OBJECT(stream_mi), "activate",
			   GTK_SIGNAL_FUNC(follow_stream_om_client), follow_info);
	gtk_menu_append(GTK_MENU(stream_menu), stream_mi);
	gtk_widget_show(stream_mi);

	/* Host 1 --> Host 0 */
	snprintf(string, sizeof(string), "%s:%s --> %s:%s (%u bytes)",
		 hostname1, port1, hostname0, port0,
		 stats.bytes_written[1]);
	stream_mi = gtk_menu_item_new_with_label(string);
	gtk_signal_connect(GTK_OBJECT(stream_mi), "activate",
			   GTK_SIGNAL_FUNC(follow_stream_om_server), follow_info);
	gtk_menu_append(GTK_MENU(stream_menu), stream_mi);
	gtk_widget_show(stream_mi);

	gtk_option_menu_set_menu(GTK_OPTION_MENU(stream_om), stream_menu);
	/* Set history to 0th item, i.e., the first item. */
	gtk_option_menu_set_history(GTK_OPTION_MENU(stream_om), 0);
	gtk_box_pack_start(GTK_BOX(hbox), stream_om, FALSE, FALSE, 0);

	/* ASCII radio button */
	radio_bt = gtk_radio_button_new_with_label(NULL, "ASCII");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), TRUE);
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
	gtk_signal_connect(GTK_OBJECT(radio_bt), "toggled",
			   GTK_SIGNAL_FUNC(follow_charset_toggle_cb),
			   follow_info);
	follow_info->ascii_bt = radio_bt;
	follow_info->show_type = SHOW_ASCII;

	/* EBCDIC radio button */
	radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_group
					    (GTK_RADIO_BUTTON(radio_bt)),
					    "EBCDIC");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), FALSE);
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
	gtk_signal_connect(GTK_OBJECT(radio_bt), "toggled",
			   GTK_SIGNAL_FUNC(follow_charset_toggle_cb),
			   follow_info);
	follow_info->ebcdic_bt = radio_bt;

	/* HEX DUMP radio button */
	radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_group
					    (GTK_RADIO_BUTTON(radio_bt)),
					    "Hex Dump");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), FALSE);
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
	gtk_signal_connect(GTK_OBJECT(radio_bt), "toggled",
			   GTK_SIGNAL_FUNC(follow_charset_toggle_cb),
			   follow_info);
	follow_info->hexdump_bt = radio_bt;

	/* Create Close Button */
	button = gtk_button_new_with_label("Close");
	gtk_signal_connect_object(GTK_OBJECT(button), "clicked",
				  GTK_SIGNAL_FUNC(gtk_widget_destroy),
				  GTK_OBJECT(streamwindow));
	gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, FALSE, 0);

	/* Catch the "key_press_event" signal in the window, so that we can catch
	the ESC key being pressed and act as if the "Cancel" button had
	been selected. */
	dlg_set_cancel(streamwindow, button);

	/* Create Save As Button */
	button = gtk_button_new_with_label("Save As");
	gtk_signal_connect(GTK_OBJECT(button), "clicked",
			   GTK_SIGNAL_FUNC(follow_save_as_cmd_cb),
			   follow_info);
	gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, FALSE, 0);

	/* Create Print Button */
	button = gtk_button_new_with_label("Print");
	gtk_signal_connect(GTK_OBJECT(button), "clicked",
			   GTK_SIGNAL_FUNC(follow_print_stream), follow_info);
	gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, FALSE, 0);


	/* Tuck away the follow_info object into the window */
	gtk_object_set_data(GTK_OBJECT(streamwindow), E_FOLLOW_INFO_KEY,
			    follow_info);

	follow_load_text(follow_info);

	data_out_file = NULL;

	/* Make sure this widget gets destroyed if we quit the main loop,
	   so that if we exit, we clean up any temporary files we have
	   for "Follow TCP Stream" windows. */
	gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(streamwindow));
	gtk_widget_show_all(streamwindow);
}

/* The destroy call back has the responsibility of
 * unlinking the temporary file */
static void
follow_destroy_cb(GtkWidget *w, gpointer data)
{
	follow_info_t	*follow_info;

	follow_info = gtk_object_get_data(GTK_OBJECT(w), E_FOLLOW_INFO_KEY);
	unlink(follow_info->data_out_filename);
	gtk_widget_destroy(w);
	g_free(follow_info);
}

/* XXX - can I emulate follow_charset_toggle_cb() instead of having
 * 3 different functions here? */
static void
follow_stream_om_both(GtkWidget *w, gpointer data)
{
	follow_info_t	*follow_info = data;
	follow_info->show_stream = BOTH_HOSTS;
	follow_load_text(follow_info);
}

static void
follow_stream_om_client(GtkWidget *w, gpointer data)
{
	follow_info_t	*follow_info = data;
	follow_info->show_stream = FROM_CLIENT;
	follow_load_text(follow_info);
}

static void
follow_stream_om_server(GtkWidget *w, gpointer data)
{
	follow_info_t	*follow_info = data;
	follow_info->show_stream = FROM_SERVER;
	follow_load_text(follow_info);
}


/* Handles the ASCII/EBCDIC toggling */
static void
follow_charset_toggle_cb(GtkWidget * w, gpointer data)
{
	follow_info_t	*follow_info = data;

	if (GTK_TOGGLE_BUTTON(follow_info->ebcdic_bt)->active)
		follow_info->show_type = SHOW_EBCDIC;
	else if (GTK_TOGGLE_BUTTON(follow_info->hexdump_bt)->active)
		follow_info->show_type = SHOW_HEXDUMP;
	else if (GTK_TOGGLE_BUTTON(follow_info->ascii_bt)->active)
		follow_info->show_type = SHOW_ASCII;
	else
		g_assert_not_reached();

	follow_load_text(follow_info);
}

#define FLT_BUF_SIZE 1024
static void
follow_read_stream(follow_info_t *follow_info,
		   void (*print_line) (char *, int, gboolean, void *),
		   void *arg)
{
    tcp_stream_chunk	sc;
    int			bcount, iplen;
    guint8		client_addr[MAX_IPADDR_LEN];
    guint16		client_port = 0;
    gboolean		is_server;
    guint16		current_pos, global_client_pos = 0, global_server_pos = 0;
    guint16		*global_pos;
    gboolean		skip;

    iplen = (follow_info->is_ipv6) ? 16 : 4;
     
    data_out_file = fopen(follow_info->data_out_filename, "rb");
    if (data_out_file) {
	char buffer[FLT_BUF_SIZE];
	int nchars;
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
		sc.dlen -= bcount;
		if (!skip) {
		    switch (follow_info->show_type) {
			case SHOW_EBCDIC:
			    /* If our native arch is ASCII, call: */
			    EBCDIC_to_ASCII(buffer, nchars);
			    (*print_line) (buffer, nchars, is_server, arg);
			    break;
			case SHOW_ASCII:
			    /* If our native arch is EBCDIC, call:
			     * ASCII_TO_EBCDIC(buffer, nchars);
			     */
			    (*print_line) (buffer, nchars, is_server, arg);
			    break;
			case SHOW_HEXDUMP:
			    current_pos = 0;
			    while (current_pos < nchars) {
				gchar hexbuf[256];
				gchar hexchars[] = "0123456789abcdef";
				int i, cur;
				/* is_server indentation : put 63 spaces at the begenning
				 * of the string */
				sprintf(hexbuf, is_server ?
					"                                 "
					"                              %08X  " :
					"%08X  ", *global_pos);
				cur = strlen(hexbuf);
				for (i = 0; i < 16 && current_pos + i < nchars;
				     i++) {
				    hexbuf[cur++] =
					hexchars[(buffer[current_pos + i] & 0xf0)
						 >> 4];
				    hexbuf[cur++] =
					hexchars[buffer[current_pos + i] & 0x0f];
				    if (i == 7) {
					hexbuf[cur++] = ' ';
					hexbuf[cur++] = ' ';
				    } else if (i != 15)
					hexbuf[cur++] = ' ';
				}
				current_pos += i;
				(*global_pos) += i;
				hexbuf[cur++] = '\n';
				hexbuf[cur] = 0;
				(*print_line) (hexbuf, strlen(hexbuf), is_server, arg);
			    }
			    break;
		    }
		}
	    }
	}
	if (ferror(data_out_file)) {
	    simple_dialog(ESD_TYPE_WARN, NULL,
			  "Error reading temporary file %s: %s", follow_info->data_out_filename,
			  strerror(errno));
	}
	fclose(data_out_file);
	data_out_file = NULL;
    } else {
	simple_dialog(ESD_TYPE_WARN, NULL,
		      "Could not open temporary file %s: %s", follow_info->data_out_filename,
		      strerror(errno));
    }
}

/*
 * XXX - for text printing, we probably want to wrap lines at 80 characters;
 * for PostScript printing, we probably want to wrap them at the appropriate
 * width, and perhaps put some kind of dingbat (to use the technical term)
 * to indicate a wrapped line, along the lines of what's done when displaying
 * this in a window, as per Warren Young's suggestion.
 *
 * For now, we support only text printing.
 */
static void
follow_print_text(char *buffer, int nchars, gboolean is_server, void *arg)
{
    FILE *fh = arg;

    fwrite(buffer, nchars, 1, fh);
}

static void
follow_print_stream(GtkWidget * w, gpointer data)
{
    FILE		*fh;
    gboolean		to_file;
    char		*print_dest;
    follow_info_t	*follow_info = data;

    switch (prefs.pr_dest) {
    case PR_DEST_CMD:
	print_dest = prefs.pr_cmd;
	to_file = FALSE;
	break;

    case PR_DEST_FILE:
	print_dest = prefs.pr_file;
	to_file = TRUE;
	break;
    default:			/* "Can't happen" */
	simple_dialog(ESD_TYPE_CRIT, NULL,
		      "Couldn't figure out where to send the print "
		      "job. Check your preferences.");
	return;
    }

    fh = open_print_dest(to_file, print_dest);
    if (fh == NULL) {
	switch (to_file) {
	case FALSE:
	    simple_dialog(ESD_TYPE_WARN, NULL,
			  "Couldn't run print command %s.", prefs.pr_cmd);
	    break;

	case TRUE:
	    simple_dialog(ESD_TYPE_WARN, NULL,
			  file_write_error_message(errno), prefs.pr_file);
	    break;
	}
	return;
    }

    print_preamble(fh, PR_FMT_TEXT);
    follow_read_stream(follow_info, follow_print_text, fh);
    print_finale(fh, PR_FMT_TEXT);
    close_print_dest(to_file, fh);
}

static void
follow_add_to_gtk_text(char *buffer, int nchars, gboolean is_server,
		       void *arg)
{
    GtkWidget *text = arg;

    if (is_server)
	gtk_text_insert(GTK_TEXT(text), m_r_font, &prefs.st_server_fg,
			&prefs.st_server_bg, buffer, nchars);
    else
	gtk_text_insert(GTK_TEXT(text), m_r_font, &prefs.st_client_fg,
			&prefs.st_client_bg, buffer, nchars);
}

static void
follow_load_text(follow_info_t *follow_info)
{
    int bytes_already;

    /* Delete any info already in text box */
    bytes_already = gtk_text_get_length(GTK_TEXT(follow_info->text));
    if (bytes_already > 0) {
	gtk_text_set_point(GTK_TEXT(follow_info->text), 0);
	gtk_text_forward_delete(GTK_TEXT(follow_info->text), bytes_already);
    }

    /* stop the updates while we fill the text box */
    gtk_text_freeze(GTK_TEXT(follow_info->text));
    follow_read_stream(follow_info, follow_add_to_gtk_text, follow_info->text);
    gtk_text_thaw(GTK_TEXT(follow_info->text));
}


/*
 * Keep a static pointer to the current "Save TCP Follow Stream As" window, if
 * any, so that if somebody tries to do "Save"
 * while there's already a "Save TCP Follow Stream" window up, we just pop
 * up the existing one, rather than creating a new one.
 */
static void
follow_save_as_cmd_cb(GtkWidget *w, gpointer data)
{
    GtkWidget		*ok_bt, *new_win;
    follow_info_t	*follow_info = data;

    if (follow_info->follow_save_as_w != NULL) {
	/* There's already a dialog box; reactivate it. */
	reactivate_window(follow_info->follow_save_as_w);
	return;
    }

    new_win = gtk_file_selection_new("Ethereal: Save TCP Follow Stream As");
    follow_info->follow_save_as_w = new_win;
    gtk_signal_connect(GTK_OBJECT(new_win), "destroy",
		    GTK_SIGNAL_FUNC(follow_save_as_destroy_cb), follow_info);

    /* Tuck away the follow_info object into the window */
    gtk_object_set_data(GTK_OBJECT(new_win), E_FOLLOW_INFO_KEY,
			    follow_info);

    /* If we've opened a file, start out by showing the files in the directory
       in which that file resided. */
    if (last_open_dir)
	gtk_file_selection_complete(GTK_FILE_SELECTION(new_win),
				    last_open_dir);

    /* Connect the ok_button to file_save_as_ok_cb function and pass along a
       pointer to the file selection box widget */
    ok_bt = GTK_FILE_SELECTION(new_win)->ok_button;
    gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
		       (GtkSignalFunc) follow_save_as_ok_cb,
		       new_win);

    /* Connect the cancel_button to destroy the widget */
    gtk_signal_connect_object(GTK_OBJECT(GTK_FILE_SELECTION
					 (new_win)->cancel_button),
			      "clicked",
			      (GtkSignalFunc) gtk_widget_destroy,
			      GTK_OBJECT(new_win));

    /* Catch the "key_press_event" signal in the window, so that we can catch
       the ESC key being pressed and act as if the "Cancel" button had
       been selected. */
    dlg_set_cancel(new_win,
		   GTK_FILE_SELECTION(new_win)->cancel_button);

    gtk_file_selection_set_filename(GTK_FILE_SELECTION(new_win), "");
    gtk_widget_show_all(new_win);
}


static void
follow_save_as_ok_cb(GtkWidget * w, GtkFileSelection * fs)
{
	gchar		*to_name;
	follow_info_t	*follow_info;
	FILE		*fh;

	to_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));

	gtk_widget_hide(GTK_WIDGET(fs));
	follow_info = gtk_object_get_data(GTK_OBJECT(fs), E_FOLLOW_INFO_KEY);
	gtk_widget_destroy(GTK_WIDGET(fs));

	fh = fopen(to_name, "wb");
	if (fh == NULL) {
		simple_dialog(ESD_TYPE_WARN, NULL,
			file_write_error_message(errno), to_name);
		return;
	}

	follow_read_stream(follow_info, follow_print_text, fh);
	fclose(fh);
	g_free(to_name);
}

static void
follow_save_as_destroy_cb(GtkWidget * win, gpointer data)
{
	follow_info_t	*follow_info = data;

	/* Note that we no longer have a dialog box. */
	follow_info->follow_save_as_w = NULL;
}
