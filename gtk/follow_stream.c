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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>

#include <gtk/gtk.h>

#include <epan/addr_resolv.h>
#include <epan/follow.h>
#include <epan/filesystem.h>
#include <epan/prefs.h>
#include <epan/charsets.h>

#include <../alert_box.h>
#include <../isprint.h>
#include <../print.h>
#include <../simple_dialog.h>
#include <wsutil/file_util.h>

#include <gtk/color_utils.h>
#include <gtk/stock_icons.h>
#include <gtk/dlg_utils.h>
#include <gtk/follow_stream.h>
#include <gtk/font_utils.h>
#include <gtk/file_dlg.h>
#include <gtk/gui_utils.h>
#include <gtk/help_dlg.h>
#include "gtk/main.h"
#include "gtk/old-gtk-compat.h"

#ifdef _WIN32
#include "../tempfile.h"
#include "win32/print_win32.h"
#endif

/* static variable declarations to speed up the performance
 * of follow_load_text and follow_add_to_gtk_text
 */
static GdkColor server_fg, server_bg;
static GdkColor client_fg, client_bg;
static GtkTextTag *server_tag, *client_tag;

static void follow_find_destroy_cb(GtkWidget * win _U_, gpointer data);
static void follow_find_button_cb(GtkWidget * w, gpointer data);
static gboolean follow_save_as_ok_cb(GtkWidget * w _U_, gpointer fs);
static void follow_destroy_cb(GtkWidget *w, gpointer data _U_);
static void follow_save_as_destroy_cb(GtkWidget * win _U_, gpointer data);

GList *follow_infos = NULL;

static frs_return_t
follow_read_stream(follow_info_t *follow_info,
		   gboolean (*print_line_fcn_p)(char *, size_t, gboolean, void *),
		   void *arg)
{
	switch(follow_info->follow_type) {

	case FOLLOW_TCP :
		return follow_read_tcp_stream(follow_info, print_line_fcn_p, arg);

	case FOLLOW_UDP :
		return follow_read_udp_stream(follow_info, print_line_fcn_p, arg);

	case FOLLOW_SSL :
		return follow_read_ssl_stream(follow_info, print_line_fcn_p, arg);

	default :
		g_assert_not_reached();
		return 0;
	}
}

gboolean
follow_add_to_gtk_text(char *buffer, size_t nchars, gboolean is_server,
		       void *arg)
{
	GtkWidget *text = arg;
	GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text));
	GtkTextIter    iter;

	/* While our isprint() hack is in place, we
	 * have to convert some chars to '.' in order
	 * to be able to see the data we *should* see
	 * in the GtkText widget.
	 */
	size_t i;

	for (i = 0; i < nchars; i++) {
		if (buffer[i] == '\n' || buffer[i] == '\r')
			continue;
		if (! isprint((guchar)buffer[i])) {
			buffer[i] = '.';
		}
	}

	gtk_text_buffer_get_end_iter(buf, &iter);
	if (is_server) {
		gtk_text_buffer_insert_with_tags(buf, &iter, buffer, (gint) nchars,
						 server_tag, NULL);
	} else {
		gtk_text_buffer_insert_with_tags(buf, &iter, buffer, (gint) nchars,
						 client_tag, NULL);
	}
	return TRUE;
}

/*
 * XXX - for text printing, we probably want to wrap lines at 80 characters;
 * (PostScript printing is doing this already), and perhaps put some kind of
 * dingbat (to use the technical term) to indicate a wrapped line, along the
 * lines of what's done when displaying this in a window, as per Warren Young's
 * suggestion.
 */
static gboolean
follow_print_text(char *buffer, size_t nchars, gboolean is_server _U_,
		  void *arg)
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
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w))) {
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

void
follow_load_text(follow_info_t *follow_info)
{
	GtkTextBuffer *buf;

	buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(follow_info->text));

	/* prepare colors one time for repeated use by follow_add_to_gtk_text */
	color_t_to_gdkcolor(&server_fg, &prefs.st_server_fg);
	color_t_to_gdkcolor(&server_bg, &prefs.st_server_bg);
	color_t_to_gdkcolor(&client_fg, &prefs.st_client_fg);
	color_t_to_gdkcolor(&client_bg, &prefs.st_client_bg);

	/* prepare tags one time for repeated use by follow_add_to_gtk_text */
	server_tag = gtk_text_buffer_create_tag(buf, NULL, "foreground-gdk",
						&server_fg, "background-gdk",
						&server_bg, "font-desc",
						user_font_get_regular(), NULL);
	client_tag = gtk_text_buffer_create_tag(buf, NULL, "foreground-gdk",
						&client_fg, "background-gdk",
						&client_bg, "font-desc",
						user_font_get_regular(), NULL);

	/* Delete any info already in text box */
	gtk_text_buffer_set_text(buf, "", -1);

	follow_read_stream(follow_info, follow_add_to_gtk_text,
			   follow_info->text);
}

void
follow_filter_out_stream(GtkWidget * w _U_, gpointer data)
{
	follow_info_t	*follow_info = data;

	/* Lock out user from messing with us. (ie. don't free our data!) */
	gtk_widget_set_sensitive(follow_info->streamwindow, FALSE);

	/* Set the display filter. */
	gtk_entry_set_text(GTK_ENTRY(follow_info->filter_te),
			   follow_info->filter_out_filter);

	/* Run the display filter so it goes in effect. */
	main_filter_packets(&cfile, follow_info->filter_out_filter, FALSE);

	/* we force a subsequent close */
	window_destroy(follow_info->streamwindow);

	return;
}

static void
follow_find_cb(GtkWidget * w _U_, gpointer data)
{
	follow_info_t      	*follow_info = data;
	GtkWidget		*find_dlg_w, *main_vb, *buttons_row, *find_lb;
	GtkWidget		*find_hb, *find_text_box, *find_bt, *cancel_bt;

	if (follow_info->find_dlg_w != NULL) {
		/* There's already a dialog box; reactivate it. */
		reactivate_window(follow_info->find_dlg_w);
		return;
	}

	/* Create the find box */
	find_dlg_w = dlg_window_new("Wireshark: Find text");
	gtk_window_set_transient_for(GTK_WINDOW(find_dlg_w),
				     GTK_WINDOW(follow_info->streamwindow));
	gtk_window_set_destroy_with_parent(GTK_WINDOW(find_dlg_w), TRUE);
	follow_info->find_dlg_w = find_dlg_w;

	g_signal_connect(find_dlg_w, "destroy", G_CALLBACK(follow_find_destroy_cb),
		       follow_info);
	g_signal_connect(find_dlg_w, "delete_event", G_CALLBACK(window_delete_event_cb),
		       NULL);

	/* Main vertical box */
	main_vb = gtk_vbox_new(FALSE, 3);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
	gtk_container_add(GTK_CONTAINER(find_dlg_w), main_vb);

	/* Horizontal box for find label, entry field and up/down radio
	   buttons */
	find_hb = gtk_hbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(main_vb), find_hb);
	gtk_widget_show(find_hb);

	/* Find label */
	find_lb = gtk_label_new("Find text:");
	gtk_box_pack_start(GTK_BOX(find_hb), find_lb, FALSE, FALSE, 0);
	gtk_widget_show(find_lb);

	/* Find field */
	find_text_box = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(find_hb), find_text_box, FALSE, FALSE, 0);
	gtk_widget_set_tooltip_text(find_text_box, "Text to search for (case sensitive)");
	gtk_widget_show(find_text_box);

	/* Buttons row */
	buttons_row = dlg_button_row_new(GTK_STOCK_FIND, GTK_STOCK_CANCEL,
					 NULL);
	gtk_container_add(GTK_CONTAINER(main_vb), buttons_row);
	find_bt = g_object_get_data(G_OBJECT(buttons_row), GTK_STOCK_FIND);
	cancel_bt = g_object_get_data(G_OBJECT(buttons_row), GTK_STOCK_CANCEL);

	g_signal_connect(find_bt, "clicked", G_CALLBACK(follow_find_button_cb), follow_info);
	g_object_set_data(G_OBJECT(find_bt), "find_string", find_text_box);
	window_set_cancel_button(find_dlg_w, cancel_bt,
				 window_cancel_button_cb);

	/* Hitting return in the find field "clicks" the find button */
	dlg_set_activate(find_text_box, find_bt);

	/* Show the dialog */
	gtk_widget_show_all(find_dlg_w);
	window_present(find_dlg_w);
}

static void
follow_find_button_cb(GtkWidget * w, gpointer data)
{
	gboolean		found;
	const gchar		*find_string;
	follow_info_t	*follow_info = data;
	GtkTextBuffer	*buffer;
	GtkTextIter		iter, match_start, match_end;
	GtkTextMark		*last_pos_mark;
	GtkWidget		*find_string_w;

	/* Get the text the user typed into the find field */
	find_string_w = (GtkWidget *)g_object_get_data(G_OBJECT(w), "find_string");
	find_string = gtk_entry_get_text(GTK_ENTRY(find_string_w));

	/* Get the buffer associated with the follow stream */
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(follow_info->text));
	gtk_text_buffer_get_start_iter(buffer, &iter);

	/* Look for the search string in the buffer */
	last_pos_mark = gtk_text_buffer_get_mark(buffer, "last_position");
	if(last_pos_mark)
		gtk_text_buffer_get_iter_at_mark(buffer, &iter, last_pos_mark);

	found = gtk_text_iter_forward_search(&iter, find_string, 0,
					     &match_start,
					     &match_end,
					     NULL);

	if(found) {
		gtk_text_buffer_select_range(buffer, &match_start, &match_end);
		last_pos_mark = gtk_text_buffer_create_mark (buffer,
							     "last_position",
							     &match_end, FALSE);
		gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(follow_info->text), last_pos_mark);
	} else {
		/* We didn't find a match */
		simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
			      "%sFind text has reached the end of the followed "
			      "stream%s\n\nThe next search will start from the "
			      "beginning", simple_dialog_primary_start(),
			      simple_dialog_primary_end());
		if(last_pos_mark)
			gtk_text_buffer_delete_mark(buffer, last_pos_mark);
	}

}

static void
follow_find_destroy_cb(GtkWidget * win _U_, gpointer data)
{
	follow_info_t	*follow_info = data;

	/* Note that we no longer have a dialog box. */
	follow_info->find_dlg_w = NULL;
}

static void
follow_print_stream(GtkWidget * w _U_, gpointer data)
{
	print_stream_t	*stream;
	gboolean	 to_file;
	char		*print_dest;
	follow_info_t	*follow_info = data;
#ifdef _WIN32
	gboolean         win_printer = FALSE;
	int              tmp_fd;
	char             *tmp_namebuf;
#endif

	switch (prefs.pr_dest) {
	case PR_DEST_CMD:
#ifdef _WIN32
		win_printer = TRUE;
		/* (The code for creating a temp filename is adapted from print_dlg.c).   */
		/* We currently don't have a function in util.h to create just a tempfile */
		/* name, so simply create a tempfile using the "official" function,       */
		/* then delete this file again. After this, the name MUST be available.   */
		/* */
		/* Don't use tmpnam() or such, as this will fail under some ACL           */
		/* circumstances: http://bugs.wireshark.org/bugzilla/show_bug.cgi?id=358  */
		/* Also: tmpnam is "insecure" and should not be used.                     */
		tmp_fd = create_tempfile(&tmp_namebuf, "wshprint");
		if(tmp_fd == -1) {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "Couldn't create temporary file for printing:\n%s", tmp_namebuf);
			return;
		}
		ws_close(tmp_fd);
		ws_unlink(tmp_namebuf);
		print_dest = tmp_namebuf;
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
			open_failure_alert_box(print_dest, errno, TRUE);
		} else {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "Couldn't run print command %s.",
				      prefs.pr_cmd);
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
			write_failure_alert_box(print_dest, errno);
		} else {
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				      "Error closing print destination.");
		}
	}
#ifdef _WIN32
	if (win_printer) {
		print_mswin(print_dest);

		/* trash temp file */
		ws_remove(print_dest);
	}
#endif
	return;

 print_error:
	if (to_file) {
		write_failure_alert_box(print_dest, errno);
	} else {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			      "Error writing to print command: %s",
			      g_strerror(errno));
	}
	/* XXX - cancel printing? */
	destroy_print_stream(stream);

#ifdef _WIN32
	if (win_printer) {
		/* trash temp file */
		ws_remove(print_dest);
	}
#endif
}

/*
 * Keep a static pointer to the current "Save Follow Stream As" window, if
 * any, so that if somebody tries to do "Save"
 * while there's already a "Save Follow Stream" window up, we just pop
 * up the existing one, rather than creating a new one.
 */

static void
follow_save_as_cmd_cb(GtkWidget *w _U_, gpointer data)
{
	GtkWidget		*new_win;
	follow_info_t	*follow_info = data;

#if 0  /* XXX: GtkFileChooserDialog/gtk_dialog_run currently being used is effectively modal so this is not req'd */
	if (follow_info->follow_save_as_w != NULL) {
		/* There's already a dialog box; reactivate it. */
		reactivate_window(follow_info->follow_save_as_w);
		return;
	}
#endif
	new_win = file_selection_new("Wireshark: Save Follow Stream As",
				     FILE_SELECTION_SAVE);
	follow_info->follow_save_as_w = new_win;
	gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(new_win), TRUE);

	/* Tuck away the follow_info object into the window */
	g_object_set_data(G_OBJECT(new_win), E_FOLLOW_INFO_KEY, follow_info);

	g_signal_connect(new_win, "destroy", G_CALLBACK(follow_save_as_destroy_cb),
		       follow_info);

#if 0
	if (gtk_dialog_run(GTK_DIALOG(new_win)) == GTK_RESPONSE_ACCEPT)
		{
			follow_save_as_ok_cb(new_win, new_win);
		} else {
		window_destroy(new_win);
	}
#endif
	/* "Run" the GtkFileChooserDialog.                                              */
        /* Upon exit: If "Accept" run the OK callback.                                  */
        /*            If the OK callback returns with a FALSE status, re-run the dialog.*/
        /*            If not accept (ie: cancel) destroy the window.                    */
        /* XXX: If the OK callback pops up an alert box (eg: for an error) it *must*    */
        /*      return with a TRUE status so that the dialog window will be destroyed.  */
	/*      Trying to re-run the dialog after popping up an alert box will not work */
        /*       since the user will not be able to dismiss the alert box.              */
	/*      The (somewhat unfriendly) effect: the user must re-invoke the           */
	/*      GtkFileChooserDialog whenever the OK callback pops up an alert box.     */
	/*                                                                              */
        /*      ToDo: use GtkFileChooserWidget in a dialog window instead of            */
	/*            GtkFileChooserDialog.                                             */
	while (gtk_dialog_run(GTK_DIALOG(new_win)) == GTK_RESPONSE_ACCEPT) {
		if (follow_save_as_ok_cb(NULL, new_win)) {
                    break; /* we're done */
		}
	}
	window_destroy(new_win);
}


static gboolean
follow_save_as_ok_cb(GtkWidget * w _U_, gpointer fs)
{
	gchar		*to_name;
	follow_info_t	*follow_info;
	FILE		*fh;
	print_stream_t	*stream = NULL;
	gchar		*dirname;

	to_name = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs));

	/* Perhaps the user specified a directory instead of a file.
	   Check whether they did. */
	if (test_for_directory(to_name) == EISDIR) {
		/* It's a directory - set the file selection box to display that
		   directory, and leave the selection box displayed. */
		set_last_open_dir(to_name);
		g_free(to_name);
		file_selection_set_current_folder(fs, get_last_open_dir());
		gtk_file_chooser_set_current_name(fs, "");
		return FALSE; /* do gtk_dialog_run again */
	}

	follow_info = g_object_get_data(G_OBJECT(fs), E_FOLLOW_INFO_KEY);

	if (follow_info->show_type == SHOW_RAW) {
		/* Write the data out as raw binary data */
		fh = ws_fopen(to_name, "wb");
	} else {
		/* Write it out as text */
		fh = ws_fopen(to_name, "w");
	}
	if (fh == NULL) {
		open_failure_alert_box(to_name, errno, TRUE);
		g_free(to_name);
		return TRUE;
	}

#if 0 /* handled by caller (for now) .... */
	gtk_widget_hide(GTK_WIDGET(fs));
	window_destroy(GTK_WIDGET(fs));
#endif
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
		switch (follow_read_stream(follow_info, follow_print_text,
					   stream)) {
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
        return TRUE;
}

static void
follow_save_as_destroy_cb(GtkWidget * win _U_, gpointer data)
{
	follow_info_t	*follow_info = data;

	/* Note that we no longer have a dialog box. */
	follow_info->follow_save_as_w = NULL;
}

static void
follow_stream_direction_changed(GtkWidget *w, gpointer data)
{
	follow_info_t *follow_info = data;

	switch(gtk_combo_box_get_active(GTK_COMBO_BOX(w))) {

	case 0 :
		follow_info->show_stream = BOTH_HOSTS;
		follow_load_text(follow_info);
		break;
	case 1 :
		follow_info->show_stream = FROM_CLIENT;
		follow_load_text(follow_info);
		break;
	case 2 :
		follow_info->show_stream = FROM_SERVER;
		follow_load_text(follow_info);
		break;
	}
}

/* Add a "follow_info_t" structure to the list. */
static void
remember_follow_info(follow_info_t *follow_info)
{
	follow_infos = g_list_append(follow_infos, follow_info);
}

#define IS_SHOW_TYPE(x) (follow_info->show_type == x ? 1 : 0)
/* Remove a "follow_info_t" structure from the list. */
static void
forget_follow_info(follow_info_t *follow_info)
{
	follow_infos = g_list_remove(follow_infos, follow_info);
}

void
follow_stream(gchar *title, follow_info_t *follow_info,
	      gchar *both_directions_string,
	      gchar *server_to_client_string, gchar *client_to_server_string)
{
	GtkWidget	*streamwindow, *vbox, *txt_scrollw, *text;
	GtkWidget	*hbox, *bbox, *button, *radio_bt;
	GtkWidget	*stream_fr, *stream_vb, *direction_hbox;
	GtkWidget	*stream_cmb;
	follow_stats_t stats;

	follow_info->show_type = SHOW_RAW;

	streamwindow = dlg_window_new(title);

	/* needed in follow_filter_out_stream(), is there a better way? */
	follow_info->streamwindow = streamwindow;

	gtk_widget_set_name(streamwindow, title);
	gtk_window_set_default_size(GTK_WINDOW(streamwindow),
				    DEF_WIDTH, DEF_HEIGHT);
	gtk_container_set_border_width(GTK_CONTAINER(streamwindow), 6);

	/* setup the container */
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
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(txt_scrollw),
					    GTK_SHADOW_IN);
	gtk_box_pack_start(GTK_BOX(stream_vb), txt_scrollw, TRUE, TRUE, 0);

	/* create a text box */
	text = gtk_text_view_new();
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text), GTK_WRAP_WORD_CHAR);

	gtk_container_add(GTK_CONTAINER(txt_scrollw), text);
	follow_info->text = text;

	/* direction hbox */
	direction_hbox = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(stream_vb), direction_hbox, FALSE, FALSE, 0);

	stream_cmb = gtk_combo_box_text_new();

	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(stream_cmb),
				  both_directions_string);
	follow_info->show_stream = BOTH_HOSTS;

	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(stream_cmb),
				  server_to_client_string);

	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(stream_cmb),
				   client_to_server_string);

	gtk_combo_box_set_active(GTK_COMBO_BOX(stream_cmb), 0); /* Do this before signal_connect  */
								/*  so callback not triggered     */

	g_signal_connect(stream_cmb, "changed",
			 G_CALLBACK(follow_stream_direction_changed),
			 follow_info);

	gtk_widget_set_tooltip_text(stream_cmb, "Select the stream direction to display");
	gtk_box_pack_start(GTK_BOX(direction_hbox), stream_cmb, TRUE, TRUE, 0);

	/* stream hbox */
	hbox = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(stream_vb), hbox, FALSE, FALSE, 0);

	/* Create Find Button */
	button = gtk_button_new_from_stock(GTK_STOCK_FIND);
	g_signal_connect(button, "clicked", G_CALLBACK(follow_find_cb), follow_info);
	gtk_widget_set_tooltip_text(button, "Find text in the displayed content");
	gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

	/* Create Save As Button */
	button = gtk_button_new_from_stock(GTK_STOCK_SAVE_AS);
	g_signal_connect(button, "clicked", G_CALLBACK(follow_save_as_cmd_cb), follow_info);
	gtk_widget_set_tooltip_text(button, "Save the content as currently displayed");
	gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

	/* Create Print Button */
    button = gtk_button_new_from_stock(GTK_STOCK_PRINT);
    g_signal_connect(button, "clicked", G_CALLBACK(follow_print_stream), follow_info);
    gtk_widget_set_tooltip_text(button, "Print the content as currently displayed");
    gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

	/* Stream to show */
	follow_stats(&stats);

	follow_info->is_ipv6 = stats.is_ipv6;

	/* ASCII radio button */
	radio_bt = gtk_radio_button_new_with_label(NULL, "ASCII");
	gtk_widget_set_tooltip_text(radio_bt, "Stream data output in \"ASCII\" format");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt),
		IS_SHOW_TYPE(SHOW_ASCII));
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, TRUE, TRUE, 0);
	g_signal_connect(radio_bt, "toggled", G_CALLBACK(follow_charset_toggle_cb),
                       follow_info);
	follow_info->ascii_bt = radio_bt;

	/* EBCDIC radio button */
	radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_get_group
						   (GTK_RADIO_BUTTON(radio_bt)),
						   "EBCDIC");
	gtk_widget_set_tooltip_text(radio_bt, "Stream data output in \"EBCDIC\" format");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt),
		IS_SHOW_TYPE(SHOW_EBCDIC));
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, TRUE, TRUE, 0);
	g_signal_connect(radio_bt, "toggled", G_CALLBACK(follow_charset_toggle_cb),
                       follow_info);
	follow_info->ebcdic_bt = radio_bt;

	/* HEX DUMP radio button */
	radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_get_group
						   (GTK_RADIO_BUTTON(radio_bt)),
						   "Hex Dump");
	gtk_widget_set_tooltip_text(radio_bt, "Stream data output in \"Hexdump\" format");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt),
		IS_SHOW_TYPE(SHOW_HEXDUMP));
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, TRUE, TRUE, 0);
	g_signal_connect(radio_bt, "toggled", G_CALLBACK(follow_charset_toggle_cb),
                       follow_info);
	follow_info->hexdump_bt = radio_bt;

	/* C Array radio button */
	radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_get_group
						   (GTK_RADIO_BUTTON(radio_bt)),
						   "C Arrays");
	gtk_widget_set_tooltip_text(radio_bt, "Stream data output in \"C Array\" format");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt),
		IS_SHOW_TYPE(SHOW_CARRAY));
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, TRUE, TRUE, 0);
	g_signal_connect(radio_bt, "toggled", G_CALLBACK(follow_charset_toggle_cb),
                       follow_info);
	follow_info->carray_bt = radio_bt;

	/* Raw radio button */
	radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_get_group
						   (GTK_RADIO_BUTTON(radio_bt)),
						   "Raw");
	gtk_widget_set_tooltip_text(radio_bt, "Stream data output in \"Raw\" (binary) format. As this contains non printable characters, the screen output will be in ASCII format");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt),
		IS_SHOW_TYPE(SHOW_RAW));
	gtk_box_pack_start(GTK_BOX(hbox), radio_bt, TRUE, TRUE, 0);
	g_signal_connect(radio_bt, "toggled", G_CALLBACK(follow_charset_toggle_cb),
                       follow_info);
	follow_info->raw_bt = radio_bt;

	/* Button row: help, filter out, close button */
	bbox = dlg_button_row_new(WIRESHARK_STOCK_FILTER_OUT_STREAM,
				  GTK_STOCK_CLOSE, GTK_STOCK_HELP,
				  NULL);
	gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 5);


	button = g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_FILTER_OUT_STREAM);
	gtk_widget_set_tooltip_text(button, "Build a display filter which cuts this stream from the capture");
	g_signal_connect(button, "clicked", G_CALLBACK(follow_filter_out_stream),
		       follow_info);

	button = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(streamwindow, button, window_cancel_button_cb);
	gtk_widget_set_tooltip_text(button, "Close the dialog and keep the current display filter");
	gtk_widget_grab_default(button);

	button = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
	g_signal_connect(button, "clicked", G_CALLBACK(topic_cb),
			 (gpointer)HELP_FOLLOW_STREAM_DIALOG);

	/* Tuck away the follow_info object into the window */
	g_object_set_data(G_OBJECT(streamwindow), E_FOLLOW_INFO_KEY, follow_info);

	follow_load_text(follow_info);
	remember_follow_info(follow_info);


	g_signal_connect(streamwindow, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(streamwindow, "destroy", G_CALLBACK(follow_destroy_cb), NULL);

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
	follow_info_t *follow_info;
	follow_record_t *follow_record;
	GList *cur;
	int i;

	follow_info = g_object_get_data(G_OBJECT(w), E_FOLLOW_INFO_KEY);

	switch(follow_info->follow_type) {

	case FOLLOW_TCP :
		i = ws_unlink(follow_info->data_out_filename);
		if(i != 0) {
			g_warning("Follow: Couldn't remove temporary file: \"%s\", errno: %s (%u)", follow_info->data_out_filename, g_strerror(errno), errno);
		}
		break;

	case FOLLOW_UDP :
		for(cur = follow_info->payload; cur; cur = g_list_next(cur))
			if(cur->data) {
				follow_record = cur->data;
				if(follow_record->data)
					g_byte_array_free(follow_record->data,
							  TRUE);

				g_free(follow_record);
			}

		g_list_free(follow_info->payload);
		break;

	case FOLLOW_SSL :
		/* free decrypted data list*/
		for (cur = follow_info->payload; cur; cur = g_list_next(cur))
			if (cur->data)
				{
					g_free(cur->data);
					cur->data = NULL;
				}
		g_list_free (follow_info->payload);
		break;
	}

	g_free(follow_info->data_out_filename);
	g_free(follow_info->filter_out_filter);
	g_free((gpointer)follow_info->client_ip.data);
	forget_follow_info(follow_info);
	g_free(follow_info);
}

frs_return_t
follow_show(follow_info_t *follow_info,
	    gboolean (*print_line_fcn_p)(char *, size_t, gboolean, void *),
	    char *buffer, size_t nchars, gboolean is_server, void *arg,
	    guint32 *global_pos, guint32 *server_packet_count,
	    guint32 *client_packet_count)
{
	gchar initbuf[256];
	guint32 current_pos;
	static const gchar hexchars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

	switch (follow_info->show_type) {

	case SHOW_EBCDIC:
		/* If our native arch is ASCII, call: */
		EBCDIC_to_ASCII(buffer, (guint) nchars);
		if (!(*print_line_fcn_p) (buffer, nchars, is_server, arg))
			return FRS_PRINT_ERROR;
		break;

	case SHOW_ASCII:
                /* If our native arch is EBCDIC, call:
                 * ASCII_TO_EBCDIC(buffer, nchars);
                 */
                if (!(*print_line_fcn_p) (buffer, nchars, is_server, arg))
			return FRS_PRINT_ERROR;
                break;

	case SHOW_RAW:
                /* Don't translate, no matter what the native arch
                 * is.
                 */
                if (!(*print_line_fcn_p) (buffer, nchars, is_server, arg))
			return FRS_PRINT_ERROR;
                break;

	case SHOW_HEXDUMP:
                current_pos = 0;
                while (current_pos < nchars) {
			gchar hexbuf[256];
			int i;
			gchar *cur = hexbuf, *ascii_start;

			/* is_server indentation : put 4 spaces at the
			 * beginning of the string */
			/* XXX - We might want to prepend each line with "C" or "S" instead. */
			if (is_server && follow_info->show_stream == BOTH_HOSTS) {
				memset(cur, ' ', 4);
				cur += 4;
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
			if (!(*print_line_fcn_p) (hexbuf, strlen(hexbuf), is_server, arg))
				return FRS_PRINT_ERROR;
                }
                break;

	case SHOW_CARRAY:
                current_pos = 0;
                g_snprintf(initbuf, sizeof(initbuf), "char peer%d_%d[] = {\n",
			   is_server ? 1 : 0,
			   is_server ? (*server_packet_count)++ : (*client_packet_count)++);
                if (!(*print_line_fcn_p) (initbuf, strlen(initbuf), is_server, arg))
			return FRS_PRINT_ERROR;

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
			if (!(*print_line_fcn_p) (hexbuf, strlen(hexbuf), is_server, arg))
				return FRS_PRINT_ERROR;
                }
                break;
	}

	return FRS_OK;
}
