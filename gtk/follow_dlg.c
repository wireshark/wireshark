/* follow_dlg.c
 *
 * $Id: follow_dlg.c,v 1.1 2000/08/03 12:44:36 gram Exp $
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
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_IO_H
#include <io.h> /* open/close on win32 */
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
#include "prefs.h"
#include "util.h"
#include "ui_util.h"


static void follow_destroy_cb(GtkWidget *win, gpointer data);
static void follow_charset_toggle_cb(GtkWidget *w, gpointer parent_w);
static void follow_load_text(GtkWidget *text, char *filename, guint8 show_type);
static void follow_print_stream(GtkWidget *w, gpointer parent_w);
static void follow_save_as_cmd_cb(GtkWidget *w, gpointer data);
static void follow_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void follow_save_as_destroy_cb(GtkWidget *win, gpointer user_data);

FILE        *data_out_file = NULL;
static char data_out_filename[128+1];

/* Follow the TCP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
follow_stream_cb( GtkWidget *w, gpointer data )
{
  GtkWidget *streamwindow, *box, *txt_scrollw, *text, *filter_te;
  GtkWidget *hbox, *button;
  GtkWidget *b_ascii, *b_ebcdic, *b_hexdump;
  int        tmp_fd;
  gchar     *follow_filter;

  if( pi.ipproto == 6 ) {
    /* we got tcp so we can follow */
    /* Create a temporary file into which to dump the reassembled data
       from the TCP stream, and set "data_out_file" to refer to it, so
       that the TCP code will write to it.

       XXX - it might be nicer to just have the TCP code directly
       append stuff to the text widget for the TCP stream window,
       if we can arrange that said window not pop up until we're
       done. */
    tmp_fd = create_tempfile( data_out_filename, sizeof data_out_filename, "follow");
    if (tmp_fd == -1) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not create temporary file %s: %s", data_out_filename, strerror(errno));
      return;
    }
    data_out_file = fdopen( tmp_fd, "wb" );
    if( data_out_file == NULL ) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not create temporary file %s: %s", data_out_filename, strerror(errno));
      close(tmp_fd);
      unlink(data_out_filename);
      return;
    }

    /* Create a new filter that matches all packets in the TCP stream,
       and set the display filter entry accordingly */
    reset_tcp_reassembly();
    follow_filter = build_follow_filter( &pi );

    /* set the display filter entry accordingly */
    filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);
    gtk_entry_set_text(GTK_ENTRY(filter_te), follow_filter);

    /* Run the display filter so it goes in effect. */
    filter_packets(&cfile, follow_filter);

    /* the data_out_file should now be full of the streams information */
    fclose( data_out_file );

    /* the data_out_filename file now has all the text that was in the session */
    streamwindow = gtk_window_new( GTK_WINDOW_TOPLEVEL);
    gtk_widget_set_name( streamwindow, "TCP stream window" );

    gtk_signal_connect( GTK_OBJECT(streamwindow), "destroy",
			GTK_SIGNAL_FUNC(follow_destroy_cb), NULL);
			
    if( incomplete_tcp_stream ) {
      gtk_window_set_title( GTK_WINDOW(streamwindow), 
			    "Contents of TCP stream (incomplete)" );
    } else {
      gtk_window_set_title( GTK_WINDOW(streamwindow),
			    "Contents of TCP stream" );
    }
    gtk_widget_set_usize( GTK_WIDGET(streamwindow), DEF_WIDTH, DEF_HEIGHT );
    gtk_container_border_width( GTK_CONTAINER(streamwindow), 2 );

    /* setup the container */
    box = gtk_vbox_new( FALSE, 0 );
    gtk_container_add( GTK_CONTAINER(streamwindow), box );
    gtk_widget_show( box );

    /* create a scrolled window for the text */
    txt_scrollw = gtk_scrolled_window_new( NULL, NULL );
    gtk_box_pack_start( GTK_BOX(box), txt_scrollw, TRUE, TRUE, 0 );
    gtk_scrolled_window_set_policy( GTK_SCROLLED_WINDOW(txt_scrollw),
					GTK_POLICY_NEVER,
					GTK_POLICY_ALWAYS );
    set_scrollbar_placement_scrollw(txt_scrollw, prefs.gui_scrollbar_on_right);
    remember_scrolled_window(txt_scrollw);
    gtk_widget_show( txt_scrollw );

    /* create a text box */
    text = gtk_text_new( NULL, NULL );
    gtk_text_set_editable( GTK_TEXT(text), FALSE);
    gtk_container_add( GTK_CONTAINER(txt_scrollw), text );
    gtk_widget_show(text);

    /* Create hbox */
    hbox = gtk_hbox_new( FALSE, 1 );
    gtk_box_pack_end( GTK_BOX(box), hbox, FALSE, FALSE, 0);
    gtk_widget_show(hbox);

#define E_FOLLOW_ASCII_KEY "follow_ascii_key"
#define E_FOLLOW_EBCDIC_KEY "follow_ebcdic_key"
#define E_FOLLOW_HEXDUMP_KEY "follow_hexdump_key"

    /* Create Radio Buttons */
    b_ascii = gtk_radio_button_new_with_label(NULL, "ASCII");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(b_ascii), TRUE);
    gtk_object_set_data(GTK_OBJECT(streamwindow), E_FOLLOW_ASCII_KEY, b_ascii);
    gtk_box_pack_start(GTK_BOX(hbox), b_ascii, FALSE, FALSE, 0);
    gtk_signal_connect(GTK_OBJECT(b_ascii), "toggled",
		    GTK_SIGNAL_FUNC(follow_charset_toggle_cb),
		    GTK_OBJECT(streamwindow));
    gtk_widget_show(b_ascii);

    b_ebcdic = gtk_radio_button_new_with_label(
		    gtk_radio_button_group(GTK_RADIO_BUTTON(b_ascii)),
		    "EBCDIC");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(b_ebcdic), FALSE);
    gtk_object_set_data(GTK_OBJECT(streamwindow), E_FOLLOW_EBCDIC_KEY, b_ebcdic);
    gtk_box_pack_start(GTK_BOX(hbox), b_ebcdic, FALSE, FALSE, 0);
    gtk_signal_connect(GTK_OBJECT(b_ebcdic), "toggled",
		    GTK_SIGNAL_FUNC(follow_charset_toggle_cb),
		    GTK_OBJECT(streamwindow));
    gtk_widget_show(b_ebcdic);

    b_hexdump = gtk_radio_button_new_with_label(
		    gtk_radio_button_group(GTK_RADIO_BUTTON(b_ascii)),
		    "Hex. Dump");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(b_hexdump), FALSE);
    gtk_object_set_data(GTK_OBJECT(streamwindow), E_FOLLOW_HEXDUMP_KEY, b_hexdump);
    gtk_box_pack_start(GTK_BOX(hbox), b_hexdump, FALSE, FALSE, 0);
    gtk_signal_connect(GTK_OBJECT(b_hexdump), "toggled",
		    GTK_SIGNAL_FUNC(follow_charset_toggle_cb),
		    GTK_OBJECT(streamwindow));
    gtk_widget_show(b_hexdump);

    /* Create Close Button */
    button = gtk_button_new_with_label("Close");
    gtk_signal_connect_object(GTK_OBJECT(button), "clicked",
		    GTK_SIGNAL_FUNC(gtk_widget_destroy),
		    GTK_OBJECT(streamwindow));
    gtk_box_pack_end( GTK_BOX(hbox), button, FALSE, FALSE, 0);
    gtk_widget_show( button );

    /* Create Save As Button */
    button = gtk_button_new_with_label("Save As");
    gtk_signal_connect(GTK_OBJECT(button), "clicked",
                   GTK_SIGNAL_FUNC(follow_save_as_cmd_cb),
                   GTK_OBJECT(streamwindow));
    gtk_box_pack_end( GTK_BOX(hbox), button, FALSE, FALSE, 0);
    gtk_widget_show( button );

    /* Create Print Button */
    button = gtk_button_new_with_label("Print");
    gtk_signal_connect(GTK_OBJECT(button), "clicked",
                   GTK_SIGNAL_FUNC(follow_print_stream),
                   GTK_OBJECT(streamwindow));
    gtk_box_pack_end( GTK_BOX(hbox), button, FALSE, FALSE, 0);
    gtk_widget_show( button );

    /* Tuck away the textbox into streamwindow */
#define E_FOLLOW_TEXT_KEY "follow_text_key"
    gtk_object_set_data(GTK_OBJECT(streamwindow), E_FOLLOW_TEXT_KEY, text);

    follow_load_text(text, data_out_filename, 0);

    data_out_file = NULL;

    /* Make sure this widget gets destroyed if we quit the main loop,
       so that if we exit, we clean up any temporary files we have
       for "Follow TCP Stream" windows. */
    gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(streamwindow));
    gtk_widget_show( streamwindow );
  } else {
    simple_dialog(ESD_TYPE_CRIT, NULL,
      "Error following stream.  Please make\n"
      "sure you have a TCP packet selected.");
  }
}

/* The destroy call back has the responsibility of
 * unlinking the temporary file */
static void
follow_destroy_cb(GtkWidget *win, gpointer data)
{
	unlink(data_out_filename);
	gtk_widget_destroy(win);
}

#define E_FOLLOW_ASCII_TYPE	0
#define E_FOLLOW_EBCDIC_TYPE	1
#define E_FOLLOW_HEXDUMP_TYPE	2

/* Handles the ASCII/EBCDIC toggling */
static void
follow_charset_toggle_cb(GtkWidget *w, gpointer parent_w)
{
	guint8		show_type = E_FOLLOW_ASCII_TYPE;
	GtkWidget	*b_ascii, *b_ebcdic, *b_hexdump, *text;

	b_ascii = (GtkWidget*) gtk_object_get_data(GTK_OBJECT(parent_w),
						   E_FOLLOW_ASCII_KEY);
	b_ebcdic = (GtkWidget*) gtk_object_get_data(GTK_OBJECT(parent_w),
						    E_FOLLOW_EBCDIC_KEY);
	b_hexdump = (GtkWidget*) gtk_object_get_data(GTK_OBJECT(parent_w),
						     E_FOLLOW_HEXDUMP_KEY);
	text = (GtkWidget*) gtk_object_get_data(GTK_OBJECT(parent_w),
						E_FOLLOW_TEXT_KEY);

	g_assert(b_ascii);
	g_assert(b_ebcdic);
	g_assert(b_hexdump);
	g_assert(text);

	if (GTK_TOGGLE_BUTTON(b_ebcdic)->active)
		show_type = E_FOLLOW_EBCDIC_TYPE;
	else if (GTK_TOGGLE_BUTTON(b_hexdump)->active)
		show_type = E_FOLLOW_HEXDUMP_TYPE;

	follow_load_text(text, data_out_filename, show_type);
}

#define FLT_BUF_SIZE 1024
static void
follow_read_stream(char *filename, guint8 show_type,
   void (*print_line)(char *, int, gboolean, void *), void *arg)
{
  tcp_stream_chunk sc;
  int bcount;
  guint32 client_addr = 0;
  guint16 client_port = 0;
  gboolean is_server;
  guint16 current_pos, global_client_pos = 0, global_server_pos = 0;
  guint16 *global_pos;

  data_out_file = fopen( filename, "rb" );
  if( data_out_file ) {
    char buffer[FLT_BUF_SIZE];
    int nchars;
    while(fread(&sc.src_addr, 1, sizeof(sc), data_out_file)) {
      if (client_addr == 0) {
        client_addr = sc.src_addr;
        client_port = sc.src_port;
      }
      if (client_addr == sc.src_addr && client_port == sc.src_port) {
	is_server = FALSE;
	global_pos = &global_client_pos;
      }
      else {
	is_server = TRUE;
	global_pos = &global_server_pos;
      }
        
      while (sc.dlen > 0) {
        bcount = (sc.dlen < FLT_BUF_SIZE) ? sc.dlen : FLT_BUF_SIZE;
        nchars = fread( buffer, 1, bcount, data_out_file );
        if (nchars == 0)
          break;
        sc.dlen -= bcount;
	switch (show_type) {
	case E_FOLLOW_EBCDIC_TYPE:
		/* If our native arch is ASCII, call: */
		EBCDIC_to_ASCII(buffer, nchars);
	case E_FOLLOW_ASCII_TYPE:
		/* If our native arch is EBCDIC, call:
		 * ASCII_TO_EBCDIC(buffer, nchars);
		 */
	  	(*print_line)( buffer, nchars, is_server, arg );
		break;
	case E_FOLLOW_HEXDUMP_TYPE:
		current_pos = 0;
		while (current_pos < nchars)
		{
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
		    for (i=0; i < 16 && current_pos+i < nchars; i++) {
			hexbuf[cur++] = hexchars[(buffer[current_pos+i] & 0xf0) >> 4];
			hexbuf[cur++] = hexchars[buffer[current_pos+i] & 0x0f];
			if (i == 7) {
			    hexbuf[cur++] = ' '; hexbuf[cur++] = ' ';
			}
			else if (i != 15)
			    hexbuf[cur++] = ' ';
		    }
		    current_pos += i;
		    (*global_pos) += i;
		    hexbuf[cur++] = '\n';
		    hexbuf[cur] = 0;
		    (*print_line)( hexbuf, strlen(hexbuf), is_server, arg );
		}
		break;
	}
      }
    }
    if( ferror( data_out_file ) ) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Error reading temporary file %s: %s", filename, strerror(errno));
    }
    fclose( data_out_file );
    data_out_file = NULL;
  } else {
    simple_dialog(ESD_TYPE_WARN, NULL,
      "Could not open temporary file %s: %s", filename, strerror(errno));
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
follow_print_stream(GtkWidget *w, gpointer parent_w)
{
       FILE *fh;
       gboolean to_file;
       char* print_dest;
       guint8 show_type = E_FOLLOW_ASCII_TYPE;
       GtkWidget *button;

       switch (prefs.pr_dest) {
               case PR_DEST_CMD:
                       print_dest = prefs.pr_cmd;
                       to_file = FALSE;
                       break;

               case PR_DEST_FILE:
                       print_dest = prefs.pr_file;
                       to_file = TRUE;
                       break;
               default: /* "Can't happen" */
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
                                               file_write_error_message(errno),
                                               prefs.pr_file);
                               break;
               }
               return;
       }

       button = (GtkWidget*) gtk_object_get_data(GTK_OBJECT(parent_w),
                       E_FOLLOW_EBCDIC_KEY);
       if (GTK_TOGGLE_BUTTON(button)->active)
               show_type = E_FOLLOW_EBCDIC_TYPE;
       button = (GtkWidget*) gtk_object_get_data(GTK_OBJECT(parent_w),
                       E_FOLLOW_HEXDUMP_KEY);
       if (GTK_TOGGLE_BUTTON(button)->active)
               show_type = E_FOLLOW_HEXDUMP_TYPE;

       print_preamble(fh, PR_FMT_TEXT);
       follow_read_stream(data_out_filename, show_type, follow_print_text, fh);
       print_finale(fh, PR_FMT_TEXT);
       close_print_dest(to_file, fh);
}

static void
follow_add_to_gtk_text(char *buffer, int nchars, gboolean is_server, void *arg)
{
  GtkWidget *text = arg;

  if (is_server)
    gtk_text_insert( GTK_TEXT(text), m_r_font, &prefs.st_server_fg,
            &prefs.st_server_bg, buffer, nchars );
  else
    gtk_text_insert( GTK_TEXT(text), m_r_font, &prefs.st_client_fg,
            &prefs.st_client_bg, buffer, nchars );
}

static void
follow_load_text(GtkWidget *text, char *filename, guint8 show_type)
{
  int bytes_already;

  /* Delete any info already in text box */
  bytes_already = gtk_text_get_length(GTK_TEXT(text));
  if (bytes_already > 0) {
    gtk_text_set_point(GTK_TEXT(text), 0);
    gtk_text_forward_delete(GTK_TEXT(text), bytes_already);
  }

  /* stop the updates while we fill the text box */
  gtk_text_freeze( GTK_TEXT(text) );
  follow_read_stream(filename, show_type, follow_add_to_gtk_text, text);
  gtk_text_thaw( GTK_TEXT(text) );
}

	
/*
 * Keep a static pointer to the current "Save TCP Follow Stream As" window, if
 * any, so that if somebody tries to do "Save"
 * while there's already a "Save TCP Follow Stream" window up, we just pop
 * up the existing one, rather than creating a new one.
 */
static GtkWidget *follow_save_as_w;

static void
follow_save_as_cmd_cb(GtkWidget *w, gpointer data)
{
  GtkWidget *ok_bt;

  if (follow_save_as_w != NULL) {
    /* There's already a dialog box; reactivate it. */
    reactivate_window(follow_save_as_w);
    return;
  }

  follow_save_as_w = gtk_file_selection_new ("Ethereal: Save TCP Follow Stream As");
  gtk_signal_connect(GTK_OBJECT(follow_save_as_w), "destroy",
	GTK_SIGNAL_FUNC(follow_save_as_destroy_cb), NULL);

  /* If we've opened a file, start out by showing the files in the directory
     in which that file resided. */
  if (last_open_dir)
    gtk_file_selection_complete(GTK_FILE_SELECTION(follow_save_as_w), last_open_dir);

  /* Connect the ok_button to file_save_as_ok_cb function and pass along a
     pointer to the file selection box widget */
  ok_bt = GTK_FILE_SELECTION (follow_save_as_w)->ok_button;
  gtk_signal_connect(GTK_OBJECT (ok_bt), "clicked",
    (GtkSignalFunc) follow_save_as_ok_cb, follow_save_as_w);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (follow_save_as_w)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (follow_save_as_w));

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(follow_save_as_w, GTK_FILE_SELECTION(follow_save_as_w)->cancel_button);

  gtk_file_selection_set_filename(GTK_FILE_SELECTION(follow_save_as_w), "");
  gtk_widget_show(follow_save_as_w);
}

static void
follow_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs)
{
  gchar	*to_name;

  to_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  copy_binary_file(data_out_filename, to_name);

  g_free(to_name);
}

static void
follow_save_as_destroy_cb(GtkWidget *win, gpointer user_data)
{
  /* Note that we no longer have a dialog box. */
  follow_save_as_w = NULL;
}
