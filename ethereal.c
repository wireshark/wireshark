/* ethereal.c
 *
 * $Id: ethereal.c,v 1.102 1999/08/22 00:47:44 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Richard Sharpe, 13-Feb-1999, added support for initializing structures
 *                              needed by dissect routines
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
 *
 * To do:
 * - Live browser/capture display
 * - Graphs
 * - Get AIX to work
 * - Check for end of packet in dissect_* routines.
 * - Playback window
 * - Multiple window support
 * - Add cut/copy/paste
 * - Create header parsing routines
 * - Check fopens, freads, fwrites
 * - Make byte view scrollbars automatic?
 * - Make byte view selections more fancy?
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <signal.h>

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include "ethereal.h"
#include "timestamp.h"
#include "packet.h"
#include "capture.h"
#include "summary.h"
#include "file.h"
#include "menu.h"
#include "etypes.h"
#include "prefs.h"
#include "column.h"
#include "print.h"
#include "resolv.h"
#include "follow.h"
#include "util.h"
#include "gtkpacket.h"
#include "dfilter.h"

static void file_open_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void file_save_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void file_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void print_cmd_toggle_dest(GtkWidget *widget, gpointer data);
static void print_file_cb(GtkWidget *file_bt, gpointer file_te);
static void print_fs_ok_cb(GtkWidget *w, gpointer data);
static void print_fs_cancel_cb(GtkWidget *w, gpointer data);
static void print_ok_cb(GtkWidget *ok_bt, gpointer parent_w);
static void print_close_cb(GtkWidget *close_bt, gpointer parent_w);

FILE        *data_out_file = NULL;
packet_info  pi;
capture_file cf;
GtkWidget   *file_sel, *packet_list, *tree_view, *byte_view, *prog_bar,
            *info_bar;
GdkFont     *m_r_font, *m_b_font;
guint        main_ctx, file_ctx;
gint         start_capture = 0;
gchar        comp_info_str[256];
gchar       *ethereal_path = NULL;
gchar       *medium_font = MONO_MEDIUM_FONT;
gchar       *bold_font = MONO_BOLD_FONT;
gchar       *last_open_dir = NULL;

ts_type timestamp_type = RELATIVE;

GtkStyle *item_style;

#ifdef HAVE_LIBPCAP
int sync_mode;	/* allow sync */
int sync_pipe[2]; /* used to sync father */
int fork_mode;	/* fork a child to do the capture */
int sigusr2_received = 0;
int quit_after_cap; /* Makes a "capture only mode". Implies -k */
#endif

/* Specifies byte offsets for object selected in tree */
static gint tree_selected_start=-1, tree_selected_len=-1; 

#define E_DFILTER_TE_KEY "display_filter_te"
#define E_RFILTER_TE_KEY "read_filter_te"

/* About Ethereal window */
void
about_ethereal( GtkWidget *w, gpointer data ) {
  simple_dialog(ESD_TYPE_INFO, NULL,
		"GNU Ethereal - network protocol analyzer\n"
		"Version %s (C) 1998 Gerald Combs <gerald@zing.org>\n"
                "Compiled with %s\n\n"
		"Contributors:\n"

		"Gilbert Ramirez          <gramirez@tivoli.com>\n"
		"Hannes R. Boehm          <hannes@boehm.org>\n"
		"Mike Hall                <mlh@io.com>\n"
		"Bobo Rajec               <bobo@bsp-consulting.sk>\n"
		"Laurent Deniel           <deniel@worldnet.fr>\n"
		"Don Lafontaine           <lafont02@cn.ca>\n"
		"Guy Harris               <guy@netapp.com>\n"
		"Simon Wilkinson          <sxw@dcs.ed.ac.uk>\n"
		"Joerg Mayer              <jmayer@telemation.de>\n"
		"Martin Maciaszek         <fastjack@i-s-o.net>\n"
		"Didier Jorand            <Didier.Jorand@alcatel.fr>\n"
		"Jun-ichiro itojun Hagino <itojun@iijlab.net>\n"
		"Richard Sharpe           <sharpe@ns.aus.com>\n"
		"John McDermott           <jjm@jkintl.com>\n"
		"Jeff Jahr                <jjahr@shastanets.com>\n"
		"Brad Robel-Forrest       <bradr@watchguard.com>\n"
		"Ashok Narayanan          <ashokn@cisco.com>\n"
		"Aaron Hillegass          <aaron@classmax.com>\n"
		"Jason Lango              <jal@netapp.com>\n"
		"Johan Feyaerts           <Johan.Feyaerts@siemens.atea.be>\n"
		"Olivier Abad             <abad@daba.dhis.org>\n"
		"Thierry Andry            <Thierry.Andry@advalvas.be>\n"
		"Jeff Foster              <jfoste@woodward.com>\n"

		"\nSee http://ethereal.zing.org for more information",
                VERSION, comp_info_str);
}

/* Update the progress bar */
gint
file_progress_cb(gpointer p) {
  capture_file *cf = (capture_file*) p;
  gtk_progress_bar_update(GTK_PROGRESS_BAR(prog_bar),
    (gfloat) ftell(cf->fh) / (gfloat) cf->f_len);
  return TRUE;
}

/* Follow the TCP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
follow_stream_cb( GtkWidget *w, gpointer data ) {
  char      filename1[128+1];
  GtkWidget *streamwindow, *box, *text, *vscrollbar, *table;
  int        tmp_fd;
  gchar     *old_dfilter;

  if( pi.ipproto == 6 ) {
    /* we got tcp so we can follow */
    /* Create a temporary file into which to dump the reassembled data
       from the TCP stream, and set "data_out_file" to refer to it, so
       that the TCP code will write to it.

       XXX - it might be nicer to just have the TCP code directly
       append stuff to the text widget for the TCP stream window,
       if we can arrange that said window not pop up until we're
       done. */
    tmp_fd = create_tempfile( filename1, sizeof filename1, "follow");
    if (tmp_fd == -1) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not create temporary file %s: %s", filename1, strerror(errno));
      return;
    }
    data_out_file = fdopen( tmp_fd, "w" );
    if( data_out_file == NULL ) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not create temporary file %s: %s", filename1, strerror(errno));
      close(tmp_fd);
      unlink(filename1);
      return;
    }

    /* Save any display filter we currently have. */
    old_dfilter = cf.dfilter;

    /* Create a new filter that matches all packets in the TCP stream,
       and set the display filter entry accordingly */
    reset_tcp_reassembly();
    cf.dfilter = build_follow_filter( &pi );

    /* Run the display filter so it goes in effect. */
    filter_packets(&cf);

    /* the data_out_file should now be full of the streams information */
    fclose( data_out_file );

    /* the filename1 file now has all the text that was in the session */
    streamwindow = gtk_window_new( GTK_WINDOW_TOPLEVEL);
    gtk_widget_set_name( streamwindow, "TCP stream window" );
    gtk_signal_connect( GTK_OBJECT(streamwindow), "delete_event",
			NULL, "WM destroy" );
    gtk_signal_connect( GTK_OBJECT(streamwindow), "destroy",
			NULL, "WM destroy" );
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

    /* set up the table we attach to */
    table = gtk_table_new( 1, 2, FALSE );
    gtk_table_set_col_spacing( GTK_TABLE(table), 0, 2);
    gtk_box_pack_start( GTK_BOX(box), table, TRUE, TRUE, 0 );
    gtk_widget_show( table );

    /* create a text box */
    text = gtk_text_new( NULL, NULL );
    gtk_text_set_editable( GTK_TEXT(text), FALSE);
    gtk_table_attach( GTK_TABLE(table), text, 0, 1, 0, 1,
		      GTK_EXPAND | GTK_SHRINK | GTK_FILL,
		      GTK_EXPAND | GTK_SHRINK | GTK_FILL, 0, 0 );
    gtk_widget_show(text);

    /* create the scrollbar */
    vscrollbar = gtk_vscrollbar_new( GTK_TEXT(text)->vadj );
    gtk_table_attach( GTK_TABLE(table), vscrollbar, 1, 2, 0, 1,
		      GTK_FILL, GTK_EXPAND | GTK_SHRINK | GTK_FILL, 0, 0 );
    gtk_widget_show( vscrollbar );
    gtk_widget_realize( text );

    /* stop the updates while we fill the text box */
    gtk_text_freeze( GTK_TEXT(text) );
    data_out_file = fopen( filename1, "r" );
    if( data_out_file ) {
      char buffer[1024];
      int nchars;
      while( 1 ) {
	nchars = fread( buffer, 1, 1024, data_out_file );
	gtk_text_insert( GTK_TEXT(text), m_r_font, NULL, NULL, buffer, nchars );
	if( nchars < 1024 ) {
	  break;
	}
      }
      if( ferror( data_out_file ) ) {
        simple_dialog(ESD_TYPE_WARN, NULL,
          "Error reading temporary file %s: %s", filename1, strerror(errno));
      }
      fclose( data_out_file );
    } else {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open temporary file %s: %s", filename1, strerror(errno));
    }
    gtk_text_thaw( GTK_TEXT(text) );
    unlink( filename1 );
    data_out_file = NULL;
    gtk_widget_show( streamwindow );
    if( cf.dfilter != NULL ) {
      g_free( cf.dfilter );
    }
    cf.dfilter = old_dfilter;
    filter_packets(&cf);
  } else {
    simple_dialog(ESD_TYPE_WARN, NULL,
      "Error following stream.  Please make\n"
      "sure you have a TCP packet selected.");
  }
}

/* Match selected byte pattern */
void
match_selected_cb(GtkWidget *w, gpointer data)
{
    char *buf = g_malloc(1024);
    GtkWidget *filter_te = NULL;
    char *ptr;
    int i;
    guint8 *c;

    filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);

    if (tree_selected_start<0) {
	simple_dialog(ESD_TYPE_WARN, NULL,
		      "Error determining selected bytes.  Please make\n"
		      "sure you have selected a field within the tree\n"
		      "view to be matched.");
	return;
    }

    c = cf.pd + tree_selected_start;
    ptr = buf;

    sprintf(ptr, "frame[%d : %d] == ", tree_selected_start, tree_selected_len);
    ptr = buf+strlen(buf);

    if (tree_selected_len == 1) {
        sprintf(ptr, "0x%02x", *c++);
    }
    else {
	    for (i=0;i<tree_selected_len; i++) {
		if (i == 0 ) {
			sprintf(ptr, "%02x", *c++);
		}
		else {
			sprintf(ptr, ":%02x", *c++);
		}
		ptr = buf+strlen(buf);
	    }
    }

    if( cf.dfilter != NULL ) {
      /* get rid of this one */
      g_free( cf.dfilter );
    }
    /* create a new one and set the display filter entry accordingly */
    cf.dfilter = buf;
    if (filter_te) {
	gtk_entry_set_text(GTK_ENTRY(filter_te), cf.dfilter);
    }
    /* Run the display filter so it goes in effect. */
    filter_packets(&cf);
}

/* Open a file */
void
file_open_cmd_cb(GtkWidget *w, gpointer data) {
  GtkWidget *filter_hbox, *filter_bt, *filter_te;

  if (last_open_dir)
	  chdir(last_open_dir);

  file_sel = gtk_file_selection_new ("Ethereal: Open Capture File");
  
  /* Connect the ok_button to file_open_ok_cb function and pass along a
     pointer to the file selection box widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (file_sel)->ok_button),
    "clicked", (GtkSignalFunc) file_open_ok_cb, file_sel );

  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_sel)->ok_button),
      E_DFILTER_TE_KEY, gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY));

  filter_hbox = gtk_hbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(filter_hbox), 0);
  gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(file_sel)->action_area),
    filter_hbox, FALSE, FALSE, 0);
  gtk_widget_show(filter_hbox);

  filter_bt = gtk_button_new_with_label("Filter:");
  gtk_signal_connect(GTK_OBJECT(filter_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_cb), (gpointer) E_PR_PG_FILTER);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);
  
  filter_te = gtk_entry_new();
  gtk_object_set_data(GTK_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_te, TRUE, TRUE, 3);
  gtk_widget_show(filter_te);

  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_sel)->ok_button),
    E_RFILTER_TE_KEY, filter_te);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (file_sel)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_sel));

#ifdef HAVE_LIBPCAP
  if( fork_mode && (cf.save_file != NULL) )
#else
  if( cf.save_file != NULL )
#endif
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), cf.save_file);
  else
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), "");

  gtk_widget_show(file_sel);
}

static void
file_open_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
  gchar     *cf_name, *rfilter, *s;
  GtkWidget *filter_te;
  dfilter   *rfcode = NULL;
  int        err;

  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (fs)));
  filter_te = gtk_object_get_data(GTK_OBJECT(w), E_RFILTER_TE_KEY);
  rfilter = gtk_entry_get_text(GTK_ENTRY(filter_te));
  if (rfilter[0] != '\0') {
	rfcode = dfilter_new();
	if (dfilter_compile(rfcode, rfilter) != 0) {
		simple_dialog(ESD_TYPE_WARN, NULL, dfilter_error_msg);
		dfilter_destroy(rfcode);
		return;
	}
  }

  /* Try to open the capture file. */
  if ((err = open_cap_file(cf_name, &cf)) != 0) {
    /* We couldn't open it; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the open error,
       try again. */
    if (rfcode != NULL)
      dfilter_destroy(rfcode);
    return;
  }

  /* Attach the new read filter to "cf" ("open_cap_file()" succeeded, so
     it closed the previous capture file, and thus destroyed any
     previous read filter attached to "cf"). */
  cf.rfcode = rfcode;

  /* We've crossed the Rubicon; get rid of the file selection box. */
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  err = read_cap_file(&cf);
  /* Save the directory name; we can write over cf_name. */
  s = strrchr(cf_name, '/');
  if (s && last_open_dir) {
	  *s = '\0';
	  if (strcmp(last_open_dir, cf_name) != 0) {
		  g_free(last_open_dir);
		  last_open_dir = g_strdup(cf_name);
	  }
  }
  else if (s) { /* ! last_open_dir */
	  *s = '\0';
	  last_open_dir = g_strdup(cf_name);
  }
  else {
	  last_open_dir = NULL;
  }
  set_menu_sensitivity("/File/Save", FALSE);
  set_menu_sensitivity("/File/Save As...", TRUE);
  g_free(cf_name);
}

/* Close a file */
void
file_close_cmd_cb(GtkWidget *widget, gpointer data) {
  close_cap_file(&cf, info_bar, file_ctx);
}

void
file_save_cmd_cb(GtkWidget *w, gpointer data) {
  file_sel = gtk_file_selection_new ("Ethereal: Save Capture File");
 
  /* Connect the ok_button to file_save_ok_cb function and pass along a
     pointer to the file selection box widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (file_sel)->ok_button),
    "clicked", (GtkSignalFunc) file_save_ok_cb, file_sel );

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (file_sel)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_sel));

  gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), "");

  gtk_widget_show(file_sel);
}

void
file_save_as_cmd_cb(GtkWidget *w, gpointer data) {
  file_sel = gtk_file_selection_new ("Ethereal: Save Capture File As");

  /* Connect the ok_button to file_save_as_ok_cb function and pass along a
     pointer to the file selection box widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (file_sel)->ok_button),
    "clicked", (GtkSignalFunc) file_save_as_ok_cb, file_sel );

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (file_sel)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_sel));

  gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), "");
  gtk_widget_show(file_sel);
}

static void
file_save_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
	gchar	*cf_name;
	int	err;

	cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
	gtk_widget_hide(GTK_WIDGET (fs));
	gtk_widget_destroy(GTK_WIDGET (fs));

	if (!file_mv(cf.save_file, cf_name))
		return;

	g_free(cf.save_file);
	cf.save_file = g_strdup(cf_name);
	cf.user_saved = 1;
        if ((err = open_cap_file(cf_name, &cf)) == 0) {
		err = read_cap_file(&cf);
		set_menu_sensitivity("/File/Save", FALSE);
		set_menu_sensitivity("/File/Save As...", TRUE);
	}
}

static void
file_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
	gchar	*cf_name;
	int	err;

	cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
	gtk_widget_hide(GTK_WIDGET (fs));
	gtk_widget_destroy(GTK_WIDGET (fs));
	if (!file_cp(cf.filename, cf_name))
		return;
	g_free(cf.filename);
	cf.filename = g_strdup(cf_name);
	cf.user_saved = 1;
        if ((err = open_cap_file(cf.filename, &cf)) == 0) {
		err = read_cap_file(&cf);
		set_menu_sensitivity("/File/Save", FALSE);
		set_menu_sensitivity("/File/Save As...", TRUE);
	}
}

/* Reload a file using the current read and display filters */
void
file_reload_cmd_cb(GtkWidget *w, gpointer data) {
  /*GtkWidget *filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);*/
  GtkWidget *filter_te;

  filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);

  if (cf.dfilter) g_free(cf.dfilter);
  cf.dfilter = g_strdup(gtk_entry_get_text(GTK_ENTRY(filter_te)));
  if (open_cap_file(cf.filename, &cf) == 0)
    read_cap_file(&cf);
  /* XXX - change the menu if the open fails? */
}

/* Run the current display filter on the current packet set, and
   redisplay. */
static void
filter_activate_cb(GtkWidget *w, gpointer data)
{
  char *s = gtk_entry_get_text(GTK_ENTRY(w));

  if (cf.dfilter)
	g_free(cf.dfilter);

  /* simple check for empty string. XXX - need to modify to search for /^\s+$/ */
  if (s[0] == '\0' ) {
	cf.dfilter = NULL;
  }
  else {
	cf.dfilter = g_strdup(s);
  }

  filter_packets(&cf);
}

/*
 * Remember whether we printed to a printer or a file the last time we
 * printed something.
 */
static int     print_to_file;

/* Keys for gtk_object_set_data */
#define PRINT_CMD_LB_KEY  "printer_command_label"
#define PRINT_CMD_TE_KEY  "printer_command_entry"
#define PRINT_FILE_BT_KEY "printer_file_button"
#define PRINT_FILE_TE_KEY "printer_file_entry"
#define PRINT_DEST_RB_KEY "printer_destination_radio_button"

/* Print the capture */
void
file_print_cmd_cb(GtkWidget *widget, gpointer data)
{
  GtkWidget     *print_w;
  GtkWidget     *main_vb, *main_tb, *button;
#if 0
  GtkWidget     *format_hb, *format_lb;
  GSList        *format_grp;
#endif
  GtkWidget     *dest_rb;
  GtkWidget     *dest_hb, *dest_lb;
  GtkWidget     *cmd_lb, *cmd_te;
  GtkWidget     *file_bt_hb, *file_bt, *file_te;
  GSList        *dest_grp;
  GtkWidget     *bbox, *ok_bt, *cancel_bt;

  /* XXX - don't pop up one if there's already one open; instead,
       give it the input focus if that's possible. */

  print_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(print_w), "Ethereal: Print");

  /* Enclosing containers for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(print_w), main_vb);
  gtk_widget_show(main_vb);
  
  main_tb = gtk_table_new(4, 2, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
  gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
  gtk_widget_show(main_tb);

  /* XXX - printing multiple frames in PostScript looks as if it's
     tricky - you have to deal with page boundaries, I think -
     and I'll have to spend some time learning enough about
     PostScript to figure it out, so, for now, we only print
     multiple frames as text. */
#if 0
  /* Output format */
  format_lb = gtk_label_new("Format:");
  gtk_misc_set_alignment(GTK_MISC(format_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), format_lb, 0, 1, 0, 1);
  gtk_widget_show(format_lb);

  format_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), format_hb, 1, 2, 0, 1);
  gtk_widget_show(format_hb);

  button = gtk_radio_button_new_with_label(NULL, "Plain Text");
  if (prefs.pr_format == PR_FMT_TEXT)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
  format_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
  gtk_box_pack_start(GTK_BOX(format_hb), button, FALSE, FALSE, 10);
  gtk_widget_show(button);

  button = gtk_radio_button_new_with_label(format_grp, "PostScript");
  if (prefs.pr_format == PR_FMT_PS)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
  gtk_box_pack_start(GTK_BOX(format_hb), button, FALSE, FALSE, 10);
  gtk_widget_show(button);
#endif

  /* Output destination */
  dest_lb = gtk_label_new("Print to:");
  gtk_misc_set_alignment(GTK_MISC(dest_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), dest_lb, 0, 1, 1, 2);
  gtk_widget_show(dest_lb);

  dest_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), dest_hb, 1, 2, 1, 2);
  gtk_widget_show(dest_hb);

  button = gtk_radio_button_new_with_label(NULL, "Command");
  if (!print_to_file)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(button), TRUE);
  dest_grp = gtk_radio_button_group(GTK_RADIO_BUTTON(button));
  gtk_box_pack_start(GTK_BOX(dest_hb), button, FALSE, FALSE, 10);
  gtk_widget_show(button);

  dest_rb = gtk_radio_button_new_with_label(dest_grp, "File");
  if (print_to_file)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(dest_rb), TRUE);
  gtk_signal_connect(GTK_OBJECT(dest_rb), "toggled",
			GTK_SIGNAL_FUNC(print_cmd_toggle_dest), NULL);
  gtk_box_pack_start(GTK_BOX(dest_hb), dest_rb, FALSE, FALSE, 10);
  gtk_widget_show(dest_rb);

  /* Command text entry */
  cmd_lb = gtk_label_new("Command:");
  gtk_object_set_data(GTK_OBJECT(dest_rb), PRINT_CMD_LB_KEY, cmd_lb);
  gtk_misc_set_alignment(GTK_MISC(cmd_lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), cmd_lb, 0, 1, 2, 3);
  gtk_widget_set_sensitive(cmd_lb, !print_to_file);
  gtk_widget_show(cmd_lb);

  cmd_te = gtk_entry_new();
  gtk_object_set_data(GTK_OBJECT(dest_rb), PRINT_CMD_TE_KEY, cmd_te);
  if (prefs.pr_cmd)
    gtk_entry_set_text(GTK_ENTRY(cmd_te), prefs.pr_cmd);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), cmd_te, 1, 2, 2, 3);
  gtk_widget_set_sensitive(cmd_te, !print_to_file);
  gtk_widget_show(cmd_te);

  /* File button and text entry */
  file_bt_hb = gtk_hbox_new(FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), file_bt_hb, 0, 1, 3, 4);
  gtk_widget_show(file_bt_hb);

  file_bt = gtk_button_new_with_label("File:");
  gtk_object_set_data(GTK_OBJECT(dest_rb), PRINT_FILE_BT_KEY, file_bt);
  gtk_box_pack_end(GTK_BOX(file_bt_hb), file_bt, FALSE, FALSE, 0);
  gtk_widget_set_sensitive(file_bt, print_to_file);
  gtk_widget_show(file_bt);

  file_te = gtk_entry_new();
  gtk_object_set_data(GTK_OBJECT(dest_rb), PRINT_FILE_TE_KEY, file_te);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), file_te, 1, 2, 3, 4);
  gtk_widget_set_sensitive(file_te, print_to_file);
  gtk_widget_show(file_te);

  gtk_signal_connect(GTK_OBJECT(file_bt), "clicked",
		GTK_SIGNAL_FUNC(print_file_cb), GTK_OBJECT(file_te));

  /* Button row: OK and Cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = gtk_button_new_with_label ("OK");
  gtk_object_set_data(GTK_OBJECT(ok_bt), PRINT_DEST_RB_KEY, dest_rb);
  gtk_object_set_data(GTK_OBJECT(ok_bt), PRINT_CMD_TE_KEY, cmd_te);
  gtk_object_set_data(GTK_OBJECT(ok_bt), PRINT_FILE_TE_KEY, file_te);
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(print_ok_cb), GTK_OBJECT(print_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(print_close_cb), GTK_OBJECT(print_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

#if 0
  display_opt_window_active = TRUE;
#endif
  gtk_widget_show(print_w);
}

static void
print_cmd_toggle_dest(GtkWidget *widget, gpointer data)
{
  GtkWidget     *cmd_lb, *cmd_te, *file_bt, *file_te;
  int            to_file;

  cmd_lb = GTK_WIDGET(gtk_object_get_data(GTK_OBJECT(widget),
    PRINT_CMD_LB_KEY));
  cmd_te = GTK_WIDGET(gtk_object_get_data(GTK_OBJECT(widget),
    PRINT_CMD_TE_KEY));
  file_bt = GTK_WIDGET(gtk_object_get_data(GTK_OBJECT(widget),
    PRINT_FILE_BT_KEY));
  file_te = GTK_WIDGET(gtk_object_get_data(GTK_OBJECT(widget),
    PRINT_FILE_TE_KEY));
  if (GTK_TOGGLE_BUTTON (widget)->active) {
    /* They selected "Print to File" */
    to_file = TRUE;
  } else {
    /* They selected "Print to Command" */
    to_file = FALSE;
  }
  gtk_widget_set_sensitive(cmd_lb, !to_file);
  gtk_widget_set_sensitive(cmd_te, !to_file);
  gtk_widget_set_sensitive(file_bt, to_file);
  gtk_widget_set_sensitive(file_te, to_file);
}

static void
print_file_cb(GtkWidget *file_bt, gpointer file_te)
{
  GtkWidget *fs;

  fs = gtk_file_selection_new ("Ethereal: Print to File");
	gtk_object_set_data(GTK_OBJECT(fs), PRINT_FILE_TE_KEY, file_te);

  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->ok_button),
    "clicked", (GtkSignalFunc) print_fs_ok_cb, fs);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->cancel_button),
    "clicked", (GtkSignalFunc) print_fs_cancel_cb, fs);

  gtk_widget_show(fs);
}

static void
print_fs_ok_cb(GtkWidget *w, gpointer data)
{
  
  gtk_entry_set_text(GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(data),
      PRINT_FILE_TE_KEY)),
      gtk_file_selection_get_filename (GTK_FILE_SELECTION(data)));
  gtk_widget_destroy(GTK_WIDGET(data));
}

static void
print_fs_cancel_cb(GtkWidget *w, gpointer data)
{
  gtk_widget_destroy(GTK_WIDGET(data));
}

static void
print_ok_cb(GtkWidget *ok_bt, gpointer parent_w)
{
  GtkWidget *button;
  char *dest;

  button = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(ok_bt),
                                              PRINT_DEST_RB_KEY);
  if (GTK_TOGGLE_BUTTON (button)->active)
    print_to_file = TRUE;
  else
    print_to_file = FALSE;

  if (print_to_file)
    dest = g_strdup(gtk_entry_get_text(GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(ok_bt),
      PRINT_FILE_TE_KEY))));
  else
    dest = g_strdup(gtk_entry_get_text(GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(ok_bt),
      PRINT_CMD_TE_KEY))));

  gtk_widget_destroy(GTK_WIDGET(parent_w));
#if 0
  display_opt_window_active = FALSE;
#endif

  /* Now print the packets */
  if (!print_packets(&cf, print_to_file, dest)) {
    if (print_to_file)
      simple_dialog(ESD_TYPE_WARN, NULL,
        file_write_error_message(errno), dest);
    else
      simple_dialog(ESD_TYPE_WARN, NULL, "Couldn't run print command %s.",
        prefs.pr_cmd);
  }

  g_free(dest);
}

static void
print_close_cb(GtkWidget *close_bt, gpointer parent_w)
{

  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
#if 0
  display_opt_window_active = FALSE;
#endif
}

/* Print a packet */
void
file_print_packet_cmd_cb(GtkWidget *widget, gpointer data) {
  FILE *fh;

  switch (prefs.pr_dest) {

  case PR_DEST_CMD:
    fh = popen(prefs.pr_cmd, "w");
    break;

  case PR_DEST_FILE:
    fh = fopen(prefs.pr_file, "w");
    break;

  default:
    fh = NULL;	/* XXX - "can't happen" */
    break;
  }
  if (fh == NULL) {
    switch (prefs.pr_dest) {

    case PR_DEST_CMD:
      simple_dialog(ESD_TYPE_WARN, NULL, "Couldn't run print command %s.",
        prefs.pr_cmd);
      break;

    case PR_DEST_FILE:
      simple_dialog(ESD_TYPE_WARN, NULL, file_write_error_message(errno),
        prefs.pr_file);
      break;
    }
    return;
  }

  print_preamble(fh);
  proto_tree_print(-1, (GNode*) cf.protocol_tree, cf.pd, cf.fd, fh);
  print_finale(fh);
  close_print_dest(prefs.pr_dest == PR_DEST_FILE, fh);
}

/* What to do when a list item is selected/unselected */
void
packet_list_select_cb(GtkWidget *w, gint row, gint col, gpointer evt) {

#ifdef HAVE_LIBPCAP
  if (!sync_mode) {
#endif
    if (cf.wth)
      return; 
#ifdef HAVE_LIBPCAP
  }
#endif
  blank_packetinfo();
  select_packet(&cf, row);
}

void
packet_list_unselect_cb(GtkWidget *w, gint row, gint col, gpointer evt) {
  unselect_packet(&cf);
}

void
tree_view_cb(GtkWidget *w, gpointer data) {

  tree_selected_start = -1;
  tree_selected_len = -1;

  if (GTK_TREE(w)->selection) {
    tree_selected_start = 
	(gint) gtk_object_get_data(GTK_OBJECT(GTK_TREE(w)->selection->data),
				   E_TREEINFO_START_KEY);
    tree_selected_len   = 
	(gint) gtk_object_get_data(GTK_OBJECT(GTK_TREE(w)->selection->data),
				   E_TREEINFO_LEN_KEY);
  }

  gtk_text_freeze(GTK_TEXT(byte_view));
  gtk_text_set_point(GTK_TEXT(byte_view), 0);
  gtk_text_forward_delete(GTK_TEXT(byte_view),
    gtk_text_get_length(GTK_TEXT(byte_view)));
  packet_hex_print(GTK_TEXT(byte_view), cf.pd, cf.fd->cap_len, 
		   tree_selected_start, 
		   tree_selected_len);
  
  gtk_text_thaw(GTK_TEXT(byte_view));
}

void
file_quit_cmd_cb (GtkWidget *widget, gpointer data) {
  if (cf.save_file && !cf.user_saved) {
	unlink(cf.save_file);
  }
  gtk_exit(0);
}

void blank_packetinfo() {
  pi.ip_src   = 0;
  pi.ip_dst   = 0;
  pi.ipproto  = 0;
  pi.srcport  = 0;
  pi.destport = 0;
}

/* Things to do when the main window is realized */
void
main_realize_cb(GtkWidget *w, gpointer data) {
#ifdef HAVE_LIBPCAP
  if (start_capture) {
    capture();
    start_capture = 0;
  }
#endif
}

#ifdef HAVE_LIBPCAP
static void 
sigusr2_handler(int sig) {
  sigusr2_received = 1;
  signal(SIGUSR2, sigusr2_handler);
}
#endif

/* call initialization routines at program startup time */
static void
ethereal_proto_init(void) {
  proto_init();
  init_dissect_udp();
  dfilter_init();
}

static void 
print_usage(void) {

  fprintf(stderr, "This is GNU %s %s, compiled with %s\n", PACKAGE,
	  VERSION, comp_info_str);
  fprintf(stderr, "%s [-vh] [-FkQS] [-b bold font] [-B byte view height] [-c count]\n",
	  PACKAGE);
  fprintf(stderr, "         [-f \"filter expression\"] [-i interface] [-m medium font] [-n]\n");
  fprintf(stderr, "         [-P packet list height] [-r infile] [-s snaplen]\n");
  fprintf(stderr, "         [-t <time stamp format>] [-T tree view height] [-w savefile] \n");
}

/* And now our feature presentation... [ fade to music ] */
int
main(int argc, char *argv[])
{
  char               *command_name, *s;
  int                  i;
#ifndef WIN32
  int                  opt;
  extern char         *optarg;
#endif
  char                *pf_path;
  int                 pf_open_errno = 0;
  int                 err;
  GtkWidget           *window, *main_vbox, *menubar, *u_pane, *l_pane,
                      *bv_table, *bv_hscroll, *bv_vscroll, *stat_hbox, 
                      *tv_scrollw, *filter_bt, *filter_te;
  GtkStyle            *pl_style;
  GtkAccelGroup       *accel;
  GtkWidget	      *packet_sw;
  gint                 pl_size = 280, tv_size = 95, bv_size = 75;
  gchar               *rc_file, *cf_name = NULL, *rfilter = NULL;
  dfilter             *rfcode = NULL;
  gboolean             rfilter_parse_failed = FALSE;
  e_prefs             *prefs;
  gchar              **col_title;

  ethereal_path = argv[0];

  /* If invoked as "ethereal-dump-fields", we dump out a glossary of
     display filter symbols; we specify that by checking the name,
     so that we can do so before looking at the argument list -
     we don't want to look at the argument list, because we don't
     want to call "gtk_init()", because we don't want to have to
     do any X stuff just to do a build. */
  command_name = strrchr(ethereal_path, '/');
  if (command_name == NULL)
    command_name = ethereal_path;
  else
    command_name++;
  if (strcmp(command_name, "ethereal-dump-fields") == 0) {
    ethereal_proto_init();
    proto_registrar_dump();
    exit(0);
  }
  
  /* Let GTK get its args */
  gtk_init (&argc, &argv);
  
  prefs = read_prefs(&pf_path);
  if (pf_path != NULL) {
    /* The preferences file exists, but couldn't be opened; "pf_path" is
       its pathname.  Remember "errno", as that says why the attempt
       failed. */
    pf_open_errno = errno;
  }

  /* Initialize the capture file struct */
  cf.plist		= NULL;
  cf.plist_end		= NULL;
  cf.wth		= NULL;
  cf.fh			= NULL;
  cf.rfcode		= NULL;
  cf.dfilter		= NULL;
  cf.dfcode		= dfilter_new();
#ifdef HAVE_LIBPCAP
  cf.cfilter		= NULL;
#endif
  cf.iface		= NULL;
  cf.save_file		= NULL;
  cf.save_file_fd	= -1;
  cf.user_saved		= 0;
  cf.snap		= WTAP_MAX_PACKET_SIZE;
  cf.count		= 0;
  cf.cinfo.num_cols	= prefs->num_cols;
  cf.cinfo.col_fmt      = (gint *) g_malloc(sizeof(gint) * cf.cinfo.num_cols);
  cf.cinfo.fmt_matx	= (gboolean **) g_malloc(sizeof(gboolean *) * cf.cinfo.num_cols);
  cf.cinfo.col_data	= (gchar **) g_malloc(sizeof(gchar *) * cf.cinfo.num_cols);
  cf.cinfo.col_width	= (gint *) g_malloc(sizeof(gint) * cf.cinfo.num_cols);

  /* Assemble the compile-time options */
  snprintf(comp_info_str, 256,
#ifdef GTK_MAJOR_VERSION
    "GTK+ %d.%d.%d, %s libpcap", GTK_MAJOR_VERSION, GTK_MINOR_VERSION,
    GTK_MICRO_VERSION,
#else
    "GTK+ (version unknown), %s libpcap",
#endif

#ifdef HAVE_LIBPCAP
   "with"
#else
   "without"
#endif
   );

#ifndef WIN32
  /* Now get our args */
  while ((opt = getopt(argc, argv, "b:B:c:f:Fhi:km:nP:Qr:R:Ss:t:T:w:W:v")) != EOF) {
    switch (opt) {
      case 'b':	       /* Bold font */
	bold_font = g_strdup(optarg);
	break;
      case 'B':        /* Byte view pane height */
        bv_size = atoi(optarg);
        break;
      case 'c':        /* Capture xxx packets */
        cf.count = atoi(optarg);
        break;
#ifdef HAVE_LIBPCAP
      case 'f':
	cf.cfilter = g_strdup(optarg);
	break;
      case 'F':	       /* Fork to capture */
        fork_mode = 1;
        break;
#endif
      case 'h':        /* Print help and exit */
	print_usage();
	exit(0);
        break;
      case 'i':        /* Use interface xxx */
        cf.iface = g_strdup(optarg);
        break;
      case 'm':        /* Medium font */
	medium_font = g_strdup(optarg);
	break;
      case 'n':        /* No name resolution */
	g_resolving_actif = 0;
	break;
#ifdef HAVE_LIBPCAP
      case 'k':        /* Start capture immediately */
        start_capture = 1;
        break;
#endif
      case 'P':        /* Packet list pane height */
        pl_size = atoi(optarg);
        break;
#ifdef HAVE_LIBPCAP
      case 'Q':        /* Quit after capture (just capture to file) */
        quit_after_cap = 1;
        start_capture = 1;  /*** -Q implies -k !! ***/
        break;
#endif
      case 'r':        /* Read capture file xxx */
        cf_name = g_strdup(optarg);
        break;
      case 'R':        /* Read file filter */
        rfilter = optarg;
        break;
#ifdef HAVE_LIBPCAP
      case 's':        /* Set the snapshot (capture) length */
        cf.snap = atoi(optarg);
        break;
      case 'S':        /* "Sync" mode: used for following file ala tail -f */
        sync_mode = 1;
        fork_mode = 1; /* -S implies -F */
        break;
#endif
      case 't':        /* Time stamp type */
        if (strcmp(optarg, "r") == 0)
          timestamp_type = RELATIVE;
        else if (strcmp(optarg, "a") == 0)
          timestamp_type = ABSOLUTE;
        else if (strcmp(optarg, "d") == 0)
          timestamp_type = DELTA;
        else {
          fprintf(stderr, "ethereal: Invalid time stamp type \"%s\"\n",
            optarg);
          fprintf(stderr, "It must be \"r\" for relative, \"a\" for absolute,\n");
          fprintf(stderr, "or \"d\" for delta.\n");
          exit(1);
        }
        break;
      case 'T':        /* Tree view pane height */
        tv_size = atoi(optarg);
        break;
      case 'v':        /* Show version and exit */
        printf("%s %s, with %s\n", PACKAGE, VERSION, comp_info_str);
        exit(0);
        break;
#ifdef HAVE_LIBPCAP
      case 'w':        /* Write to capture file xxx */
        cf.save_file = g_strdup(optarg);
	break;
      case 'W':        /* Write to capture file FD xxx */
        cf.save_file_fd = atoi(optarg);
	break;
#endif
    }
  }
#endif

  if (start_capture) {
    if (cf.iface == NULL) {
      fprintf(stderr, "ethereal: \"-k\" flag was specified without \"-i\" flag\n");
      exit(1);
    }
    if (cf.save_file == NULL) {
      fprintf(stderr, "ethereal: \"-k\" flag was specified without \"-w\" flag\n");
      exit(1);
    }
    if (fork_mode) {
      if (cf.save_file_fd == -1) {
        fprintf(stderr, "ethereal: \"-k\" flag was specified with \"-%c\" flag but without \"-W\" flag\n",
            (sync_mode ? 'S' : 'F'));
        exit(1);
      }
    }
  }

#ifdef HAVE_LIBPCAP
  if (sync_mode)
    signal(SIGUSR2, sigusr2_handler);
#endif

  /* Build the column format array */  
  col_title = (gchar **) g_malloc(sizeof(gchar *) * cf.cinfo.num_cols);
  
  for (i = 0; i < cf.cinfo.num_cols; i++) {
    cf.cinfo.col_fmt[i] = get_column_format(i);
    col_title[i] = g_strdup(get_column_title(i));
    cf.cinfo.fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean) *
      NUM_COL_FMTS);
    get_column_format_matches(cf.cinfo.fmt_matx[i], cf.cinfo.col_fmt[i]);
    cf.cinfo.col_data[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
  }

  if (cf.snap < 1)
    cf.snap = WTAP_MAX_PACKET_SIZE;
  else if (cf.snap < MIN_PACKET_SIZE)
    cf.snap = MIN_PACKET_SIZE;
  
  rc_file = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(RC_FILE) + 4);
  sprintf(rc_file, "%s/%s", getenv("HOME"), RC_FILE);
  gtk_rc_parse(rc_file);

  if ((m_r_font = gdk_font_load(medium_font)) == NULL) {
    fprintf(stderr, "ethereal: Error font %s not found (use -m option)\n", medium_font);
    exit(1);
  }

  if ((m_b_font = gdk_font_load(bold_font)) == NULL) {
    fprintf(stderr, "ethereal: Error font %s not found (use -b option)\n", bold_font);
    exit(1);
  }

  /* Main window */  
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_widget_set_name(window, "main window");
  gtk_signal_connect(GTK_OBJECT(window), "delete_event",
    GTK_SIGNAL_FUNC(file_quit_cmd_cb), "WM destroy");
  gtk_signal_connect(GTK_OBJECT(window), "destroy", 
    GTK_SIGNAL_FUNC(file_quit_cmd_cb), "WM destroy");
  gtk_signal_connect(GTK_OBJECT (window), "realize",
    GTK_SIGNAL_FUNC(main_realize_cb), NULL);
  gtk_window_set_title(GTK_WINDOW(window), "The Ethereal Network Analyzer");
  gtk_widget_set_usize(GTK_WIDGET(window), DEF_WIDTH, -1);
  gtk_window_set_policy(GTK_WINDOW(window), TRUE, TRUE, FALSE);

  /* Container for menu bar, paned windows and progress/info box */
  main_vbox = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vbox), 1);
  gtk_container_add(GTK_CONTAINER(window), main_vbox);
  gtk_widget_show(main_vbox);

  /* Menu bar */
  get_main_menu(&menubar, &accel);
  gtk_window_add_accel_group(GTK_WINDOW(window), accel);
  gtk_box_pack_start(GTK_BOX(main_vbox), menubar, FALSE, TRUE, 0);
  gtk_widget_show(menubar);

  /* Panes for the packet list, tree, and byte view */
  u_pane = gtk_vpaned_new();
  gtk_paned_gutter_size(GTK_PANED(u_pane), (GTK_PANED(u_pane))->handle_size);
  l_pane = gtk_vpaned_new();
  gtk_paned_gutter_size(GTK_PANED(l_pane), (GTK_PANED(l_pane))->handle_size);
  gtk_container_add(GTK_CONTAINER(main_vbox), u_pane);
  gtk_widget_show(u_pane);
  gtk_paned_add2 (GTK_PANED(u_pane), l_pane);
  gtk_widget_show(l_pane);

  /* Packet list */
  packet_list = gtk_clist_new_with_titles(cf.cinfo.num_cols, col_title);
  gtk_clist_column_titles_passive(GTK_CLIST(packet_list));
  packet_sw = gtk_scrolled_window_new(NULL, NULL);
  gtk_widget_show(packet_sw);
  gtk_container_add(GTK_CONTAINER(packet_sw), packet_list);
  pl_style = gtk_style_new();
  gdk_font_unref(pl_style->font);
  pl_style->font = m_r_font;
  gtk_widget_set_style(packet_list, pl_style);
  gtk_widget_set_name(packet_list, "packet list");
  gtk_signal_connect(GTK_OBJECT(packet_list), "select_row",
    GTK_SIGNAL_FUNC(packet_list_select_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(packet_list), "unselect_row",
    GTK_SIGNAL_FUNC(packet_list_unselect_cb), NULL);
  for (i = 0; i < cf.cinfo.num_cols; i++) {
    if (get_column_resize_type(cf.cinfo.col_fmt[i]) != RESIZE_MANUAL)
      gtk_clist_set_column_auto_resize(GTK_CLIST(packet_list), i, TRUE);

    /* Right-justify the packet number column. */
    if (cf.cinfo.col_fmt[i] == COL_NUMBER)
      gtk_clist_set_column_justification(GTK_CLIST(packet_list), i, 
        GTK_JUSTIFY_RIGHT);

    /* Save static column sizes to use during a "-S" capture, so that
       the columns don't resize during a live capture. */
    cf.cinfo.col_width[i] = get_column_width(get_column_format(i),
						pl_style->font);
  }
  gtk_widget_set_usize(packet_list, -1, pl_size);
  gtk_paned_add1(GTK_PANED(u_pane), packet_sw);
  gtk_widget_show(packet_list);
  
  /* Tree view */
  tv_scrollw = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(tv_scrollw),
    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_paned_add1(GTK_PANED(l_pane), tv_scrollw);
  gtk_widget_set_usize(tv_scrollw, -1, tv_size);
  gtk_widget_show(tv_scrollw);
  
  tree_view = gtk_tree_new();
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(tv_scrollw),
		  tree_view);
  gtk_tree_set_selection_mode(GTK_TREE(tree_view), GTK_SELECTION_SINGLE);

  /* XXX - what's the difference between the next two lines? */
  gtk_tree_set_view_lines(GTK_TREE(tree_view), FALSE);
  gtk_tree_set_view_mode(GTK_TREE(tree_view), GTK_TREE_VIEW_ITEM);

  gtk_signal_connect(GTK_OBJECT(tree_view), "selection_changed",
    GTK_SIGNAL_FUNC(tree_view_cb), NULL);
  gtk_widget_show(tree_view);

  item_style = gtk_style_new();
  gdk_font_unref(item_style->font);
  item_style->font = m_r_font;

  /* Byte view */
  bv_table = gtk_table_new (2, 2, FALSE);
  gtk_paned_add2(GTK_PANED(l_pane), bv_table);
  gtk_widget_set_usize(bv_table, -1, bv_size);
  gtk_widget_show(bv_table);

  byte_view = gtk_text_new(NULL, NULL);
  gtk_text_set_editable(GTK_TEXT(byte_view), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(byte_view), FALSE);
  gtk_table_attach (GTK_TABLE (bv_table), byte_view, 0, 1, 0, 1,
    GTK_FILL | GTK_EXPAND, GTK_FILL | GTK_EXPAND | GTK_SHRINK, 0, 0);
  gtk_widget_show(byte_view);

  bv_hscroll = gtk_hscrollbar_new(GTK_TEXT(byte_view)->hadj);
  gtk_table_attach(GTK_TABLE(bv_table), bv_hscroll, 0, 1, 1, 2,
    GTK_EXPAND | GTK_FILL, GTK_FILL, 0, 0);
  gtk_widget_show (bv_hscroll);

  bv_vscroll = gtk_vscrollbar_new(GTK_TEXT(byte_view)->vadj);
  gtk_table_attach(GTK_TABLE(bv_table), bv_vscroll, 1, 2, 0, 1,
    GTK_FILL, GTK_EXPAND | GTK_FILL | GTK_SHRINK, 0, 0);
  gtk_widget_show(bv_vscroll);
  
  /* Progress/filter/info box */
  stat_hbox = gtk_hbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(stat_hbox), 0);
  gtk_box_pack_start(GTK_BOX(main_vbox), stat_hbox, FALSE, TRUE, 0);
  gtk_widget_show(stat_hbox);

  prog_bar = gtk_progress_bar_new();  
  gtk_box_pack_start(GTK_BOX(stat_hbox), prog_bar, FALSE, TRUE, 3);
  gtk_widget_show(prog_bar);

  filter_bt = gtk_button_new_with_label("Filter:");
  gtk_signal_connect(GTK_OBJECT(filter_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_cb), (gpointer) E_PR_PG_FILTER);
  gtk_box_pack_start(GTK_BOX(stat_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);
  
  filter_te = gtk_entry_new();
  gtk_object_set_data(GTK_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(stat_hbox), filter_te, TRUE, TRUE, 3);
  gtk_signal_connect(GTK_OBJECT(filter_te), "activate",
    GTK_SIGNAL_FUNC(filter_activate_cb), (gpointer) NULL);
  gtk_widget_show(filter_te);

  /* Sets the text entry widget pointer as the E_DILTER_TE_KEY data
   * of any widget that ends up calling a callback which needs
   * that text entry pointer */
  set_menu_object_data("/File/Open...", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/File/Reload", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Display/Match Selected", E_DFILTER_TE_KEY,
    filter_te);

  info_bar = gtk_statusbar_new();
  main_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "main");
  file_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "file");
  gtk_statusbar_push(GTK_STATUSBAR(info_bar), main_ctx, DEF_READY_MESSAGE);
  gtk_box_pack_start(GTK_BOX(stat_hbox), info_bar, TRUE, TRUE, 0);
  gtk_widget_show(info_bar);

/* 
   Hmmm should we do it here
*/

  ethereal_proto_init();   /* Init anything that needs initializing */

  gtk_widget_show(window);

  /* If we were given the name of a capture file, read it in now;
     we defer it until now, so that, if we can't open it, and pop
     up an alert box, the alert box is more likely to come up on
     top of the main window - but before the preference-file-error
     alert box, so, if we get one of those, it's more likely to come
     up on top of us. */
  if (cf_name) {
    if (rfilter != NULL) {
      rfcode = dfilter_new();
      if (dfilter_compile(rfcode, rfilter) != 0) {
        simple_dialog(ESD_TYPE_WARN, NULL, dfilter_error_msg);
        dfilter_destroy(rfcode);
        rfilter_parse_failed = TRUE;
      }
    }
    if (!rfilter_parse_failed) {
      if ((err = open_cap_file(cf_name, &cf)) == 0) {
        cf.rfcode = rfcode;
        err = read_cap_file(&cf);
        s = strrchr(cf_name, '/');
        if (s) {
          last_open_dir = cf_name;
          *s = '\0';
        }
        set_menu_sensitivity("/File/Save As...", TRUE);
      }
    }
  }

  /* If we failed to open the preferences file, pop up an alert box;
     we defer it until now, so that the alert box is more likely to
     come up on top of the main window. */
  if (pf_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Can't open preferences file\n\"%s\": %s.", pf_path,
        strerror(pf_open_errno));
  }

  gtk_main();

  exit(0);
}
