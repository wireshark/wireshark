/* ethereal.c
 *
 * $Id: ethereal.c,v 1.49 1999/07/07 23:54:12 guy Exp $
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
 * - Fix progress/status bar glitches?  (GTK+ bug?)
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
#include <pcap.h> /* needed for capture.h */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
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

static void file_save_ok_cb(GtkWidget *w, GtkFileSelection *fs);
static void file_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs);

FILE        *data_out_file = NULL;
packet_info  pi;
capture_file cf;
proto_tree	*protocol_tree = NULL;
GtkWidget   *file_sel, *packet_list, *tree_view, *byte_view, *prog_bar,
            *info_bar;
GdkFont     *m_r_font, *m_b_font;
GtkStyle    *pl_style;
guint        main_ctx, file_ctx;
frame_data  *fd;
gint         start_capture = 0;
gchar        comp_info_str[256];
gchar       *ethereal_path = NULL;
gchar       *medium_font = MONO_MEDIUM_FONT;
gchar       *bold_font = MONO_BOLD_FONT;

ts_type timestamp_type = RELATIVE;

GtkStyle *item_style;

int sync_mode;	/* allow sync */
int sync_pipe[2]; /* used to sync father */
int fork_mode;	/* fork a child to do the capture */
int sigusr2_received = 0;
int quit_after_cap; /* Makes a "capture only mode". Implies -k */

/* Specifies byte offsets for object selected in tree */
static gint tree_selected_start=-1, tree_selected_len=-1; 

#define E_DFILTER_TE_KEY "display_filter_te"

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

		"\nSee http://ethereal.zing.org for more information",
                VERSION, comp_info_str);
}

/* Things to do when the OK button is pressed */
void
file_sel_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
  gchar     *cf_name;
  int        err;

  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (fs)));
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  /* this depends upon load_cap_file removing the filename from
   * cf_name, leaving only the path to the directory. */
  if ((err = load_cap_file(cf_name, &cf)) == 0)
    chdir(cf_name);
  else {
    simple_dialog(ESD_TYPE_WARN, NULL, file_open_error_message(err, FALSE),
		cf_name);
  }
  g_free(cf_name);
#ifdef USE_ITEM
    set_menu_sensitivity("/File/Save", FALSE);
    set_menu_sensitivity("/File/Save As...", TRUE);
    set_menu_sensitivity("/Tools/Summary", TRUE);
#else
    set_menu_sensitivity("<Main>/File/Save", FALSE);
    set_menu_sensitivity("<Main>/File/Save As...", TRUE);
    set_menu_sensitivity("<Main>/Tools/Summary", TRUE);
#endif
}

/* Update the progress bar */
gint
file_progress_cb(gpointer p) {
  gtk_progress_bar_update(GTK_PROGRESS_BAR(prog_bar),
    (gfloat) ftell(cf.fh) / (gfloat) cf.f_len);
  return TRUE;
}

/* Follow a TCP stream */
void
follow_stream_cb( GtkWidget *w, gpointer data ) {
  char filename1[128];
  GtkWidget *streamwindow, *box, *text, *vscrollbar, *table;
  GtkWidget *filter_te = NULL;
  int err;

  if (w)
  	filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);

  if( pi.ipproto == 6 ) {
    /* we got tcp so we can follow */
    /* check to see if we are using a filter */
    if( cf.dfilter != NULL ) {
      /* get rid of this one */
      g_free( cf.dfilter );
      cf.dfilter = NULL;
    }
    /* create a new one and set the display filter entry accordingly */
    cf.dfilter = build_follow_filter( &pi );
    if (filter_te)
	    gtk_entry_set_text(GTK_ENTRY(filter_te), cf.dfilter);
    /* reload so it goes in effect. Also we set data_out_file which 
       tells the tcp code to output the data */
    close_cap_file( &cf, info_bar, file_ctx);
    strcpy( filename1, tmpnam(NULL) );
    data_out_file = fopen( filename1, "a" );
    if( data_out_file == NULL ) {
      fprintf( stderr, "Could not open tmp file %s\n", filename1 );
    }
    reset_tcp_reassembly();
    err = load_cap_file( cf.filename, &cf );
    if (err != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL, file_open_error_message(err, FALSE),
		cf.filename);
    }
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
    data_out_file = NULL;
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
      fclose( data_out_file );
      unlink( filename1 );
    }
    gtk_text_thaw( GTK_TEXT(text) );
    data_out_file = NULL;
    gtk_widget_show( streamwindow );
    if( cf.dfilter != NULL ) {
      g_free( cf.dfilter );
      cf.dfilter = NULL;
    }
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
#if 0
    char *buf = malloc(1024);
#endif
    GtkWidget *filter_te = NULL;

    if (w)
  	filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);

    if (tree_selected_start<0) {
	simple_dialog(ESD_TYPE_WARN, NULL,
		      "Error determining selected bytes.  Please make\n"
		      "sure you have selected a field within the tree\n"
		      "view to be matched.");
	return;
    }
#if 0
    switch (cf.lnk_t) {
    case DLT_EN10MB :
	c="ether";
	break;
    case DLT_FDDI :
	c="fddi";
	break;
    default :
#endif
	simple_dialog(ESD_TYPE_WARN, NULL,
		      "Unsupported frame type format. Only Ethernet and FDDI\n"
		      "frame formats are supported.");
	return;
#if 0
    }

    sprintf(buf, "("); ptr = buf+strlen(buf);
    for (i=0, c=cf.pd+tree_selected_start; i+4<tree_selected_len; i+=4, c+=4) {
	sprintf(ptr, "(ether[%d : 4]=0x%02X%02X%02X%02X) and ", 
	       tree_selected_start+i, 
	       *c,
	       *(c+1),
	       *(c+2),
	       *(c+3));
	ptr = buf+strlen(buf);
    }

    sprintf(ptr, "(ether[%d : %d]=0x", 
	   tree_selected_start+i, 
	   tree_selected_len - i);
    ptr = buf+strlen(buf);
    for (;i<tree_selected_len; i++) {
	sprintf(ptr, "%02X", *c++);
	ptr = buf+strlen(buf);
    }

    sprintf(ptr, "))");

    if( cf.dfilter != NULL ) {
      /* get rid of this one */
      g_free( cf.dfilter );
      cf.dfilter = NULL;
    }
    /* create a new one and set the display filter entry accordingly */
    cf.dfilter = buf;
    if (filter_te)
	gtk_entry_set_text(GTK_ENTRY(filter_te), cf.dfilter);
    /* reload so it goes in effect. */
    close_cap_file( &cf, info_bar, file_ctx);
    load_cap_file( cf.filename, &cf );
    if( cf.dfilter != NULL ) {
      g_free( cf.dfilter );
      cf.dfilter = NULL;
    }
#endif
}

/* Open a file */
void
file_open_cmd_cb(GtkWidget *w, gpointer data) {
  file_sel = gtk_file_selection_new ("Ethereal: Open Capture File");
  
  /* Connect the ok_button to file_ok_sel_cb function and pass along the
     pointer to the filter entry */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (file_sel)->ok_button),
    "clicked", (GtkSignalFunc) file_sel_ok_cb, file_sel );

  /* Gilbert --- I added this if statement. Is this right? */
  if (w)
  gtk_object_set_data(GTK_OBJECT(GTK_FILE_SELECTION(file_sel)->ok_button),
    E_DFILTER_TE_KEY, gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY));

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (file_sel)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_sel));

  if( fork_mode && (cf.save_file != NULL) )
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), cf.save_file);
  else
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), "");

  gtk_widget_show(file_sel);
}

/* Close a file */
void
file_close_cmd_cb(GtkWidget *widget, gpointer data) {
  close_cap_file(&cf, info_bar, file_ctx);
#ifdef USE_ITEM
  set_menu_sensitivity("/File/Close", FALSE);
  set_menu_sensitivity("/File/Reload", FALSE);
  set_menu_sensitivity("/Tools/Summary", FALSE);
#else
  set_menu_sensitivity("<Main>/File/Close", FALSE);
  set_menu_sensitivity("<Main>/File/Reload", FALSE);
  set_menu_sensitivity("<Main>/Tools/Summary", FALSE);
#endif
}

void
file_save_cmd_cb(GtkWidget *w, gpointer data) {
  file_sel = gtk_file_selection_new ("Ethereal: Save Capture File");
  
  /* Connect the ok_button to file_ok_sel_cb function and pass along the
     pointer to the filter entry */
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
  file_sel = gtk_file_selection_new ("Ethereal: Save Capture File as");

  /* Connect the ok_button to file_ok_sel_cb function and pass along the
     pointer to the filter entry */
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
	err = load_cap_file(cf_name, &cf);
	if (err != 0) {
		simple_dialog(ESD_TYPE_WARN, NULL,
		    file_open_error_message(err, FALSE), cf_name);
	}

#ifdef USE_ITEM
	set_menu_sensitivity("/File/Save", FALSE);
	set_menu_sensitivity("/File/Save As...", TRUE);
#else
	set_menu_sensitivity("<Main>/File/Save", FALSE);
	set_menu_sensitivity("<Main>/File/Save As...", TRUE);
#endif
}

static void
file_save_as_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
	gchar	*cf_name;
	int	err;

	cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
	gtk_widget_hide(GTK_WIDGET (fs));
	gtk_widget_destroy(GTK_WIDGET (fs));

	if (!file_cp(cf.save_file, cf_name))
		return;
	g_free(cf.save_file);
	cf.save_file = g_strdup(cf_name);
	cf.user_saved = 1;
	err = load_cap_file(cf_name, &cf);
	if (err != 0) {
		simple_dialog(ESD_TYPE_WARN, NULL,
		    file_open_error_message(err, FALSE), cf_name);
	}

#ifdef USE_ITEM
	set_menu_sensitivity("/File/Save", FALSE);
	set_menu_sensitivity("/File/Save As...", TRUE);
#else
	set_menu_sensitivity("<Main>/File/Save", FALSE);
	set_menu_sensitivity("<Main>/File/Save As...", TRUE);
#endif
}

/* Reload a file using the current display filter */
void
file_reload_cmd_cb(GtkWidget *w, gpointer data) {
  /*GtkWidget *filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);*/
  GtkWidget *filter_te;
  int err;

  filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);

  if (cf.dfilter) g_free(cf.dfilter);
  cf.dfilter = g_strdup(gtk_entry_get_text(GTK_ENTRY(filter_te)));
  err = load_cap_file(cf.filename, &cf);
  if (err != 0) {
    simple_dialog(ESD_TYPE_WARN, NULL, file_open_error_message(err, FALSE),
		cf.filename);
  }
}

/* Print a packet */
void
file_print_cmd_cb(GtkWidget *widget, gpointer data) {
    print_tree(cf.pd, fd, GTK_TREE(tree_view));
}

/* What to do when a list item is selected/unselected */
void
packet_list_select_cb(GtkWidget *w, gint row, gint col, gpointer evt) {

  if (!sync_mode) {
  if (cf.wth) return; 
  }
  blank_packetinfo();
  gtk_text_freeze(GTK_TEXT(byte_view));
  gtk_text_set_point(GTK_TEXT(byte_view), 0);
  gtk_text_forward_delete(GTK_TEXT(byte_view),
  gtk_text_get_length(GTK_TEXT(byte_view)));

  /* get the frame data struct pointer for this frame */
  fd = (frame_data *) gtk_clist_get_row_data(GTK_CLIST(w), row);
  fseek(cf.fh, fd->file_off, SEEK_SET);
  fread(cf.pd, sizeof(guint8), fd->cap_len, cf.fh);

  /* create the logical protocol tree */
  if (protocol_tree)
      proto_tree_free(protocol_tree);
  protocol_tree = proto_tree_create_root();
  dissect_packet(cf.pd, fd, protocol_tree);

  /* display the GUI protocol tree and hex dump */
  proto_tree_draw(protocol_tree, tree_view);
  packet_hex_print(GTK_TEXT(byte_view), cf.pd, fd->cap_len, -1, -1);
  gtk_text_thaw(GTK_TEXT(byte_view));
}

void
packet_list_unselect_cb(GtkWidget *w, gint row, gint col, gpointer evt) {
  gtk_text_freeze(GTK_TEXT(byte_view));
  gtk_text_set_point(GTK_TEXT(byte_view), 0);
  gtk_text_forward_delete(GTK_TEXT(byte_view),
    gtk_text_get_length(GTK_TEXT(byte_view)));
  gtk_text_thaw(GTK_TEXT(byte_view));
  gtk_tree_clear_items(GTK_TREE(tree_view), 0,
    g_list_length(GTK_TREE(tree_view)->children));
}

void
tree_view_cb(GtkWidget *w) {

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
  packet_hex_print(GTK_TEXT(byte_view), cf.pd, fd->cap_len, 
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
  pi.srcip    = 0;
  pi.destip   = 0;
  pi.ipproto  = 0;
  pi.srcport  = 0;
  pi.destport = 0;
}

/* Things to do when the main window is realized */
void
main_realize_cb(GtkWidget *w, gpointer data) {
  if (start_capture) {
    capture();
    start_capture = 0;
  }
}

static void 
sigusr2_handler(int sig) {
  sigusr2_received = 1;
  signal(SIGUSR2, sigusr2_handler);
}

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
  int                  opt, i;
  extern char         *optarg;
  char                *pf_path;
  int                 pf_open_errno = 0;
  int                 err;
  GtkWidget           *window, *main_vbox, *menubar, *u_pane, *l_pane,
                      *bv_table, *bv_hscroll, *bv_vscroll, *stat_hbox, 
                      *tv_scrollw, *filter_bt, *filter_te;
#ifdef GTK_HAVE_FEATURES_1_1_0
  GtkAccelGroup *accel;
#else
  GtkAcceleratorTable *accel;
#endif

#ifdef GTK_HAVE_FEATURES_1_1_4
  GtkWidget	*packet_sw;
#endif
  gint                 pl_size = 280, tv_size = 95, bv_size = 75;
  gchar               *rc_file, *cf_name = NULL;
  e_prefs             *prefs;
  gint                *col_fmt;

  ethereal_path = argv[0];

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
  cf.wth		= NULL;
  cf.fh			= NULL;
  cf.dfilter		= NULL;
  cf.cfilter		= NULL;
  cf.dfcode		= NULL;
  cf.iface		= NULL;
  cf.save_file		= NULL;
  cf.user_saved		= 0;
  cf.snap		= MAX_PACKET_SIZE;
  cf.count		= 0;
  cf.cinfo.num_cols	= prefs->num_cols;
  cf.cinfo.col_title    = (gchar **) g_malloc(sizeof(gchar *) * cf.cinfo.num_cols);
  cf.cinfo.fmt_matx	= (gboolean **) g_malloc(sizeof(gboolean *) * cf.cinfo.num_cols);
  cf.cinfo.col_data	= (gchar **) g_malloc(sizeof(gchar *) * cf.cinfo.num_cols);
  cf.cinfo.col_width	= (gint *) g_malloc(sizeof(gint) * cf.cinfo.num_cols);

  /* Assemble the compile-time options */
  snprintf(comp_info_str, 256,
#ifdef GTK_MAJOR_VERSION
    "GTK+ %d.%d.%d", GTK_MAJOR_VERSION, GTK_MINOR_VERSION,
    GTK_MICRO_VERSION
#else
    "GTK+ (version unknown)"
#endif
   );

  /* Now get our args */
  while ((opt = getopt(argc, argv, "b:B:c:f:Fhi:km:nP:Qr:Ss:t:T:w:v")) != EOF) {
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
      case 'f':
	cf.cfilter = g_strdup(optarg);
	break;
      case 'F':	       /* Fork to capture */
        fork_mode = 1;
        break;
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
      case 'k':        /* Start capture immediately */
        start_capture = 1;
        break;
      case 'P':        /* Packet list pane height */
        pl_size = atoi(optarg);
        break;
      case 'Q':        /* Quit after capture (just capture to file) */
        quit_after_cap = 1;
        start_capture = 1;  /*** -Q implies -k !! ***/
        break;
      case 'r':        /* Read capture file xxx */
        cf_name = g_strdup(optarg);
        break;
      case 's':        /* Set the snapshot (capture) length */
        cf.snap = atoi(optarg);
        break;
      case 'S':        /* "Sync" mode: used for following file ala tail -f */
        sync_mode = 1;
        fork_mode = 1; /* -S implies -F */
        break;
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
      case 'w':        /* Write capture file xxx */
        cf.save_file = g_strdup(optarg);
	break;
    }
  }

  if (start_capture) {
    if (cf.iface == NULL) {
      fprintf(stderr, "ethereal: \"-k\" flag was specified without \"-i\" flag\n");
      exit(1);
    }
    if (cf.save_file == NULL) {
      fprintf(stderr, "ethereal: \"-k\" flag was specified without \"-w\" flag\n");
      exit(1);
    }
  }

  if (sync_mode)
    signal(SIGUSR2, sigusr2_handler);

  /* Build the column format array */  
  col_fmt   = (gint *) g_malloc(sizeof(gint) * cf.cinfo.num_cols);
  
  for (i = 0; i < cf.cinfo.num_cols; i++) {
    col_fmt[i]   = get_column_format(i);
    cf.cinfo.col_title[i] = g_strdup(get_column_title(i));
    cf.cinfo.fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean) *
      NUM_COL_FMTS);
    get_column_format_matches(cf.cinfo.fmt_matx[i], col_fmt[i]);
    cf.cinfo.col_data[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
    cf.cinfo.col_width[i] = 0;
  }

  if (cf.snap < 1)
    cf.snap = MAX_PACKET_SIZE;
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
#ifdef GTK_HAVE_FEATURES_1_1_0
  gtk_window_add_accel_group(GTK_WINDOW(window), accel);
#else
  gtk_window_add_accelerator_table(GTK_WINDOW(window), accel);
#endif
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
  packet_list = gtk_clist_new_with_titles(cf.cinfo.num_cols,
    cf.cinfo.col_title);
  gtk_clist_column_titles_passive(GTK_CLIST(packet_list));
#ifdef GTK_HAVE_FEATURES_1_1_4
  packet_sw = gtk_scrolled_window_new(NULL, NULL);
  gtk_widget_show(packet_sw);
  gtk_container_add(GTK_CONTAINER(packet_sw), packet_list);
#endif
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
    gtk_clist_set_column_width(GTK_CLIST(packet_list), i,
      gdk_string_width(pl_style->font, cf.cinfo.col_title[i]));
    if (col_fmt[i] == COL_NUMBER)
      gtk_clist_set_column_justification(GTK_CLIST(packet_list), i, 
        GTK_JUSTIFY_RIGHT);
  }
  gtk_widget_set_usize(packet_list, -1, pl_size);
#ifdef GTK_HAVE_FEATURES_1_1_4
  gtk_paned_add1(GTK_PANED(u_pane), packet_sw);
#else
  gtk_paned_add1(GTK_PANED(u_pane), packet_list);
#endif
  gtk_widget_show(packet_list);
  
  /* Tree view */
  tv_scrollw = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(tv_scrollw),
    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_paned_add1(GTK_PANED(l_pane), tv_scrollw);
  gtk_widget_set_usize(tv_scrollw, -1, tv_size);
  gtk_widget_show(tv_scrollw);
  
  tree_view = gtk_tree_new();
#ifdef GTK_HAVE_FEATURES_1_1_4
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(tv_scrollw),
		  tree_view);
#else
  gtk_container_add(GTK_CONTAINER(tv_scrollw), tree_view);
#endif
  gtk_tree_set_selection_mode(GTK_TREE(tree_view), GTK_SELECTION_SINGLE);
  gtk_tree_set_view_lines(GTK_TREE(tree_view), FALSE);
  gtk_tree_set_view_mode(GTK_TREE(tree_view), TRUE);
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
  gtk_widget_show(filter_te);

#ifdef USE_ITEM
  set_menu_object_data("/File/Open...", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/File/Reload", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Tools/Follow TCP Stream", E_DFILTER_TE_KEY,
    filter_te);
#else
  set_menu_object_data("<Main>/File/Open...", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("<Main>/File/Reload", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("<Main>/Tools/Follow TCP Stream", E_DFILTER_TE_KEY,
    filter_te);
#endif
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
     up an alert box, the alert box is more likely to cmoe up on
     top of the main window - but before the preference-file-error
     alert box, so, if we get one of those, it's more likely to come
     up on top of us. */
  if (cf_name) {
    err = load_cap_file(cf_name, &cf);
    if (err != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL, file_open_error_message(err, FALSE),
		cf_name);
    }
    cf_name[0] = '\0';
#ifdef USE_ITEM
    set_menu_sensitivity("/File/Save As...", TRUE);
    set_menu_sensitivity("/Tools/Summary", TRUE);
#else
    set_menu_sensitivity("<Main>/File/Save As...", TRUE);
    set_menu_sensitivity("<Main>/Tools/Summary", TRUE);
#endif
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
