/* main.c
 *
 * $Id: main.c,v 1.20 1999/10/11 18:02:46 guy Exp $
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
 * - Graphs
 * - Get AIX to work
 * - Check for end of packet in dissect_* routines.
 * - Playback window
 * - Multiple window support
 * - Add cut/copy/paste
 * - Create header parsing routines
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

#include "main.h"
#include "timestamp.h"
#include "packet.h"
#include "capture.h"
#include "summary.h"
#include "file.h"
#include "menu.h"
#include "prefs_dlg.h"
#include "column.h"
#include "print.h"
#include "resolv.h"
#include "follow.h"
#include "util.h"
#include "proto_draw.h"
#include "dfilter.h"
#include "keys.h"

FILE        *data_out_file = NULL;
packet_info  pi;
capture_file cf;
GtkWidget   *file_sel, *packet_list, *tree_view, *byte_view, *prog_bar,
            *info_bar;
GdkFont     *m_r_font, *m_b_font;
guint        main_ctx, file_ctx;
gchar        comp_info_str[256];
gchar       *ethereal_path = NULL;
gchar       *medium_font = MONO_MEDIUM_FONT;
gchar       *bold_font = MONO_BOLD_FONT;
gchar       *last_open_dir = NULL;

ts_type timestamp_type = RELATIVE;

GtkStyle *item_style;

/* Specifies byte offsets for object selected in tree */
static gint tree_selected_start=-1, tree_selected_len=-1; 


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
		"Peter Torvals            <petertv@xoommail.com>\n"
		"Christophe Tronche       <ch.tronche@computer.org>\n"

		"\nSee http://ethereal.zing.org for more information",
                VERSION, comp_info_str);
}

/* Follow the TCP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
follow_stream_cb( GtkWidget *w, gpointer data ) {
  char      filename1[128+1];
  GtkWidget *streamwindow, *box, *text, *vscrollbar, *table;
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

    /* Create a new filter that matches all packets in the TCP stream,
       and set the display filter entry accordingly */
    reset_tcp_reassembly();
    follow_filter = build_follow_filter( &pi );

    /* Run the display filter so it goes in effect. */
    filter_packets(&cf, follow_filter);

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
    char *buf;
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
    buf = g_malloc(32 + tree_selected_len * 3);
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

    /* create a new one and set the display filter entry accordingly */
    if (filter_te) {
	gtk_entry_set_text(GTK_ENTRY(filter_te), buf);
    }
    /* Run the display filter so it goes in effect. */
    filter_packets(&cf, buf);
}

/* Run the current display filter on the current packet set, and
   redisplay. */
static void
filter_activate_cb(GtkWidget *w, gpointer data)
{
  char *s = gtk_entry_get_text(GTK_ENTRY(w));

  filter_packets(&cf, g_strdup(s));
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

void collapse_all_cb(GtkWidget *widget, gpointer data) {
  if (cf.protocol_tree)
    collapse_all_tree(cf.protocol_tree, tree_view);
}

void expand_all_cb(GtkWidget *widget, gpointer data) {
  if (cf.protocol_tree)
    expand_all_tree(cf.protocol_tree, tree_view);
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

/* call initialization routines at program startup time */
static void
ethereal_proto_init(void) {
  proto_init();
  init_dissect_udp();
  dfilter_init();
}

static void
ethereal_proto_cleanup(void) {
	proto_cleanup();
	dfilter_cleanup();
}

static void 
print_usage(void) {

  fprintf(stderr, "This is GNU %s %s, compiled with %s\n", PACKAGE,
	  VERSION, comp_info_str);
  fprintf(stderr, "%s [-vh] [-kQS] [-b <bold font>] [-B <byte view height>] [-c count]\n",
	  PACKAGE);
  fprintf(stderr, "         [-f <filter expression>] [-i interface] [-m <medium font>] [-n]\n");
  fprintf(stderr, "         [-P <packet list height>] [-r infile] [-s snaplen]\n");
  fprintf(stderr, "         [-t <time stamp format>] [-T <tree view height>] [-w savefile] \n");
}

/* And now our feature presentation... [ fade to music ] */
int
main(int argc, char *argv[])
{
  char                *command_name, *s;
  int                  i;
#ifndef WIN32
  int                  opt;
  extern char         *optarg;
#endif
  char                *pf_path;
  int                 pf_open_errno = 0;
  int                 err;
#ifdef HAVE_LIBPCAP
  gboolean            start_capture = FALSE;
  gchar              *save_file = NULL;
#endif
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

#ifdef HAVE_LIBPCAP
  /* Set "capture_child" to indicate whether this is going to be a child
     process for a "-S" capture? */
  capture_child = (strcmp(command_name, CHILD_NAME) == 0);
#endif

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
  cf.dfcode		= NULL;
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
  cf.cinfo.col_width	= (gint *) g_malloc(sizeof(gint) * cf.cinfo.num_cols);
  cf.cinfo.col_title    = (gchar **) g_malloc(sizeof(gchar *) * cf.cinfo.num_cols);
  cf.cinfo.col_data	= (gchar **) g_malloc(sizeof(gchar *) * cf.cinfo.num_cols);

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
  while ((opt = getopt(argc, argv, "b:B:c:f:hi:km:nP:Qr:R:Ss:t:T:w:W:v")) != EOF) {
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
        start_capture = TRUE;
        break;
#endif
      case 'P':        /* Packet list pane height */
        pl_size = atoi(optarg);
        break;
#ifdef HAVE_LIBPCAP
      case 'Q':        /* Quit after capture (just capture to file) */
        quit_after_cap = 1;
        start_capture = TRUE;  /*** -Q implies -k !! ***/
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
        sync_mode = TRUE;
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
        save_file = g_strdup(optarg);
	break;
      case 'W':        /* Write to capture file FD xxx */
        cf.save_file_fd = atoi(optarg);
	break;
#endif
      case '?':        /* Bad flag - print usage message */
        print_usage();
        break;
    }
  }
#endif

#ifdef HAVE_LIBPCAP
  if (start_capture) {
    if (cf.iface == NULL) {
      fprintf(stderr, "ethereal: \"-k\" flag was specified without \"-i\" flag\n");
      exit(1);
    }
  }
  if (capture_child) {
    if (cf.save_file_fd == -1) {
      /* XXX - send this to the standard output as something our parent
         should put in an error message box? */
      fprintf(stderr, "%s: \"-W\" flag not specified\n", CHILD_NAME);
      exit(1);
    }
  }
#endif

  /* Build the column format array */  
  for (i = 0; i < cf.cinfo.num_cols; i++) {
    cf.cinfo.col_fmt[i] = get_column_format(i);
    cf.cinfo.col_title[i] = g_strdup(get_column_title(i));
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
  packet_list = gtk_clist_new_with_titles(cf.cinfo.num_cols, cf.cinfo.col_title);
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

#ifdef HAVE_LIBPCAP
  /* Is this a "child" ethereal, which is only supposed to pop up a
     capture box to let us stop the capture, and run a capture
     to a file that our parent will read? */
  if (!capture_child) {
#endif
    /* No.  Pop up the main window, and read in a capture file if
       we were told to. */

    gtk_widget_show(window);

    colors_init(&cf);

    /* If we were given the name of a capture file, read it in now;
       we defer it until now, so that, if we can't open it, and pop
       up an alert box, the alert box is more likely to come up on
       top of the main window - but before the preference-file-error
       alert box, so, if we get one of those, it's more likely to come
       up on top of us. */
    if (cf_name) {
      if (rfilter != NULL) {
        rfcode = dfilter_compile(rfilter);
        if (rfcode == NULL) {
          simple_dialog(ESD_TYPE_WARN, NULL, dfilter_error_msg);
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
#ifdef HAVE_LIBPCAP
  }
#endif

  /* If we failed to open the preferences file, pop up an alert box;
     we defer it until now, so that the alert box is more likely to
     come up on top of the main window. */
  if (pf_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open preferences file\n\"%s\": %s.", pf_path,
        strerror(pf_open_errno));
  }

#ifdef HAVE_LIBPCAP
  if (capture_child) {
    /* This is the child process for a sync mode or fork mode capture,
       so just do the low-level work of a capture - don't create
       a temporary file and fork off *another* child process (so don't
       call "do_capture()"). */

       capture();

       /* The capture is done; there's nothing more for us to do. */
       gtk_exit(0);
  } else {
    if (start_capture) {
      /* "-k" was specified; start a capture. */
      do_capture(save_file);
    }
  }
#endif

  gtk_main();

  ethereal_proto_cleanup();

  exit(0);
}
