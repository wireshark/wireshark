/* ethereal.c
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 * - Add time stamps to packet list?
 * - Live browser/capture display
 * - Graphs
 * - Prefs dialog
 * - Get AIX to work
 * - Fix PPP support.
 * - Check for end of packet in dissect_* routines.
 * - Playback window
 * - Multiple window support
 * - Add cut/copy/paste
 * - Handle snoop files
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>

#include "packet.h"
#include "file.h"
#include "ethereal.h"
#include "menu.h"
#include "etypes.h"
#include "print.h"
#include "resolv.h"

capture_file cf;
GtkWidget   *file_sel, *packet_list, *tree_view, *byte_view, *prog_bar,
  *info_bar;
GdkFont     *m_r_font, *m_b_font;
guint        main_ctx, file_ctx;
frame_data  *fd;
gint         start_capture = 0;

const gchar *list_item_data_key = "list_item_data";

extern pr_opts printer_opts;

/* Things to do when the OK button is pressed */
void
file_sel_ok_cb(GtkWidget *w, GtkFileSelection *fs) {
  gchar  *cf_name;
  int     err;
  
  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (fs)));
  gtk_widget_hide(GTK_WIDGET (fs));
  gtk_widget_destroy(GTK_WIDGET (fs));

  if ((err = load_cap_file(cf_name, &cf)) == 0)
    chdir(cf_name);
  g_free(cf_name);
}

/* Update the progress bar */
gint
file_progress_cb(gpointer p) {
  gtk_progress_bar_update(GTK_PROGRESS_BAR(prog_bar),
    (gfloat) ftell(cf.fh) / (gfloat) cf.f_len);
  return TRUE;
}

/* Open a file */
void
file_open_cmd_cb(GtkWidget *widget, gpointer data) {
  file_sel = gtk_file_selection_new ("Ethereal: Open Capture File");
  
  /* Connect the ok_button to file_ok_sel_cb function */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION (file_sel)->ok_button),
    "clicked", (GtkSignalFunc) file_sel_ok_cb, file_sel );

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect_object(GTK_OBJECT (GTK_FILE_SELECTION
    (file_sel)->cancel_button), "clicked", (GtkSignalFunc)
    gtk_widget_destroy, GTK_OBJECT (file_sel));

  gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_sel), "");

  gtk_widget_show(file_sel);
}

/* Close a file */
void
file_close_cmd_cb(GtkWidget *widget, gpointer data) {
  close_cap_file(&cf, info_bar, file_ctx);
  set_menu_sensitivity("<Main>/File/Close", FALSE);
}

/* Print a packet */
void
file_print_cmd_cb(GtkWidget *widget, gpointer data) {
    print_tree(cf.pd, fd, GTK_TREE(tree_view));
}

/* What to do when a list item is selected/unselected */
void
packet_list_select_cb(GtkWidget *w, gint row, gint col, gpointer evt) {
  GList      *l;
  
  gtk_text_freeze(GTK_TEXT(byte_view));
  gtk_text_set_point(GTK_TEXT(byte_view), 0);
  gtk_text_forward_delete(GTK_TEXT(byte_view),
    gtk_text_get_length(GTK_TEXT(byte_view)));
  l = g_list_nth(cf.plist, row);
  if (l) {
    fd = (frame_data *) l->data;
    fseek(cf.fh, fd->file_off, SEEK_SET);
    fread(cf.pd, sizeof(guint8), fd->cap_len, cf.fh);
    dissect_packet(cf.pd, fd, GTK_TREE(tree_view));
    packet_hex_print(GTK_TEXT(byte_view), cf.pd, fd->cap_len, -1, -1);
  }
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
  gint       start = -1, len = -1;
  guint32    tinfo = 0;

  if (GTK_TREE(w)->selection) {
    tinfo = (guint32) gtk_object_get_user_data(GTK_TREE(w)->selection->data);
    start = (tinfo >> 16) & 0xffff;
    len   = tinfo & 0xffff;
  }

  gtk_text_freeze(GTK_TEXT(byte_view));
  gtk_text_set_point(GTK_TEXT(byte_view), 0);
  gtk_text_forward_delete(GTK_TEXT(byte_view),
    gtk_text_get_length(GTK_TEXT(byte_view)));
  packet_hex_print(GTK_TEXT(byte_view), cf.pd, fd->cap_len, start, len);
  gtk_text_thaw(GTK_TEXT(byte_view));
}

void
file_quit_cmd_cb (GtkWidget *widget, gpointer data) {
  gtk_exit(0);
}

/* Things to do when the OK button is pressed */
void
main_realize_cb(GtkWidget *w, gpointer data) {
  gchar  *cf_name = (gchar *) data;
  int     err;
  
  if (cf_name) {
    err = load_cap_file(cf_name, &cf);
    cf_name[0] = '\0';
  }
  if (start_capture) {
    if (cf.save_file)
      capture(1);
    else
      capture(0);
    start_capture = 0;
  }
}

void 
print_usage(void) {

  fprintf(stderr, "This is GNU %s %s\n", PACKAGE, VERSION);
  fprintf(stderr, "%s [-v] [-b bold font] [-B byte view height] [-c count] [-h]\n",
	  PACKAGE);
  fprintf(stderr, "         [-i interface] [-m medium font] [-n] [-P packet list height]\n");
  fprintf(stderr, "         [-r infile] [-s snaplen] [-T tree view height]\n");
  fprintf(stderr, "         [-w savefile] \n");
}

int
main(int argc, char *argv[])
{
  int                  opt;
  extern char         *optarg;
  GtkWidget           *window, *main_vbox, *menubar, *u_pane, *l_pane,
                      *bv_table, *bv_hscroll, *bv_vscroll, *stat_hbox, 
                      *tv_scrollw;
  GtkStyle            *pl_style;
  GtkAcceleratorTable *accel;
  gint                 col_width, pl_size = 280, tv_size = 95, bv_size = 75;
  gchar               *rc_file, *cf_name = NULL;
  gchar               *cl_title[] = {"No.", "Source", "Destination",
                      "Protocol", "Info"};
  gchar               *medium_font = MONO_MEDIUM_FONT;
  gchar               *bold_font = MONO_BOLD_FONT;

  /* Initialize the capture file struct */
  cf.plist     = NULL;
  cf.pfh       = NULL;
  cf.fh        = NULL;
  cf.filter    = NULL;
  cf.iface     = NULL;
  cf.save_file = NULL;
  cf.snap      = 68;
  cf.count     = 0;
    
  /* Let GTK get its args */
  gtk_init (&argc, &argv);

  /* Now get our args */
  while ((opt = getopt(argc, argv, "b:B:c:hi:m:nP:r:s:T:w:v")) != EOF) {
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
      case 'r':        /* Read capture file xxx */
        cf_name = g_strdup(optarg);
        break;
      case 's':        /* Set the snapshot (capture) length */
        cf.snap = atoi(optarg);
        break;
      case 'T':        /* Tree view pane height */
        tv_size = atoi(optarg);
        break;
      case 'v':        /* Show version and exit */
        printf("%s %s\n", PACKAGE, VERSION);
        exit(0);
        break;
      case 'w':        /* Write capture file xxx */
        cf.save_file = g_strdup(optarg);
	break;
    }
  }
  
  if (cf.snap < 1)
    cf.snap = 4096;
  else if (cf.snap < 68)
    cf.snap = 68;
  
  rc_file = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(RC_FILE) + 4);
  sprintf(rc_file, "%s/%s", getenv("HOME"), RC_FILE);
  gtk_rc_parse(rc_file);

  /* initialize printer options. temporary! we should only initialize
   * if the options are not set in some ethereal initialization file */
  printer_opts.output_format = 0;
  printer_opts.output_dest = 0;
  printer_opts.file = g_strdup("ethereal.out");
  printer_opts.cmd = g_strdup("lpr");

  if ((m_r_font = gdk_font_load(medium_font)) == NULL) {
    fprintf(stderr, "Error font %s not found (use -m option)\n", medium_font);
    exit(1);
  }

  if ((m_b_font = gdk_font_load(bold_font)) == NULL) {
    fprintf(stderr, "Error font %s not found (use -b option)\n", bold_font);
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
    GTK_SIGNAL_FUNC(main_realize_cb), cf_name);
  gtk_window_set_title(GTK_WINDOW(window), "The Ethereal Network Analyzer");
  gtk_widget_set_usize(GTK_WIDGET(window), DEF_WIDTH, -1);

  /* Container for menu bar, paned windows and progress/info box */
  main_vbox = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vbox), 1);
  gtk_container_add(GTK_CONTAINER(window), main_vbox);
  gtk_widget_show(main_vbox);

  /* Menu bar */
  get_main_menu(&menubar, &accel);
  gtk_window_add_accelerator_table(GTK_WINDOW(window), accel);
  gtk_box_pack_start(GTK_BOX(main_vbox), menubar, FALSE, TRUE, 0);
  gtk_widget_show(menubar);

  /* Panes for the packet list, tree, and byte view */
  u_pane = gtk_vpaned_new();
  l_pane = gtk_vpaned_new();
  gtk_container_add(GTK_CONTAINER(main_vbox), u_pane);
  gtk_widget_show(u_pane);
  gtk_paned_add2 (GTK_PANED(u_pane), l_pane);
  gtk_widget_show(l_pane);

  /* Packet list */
  packet_list = gtk_clist_new_with_titles(5, cl_title);
  pl_style = gtk_style_new();
  gdk_font_unref(pl_style->font);
  pl_style->font = m_r_font;
  gtk_widget_set_style(packet_list, pl_style);
  gtk_widget_set_name(packet_list, "packet list");
  gtk_signal_connect(GTK_OBJECT(packet_list), "select_row",
    GTK_SIGNAL_FUNC(packet_list_select_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(packet_list), "unselect_row",
    GTK_SIGNAL_FUNC(packet_list_unselect_cb), NULL);
  gtk_clist_set_column_justification(GTK_CLIST(packet_list), 0, 
    GTK_JUSTIFY_RIGHT);
  col_width = (gdk_string_width(pl_style->font, "0") * 7) + 2;
  gtk_clist_set_column_width(GTK_CLIST(packet_list), 0, col_width);
  col_width = gdk_string_width(pl_style->font, "00:00:00:00:00:00") + 2;
  gtk_clist_set_column_width(GTK_CLIST(packet_list), 1, col_width);
  gtk_clist_set_column_width(GTK_CLIST(packet_list), 2, col_width);
  col_width = gdk_string_width(pl_style->font, "AppleTalk") + 2;
  gtk_clist_set_column_width(GTK_CLIST(packet_list), 3, col_width);
  gtk_widget_set_usize(packet_list, -1, pl_size);
  gtk_paned_add1(GTK_PANED(u_pane), packet_list);
  gtk_widget_show(packet_list);
  
  /* Tree view */
  tv_scrollw = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(tv_scrollw),
    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_paned_add1(GTK_PANED(l_pane), tv_scrollw);
  gtk_widget_set_usize(tv_scrollw, -1, tv_size);
  gtk_widget_show(tv_scrollw);
  
  tree_view = gtk_tree_new();
  gtk_container_add(GTK_CONTAINER(tv_scrollw), tree_view);
  gtk_tree_set_selection_mode(GTK_TREE(tree_view), GTK_SELECTION_SINGLE);
  gtk_tree_set_view_lines(GTK_TREE(tree_view), FALSE);
  gtk_tree_set_view_mode(GTK_TREE(tree_view), TRUE);
  gtk_signal_connect(GTK_OBJECT(tree_view), "selection_changed",
    GTK_SIGNAL_FUNC(tree_view_cb), NULL);
  gtk_widget_show(tree_view);

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
  
  /* Progress/info box */
  stat_hbox = gtk_hbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(stat_hbox), 0);
  gtk_box_pack_start(GTK_BOX(main_vbox), stat_hbox, FALSE, TRUE, 0);
  gtk_widget_show(stat_hbox);

  prog_bar = gtk_progress_bar_new();  
  gtk_box_pack_start(GTK_BOX(stat_hbox), prog_bar, FALSE, TRUE, 0);
  gtk_widget_show(prog_bar);

  info_bar = gtk_statusbar_new();
  main_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "main");
  file_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "file");
  gtk_statusbar_push(GTK_STATUSBAR(info_bar), main_ctx, DEF_READY_MESSAGE);
  gtk_box_pack_start(GTK_BOX(stat_hbox), info_bar, TRUE, TRUE, 0);
  gtk_widget_show(info_bar);

  gtk_widget_show(window);
  gtk_main();

  exit(0);
}
