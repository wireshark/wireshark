/* main.c
 *
 * $Id: main.c,v 1.138 2000/08/20 08:08:30 guy Exp $
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
 * - Check for end of packet in dissect_* routines.
 * - Playback window
 * - Multiple window support
 * - Add cut/copy/paste
 * - Create header parsing routines
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_IO_H
#include <io.h> /* open/close on win32 */
#endif

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <signal.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#if defined(HAVE_UCD_SNMP_SNMP_H)
#ifdef HAVE_UCD_SNMP_VERSION_H
#include <ucd-snmp/version.h>
#endif /* HAVE_UCD_SNMP_VERSION_H */
#elif defined(HAVE_SNMP_SNMP_H)
#ifdef HAVE_SNMP_VERSION_H
#include <snmp/version.h>
#endif /* HAVE_SNMP_VERSION_H */
#endif /* SNMP */

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#include "main.h"
#include "timestamp.h"
#include "packet.h"
#include "capture.h"
#include "summary.h"
#include "file.h"
#include "menu.h"
#include "../menu.h"
#include "filter_prefs.h"
#include "prefs_dlg.h"
#include "column.h"
#include "print.h"
#include "resolv.h"
#include "util.h"
#include "simple_dialog.h"
#include "proto_draw.h"
#include "dfilter.h"
#include "keys.h"
#include "packet_win.h"
#include "gtkglobals.h"
#include "plugins.h"

packet_info  pi;
capture_file cfile;
GtkWidget   *top_level, *packet_list, *tree_view, *byte_view,
            *info_bar, *tv_scrollw, *pkt_scrollw;
static GtkWidget	*bv_scrollw;
GdkFont     *m_r_font, *m_b_font;
guint        main_ctx, file_ctx;
gchar        comp_info_str[256];
gchar       *ethereal_path = NULL;
gchar       *last_open_dir = NULL;

ts_type timestamp_type = RELATIVE;

GtkStyle *item_style;

/* Specifies the field currently selected in the GUI protocol tree */
field_info *finfo_selected = NULL;

static char* hfinfo_numeric_format(header_field_info *hfinfo);
static char *boldify(const char *font_name);
static void create_main_window(gint, gint, gint, e_prefs*);

/* About Ethereal window */
void
about_ethereal( GtkWidget *w, gpointer data ) {
  simple_dialog(ESD_TYPE_INFO, NULL,
		"Ethereal - Network Protocol Analyzer\n"
		"Version " VERSION " (C) 1998-2000 Gerald Combs <gerald@zing.org>\n"
                "Compiled with %s\n\n"

		"Check the man page for complete documentation and\n"
		"for the list of contributors.\n"

		"\nSee http://ethereal.zing.org/ for more information.",
                 comp_info_str);
}


/* Match selected byte pattern */
void
match_selected_cb(GtkWidget *w, gpointer data)
{
    char		*buf;
    GtkWidget		*filter_te;
    char		*ptr, *format, *stringified;
    int			i, dfilter_len, abbrev_len;
    guint8		*c;
    header_field_info	*hfinfo;

    filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY);

    if (!finfo_selected) {
	simple_dialog(ESD_TYPE_CRIT, NULL,
		      "Error determining selected bytes.  Please make\n"
		      "sure you have selected a field within the tree\n"
		      "view to be matched.");
	return;
    }

    hfinfo = finfo_selected->hfinfo;
    g_assert(hfinfo);
    abbrev_len = strlen(hfinfo->abbrev);

	switch(hfinfo->type) {

		case FT_BOOLEAN:
		        dfilter_len = abbrev_len + 2;
		        buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s%s", finfo_selected->value.numeric ? "" : "!",
					hfinfo->abbrev);
			break;

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			dfilter_len = abbrev_len + 20;
		        buf = g_malloc0(dfilter_len);
			format = hfinfo_numeric_format(hfinfo);
		        snprintf(buf, dfilter_len, format, hfinfo->abbrev, finfo_selected->value.numeric);
			break;

		case FT_IPv4:
			dfilter_len = abbrev_len + 4 + 15 + 1;
		        buf = g_malloc0(dfilter_len);
		        snprintf(buf, dfilter_len, "%s == %s", hfinfo->abbrev,
					ipv4_addr_str(&(finfo_selected->value.ipv4)));
			break;

		case FT_IPXNET:
			dfilter_len = abbrev_len + 15;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == 0x%08x", hfinfo->abbrev,
					finfo_selected->value.numeric);
			break;

		case FT_IPv6:
			stringified = ip6_to_str((struct e_in6_addr*) &(finfo_selected->value.ipv6));
			dfilter_len = abbrev_len + 4 + strlen(stringified) + 1;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %s", hfinfo->abbrev,
					stringified);
			break;

		case FT_DOUBLE:
			dfilter_len = abbrev_len + 30;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %f", hfinfo->abbrev,
					finfo_selected->value.floating);
			break;

		case FT_ETHER:
			dfilter_len = abbrev_len + 22;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %s",
					hfinfo->abbrev,
					ether_to_str(finfo_selected->value.ether));
			break;
#if 0

		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
			memcpy(&fi->value.time, va_arg(ap, struct timeval*),
				sizeof(struct timeval));
			break;

		case FT_STRING:
			/* This g_strdup'ed memory is freed in proto_tree_free_node() */
			fi->value.string = g_strdup(va_arg(ap, char*));
			break;

		case FT_TEXT_ONLY:
			; /* nothing */
			break;
#endif
		default:
		    c = cfile.pd + finfo_selected->start;
		    buf = g_malloc0(32 + finfo_selected->length * 3);
		    ptr = buf;

		    sprintf(ptr, "frame[%d] == ", finfo_selected->start);
		    ptr = buf+strlen(buf);

		    if (finfo_selected->length == 1) {
			sprintf(ptr, "0x%02x", *c++);
		    }
		    else {
			    for (i=0;i<finfo_selected->length; i++) {
				if (i == 0 ) {
					sprintf(ptr, "%02x", *c++);
				}
				else {
					sprintf(ptr, ":%02x", *c++);
				}
				ptr = buf+strlen(buf);
			    }
		    }
		    break;
	}

    /* create a new one and set the display filter entry accordingly */
    gtk_entry_set_text(GTK_ENTRY(filter_te), buf);

    /* Run the display filter so it goes in effect. */
    filter_packets(&cfile, buf);

    /* Don't g_free(buf) here. filter_packets() will do it the next time it's called */
}

static char*
hfinfo_numeric_format(header_field_info *hfinfo)
{
	char *format = NULL;

	/* Pick the proper format string */
	switch(hfinfo->display) {
		case BASE_DEC:
		case BASE_NONE:
		case BASE_OCT: /* I'm lazy */
		case BASE_BIN: /* I'm lazy */
			switch(hfinfo->type) {
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					format = "%s == %u";
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					format = "%s == %d";
					break;
				default:
					g_assert_not_reached();
					;
			}
			break;
		case BASE_HEX:
			switch(hfinfo->type) {
				case FT_UINT8:
					format = "%s == 0x%02x";
					break;
				case FT_UINT16:
					format = "%s == 0x%04x";
					break;
				case FT_UINT24:
					format = "%s == 0x%06x";
					break;
				case FT_UINT32:
					format = "%s == 0x%08x";
					break;
				default:
					g_assert_not_reached();
					;
			}
			break;
		default:
			g_assert_not_reached();
			;
	}
	return format;
}


/* Run the current display filter on the current packet set, and
   redisplay. */
static void
filter_activate_cb(GtkWidget *w, gpointer data)
{
  GtkCombo  *filter_cm = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_CM_KEY);
  GList     *filter_list = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_FL_KEY);
  GList     *li, *nl = NULL;
  gboolean   add_filter = TRUE;
  
  char *s = gtk_entry_get_text(GTK_ENTRY(w));
  
  /* GtkCombos don't let us get at their list contents easily, so we maintain
     our own filter list, and feed it to gtk_combo_set_popdown_strings when
     a new filter is added. */
  if (filter_packets(&cfile, g_strdup(s))) {
    li = g_list_first(filter_list);
    while (li) {
      if (li->data && strcmp(s, li->data) == 0)
        add_filter = FALSE;
      li = li->next;
    }

    if (add_filter) {
      filter_list = g_list_append(filter_list, g_strdup(s));
      li = g_list_first(filter_list);
      while (li) {
        nl = g_list_append(nl, strdup(li->data));
        li = li->next;
      }
      gtk_combo_set_popdown_strings(filter_cm, nl);
      gtk_entry_set_text(GTK_ENTRY(filter_cm->entry), g_list_last(filter_list)->data);
    }
  }
}

/* redisplay with no display filter */
static void
filter_reset_cb(GtkWidget *w, gpointer data)
{
  GtkWidget *filter_te = NULL;

  if ((filter_te = gtk_object_get_data(GTK_OBJECT(w), E_DFILTER_TE_KEY))) {
    gtk_entry_set_text(GTK_ENTRY(filter_te), "");
  }

  filter_packets(&cfile, NULL);
}

/* GTKClist compare routine, overrides default to allow numeric comparison */
static gint
packet_list_compare(GtkCList *clist, gconstpointer  ptr1, gconstpointer  ptr2)
{
  /* Get row text strings */
  char *text1 = GTK_CELL_TEXT (((GtkCListRow *)ptr1)->cell[clist->sort_column])->text;
  char *text2 = GTK_CELL_TEXT (((GtkCListRow *)ptr2)->cell[clist->sort_column])->text;

  /* Attempt to convert to numbers */
  double  num1 = atof(text1);
  double  num2 = atof(text2);
  
  gint  col_fmt = cfile.cinfo.col_fmt[clist->sort_column];
  
  if ((col_fmt == COL_NUMBER) || (col_fmt == COL_REL_TIME) || (col_fmt == COL_DELTA_TIME) ||
      ((col_fmt == COL_CLS_TIME) && (timestamp_type == RELATIVE)) ||
      ((col_fmt == COL_CLS_TIME) && (timestamp_type == DELTA))    ||
      (col_fmt == COL_UNRES_SRC_PORT) || (col_fmt == COL_UNRES_DST_PORT) ||
      ((num1 != 0) && (num2 != 0) && ((col_fmt == COL_DEF_SRC_PORT) || (col_fmt == COL_RES_SRC_PORT) ||
                                      (col_fmt == COL_DEF_DST_PORT) || (col_fmt == COL_RES_DST_PORT))) ||
      (col_fmt == COL_PACKET_LENGTH)) {

    /* Compare numeric column */

    if (num1 < num2)
      return -1;
    else if (num1 > num2)
      return 1;
    else
      return 0;
  }
  
  else {
    
    /* Compare text column */
    if (!text2)
      return (text1 != NULL);

    if (!text1)
      return -1;

    return strcmp(text1, text2);
  }
}

/* What to do when a column is clicked */
static void 
packet_list_click_column_cb(GtkCList *clist, gint column, gpointer data)
{
  if (column == clist->sort_column) {
    if (clist->sort_type == GTK_SORT_ASCENDING)
      clist->sort_type = GTK_SORT_DESCENDING;
    else
      clist->sort_type = GTK_SORT_ASCENDING;
  }
  else {
    clist->sort_type = GTK_SORT_ASCENDING;
    gtk_clist_set_sort_column(clist, column);
  }

  gtk_clist_sort(clist);
}

/* What to do when a list item is selected/unselected */
static void
packet_list_select_cb(GtkWidget *w, gint row, gint col, gpointer evt) {

  blank_packetinfo();
  select_packet(&cfile, row);
}

static void
packet_list_unselect_cb(GtkWidget *w, gint row, gint col, gpointer evt) {
  unselect_packet(&cfile);
}

static void
tree_view_select_row_cb(GtkCTree *ctree, GList *node, gint column, gpointer user_data)
{
	field_info	*finfo;

	g_assert(node);
	finfo = gtk_ctree_node_get_row_data( ctree, GTK_CTREE_NODE(node) );
	if (!finfo) return;

	finfo_selected = finfo;

	set_menus_for_selected_tree_row(TRUE);

	packet_hex_print(GTK_TEXT(byte_view), cfile.pd, cfile.current_frame->cap_len, 
		finfo->start, finfo->length, cfile.current_frame->flags.encoding);
}

static void
tree_view_unselect_row_cb(GtkCTree *ctree, GList *node, gint column, gpointer user_data)
{
	finfo_selected = NULL;
	set_menus_for_selected_tree_row(FALSE);
	packet_hex_print(GTK_TEXT(byte_view), cfile.pd, cfile.current_frame->cap_len, 
		-1, -1, cfile.current_frame->flags.encoding);
}

void collapse_all_cb(GtkWidget *widget, gpointer data) {
  if (cfile.protocol_tree)
    collapse_all_tree(cfile.protocol_tree, tree_view);
}

void expand_all_cb(GtkWidget *widget, gpointer data) {
  if (cfile.protocol_tree)
    expand_all_tree(cfile.protocol_tree, tree_view);
}

void resolve_name_cb(GtkWidget *widget, gpointer data) {
  if (cfile.protocol_tree) {
    int tmp = g_resolving_actif;
    g_resolving_actif = 1;
    gtk_clist_clear ( GTK_CLIST(tree_view) );
    proto_tree_draw(cfile.protocol_tree, tree_view);
    g_resolving_actif = tmp;
  }
}

/* Set the scrollbar placement of a scrolled window based upon pos value:
   0 = left, 1 = right */
void
set_scrollbar_placement_scrollw(GtkWidget *scrollw, int pos) /* 0=left, 1=right */
{
	if (pos) {
		gtk_scrolled_window_set_placement(GTK_SCROLLED_WINDOW(scrollw),
				GTK_CORNER_TOP_LEFT);
	} else {
		gtk_scrolled_window_set_placement(GTK_SCROLLED_WINDOW(scrollw),
				GTK_CORNER_TOP_RIGHT);
	}
}

/* List of all scrolled windows, so we can globally set the scrollbar
   placement of them. */
static GList *scrolled_windows;

/* Add a scrolled window to the list of scrolled windows. */
static void forget_scrolled_window(GtkWidget *scrollw, gpointer data);

void
remember_scrolled_window(GtkWidget *scrollw)
{
  scrolled_windows = g_list_append(scrolled_windows, scrollw);

  /* Catch the "destroy" event on the widget, so that we remove it from
     the list when it's destroyed. */
  gtk_signal_connect(GTK_OBJECT(scrollw), "destroy",
		     GTK_SIGNAL_FUNC(forget_scrolled_window), NULL);
}

/* Remove a scrolled window from the list of scrolled windows. */
static void
forget_scrolled_window(GtkWidget *scrollw, gpointer data)
{
  scrolled_windows = g_list_remove(scrolled_windows, scrollw);
}

static void
set_scrollbar_placement_cb(gpointer data, gpointer user_data)
{
	set_scrollbar_placement_scrollw((GtkWidget *)data,
	    *(int *)user_data);
}

/* Set the scrollbar placement of all scrolled windows based on pos value:
   0 = left, 1 = right */
void
set_scrollbar_placement_all(int pos)
{
	g_list_foreach(scrolled_windows, set_scrollbar_placement_cb, &pos);
}

/* Set the selection mode of the packet list window. */
void
set_plist_sel_browse(gboolean val)
{
	gboolean old_val;

	old_val =
	    (GTK_CLIST(packet_list)->selection_mode == GTK_SELECTION_SINGLE);

	if (val == old_val) {
		/*
		 * The mode isn't changing, so don't do anything.
		 * In particular, don't gratuitiously unselect the
		 * current packet.
		 *
		 * XXX - why do we have to unselect the current packet
		 * ourselves?  The documentation for the GtkCList at
		 *
		 *	http://developer.gnome.org/doc/API/gtk/gtkclist.html
		 *
		 * says "Note that setting the widget's selection mode to
		 * one of GTK_SELECTION_BROWSE or GTK_SELECTION_SINGLE will
		 * cause all the items in the GtkCList to become deselected."
		 */
		return;
	}

	if (finfo_selected)
		unselect_packet(&cfile);

	/* Yeah, GTK uses "browse" in the case where we do not, but oh well. I think
	 * "browse" in Ethereal makes more sense than "SINGLE" in GTK+ */
	if (val) {
		gtk_clist_set_selection_mode(GTK_CLIST(packet_list), GTK_SELECTION_SINGLE);
	}
	else {
		gtk_clist_set_selection_mode(GTK_CLIST(packet_list), GTK_SELECTION_BROWSE);
	}
}

/* Set the selection mode of a given packet tree window. */
void
set_ptree_sel_browse(GtkWidget *tv, gboolean val)
{
	/* Yeah, GTK uses "browse" in the case where we do not, but oh well. I think
	 * "browse" in Ethereal makes more sense than "SINGLE" in GTK+ */
	if (val) {
		gtk_clist_set_selection_mode(GTK_CLIST(tv), GTK_SELECTION_SINGLE);
	}
	else {
		gtk_clist_set_selection_mode(GTK_CLIST(tv), GTK_SELECTION_BROWSE);
	}
}

/* Set the selection mode of all packet tree windows. */
void
set_ptree_sel_browse_all(gboolean val)
{
	set_ptree_sel_browse(tree_view, val);
	set_ptree_sel_browse_packet_wins(val);
}

/* Set the line style of a given packet tree window. */
void
set_ptree_line_style(GtkWidget *tv, gint style)
{
	/* I'm using an assert here since the preferences code limits
	 * the user input, both in the GUI and when reading the preferences file.
	 * If the value is incorrect, it's a program error, not a user-initiated error.
	 */
	g_assert(style >= GTK_CTREE_LINES_NONE && style <= GTK_CTREE_LINES_TABBED);
	gtk_ctree_set_line_style( GTK_CTREE(tv), style );
}

/* Set the line style of all packet tree window. */
void
set_ptree_line_style_all(gint style)
{
	set_ptree_line_style(tree_view, style);
	set_ptree_line_style_packet_wins(style);
}

/* Set the expander style of a given packet tree window. */
void
set_ptree_expander_style(GtkWidget *tv, gint style)
{
	/* I'm using an assert here since the preferences code limits
	 * the user input, both in the GUI and when reading the preferences file.
	 * If the value is incorrect, it's a program error, not a user-initiated error.
	 */
	g_assert(style >= GTK_CTREE_EXPANDER_NONE && style <= GTK_CTREE_EXPANDER_CIRCULAR);
	gtk_ctree_set_expander_style( GTK_CTREE(tv), style );
}
	
void
set_ptree_expander_style_all(gint style)
{
	set_ptree_expander_style(tree_view, style);
	set_ptree_expander_style_packet_wins(style);
}

static gboolean
main_window_delete_event_cb(GtkWidget *widget, GdkEvent *event, gpointer data)
{
	file_quit_cmd_cb(widget, data);

	/* Say that the window should be deleted. */
	return FALSE;
}

void
file_quit_cmd_cb (GtkWidget *widget, gpointer data)
{
	/* XXX - should we check whether the capture file is an
	   unsaved temporary file for a live capture and, if so,
	   pop up a "do you want to exit without saving the capture
	   file?" dialog, and then just return, leaving said dialog
	   box to forcibly quit if the user clicks "OK"?

	   If so, note that this should be done in a subroutine that
	   returns TRUE if we do so, and FALSE otherwise, and that
	   "main_window_delete_event_cb()" should return its
	   return value. */

	/* Are we in the middle of reading a capture? */
	if (cfile.state == FILE_READ_IN_PROGRESS) {
		/* Yes, so we can't just close the file and quit, as
		   that may yank the rug out from under the read in
		   progress; instead, just set the state to
		   "FILE_READ_ABORTED" and return - the code doing the read
		   will check for that and, if it sees that, will clean
		   up and quit. */
		cfile.state = FILE_READ_ABORTED;
	} else {
		/* Close any capture file we have open; on some OSes, you
		   can't unlink a temporary capture file if you have it
		   open.
		   "close_cap_file()" will unlink it after closing it if
		   it's a temporary file.

		   We do this here, rather than after the main loop returns,
		   as, after the main loop returns, the main window may have
		   been destroyed (if this is called due to a "destroy"
		   even on the main window rather than due to the user
		   selecting a menu item), and there may be a crash
		   or other problem when "close_cap_file()" tries to
		   clean up stuff in the main window.

		   XXX - is there a better place to put this?
		   Or should we have a routine that *just* closes the
		   capture file, and doesn't do anything with the UI,
		   which we'd call here, and another routine that
		   calls that routine and also cleans up the UI, which
		   we'd call elsewhere? */
		close_cap_file(&cfile, info_bar);

		/* Exit by leaving the main loop, so that any quit functions
		   we registered get called. */
		gtk_main_quit();
	}
}

static void 
print_usage(void) {

  fprintf(stderr, "This is GNU " PACKAGE " " VERSION ", compiled with %s\n",
	  comp_info_str);
#ifdef HAVE_LIBPCAP
  fprintf(stderr, "%s [ -vh ] [ -kQS ] [ -B <byte view height> ] [ -c count ]\n",
	  PACKAGE);
  fprintf(stderr, "\t[ -D ] [ -f <capture filter> ] [ -i interface ] [ -m <medium font> ] \n");
  fprintf(stderr, "\t[ -n ] [ -o <preference setting> ] ... [ -P <packet list height> ]\n");
  fprintf(stderr, "\t[ -r infile ] [ -R <read filter> ] [ -s snaplen ] \n");
  fprintf(stderr, "\t[ -T <tree view height> ] [ -w savefile ]\n");
#else
  fprintf(stderr, "%s [ -vh ] [ -B <byte view height> ] [ -m <medium font> ] [ -n ]\n",
	  PACKAGE);
  fprintf(stderr, "\t[ -o <preference setting> ... [ -P <packet list height> ]\n");
  fprintf(stderr, "\t[ -r infile ] [ -R <read filter> ] [ -t <time stamp format> ]\n");
  fprintf(stderr, "\t[ -T <tree view height> ]\n");
#endif
}

/* And now our feature presentation... [ fade to music ] */
int
main(int argc, char *argv[])
{
#ifdef HAVE_LIBPCAP
  char                *command_name;
#endif
  char                *s;
  int                  i;
  int                  opt;
  extern char         *optarg;
  gboolean             arg_error = FALSE;
#ifdef HAVE_LIBPCAP
#ifdef WIN32
  char pcap_version[] = "0.4a6";
#else
  extern char          pcap_version[];
#endif
#endif
  char                *gpf_path, *pf_path;
  int                  gpf_open_errno, pf_open_errno;
  int                  err;
#ifdef HAVE_LIBPCAP
  gboolean             start_capture = FALSE;
  gchar               *save_file = NULL;
  GList               *if_list;
  gchar                err_str[PCAP_ERRBUF_SIZE];
#else
  gboolean             capture_option_specified = FALSE;
#endif
  gint                 pl_size = 280, tv_size = 95, bv_size = 75;
  gchar               *rc_file, *cf_name = NULL, *rfilter = NULL;
  dfilter             *rfcode = NULL;
  gboolean             rfilter_parse_failed = FALSE;
  e_prefs             *prefs;
  char                *bold_font_name;

  ethereal_path = argv[0];

#ifdef HAVE_LIBPCAP
  command_name = get_basename(ethereal_path);
  /* Set "capture_child" to indicate whether this is going to be a child
     process for a "-S" capture. */
  capture_child = (strcmp(command_name, CHILD_NAME) == 0);
#endif

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps a list of fields registered
     by the dissectors, and we must do it before we read the preferences,
     in case any dissectors register preferences. */
  dissect_init();

  /* Now register the preferences for any non-dissector modules.
     We must do that before we read the preferences as well. */
  prefs_register_modules();

  /* If invoked with the "-G" flag, we dump out a glossary of
     display filter symbols.

     We must do this before calling "gtk_init()", because "gtk_init()"
     tries to open an X display, and we don't want to have to do any X
     stuff just to do a build.

     Given that we call "gtk_init()" before doing the regular argument
     list processing, so that it can handle X and GTK+ arguments and
     remove them from the list at which we look, this means we must do
     this before doing the regular argument list processing, as well.

     This means that:

	you must give the "-G" flag as the first flag on the command line;

	you must give it as "-G", nothing more, nothing less;

	any arguments after the "-G" flag will not be used. */
  if (argc >= 2 && strcmp(argv[1], "-G") == 0) {
    proto_registrar_dump();
    exit(0);
  }

  /* Set the current locale according to the program environment. 
   * We haven't localized anything, but some GTK widgets are localized
   * (the file selection dialogue, for example).
   * This also sets the C-language locale to the native environment. */
  gtk_set_locale();

  /* Let GTK get its args */
  gtk_init (&argc, &argv);
  
  prefs = read_prefs(&gpf_open_errno, &gpf_path, &pf_open_errno, &pf_path);

  /* Initialize the capture file struct */
  cfile.plist		= NULL;
  cfile.plist_end		= NULL;
  cfile.wth		= NULL;
  cfile.filename		= NULL;
  cfile.user_saved		= FALSE;
  cfile.is_tempfile	= FALSE;
  cfile.rfcode		= NULL;
  cfile.dfilter		= NULL;
  cfile.dfcode		= NULL;
#ifdef HAVE_LIBPCAP
  cfile.cfilter		= g_strdup(EMPTY_FILTER);
#endif
  cfile.iface		= NULL;
  cfile.save_file		= NULL;
  cfile.save_file_fd	= -1;
  cfile.snap		= WTAP_MAX_PACKET_SIZE;
  cfile.count		= 0;
  cfile.cinfo.num_cols	= prefs->num_cols;
  cfile.cinfo.col_fmt      = (gint *) g_malloc(sizeof(gint) * cfile.cinfo.num_cols);
  cfile.cinfo.fmt_matx	= (gboolean **) g_malloc(sizeof(gboolean *) * cfile.cinfo.num_cols);
  cfile.cinfo.col_width	= (gint *) g_malloc(sizeof(gint) * cfile.cinfo.num_cols);
  cfile.cinfo.col_title    = (gchar **) g_malloc(sizeof(gchar *) * cfile.cinfo.num_cols);
  cfile.cinfo.col_data	= (gchar **) g_malloc(sizeof(gchar *) * cfile.cinfo.num_cols);

  /* Assemble the compile-time options */
  snprintf(comp_info_str, 256,
#ifdef GTK_MAJOR_VERSION
    "GTK+ %d.%d.%d, %s%s, %s%s, %s%s", GTK_MAJOR_VERSION, GTK_MINOR_VERSION,
    GTK_MICRO_VERSION,
#else
    "GTK+ (version unknown), %s%s, %s%s, %s%s",
#endif

#ifdef HAVE_LIBPCAP
   "with libpcap ", pcap_version,
#else
   "without libpcap", "",
#endif

#ifdef HAVE_LIBZ
#ifdef ZLIB_VERSION
   "with libz ", ZLIB_VERSION,
#else /* ZLIB_VERSION */
   "with libz ", "(version unknown)",
#endif /* ZLIB_VERSION */
#else /* HAVE_LIBZ */
   "without libz", "",
#endif /* HAVE_LIBZ */

/* Oh, this is pretty */
#if defined(HAVE_UCD_SNMP_SNMP_H)
#ifdef HAVE_UCD_SNMP_VERSION_H
   "with UCD SNMP ", VersionInfo
#else /* HAVE_UCD_SNMP_VERSION_H */
   "with UCD SNMP ", "(version unknown)"
#endif /* HAVE_UCD_SNMP_VERSION_H */
#elif defined(HAVE_SNMP_SNMP_H)
#ifdef HAVE_SNMP_VERSION_H
   "with CMU SNMP ", snmp_Version()
#else /* HAVE_SNMP_VERSION_H */
   "with CMU SNMP ", "(version unknown)"
#endif /* HAVE_SNMP_VERSION_H */
#else /* no SNMP */
   "without SNMP", ""
#endif
   );

  /* Now get our args */
  while ((opt = getopt(argc, argv, "B:c:Df:hi:km:no:P:Qr:R:Ss:t:T:w:W:vZ:")) != EOF) {
    switch (opt) {
      case 'B':        /* Byte view pane height */
        bv_size = atoi(optarg);
        break;
      case 'c':        /* Capture xxx packets */
#ifdef HAVE_LIBPCAP
        cfile.count = atoi(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'D':        /* Turn off DSCP printing */
	g_ip_dscp_actif = FALSE;
	break;
      case 'f':
#ifdef HAVE_LIBPCAP
	if (cfile.cfilter)
		g_free(cfile.cfilter);
	cfile.cfilter = g_strdup(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
	break;
      case 'h':        /* Print help and exit */
	print_usage();
	exit(0);
        break;
      case 'i':        /* Use interface xxx */
#ifdef HAVE_LIBPCAP
        cfile.iface = g_strdup(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'k':        /* Start capture immediately */
#ifdef HAVE_LIBPCAP
        start_capture = TRUE;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'm':        /* Fixed-width font for the display */
        if (prefs->gui_font_name != NULL)
          g_free(prefs->gui_font_name);
	prefs->gui_font_name = g_strdup(optarg);
	break;
      case 'n':        /* No name resolution */
	g_resolving_actif = 0;
	break;
      case 'o':        /* Override preference from command line */
        switch (prefs_set_pref(optarg)) {

	case PREFS_SET_SYNTAX_ERR:
          fprintf(stderr, "ethereal: Invalid -o flag \"%s\"\n", optarg);
          exit(1);
          break;

        case PREFS_SET_NO_SUCH_PREF:
          fprintf(stderr, "ethereal: -o flag \"%s\" specifies unknown preference\n",
			optarg);
          exit(1);
          break;
        }
        break;
      case 'P':        /* Packet list pane height */
        pl_size = atoi(optarg);
        break;
      case 'Q':        /* Quit after capture (just capture to file) */
#ifdef HAVE_LIBPCAP
        quit_after_cap = 1;
        start_capture = TRUE;  /*** -Q implies -k !! ***/
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'r':        /* Read capture file xxx */
	/* We may set "last_open_dir" to "cf_name", and if we change
	   "last_open_dir" later, we free the old value, so we have to
	   set "cf_name" to something that's been allocated. */
        cf_name = g_strdup(optarg);
        break;
      case 'R':        /* Read file filter */
        rfilter = optarg;
        break;
      case 's':        /* Set the snapshot (capture) length */
#ifdef HAVE_LIBPCAP
        cfile.snap = atoi(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'S':        /* "Sync" mode: used for following file ala tail -f */
#ifdef HAVE_LIBPCAP
        sync_mode = TRUE;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
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
      case 'w':        /* Write to capture file xxx */
#ifdef HAVE_LIBPCAP
        save_file = g_strdup(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
	break;
      case 'W':        /* Write to capture file FD xxx */
#ifdef HAVE_LIBPCAP
        cfile.save_file_fd = atoi(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
	break;

#ifdef _WIN32
      case 'Z':        /* Write to pipe FD XXX */
#ifdef HAVE_LIBPCAP
        /* associate stdout with pipe */
        i = atoi(optarg);
        if (dup2(i, 1) < 0) {
          fprintf(stderr, "Unable to dup pipe handle\n");
          exit(1);
        }
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif /* HAVE_LIBPCAP */
        break;
#endif /* _WIN32 */

      default:
      case '?':        /* Bad flag - print usage message */
        arg_error = TRUE;
        break;
    }
  }

  /* Notify all registered modules that have had any of their preferences
     changed either from one of the preferences file or from the command
     line that its preferences have changed. */
  prefs_apply_all();

#ifndef HAVE_LIBPCAP
  if (capture_option_specified)
    fprintf(stderr, "This version of Ethereal was not built with support for capturing packets.\n");
#endif
  if (arg_error)
    print_usage();
#ifdef HAVE_LIBPCAP
  if (start_capture) {
    /* We're supposed to do a live capture; did the user specify an interface
       to use? */
    if (cfile.iface == NULL) {
      /* No - pick the first one from the list of interfaces. */
      if_list = get_interface_list(&err, err_str);
      if (if_list == NULL) {
        switch (err) {

        case CANT_GET_INTERFACE_LIST:
            fprintf(stderr, "ethereal: Can't get list of interfaces: %s\n",
			err_str);
            break;

        case NO_INTERFACES_FOUND:
            fprintf(stderr, "ethereal: There are no interfaces on which a capture can be done\n");
            break;
        }
        exit(2);
      }
      cfile.iface = g_strdup(if_list->data);	/* first interface */
      free_interface_list(if_list);
    }
  }
  if (capture_child) {
    if (cfile.save_file_fd == -1) {
      /* XXX - send this to the standard output as something our parent
         should put in an error message box? */
      fprintf(stderr, "%s: \"-W\" flag not specified\n", CHILD_NAME);
      exit(1);
    }
  }
#endif

  /* Build the column format array */  
  for (i = 0; i < cfile.cinfo.num_cols; i++) {
    cfile.cinfo.col_fmt[i] = get_column_format(i);
    cfile.cinfo.col_title[i] = g_strdup(get_column_title(i));
    cfile.cinfo.fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean) *
      NUM_COL_FMTS);
    get_column_format_matches(cfile.cinfo.fmt_matx[i], cfile.cinfo.col_fmt[i]);
    if (cfile.cinfo.col_fmt[i] == COL_INFO)
      cfile.cinfo.col_data[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
    else
      cfile.cinfo.col_data[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
  }

  if (cfile.snap < 1)
    cfile.snap = WTAP_MAX_PACKET_SIZE;
  else if (cfile.snap < MIN_PACKET_SIZE)
    cfile.snap = MIN_PACKET_SIZE;
  
  rc_file = (gchar *) g_malloc(strlen(get_home_dir()) + strlen(RC_FILE) + 4);
  sprintf(rc_file, "%s/%s", get_home_dir(), RC_FILE);
  gtk_rc_parse(rc_file);

  /* Try to load the regular and boldface fixed-width fonts */
  bold_font_name = boldify(prefs->gui_font_name);
  m_r_font = gdk_font_load(prefs->gui_font_name);
  m_b_font = gdk_font_load(bold_font_name);
  if (m_r_font == NULL || m_b_font == NULL) {
    /* XXX - pop this up as a dialog box? */
    if (m_r_font == NULL)
      fprintf(stderr, "ethereal: Warning: font %s not found - defaulting to 6x13 and 6x13bold\n",
		prefs->gui_font_name);
    else
      gdk_font_unref(m_r_font);
    if (m_b_font == NULL)
      fprintf(stderr, "ethereal: Warning: font %s not found - defaulting to 6x13 and 6x13bold\n",
		bold_font_name);
    else
      gdk_font_unref(m_b_font);
    g_free(bold_font_name);
    if ((m_r_font = gdk_font_load("6x13")) == NULL) {
      fprintf(stderr, "ethereal: Error: font 6x13 not found\n");
      exit(1);
    }
    if ((m_b_font = gdk_font_load("6x13bold")) == NULL) {
      fprintf(stderr, "ethereal: Error: font 6x13 not found\n");
      exit(1);
    }
  }

  create_main_window(pl_size, tv_size, bv_size, prefs);

#ifdef HAVE_LIBPCAP
  /* Is this a "child" ethereal, which is only supposed to pop up a
     capture box to let us stop the capture, and run a capture
     to a file that our parent will read? */
  if (!capture_child) {
#endif
    /* No.  Pop up the main window, and read in a capture file if
       we were told to. */

    gtk_widget_show(top_level);
    set_menus_for_capture_file(FALSE);

    cfile.colors = colfilter_new();

    /* If we were given the name of a capture file, read it in now;
       we defer it until now, so that, if we can't open it, and pop
       up an alert box, the alert box is more likely to come up on
       top of the main window - but before the preference-file-error
       alert box, so, if we get one of those, it's more likely to come
       up on top of us. */
    if (cf_name) {
      if (rfilter != NULL) {
        if (dfilter_compile(rfilter, &rfcode) != 0) {
          simple_dialog(ESD_TYPE_CRIT, NULL, dfilter_error_msg);
          rfilter_parse_failed = TRUE;
        }
      }
      if (!rfilter_parse_failed) {
        if ((err = open_cap_file(cf_name, FALSE, &cfile)) == 0) {
          /* "open_cap_file()" succeeded, so it closed the previous
	     capture file, and thus destroyed any previous read filter
	     attached to "cf". */
          cfile.rfcode = rfcode;
          switch (read_cap_file(&cfile, &err)) {

          case READ_SUCCESS:
          case READ_ERROR:
            /* Just because we got an error, that doesn't mean we were unable
               to read any of the file; we handle what we could get from the
               file. */
            break;

          case READ_ABORTED:
            /* Exit now. */
            gtk_exit(0);
            break;
          }
          /* Save the name of the containing directory specified in the
	     path name, if any; we can write over cf_name, which is a
             good thing, given that "get_dirname()" does write over its
             argument. */
          s = get_dirname(cf_name);
          if (s != NULL)
            last_open_dir = s;
        } else {
          dfilter_destroy(rfcode);
          cfile.rfcode = NULL;
        }
      }
    }
#ifdef HAVE_LIBPCAP
  }
#endif

  /* If the global preferences file exists but we failed to open it,
     pop up an alert box; we defer that until now, so that the alert
     box is more likely to come up on top of the main window. */
  if (gpf_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open global preferences file\n\"%s\": %s.", gpf_path,
        strerror(gpf_open_errno));
  }

  /* If the user's preferences file exists but we failed to open it,
     pop up an alert box; we defer that until now, so that the alert
     box is more likely to come up on top of the main window. */
  if (pf_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open your preferences file\n\"%s\": %s.", pf_path,
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
    else {
      set_menus_for_capture_in_progress(FALSE);
    }
  }
#else
  set_menus_for_capture_in_progress(FALSE);
#endif

  gtk_main();

  dissect_cleanup();
  g_free(rc_file);

  gtk_exit(0);

  /* This isn't reached, but we need it to keep GCC from complaining
     that "main()" returns without returning a value - it knows that
     "exit()" never returns, but it doesn't know that "gtk_exit()"
     doesn't, as GTK+ doesn't declare it with the attribute
     "noreturn". */
  return 0;	/* not reached */
}

#ifdef WIN32

/* We build this as a GUI subsystem application on Win32, so
   "WinMain()", not "main()", gets called.

   Hack shamelessly stolen from the Win32 port of the GIMP. */
#ifdef __GNUC__
#define _stdcall  __attribute__((stdcall))
#endif

int _stdcall
WinMain (struct HINSTANCE__ *hInstance,
	 struct HINSTANCE__ *hPrevInstance,
	 char               *lpszCmdLine,
	 int                 nCmdShow)
{
  return main (__argc, __argv);
}

#endif

/* Given a font name, construct the name of the next heavier version of
   that font. */

#define	XLFD_WEIGHT	3	/* index of the "weight" field */

/* Map from a given weight to the appropriate weight for the "bold"
   version of a font.
   XXX - the XLFD says these strings shouldn't be used for font matching;
   can we get the weight, as a number, from GDK, and ask GDK to find us
   a font just like the given font, but with the appropriate higher
   weight? */
static const struct {
	char	*light;
	char	*heavier;
} weight_map[] = {
	{ "ultralight", "light" },
	{ "extralight", "semilight" },
	{ "light",      "medium" },
	{ "semilight",  "semibold" },
	{ "medium",     "bold" },
	{ "semibold",   "extrabold" },
	{ "bold",       "ultrabold" }
};
#define	N_WEIGHTS	(sizeof weight_map / sizeof weight_map[0])
	
static char *
boldify(const char *font_name)
{
	char *bold_font_name;
	gchar **xlfd_tokens;
	int i;

	/* Is this an XLFD font?  If it begins with "-", yes, otherwise no. */
	if (font_name[0] == '-') {
		xlfd_tokens = g_strsplit(font_name, "-", XLFD_WEIGHT+1);
		for (i = 0; i < N_WEIGHTS; i++) {
			if (strcmp(xlfd_tokens[XLFD_WEIGHT],
			    weight_map[i].light) == 0) {
				g_free(xlfd_tokens[XLFD_WEIGHT]);
				xlfd_tokens[XLFD_WEIGHT] =
				    g_strdup(weight_map[i].heavier);
				break;
			}
		}
		bold_font_name = g_strjoinv("-", xlfd_tokens);
		g_strfreev(xlfd_tokens);
	} else {
		/* Append "bold" to the name of the font. */
		bold_font_name = g_strconcat(font_name, "bold", NULL);
	}
	return bold_font_name;
}

static void
create_main_window (gint pl_size, gint tv_size, gint bv_size, e_prefs *prefs)
{
  GtkWidget           *main_vbox, *menubar, *u_pane, *l_pane,
                      *stat_hbox,
                      *filter_bt, *filter_cm, *filter_te,
                      *filter_reset;
  GList               *filter_list = NULL;
  GtkStyle            *pl_style;
  GtkAccelGroup       *accel;
  int			i;

  /* Main window */  
  top_level = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_widget_set_name(top_level, "main window");
  gtk_signal_connect(GTK_OBJECT(top_level), "delete_event", 
    GTK_SIGNAL_FUNC(main_window_delete_event_cb), NULL);
  gtk_window_set_title(GTK_WINDOW(top_level), "The Ethereal Network Analyzer");
  gtk_widget_set_usize(GTK_WIDGET(top_level), DEF_WIDTH, -1);
  gtk_window_set_policy(GTK_WINDOW(top_level), TRUE, TRUE, FALSE);

  /* Container for menu bar, paned windows and progress/info box */
  main_vbox = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vbox), 1);
  gtk_container_add(GTK_CONTAINER(top_level), main_vbox);
  gtk_widget_show(main_vbox);

  /* Menu bar */
  get_main_menu(&menubar, &accel);
  gtk_window_add_accel_group(GTK_WINDOW(top_level), accel);
  gtk_box_pack_start(GTK_BOX(main_vbox), menubar, FALSE, TRUE, 0);
  gtk_widget_show(menubar);

  /* Panes for the packet list, tree, and byte view */
  u_pane = gtk_vpaned_new();
  gtk_paned_gutter_size(GTK_PANED(u_pane), (GTK_PANED(u_pane))->handle_size);
  l_pane = gtk_vpaned_new();
  gtk_paned_gutter_size(GTK_PANED(l_pane), (GTK_PANED(l_pane))->handle_size);
  gtk_container_add(GTK_CONTAINER(main_vbox), u_pane);
  gtk_widget_show(l_pane);
  gtk_paned_add2(GTK_PANED(u_pane), l_pane);
  gtk_widget_show(u_pane);

  /* Packet list */
  pkt_scrollw = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW(pkt_scrollw),
    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  set_scrollbar_placement_scrollw(pkt_scrollw, prefs->gui_scrollbar_on_right);
  remember_scrolled_window(pkt_scrollw);
  gtk_widget_show(pkt_scrollw);
  gtk_paned_add1(GTK_PANED(u_pane), pkt_scrollw);

  packet_list = gtk_clist_new_with_titles(cfile.cinfo.num_cols, cfile.cinfo.col_title);
  gtk_container_add(GTK_CONTAINER(pkt_scrollw), packet_list);
  
  set_plist_sel_browse(prefs->gui_plist_sel_browse);
  pl_style = gtk_style_new();
  gdk_font_unref(pl_style->font);
  pl_style->font = m_r_font;
  gtk_widget_set_style(packet_list, pl_style);
  gtk_widget_set_name(packet_list, "packet list");
  gtk_signal_connect (GTK_OBJECT (packet_list), "click_column",
    GTK_SIGNAL_FUNC(packet_list_click_column_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(packet_list), "select_row",
    GTK_SIGNAL_FUNC(packet_list_select_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(packet_list), "unselect_row",
    GTK_SIGNAL_FUNC(packet_list_unselect_cb), NULL);
  for (i = 0; i < cfile.cinfo.num_cols; i++) {
    if (get_column_resize_type(cfile.cinfo.col_fmt[i]) != RESIZE_MANUAL)
      gtk_clist_set_column_auto_resize(GTK_CLIST(packet_list), i, TRUE);

    /* Right-justify the packet number column. */
    if (cfile.cinfo.col_fmt[i] == COL_NUMBER)
      gtk_clist_set_column_justification(GTK_CLIST(packet_list), i, 
        GTK_JUSTIFY_RIGHT);

    /* Save static column sizes to use during a "-S" capture, so that
       the columns don't resize during a live capture. */
    cfile.cinfo.col_width[i] = gdk_string_width(pl_style->font,
			        get_column_longest_string(get_column_format(i)));
  }
  gtk_widget_set_usize(packet_list, -1, pl_size);
  gtk_signal_connect_object(GTK_OBJECT(packet_list), "button_press_event",
    GTK_SIGNAL_FUNC(popup_menu_handler), gtk_object_get_data(GTK_OBJECT(popup_menu_object), PM_PACKET_LIST_KEY));
  gtk_clist_set_compare_func(GTK_CLIST(packet_list), packet_list_compare);
  gtk_widget_show(packet_list);

  /* Tree view */
  create_tree_view(tv_size, prefs, l_pane, &tv_scrollw, &tree_view,
			prefs->gui_scrollbar_on_right);
  gtk_signal_connect(GTK_OBJECT(tree_view), "tree-select-row",
    GTK_SIGNAL_FUNC(tree_view_select_row_cb), NULL);
  gtk_signal_connect(GTK_OBJECT(tree_view), "tree-unselect-row",
    GTK_SIGNAL_FUNC(tree_view_unselect_row_cb), NULL);
  gtk_signal_connect_object(GTK_OBJECT(tree_view), "button_press_event",
    GTK_SIGNAL_FUNC(popup_menu_handler), gtk_object_get_data(GTK_OBJECT(popup_menu_object), PM_TREE_VIEW_KEY));
  gtk_widget_show(tree_view);

  item_style = gtk_style_new();
  gdk_font_unref(item_style->font);
  item_style->font = m_r_font;

  /* Byte view. */
  create_byte_view(bv_size, l_pane, &byte_view, &bv_scrollw,
			prefs->gui_scrollbar_on_right);

  /* Filter/info box */
  stat_hbox = gtk_hbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(stat_hbox), 0);
  gtk_box_pack_start(GTK_BOX(main_vbox), stat_hbox, FALSE, TRUE, 0);
  gtk_widget_show(stat_hbox);

  filter_bt = gtk_button_new_with_label("Filter:");
  /* A non-null pointer passed to "filter_browse_cb()" causes it to
     give the dialog box it pops up an "Apply" button. */
  gtk_signal_connect(GTK_OBJECT(filter_bt), "clicked",
    GTK_SIGNAL_FUNC(filter_browse_cb), "");
  gtk_box_pack_start(GTK_BOX(stat_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);
  
  filter_cm = gtk_combo_new();
  filter_list = g_list_append (filter_list, "");
  gtk_combo_set_popdown_strings(GTK_COMBO(filter_cm), filter_list);
  gtk_combo_disable_activate(GTK_COMBO(filter_cm));
  filter_te = GTK_COMBO(filter_cm)->entry;
  gtk_object_set_data(GTK_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_object_set_data(GTK_OBJECT(filter_te), E_DFILTER_CM_KEY, filter_cm);
  gtk_object_set_data(GTK_OBJECT(filter_te), E_DFILTER_FL_KEY, filter_list);
  gtk_box_pack_start(GTK_BOX(stat_hbox), filter_cm, TRUE, TRUE, 3);
  gtk_signal_connect(GTK_OBJECT(filter_te), "activate",
    GTK_SIGNAL_FUNC(filter_activate_cb), (gpointer) NULL);
  gtk_widget_show(filter_cm);

  filter_reset = gtk_button_new_with_label("Reset");
  gtk_object_set_data(GTK_OBJECT(filter_reset), E_DFILTER_TE_KEY, filter_te);
  gtk_signal_connect(GTK_OBJECT(filter_reset), "clicked",
		     GTK_SIGNAL_FUNC(filter_reset_cb), (gpointer) NULL);
  gtk_box_pack_start(GTK_BOX(stat_hbox), filter_reset, FALSE, TRUE, 1);
  gtk_widget_show(filter_reset);

  /* Sets the text entry widget pointer as the E_DILTER_TE_KEY data
   * of any widget that ends up calling a callback which needs
   * that text entry pointer */
  set_menu_object_data("/File/Open...", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/File/Reload", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Edit/Filters...", E_FILT_TE_PTR_KEY, filter_te);
  set_menu_object_data("/Display/Match Selected", E_DFILTER_TE_KEY, filter_te);
  set_menu_object_data("/Tools/Follow TCP Stream", E_DFILTER_TE_KEY, filter_te);

  info_bar = gtk_statusbar_new();
  main_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "main");
  file_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "file");
  gtk_statusbar_push(GTK_STATUSBAR(info_bar), main_ctx, DEF_READY_MESSAGE);
  gtk_box_pack_start(GTK_BOX(stat_hbox), info_bar, TRUE, TRUE, 0);
  gtk_widget_show(info_bar);
}
