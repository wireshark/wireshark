/* main.c
 *
 * $Id: main.c,v 1.366 2004/01/21 21:19:33 ulfl Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Richard Sharpe, 13-Feb-1999, added support for initializing structures
 *                              needed by dissect routines
 * Jeff Foster,    2001/03/12,  added support tabbed hex display windowss
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
 * - Graphs
 * - Playback window
 * - Multiple window support
 * - Add cut/copy/paste
 * - Create header parsing routines
 * - Make byte view selections more fancy?
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#include <gtk/gtk.h>

#include <string.h>
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_IO_H
#include <io.h> /* open/close on win32 */
#endif

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#ifdef WIN32 /* Needed for console I/O */
#include <fcntl.h>
#include <conio.h>
#endif

#include <epan/epan.h>
#include <epan/filesystem.h>
#include <epan/epan_dissect.h>

#include "cvsversion.h"
#include "main.h"
#include <epan/timestamp.h>
#include <epan/packet.h>
#include "capture.h"
#include "summary.h"
#include "file.h"
#include "filters.h"
#include "disabled_protos.h"
#include "prefs.h"
#include "menu.h"
#include "../menu.h"
#include "color.h"
#include "color_filters.h"
#include "color_utils.h"
#include "filter_prefs.h"
#include "file_dlg.h"
#include "column.h"
#include "print.h"
#include <epan/resolv.h>
#ifdef HAVE_LIBPCAP
#include "pcap-util.h"
#endif
#include "statusbar.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "proto_draw.h"
#include <epan/dfilter/dfilter.h>
#include "keys.h"
#include "packet_win.h"
#include "gtkglobals.h"
#include <epan/plugins.h>
#include "colors.h"
#include <epan/strutil.h>
#include "register.h"
#include <prefs-int.h>
#include "ringbuffer.h"
#include "../ui_util.h"
#include "ui_util.h"
#include "toolbar.h"
#include "../tap.h"
#include "../util.h"
#include "../version_info.h"
#include "compat_macros.h"
#include "find_dlg.h"
#include "packet_list.h"
#include "recent.h"
#include "follow_dlg.h"

#ifdef WIN32
#include "capture-wpcap.h"
#endif

typedef struct column_arrows {
  GtkWidget *table;
  GtkWidget *ascend_pm;
  GtkWidget *descend_pm;
} column_arrows;

capture_file cfile;
GtkWidget   *main_display_filter_widget=NULL;
GtkWidget   *top_level = NULL, *tree_view, *byte_nb_ptr, *tv_scrollw;
GtkWidget   *upper_pane, *lower_pane;
GtkWidget   *menubar, *main_vbox, *main_tb, *pkt_scrollw, *stat_hbox, *filter_tb;
static GtkWidget	*info_bar;
#if GTK_MAJOR_VERSION < 2
GdkFont     *m_r_font, *m_b_font;
guint	     m_font_height, m_font_width;
#else
PangoFontDescription *m_r_font, *m_b_font;
#endif
static guint    main_ctx, file_ctx, help_ctx;
static GString *comp_info_str, *runtime_info_str;
gchar       *ethereal_path = NULL;
gchar       *last_open_dir = NULL;
static gboolean updated_last_open_dir = FALSE;
static gint root_x = G_MAXINT, root_y = G_MAXINT, top_width, top_height;
static gboolean updated_geometry = FALSE;

/* init with an invalid value, so that "recent" can detect this and */
/* distinguish it from a command line value */
ts_type timestamp_type = TS_NOT_SET;

#if GTK_MAJOR_VERSION < 2
GtkStyle *item_style;
#endif

#ifdef WIN32
static gboolean has_no_console;	/* TRUE if app has no console */
static gboolean console_was_created; /* TRUE if console was created */
static void create_console(void);
static void destroy_console(void);
static void console_log_handler(const char *log_domain,
    GLogLevelFlags log_level, const char *message, gpointer user_data);
#endif

#ifdef HAVE_LIBPCAP
static gboolean list_link_layer_types;
#endif

static void create_main_window(gint, gint, gint, e_prefs*);
#ifdef WIN32
#if GTK_MAJOR_VERSION >= 2
static void try_to_get_windows_font_gtk2 (void);
#endif
#endif

#define E_DFILTER_CM_KEY          "display_filter_combo"
#define E_DFILTER_FL_KEY          "display_filter_list"

/* About Ethereal window */
#define MAX_ABOUT_MSG_LEN 2048

void
about_ethereal( GtkWidget *w _U_, gpointer data _U_ ) {
  GtkWidget   *win, *main_vb, *top_hb, *msg_label, *bbox, *ok_btn;
  gchar        message[MAX_ABOUT_MSG_LEN];

  /*
   * XXX - use GtkDialog?  The GNOME 2.x GnomeAbout widget does.
   * Should we use GtkDialog for simple_dialog() as well?  Or
   * is the GTK+ 2.x GtkDialog appropriate but the 1.2[.x] one
   * not?  (The GNOME 1.x GnomeAbout widget uses GnomeDialog.)
   */
  win = dlg_window_new("About Ethereal");
  gtk_container_border_width(GTK_CONTAINER(win), 7);

  /* Container for our rows */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(win), main_vb);
  gtk_widget_show(main_vb);

  /* Top row: Message text */
  top_hb = gtk_hbox_new(FALSE, 10);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);

  /* Construct the message string */
  snprintf(message, MAX_ABOUT_MSG_LEN,
	   "Ethereal - Network Protocol Analyzer\n\n"
	   
	   "Version " VERSION
#ifdef CVSVERSION
	   " (cvs " CVSVERSION ")"
#endif
	   " (C) 1998-2004 Gerald Combs <gerald@ethereal.com>\n\n"

       "%s\n"
       "%s\n\n"

       "Ethereal is Open Source software released under the GNU General Public License.\n\n"

	   "Check the man page for complete documentation and\n"
	   "for the list of contributors.\n\n"

	   "See http://www.ethereal.com for more information.",
	    comp_info_str->str, runtime_info_str->str);

  msg_label = gtk_label_new(message);
  gtk_label_set_justify(GTK_LABEL(msg_label), GTK_JUSTIFY_FILL);
  gtk_container_add(GTK_CONTAINER(top_hb), msg_label);
  gtk_widget_show(msg_label);

  /* Button row */
  bbox = dlg_button_row_new(GTK_STOCK_OK, NULL);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_btn = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
  SIGNAL_CONNECT_OBJECT(ok_btn, "clicked", gtk_widget_destroy, win);
  gtk_widget_grab_default(ok_btn);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(win, ok_btn);

  gtk_widget_show(win);
}

#if GTK_MAJOR_VERSION < 2
void
set_fonts(GdkFont *regular, GdkFont *bold)
#else
void
set_fonts(PangoFontDescription *regular, PangoFontDescription *bold)
#endif
{
	/* Yes, assert. The code that loads the font should check
	 * for NULL and provide its own error message. */
	g_assert(m_r_font && m_b_font);
	m_r_font = regular;
	m_b_font = bold;

#if GTK_MAJOR_VERSION < 2
	m_font_height = m_r_font->ascent + m_r_font->descent;
	m_font_width = gdk_string_width(m_r_font, "0");
#endif
}

/*
 * Go to frame specified by currently selected protocol tree item.
 */
void
goto_framenum_cb(GtkWidget *w _U_, gpointer data _U_)
{
    if (cfile.finfo_selected) {
	header_field_info	*hfinfo;
	guint32			framenum;

	hfinfo = cfile.finfo_selected->hfinfo;
	g_assert(hfinfo);
	if (hfinfo->type == FT_FRAMENUM) {
	    framenum = fvalue_get_integer(&cfile.finfo_selected->value);
	    if (framenum != 0)
		goto_frame(&cfile, framenum);
	}
    }
}

void
goto_top_frame_cb(GtkWidget *w _U_, gpointer d _U_)
{
    goto_top_frame(&cfile);
}

void
goto_bottom_frame_cb(GtkWidget *w _U_, gpointer d _U_)
{
    goto_bottom_frame(&cfile);
}


void
view_zoom_in_cb(GtkWidget *w _U_, gpointer d _U_)
{

    recent.gui_zoom_level++;
    font_apply();
}

void
view_zoom_out_cb(GtkWidget *w _U_, gpointer d _U_)
{

    recent.gui_zoom_level--;
    font_apply();
}

void
view_zoom_100_cb(GtkWidget *w _U_, gpointer d _U_)
{

    recent.gui_zoom_level = 0;
    font_apply();
}


/* Match selected byte pattern */
static void
match_selected_cb_do(gpointer data, int action, gchar *text)
{
    GtkWidget		*filter_te;
    char		*cur_filter, *new_filter;

    if (!text)
	return;
    g_assert(data);
    filter_te = OBJECT_GET_DATA(data, E_DFILTER_TE_KEY);
    g_assert(filter_te);

    cur_filter = gtk_editable_get_chars(GTK_EDITABLE(filter_te), 0, -1);

    switch (action&MATCH_SELECTED_MASK) {

    case MATCH_SELECTED_REPLACE:
	new_filter = g_strdup(text);
	break;

    case MATCH_SELECTED_AND:
	if ((!cur_filter) || (0 == strlen(cur_filter)))
	    new_filter = g_strdup(text);
	else
	    new_filter = g_strconcat("(", cur_filter, ") && (", text, ")", NULL);
	break;

    case MATCH_SELECTED_OR:
	if ((!cur_filter) || (0 == strlen(cur_filter)))
	    new_filter = g_strdup(text);
	else
	    new_filter = g_strconcat("(", cur_filter, ") || (", text, ")", NULL);
	break;

    case MATCH_SELECTED_NOT:
	new_filter = g_strconcat("!(", text, ")", NULL);
	break;

    case MATCH_SELECTED_AND_NOT:
	if ((!cur_filter) || (0 == strlen(cur_filter)))
	    new_filter = g_strconcat("!(", text, ")", NULL);
	else
	    new_filter = g_strconcat("(", cur_filter, ") && !(", text, ")", NULL);
	break;

    case MATCH_SELECTED_OR_NOT:
	if ((!cur_filter) || (0 == strlen(cur_filter)))
	    new_filter = g_strconcat("!(", text, ")", NULL);
	else
	    new_filter = g_strconcat("(", cur_filter, ") || !(", text, ")", NULL);
	break;

    default:
	g_assert_not_reached();
	new_filter = NULL;
	break;
    }

    /* Free up the copy we got of the old filter text. */
    g_free(cur_filter);

    /* create a new one and set the display filter entry accordingly */
    gtk_entry_set_text(GTK_ENTRY(filter_te), new_filter);

    /* Run the display filter so it goes in effect. */
    if (action&MATCH_SELECTED_APPLY_NOW)
	filter_packets(&cfile, new_filter);

    /* Free up the new filter text. */
    g_free(new_filter);

    /* Free up the generated text we were handed. */
    g_free(text);
}

void
match_selected_cb_replace_ptree(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

void
match_selected_cb_and_ptree(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

void
match_selected_cb_or_ptree(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

void
match_selected_cb_not_ptree(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

void
match_selected_cb_and_ptree_not(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

void
match_selected_cb_or_ptree_not(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_OR_NOT,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

void
prepare_selected_cb_replace_ptree(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_REPLACE,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

void
prepare_selected_cb_and_ptree(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_AND,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

void
prepare_selected_cb_or_ptree(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_OR,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

void
prepare_selected_cb_not_ptree(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_NOT,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

void
prepare_selected_cb_and_ptree_not(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_AND_NOT,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

void
prepare_selected_cb_or_ptree_not(GtkWidget *w, gpointer data)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    MATCH_SELECTED_OR_NOT,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}

static gchar *
get_text_from_packet_list(gpointer data)
{
    gint	row = (gint)OBJECT_GET_DATA(data, E_MPACKET_LIST_ROW_KEY);
    gint	column = (gint)OBJECT_GET_DATA(data, E_MPACKET_LIST_COL_KEY);
    frame_data *fdata = (frame_data *)packet_list_get_row_data(row);
    epan_dissect_t *edt;
    gchar      *buf=NULL;
    int         len;
    int         err;

    if (fdata != NULL) {
	if (!wtap_seek_read(cfile.wth, fdata->file_off, &cfile.pseudo_header,
		       cfile.pd, fdata->cap_len, &err)) {
	    simple_dialog(ESD_TYPE_CRIT, NULL,
		          file_read_error_message(err), cfile.filename);
	    return NULL;
	}

	edt = epan_dissect_new(FALSE, FALSE);
	epan_dissect_run(edt, &cfile.pseudo_header, cfile.pd, fdata,
			 &cfile.cinfo);
	epan_dissect_fill_in_columns(edt);

	if (strlen(cfile.cinfo.col_expr[column]) != 0 &&
	    strlen(cfile.cinfo.col_expr_val[column]) != 0) {
	    len = strlen(cfile.cinfo.col_expr[column]) +
		  strlen(cfile.cinfo.col_expr_val[column]) + 5;
	    buf = g_malloc0(len);
	    snprintf(buf, len, "%s == %s", cfile.cinfo.col_expr[column],
		     cfile.cinfo.col_expr_val[column]);
    	}

	epan_dissect_free(edt);
    }

    return buf;
}

void
match_selected_cb_replace_plist(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
match_selected_cb_and_plist(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
match_selected_cb_or_plist(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
match_selected_cb_not_plist(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
match_selected_cb_and_plist_not(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
match_selected_cb_or_plist_not(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_replace_plist(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_REPLACE,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_and_plist(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_AND,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_or_plist(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_OR,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_not_plist(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_NOT,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_and_plist_not(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_AND_NOT,
        get_text_from_packet_list(data));
}

void
prepare_selected_cb_or_plist_not(GtkWidget *w _U_, gpointer data)
{
    match_selected_cb_do(data,
        MATCH_SELECTED_OR_NOT,
        get_text_from_packet_list(data));
}




static guint dfilter_combo_max_recent = 10;

/* add a display filter to the combo box */
/* Note: a new filter string will replace an old identical one */
static gboolean
dfilter_combo_add(GtkWidget *filter_cm, char *s) {
  GList     *li;
  GList     *filter_list = OBJECT_GET_DATA(filter_cm, E_DFILTER_FL_KEY);


  /* GtkCombos don't let us get at their list contents easily, so we maintain
     our own filter list, and feed it to gtk_combo_set_popdown_strings when
     a new filter is added. */
    li = g_list_first(filter_list);
    while (li) {
        /* If the filter is already in the list, remove the old one and 
		 * append the new one at the latest position (at g_list_append() below) */
		if (li->data && strcmp(s, li->data) == 0) {
          filter_list = g_list_remove(filter_list, li->data);
		  break;
		}
      li = li->next;
    }

    filter_list = g_list_append(filter_list, s);
    OBJECT_SET_DATA(filter_cm, E_DFILTER_FL_KEY, filter_list);
    gtk_combo_set_popdown_strings(GTK_COMBO(filter_cm), filter_list);
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(filter_cm)->entry), g_list_last(filter_list)->data);

    return TRUE;
}


/* write all non empty display filters (until maximum count) 
 * of the combo box GList to the user's recent file */
void
dfilter_recent_combo_write_all(FILE *rf) {
  GtkWidget *filter_cm = OBJECT_GET_DATA(top_level, E_DFILTER_CM_KEY);
  GList     *filter_list = OBJECT_GET_DATA(filter_cm, E_DFILTER_FL_KEY);
  GList     *li;
  guint      max_count = 0;


  /* write all non empty display filter strings to the recent file (until max count) */
  li = g_list_first(filter_list);
  while ( li && (max_count++ <= dfilter_combo_max_recent) ) {
    if (strlen(li->data)) {
      fprintf (rf, RECENT_KEY_DISPLAY_FILTER ": %s\n", (char *)li->data);
    }
    li = li->next;
  }
}


/* add a display filter coming from the user's recent file to the dfilter combo box */
gboolean
dfilter_combo_add_recent(gchar *s) {
  GtkWidget *filter_cm = OBJECT_GET_DATA(top_level, E_DFILTER_CM_KEY);
  char      *dup;

  dup = g_strdup(s);
  if (!dfilter_combo_add(filter_cm, dup)) {
    g_free(dup);
    return FALSE;
  }

  return TRUE;
}


/* Run the current display filter on the current packet set, and
   redisplay. */
static void
filter_activate_cb(GtkWidget *w, gpointer data)
{
  GtkCombo  *filter_cm = OBJECT_GET_DATA(w, E_DFILTER_CM_KEY);
  GList     *filter_list = OBJECT_GET_DATA(filter_cm, E_DFILTER_FL_KEY);
  GList     *li;
  gboolean   add_filter = TRUE;
  gboolean   free_filter = TRUE;
  char      *s;

  g_assert(data);
  s = g_strdup(gtk_entry_get_text(GTK_ENTRY(data)));

  /* GtkCombos don't let us get at their list contents easily, so we maintain
     our own filter list, and feed it to gtk_combo_set_popdown_strings when
     a new filter is added. */
  if (filter_packets(&cfile, s)) {
    li = g_list_first(filter_list);
    while (li) {
      if (li->data && strcmp(s, li->data) == 0)
        add_filter = FALSE;
      li = li->next;
    }

    if (add_filter) {
      free_filter = FALSE;
      filter_list = g_list_append(filter_list, s);
      OBJECT_SET_DATA(filter_cm, E_DFILTER_FL_KEY, filter_list);
      gtk_combo_set_popdown_strings(filter_cm, filter_list);
      gtk_entry_set_text(GTK_ENTRY(filter_cm->entry), g_list_last(filter_list)->data);
    }
  }
  if (free_filter)
    g_free(s);
}

/* redisplay with no display filter */
static void
filter_reset_cb(GtkWidget *w, gpointer data _U_)
{
  GtkWidget *filter_te = NULL;

  if ((filter_te = OBJECT_GET_DATA(w, E_DFILTER_TE_KEY))) {
    gtk_entry_set_text(GTK_ENTRY(filter_te), "");
  }
  filter_packets(&cfile, NULL);
}

/* mark as reference time frame */
static void
set_frame_reftime(gboolean set, frame_data *frame, gint row) {
  if (row == -1)
    return;
  if (set) {
    frame->flags.ref_time=1;
  } else {
    frame->flags.ref_time=0;
  }
  reftime_packets(&cfile);
}

/* 0: toggle ref time status for the selected frame 
 * 1: find next ref time frame
 * 2: find previous reftime frame
 */
void 
reftime_frame_cb(GtkWidget *w _U_, gpointer data _U_, guint action)
{

  switch(action){
  case 0: /* toggle ref frame */
    if (cfile.current_frame) {
      /* XXX hum, should better have a "cfile->current_row" here ... */
      set_frame_reftime(!cfile.current_frame->flags.ref_time,
	  	     cfile.current_frame,
		     packet_list_find_row_from_data(cfile.current_frame));
    }
    break;
  case 1: /* find next ref frame */
    find_previous_next_frame_with_filter("frame.ref_time", FALSE);
    break;
  case 2: /* find previous ref frame */
    find_previous_next_frame_with_filter("frame.ref_time", TRUE);
    break;
  }
}

#if GTK_MAJOR_VERSION < 2
static void
tree_view_select_row_cb(GtkCTree *ctree, GList *node, gint column _U_,
                        gpointer user_data _U_)
#else
static void
tree_view_selection_changed_cb(GtkTreeSelection *sel, gpointer user_data _U_)
#endif
{
    field_info   *finfo;
    gchar        *help_str = NULL;
    gchar         len_str[2+10+1+5+1]; /* ", {N} bytes\0",
                                          N < 4294967296 */
    gboolean      has_blurb = FALSE;
    guint         length = 0, byte_len;
    GtkWidget    *byte_view;
    const guint8 *byte_data;
#if GTK_MAJOR_VERSION >= 2
    GtkTreeModel *model;
    GtkTreeIter   iter;
#endif

#if GTK_MAJOR_VERSION >= 2
    /* if nothing is selected */
    if (!gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        /*
         * Which byte view is displaying the current protocol tree
         * row's data?
         */
        byte_view = get_notebook_bv_ptr(byte_nb_ptr);
        if (byte_view == NULL)
            return;	/* none */

        byte_data = get_byte_view_data_and_length(byte_view, &byte_len);
        if (byte_data == NULL)
            return;	/* none */

        unselect_field(&cfile);
        packet_hex_print(GTK_TEXT_VIEW(byte_view), byte_data,
                         cfile.current_frame, NULL, byte_len);
        return;
    }
    gtk_tree_model_get(model, &iter, 1, &finfo, -1);
#else
    g_assert(node);
    finfo = gtk_ctree_node_get_row_data( ctree, GTK_CTREE_NODE(node) );
#endif
    if (!finfo) return;

    set_notebook_page(byte_nb_ptr, finfo->ds_tvb);

    byte_view = get_notebook_bv_ptr(byte_nb_ptr);
    byte_data = get_byte_view_data_and_length(byte_view, &byte_len);
    g_assert(byte_data != NULL);

    cfile.finfo_selected = finfo;
    set_menus_for_selected_tree_row(&cfile);

    if (finfo->hfinfo) {
        if (finfo->hfinfo->blurb != NULL &&
            finfo->hfinfo->blurb[0] != '\0') {
            has_blurb = TRUE;
            length = strlen(finfo->hfinfo->blurb);
        } else {
            length = strlen(finfo->hfinfo->name);
        }
        if (finfo->length == 0) {
            len_str[0] = '\0';
        } else if (finfo->length == 1) {
            strcpy (len_str, ", 1 byte");
        } else {
            snprintf (len_str, sizeof len_str, ", %d bytes", finfo->length);
        }
        statusbar_pop_field_msg();	/* get rid of current help msg */
        if (length) {
            length += strlen(finfo->hfinfo->abbrev) + strlen(len_str) + 10;
            help_str = g_malloc(sizeof(gchar) * length);
            sprintf(help_str, "%s (%s)%s",
                    (has_blurb) ? finfo->hfinfo->blurb : finfo->hfinfo->name,
                    finfo->hfinfo->abbrev, len_str);
            statusbar_push_field_msg(help_str);
            g_free(help_str);
        } else {
            /*
             * Don't show anything if the field name is zero-length;
             * the pseudo-field for "proto_tree_add_text()" is such
             * a field, and we don't want "Text (text)" showing up
             * on the status line if you've selected such a field.
             *
             * XXX - there are zero-length fields for which we *do*
             * want to show the field name.
             *
             * XXX - perhaps the name and abbrev field should be null
             * pointers rather than null strings for that pseudo-field,
             * but we'd have to add checks for null pointers in some
             * places if we did that.
             *
             * Or perhaps protocol tree items added with
             * "proto_tree_add_text()" should have -1 as the field index,
             * with no pseudo-field being used, but that might also
             * require special checks for -1 to be added.
             */
            statusbar_push_field_msg("");
        }
    }

#if GTK_MAJOR_VERSION < 2
    packet_hex_print(GTK_TEXT(byte_view), byte_data, cfile.current_frame,
                     finfo, byte_len);
#else
    packet_hex_print(GTK_TEXT_VIEW(byte_view), byte_data, cfile.current_frame,
                     finfo, byte_len);
#endif
}

#if GTK_MAJOR_VERSION < 2
static void
tree_view_unselect_row_cb(GtkCTree *ctree _U_, GList *node _U_, gint column _U_,
                          gpointer user_data _U_)
{
	GtkWidget	*byte_view;
	const guint8	*data;
	guint		len;

	/*
	 * Which byte view is displaying the current protocol tree
	 * row's data?
	 */
	byte_view = get_notebook_bv_ptr(byte_nb_ptr);
	if (byte_view == NULL)
		return;	/* none */

	data = get_byte_view_data_and_length(byte_view, &len);
	if (data == NULL)
		return;	/* none */

	unselect_field(&cfile);
	packet_hex_print(GTK_TEXT(byte_view), data, cfile.current_frame,
		NULL, len);
}
#endif

void collapse_all_cb(GtkWidget *widget _U_, gpointer data _U_) {
  if (cfile.edt->tree)
    collapse_all_tree(cfile.edt->tree, tree_view);
}

void expand_all_cb(GtkWidget *widget _U_, gpointer data _U_) {
  if (cfile.edt->tree)
    expand_all_tree(cfile.edt->tree, tree_view);
}

void resolve_name_cb(GtkWidget *widget _U_, gpointer data _U_) {
  if (cfile.edt->tree) {
    guint32 tmp = g_resolv_flags;
    g_resolv_flags = RESOLV_ALL;
    proto_tree_draw(cfile.edt->tree, tree_view);
    g_resolv_flags = tmp;
  }
}

/*
 * Push a message referring to file access onto the statusbar.
 */
void
statusbar_push_file_msg(gchar *msg)
{
	gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, msg);
}

/*
 * Pop a message referring to file access off the statusbar.
 */
void
statusbar_pop_file_msg(void)
{
	gtk_statusbar_pop(GTK_STATUSBAR(info_bar), file_ctx);
}

/*
 * XXX - do we need multiple statusbar contexts?
 */

/*
 * Push a message referring to the currently-selected field onto the statusbar.
 */
void
statusbar_push_field_msg(gchar *msg)
{
	gtk_statusbar_push(GTK_STATUSBAR(info_bar), help_ctx, msg);
}

/*
 * Pop a message referring to the currently-selected field off the statusbar.
 */
void
statusbar_pop_field_msg(void)
{
	gtk_statusbar_pop(GTK_STATUSBAR(info_bar), help_ctx);
}

static gboolean
do_quit(void)
{
	gchar *rec_path;


	/* write user's recent file to disk
	 * It is no problem to write this file, even if we do not quit */
	write_recent(&rec_path);

	/* XXX - should we check whether the capture file is an
	   unsaved temporary file for a live capture and, if so,
	   pop up a "do you want to exit without saving the capture
	   file?" dialog, and then just return, leaving said dialog
	   box to forcibly quit if the user clicks "OK"?

	   If so, note that this should be done in a subroutine that
	   returns TRUE if we do so, and FALSE otherwise, and if it
	   returns TRUE we should return TRUE without nuking anything.

	   Note that, if we do that, we might also want to check if
	   an "Update list of packets in real time" capture is in
	   progress and, if so, ask whether they want to terminate
	   the capture and discard it, and return TRUE, before nuking
	   any child capture, if they say they don't want to do so. */

#ifdef HAVE_LIBPCAP
	/* Nuke any child capture in progress. */
	kill_capture_child();
#endif

	/* Are we in the middle of reading a capture? */
	if (cfile.state == FILE_READ_IN_PROGRESS) {
		/* Yes, so we can't just close the file and quit, as
		   that may yank the rug out from under the read in
		   progress; instead, just set the state to
		   "FILE_READ_ABORTED" and return - the code doing the read
		   will check for that and, if it sees that, will clean
		   up and quit. */
		cfile.state = FILE_READ_ABORTED;

		/* Say that the window should *not* be deleted;
		   that'll be done by the code that cleans up. */
		return TRUE;
	} else {
		/* Close any capture file we have open; on some OSes, you
		   can't unlink a temporary capture file if you have it
		   open.
		   "cf_close()" will unlink it after closing it if
		   it's a temporary file.

		   We do this here, rather than after the main loop returns,
		   as, after the main loop returns, the main window may have
		   been destroyed (if this is called due to a "destroy"
		   even on the main window rather than due to the user
		   selecting a menu item), and there may be a crash
		   or other problem when "cf_close()" tries to
		   clean up stuff in the main window.

		   XXX - is there a better place to put this?
		   Or should we have a routine that *just* closes the
		   capture file, and doesn't do anything with the UI,
		   which we'd call here, and another routine that
		   calls that routine and also cleans up the UI, which
		   we'd call elsewhere? */
		cf_close(&cfile);

		/* Exit by leaving the main loop, so that any quit functions
		   we registered get called. */
		gtk_main_quit();

		/* Say that the window should be deleted. */
		return FALSE;
	}
}

static gboolean
main_window_delete_event_cb(GtkWidget *widget _U_, GdkEvent *event _U_, gpointer data _U_)
{
	/* "do_quit()" indicates whether the main window should be deleted. */
	return do_quit();
}

static gboolean
main_window_configure_event_cb(GtkWidget *widget, GdkEvent *event _U_, gpointer data _U_)
{
	gint desk_x, desk_y;

	/* Try to grab our geometry.

	   GTK+ provides two routines to get a window's position relative
	   to the X root window.  If I understand the documentation correctly,
	   gdk_window_get_deskrelative_origin applies mainly to Enlightenment
	   and gdk_window_get_root_origin applies for all other WMs.

	   The code below tries both routines, and picks the one that returns
	   the upper-left-most coordinates.

	   More info at:

	http://mail.gnome.org/archives/gtk-devel-list/2001-March/msg00289.html
	http://www.gtk.org/faq/#AEN606

	   XXX - should we get this from the event itself? */

	gdk_window_get_root_origin(widget->window, &root_x, &root_y);
	if (gdk_window_get_deskrelative_origin(widget->window,
				&desk_x, &desk_y)) {
		if (desk_x <= root_x && desk_y <= root_y) {
			root_x = desk_x;
			root_y = desk_y;
		}
	}

	/* XXX - Is this the "approved" method? */
	gdk_window_get_size(widget->window, &top_width, &top_height);

	updated_geometry = TRUE;

	return FALSE;
}

void
file_quit_cmd_cb (GtkWidget *widget _U_, gpointer data _U_)
{
	do_quit();
}

static void
print_usage(gboolean print_ver) {

  FILE *output;

  if (print_ver) {
    output = stdout;
    fprintf(output, "This is GNU " PACKAGE " " VERSION
#ifdef CVSVERSION
	" (cvs " CVSVERSION ")"
#endif
	"\n%s\n%s\n",
	comp_info_str->str, runtime_info_str->str);
  } else {
    output = stderr;
  }
#ifdef HAVE_LIBPCAP
  fprintf(output, "\n%s [ -vh ] [ -klLnpQS ] [ -a <capture autostop condition> ] ...\n",
	  PACKAGE);
  fprintf(output, "\t[ -b <number of ringbuffer files>[:<duration>] ]\n");
  fprintf(output, "\t[ -B <byte view height> ] [ -c <count> ] [ -f <capture filter> ]\n");
  fprintf(output, "\t[ -i <interface> ] [ -m <medium font> ] [ -N <resolving> ]\n");
  fprintf(output, "\t[ -o <preference setting> ] ... [ -P <packet list height> ]\n");
  fprintf(output, "\t[ -r <infile> ] [ -R <read filter> ] [ -s <snaplen> ] \n");
  fprintf(output, "\t[ -t <time stamp format> ] [ -T <tree view height> ]\n");
  fprintf(output, "\t[ -w <savefile> ] [ -y <link type> ] [ -z <statistics string> ]\n");
  fprintf(output, "\t[ <infile> ]\n");
#else
  fprintf(output, "\n%s [ -vh ] [ -n ] [ -B <byte view height> ] [ -m <medium font> ]\n",
	  PACKAGE);
  fprintf(output, "\t[ -N <resolving> ] [ -o <preference setting> ...\n");
  fprintf(output, "\t[ -P <packet list height> ] [ -r <infile> ] [ -R <read filter> ]\n");
  fprintf(output, "\t[ -t <time stamp format> ] [ -T <tree view height> ]\n");
  fprintf(output, "\t[ -z <statistics string> ] [ <infile> ]\n");
#endif
}

static void
show_version(void)
{
#ifdef WIN32
  create_console();
#endif

  printf(PACKAGE " " VERSION
#ifdef CVSVERSION
      " (cvs " CVSVERSION ")"
#endif
      "\n%s\n%s\n",
      comp_info_str->str, runtime_info_str->str);
}

static int
get_natural_int(const char *string, const char *name)
{
  long number;
  char *p;

  number = strtol(string, &p, 10);
  if (p == string || *p != '\0') {
    fprintf(stderr, "ethereal: The specified %s \"%s\" is not a decimal number\n",
	    name, string);
    exit(1);
  }
  if (number < 0) {
    fprintf(stderr, "ethereal: The specified %s \"%s\" is a negative number\n",
	    name, string);
    exit(1);
  }
  if (number > INT_MAX) {
    fprintf(stderr, "ethereal: The specified %s \"%s\" is too large (greater than %d)\n",
	    name, string, INT_MAX);
    exit(1);
  }
  return number;
}

static int
get_positive_int(const char *string, const char *name)
{
  long number;

  number = get_natural_int(string, name);

  if (number == 0) {
    fprintf(stderr, "ethereal: The specified %s is zero\n",
	    name);
    exit(1);
  }

  return number;
}

#ifdef HAVE_LIBPCAP
/*
 * Given a string of the form "<autostop criterion>:<value>", as might appear
 * as an argument to a "-a" option, parse it and set the criterion in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
static gboolean
set_autostop_criterion(const char *autostoparg)
{
  guchar *p, *colonp;

  colonp = strchr(autostoparg, ':');
  if (colonp == NULL)
    return FALSE;

  p = colonp;
  *p++ = '\0';

  /*
   * Skip over any white space (there probably won't be any, but
   * as we allow it in the preferences file, we might as well
   * allow it here).
   */
  while (isspace(*p))
    p++;
  if (*p == '\0') {
    /*
     * Put the colon back, so if our caller uses, in an
     * error message, the string they passed us, the message
     * looks correct.
     */
    *colonp = ':';
    return FALSE;
  }
  if (strcmp(autostoparg,"duration") == 0) {
    capture_opts.has_autostop_duration = TRUE;
    capture_opts.autostop_duration = get_positive_int(p,"autostop duration");
  } else if (strcmp(autostoparg,"filesize") == 0) {
    capture_opts.has_autostop_filesize = TRUE;
    capture_opts.autostop_filesize = get_positive_int(p,"autostop filesize");
  } else {
    return FALSE;
  }
  *colonp = ':'; /* put the colon back */
  return TRUE;
}

/*
 * Given a string of the form "<ring buffer file>:<duration>", as might appear
 * as an argument to a "-b" option, parse it and set the arguments in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
static gboolean
get_ring_arguments(const char *arg)
{
  guchar *p = NULL, *colonp;

  colonp = strchr(arg, ':');

  if (colonp != NULL) {
    p = colonp;
    *p++ = '\0';
  }

  capture_opts.ringbuffer_num_files = 
    get_natural_int(arg, "number of ring buffer files");

  if (colonp == NULL)
    return TRUE;

  /*
   * Skip over any white space (there probably won't be any, but
   * as we allow it in the preferences file, we might as well
   * allow it here).
   */
  while (isspace(*p))
    p++;
  if (*p == '\0') {
    /*
     * Put the colon back, so if our caller uses, in an
     * error message, the string they passed us, the message
     * looks correct.
     */
    *colonp = ':';
    return FALSE;
  }

  capture_opts.has_ring_duration = TRUE;
  capture_opts.ringbuffer_duration = get_positive_int(p,
						      "ring buffer duration");

  *colonp = ':';	/* put the colon back */
  return TRUE;
}
#endif

#if defined WIN32 || GTK_MAJOR_VERSION < 2 || ! defined USE_THREADS
/* 
   Once every 3 seconds we get a callback here which we use to update
   the tap extensions. Since Gtk1 is single threaded we dont have to
   worry about any locking or critical regions.
 */
static gint
update_cb(gpointer data _U_)
{
	draw_tap_listeners(FALSE);
	return 1;
}
#else

/* if these three functions are copied to gtk1 ethereal, since gtk1 does not
   use threads all updte_thread_mutex can be dropped and protect/unprotect 
   would just be empty functions.

   This allows gtk2-rpcstat.c and friends to be copied unmodified to 
   gtk1-ethereal and it will just work.
 */
static GStaticMutex update_thread_mutex = G_STATIC_MUTEX_INIT;
gpointer
update_thread(gpointer data _U_)
{
    while(1){
        GTimeVal tv1, tv2;
        g_get_current_time(&tv1);
        g_static_mutex_lock(&update_thread_mutex);
        gdk_threads_enter();
        draw_tap_listeners(FALSE);
        gdk_threads_leave();
        g_static_mutex_unlock(&update_thread_mutex);
        g_thread_yield();
        g_get_current_time(&tv2);
        if( ((tv1.tv_sec + 2) * 1000000 + tv1.tv_usec) >
            (tv2.tv_sec * 1000000 + tv2.tv_usec) ){
            g_usleep(((tv1.tv_sec + 2) * 1000000 + tv1.tv_usec) -
                     (tv2.tv_sec * 1000000 + tv2.tv_usec));
        }
    }
    return NULL;
}
#endif
void
protect_thread_critical_region(void)
{
#if ! defined WIN32 && GTK_MAJOR_VERSION >= 2 && defined USE_THREADS
    g_static_mutex_lock(&update_thread_mutex);
#endif
}
void
unprotect_thread_critical_region(void)
{
#if ! defined WIN32 && GTK_MAJOR_VERSION >= 2 && defined USE_THREADS
    g_static_mutex_unlock(&update_thread_mutex);
#endif
}

/* structure to keep track of what tap listeners have been registered.
 */
typedef struct _ethereal_tap_list {
	struct _ethereal_tap_list *next;
	char *cmd;
	void (*func)(char *arg);
} ethereal_tap_list;
static ethereal_tap_list *tap_list=NULL;

void
register_ethereal_tap(char *cmd, void (*func)(char *arg))
{
	ethereal_tap_list *newtl;

	newtl=malloc(sizeof(ethereal_tap_list));
	newtl->next=tap_list;
	tap_list=newtl;
	newtl->cmd=cmd;
	newtl->func=func;

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

#ifdef WIN32
  WSADATA 	       wsaData;
#endif  /* WIN32 */

  char                *rf_path;
  int                  rf_open_errno;
  char                *gpf_path, *pf_path;
  char                *cf_path, *df_path;
  char                *gdp_path, *dp_path;
  int                  gpf_open_errno, gpf_read_errno;
  int                  pf_open_errno, pf_read_errno;
  int                  cf_open_errno, df_open_errno;
  int                  gdp_open_errno, gdp_read_errno;
  int                  dp_open_errno, dp_read_errno;
  int                  err;
#ifdef HAVE_LIBPCAP
  gboolean             start_capture = FALSE;
  gchar               *save_file = NULL;
  GList               *if_list;
  if_info_t           *if_info;
  GList               *lt_list, *lt_entry;
  data_link_info_t    *data_link_info;
  gchar                err_str[PCAP_ERRBUF_SIZE];
  gboolean             stats_known;
  struct pcap_stat     stats;
#else
  gboolean             capture_option_specified = FALSE;
#endif
  gint                 pl_size = 280, tv_size = 95, bv_size = 75;
  gchar               *rc_file, *cf_name = NULL, *rfilter = NULL;
  dfilter_t           *rfcode = NULL;
  gboolean             rfilter_parse_failed = FALSE;
  e_prefs             *prefs;
  char                 badopt;
#if GTK_MAJOR_VERSION < 2
  char                *bold_font_name;
#endif
  gboolean             prefs_write_needed = FALSE;
  ethereal_tap_list   *tli = NULL;
  gchar               *tap_opt = NULL;

#define OPTSTRING_INIT "a:b:B:c:f:hi:klLm:nN:o:pP:Qr:R:Ss:t:T:w:vy:z:"

#ifdef HAVE_LIBPCAP
#ifdef WIN32
#define OPTSTRING_CHILD "W:Z:"
#else
#define OPTSTRING_CHILD "W:"
#endif  /* WIN32 */
#else
#define OPTSTRING_CHILD ""
#endif  /* HAVE_LIBPCAP */

  char optstring[sizeof(OPTSTRING_INIT) + sizeof(OPTSTRING_CHILD) - 1] =
    OPTSTRING_INIT;

  ethereal_path = argv[0];

#ifdef WIN32
  /* Arrange that if we have no console window, and a GLib message logging
     routine is called to log a message, we pop up a console window.

     We do that by inserting our own handler for all messages logged
     to the default domain; that handler pops up a console if necessary,
     and then calls the default handler. */
  g_log_set_handler(NULL,
		    G_LOG_LEVEL_ERROR|
		    G_LOG_LEVEL_CRITICAL|
		    G_LOG_LEVEL_WARNING|
		    G_LOG_LEVEL_MESSAGE|
		    G_LOG_LEVEL_INFO|
		    G_LOG_LEVEL_DEBUG|
		    G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION,
		    console_log_handler, NULL);
#endif

#ifdef HAVE_LIBPCAP
  command_name = get_basename(ethereal_path);
  /* Set "capture_child" to indicate whether this is going to be a child
     process for a "-S" capture. */
  capture_child = (strcmp(command_name, CHILD_NAME) == 0);
  if (capture_child)
    strcat(optstring, OPTSTRING_CHILD);
#endif

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps information registered by the
     dissectors, and we must do it before we read the preferences, in
     case any dissectors register preferences. */
  epan_init(PLUGIN_DIR,register_all_protocols,register_all_protocol_handoffs);

  /* Register all tap listeners; we do this before we parse the arguments,
     as the "-z" argument can specify a registered tap. */
  register_all_tap_listeners();

  /* Now register the preferences for any non-dissector modules.
     We must do that before we read the preferences as well. */
  prefs_register_modules();

  /* If invoked with the "-G" flag, we dump out information based on
     the argument to the "-G" flag; if no argument is specified,
     for backwards compatibility we dump out a glossary of display
     filter symbols.

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

	the first argument after the "-G" flag, if present, will be used
	to specify the information to dump;

	arguments after that will not be used. */
  if (argc >= 2 && strcmp(argv[1], "-G") == 0) {
    if (argc == 2)
      proto_registrar_dump_fields();
    else {
      if (strcmp(argv[2], "fields") == 0)
        proto_registrar_dump_fields();
      else if (strcmp(argv[2], "protocols") == 0)
        proto_registrar_dump_protocols();
      else {
        fprintf(stderr, "ethereal: Invalid \"%s\" option for -G flag\n",
                argv[2]);
        exit(1);
      }
    }
    exit(0);
  }

  /* multithread support currently doesn't seem to work in win32 gtk2.0.6 */
#if ! defined WIN32 && GTK_MAJOR_VERSION >= 2 && defined G_THREADS_ENABLED && defined USE_THREADS
  {
      GThread *ut;
      g_thread_init(NULL);
      gdk_threads_init();
      ut=g_thread_create(update_thread, NULL, FALSE, NULL);
      g_thread_set_priority(ut, G_THREAD_PRIORITY_LOW);
  }
#else  /* WIN32 || GTK1.2 || !G_THREADS_ENABLED || !USE_THREADS */
  /* this is to keep tap extensions updating once every 3 seconds */
  gtk_timeout_add(3000, (GtkFunction)update_cb,(gpointer)NULL);
#endif /* !WIN32 && GTK2 && G_THREADS_ENABLED */

#if HAVE_GNU_ADNS
  gtk_timeout_add(750, (GtkFunction) host_name_lookup_process, NULL);
#endif


  /* Set the current locale according to the program environment.
   * We haven't localized anything, but some GTK widgets are localized
   * (the file selection dialogue, for example).
   * This also sets the C-language locale to the native environment. */
  gtk_set_locale();

  /* Let GTK get its args */
  gtk_init (&argc, &argv);

  /* Read the preference files. */
  prefs = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
                     &pf_open_errno, &pf_read_errno, &pf_path);

#ifdef HAVE_LIBPCAP
  capture_opts.has_snaplen = FALSE;
  capture_opts.snaplen = MIN_PACKET_SIZE;
  capture_opts.has_autostop_count = FALSE;
  capture_opts.autostop_count = 1;
  capture_opts.has_autostop_duration = FALSE;
  capture_opts.autostop_duration = 1;
  capture_opts.has_autostop_filesize = FALSE;
  capture_opts.autostop_filesize = 1;
  capture_opts.ringbuffer_on = FALSE;
  capture_opts.ringbuffer_num_files = RINGBUFFER_MIN_NUM_FILES;
  capture_opts.has_ring_duration = FALSE;
  capture_opts.ringbuffer_duration = 1;
  capture_opts.linktype = -1;

  /* If this is a capture child process, it should pay no attention
     to the "prefs.capture_prom_mode" setting in the preferences file;
     it should do what the parent process tells it to do, and if
     the parent process wants it not to run in promiscuous mode, it'll
     tell it so with a "-p" flag.

     Otherwise, set promiscuous mode from the preferences setting. */
  if (capture_child)
    capture_opts.promisc_mode = TRUE;
  else
    capture_opts.promisc_mode = prefs->capture_prom_mode;

  /* Set "Update list of packets in real time" mode from the preferences
     setting. */
  capture_opts.sync_mode = prefs->capture_real_time;

  /* And do the same for "Automatic scrolling in live capture" mode. */
  auto_scroll_live = prefs->capture_auto_scroll;
#endif

  /* Set the name resolution code's flags from the preferences. */
  g_resolv_flags = prefs->name_resolve;

  /* Read the capture filter file. */
  read_filter_list(CFILTER_LIST, &cf_path, &cf_open_errno);

  /* Read the display filter file. */
  read_filter_list(DFILTER_LIST, &df_path, &df_open_errno);

  /* Read the disabled protocols file. */
  read_disabled_protos_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
			    &dp_path, &dp_open_errno, &dp_read_errno);

  init_cap_file(&cfile);

#ifdef WIN32
  /* Load wpcap if possible. Do this before collecting the run-time version information */
  load_wpcap();

  /* Start windows sockets */
  WSAStartup( MAKEWORD( 1, 1 ), &wsaData );
#endif  /* WIN32 */

  /* Assemble the compile-time version information string */
  comp_info_str = g_string_new("Compiled ");
  g_string_append(comp_info_str, "with ");
  g_string_sprintfa(comp_info_str,
#ifdef GTK_MAJOR_VERSION
                    "GTK+ %d.%d.%d", GTK_MAJOR_VERSION, GTK_MINOR_VERSION,
                    GTK_MICRO_VERSION);
#else
                    "GTK+ (version unknown)");
#endif

  g_string_append(comp_info_str, ", ");
  get_compiled_version_info(comp_info_str);

  /* Assemble the run-time version information string */
  runtime_info_str = g_string_new("Running ");
  get_runtime_version_info(runtime_info_str);

  /* Now get our args */
  while ((opt = getopt(argc, argv, optstring)) != -1) {
    switch (opt) {
      case 'a':        /* autostop criteria */
#ifdef HAVE_LIBPCAP
        if (set_autostop_criterion(optarg) == FALSE) {
          fprintf(stderr, "ethereal: Invalid or unknown -a flag \"%s\"\n", optarg);
          exit(1);
        }
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'b':        /* Ringbuffer option */
#ifdef HAVE_LIBPCAP
        capture_opts.ringbuffer_on = TRUE;
	if (get_ring_arguments(optarg) == FALSE) {
          fprintf(stderr, "ethereal: Invalid or unknown -b arg \"%s\"\n", optarg);
          exit(1);
	}
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'B':        /* Byte view pane height */
        bv_size = get_positive_int(optarg, "byte view pane height");
        break;
      case 'c':        /* Capture xxx packets */
#ifdef HAVE_LIBPCAP
        capture_opts.has_autostop_count = TRUE;
        capture_opts.autostop_count = get_positive_int(optarg, "packet count");
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
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
	print_usage(TRUE);
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
      case 'l':        /* Automatic scrolling in live capture mode */
#ifdef HAVE_LIBPCAP
        auto_scroll_live = TRUE;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'L':        /* Print list of link-layer types and exit */
#ifdef HAVE_LIBPCAP
        list_link_layer_types = TRUE;
        break;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'm':        /* Fixed-width font for the display */
        if (prefs->PREFS_GUI_FONT_NAME != NULL)
          g_free(prefs->PREFS_GUI_FONT_NAME);
        prefs->PREFS_GUI_FONT_NAME = g_strdup(optarg);
        break;
      case 'n':        /* No name resolution */
        g_resolv_flags = RESOLV_NONE;
        break;
      case 'N':        /* Select what types of addresses/port #s to resolve */
        if (g_resolv_flags == RESOLV_ALL)
          g_resolv_flags = RESOLV_NONE;
        badopt = string_to_name_resolve(optarg, &g_resolv_flags);
        if (badopt != '\0') {
          fprintf(stderr, "ethereal: -N specifies unknown resolving option '%c'; valid options are 'm', 'n', and 't'\n",
			badopt);
          exit(1);
        }
        break;
      case 'o':        /* Override preference from command line */
        switch (prefs_set_pref(optarg)) {

	case PREFS_SET_SYNTAX_ERR:
          fprintf(stderr, "ethereal: Invalid -o flag \"%s\"\n", optarg);
          exit(1);
          break;

        case PREFS_SET_NO_SUCH_PREF:
        case PREFS_SET_OBSOLETE:
          fprintf(stderr, "ethereal: -o flag \"%s\" specifies unknown preference\n",
			optarg);
          exit(1);
          break;
        }
        break;
      case 'p':        /* Don't capture in promiscuous mode */
#ifdef HAVE_LIBPCAP
	capture_opts.promisc_mode = FALSE;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
	break;
      case 'P':        /* Packet list pane height */
        pl_size = get_positive_int(optarg, "packet list pane height");
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
        capture_opts.has_snaplen = TRUE;
        capture_opts.snaplen = get_positive_int(optarg, "snapshot length");
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'S':        /* "Sync" mode: used for following file ala tail -f */
#ifdef HAVE_LIBPCAP
        capture_opts.sync_mode = TRUE;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 't':        /* Time stamp type */
        if (strcmp(optarg, "r") == 0)
          timestamp_type = TS_RELATIVE;
        else if (strcmp(optarg, "a") == 0)
          timestamp_type = TS_ABSOLUTE;
        else if (strcmp(optarg, "ad") == 0)
          timestamp_type = TS_ABSOLUTE_WITH_DATE;
        else if (strcmp(optarg, "d") == 0)
          timestamp_type = TS_DELTA;
        else {
          fprintf(stderr, "ethereal: Invalid time stamp type \"%s\"\n",
            optarg);
          fprintf(stderr, "It must be \"r\" for relative, \"a\" for absolute,\n");
          fprintf(stderr, "\"ad\" for absolute with date, or \"d\" for delta.\n");
          exit(1);
        }
        break;
      case 'T':        /* Tree view pane height */
        tv_size = get_positive_int(optarg, "tree view pane height");
        break;
      case 'v':        /* Show version and exit */
        show_version();
#ifdef WIN32
        if (console_was_created)
          destroy_console();
#endif
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
      case 'y':        /* Set the pcap data link type */
#ifdef HAVE_LIBPCAP
#ifdef HAVE_PCAP_DATALINK_NAME_TO_VAL
        capture_opts.linktype = pcap_datalink_name_to_val(optarg);
        if (capture_opts.linktype == -1) {
          fprintf(stderr, "ethereal: The specified data link type \"%s\" is not valid\n",
                  optarg);
          exit(1);
        }
#else /* HAVE_PCAP_DATALINK_NAME_TO_VAL */
        /* XXX - just treat it as a number */
        capture_opts.linktype = get_natural_int(optarg, "data link type");
#endif /* HAVE_PCAP_DATALINK_NAME_TO_VAL */
#else /* HAVE_LIBPCAP */
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif /* HAVE_LIBPCAP */
        break;
#ifdef HAVE_LIBPCAP
      /* This is a hidden option supporting Sync mode, so we don't set
       * the error flags for the user in the non-libpcap case.
       */
      case 'W':        /* Write to capture file FD xxx */
        cfile.save_file_fd = atoi(optarg);
	break;
#endif
      case 'z':
        for(tli=tap_list;tli;tli=tli->next){
          if(!strncmp(tli->cmd,optarg,strlen(tli->cmd))){
            tap_opt = g_strdup(optarg);
            break;
          }
        }
        if(!tli){
          fprintf(stderr,"ethereal: invalid -z argument.\n");
          fprintf(stderr,"  -z argument must be one of :\n");
          for(tli=tap_list;tli;tli=tli->next){
            fprintf(stderr,"     %s\n",tli->cmd);
          }
          exit(1);
        }
        break;

#ifdef _WIN32
#ifdef HAVE_LIBPCAP
      /* Hidden option supporting Sync mode */
      case 'Z':        /* Write to pipe FD XXX */
        /* associate stdout with pipe */
        i = atoi(optarg);
        if (dup2(i, 1) < 0) {
          fprintf(stderr, "Unable to dup pipe handle\n");
          exit(1);
        }
        break;
#endif /* HAVE_LIBPCAP */
#endif /* _WIN32 */

      default:
      case '?':        /* Bad flag - print usage message */
        arg_error = TRUE;
        break;
    }
  }
  argc -= optind;
  argv += optind;
  if (argc >= 1) {
    if (cf_name != NULL) {
      /*
       * Input file name specified with "-r" *and* specified as a regular
       * command-line argument.
       */
      arg_error = TRUE;
    } else {
      /*
       * Input file name not specified with "-r", and a command-line argument
       * was specified; treat it as the input file name.
       *
       * Yes, this is different from tethereal, where non-flag command-line
       * arguments are a filter, but this works better on GUI desktops
       * where a command can be specified to be run to open a particular
       * file - yes, you could have "-r" as the last part of the command,
       * but that's a bit ugly.
       */
      cf_name = g_strdup(argv[0]);
    }
    argc--;
    argv++;
  }

  if (argc != 0) {
    /*
     * Extra command line arguments were specified; complain.
     */
    fprintf(stderr, "Invalid argument: %s\n", argv[0]);
    arg_error = TRUE;
  }

#ifndef HAVE_LIBPCAP
  if (capture_option_specified)
    fprintf(stderr, "This version of Ethereal was not built with support for capturing packets.\n");
#endif
  if (arg_error) {
    print_usage(FALSE);
    exit(1);
  }

#ifdef HAVE_LIBPCAP
  if (start_capture && list_link_layer_types) {
    /* Specifying *both* is bogus. */
    fprintf(stderr, "ethereal: You cannot specify both -L and a live capture.\n");
    exit(1);
  }

  if (list_link_layer_types) {
    /* We're supposed to list the link-layer types for an interface;
       did the user also specify a capture file to be read? */
    if (cf_name) {
      /* Yes - that's bogus. */
      fprintf(stderr, "ethereal: You cannot specify -L and a capture file to be read.\n");
      exit(1);
    }
    /* No - did they specify a ring buffer option? */
    if (capture_opts.ringbuffer_on) {
      fprintf(stderr, "ethereal: Ring buffer requested, but a capture is not being done.\n");
      exit(1);
    }
  } else {
    /* We're supposed to do a live capture; did the user also specify
       a capture file to be read? */
    if (start_capture && cf_name) {
      /* Yes - that's bogus. */
      fprintf(stderr, "ethereal: You cannot specify both a live capture and a capture file to be read.\n");
      exit(1);
    }

    /* No - was the ring buffer option specified and, if so, does it make
       sense? */
    if (capture_opts.ringbuffer_on) {
      /* Ring buffer works only under certain conditions:
	 a) ring buffer does not work with temporary files;
	 b) sync_mode and capture_opts.ringbuffer_on are mutually exclusive -
	    sync_mode takes precedence;
	 c) it makes no sense to enable the ring buffer if the maximum
	    file size is set to "infinite". */
      if (save_file == NULL) {
	fprintf(stderr, "ethereal: Ring buffer requested, but capture isn't being saved to a permanent file.\n");
	capture_opts.ringbuffer_on = FALSE;
      }
      if (capture_opts.sync_mode) {
	fprintf(stderr, "ethereal: Ring buffer requested, but an \"Update list of packets in real time\" capture is being done.\n");
	capture_opts.ringbuffer_on = FALSE;
      }
      if (!capture_opts.has_autostop_filesize) {
	fprintf(stderr, "ethereal: Ring buffer requested, but no maximum capture file size was specified.\n");
	capture_opts.ringbuffer_on = FALSE;
      }
    }
  }

  if (start_capture || list_link_layer_types) {
    /* Did the user specify an interface to use? */
    if (cfile.iface == NULL) {
      /* No - is a default specified in the preferences file? */
      if (prefs->capture_device != NULL) {
          /* Yes - use it. */
          cfile.iface = g_strdup(prefs->capture_device);
      } else {
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
        if_info = if_list->data;	/* first interface */
        cfile.iface = g_strdup(if_info->name);
        free_interface_list(if_list);
      }
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

  if (list_link_layer_types) {
    /* Get the list of link-layer types for the capture device. */
    lt_list = get_pcap_linktype_list(cfile.iface, err_str);
    if (lt_list == NULL) {
      if (err_str[0] != '\0') {
	fprintf(stderr, "ethereal: The list of data link types for the capture device could not be obtained (%s).\n"
	  "Please check to make sure you have sufficient permissions, and that\n"
	  "you have the proper interface or pipe specified.\n", err_str);
      } else
	fprintf(stderr, "ethereal: The capture device has no data link types.\n");
      exit(2);
    }
    fprintf(stderr, "Data link types (use option -y to set):\n");
    for (lt_entry = lt_list; lt_entry != NULL;
         lt_entry = g_list_next(lt_entry)) {
      data_link_info = lt_entry->data;
      fprintf(stderr, "  %s", data_link_info->name);
      if (data_link_info->description != NULL)
	fprintf(stderr, " (%s)", data_link_info->description);
      else
	fprintf(stderr, " (not supported)");
      putchar('\n');
    }
    free_pcap_linktype_list(lt_list);
    exit(0);
  }

#endif

  /* Notify all registered modules that have had any of their preferences
     changed either from one of the preferences file or from the command
     line that their preferences have changed. */
  prefs_apply_all();

  /* disabled protocols as per configuration file */
  if (gdp_path == NULL && dp_path == NULL) {
    set_disabled_protos_list();
  }

  /* Build the column format array */
  col_setup(&cfile.cinfo, prefs->num_cols);
  for (i = 0; i < cfile.cinfo.num_cols; i++) {
    cfile.cinfo.col_fmt[i] = get_column_format(i);
    cfile.cinfo.col_title[i] = g_strdup(get_column_title(i));
    cfile.cinfo.fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean) *
      NUM_COL_FMTS);
    get_column_format_matches(cfile.cinfo.fmt_matx[i], cfile.cinfo.col_fmt[i]);
    cfile.cinfo.col_data[i] = NULL;
    if (cfile.cinfo.col_fmt[i] == COL_INFO)
      cfile.cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
    else
      cfile.cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
    cfile.cinfo.col_fence[i] = 0;
    cfile.cinfo.col_expr[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
    cfile.cinfo.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
  }

  for (i = 0; i < cfile.cinfo.num_cols; i++) {
      int j;

      for (j = 0; j < NUM_COL_FMTS; j++) {
         if (!cfile.cinfo.fmt_matx[i][j])
             continue;
         
         if (cfile.cinfo.col_first[j] == -1)
             cfile.cinfo.col_first[j] = i;
         cfile.cinfo.col_last[j] = i;
      }
  }

#ifdef HAVE_LIBPCAP
  if (capture_opts.has_snaplen) {
    if (capture_opts.snaplen < 1)
      capture_opts.snaplen = WTAP_MAX_PACKET_SIZE;
    else if (capture_opts.snaplen < MIN_PACKET_SIZE)
      capture_opts.snaplen = MIN_PACKET_SIZE;
  }

  /* Check the value range of the ringbuffer_num_files parameter */
  if (capture_opts.ringbuffer_num_files > RINGBUFFER_MAX_NUM_FILES)
    capture_opts.ringbuffer_num_files = RINGBUFFER_MAX_NUM_FILES;
#if RINGBUFFER_MIN_NUM_FILES > 0
  else if (capture_opts.ringbuffer_num_files < RINGBUFFER_MIN_NUM_FILES)
    capture_opts.ringbuffer_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif
#endif

#ifdef WIN32
#if GTK_MAJOR_VERSION >= 2
  try_to_get_windows_font_gtk2();
#endif
#endif
    
  /* read in rc file from global and personal configuration paths. */
  gtk_rc_parse(RC_FILE);
  rc_file = get_persconffile_path(RC_FILE, FALSE);
  gtk_rc_parse(rc_file);

  /* Try to load the regular and boldface fixed-width fonts */
#if GTK_MAJOR_VERSION < 2
  bold_font_name = font_boldify(prefs->PREFS_GUI_FONT_NAME);
  m_r_font = gdk_font_load(prefs->PREFS_GUI_FONT_NAME);
  m_b_font = gdk_font_load(bold_font_name);
#else
  m_r_font = pango_font_description_from_string(prefs->PREFS_GUI_FONT_NAME);
  m_b_font = pango_font_description_copy(m_r_font);
  pango_font_description_set_weight(m_b_font, PANGO_WEIGHT_BOLD);
#endif
  if (m_r_font == NULL || m_b_font == NULL) {
    /* XXX - pop this up as a dialog box? no */
    if (m_r_font == NULL) {
#ifdef HAVE_LIBPCAP
      if (!capture_child)
#endif
#if GTK_MAJOR_VERSION < 2
	fprintf(stderr, "ethereal: Warning: font %s not found - defaulting to 6x13 and 6x13bold\n",
#else
	fprintf(stderr, "ethereal: Warning: font %s not found - defaulting to Monospace 9\n",
#endif
		prefs->PREFS_GUI_FONT_NAME);
    } else {
#if GTK_MAJOR_VERSION < 2
      gdk_font_unref(m_r_font);
#else
      pango_font_description_free(m_r_font);
#endif
    }
    if (m_b_font == NULL) {
#ifdef HAVE_LIBPCAP
      if (!capture_child)
#endif
#if GTK_MAJOR_VERSION < 2
	fprintf(stderr, "ethereal: Warning: font %s not found - defaulting to 6x13 and 6x13bold\n",
		bold_font_name);
#else
        fprintf(stderr, "ethereal: Warning: bold font %s not found - defaulting"
                        " to Monospace 9\n", prefs->PREFS_GUI_FONT_NAME);
#endif
    } else {
#if GTK_MAJOR_VERSION < 2
      gdk_font_unref(m_b_font);
#else
      pango_font_description_free(m_b_font);
#endif
    }
#if GTK_MAJOR_VERSION < 2
    g_free(bold_font_name);
    if ((m_r_font = gdk_font_load("6x13")) == NULL) {
      fprintf(stderr, "ethereal: Error: font 6x13 not found\n");
#else
    if ((m_r_font = pango_font_description_from_string("Monospace 9")) == NULL)
    {
            fprintf(stderr, "ethereal: Error: font Monospace 9 not found\n");
#endif
      exit(1);
    }
#if GTK_MAJOR_VERSION < 2
    if ((m_b_font = gdk_font_load("6x13bold")) == NULL) {
      fprintf(stderr, "ethereal: Error: font 6x13bold not found\n");
#else
    if ((m_b_font = pango_font_description_copy(m_r_font)) == NULL) {
            fprintf(stderr, "ethereal: Error: font Monospace 9 bold not found\n");
#endif
      exit(1);
    }
    g_free(prefs->PREFS_GUI_FONT_NAME);
#if GTK_MAJOR_VERSION < 2
    prefs->PREFS_GUI_FONT_NAME = g_strdup("6x13");
#else
    pango_font_description_set_weight(m_b_font, PANGO_WEIGHT_BOLD);
    prefs->PREFS_GUI_FONT_NAME = g_strdup("Monospace 9");
#endif
  }

  /* Call this for the side-effects that set_fonts() produces */
  set_fonts(m_r_font, m_b_font);


#ifdef HAVE_LIBPCAP
  /* Is this a "child" ethereal, which is only supposed to pop up a
     capture box to let us stop the capture, and run a capture
     to a file that our parent will read? */
  if (!capture_child) {
#endif
    /* No.  Pop up the main window, and read in a capture file if
       we were told to. */
    create_main_window(pl_size, tv_size, bv_size, prefs);

    /* Read the recent file, as we have the gui now ready for it. */
    read_recent(&rf_path, &rf_open_errno);

    colors_init();
    colfilter_init();

    /* If we were given the name of a capture file, read it in now;
       we defer it until now, so that, if we can't open it, and pop
       up an alert box, the alert box is more likely to come up on
       top of the main window - but before the preference-file-error
       alert box, so, if we get one of those, it's more likely to come
       up on top of us. */
    if (cf_name) {
      if (rfilter != NULL) {
        if (!dfilter_compile(rfilter, &rfcode)) {
          simple_dialog(ESD_TYPE_CRIT, NULL, dfilter_error_msg);
          rfilter_parse_failed = TRUE;
        }
      }
      if (!rfilter_parse_failed) {
        if ((err = cf_open(cf_name, FALSE, &cfile)) == 0) {
          /* "cf_open()" succeeded, so it closed the previous
	     capture file, and thus destroyed any previous read filter
	     attached to "cf". */
          cfile.rfcode = rfcode;

          /* Open tap windows; we do so after creating the main window,
             to avoid GTK warnings, and after successfully opening the
             capture file, so we know we have something to tap. */
          if (tap_opt && tli) {
            (*tli->func)(tap_opt);
            g_free(tap_opt);
          }

          /* Read the capture file. */
          switch (cf_read(&cfile, &err)) {

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
	  set_last_open_dir(s);
          g_free(cf_name);
          cf_name = NULL;
        } else {
          if (rfcode != NULL)
            dfilter_free(rfcode);
          cfile.rfcode = NULL;
        }
      }
    }
#ifdef HAVE_LIBPCAP
  }
#endif

  /* If the global preferences file exists but we failed to open it
     or had an error reading it, pop up an alert box; we defer that
     until now, so that the alert box is more likely to come up on top of
     the main window. */
  if (gpf_path != NULL) {
    if (gpf_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open global preferences file\n\"%s\": %s.", gpf_path,
        strerror(gpf_open_errno));
    }
    if (gpf_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "I/O error reading global preferences file\n\"%s\": %s.", gpf_path,
        strerror(gpf_read_errno));
    }
  }

  /* If the user's preferences file exists but we failed to open it
     or had an error reading it, pop up an alert box; we defer that
     until now, so that the alert box is more likely to come up on top of
     the main window. */
  if (pf_path != NULL) {
    if (pf_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open your preferences file\n\"%s\": %s.", pf_path,
        strerror(pf_open_errno));
    }
    if (pf_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "I/O error reading your preferences file\n\"%s\": %s.", pf_path,
        strerror(pf_read_errno));
    }
    g_free(pf_path);
    pf_path = NULL;
  }

  /* If the user's capture filter file exists but we failed to open it,
     pop up an alert box; we defer that until now, so that the alert
     box is more likely to come up on top of the main window. */
  if (cf_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open your capture filter file\n\"%s\": %s.", cf_path,
        strerror(cf_open_errno));
      g_free(cf_path);
  }

  /* If the user's display filter file exists but we failed to open it,
     pop up an alert box; we defer that until now, so that the alert
     box is more likely to come up on top of the main window. */
  if (df_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open your display filter file\n\"%s\": %s.", df_path,
        strerror(df_open_errno));
      g_free(df_path);
  }

  /* If the global disabled protocols file exists but we failed to open it,
     or had an error reading it, pop up an alert box; we defer that until now,
     so that the alert box is more likely to come up on top of the main
     window. */
  if (gdp_path != NULL) {
    if (gdp_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open global disabled protocols file\n\"%s\": %s.",
	gdp_path, strerror(gdp_open_errno));
    }
    if (gdp_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "I/O error reading global disabled protocols file\n\"%s\": %s.",
	gdp_path, strerror(gdp_read_errno));
    }
    g_free(gdp_path);
  }

  /* If the user's disabled protocols file exists but we failed to open it,
     or had an error reading it, pop up an alert box; we defer that until now,
     so that the alert box is more likely to come up on top of the main
     window. */
  if (dp_path != NULL) {
    if (dp_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Could not open your disabled protocols file\n\"%s\": %s.", dp_path,
        strerror(dp_open_errno));
    }
    if (dp_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "I/O error reading your disabled protocols file\n\"%s\": %s.", dp_path,
        strerror(dp_read_errno));
    }
    g_free(dp_path);
  }

#ifdef HAVE_LIBPCAP
  if (capture_child) {
    /* This is the child process for a sync mode or fork mode capture,
       so just do the low-level work of a capture - don't create
       a temporary file and fork off *another* child process (so don't
       call "do_capture()"). */

       /* XXX - hand these stats to the parent process */
       capture(&stats_known, &stats);

       /* The capture is done; there's nothing more for us to do. */
       gtk_exit(0);
  } else {
    if (start_capture) {
      /* "-k" was specified; start a capture. */
      if (do_capture(save_file)) {
        /* The capture started.  Open tap windows; we do so after creating
           the main window, to avoid GTK warnings, and after starting the
           capture, so we know we have something to tap. */
        if (tap_opt && tli) {
          (*tli->func)(tap_opt);
          g_free(tap_opt);
        }
      }
      if (save_file != NULL) {
        /* Save the directory name for future file dialogs. */
        s = get_dirname(save_file);  /* Overwrites save_file */
        set_last_open_dir(s);
        g_free(save_file);
        save_file = NULL;
      }
    }
    else {
      set_menus_for_capture_in_progress(FALSE);
    }
  }

  if (!start_capture && (cfile.cfilter == NULL || strlen(cfile.cfilter) == 0)) {
    if (cfile.cfilter) {
      g_free(cfile.cfilter);
    }
    cfile.cfilter = g_strdup(get_conn_cfilter());
  }
#else
  set_menus_for_capture_in_progress(FALSE);
#endif

  gtk_main();

  /* If the last opened directory, or our geometry, has changed, save
     whatever we're supposed to save. */
  if (updated_last_open_dir || updated_geometry) {
    /* Re-read our saved preferences. */
    prefs = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
		       &pf_open_errno, &pf_read_errno, &pf_path);
    if (pf_path == NULL) {
      /* We succeeded in reading the preferences. */

      if (updated_last_open_dir) {
	/* The pathname of the last directory in which we've opened
	   a file has changed.  If it changed from what's in the
	   preferences file, and we're supposed to save it, update
	   the preference value and note that we will have to write
	   the preferences out. */
	if (prefs->gui_fileopen_style == FO_STYLE_LAST_OPENED) {
	  /* Yes, we're supposed to save it.
	     Has a file been opened since Ethereal was started? */
	  if (last_open_dir != NULL) {
	    /* Yes.  Is the most recently navigated-to directory
	       different from the saved directory? */
	    if (prefs->gui_fileopen_remembered_dir == NULL ||
	        strcmp(prefs->gui_fileopen_remembered_dir, last_open_dir) != 0) {
	      /* Yes. */
	      prefs->gui_fileopen_remembered_dir = last_open_dir;
	      prefs_write_needed = TRUE;
	    }
	  }
	}
      }

      if (updated_geometry) {
        /* We got a geometry update, in the form of a configure_notify
           event, so the geometry has changed.  If it changed from
           what's in the preferences file, and we're supposed to save
	   the current values of the changed geometry item (position or
	   size), update the preference value and note that we will have
	   to write the preferences out.

	   XXX - should GUI stuff such as this be in a separate file? */
	if (prefs->gui_geometry_save_position) {
	  if (prefs->gui_geometry_main_x != root_x) {
	    prefs->gui_geometry_main_x = root_x;
	    prefs_write_needed = TRUE;
	  }
	  if (prefs->gui_geometry_main_y != root_y) {
	    prefs->gui_geometry_main_y = root_y;
	    prefs_write_needed = TRUE;
	  }
	}

	if (prefs->gui_geometry_save_size) {
	  if (prefs->gui_geometry_main_width != top_width) {
	    prefs->gui_geometry_main_width = top_width;
	    prefs_write_needed = TRUE;
	  }
	  if (prefs->gui_geometry_main_height != top_height) {
	    prefs->gui_geometry_main_height = top_height;
	    prefs_write_needed = TRUE;
	  }
	}
      }
    
      /* Save the preferences if we need to do so.

         XXX - this doesn't save the preferences if you don't have a
         preferences file.  Forcibly writing a preferences file would
         save the current settings even if you haven't changed them,
         meaning that if the defaults change it won't affect you.
         Perhaps we need to keep track of what the *user* has changed,
         and only write out *those* preferences. */
      if (prefs_write_needed) {
	write_prefs(&pf_path);
      }
    } else {
      /* We failed to read the preferences - silently ignore the
         error. */
      g_free(pf_path);
    }
  }

  epan_cleanup();
  g_free(rc_file);

#ifdef WIN32
  /* Shutdown windows sockets */
  WSACleanup();

  /* For some unknown reason, the "atexit()" call in "create_console()"
     doesn't arrange that "destroy_console()" be called when we exit,
     so we call it here if a console was created. */
  if (console_was_created)
    destroy_console();
#endif

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
  has_no_console = TRUE;
  return main (__argc, __argv);
}

/*
 * If this application has no console window to which its standard output
 * would go, create one.
 */
static void
create_console(void)
{
  if (has_no_console) {
    /* We have no console to which to print the version string, so
       create one and make it the standard input, output, and error. */
    if (!AllocConsole())
      return;   /* couldn't create console */
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    /* Well, we have a console now. */
    has_no_console = FALSE;
    console_was_created = TRUE;

    /* Now register "destroy_console()" as a routine to be called just
       before the application exits, so that we can destroy the console
       after the user has typed a key (so that the console doesn't just
       disappear out from under them, giving the user no chance to see
       the message(s) we put in there). */
    atexit(destroy_console);
  }
}

static void
destroy_console(void)
{
  printf("\n\nPress any key to exit\n");
  _getch();
  FreeConsole();
}

/* This routine should not be necessary, at least as I read the GLib
   source code, as it looks as if GLib is, on Win32, *supposed* to
   create a console window into which to display its output.

   That doesn't happen, however.  I suspect there's something completely
   broken about that code in GLib-for-Win32, and that it may be related
   to the breakage that forces us to just call "printf()" on the message
   rather than passing the message on to "g_log_default_handler()"
   (which is the routine that does the aforementioned non-functional
   console window creation). */
static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
		    const char *message, gpointer user_data)
{
  create_console();
  if (console_was_created) {
    /* For some unknown reason, the above doesn't appear to actually cause
       anything to be sent to the standard output, so we'll just splat the
       message out directly, just to make sure it gets out. */
    printf("%s\n", message);
  } else
    g_log_default_handler(log_domain, log_level, message, user_data);
}
#endif

#if GTK_MAJOR_VERSION < 2
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
	{ "normal",     "bold" },
	{ "semibold",   "extrabold" },
	{ "bold",       "ultrabold" }
};
#define	N_WEIGHTS	(sizeof weight_map / sizeof weight_map[0])

char *
font_boldify(const char *font_name)
{
	char *bold_font_name;
	gchar **xlfd_tokens;
	unsigned int i;

	/* Is this an XLFD font?  If it begins with "-", yes, otherwise no. */
	if (font_name[0] == '-') {
		xlfd_tokens = g_strsplit(font_name, "-", XLFD_WEIGHT+1);

		/*
		 * Make sure we *have* a weight (this might not be a valid
		 * XLFD font name).
		 */
		for (i = 0; i < XLFD_WEIGHT+1; i++) {
			if (xlfd_tokens[i] == NULL) {
				/*
				 * We don't, so treat this as a non-XLFD
				 * font name.
				 */
				goto not_xlfd;
			}
		}
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
		return bold_font_name;
	}

not_xlfd:
	/*
	 * This isn't an XLFD font name; just append "bold" to the name
	 * of the font.
	 */
	bold_font_name = g_strconcat(font_name, "bold", NULL);
	return bold_font_name;
}
#endif


char *font_zoom(char *gui_font_name)
{
    char new_font_name[200];
    char *font_name_dup;
    char *font_name_p;
    long font_point_size_l;
#if GTK_MAJOR_VERSION < 2
    int minus_chars;
    char *font_foundry;
    char *font_family;
    char *font_weight;
    char *font_slant;
    char *font_set_width;
    char *font_add_style;
    char *font_pixel_size;
    char *font_point_size;
    char *font_res_x;
    char *font_res_y;
    char *font_spacing;
    char *font_aver_width;
    char *font_charset_reg;
    char *font_charset_encoding;
#endif

#if GTK_MAJOR_VERSION >= 2
    font_name_dup = strdup(gui_font_name);
    font_name_p = font_name_dup;

    /* find the start of the font_size string */
    font_name_p = strrchr(font_name_dup, ' ');
    *font_name_p = 0;
    font_name_p++;

    /* calculate the new font size */
    font_point_size_l = strtol(font_name_p, NULL, 10);
    font_point_size_l += recent.gui_zoom_level;

    /* build a new font name */
    sprintf(new_font_name, "%s %u", font_name_dup, font_point_size_l);
    g_free(font_name_dup);

    return strdup(new_font_name);
#else
    font_name_dup = strdup(gui_font_name);
    font_name_p = font_name_dup;

    minus_chars = 0;
    /* replace all '-' chars by 0 and count them */
    while ((font_name_p = strchr(font_name_p, '-')) != NULL) {
        *font_name_p = 0;
        font_name_p++;
        minus_chars++;
    }

    if (minus_chars != 14) {
        return NULL;
    }

    /* first element empty */
    font_name_p = font_name_dup;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    /* get pointers to all font name elements */
    font_foundry = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_family = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_weight = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_slant = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_set_width = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_add_style = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_pixel_size = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_point_size = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_res_x = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_res_y = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_spacing = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_aver_width = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_charset_reg = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    font_charset_encoding = font_name_p;
    font_name_p += strlen(font_name_p);
    font_name_p++;

    /* calculate the new font size */
    font_point_size_l = strtol(font_point_size, NULL, 10);
    font_point_size_l += recent.gui_zoom_level*10;
    if (font_point_size_l <= 0)
        font_point_size_l = 10;

    /* build a new font name */
    sprintf(new_font_name, "-%s-%s-%s-%s-%s--%s-%ld-%s-%s-%s-%s-%s-%s", 
        font_foundry, font_family, font_weight, font_slant, font_set_width, 
        font_pixel_size, font_point_size_l, font_res_x, font_res_y,
        font_spacing, font_aver_width, font_charset_reg, font_charset_encoding);
    g_free(font_name_dup);

    return strdup(new_font_name);
#endif
}


void
font_apply(void) {
    char *gui_font_name;
#if GTK_MAJOR_VERSION < 2
	GdkFont *new_r_font, *new_b_font;
	char *bold_font_name;
	GdkFont *old_r_font = NULL, *old_b_font = NULL;
#else
	PangoFontDescription *new_r_font, *new_b_font;
	PangoFontDescription *old_r_font = NULL, *old_b_font = NULL;
#endif


    /* convert font name to reflect the zoom level */
    gui_font_name = font_zoom(prefs.PREFS_GUI_FONT_NAME);
    if (gui_font_name == NULL) {
        simple_dialog(ESD_TYPE_WARN, NULL,
            "Font name: \"%s\" invalid, please update font setting in Edit->Preferences",
            gui_font_name);
        return;
    }

	/* XXX - what if the world changed out from under
	   us, so that one or both of these fonts cannot
	   be loaded? */
#if GTK_MAJOR_VERSION < 2
	new_r_font = gdk_font_load(gui_font_name);
	bold_font_name = font_boldify(gui_font_name);
	new_b_font = gdk_font_load(bold_font_name);
#else
	new_r_font = pango_font_description_from_string(gui_font_name);
	new_b_font = pango_font_description_copy(new_r_font);
	pango_font_description_set_weight(new_b_font,
		PANGO_WEIGHT_BOLD);
#endif
	set_plist_font(new_r_font);
	set_ptree_font_all(new_r_font);
	old_r_font = m_r_font;
	old_b_font = m_b_font;
	set_fonts(new_r_font, new_b_font);
#if GTK_MAJOR_VERSION < 2
	g_free(bold_font_name);
#endif

	/* Redraw the hex dump windows. */
	redraw_hex_dump_all();

    /* Redraw the "Follow TCP Stream" windows. */
	follow_redraw_all();

    /* We're no longer using the old fonts; unreference them. */
#if GTK_MAJOR_VERSION < 2
	if (old_r_font != NULL)
		gdk_font_unref(old_r_font);
	if (old_b_font != NULL)
		gdk_font_unref(old_b_font);
#else
	if (old_r_font != NULL)
		pango_font_description_free(old_r_font);
	if (old_b_font != NULL)
		pango_font_description_free(old_b_font);
#endif
    g_free(gui_font_name);
}




#ifdef WIN32

#define NAME_BUFFER_LEN 32

#if GTK_MAJOR_VERSION < 2


/* coming from: Allin Cottrell, http://www.ecn.wfu.edu/~cottrell/gtk_win32 */
int get_windows_font_gtk1(char *fontspec)
{
    HDC h_dc;
    HGDIOBJ h_font;
    TEXTMETRIC tm;
    char name[NAME_BUFFER_LEN];
    int len, pix_height;

    h_dc = CreateDC("DISPLAY", NULL, NULL, NULL);
    if (h_dc == NULL) return 1;
    h_font = GetStockObject(DEFAULT_GUI_FONT);
    if (h_font == NULL || !SelectObject(h_dc, h_font)) {
        DeleteDC(h_dc);
        return 1;
    }
    len = GetTextFace(h_dc, NAME_BUFFER_LEN, name);
    if (len <= 0) {
        DeleteDC(h_dc);
        return 1;
    }
    if (!GetTextMetrics(h_dc, &tm)) {
        DeleteDC(h_dc);
        return 1;
    }
    pix_height = tm.tmHeight;
    DeleteDC(h_dc);
    sprintf(fontspec, "-*-%s-*-*-*-*-%i-*-*-*-p-*-iso8859-1", name,
            pix_height);
    return 0;
}

void set_app_font_gtk1(GtkWidget *top_level_w)
{
    GtkStyle *style;
    char winfont[80];
 
    style = gtk_widget_get_style(top_level);
    if (get_windows_font_gtk1(winfont) == 0)
        style->font = gdk_font_load(winfont);
    if (style->font) gtk_widget_set_style(top_level, style);
}

#else /* GTK_MAJOR_VERSION */
static char appfontname[128] = "tahoma 8";

void set_app_font_gtk2(const char *fontname)
{
    GtkSettings *settings;

    if (fontname != NULL && *fontname == 0) return;

    settings = gtk_settings_get_default();

    if (fontname == NULL) {
	g_object_set(G_OBJECT(settings), "gtk-font-name", appfontname, NULL);
    } else {
	GtkWidget *w;
	PangoFontDescription *pfd;
	PangoContext *pc;
	PangoFont *pfont;

	w = gtk_label_new(NULL);
	pfd = pango_font_description_from_string(fontname);
	pc = gtk_widget_get_pango_context(w);
	pfont = pango_context_load_font(pc, pfd);

	if (pfont != NULL) {
	    strcpy(appfontname, fontname);
	    g_object_set(G_OBJECT(settings), "gtk-font-name", appfontname, NULL);
	}

	gtk_widget_destroy(w);
	pango_font_description_free(pfd);
    }
}

char *default_windows_menu_fontspec_gtk2(void)
{
    gchar *fontspec = NULL;
    NONCLIENTMETRICS ncm;

    memset(&ncm, 0, sizeof ncm);
    ncm.cbSize = sizeof ncm;

    if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, ncm.cbSize, &ncm, 0)) {
	HDC screen = GetDC(0);
	double y_scale = 72.0 / GetDeviceCaps(screen, LOGPIXELSY);
	int point_size = (int) (ncm.lfMenuFont.lfHeight * y_scale);

	if (point_size < 0) point_size = -point_size;
	fontspec = g_strdup_printf("%s %d", ncm.lfMenuFont.lfFaceName,
				   point_size);
	ReleaseDC(0, screen);
    }

    return fontspec;
}

static void try_to_get_windows_font_gtk2(void)
{
    gchar *fontspec;

    fontspec = default_windows_menu_fontspec_gtk2();

    if (fontspec != NULL) {
	int match = 0;
	PangoFontDescription *pfd;
	PangoFont *pfont;
	PangoContext *pc;
	GtkWidget *w;

	pfd = pango_font_description_from_string(fontspec);

	w = gtk_label_new(NULL);
	pc = gtk_widget_get_pango_context(w);
	pfont = pango_context_load_font(pc, pfd);
	match = (pfont != NULL);

	pango_font_description_free(pfd);
	g_object_unref(G_OBJECT(pc));
	gtk_widget_destroy(w);

	if (match) set_app_font_gtk2(fontspec);
	g_free(fontspec);
    }
}
#endif /* GTK_MAJOR_VERSION */

#endif /* WIN32 */




/*
 * Helper for main_widgets_rearrange()
 */
void foreach_remove_a_child(GtkWidget *widget, gpointer data) {
    gtk_container_remove(GTK_CONTAINER(data), widget);
}

/*
 * Rearrange the main window widgets
 */
void main_widgets_rearrange(void) {
    gint widgets = 0;
    GtkWidget *w[10];


    /* be a bit faster */
    gtk_widget_hide(main_vbox);

    /* be sure, we don't loose a widget while rearranging */
    gtk_widget_ref(menubar);
    gtk_widget_ref(main_tb);
    gtk_widget_ref(filter_tb);
    gtk_widget_ref(pkt_scrollw);
    gtk_widget_ref(tv_scrollw);
    gtk_widget_ref(byte_nb_ptr);
    gtk_widget_ref(upper_pane);
    gtk_widget_ref(lower_pane);
    gtk_widget_ref(stat_hbox);
    gtk_widget_ref(info_bar);

    /* empty all containers participating */
    gtk_container_foreach(GTK_CONTAINER(main_vbox),     foreach_remove_a_child, main_vbox);
    gtk_container_foreach(GTK_CONTAINER(upper_pane),    foreach_remove_a_child, upper_pane);
    gtk_container_foreach(GTK_CONTAINER(lower_pane),    foreach_remove_a_child, lower_pane);
    gtk_container_foreach(GTK_CONTAINER(stat_hbox),     foreach_remove_a_child, stat_hbox);

    gtk_box_pack_start(GTK_BOX(main_vbox), menubar, FALSE, TRUE, 0);

    if (recent.main_toolbar_show) {
        gtk_box_pack_start(GTK_BOX(main_vbox), main_tb, FALSE, TRUE, 0);
    }

    if (recent.packet_list_show) {
        w[widgets++] = pkt_scrollw;
    }

    if (recent.tree_view_show) {
        w[widgets++] = tv_scrollw;
    }

    if (recent.byte_view_show) {
        w[widgets++] = byte_nb_ptr;
    }

    switch(widgets) {
    case(0):
        break;
    case(1):
        gtk_container_add(GTK_CONTAINER(main_vbox), w[0]);
        break;
    case(2):
        gtk_container_add(GTK_CONTAINER(main_vbox), upper_pane);
        gtk_paned_pack1(GTK_PANED(upper_pane), w[0], TRUE, TRUE);
        gtk_paned_pack2(GTK_PANED(upper_pane), w[1], FALSE, FALSE);
        break;
    case(3):
        gtk_container_add(GTK_CONTAINER(main_vbox), upper_pane);
        gtk_paned_add1(GTK_PANED(upper_pane), w[0]);
        gtk_paned_add2(GTK_PANED(upper_pane), lower_pane);

        gtk_paned_pack1(GTK_PANED(lower_pane), w[1], TRUE, TRUE);
        gtk_paned_pack2(GTK_PANED(lower_pane), w[2], FALSE, FALSE);
        break;
    }

    if (recent.statusbar_show || recent.filter_toolbar_show) {
        gtk_box_pack_start(GTK_BOX(main_vbox), stat_hbox, FALSE, TRUE, 0);
    }

    if (recent.filter_toolbar_show) {
        gtk_box_pack_start(GTK_BOX(stat_hbox), filter_tb, FALSE, TRUE, 1);
    }

    if (recent.statusbar_show) {
        gtk_box_pack_start(GTK_BOX(stat_hbox), info_bar, TRUE, TRUE, 0);
    }

    gtk_widget_show(main_vbox);
}

static void
create_main_window (gint pl_size, gint tv_size, gint bv_size, e_prefs *prefs)
{
    GtkWidget     
                  *filter_bt, *filter_cm, *filter_te,
                  *filter_apply,
                  *filter_reset;
    GList         *filter_list = NULL;
    GtkAccelGroup *accel;
    /* Display filter construct dialog has an Apply button, and "OK" not
       only sets our text widget, it activates it (i.e., it causes us to
       filter the capture). */
    static construct_args_t args = {
        "Ethereal: Display Filter",
        TRUE,
        TRUE
    };

    /* Main window */
    top_level = gtk_window_new(GTK_WINDOW_TOPLEVEL);

#ifdef WIN32 
#if GTK_MAJOR_VERSION < 2
    set_app_font_gtk1(top_level);
#endif
#endif
    
    gtk_widget_set_name(top_level, "main window");
    SIGNAL_CONNECT(top_level, "delete_event", main_window_delete_event_cb,
                   NULL);
    SIGNAL_CONNECT(top_level, "realize", window_icon_realize_cb, NULL);
    gtk_window_set_title(GTK_WINDOW(top_level), "The Ethereal Network Analyzer");
    if (prefs->gui_geometry_save_position) {
        gtk_widget_set_uposition(GTK_WIDGET(top_level),
                                 prefs->gui_geometry_main_x,
                                 prefs->gui_geometry_main_y);
    }
    if (prefs->gui_geometry_save_size) {
        WIDGET_SET_SIZE(top_level, prefs->gui_geometry_main_width,
                        prefs->gui_geometry_main_height);
    } else {
        WIDGET_SET_SIZE(top_level, DEF_WIDTH, -1);
    }
    gtk_window_set_policy(GTK_WINDOW(top_level), TRUE, TRUE, FALSE);
    SIGNAL_CONNECT(top_level, "configure_event", main_window_configure_event_cb,
                   NULL);

    /* Container for menu bar, toolbar(s), paned windows and progress/info box */
    main_vbox = gtk_vbox_new(FALSE, 1);
    gtk_container_border_width(GTK_CONTAINER(main_vbox), 1);
    gtk_container_add(GTK_CONTAINER(top_level), main_vbox);
    gtk_widget_show(main_vbox);

    /* Menu bar */
    menubar = main_menu_new(&accel);
    gtk_window_add_accel_group(GTK_WINDOW(top_level), accel);
    gtk_widget_show(menubar);

    /* Main Toolbar */
    main_tb = toolbar_new();
    gtk_widget_show (main_tb);

    /* Packet list */
    pkt_scrollw = packet_list_new(prefs);
    WIDGET_SET_SIZE(packet_list, -1, pl_size);
    gtk_widget_show(pkt_scrollw);

    /* Tree view */
#if GTK_MAJOR_VERSION < 2
    item_style = gtk_style_new();
    gdk_font_unref(item_style->font);
    item_style->font = m_r_font;
#endif
    tv_scrollw = main_tree_view_new(prefs, &tree_view);
    WIDGET_SET_SIZE(tv_scrollw, -1, tv_size);
    gtk_widget_show(tv_scrollw);

#if GTK_MAJOR_VERSION < 2
    SIGNAL_CONNECT(tree_view, "tree-select-row", tree_view_select_row_cb, NULL);
    SIGNAL_CONNECT(tree_view, "tree-unselect-row", tree_view_unselect_row_cb,
                   NULL);
#else
    SIGNAL_CONNECT(gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view)),
                   "changed", tree_view_selection_changed_cb, NULL);
#endif
    SIGNAL_CONNECT(tree_view, "button_press_event", popup_menu_handler,
                   OBJECT_GET_DATA(popup_menu_object, PM_TREE_VIEW_KEY));
    gtk_widget_show(tree_view);

    /* Byte view. */
    byte_nb_ptr = byte_view_new();
    WIDGET_SET_SIZE(byte_nb_ptr, -1, bv_size);
    gtk_widget_show(byte_nb_ptr);

    SIGNAL_CONNECT(byte_nb_ptr, "button_press_event", popup_menu_handler,
                   OBJECT_GET_DATA(popup_menu_object, PM_HEXDUMP_KEY));


    /* Panes for the packet list, tree, and byte view */
    lower_pane = gtk_vpaned_new();
    gtk_paned_gutter_size(GTK_PANED(lower_pane), (GTK_PANED(lower_pane))->handle_size);
    gtk_widget_show(lower_pane);

    upper_pane = gtk_vpaned_new();
    gtk_paned_gutter_size(GTK_PANED(upper_pane), (GTK_PANED(upper_pane))->handle_size);
    gtk_widget_show(upper_pane);

    /* filter toolbar */
#if GTK_MAJOR_VERSION < 2
    filter_tb = gtk_toolbar_new(GTK_ORIENTATION_HORIZONTAL,
                               GTK_TOOLBAR_BOTH);
#else
    filter_tb = gtk_toolbar_new();
    gtk_toolbar_set_orientation(GTK_TOOLBAR(filter_tb),
                                GTK_ORIENTATION_HORIZONTAL);
#endif /* GTK_MAJOR_VERSION */
    gtk_widget_show(filter_tb);

    filter_bt = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_DISPLAY_FILTER_ENTRY);
    SIGNAL_CONNECT(filter_bt, "clicked", display_filter_construct_cb, &args);
    gtk_widget_show(filter_bt);
    OBJECT_SET_DATA(top_level, E_FILT_BT_PTR_KEY, filter_bt);

    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_bt, 
        "Edit/Apply display filter...", "Private");

    filter_cm = gtk_combo_new();
    filter_list = g_list_append (filter_list, "");
    gtk_combo_set_popdown_strings(GTK_COMBO(filter_cm), filter_list);
    gtk_combo_disable_activate(GTK_COMBO(filter_cm));
    gtk_combo_set_case_sensitive(GTK_COMBO(filter_cm), TRUE);
    OBJECT_SET_DATA(filter_cm, E_DFILTER_FL_KEY, filter_list);
    filter_te = GTK_COMBO(filter_cm)->entry;
    main_display_filter_widget=filter_te;
    OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, filter_te);
    OBJECT_SET_DATA(filter_te, E_DFILTER_CM_KEY, filter_cm);
    OBJECT_SET_DATA(top_level, E_DFILTER_CM_KEY, filter_cm);
    SIGNAL_CONNECT(filter_te, "activate", filter_activate_cb, filter_te);
    WIDGET_SET_SIZE(filter_cm, 400, -1);
    gtk_widget_show(filter_cm);
    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_cm, 
        "Enter a display filter", "Private");

    filter_reset = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLEAR);
    OBJECT_SET_DATA(filter_reset, E_DFILTER_TE_KEY, filter_te);
    SIGNAL_CONNECT(filter_reset, "clicked", filter_reset_cb, NULL);
    gtk_widget_show(filter_reset);
    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_reset, 
        "Clear the current display filter", "Private");

    filter_apply = BUTTON_NEW_FROM_STOCK(GTK_STOCK_APPLY);
    OBJECT_SET_DATA(filter_apply, E_DFILTER_CM_KEY, filter_cm);
    SIGNAL_CONNECT(filter_apply, "clicked", filter_activate_cb, filter_te);
    gtk_widget_show(filter_apply);
    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_apply, 
        "Apply this display filter", "Private");

    /* Sets the text entry widget pointer as the E_DILTER_TE_KEY data
     * of any widget that ends up calling a callback which needs
     * that text entry pointer */
    set_menu_object_data("/File/Open...", E_DFILTER_TE_KEY, filter_te);
    set_menu_object_data("/Analyze/Display Filters...", E_FILT_TE_PTR_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Follow TCP Stream", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Match/Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Match/Not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Match/And Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Match/Or Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Match/And Not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Match/Or Not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare/Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare/Not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare/And Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare/Or Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare/And Not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare/Or Not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_toolbar_object_data(E_DFILTER_TE_KEY, filter_te);
    OBJECT_SET_DATA(popup_menu_object, E_DFILTER_TE_KEY, filter_te);
    OBJECT_SET_DATA(popup_menu_object, E_MPACKET_LIST_KEY, packet_list);

    /* statusbar */
    info_bar = gtk_statusbar_new();
    main_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "main");
    file_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "file");
    help_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "help");
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), main_ctx, DEF_READY_MESSAGE);
    gtk_widget_show(info_bar);

    /* Filter/info hbox */
    stat_hbox = gtk_hbox_new(FALSE, 1);
    gtk_container_border_width(GTK_CONTAINER(stat_hbox), 0);
    gtk_widget_show(stat_hbox);

    /* rearrange all the widgets */
    main_widgets_rearrange();

    gtk_widget_show(top_level);

    /* Fill in column titles.  This must be done after the top level window
       is displayed.

       XXX - is that still true, with fixed-width columns? */
    packet_list_set_column_titles();
}


void
set_last_open_dir(char *dirname)
{
	int len;
	gchar *new_last_open_dir;

	if (dirname) {
		len = strlen(dirname);
		if (dirname[len-1] == G_DIR_SEPARATOR) {
			new_last_open_dir = g_strconcat(dirname, NULL);
		}
		else {
			new_last_open_dir = g_strconcat(dirname,
				G_DIR_SEPARATOR_S, NULL);
		}

		if (last_open_dir == NULL ||
		    strcmp(last_open_dir, new_last_open_dir) != 0)
			updated_last_open_dir = TRUE;
	}
	else {
		new_last_open_dir = NULL;
		if (last_open_dir != NULL)
			updated_last_open_dir = TRUE;
	}

	if (last_open_dir) {
		g_free(last_open_dir);
	}
	last_open_dir = new_last_open_dir;
}
