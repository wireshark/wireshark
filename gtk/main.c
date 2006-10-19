/* main.c
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <string.h>
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#ifdef _WIN32 /* Needed for console I/O */
#include <fcntl.h>
#include <conio.h>
#endif

#ifdef HAVE_LIBPORTAUDIO
#include <portaudio.h>
#endif /* HAVE_LIBPORTAUDIO */

#include <epan/epan.h>
#include <epan/filesystem.h>
#include <epan/privileges.h>
#include <epan/epan_dissect.h>
#include <epan/timestamp.h>
#include <epan/packet.h>
#include <epan/plugins.h>
#include <epan/dfilter/dfilter.h>
#include <epan/strutil.h>
#include <epan/addr_resolv.h>
#include <epan/emem.h>
#include <epan/ex-opt.h>
#include <epan/funnel.h>
#include <epan/expert.h>

/* general (not GTK specific) */
#include "file.h"
#include "summary.h"
#include "filters.h"
#include "disabled_protos.h"
#include <epan/prefs.h>
#include "filter_dlg.h"
#include "layout_prefs.h"
#include "color.h"
#include "color_filters.h"
#include "print.h"
#include "simple_dialog.h"
#include "register.h"
#include <epan/prefs-int.h>
#include "ringbuffer.h"
#include "../ui_util.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include "util.h"
#include "clopts_common.h"
#include "cmdarg_err.h"
#include "version_info.h"
#include "merge.h"
#include "u3.h"


#ifdef HAVE_LIBPCAP
#include "capture-pcap-util.h"
#include "capture.h"
#include "capture_sync.h"
#endif

#ifdef _WIN32
#include "capture-wpcap.h"
#include "capture_wpcap_packet.h"
#include <tchar.h> /* Needed for Unicode */
#if GTK_MAJOR_VERSION >= 2
#include <commctrl.h>
#endif /* GTK_MAJOR_VERSION >= 2 */
#endif /* _WIN32 */

#if GTK_MAJOR_VERSION < 2 && GTK_MINOR_VERSION < 3
#include "ethclist.h"
#endif

/* GTK related */
#include "statusbar.h"
#include "alert_box.h"
#if 0
#include "dlg_utils.h"
#endif
#include "file_dlg.h"
#include "gtkglobals.h"
#include "colors.h"
#include "gui_utils.h"
#include "compat_macros.h"

#include "main.h"
#include "menu.h"
#include "../main_window.h"
#include "../menu.h"
#include "capture_file_dlg.h"
#include <epan/column.h>
#include "proto_draw.h"
#include "keys.h"
#include "packet_win.h"
#include "toolbar.h"
#include "find_dlg.h"
#include "packet_list.h"
#include "recent.h"
#include "follow_dlg.h"
#include "font_utils.h"
#include "about_dlg.h"
#include "help_dlg.h"
#include "decode_as_dlg.h"
#include "webbrowser.h"
#include "capture_dlg.h"
#include "capture_ui_utils.h"
#include "log.h"
#include "../epan/emem.h"
#include "file_util.h"
#include "../image/wsicon16.xpm"
#include "../image/wsicon32.xpm"
#include "../image/wsicon48.xpm"
#include "../image/wsicon64.xpm"
#include "../image/wsiconcap16.xpm"
#include "../image/wsiconcap32.xpm"
#include "../image/wsiconcap48.xpm"

#ifdef HAVE_AIRPCAP
#include <airpcap.h>
#include "airpcap_loader.h"
#include "airpcap_dlg.h"
#include "airpcap_gui_utils.h"

#include "./gtk/toolbar.h"

#include "./image/toolbar/wep_closed_24.xpm"
#endif

/*
 * Files under personal and global preferences directories in which
 * GTK settings for Wireshark are stored.
 */
#define RC_FILE "gtkrc"

#ifdef HAVE_LIBPCAP
#define DEF_READY_MESSAGE " Ready to load or capture"
#else
#define DEF_READY_MESSAGE " Ready to load file"
#endif

capture_file cfile;
GtkWidget   *main_display_filter_widget=NULL;
GtkWidget   *top_level = NULL, *tree_view, *byte_nb_ptr, *tv_scrollw;
static GtkWidget   *main_pane_v1, *main_pane_v2, *main_pane_h1, *main_pane_h2;
static GtkWidget   *main_first_pane, *main_second_pane;
static GtkWidget   *status_pane;
static GtkWidget   *menubar, *main_vbox, *main_tb, *pkt_scrollw, *stat_hbox, *filter_tb;

#ifdef HAVE_AIRPCAP
GtkWidget *airpcap_tb;
#endif

static GtkWidget	*info_bar;
static GtkWidget    *packets_bar = NULL;
static GtkWidget    *welcome_pane;
static guint		main_ctx, file_ctx, help_ctx;
static guint        packets_ctx;
static gchar        *packets_str = NULL;
GString *comp_info_str, *runtime_info_str;
gboolean have_capture_file = FALSE; /* XXX - is there an aquivalent in cfile? */

#ifdef _WIN32
static gboolean has_console;	/* TRUE if app has console */
static void destroy_console(void);
#endif
static void console_log_handler(const char *log_domain,
    GLogLevelFlags log_level, const char *message, gpointer user_data);

#ifdef HAVE_LIBPCAP
static gboolean list_link_layer_types;
capture_options global_capture_opts;
capture_options *capture_opts = &global_capture_opts;
#endif

gboolean block_toolbar_signals = FALSE;

static void create_main_window(gint, gint, gint, e_prefs*);
static void show_main_window(gboolean);
static void file_quit_answered_cb(gpointer dialog, gint btn, gpointer data);
static void main_save_window_geometry(GtkWidget *widget);

#define E_DFILTER_CM_KEY          "display_filter_combo"
#define E_DFILTER_FL_KEY          "display_filter_list"

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
	main_filter_packets(&cfile, new_filter, FALSE);

    /* Free up the new filter text. */
    g_free(new_filter);
}

void
match_selected_ptree_cb(GtkWidget *w, gpointer data, MATCH_SELECTED_E action)
{
    if (cfile.finfo_selected)
	match_selected_cb_do((data ? data : w),
	    action,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}


static void selected_ptree_info_answered_cb(gpointer dialog _U_, gint btn, gpointer data)
{
    gchar *selected_proto_url;
    gchar *proto_abbrev = data;


    switch(btn) {
    case(ESD_BTN_OK):
        if (cfile.finfo_selected) {
            /* open wiki page using the protocol abbreviation */
            selected_proto_url = g_strdup_printf("http://wiki.wireshark.org/Protocols/%s", proto_abbrev);
            browser_open_url(selected_proto_url);
            g_free(selected_proto_url);
        }
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}


void
selected_ptree_info_cb(GtkWidget *widget _U_, gpointer data _U_)
{
    int field_id;
    const gchar *proto_abbrev;
    gpointer  dialog;


    if (cfile.finfo_selected) {
        /* convert selected field to protocol abbreviation */
        /* XXX - could this conversion be simplified? */
        field_id = cfile.finfo_selected->hfinfo->id;
        /* if the selected field isn't a protocol, get it's parent */
        if(!proto_registrar_is_protocol(field_id)) {
            field_id = proto_registrar_get_parent(cfile.finfo_selected->hfinfo->id);
        }

        proto_abbrev = proto_registrar_get_abbrev(field_id);

        /* ask the user if the wiki page really should be opened */
        dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_OK_CANCEL,
                    PRIMARY_TEXT_START "Open Wireshark Wiki page of protocol \"%s\"?" PRIMARY_TEXT_END "\n"
                    "\n"
                    "This will open the \"%s\" related Wireshark Wiki page in your Web browser.\n"
                    "\n"
                    "The Wireshark Wiki is a collaborative approach to provide information\n"
                    "about Wireshark in several ways (not limited to protocol specifics).\n"
                    "\n"
                    "This Wiki is new, so the page of the selected protocol\n"
                    "may not exist and/or may not contain valuable information.\n"
                    "\n"
                    "As everyone can edit the Wiki and add new content (or extend existing),\n"
                    "you are encouraged to add information if you can.\n"
                    "\n"
                    "Hint 1: If you are new to wiki editing, try out editing the Sandbox first!\n"
                    "\n"
                    "Hint 2: If you want to add a new protocol page, you should use the ProtocolTemplate,\n"
                    "which will save you a lot of editing and will give a consistent look over the pages.",
                    proto_abbrev, proto_abbrev);
        simple_dialog_set_cb(dialog, selected_ptree_info_answered_cb, (gpointer) proto_abbrev);
    }
}


void
selected_ptree_ref_cb(GtkWidget *widget _U_, gpointer data _U_)
{
    int field_id;
    const gchar *proto_abbrev;
    gchar *selected_proto_url;


    if (cfile.finfo_selected) {
        /* convert selected field to protocol abbreviation */
        /* XXX - could this conversion be simplified? */
        field_id = cfile.finfo_selected->hfinfo->id;
        /* if the selected field isn't a protocol, get it's parent */
        if(!proto_registrar_is_protocol(field_id)) {
            field_id = proto_registrar_get_parent(cfile.finfo_selected->hfinfo->id);
        }

        proto_abbrev = proto_registrar_get_abbrev(field_id);

        /* open reference page using the protocol abbreviation */
        selected_proto_url = g_strdup_printf("http://www.wireshark.org/docs/dfref/%c/%s.html", proto_abbrev[0], proto_abbrev);
        browser_open_url(selected_proto_url);
        g_free(selected_proto_url);
    }
}

static gchar *
get_text_from_packet_list(gpointer data)
{
    gint	row = GPOINTER_TO_INT(OBJECT_GET_DATA(data, E_MPACKET_LIST_ROW_KEY));
    gint	column = GPOINTER_TO_INT(OBJECT_GET_DATA(data, E_MPACKET_LIST_COL_KEY));
    frame_data *fdata = (frame_data *)packet_list_get_row_data(row);
    epan_dissect_t *edt;
    gchar      *buf=NULL;
    int         len;
    int         err;
    gchar       *err_info;

    if (fdata != NULL) {
	if (!wtap_seek_read(cfile.wth, fdata->file_off, &cfile.pseudo_header,
		       cfile.pd, fdata->cap_len, &err, &err_info)) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		          cf_read_error_message(err, err_info), cfile.filename);
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
	    buf = ep_alloc0(len);
	    g_snprintf(buf, len, "%s == %s", cfile.cinfo.col_expr[column],
		     cfile.cinfo.col_expr_val[column]);
    	}

	epan_dissect_free(edt);
    }

    return buf;
}

void
match_selected_plist_cb(GtkWidget *w _U_, gpointer data, MATCH_SELECTED_E action)
{
    match_selected_cb_do(data,
        action,
        get_text_from_packet_list(data));
}

/* This function allows users to right click in the details window and copy the text
 * information to the operating systems clipboard.
 *
 * We first check to see if a string representation is setup in the tree and then
 * read the string. If not available then we try to grab the value. If all else
 * fails we display a message to the user to indicate the copy could not be completed.
 */
void
copy_selected_plist_cb(GtkWidget *w _U_, gpointer data _U_)
{
	GString *gtk_text_str = g_string_new("");
    char labelstring[256];
    char *stringpointer = labelstring;

    if (cfile.finfo_selected->rep->representation != 0) {
        g_string_sprintfa(gtk_text_str, "%s", cfile.finfo_selected->rep->representation);   /* Get the represented data */
    }
    if (gtk_text_str->len == 0) {                                                           /* If no representation then... */
        proto_item_fill_label(cfile.finfo_selected, stringpointer);                         /* Try to read the value */
        g_string_sprintfa(gtk_text_str, "%s", stringpointer);
    }
    if (gtk_text_str->len == 0) {                                                           /* Could not get item so display error msg */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not acquire information to copy, try expanding or choosing another item");
    }
    else
    {
        copy_to_clipboard(gtk_text_str);                     /* Copy string to clipboard */
    }
    g_string_free(gtk_text_str, TRUE);                       /* Free the memory */
}


/* XXX: use a preference for this setting! */
static guint dfilter_combo_max_recent = 10;

/* add a display filter to the combo box */
/* Note: a new filter string will replace an old identical one */
static gboolean
dfilter_combo_add(GtkWidget *filter_cm, char *s) {
  GList     *li;
  GList     *dfilter_list = OBJECT_GET_DATA(filter_cm, E_DFILTER_FL_KEY);


  /* GtkCombos don't let us get at their list contents easily, so we maintain
     our own filter list, and feed it to gtk_combo_set_popdown_strings when
     a new filter is added. */
    li = g_list_first(dfilter_list);
    while (li) {
        /* If the filter is already in the list, remove the old one and
		 * append the new one at the latest position (at g_list_append() below) */
		if (li->data && strcmp(s, li->data) == 0) {
          dfilter_list = g_list_remove(dfilter_list, li->data);
		  break;
		}
      li = li->next;
    }

    dfilter_list = g_list_append(dfilter_list, s);
    OBJECT_SET_DATA(filter_cm, E_DFILTER_FL_KEY, dfilter_list);
    gtk_combo_set_popdown_strings(GTK_COMBO(filter_cm), dfilter_list);
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(filter_cm)->entry), g_list_last(dfilter_list)->data);

    return TRUE;
}


/* write all non empty display filters (until maximum count)
 * of the combo box GList to the user's recent file */
void
dfilter_recent_combo_write_all(FILE *rf) {
  GtkWidget *filter_cm = OBJECT_GET_DATA(top_level, E_DFILTER_CM_KEY);
  GList     *dfilter_list = OBJECT_GET_DATA(filter_cm, E_DFILTER_FL_KEY);
  GList     *li;
  guint      max_count = 0;


  /* write all non empty display filter strings to the recent file (until max count) */
  li = g_list_first(dfilter_list);
  while ( li && (max_count++ <= dfilter_combo_max_recent) ) {
    if (strlen(li->data)) {
      fprintf (rf, RECENT_KEY_DISPLAY_FILTER ": %s\n", (char *)li->data);
    }
    li = li->next;
  }
}

/* empty the combobox entry field */
void
dfilter_combo_add_empty(void) {
  GtkWidget *filter_cm = OBJECT_GET_DATA(top_level, E_DFILTER_CM_KEY);

  gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(filter_cm)->entry), "");
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


/* call cf_filter_packets() and add this filter string to the recent filter list */
gboolean
main_filter_packets(capture_file *cf, const gchar *dftext, gboolean force)
{
  GtkCombo  *filter_cm = OBJECT_GET_DATA(top_level, E_DFILTER_CM_KEY);
  GList     *dfilter_list = OBJECT_GET_DATA(filter_cm, E_DFILTER_FL_KEY);
  GList     *li;
  gboolean   add_filter = TRUE;
  gboolean   free_filter = TRUE;
  char      *s;
  cf_status_t cf_status;

  /* we'll crash later on if dftext is NULL */
  g_assert(dftext != NULL);

  s = g_strdup(dftext);

  /* GtkCombos don't let us get at their list contents easily, so we maintain
     our own filter list, and feed it to gtk_combo_set_popdown_strings when
     a new filter is added. */
  cf_status = cf_filter_packets(cf, s, force);
  if (cf_status == CF_OK) {
    li = g_list_first(dfilter_list);
    while (li) {
      if (li->data && strcmp(s, li->data) == 0)
        add_filter = FALSE;
      li = li->next;
    }

    if (add_filter) {
      /* trim list size first */
      while (g_list_length(dfilter_list) >= dfilter_combo_max_recent) {
        dfilter_list = g_list_remove(dfilter_list, g_list_first(dfilter_list)->data);
      }

      free_filter = FALSE;
      dfilter_list = g_list_append(dfilter_list, s);
      OBJECT_SET_DATA(filter_cm, E_DFILTER_FL_KEY, dfilter_list);
      gtk_combo_set_popdown_strings(filter_cm, dfilter_list);
      gtk_entry_set_text(GTK_ENTRY(filter_cm->entry), g_list_last(dfilter_list)->data);
    }
  }
  if (free_filter)
    g_free(s);

  return (cf_status == CF_OK);
}


/* Run the current display filter on the current packet set, and
   redisplay. */
static void
filter_activate_cb(GtkWidget *w _U_, gpointer data)
{
  const char *s;

  s = gtk_entry_get_text(GTK_ENTRY(data));

  main_filter_packets(&cfile, s, FALSE);
}

/* redisplay with no display filter */
static void
filter_reset_cb(GtkWidget *w, gpointer data _U_)
{
  GtkWidget *filter_te = NULL;

  if ((filter_te = OBJECT_GET_DATA(w, E_DFILTER_TE_KEY))) {
    gtk_entry_set_text(GTK_ENTRY(filter_te), "");
  }
  main_filter_packets(&cfile, "", FALSE);
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
  cf_reftime_packets(&cfile);
}


GtkWidget *reftime_dialog = NULL;

static void reftime_answered_cb(gpointer dialog _U_, gint btn, gpointer data _U_)
{
    switch(btn) {
    case(ESD_BTN_YES):
        timestamp_set_type(TS_RELATIVE);
        recent.gui_time_format  = TS_RELATIVE;
        cf_change_time_formats(&cfile);
        break;
    case(ESD_BTN_NO):
        break;
    default:
        g_assert_not_reached();
    }

    if (cfile.current_frame) {
      /* XXX hum, should better have a "cfile->current_row" here ... */
      set_frame_reftime(!cfile.current_frame->flags.ref_time,
	  	     cfile.current_frame,
		     packet_list_find_row_from_data(cfile.current_frame));
    }
}


void
reftime_frame_cb(GtkWidget *w _U_, gpointer data _U_, REFTIME_ACTION_E action)
{

  switch(action){
  case REFTIME_TOGGLE:
    if (cfile.current_frame) {
        if(recent.gui_time_format != TS_RELATIVE && cfile.current_frame->flags.ref_time==0) {
            reftime_dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_YES_NO,
                PRIMARY_TEXT_START "Switch to the appropriate Time Display Format?" PRIMARY_TEXT_END "\n\n"
                "Time References don't work well with the currently selected Time Display Format.\n\n"
                "Do you want to switch to \"Seconds Since Beginning of Capture\" now?");
            simple_dialog_set_cb(reftime_dialog, reftime_answered_cb, NULL);
        } else {
      /* XXX hum, should better have a "cfile->current_row" here ... */
      set_frame_reftime(!cfile.current_frame->flags.ref_time,
	  	     cfile.current_frame,
		     packet_list_find_row_from_data(cfile.current_frame));
    }
    }
    break;
  case REFTIME_FIND_NEXT:
    find_previous_next_frame_with_filter("frame.ref_time", FALSE);
    break;
  case REFTIME_FIND_PREV:
    find_previous_next_frame_with_filter("frame.ref_time", TRUE);
    break;
  }
}

void
find_next_mark_cb(GtkWidget *w _U_, gpointer data _U_, int action _U_)
{
    find_previous_next_frame_with_filter("frame.marked == TRUE", FALSE);
}

void
find_prev_mark_cb(GtkWidget *w _U_, gpointer data _U_, int action _U_)
{
    find_previous_next_frame_with_filter("frame.marked == TRUE", TRUE);
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

        cf_unselect_field(&cfile);
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
            g_snprintf (len_str, sizeof len_str, ", %d bytes", finfo->length);
        }
        statusbar_pop_field_msg();	/* get rid of current help msg */
        if (length) {
            help_str = g_strdup_printf("%s (%s)%s",
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

	cf_unselect_field(&cfile);
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

void expand_tree_cb(GtkWidget *widget _U_, gpointer data _U_) {
#if GTK_MAJOR_VERSION < 2
  GtkCTreeNode *node;
#else
  GtkTreePath  *path;
#endif

#if GTK_MAJOR_VERSION < 2
  node = gtk_ctree_find_by_row_data(GTK_CTREE(tree_view), NULL, cfile.finfo_selected);
  if(node) {
    /* the mouse position is at an entry, expand that one */
  gtk_ctree_expand_recursive(GTK_CTREE(tree_view), node);
  }
#else
  path = tree_find_by_field_info(GTK_TREE_VIEW(tree_view), cfile.finfo_selected);
  if(path) {
    /* the mouse position is at an entry, expand that one */
  gtk_tree_view_expand_row(GTK_TREE_VIEW(tree_view), path, TRUE);
  gtk_tree_path_free(path);
  }
#endif
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
    /*g_warning("statusbar_push: %s", msg);*/
	gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, msg);
}

/*
 * Pop a message referring to file access off the statusbar.
 */
void
statusbar_pop_file_msg(void)
{
    /*g_warning("statusbar_pop");*/
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

/*
 * update the packets statusbar to the current values
 */
void packets_bar_update(void)
{

    if(packets_bar) {
        /* remove old status */
        if(packets_str) {
            g_free(packets_str);
	        gtk_statusbar_pop(GTK_STATUSBAR(packets_bar), packets_ctx);
        }

        /* do we have any packets? */
        if(cfile.count) {
            if(cfile.drops_known) {
                packets_str = g_strdup_printf(" P: %u D: %u M: %u Drops: %u",
                    cfile.count, cfile.displayed_count, cfile.marked_count, cfile.drops);
            } else {
                packets_str = g_strdup_printf(" P: %u D: %u M: %u",
                    cfile.count, cfile.displayed_count, cfile.marked_count);
            }
        } else {
            packets_str = g_strdup(" No Packets");
        }
	    gtk_statusbar_push(GTK_STATUSBAR(packets_bar), packets_ctx, packets_str);
    }
}

void
main_set_for_capture_file(gboolean have_capture_file_in)
{
    have_capture_file = have_capture_file_in;

    main_widgets_show_or_hide();
}

gboolean
main_do_quit(void)
{
	/* get the current geometry, before writing it to disk */
	main_save_window_geometry(top_level);

	/* write user's recent file to disk
	 * It is no problem to write this file, even if we do not quit */
	write_recent();

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
	capture_kill_child(capture_opts);
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
  gpointer dialog;

  if((cfile.state != FILE_CLOSED) && !cfile.user_saved && prefs.gui_ask_unsaved) {
#if GTK_MAJOR_VERSION >= 2
    gtk_window_present(GTK_WINDOW(top_level));
#endif
    /* user didn't saved his current file, ask him */
    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_DONTSAVE_CANCEL,
                PRIMARY_TEXT_START "Save capture file before program quit?" PRIMARY_TEXT_END "\n\n"
                "If you quit the program without saving, your capture data will be discarded.");
    simple_dialog_set_cb(dialog, file_quit_answered_cb, NULL);
    return TRUE;
  } else {
    /* unchanged file, just exit */
    /* "main_do_quit()" indicates whether the main window should be deleted. */
    return main_do_quit();
  }
}



static void
main_load_window_geometry(GtkWidget *widget)
{
    window_geometry_t geom;

    geom.set_pos        = prefs.gui_geometry_save_position;
    geom.x              = recent.gui_geometry_main_x;
    geom.y              = recent.gui_geometry_main_y;
    geom.set_size       = prefs.gui_geometry_save_size;
    if (recent.gui_geometry_main_width > 0 &&
        recent.gui_geometry_main_height > 0) {
        geom.width          = recent.gui_geometry_main_width;
        geom.height         = recent.gui_geometry_main_height;
        geom.set_maximized  = prefs.gui_geometry_save_maximized;
    } else {
        /* We assume this means the width and height weren't set in
           the "recent" file (or that there is no "recent" file),
           and weren't set to a default value, so we don't set the
           size.  (The "recent" file code rejects non-positive width
           and height values.) */
       geom.set_size = FALSE;
    }
    geom.maximized      = recent.gui_geometry_main_maximized;

    window_set_geometry(widget, &geom);

    if (recent.has_gui_geometry_main_upper_pane && recent.gui_geometry_main_upper_pane)
        gtk_paned_set_position(GTK_PANED(main_first_pane),  recent.gui_geometry_main_upper_pane);
    if (recent.has_gui_geometry_main_lower_pane && recent.gui_geometry_main_lower_pane)
        gtk_paned_set_position(GTK_PANED(main_second_pane), recent.gui_geometry_main_lower_pane);
    if (recent.has_gui_geometry_main_lower_pane && recent.gui_geometry_status_pane)
        gtk_paned_set_position(GTK_PANED(status_pane),      recent.gui_geometry_status_pane);
}


static void
main_save_window_geometry(GtkWidget *widget)
{
    window_geometry_t geom;

    window_get_geometry(widget, &geom);

    if (prefs.gui_geometry_save_position) {
        recent.gui_geometry_main_x = geom.x;
	    recent.gui_geometry_main_y = geom.y;
    }

    if (prefs.gui_geometry_save_size) {
        recent.gui_geometry_main_width  = geom.width,
        recent.gui_geometry_main_height = geom.height;
    }

#if GTK_MAJOR_VERSION >= 2
    if(prefs.gui_geometry_save_maximized) {
        recent.gui_geometry_main_maximized = geom.maximized;
    }

    recent.gui_geometry_main_upper_pane     = gtk_paned_get_position(GTK_PANED(main_first_pane));
    recent.gui_geometry_main_lower_pane     = gtk_paned_get_position(GTK_PANED(main_second_pane));
    recent.gui_geometry_status_pane         = gtk_paned_get_position(GTK_PANED(status_pane));
#endif
}

static void file_quit_answered_cb(gpointer dialog _U_, gint btn, gpointer data _U_)
{
    switch(btn) {
    case(ESD_BTN_SAVE):
        /* save file first */
        file_save_as_cmd(after_save_exit, NULL);
        break;
    case(ESD_BTN_DONT_SAVE):
        main_do_quit();
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}

void
file_quit_cmd_cb(GtkWidget *widget _U_, gpointer data _U_)
{
  gpointer dialog;

  if((cfile.state != FILE_CLOSED) && !cfile.user_saved && prefs.gui_ask_unsaved) {
    /* user didn't saved his current file, ask him */
    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_DONTSAVE_CANCEL,
                PRIMARY_TEXT_START "Save capture file before program quit?" PRIMARY_TEXT_END "\n\n"
                "If you quit the program without saving, your capture data will be discarded.");
    simple_dialog_set_cb(dialog, file_quit_answered_cb, NULL);
  } else {
    /* unchanged file, just exit */
    main_do_quit();
  }
}

static void
print_usage(gboolean print_ver) {

  FILE *output;

#ifdef _WIN32
  create_console();
#endif

  if (print_ver) {
    output = stdout;
    fprintf(output, "Wireshark " VERSION "%s\n"
        "Interactively dump and analyze network traffic.\n"
        "See http://www.wireshark.org for more information.\n"
        "\n"
        "%s",
	svnversion, get_copyright_info());
  } else {
    output = stderr;
  }
  fprintf(output, "\n");
  fprintf(output, "Usage: wireshark [options] ... [ <infile> ]\n");
  fprintf(output, "\n");

#ifdef HAVE_LIBPCAP
  fprintf(output, "Capture interface:\n");
  fprintf(output, "  -i <interface>           name or idx of interface (def: first non-loopback)\n");
  fprintf(output, "  -f <capture filter>      packet filter in libpcap filter syntax\n");
  fprintf(output, "  -s <snaplen>             packet snapshot length (def: 65535)\n");
  fprintf(output, "  -p                       don't capture in promiscuous mode\n");
  fprintf(output, "  -k                       start capturing immediately (def: do nothing)\n");
  fprintf(output, "  -Q                       quit Wireshark after capturing\n");
  fprintf(output, "  -S                       update packet display when new packets are captured\n");
  fprintf(output, "  -l                       turn on automatic scrolling while -S is in use\n");
#ifdef _WIN32
  fprintf(output, "  -B <buffer size>         size of kernel buffer (def: 1MB)\n");
#endif
  fprintf(output, "  -y <link type>           link layer type (def: first appropriate)\n");
  fprintf(output, "  -D                       print list of interfaces and exit\n");
  fprintf(output, "  -L                       print list of link-layer types of iface and exit\n");
  fprintf(output, "\n");
  fprintf(output, "Capture stop conditions:\n");
  fprintf(output, "  -c <packet count>        stop after n packets (def: infinite)\n");
  fprintf(output, "  -a <autostop cond.> ...  duration:NUM - stop after NUM seconds\n");
  fprintf(output, "                           filesize:NUM - stop this file after NUM KB\n");
  fprintf(output, "                              files:NUM - stop after NUM files\n");
  /*fprintf(output, "\n");*/
  fprintf(output, "Capture output:\n");
  fprintf(output, "  -b <ringbuffer opt.> ... duration:NUM - switch to next file after NUM secs\n");
  fprintf(output, "                           filesize:NUM - switch to next file after NUM KB\n");
  fprintf(output, "                              files:NUM - ringbuffer: replace after NUM files\n");
#endif  /* HAVE_LIBPCAP */

  /*fprintf(output, "\n");*/
  fprintf(output, "Input file:\n");
  fprintf(output, "  -r <infile>              set the filename to read from (no pipes or stdin!)\n");

  fprintf(output, "\n");
  fprintf(output, "Processing:\n");
  fprintf(output, "  -R <read filter>         packet filter in Wireshark display filter syntax\n");
  fprintf(output, "  -n                       disable all name resolutions (def: all enabled)\n");
  fprintf(output, "  -N <name resolve flags>  enable specific name resolution(s): \"mntC\"\n");

  fprintf(output, "\n");
  fprintf(output, "User interface:\n");
  fprintf(output, "  -g <packet number>       go to specified packet number after \"-r\"\n");
  fprintf(output, "  -m <font>                set the font name used for most text\n");
  fprintf(output, "  -t ad|a|r|d              output format of time stamps (def: r: rel. to first)\n");
  fprintf(output, "  -X <key>:<value>         eXtension options, see man page for details\n");
  fprintf(output, "  -z <statistics>          show various statistics, see man page for details\n");

  fprintf(output, "\n");
  fprintf(output, "Output:\n");
  fprintf(output, "  -w <outfile|->           set the output filename (or '-' for stdout)\n");

  fprintf(output, "\n");
  fprintf(output, "Miscellaneous:\n");
  fprintf(output, "  -h                       display this help and exit\n");
  fprintf(output, "  -v                       display version info and exit\n");
  fprintf(output, "  -o <name>:<value> ...    override preference or recent setting\n");
#ifndef _WIN32
  fprintf(output, "  --display=DISPLAY        X display to use\n");
#endif

#ifdef _WIN32
  destroy_console();
#endif
}

static void
show_version(void)
{
#ifdef _WIN32
  create_console();
#endif

  printf(PACKAGE " " VERSION "%s\n"
         "\n"
         "%s"
         "\n"
         "%s"
         "\n"
         "%s",
      svnversion, get_copyright_info(), comp_info_str->str,
      runtime_info_str->str);

#ifdef _WIN32
  destroy_console();
#endif
}

/*
 * Report an error in command-line arguments.
 * Creates a console on Windows.
 * XXX - pop this up in a window of some sort on UNIX+X11 if the controlling
 * terminal isn't the standard error?
 */
void
cmdarg_err(const char *fmt, ...)
{
  va_list ap;

#ifdef _WIN32
  create_console();
#endif
  va_start(ap, fmt);
  fprintf(stderr, "wireshark: ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}

/*
 * Report additional information for an error in command-line arguments.
 * Creates a console on Windows.
 * XXX - pop this up in a window of some sort on UNIX+X11 if the controlling
 * terminal isn't the standard error?
 */
void
cmdarg_err_cont(const char *fmt, ...)
{
  va_list ap;

#ifdef _WIN32
  create_console();
#endif
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}

#if defined(_WIN32) || GTK_MAJOR_VERSION < 2 || ! defined USE_THREADS
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

/* if these three functions are copied to gtk1 Wireshark, since gtk1 does not
   use threads all updte_thread_mutex can be dropped and protect/unprotect
   would just be empty functions.

   This allows gtk2-rpcstat.c and friends to be copied unmodified to
   gtk1-wireshark and it will just work.
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
#if !defined(_WIN32) && GTK_MAJOR_VERSION >= 2 && defined USE_THREADS
    g_static_mutex_lock(&update_thread_mutex);
#endif
}
void
unprotect_thread_critical_region(void)
{
#if !defined(_WIN32) && GTK_MAJOR_VERSION >= 2 && defined USE_THREADS
    g_static_mutex_unlock(&update_thread_mutex);
#endif
}

/* Set the file name in the status line, in the name for the main window,
   and in the name for the main window's icon. */
static void
set_display_filename(capture_file *cf)
{
  const gchar *name_ptr;
  gchar       *status_msg;
  gchar       *size_str;
  gchar       *win_name;

  name_ptr = cf_get_display_name(cf);

  if (!cf->is_tempfile && cf->filename) {
    /* Add this filename to the list of recent files in the "Recent Files" submenu */
    add_menu_recent_capture_file(cf->filename);
  }

  /* convert file size */
  if (cf->f_datalen/1024/1024 > 10) {
    size_str = g_strdup_printf("%ld MB", cf->f_datalen/1024/1024);
  } else if (cf->f_datalen/1024 > 10) {
    size_str = g_strdup_printf("%ld KB", cf->f_datalen/1024);
  } else {
    size_str = g_strdup_printf("%ld Bytes", cf->f_datalen);
  }

  /* statusbar */
#if 0
  /* XXX - don't show the highest expert level unless the TCP checksum offloading is "solved" */
  status_msg = g_strdup_printf(" File: \"%s\" %s %02lu:%02lu:%02lu [Expert: %s]",
    (cf->filename) ? cf->filename : "", size_str,
    (long)cf->elapsed_time.secs/3600,
    (long)cf->elapsed_time.secs%3600/60,
    (long)cf->elapsed_time.secs%60,
    val_to_str(expert_get_highest_severity(), expert_severity_vals, "Unknown (%u)"));
#endif
  status_msg = g_strdup_printf(" File: \"%s\" %s %02lu:%02lu:%02lu",
    (cf->filename) ? cf->filename : "", size_str,
    (long)cf->elapsed_time.secs/3600,
    (long)cf->elapsed_time.secs%3600/60,
    (long)cf->elapsed_time.secs%60);
  g_free(size_str);
  statusbar_push_file_msg(status_msg);
  g_free(status_msg);

  /* window title */
  win_name = g_strdup_printf("%s - Wireshark", name_ptr);
  set_main_window_name(win_name);
  g_free(win_name);
}

GtkWidget           *close_dlg = NULL;

static void
main_cf_cb_file_closing(capture_file *cf)
{

	/* if we have more than 10000 packets, show a splash screen while closing */
	/* XXX - don't know a better way to decide wether to show or not,
	 * as most of the time is spend in a single eth_clist_clear function,
	 * so we can't use a progress bar here! */
	if(cf->count > 10000) {
		close_dlg = simple_dialog(ESD_TYPE_STOP, ESD_BTN_NONE, "%sClosing file!%s\n\nPlease wait ...",
			simple_dialog_primary_start(), simple_dialog_primary_end());
#if GTK_MAJOR_VERSION >= 2
		gtk_window_set_position(GTK_WINDOW(close_dlg), GTK_WIN_POS_CENTER_ON_PARENT);
#else
		gtk_window_set_position(GTK_WINDOW(close_dlg), GTK_WIN_POS_CENTER);
#endif
	}

    /* Destroy all windows, which refer to the
       capture file we're closing. */
    destroy_packet_wins();
    file_save_as_destroy();

    /* Clear any file-related status bar messages.
       XXX - should be "clear *ALL* file-related status bar messages;
       will there ever be more than one on the stack? */
    statusbar_pop_file_msg();

    /* Restore the standard title bar message. */
    set_main_window_name("The Wireshark Network Analyzer");

    /* Disable all menu items that make sense only if you have a capture. */
    set_menus_for_capture_file(FALSE);
    set_menus_for_unsaved_capture_file(FALSE);
    set_menus_for_captured_packets(FALSE);
    set_menus_for_selected_packet(cf);
    set_menus_for_capture_in_progress(FALSE);
    set_menus_for_selected_tree_row(cf);

    /* Set up main window for no capture file. */
    main_set_for_capture_file(FALSE);

    main_window_update();
}

static void
main_cf_cb_file_closed(capture_file *cf _U_)
{
  if(close_dlg != NULL) {
    splash_destroy(close_dlg);
    close_dlg = NULL;
  }

  /* go back to "No packets" */
  packets_bar_update();
}

static void
main_cf_cb_file_read_start(capture_file *cf)
{
  const gchar *name_ptr;
  gchar       *load_msg;

  name_ptr = get_basename(cf->filename);

  load_msg = g_strdup_printf(" Loading: %s", name_ptr);
  statusbar_push_file_msg(load_msg);
  g_free(load_msg);
}

static void
main_cf_cb_file_read_finished(capture_file *cf)
{
    statusbar_pop_file_msg();
    set_display_filename(cf);

    /* Enable menu items that make sense if you have a capture file you've
     finished reading. */
    set_menus_for_capture_file(TRUE);
    set_menus_for_unsaved_capture_file(!cf->user_saved);

    /* Enable menu items that make sense if you have some captured packets. */
    set_menus_for_captured_packets(TRUE);

    /* Set up main window for a capture file. */
    main_set_for_capture_file(TRUE);
}

#if GTK_MAJOR_VERSION >= 2
GList *icon_list_create(
    const char **icon16_xpm,
    const char **icon32_xpm,
    const char **icon48_xpm,
    const char **icon64_xpm)
{
  GList *icon_list = NULL;
  GdkPixbuf * pixbuf16;
  GdkPixbuf * pixbuf32;
  GdkPixbuf * pixbuf48;
  GdkPixbuf * pixbuf64;


  if(icon16_xpm != NULL) {
      pixbuf16 = gdk_pixbuf_new_from_xpm_data(icon16_xpm);
      g_assert(pixbuf16);
      icon_list = g_list_append(icon_list, pixbuf16);
  }

  if(icon32_xpm != NULL) {
      pixbuf32 = gdk_pixbuf_new_from_xpm_data(icon32_xpm);
      g_assert(pixbuf32);
      icon_list = g_list_append(icon_list, pixbuf32);
  }

  if(icon48_xpm != NULL) {
      pixbuf48 = gdk_pixbuf_new_from_xpm_data(icon48_xpm);
      g_assert(pixbuf48);
      icon_list = g_list_append(icon_list, pixbuf48);
  }

  if(icon64_xpm != NULL) {
      pixbuf64 = gdk_pixbuf_new_from_xpm_data(icon64_xpm);
      g_assert(pixbuf64);
      icon_list = g_list_append(icon_list, pixbuf64);
  }

  return icon_list;
}
#endif

#ifdef HAVE_LIBPCAP
static void
main_cf_cb_live_capture_prepared(capture_options *capture_opts)
{
    gchar *title;
#if GTK_MAJOR_VERSION >= 2
    static GList *icon_list = NULL;
#endif


    if(capture_opts->iface) {
        title = g_strdup_printf("%s: Capturing - Wireshark",
                            get_interface_descriptive_name(capture_opts->iface));
    } else {
        title = g_strdup_printf("Capturing - Wireshark");
    }
    set_main_window_name(title);
    g_free(title);

#if GTK_MAJOR_VERSION >= 2
    if(icon_list == NULL) {
        icon_list = icon_list_create(wsiconcap16_xpm, wsiconcap32_xpm, wsiconcap48_xpm, NULL);
    }
    gtk_window_set_icon_list(GTK_WINDOW(top_level), icon_list);
#endif

    /* Disable menu items that make no sense if you're currently running
       a capture. */
    set_menus_for_capture_in_progress(TRUE);

    /* update statusbar */
    statusbar_push_file_msg("Waiting for capture input data ...");

    /* Don't set up main window for a capture file. */
    main_set_for_capture_file(FALSE);
}

static void
main_cf_cb_live_capture_update_started(capture_options *capture_opts)
{
    gchar *capture_msg;
    gchar *title;

    /* We've done this in "prepared" above, but it will be cleared while
       switching to the next multiple file. */
    if(capture_opts->iface) {
        title = g_strdup_printf("%s: Capturing - Wireshark",
                            get_interface_descriptive_name(capture_opts->iface));
    } else {
        title = g_strdup_printf("Capturing - Wireshark");
    }
    set_main_window_name(title);
    g_free(title);

    set_menus_for_capture_in_progress(TRUE);

    /* Enable menu items that make sense if you have some captured
       packets (yes, I know, we don't have any *yet*). */
    set_menus_for_captured_packets(TRUE);

    statusbar_pop_file_msg();

    if(capture_opts->iface) {
        capture_msg = g_strdup_printf(" %s: <live capture in progress> to file: %s",
            get_interface_descriptive_name(capture_opts->iface),
            (capture_opts->save_file) ? capture_opts->save_file : "");
    } else {
        capture_msg = g_strdup_printf(" <live capture in progress> to file: %s",
            (capture_opts->save_file) ? capture_opts->save_file : "");
    }

    statusbar_push_file_msg(capture_msg);

    g_free(capture_msg);

    /* Set up main window for a capture file. */
    main_set_for_capture_file(TRUE);
}

static void
main_cf_cb_live_capture_update_continue(capture_file *cf)
{
    gchar *capture_msg;


    statusbar_pop_file_msg();

#if 0
    /* XXX - don't show the highest expert level unless the TCP checksum offloading is "solved" */
    if (cf->f_datalen/1024/1024 > 10) {
        capture_msg = g_strdup_printf(" %s: <live capture in progress> File: %s %ld MB [Expert: %s]",
            get_interface_descriptive_name(capture_opts->iface),
            capture_opts->save_file,
            cf->f_datalen/1024/1024,
            val_to_str(expert_get_highest_severity(), expert_severity_vals, "Unknown (%u)"));
    } else if (cf->f_datalen/1024 > 10) {
        capture_msg = g_strdup_printf(" %s: <live capture in progress> File: %s %ld KB [Expert: %s]",
            get_interface_descriptive_name(capture_opts->iface),
            capture_opts->save_file,
            cf->f_datalen/1024,
            val_to_str(expert_get_highest_severity(), expert_severity_vals, "Unknown (%u)"));
    } else {
        capture_msg = g_strdup_printf(" %s: <live capture in progress> File: %s %ld Bytes [Expert: %s]",
            get_interface_descriptive_name(capture_opts->iface),
            capture_opts->save_file,
            cf->f_datalen,
            val_to_str(expert_get_highest_severity(), expert_severity_vals, "Unknown (%u)"));
    }
#endif
    if (cf->f_datalen/1024/1024 > 10) {
        capture_msg = g_strdup_printf(" %s: <live capture in progress> File: %s %ld MB",
            get_interface_descriptive_name(capture_opts->iface),
            capture_opts->save_file,
            cf->f_datalen/1024/1024);
    } else if (cf->f_datalen/1024 > 10) {
        capture_msg = g_strdup_printf(" %s: <live capture in progress> File: %s %ld KB",
            get_interface_descriptive_name(capture_opts->iface),
            capture_opts->save_file,
            cf->f_datalen/1024);
    } else {
        capture_msg = g_strdup_printf(" %s: <live capture in progress> File: %s %ld Bytes",
            get_interface_descriptive_name(capture_opts->iface),
            capture_opts->save_file,
            cf->f_datalen);
    }

    statusbar_push_file_msg(capture_msg);
}

GtkWidget * stop_dlg = NULL;

static void
main_cf_cb_live_capture_update_finished(capture_file *cf)
{
#if GTK_MAJOR_VERSION >= 2
    static GList *icon_list = NULL;
#endif

    if(stop_dlg != NULL) {
		simple_dialog_close(stop_dlg);
		stop_dlg = NULL;
	}

    /* Pop the "<live capture in progress>" message off the status bar. */
    statusbar_pop_file_msg();

    set_display_filename(cf);

    /* Enable menu items that make sense if you're not currently running
     a capture. */
    set_menus_for_capture_in_progress(FALSE);

    /* Enable menu items that make sense if you have a capture file
     you've finished reading. */
    set_menus_for_capture_file(TRUE);
    set_menus_for_unsaved_capture_file(!cf->user_saved);

    /* Set up main window for a capture file. */
    main_set_for_capture_file(TRUE);

#if GTK_MAJOR_VERSION >= 2
    if(icon_list == NULL) {
        icon_list = icon_list_create(wsicon16_xpm, wsicon32_xpm, wsicon48_xpm, wsicon64_xpm);
    }
    gtk_window_set_icon_list(GTK_WINDOW(top_level), icon_list);
#endif

    if(capture_opts->quit_after_cap) {
        /* command line asked us to quit after the capture */
        /* don't pop up a dialog to ask for unsaved files etc. */
        main_do_quit();
    }
}

static void
main_cf_cb_live_capture_fixed_started(capture_options *capture_opts)
{
    gchar *capture_msg;


    /* Enable menu items that make sense if you have some captured
       packets (yes, I know, we don't have any *yet*). */
    /*set_menus_for_captured_packets(TRUE);*/

    statusbar_pop_file_msg();

    capture_msg = g_strdup_printf(" %s: <live capture in progress> to file: %s",
        get_interface_descriptive_name(capture_opts->iface),
        (capture_opts->save_file) ? capture_opts->save_file : "");

    statusbar_push_file_msg(capture_msg);
    gtk_statusbar_push(GTK_STATUSBAR(packets_bar), packets_ctx, " P: 0");

    g_free(capture_msg);

    /* Don't set up main window for a capture file. */
    main_set_for_capture_file(FALSE);
}

static void
main_cf_cb_live_capture_fixed_continue(capture_file *cf)
{
    gchar *capture_msg;


	gtk_statusbar_pop(GTK_STATUSBAR(packets_bar), packets_ctx);

    capture_msg = g_strdup_printf(" P: %u",
        cf_get_packet_count(cf));

    gtk_statusbar_push(GTK_STATUSBAR(packets_bar), packets_ctx, capture_msg);

    g_free(capture_msg);
}

static void
main_cf_cb_live_capture_fixed_finished(capture_file *cf _U_)
{
#if GTK_MAJOR_VERSION >= 2
    static GList *icon_list = NULL;
#endif

    if(stop_dlg != NULL) {
		simple_dialog_close(stop_dlg);
		stop_dlg = NULL;
	}

    /* Pop the "<live capture in progress>" message off the status bar. */
    statusbar_pop_file_msg();

    /* Pop the "<capturing>" message off the status bar */
	gtk_statusbar_pop(GTK_STATUSBAR(packets_bar), packets_ctx);

    /*set_display_filename(cf);*/

    /* Enable menu items that make sense if you're not currently running
     a capture. */
    set_menus_for_capture_in_progress(FALSE);

    /* Restore the standard title bar message */
    /* (just in case we have trouble opening the capture file). */
    set_main_window_name("The Wireshark Network Analyzer");

#if GTK_MAJOR_VERSION >= 2
    if(icon_list == NULL) {
        icon_list = icon_list_create(wsicon16_xpm, wsicon32_xpm, wsicon48_xpm, wsicon64_xpm);
    }
    gtk_window_set_icon_list(GTK_WINDOW(top_level), icon_list);
#endif

    /* We don't have loaded the capture file, this will be done later.
     * For now we still have simply a blank screen. */

    if(capture_opts->quit_after_cap) {
        /* command line asked us to quit after the capture */
        /* don't pop up a dialog to ask for unsaved files etc. */
        main_do_quit();
    }
}

static void
main_cf_cb_live_capture_stopping(capture_file *cf _U_)
{
    /* Beware: this state won't be called, if the capture child
     * closes the capturing on it's own! */
#if 0
	/* XXX - the time to stop the capture has been reduced (this was only a
	 * problem on Win32 because of the capture piping), so showing a splash
	 * isn't really necessary any longer. Unfortunately, the GTKClist packet
	 * list seems to have problems updating after the dialog is closed, so
	 * this was disabled here. */
    stop_dlg = simple_dialog(ESD_TYPE_STOP, ESD_BTN_NONE, "%sCapture stop!%s\n\nPlease wait ...",
		simple_dialog_primary_start(), simple_dialog_primary_end());
#if GTK_MAJOR_VERSION >= 2
	gtk_window_set_position(GTK_WINDOW(stop_dlg), GTK_WIN_POS_CENTER_ON_PARENT);
#else
	gtk_window_set_position(GTK_WINDOW(stop_dlg), GTK_WIN_POS_CENTER);
#endif
#endif
}

#endif

static void
main_cf_cb_packet_selected(gpointer data)
{
    capture_file *cf = data;

    /* Display the GUI protocol tree and hex dump.
      XXX - why do we dump core if we call "proto_tree_draw()"
      before calling "add_byte_views()"? */
    add_main_byte_views(cf->edt);
    main_proto_tree_draw(cf->edt->tree);

    /* A packet is selected. */
    set_menus_for_selected_packet(cf);
}

static void
main_cf_cb_packet_unselected(capture_file *cf)
{
    /* Clear out the display of that packet. */
    clear_tree_and_hex_views();

    /* No packet is selected. */
    set_menus_for_selected_packet(cf);
}

static void
main_cf_cb_field_unselected(capture_file *cf)
{
    statusbar_pop_field_msg();
    set_menus_for_selected_tree_row(cf);
}

static void
main_cf_cb_file_safe_started(gchar * filename)
{
    const gchar  *name_ptr;
    gchar        *save_msg;

    name_ptr = get_basename(filename);

    save_msg = g_strdup_printf(" Saving: %s...", name_ptr);

    statusbar_push_file_msg(save_msg);
    g_free(save_msg);
}

static void
main_cf_cb_file_safe_finished(gpointer data _U_)
{
    /* Pop the "Saving:" message off the status bar. */
    statusbar_pop_file_msg();
}

static void
main_cf_cb_file_safe_failed(gpointer data _U_)
{
    /* Pop the "Saving:" message off the status bar. */
    statusbar_pop_file_msg();
}

static void
main_cf_cb_file_safe_reload_finished(gpointer data _U_)
{
    set_menus_for_unsaved_capture_file(FALSE);
}

static void main_cf_callback(gint event, gpointer data, gpointer user_data _U_)
{
    switch(event) {
    case(cf_cb_file_closing):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Closing");
        main_cf_cb_file_closing(data);
        break;
    case(cf_cb_file_closed):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Closed");
        main_cf_cb_file_closed(data);
        break;
    case(cf_cb_file_read_start):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read start");
        main_cf_cb_file_read_start(data);
        break;
    case(cf_cb_file_read_finished):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read finished");
        main_cf_cb_file_read_finished(data);
        break;
#ifdef HAVE_LIBPCAP
    case(cf_cb_live_capture_prepared):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture prepared");
        main_cf_cb_live_capture_prepared(data);
        break;
    case(cf_cb_live_capture_update_started):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update started");
        main_cf_cb_live_capture_update_started(data);
        break;
    case(cf_cb_live_capture_update_continue):
		/*g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update continue");*/
        main_cf_cb_live_capture_update_continue(data);
        break;
    case(cf_cb_live_capture_update_finished):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update finished");
        main_cf_cb_live_capture_update_finished(data);
        break;
    case(cf_cb_live_capture_fixed_started):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed started");
        main_cf_cb_live_capture_fixed_started(data);
        break;
    case(cf_cb_live_capture_fixed_continue):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update continue");
        main_cf_cb_live_capture_fixed_continue(data);
        break;
    case(cf_cb_live_capture_fixed_finished):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed finished");
        main_cf_cb_live_capture_fixed_finished(data);
        break;
    case(cf_cb_live_capture_stopping):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture stopping");
        main_cf_cb_live_capture_stopping(data);
        break;
#endif
    case(cf_cb_packet_selected):
        main_cf_cb_packet_selected(data);
        break;
    case(cf_cb_packet_unselected):
        main_cf_cb_packet_unselected(data);
        break;
    case(cf_cb_field_unselected):
        main_cf_cb_field_unselected(data);
        break;
    case(cf_cb_file_safe_started):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: safe started");
        main_cf_cb_file_safe_started(data);
        break;
    case(cf_cb_file_safe_finished):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: safe finished");
        main_cf_cb_file_safe_finished(data);
        break;
    case(cf_cb_file_safe_reload_finished):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: reload finished");
        main_cf_cb_file_safe_reload_finished(data);
        break;
    case(cf_cb_file_safe_failed):
		g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: safe failed");
        main_cf_cb_file_safe_failed(data);
        break;
    default:
        g_warning("main_cf_callback: event %u unknown", event);
        g_assert_not_reached();
    }
}

static void
get_epan_and_portaudio_version_info(GString *str)
{
  get_epan_compiled_version_info(str);

#ifdef HAVE_LIBPORTAUDIO
  g_string_append(str, ", ");
#ifdef PORTAUDIO_API_1
  g_string_append(str, "with PortAudio <= V18");
#else /* PORTAUDIO_API_1 */
  g_string_append(str, "with PortAudio ");
  g_string_append(str, Pa_GetVersionText());
#endif /* PORTAUDIO_API_1 */
#else /* HAVE_LIBPORTAUDIO */
  g_string_append(str, "without PortAudio");
#endif /* HAVE_LIBPORTAUDIO */
}

/* And now our feature presentation... [ fade to music ] */
int
main(int argc, char *argv[])
{
  char                *init_progfile_dir_error;
  char                *s;
  int                  i;
  int                  opt;
  extern char         *optarg;
  gboolean             arg_error = FALSE;

#ifdef _WIN32
  WSADATA 	       wsaData;
#endif  /* _WIN32 */

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
#else
  gboolean             capture_option_specified = FALSE;
#endif
  gint                 pl_size = 280, tv_size = 95, bv_size = 75;
  gchar               *rc_file, *cf_name = NULL, *rfilter = NULL;
  dfilter_t           *rfcode = NULL;
  gboolean             rfilter_parse_failed = FALSE;
  e_prefs             *prefs;
  char                 badopt;
  GtkWidget           *splash_win = NULL;
  GLogLevelFlags       log_flags;
  guint                go_to_packet = 0;
  int                  optind_initial;
  int                  status;

#ifdef HAVE_AIRPCAP
  char			err_str[AIRPCAP_ERRBUF_SIZE];
  gchar			*cant_get_if_list_errstr;
#endif

#define OPTSTRING_INIT "a:b:c:Df:g:Hhi:klLm:nN:o:pQr:R:Ss:t:vw:X:y:z:"

#if defined HAVE_LIBPCAP && defined _WIN32
#define OPTSTRING_WIN32 "B:"
#else
#define OPTSTRING_WIN32 ""
#endif

  char optstring[sizeof(OPTSTRING_INIT) + sizeof(OPTSTRING_WIN32) - 1] =
    OPTSTRING_INIT OPTSTRING_WIN32;

  /*
   * Attempt to get the pathname of the executable file.
   */
  init_progfile_dir_error = init_progfile_dir(argv[0]);

  /*
   * Get credential information for later use.
   */
  get_credential_info();

  /* initialize memory allocation subsystem */
  ep_init_chunk();
  se_init_chunk();

  /* initialize the GUID to name mapping table */
  guids_init();

  /* initialize the funnel mini-api */
  initialize_funnel_ops();

#ifdef _WIN32
  /* Load wpcap if possible. Do this before collecting the run-time version information */
  load_wpcap();

  /* ... and also load the packet.dll from wpcap */
  wpcap_packet_load();

  /* Start windows sockets */
  WSAStartup( MAKEWORD( 1, 1 ), &wsaData );
#endif  /* _WIN32 */

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

  get_compiled_version_info(comp_info_str, get_epan_and_portaudio_version_info);

  /* Assemble the run-time version information string */
  runtime_info_str = g_string_new("Running ");
  get_runtime_version_info(runtime_info_str);


  /* "pre-scan" the command line parameters, if we have "console only"
     parameters.  We do this so we don't start GTK+ if we're only showing
     command-line help or version information.

     XXX - this pre-scan is doen before we start GTK+, so we haven't
     run gtk_init() on the arguments.  That means that GTK+ arguments
     have not been removed from the argument list; those arguments
     begin with "--", and will be treated as an error by getopt().

     We thus ignore errors - *and* set "opterr" to 0 to suppress the
     error messages. */
  opterr = 0;
  optind_initial = optind;
  while ((opt = getopt(argc, argv, optstring)) != -1) {
    switch (opt) {
      case 'h':        /* Print help and exit */
        print_usage(TRUE);
        exit(0);
        break;
      case 'v':        /* Show version and exit */
        show_version();
        exit(0);
        break;
      case 'X':
          /*
           *  Extension command line options have to be processed before
           *  we call epan_init() as they are supposed to be used by dissectors
           *  or taps very early in the registration process.
           */
          ex_opt_add(optarg);
          break;
      case '?':        /* Ignore errors - the "real" scan will catch them. */
        break;
    }
  }

  /* Set getopt index back to initial value, so it will start with the
     first command line parameter again.  Also reset opterr to 1, so that
     error messages are printed by getopt().

     XXX - this seems to work on most platforms, but time will tell.
     The Single UNIX Specification says "The getopt() function need
     not be reentrant", so this isn't guaranteed to work.  The Mac
     OS X 10.4[.x] getopt() man page says

       In order to use getopt() to evaluate multiple sets of arguments, or to
       evaluate a single set of arguments multiple times, the variable optreset
       must be set to 1 before the second and each additional set of calls to
       getopt(), and the variable optind must be reinitialized.

           ...

       The optreset variable was added to make it possible to call the getopt()
       function multiple times.  This is an extension to the IEEE Std 1003.2
       (``POSIX.2'') specification.

     which I think comes from one of the other BSDs.

     XXX - if we want to control all the command-line option errors, so
     that we can display them where we choose (e.g., in a window), we'd
     want to leave opterr as 0, and produce our own messages using optopt.
     We'd have to check the value of optopt to see if it's a valid option
     letter, in which case *presumably* the error is "this option requires
     an argument but none was specified", or not a valid option letter,
     in which case *presumably* the error is "this option isn't valid".
     Some versions of getopt() let you supply a option string beginning
     with ':', which means that getopt() will return ':' rather than '?'
     for "this option requires an argument but none was specified", but
     not all do. */
  optind = optind_initial;
  opterr = 1;

  /* Set the current locale according to the program environment.
   * We haven't localized anything, but some GTK widgets are localized
   * (the file selection dialogue, for example).
   * This also sets the C-language locale to the native environment. */
  gtk_set_locale();

  /* Let GTK get its args (will need an X server, so do this after command line only commands handled) */
  gtk_init (&argc, &argv);

  cf_callback_add(main_cf_callback, NULL);

#if GTK_MAJOR_VERSION < 2 && GTK_MINOR_VERSION < 3
  /* initialize our GTK eth_clist_type */
  init_eth_clist_type();
#endif

  /* Arrange that if we have no console window, and a GLib message logging
     routine is called to log a message, we pop up a console window.

     We do that by inserting our own handler for all messages logged
     to the default domain; that handler pops up a console if necessary,
     and then calls the default handler. */

  /* We might want to have component specific log levels later ... */

  log_flags =
		    G_LOG_LEVEL_ERROR|
		    G_LOG_LEVEL_CRITICAL|
		    G_LOG_LEVEL_WARNING|
		    G_LOG_LEVEL_MESSAGE|
		    G_LOG_LEVEL_INFO|
		    G_LOG_LEVEL_DEBUG|
		    G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION;

  g_log_set_handler(NULL,
		    log_flags,
		    console_log_handler, NULL /* user_data */);
  g_log_set_handler(LOG_DOMAIN_MAIN,
		    log_flags,
		    console_log_handler, NULL /* user_data */);

#ifdef HAVE_LIBPCAP
  g_log_set_handler(LOG_DOMAIN_CAPTURE,
		    log_flags,
		    console_log_handler, NULL /* user_data */);
  g_log_set_handler(LOG_DOMAIN_CAPTURE_CHILD,
		    log_flags,
		    console_log_handler, NULL /* user_data */);

  /* Set the initial values in the capture_opts. This might be overwritten
     by preference settings and then again by the command line parameters. */
  capture_opts_init(capture_opts, &cfile);

  capture_opts->snaplen             = MIN_PACKET_SIZE;
  capture_opts->has_ring_num_files  = TRUE;
#endif

  /* We won't come till here, if we had a "console only" command line parameter. */
  splash_win = splash_new("Loading Wireshark ...");
  if (init_progfile_dir_error != NULL) {
    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Can't get pathname of Wireshark: %s.\n"
        "It won't be possible to capture traffic.\n"
        "Report this to the Wireshark developers.",
        init_progfile_dir_error);
    g_free(init_progfile_dir_error);
  }

  splash_update(splash_win, "Init dissectors ...");

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps information registered by the
     dissectors, and we must do it before we read the preferences, in
     case any dissectors register preferences. */
  epan_init(PLUGIN_DIR,register_all_protocols,register_all_protocol_handoffs,
            failure_alert_box,open_failure_alert_box,read_failure_alert_box);

  splash_update(splash_win, "Init tap listeners ...");

  /* Register all tap listeners; we do this before we parse the arguments,
     as the "-z" argument can specify a registered tap. */

  /* we register the plugin taps before the other taps because
	  stats_tree taps plugins will be registered as tap listeners
	  by stats_tree_stat.c and need to registered before that */

#ifdef HAVE_PLUGINS
  register_all_plugin_tap_listeners();
#endif

  register_all_tap_listeners();

  splash_update(splash_win, "Loading module preferences ...");

  /* Now register the preferences for any non-dissector modules.
     We must do that before we read the preferences as well. */
  prefs_register_modules();

  /* multithread support currently doesn't seem to work in win32 gtk2.0.6 */
#if !defined(_WIN32) && GTK_MAJOR_VERSION >= 2 && defined(G_THREADS_ENABLED) && defined USE_THREADS
  {
      GThread *ut;
      g_thread_init(NULL);
      gdk_threads_init();
      ut=g_thread_create(update_thread, NULL, FALSE, NULL);
      g_thread_set_priority(ut, G_THREAD_PRIORITY_LOW);
  }
#else  /* _WIN32 || GTK1.2 || !G_THREADS_ENABLED || !USE_THREADS */
  /* this is to keep tap extensions updating once every 3 seconds */
  gtk_timeout_add(3000, (GtkFunction)update_cb,(gpointer)NULL);
#endif /* !_WIN32 && GTK2 && G_THREADS_ENABLED */

#if HAVE_GNU_ADNS
  gtk_timeout_add(750, (GtkFunction) host_name_lookup_process, NULL);
#endif

  splash_update(splash_win, "Loading configuration files ...");

  /* Read the preference files. */
  prefs = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
                     &pf_open_errno, &pf_read_errno, &pf_path);

#ifdef HAVE_AIRPCAP
   /* Load the airpcap.dll */
  if(load_airpcap())
	{
	/* load the airpcap interfaces */
	airpcap_if_list = get_airpcap_interface_list(&err, err_str);

	if (airpcap_if_list == NULL && err == CANT_GET_AIRPCAP_INTERFACE_LIST) {
    cant_get_if_list_errstr = cant_get_airpcap_if_list_error_message(err_str);
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s",
                  cant_get_if_list_errstr);
    g_free(cant_get_if_list_errstr);
	}

	/* select the first ad default (THIS SHOULD BE CHANGED) */
	airpcap_if_active = airpcap_get_default_if(airpcap_if_list);
	}
#endif

  if (gpf_path != NULL) {
    if (gpf_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open global preferences file\n\"%s\": %s.", gpf_path,
        strerror(gpf_open_errno));
    }
    if (gpf_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "I/O error reading global preferences file\n\"%s\": %s.", gpf_path,
        strerror(gpf_read_errno));
    }
  }
  if (pf_path != NULL) {
    if (pf_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open your preferences file\n\"%s\": %s.", pf_path,
        strerror(pf_open_errno));
    }
    if (pf_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "I/O error reading your preferences file\n\"%s\": %s.", pf_path,
        strerror(pf_read_errno));
    }
    g_free(pf_path);
    pf_path = NULL;
  }

#ifdef _WIN32
  /* if the user wants a console to be always there, well, we should open one for him */
  if (prefs->gui_console_open == console_open_always) {
    create_console();
  }
#endif

#ifdef HAVE_LIBPCAP
  /* Set promiscuous mode from the preferences setting. */
  /* the same applies to other preferences settings as well. */
    capture_opts->promisc_mode   = prefs->capture_prom_mode;
    capture_opts->show_info      = prefs->capture_show_info;
    capture_opts->real_time_mode = prefs->capture_real_time;
    auto_scroll_live             = prefs->capture_auto_scroll;
#endif /* HAVE_LIBPCAP */

  /* Set the name resolution code's flags from the preferences. */
  g_resolv_flags = prefs->name_resolve;

  /* Read the capture filter file. */
  read_filter_list(CFILTER_LIST, &cf_path, &cf_open_errno);
  if (cf_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open your capture filter file\n\"%s\": %s.", cf_path,
        strerror(cf_open_errno));
      g_free(cf_path);
  }

  /* Read the display filter file. */
  read_filter_list(DFILTER_LIST, &df_path, &df_open_errno);
  if (df_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open your display filter file\n\"%s\": %s.", df_path,
        strerror(df_open_errno));
      g_free(df_path);
  }

  /* Read the disabled protocols file. */
  read_disabled_protos_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
			    &dp_path, &dp_open_errno, &dp_read_errno);
  if (gdp_path != NULL) {
    if (gdp_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open global disabled protocols file\n\"%s\": %s.",
	gdp_path, strerror(gdp_open_errno));
    }
    if (gdp_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "I/O error reading global disabled protocols file\n\"%s\": %s.",
	gdp_path, strerror(gdp_read_errno));
    }
    g_free(gdp_path);
  }
  if (dp_path != NULL) {
    if (dp_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open your disabled protocols file\n\"%s\": %s.", dp_path,
        strerror(dp_open_errno));
    }
    if (dp_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "I/O error reading your disabled protocols file\n\"%s\": %s.", dp_path,
        strerror(dp_read_errno));
    }
    g_free(dp_path);
  }

  /* Read the (static part) of the recent file. Only the static part of it will be read, */
  /* as we don't have the gui now to fill the recent lists which is done in the dynamic part. */
  /* We have to do this already here, so command line parameters can overwrite these values. */
  recent_read_static(&rf_path, &rf_open_errno);

  init_cap_file(&cfile);

  /* Now get our args */
  while ((opt = getopt(argc, argv, optstring)) != -1) {
    switch (opt) {
      /*** capture option specific ***/
      case 'a':        /* autostop criteria */
      case 'b':        /* Ringbuffer option */
      case 'c':        /* Capture xxx packets */
      case 'f':        /* capture filter */
      case 'k':        /* Start capture immediately */
      case 'H':        /* Hide capture info dialog box */
      case 'i':        /* Use interface xxx */
      case 'p':        /* Don't capture in promiscuous mode */
      case 'Q':        /* Quit after capture (just capture to file) */
      case 's':        /* Set the snapshot (capture) length */
      case 'S':        /* "Sync" mode: used for following file ala tail -f */
      case 'w':        /* Write to capture file xxx */
      case 'y':        /* Set the pcap data link type */
#ifdef _WIN32
      case 'B':        /* Buffer size */
#endif /* _WIN32 */
#ifdef HAVE_LIBPCAP
        status = capture_opts_add_opt(capture_opts, opt, optarg, &start_capture);
        if(status != 0) {
            exit(status);
        }
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;

      /*** all non capture option specific ***/
      case 'D':        /* Print a list of capture devices and exit */
#ifdef HAVE_LIBPCAP
        capture_opts_list_interfaces();
        exit(0);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'g':        /* Go to packet */
        go_to_packet = get_positive_int(optarg, "go to packet");
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
          cmdarg_err("-N specifies unknown resolving option '%c'; valid options are 'm', 'n', and 't'",
			badopt);
          exit(1);
        }
        break;
      case 'o':        /* Override preference from command line */
        switch (prefs_set_pref(optarg)) {
        case PREFS_SET_OK:
          break;
        case PREFS_SET_SYNTAX_ERR:
          cmdarg_err("Invalid -o flag \"%s\"", optarg);
          exit(1);
          break;
        case PREFS_SET_NO_SUCH_PREF:
          /* not a preference, might be a recent setting */
          switch (recent_set_arg(optarg)) {
            case PREFS_SET_OK:
              break;
            case PREFS_SET_SYNTAX_ERR:
              /* shouldn't happen, checked already above */
              cmdarg_err("Invalid -o flag \"%s\"", optarg);
              exit(1);
              break;
            case PREFS_SET_NO_SUCH_PREF:
            case PREFS_SET_OBSOLETE:
              cmdarg_err("-o flag \"%s\" specifies unknown preference/recent value",
	            optarg);
              exit(1);
              break;
            default:
              g_assert_not_reached();
            }
          break;
        case PREFS_SET_OBSOLETE:
          cmdarg_err("-o flag \"%s\" specifies obsolete preference",
			optarg);
          exit(1);
          break;
        default:
          g_assert_not_reached();
        }
        break;
      case 'r':        /* Read capture file xxx */
	/* We may set "last_open_dir" to "cf_name", and if we change
	   "last_open_dir" later, we free the old value, so we have to
	   set "cf_name" to something that's been allocated. */
#if defined _WIN32 && (GLIB_MAJOR_VERSION > 2 || (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION >= 6))
        /* since GLib 2.6, we need to convert filenames to utf8 for Win32 */
        cf_name = g_locale_to_utf8(optarg, -1, NULL, NULL, NULL);
#else
        cf_name = g_strdup(optarg);
#endif
        break;
      case 'R':        /* Read file filter */
        rfilter = optarg;
        break;
      case 't':        /* Time stamp type */
        if (strcmp(optarg, "r") == 0)
          timestamp_set_type(TS_RELATIVE);
        else if (strcmp(optarg, "a") == 0)
          timestamp_set_type(TS_ABSOLUTE);
        else if (strcmp(optarg, "ad") == 0)
          timestamp_set_type(TS_ABSOLUTE_WITH_DATE);
        else if (strcmp(optarg, "d") == 0)
          timestamp_set_type(TS_DELTA);
        else {
          cmdarg_err("Invalid time stamp type \"%s\"", optarg);
          cmdarg_err_cont("It must be \"r\" for relative, \"a\" for absolute,");
          cmdarg_err_cont("\"ad\" for absolute with date, or \"d\" for delta.");
          exit(1);
        }
        break;
      case 'X':
          /* ext ops were already processed just ignore them this time*/
          break;
      case 'z':
        /* We won't call the init function for the stat this soon
           as it would disallow MATE's fields (which are registered
           by the preferences set callback) from being used as
           part of a tap filter.  Instead, we just add the argument
           to a list of stat arguments. */
        if (!process_stat_cmd_arg(optarg)) {
	  cmdarg_err("Invalid -z argument.");
	  cmdarg_err_cont("  -z argument must be one of :");
	  list_stat_cmd_args();
	  exit(1);
	}
        break;
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
      cmdarg_err("File name specified both with -r and regular argument");
      arg_error = TRUE;
    } else {
      /*
       * Input file name not specified with "-r", and a command-line argument
       * was specified; treat it as the input file name.
       *
       * Yes, this is different from tshark, where non-flag command-line
       * arguments are a filter, but this works better on GUI desktops
       * where a command can be specified to be run to open a particular
       * file - yes, you could have "-r" as the last part of the command,
       * but that's a bit ugly.
       */
#if defined _WIN32 && (GLIB_MAJOR_VERSION > 2 || (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION >= 6))
      /* since GLib 2.6, we need to convert filenames to utf8 for Win32 */
      cf_name = g_locale_to_utf8(argv[0], -1, NULL, NULL, NULL);
#else
      cf_name = g_strdup(argv[0]);
#endif
    }
    argc--;
    argv++;
  }



  if (argc != 0) {
    /*
     * Extra command line arguments were specified; complain.
     */
    cmdarg_err("Invalid argument: %s", argv[0]);
    arg_error = TRUE;
  }

  if (arg_error) {
#ifndef HAVE_LIBPCAP
    if (capture_option_specified) {
      cmdarg_err("This version of Wireshark was not built with support for capturing packets.");
    }
#endif
    print_usage(FALSE);
    exit(1);
  }

#ifdef HAVE_LIBPCAP
  if (start_capture && list_link_layer_types) {
    /* Specifying *both* is bogus. */
    cmdarg_err("You can't specify both -L and a live capture.");
    exit(1);
  }

  if (list_link_layer_types) {
    /* We're supposed to list the link-layer types for an interface;
       did the user also specify a capture file to be read? */
    if (cf_name) {
      /* Yes - that's bogus. */
      cmdarg_err("You can't specify -L and a capture file to be read.");
      exit(1);
    }
    /* No - did they specify a ring buffer option? */
    if (capture_opts->multi_files_on) {
      cmdarg_err("Ring buffer requested, but a capture isn't being done.");
      exit(1);
    }
  } else {
    /* We're supposed to do a live capture; did the user also specify
       a capture file to be read? */
    if (start_capture && cf_name) {
      /* Yes - that's bogus. */
      cmdarg_err("You can't specify both a live capture and a capture file to be read.");
      exit(1);
    }

    /* No - was the ring buffer option specified and, if so, does it make
       sense? */
    if (capture_opts->multi_files_on) {
      /* Ring buffer works only under certain conditions:
	 a) ring buffer does not work with temporary files;
	 b) real_time_mode and multi_files_on are mutually exclusive -
	    real_time_mode takes precedence;
	 c) it makes no sense to enable the ring buffer if the maximum
	    file size is set to "infinite". */
      if (capture_opts->save_file == NULL) {
	cmdarg_err("Ring buffer requested, but capture isn't being saved to a permanent file.");
	capture_opts->multi_files_on = FALSE;
      }
/*      if (capture_opts->real_time_mode) {
	cmdarg_err("Ring buffer requested, but an \"Update list of packets in real time\" capture is being done.");
	capture_opts->multi_files_on = FALSE;
      }*/
      if (!capture_opts->has_autostop_filesize && !capture_opts->has_file_duration) {
	cmdarg_err("Ring buffer requested, but no maximum capture file size or duration were specified.");
/* XXX - this must be redesigned as the conditions changed */
/*	capture_opts->multi_files_on = FALSE;*/
      }
    }
  }

  if (start_capture || list_link_layer_types) {
    /* Did the user specify an interface to use? */
    if (!capture_opts_trim_iface(capture_opts,
        (prefs->capture_device) ? get_if_name(prefs->capture_device) : NULL)) {
        exit(2);
    }
  }

  if (list_link_layer_types) {
    status = capture_opts_list_link_layer_types(capture_opts);
    exit(status);
  }

  capture_opts_trim_snaplen(capture_opts, MIN_PACKET_SIZE);
  capture_opts_trim_ring_num_files(capture_opts);
#endif /* HAVE_LIBPCAP */

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

  /* read in rc file from global and personal configuration paths. */
  rc_file = get_datafile_path(RC_FILE);
  gtk_rc_parse(rc_file);
  rc_file = get_persconffile_path(RC_FILE, FALSE);
  gtk_rc_parse(rc_file);

  font_init();

  /* close the splash screen, as we are going to open the main window now */
  splash_destroy(splash_win);

  /************************************************************************/
  /* Everything is prepared now, preferences and command line was read in */

  /* Pop up the main window. */
  create_main_window(pl_size, tv_size, bv_size, prefs);

  /* Read the dynamic part of the recent file, as we have the gui now ready for it. */
  recent_read_dynamic(&rf_path, &rf_open_errno);
  color_filters_enable(recent.packet_list_colorize);

  /* rearrange all the widgets as we now have all recent settings ready for this */
  main_widgets_rearrange();

  /* Fill in column titles.  This must be done after the top level window
     is displayed.

     XXX - is that still true, with fixed-width columns? */
  packet_list_set_column_titles();

  menu_recent_read_finished();

  switch (user_font_apply()) {
  case FA_SUCCESS:
      break;
  case FA_FONT_NOT_RESIZEABLE:
      /* "user_font_apply()" popped up an alert box. */
      /* turn off zooming - font can't be resized */
  case FA_FONT_NOT_AVAILABLE:
      /* XXX - did we successfully load the un-zoomed version earlier?
      If so, this *probably* means the font is available, but not at
      this particular zoom level, but perhaps some other failure
      occurred; I'm not sure you can determine which is the case,
      however. */
      /* turn off zooming - zoom level is unavailable */
  default:
      /* in any other case than FA_SUCCESS, turn off zooming */
      recent.gui_zoom_level = 0;
      /* XXX: would it be a good idea to disable zooming (insensitive GUI)? */
  }

  dnd_init(top_level);

  colors_init();
  color_filters_init();
  decode_as_init();

  /* the window can be sized only, if it's not already shown, so do it now! */
  main_load_window_geometry(top_level);

  /* If we were given the name of a capture file, read it in now;
     we defer it until now, so that, if we can't open it, and pop
     up an alert box, the alert box is more likely to come up on
     top of the main window - but before the preference-file-error
     alert box, so, if we get one of those, it's more likely to come
     up on top of us. */
  if (cf_name) {
    show_main_window(TRUE);
    if (rfilter != NULL) {
      if (!dfilter_compile(rfilter, &rfcode)) {
        bad_dfilter_alert_box(rfilter);
        rfilter_parse_failed = TRUE;
      }
    }
    if (!rfilter_parse_failed) {
      if (cf_open(&cfile, cf_name, FALSE, &err) == CF_OK) {
        /* "cf_open()" succeeded, so it closed the previous
           capture file, and thus destroyed any previous read filter
           attached to "cf". */

        cfile.rfcode = rfcode;
        /* Open stat windows; we do so after creating the main window,
           to avoid GTK warnings, and after successfully opening the
           capture file, so we know we have something to compute stats
           on, and after registering all dissectors, so that MATE will
           have registered its field array and we can have a tap filter
           with one of MATE's late-registered fields as part of the
           filter. */
        start_requested_stats();

        /* Read the capture file. */
        switch (cf_read(&cfile)) {

        case CF_READ_OK:
        case CF_READ_ERROR:
          /* Just because we got an error, that doesn't mean we were unable
             to read any of the file; we handle what we could get from the
             file. */
          /* if the user told us to jump to a specific packet, do it now */
          if(go_to_packet != 0) {
            cf_goto_frame(&cfile, go_to_packet);
          }
          break;

        case CF_READ_ABORTED:
          /* Exit now. */
          gtk_exit(0);
          break;
        }
        /* Save the name of the containing directory specified in the
           path name, if any; we can write over cf_name, which is a
           good thing, given that "get_dirname()" does write over its
           argument. */
        s = get_dirname(cf_name);
        /* we might already set this from the recent file, don't overwrite this */
        if(get_last_open_dir() == NULL)
          set_last_open_dir(s);
        g_free(cf_name);
        cf_name = NULL;
      } else {
        if (rfcode != NULL)
          dfilter_free(rfcode);
        cfile.rfcode = NULL;
    show_main_window(FALSE);
	set_menus_for_capture_in_progress(FALSE);
      }
    }
  } else {
#ifdef HAVE_LIBPCAP
    if (start_capture) {
      if (capture_opts->save_file != NULL) {
        /* Save the directory name for future file dialogs. */
        /* (get_dirname overwrites filename) */
        s = get_dirname(g_strdup(capture_opts->save_file));
        set_last_open_dir(s);
        g_free(s);
      }
      /* "-k" was specified; start a capture. */
      show_main_window(TRUE);
      if (capture_start(capture_opts)) {
        /* The capture started.  Open stat windows; we do so after creating
	   the main window, to avoid GTK warnings, and after successfully
	   opening the capture file, so we know we have something to compute
	   stats on, and after registering all dissectors, so that MATE will
	   have registered its field array and we can have a tap filter with
           one of MATE's late-registered fields as part of the filter. */
        start_requested_stats();
      }
    }
    else {
      show_main_window(FALSE);
      set_menus_for_capture_in_progress(FALSE);
    }

    /* if the user didn't supplied a capture filter, use the one to filter out remote connections like SSH */
    if (!start_capture && strlen(capture_opts->cfilter) == 0) {
      g_free(capture_opts->cfilter);
      capture_opts->cfilter = g_strdup(get_conn_cfilter());
    }
#else /* HAVE_LIBPCAP */
    show_main_window(FALSE);
    set_menus_for_capture_in_progress(FALSE);
#endif /* HAVE_LIBPCAP */
  }

  /* register our pid if we are being run from a U3 device */
  u3_register_pid();

  /* we'll enter the GTK loop now and hand the control over to GTK ... */
  gtk_main();
  /* ... back from GTK, we're going down now! */

  /* deregister our pid */
  u3_deregister_pid();

  epan_cleanup();
  g_free(rc_file);

#ifdef _WIN32
  /* hide the (unresponsive) main window, while asking the user to close the console window */
  gtk_widget_hide(top_level);

  /* Shutdown windows sockets */
  WSACleanup();

  /* For some unknown reason, the "atexit()" call in "create_console()"
     doesn't arrange that "destroy_console()" be called when we exit,
     so we call it here if a console was created. */
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

#ifdef _WIN32

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
#if GTK_MAJOR_VERSION >= 2
  INITCOMMONCONTROLSEX comm_ctrl;

  /* Initialize our controls. Required for native Windows file dialogs. */
  memset (&comm_ctrl, 0, sizeof(comm_ctrl));
  comm_ctrl.dwSize = sizeof(comm_ctrl);
  /* Includes the animate, header, hot key, list view, progress bar,
   * status bar, tab, tooltip, toolbar, trackbar, tree view, and
   * up-down controls
   */
  comm_ctrl.dwICC = ICC_WIN95_CLASSES;
  InitCommonControlsEx(&comm_ctrl);

  /* RichEd20.DLL is needed for filter entries. */
  LoadLibrary(_T("riched20.dll"));
#endif /* GTK_MAJOR_VERSION >= 2 */

  has_console = FALSE;
  return main (__argc, __argv);
}

/*
 * If this application has no console window to which its standard output
 * would go, create one.
 */
void
create_console(void)
{
  if (!has_console) {
    /* We have no console to which to print the version string, so
       create one and make it the standard input, output, and error. */
    if (!AllocConsole())
      return;   /* couldn't create console */
    eth_freopen("CONIN$", "r", stdin);
    eth_freopen("CONOUT$", "w", stdout);
    eth_freopen("CONOUT$", "w", stderr);

    /* Well, we have a console now. */
    has_console = TRUE;

    /* Now register "destroy_console()" as a routine to be called just
       before the application exits, so that we can destroy the console
       after the user has typed a key (so that the console doesn't just
       disappear out from under them, giving the user no chance to see
       the message(s) we put in there). */
    atexit(destroy_console);

	SetConsoleTitle(_T("Wireshark Debug Console"));
  }
}

static void
destroy_console(void)
{
  if (has_console) {
    printf("\n\nPress any key to exit\n");
    _getch();
    FreeConsole();
  }
}
#endif /* _WIN32 */


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
		    const char *message, gpointer user_data _U_)
{
  time_t curr;
  struct tm *today;
  const char *level;


  /* ignore log message, if log_level isn't interesting.
     If preferences aren't loaded yet, display message anyway */
  if((log_level & G_LOG_LEVEL_MASK & prefs.console_log_level) == 0 &&
     prefs.console_log_level != 0) {
    return;
  }

  /* create a "timestamp" */
  time(&curr);
  today = localtime(&curr);

#ifdef _WIN32
  if (prefs.gui_console_open != console_open_never || log_level & G_LOG_LEVEL_ERROR) {
    /* the user wants a console or the application will terminate immediately */
    create_console();
  }
  if (has_console) {
    /* For some unknown reason, the above doesn't appear to actually cause
       anything to be sent to the standard output, so we'll just splat the
       message out directly, just to make sure it gets out. */
#endif
    switch(log_level & G_LOG_LEVEL_MASK) {
    case G_LOG_LEVEL_ERROR:
        level = "Err ";
        break;
    case G_LOG_LEVEL_CRITICAL:
        level = "Crit";
        break;
    case G_LOG_LEVEL_WARNING:
        level = "Warn";
        break;
    case G_LOG_LEVEL_MESSAGE:
        level = "Msg ";
        break;
    case G_LOG_LEVEL_INFO:
        level = "Info";
        break;
    case G_LOG_LEVEL_DEBUG:
        level = "Dbg ";
        break;
    default:
        fprintf(stderr, "unknown log_level %u\n", log_level);
        level = NULL;
        g_assert_not_reached();
    }

    fprintf(stderr, "%02u:%02u:%02u %8s %s %s\n",
            today->tm_hour, today->tm_min, today->tm_sec,
            log_domain != NULL ? log_domain : "",
            level, message);
#ifdef _WIN32
    if(log_level & G_LOG_LEVEL_ERROR) {
        /* wait for a key press before the following error handler will terminate the program
           this way the user at least can read the error message */
        printf("\n\nPress any key to exit\n");
        _getch();
    }
  } else {
    g_log_default_handler(log_domain, log_level, message, user_data);
  }
#endif
}


static GtkWidget *info_bar_new(void)
{
    /* tip: tooltips don't work on statusbars! */
    info_bar = gtk_statusbar_new();
    main_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "main");
    file_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "file");
    help_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "help");
#if GTK_MAJOR_VERSION >= 2
    gtk_statusbar_set_has_resize_grip(GTK_STATUSBAR(info_bar), FALSE);
#endif
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), main_ctx, DEF_READY_MESSAGE);

    return info_bar;
}

static GtkWidget *packets_bar_new(void)
{
    /* tip: tooltips don't work on statusbars! */
    packets_bar = gtk_statusbar_new();
    packets_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(packets_bar), "packets");
    packets_bar_update();

    return packets_bar;
}


/*
 * Helper for main_widgets_rearrange()
 */
static void foreach_remove_a_child(GtkWidget *widget, gpointer data) {
    gtk_container_remove(GTK_CONTAINER(data), widget);
}

static GtkWidget *main_widget_layout(gint layout_content)
{
    switch(layout_content) {
    case(layout_pane_content_none):
        return NULL;
        break;
    case(layout_pane_content_plist):
        return pkt_scrollw;
        break;
    case(layout_pane_content_pdetails):
        return tv_scrollw;
        break;
    case(layout_pane_content_pbytes):
        return byte_nb_ptr;
        break;
    default:
        g_assert_not_reached();
        return NULL;
    }
}


/*
 * Rearrange the main window widgets
 */
void main_widgets_rearrange(void) {
    GtkWidget *first_pane_widget1, *first_pane_widget2;
    GtkWidget *second_pane_widget1, *second_pane_widget2;
    gboolean split_top_left;

    /* be a bit faster */
    gtk_widget_hide(main_vbox);

    /* be sure, we don't loose a widget while rearranging */
    gtk_widget_ref(menubar);
    gtk_widget_ref(main_tb);
    gtk_widget_ref(filter_tb);

#ifdef HAVE_AIRPCAP
	gtk_widget_ref(airpcap_tb);
#endif

    gtk_widget_ref(pkt_scrollw);
    gtk_widget_ref(tv_scrollw);
    gtk_widget_ref(byte_nb_ptr);
    gtk_widget_ref(stat_hbox);
    gtk_widget_ref(info_bar);
    gtk_widget_ref(packets_bar);
    gtk_widget_ref(status_pane);
    gtk_widget_ref(main_pane_v1);
    gtk_widget_ref(main_pane_v2);
    gtk_widget_ref(main_pane_h1);
    gtk_widget_ref(main_pane_h2);
    gtk_widget_ref(welcome_pane);

    /* empty all containers participating */
    gtk_container_foreach(GTK_CONTAINER(main_vbox),     foreach_remove_a_child, main_vbox);
    gtk_container_foreach(GTK_CONTAINER(stat_hbox),     foreach_remove_a_child, stat_hbox);
    gtk_container_foreach(GTK_CONTAINER(status_pane),   foreach_remove_a_child, status_pane);
    gtk_container_foreach(GTK_CONTAINER(main_pane_v1),  foreach_remove_a_child, main_pane_v1);
    gtk_container_foreach(GTK_CONTAINER(main_pane_v2),  foreach_remove_a_child, main_pane_v2);
    gtk_container_foreach(GTK_CONTAINER(main_pane_h1),  foreach_remove_a_child, main_pane_h1);
    gtk_container_foreach(GTK_CONTAINER(main_pane_h2),  foreach_remove_a_child, main_pane_h2);

    /* add the menubar always at the top */
    gtk_box_pack_start(GTK_BOX(main_vbox), menubar, FALSE, TRUE, 0);

    /* main toolbar */
    gtk_box_pack_start(GTK_BOX(main_vbox), main_tb, FALSE, TRUE, 0);

    /* filter toolbar in toolbar area */
    if (!prefs.filter_toolbar_show_in_statusbar) {
        gtk_box_pack_start(GTK_BOX(main_vbox), filter_tb, FALSE, TRUE, 1);
    }

#ifdef HAVE_AIRPCAP
	/* airpcap toolbar */
	gtk_box_pack_start(GTK_BOX(main_vbox), airpcap_tb, FALSE, TRUE, 1);
#endif

    /* fill the main layout panes */
    switch(prefs.gui_layout_type) {
    case(layout_type_5):
        main_first_pane  = main_pane_v1;
        main_second_pane = main_pane_v2;
        split_top_left = FALSE;
        break;
    case(layout_type_2):
        main_first_pane  = main_pane_v1;
        main_second_pane = main_pane_h1;
        split_top_left = FALSE;
        break;
    case(layout_type_1):
        main_first_pane  = main_pane_v1;
        main_second_pane = main_pane_h1;
        split_top_left = TRUE;
        break;
    case(layout_type_4):
        main_first_pane  = main_pane_h1;
        main_second_pane = main_pane_v1;
        split_top_left = FALSE;
        break;
    case(layout_type_3):
        main_first_pane  = main_pane_h1;
        main_second_pane = main_pane_v1;
        split_top_left = TRUE;
        break;
    case(layout_type_6):
        main_first_pane  = main_pane_h1;
        main_second_pane = main_pane_h2;
        split_top_left = FALSE;
        break;
    default:
        main_first_pane = NULL;
        main_second_pane = NULL;
        split_top_left = FALSE;
        g_assert_not_reached();
    }
    if (split_top_left) {
        first_pane_widget1 = main_second_pane;
        second_pane_widget1 = main_widget_layout(prefs.gui_layout_content_1);
        second_pane_widget2 = main_widget_layout(prefs.gui_layout_content_2);
        first_pane_widget2 = main_widget_layout(prefs.gui_layout_content_3);
    } else {
        first_pane_widget1 = main_widget_layout(prefs.gui_layout_content_1);
        first_pane_widget2 = main_second_pane;
        second_pane_widget1 = main_widget_layout(prefs.gui_layout_content_2);
        second_pane_widget2 = main_widget_layout(prefs.gui_layout_content_3);
    }
    if (first_pane_widget1 != NULL)
        gtk_paned_add1(GTK_PANED(main_first_pane), first_pane_widget1);
    if (first_pane_widget2 != NULL)
        gtk_paned_add2(GTK_PANED(main_first_pane), first_pane_widget2);
    if (second_pane_widget1 != NULL)
        gtk_paned_pack1(GTK_PANED(main_second_pane), second_pane_widget1, TRUE, TRUE);
    if (second_pane_widget2 != NULL)
        gtk_paned_pack2(GTK_PANED(main_second_pane), second_pane_widget2, FALSE, FALSE);

    gtk_container_add(GTK_CONTAINER(main_vbox), main_first_pane);

    /* welcome pane */
    gtk_box_pack_start(GTK_BOX(main_vbox), welcome_pane, TRUE, TRUE, 0);

    /* statusbar hbox */
    gtk_box_pack_start(GTK_BOX(main_vbox), stat_hbox, FALSE, TRUE, 0);

    /* filter toolbar in statusbar hbox */
    if (prefs.filter_toolbar_show_in_statusbar) {
        gtk_box_pack_start(GTK_BOX(stat_hbox), filter_tb, FALSE, TRUE, 1);
    }

#ifdef HAVE_AIRPCAP
	/* airpcap toolbar */
	gtk_box_pack_start(GTK_BOX(main_vbox), airpcap_tb, FALSE, TRUE, 1);
#endif

    /* statusbar */
    gtk_box_pack_start(GTK_BOX(stat_hbox), status_pane, TRUE, TRUE, 0);
    gtk_paned_pack1(GTK_PANED(status_pane), info_bar, FALSE, FALSE);
    gtk_paned_pack2(GTK_PANED(status_pane), packets_bar, FALSE, FALSE);

    /* hide widgets on users recent settings */
    main_widgets_show_or_hide();

    gtk_widget_show(main_vbox);
}

static void
is_widget_visible(GtkWidget *widget, gpointer data)
{
    gboolean *is_visible = data;

    if (!*is_visible) {
        if (GTK_WIDGET_VISIBLE(widget))
            *is_visible = TRUE;
    }
}


#ifdef SHOW_WELCOME_PAGE
/* XXX - There seems to be some disagreement about if and how this feature should be implemented.
   As I currently don't have the time to continue this, it's temporarily disabled. - ULFL */
GtkWidget *
welcome_item(gchar *stock_item, gchar * label, gchar * message, GtkSignalFunc callback, void *callback_data)
{
    GtkWidget *w, *item_hb;
#if GTK_MAJOR_VERSION >= 2
    gchar *formatted_message;
#endif


    item_hb = gtk_hbox_new(FALSE, 1);

    w = BUTTON_NEW_FROM_STOCK(stock_item);
    WIDGET_SET_SIZE(w, 60, 60);
#if GTK_MAJOR_VERSION >= 2
    gtk_button_set_label(GTK_BUTTON(w), label);
#endif
    gtk_box_pack_start(GTK_BOX(item_hb), w, FALSE, FALSE, 0);
    SIGNAL_CONNECT(w, "clicked", callback, callback_data);

    w = gtk_label_new(message);
	gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.5);
#if GTK_MAJOR_VERSION >= 2
    formatted_message = g_strdup_printf("<span weight=\"bold\" size=\"x-large\">%s</span>", message);
    gtk_label_set_markup(GTK_LABEL(w), formatted_message);
    g_free(formatted_message);
#endif

    gtk_box_pack_start(GTK_BOX(item_hb), w, FALSE, FALSE, 10);

    return item_hb;
}


/* XXX - the layout has to be improved */
GtkWidget *
welcome_new(void)
{
    GtkWidget *welcome_scrollw, *welcome_hb, *welcome_vb, *item_hb;
    GtkWidget *w, *icon;
    gchar * message;


    welcome_scrollw = scrolled_window_new(NULL, NULL);

    welcome_hb = gtk_hbox_new(FALSE, 1);
	/*gtk_container_border_width(GTK_CONTAINER(welcome_hb), 20);*/

    welcome_vb = gtk_vbox_new(FALSE, 1);

    item_hb = gtk_hbox_new(FALSE, 1);

    icon = xpm_to_widget_from_parent(top_level, wsicon64_xpm);
    gtk_box_pack_start(GTK_BOX(item_hb), icon, FALSE, FALSE, 5);

#if GTK_MAJOR_VERSION < 2
    message = "Welcome to Wireshark!";
#else
    message = "<span weight=\"bold\" size=\"25000\">" "Welcome to Wireshark!" "</span>";
#endif
    w = gtk_label_new(message);
#if GTK_MAJOR_VERSION >= 2
    gtk_label_set_markup(GTK_LABEL(w), message);
#endif
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.5);
    gtk_box_pack_start(GTK_BOX(item_hb), w, TRUE, TRUE, 5);

    gtk_box_pack_start(GTK_BOX(welcome_vb), item_hb, TRUE, FALSE, 5);

    w = gtk_label_new("What would you like to do?");
    gtk_box_pack_start(GTK_BOX(welcome_vb), w, FALSE, FALSE, 10);
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.0);

#ifdef HAVE_LIBPCAP
    item_hb = welcome_item(WIRESHARK_STOCK_CAPTURE_START,
        "Capture",
        "Capture live data from your network",
        GTK_SIGNAL_FUNC(capture_prep_cb), NULL);
    gtk_box_pack_start(GTK_BOX(welcome_vb), item_hb, TRUE, FALSE, 5);
#endif

    item_hb = welcome_item(GTK_STOCK_OPEN,
        "Open",
        "Open a previously captured file",
        GTK_SIGNAL_FUNC(file_open_cmd_cb), NULL);
    gtk_box_pack_start(GTK_BOX(welcome_vb), item_hb, TRUE, FALSE, 5);

#if (GLIB_MAJOR_VERSION >= 2)
    item_hb = welcome_item(GTK_STOCK_HOME,
        "Home",
        "Visit the Wireshark homepage",
        GTK_SIGNAL_FUNC(topic_cb), GINT_TO_POINTER(ONLINEPAGE_HOME));
    gtk_box_pack_start(GTK_BOX(welcome_vb), item_hb, TRUE, FALSE, 5);

    item_hb = welcome_item(WIRESHARK_STOCK_WEB_SUPPORT,
        "User's Guide",
        "Open the Wireshark User's Guide",
        GTK_SIGNAL_FUNC(topic_cb), GINT_TO_POINTER(ONLINEPAGE_USERGUIDE));
    gtk_box_pack_start(GTK_BOX(welcome_vb), item_hb, TRUE, FALSE, 5);
#endif

    /* the end */
    w = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(welcome_vb), w, TRUE, TRUE, 0);

    w = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(welcome_hb), w, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(welcome_hb), welcome_vb, TRUE, TRUE, 0);

    w = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(welcome_hb), w, TRUE, TRUE, 0);

    gtk_widget_show_all(welcome_hb);

    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(welcome_scrollw),
                                          welcome_hb);
    gtk_widget_show_all(welcome_scrollw);

    return welcome_scrollw;
}
#else
static GtkWidget *
welcome_new(void)
{
    /* this is just a dummy to fill up window space, simply showing nothing */
    return scrolled_window_new(NULL, NULL);
}
#endif



/*
 * XXX - this doesn't appear to work with the paned widgets in
 * GTK+ 1.2[.x]; if you hide one of the panes, the splitter remains
 * and the other pane doesn't grow to take up the rest of the pane.
 * It does appear to work with GTK+ 2.x.
 */
void
main_widgets_show_or_hide(void)
{
    gboolean main_second_pane_show;

    if (recent.main_toolbar_show) {
        gtk_widget_show(main_tb);
    } else {
        gtk_widget_hide(main_tb);
    }

    /*
     * Show the status hbox if either:
     *
     *    1) we're showing the filter toolbar and we want it in the status
     *       line
     *
     * or
     *
     *    2) we're showing the status bar.
     */
    if ((recent.filter_toolbar_show && prefs.filter_toolbar_show_in_statusbar) ||
         recent.statusbar_show) {
        gtk_widget_show(stat_hbox);
    } else {
        gtk_widget_hide(stat_hbox);
    }

    if (recent.statusbar_show) {
        gtk_widget_show(status_pane);
    } else {
        gtk_widget_hide(status_pane);
    }

    if (recent.filter_toolbar_show) {
        gtk_widget_show(filter_tb);
    } else {
        gtk_widget_hide(filter_tb);
    }

#ifdef HAVE_AIRPCAP
	if (recent.airpcap_toolbar_show) {
        gtk_widget_show(airpcap_tb);
    } else {
        gtk_widget_hide(airpcap_tb);
    }
#endif

    if (recent.packet_list_show && have_capture_file) {
        gtk_widget_show(pkt_scrollw);
    } else {
        gtk_widget_hide(pkt_scrollw);
    }

    if (recent.tree_view_show && have_capture_file) {
        gtk_widget_show(tv_scrollw);
    } else {
        gtk_widget_hide(tv_scrollw);
    }

    if (recent.byte_view_show && have_capture_file) {
        gtk_widget_show(byte_nb_ptr);
    } else {
        gtk_widget_hide(byte_nb_ptr);
    }

    if (have_capture_file) {
        gtk_widget_show(main_first_pane);
    } else {
        gtk_widget_hide(main_first_pane);
    }

    /*
     * Is anything in "main_second_pane" visible?
     * If so, show it, otherwise hide it.
     */
    main_second_pane_show = FALSE;
    gtk_container_foreach(GTK_CONTAINER(main_second_pane), is_widget_visible,
                          &main_second_pane_show);
    if (main_second_pane_show) {
        gtk_widget_show(main_second_pane);
    } else {
        gtk_widget_hide(main_second_pane);
    }

    if (!have_capture_file) {
        if(welcome_pane) {
            gtk_widget_show(welcome_pane);
        }
    } else {
        gtk_widget_hide(welcome_pane);
    }
}


#if GTK_MAJOR_VERSION >= 2
/* called, when the window state changes (minimized, maximized, ...) */
static int
window_state_event_cb (GtkWidget *widget _U_,
                       GdkEvent *event,
                       gpointer  data _U_)
{
    GdkWindowState new_window_state = ((GdkEventWindowState*)event)->new_window_state;

    if( (event->type) == (GDK_WINDOW_STATE)) {
        if(!(new_window_state & GDK_WINDOW_STATE_ICONIFIED)) {
            /* we might have dialogs popped up while we where iconified,
               show em now */
            display_queued_messages();
        }
    }
    return FALSE;
}
#endif

#ifdef HAVE_AIRPCAP
/*
 * Changed callback for the channel combobox
 */
static void
airpcap_toolbar_channel_changed_cb(GtkWidget *w _U_, gpointer data)
{
gchar ebuf[AIRPCAP_ERRBUF_SIZE];
PAirpcapHandle ad;
const gchar *s;
int ch_num;

  s = gtk_entry_get_text(GTK_ENTRY(data));

if((data != NULL) && (w != NULL) )
	{
	s = gtk_entry_get_text(GTK_ENTRY(data));
	if((g_strcasecmp("",s)))
		{
		sscanf(s,"%d",&ch_num);
		if(airpcap_if_active != NULL)
			{
			ad = airpcap_if_open(get_airpcap_name_from_description(airpcap_if_list, airpcap_if_active->description), ebuf);

			if(ad)
				{
				airpcap_if_set_device_channel(ad,ch_num);
				airpcap_if_active->channel = ch_num;
				airpcap_if_close(ad);
				}
			}
		}
	}
}
#endif


#ifdef HAVE_AIRPCAP
/*
 * Callback for the wrong crc combo
 */
static void
airpcap_toolbar_wrong_crc_combo_cb(GtkWidget *entry, gpointer user_data)
{
gchar ebuf[AIRPCAP_ERRBUF_SIZE];
PAirpcapHandle ad;

if( !block_toolbar_signals && (airpcap_if_active != NULL))
	{
	ad = airpcap_if_open(get_airpcap_name_from_description(airpcap_if_list,airpcap_if_active->description), ebuf);

	if(ad)
		{
		airpcap_if_active->CrcValidationOn = airpcap_get_validation_type(gtk_entry_get_text(GTK_ENTRY(entry)));
		airpcap_if_set_fcs_validation(ad,airpcap_if_active->CrcValidationOn);
		/* Save configuration */
		if(!airpcap_if_store_cur_config_as_adapter_default(ad))
			{
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Cannot save configuration!!!\nRemember that in order to store the configuration in the registry you have to:\n\n- Close all the airpcap-based applications.\n- Be sure to have administrative privileges.");
			}
		airpcap_if_close(ad);
		}
	}
}
#endif

#ifdef HAVE_AIRPCAP
void
airpcap_toolbar_encryption_cb(GtkWidget *entry, gpointer user_data)
{
/* We need to directly access the .ddl functions here... */
gchar ebuf[AIRPCAP_ERRBUF_SIZE];
PAirpcapHandle ad;

gint n = 0;
gint i = 0;
airpcap_if_info_t* curr_if = NULL;

/* Apply changes to the current adapter */
if( (airpcap_if_active != NULL))
    {
	ad = airpcap_if_open(get_airpcap_name_from_description(airpcap_if_list,airpcap_if_active->description), ebuf);

	if(ad)
		{
		if(airpcap_if_active->DecryptionOn == AIRPCAP_DECRYPTION_ON)
			{
			airpcap_if_active->DecryptionOn = AIRPCAP_DECRYPTION_OFF;
			airpcap_if_set_decryption_state(ad,airpcap_if_active->DecryptionOn);
			/* Save configuration */
			if(!airpcap_if_store_cur_config_as_adapter_default(ad))
				{
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Cannot save configuration!!!\nRemember that in order to store the configuration in the registry you have to:\n\n- Close all the airpcap-based applications.\n- Be sure to have administrative privileges.");
				}
			airpcap_if_close(ad);
			}
		else
			{
			airpcap_if_active->DecryptionOn = AIRPCAP_DECRYPTION_ON;
			airpcap_if_set_decryption_state(ad,airpcap_if_active->DecryptionOn);
			/* Save configuration */
			if(!airpcap_if_store_cur_config_as_adapter_default(ad))
				{
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Cannot save configuration!!!\nRemember that in order to store the configuration in the registry you have to:\n\n- Close all the airpcap-based applications.\n- Be sure to have administrative privileges.");
				}
			airpcap_if_close(ad);
			}
		}
	}
else
    {
 	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No active AirPcap Adapter selected!");
 	return;
    }

n = g_list_length(airpcap_if_list);

/* The same kind of settings should be propagated to all the adapters */
/* Apply this change to all the adapters !!! */
for(i = 0; i < n; i++)
    {
    curr_if = (airpcap_if_info_t*)g_list_nth_data(airpcap_if_list,i);

    if( (curr_if != NULL) && (curr_if != airpcap_if_selected) )
    	{
    	ad = airpcap_if_open(get_airpcap_name_from_description(airpcap_if_list,curr_if->description), ebuf);
   		if(ad)
            {                                                                                     
            curr_if->DecryptionOn = airpcap_if_selected->DecryptionOn;
        	airpcap_if_set_decryption_state(ad,curr_if->DecryptionOn);
        	/* Save configuration for the curr_if */
        	if(!airpcap_if_store_cur_config_as_adapter_default(ad))
        		{
        		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Cannot save configuration!!!\nRemember that in order to store the configuration in the registry you have to:\n\n- Close all the airpcap-based applications.\n- Be sure to have administrative privileges.");
        		}
        	airpcap_if_close(ad);
            }
        }
    }
}
#endif

#ifdef HAVE_AIRPCAP
/*
 * Callback for the Advanced Wireless Settings button
 */
static void
toolbar_display_airpcap_advanced_cb(GtkWidget *w, gpointer data)
{
int *from_widget;

    from_widget = (gint*)g_malloc(sizeof(gint));
    *from_widget = AIRPCAP_ADVANCED_FROM_TOOLBAR;
    OBJECT_SET_DATA(airpcap_tb,AIRPCAP_ADVANCED_FROM_KEY,from_widget);

	display_airpcap_advanced_cb(w,data);
}
#endif

#ifdef HAVE_AIRPCAP
/*
 * Callback for the Decryption Key Management button
 */
static void
toolbar_display_airpcap_key_management_cb(GtkWidget *w, gpointer data)
{
int *from_widget;

    from_widget = (gint*)g_malloc(sizeof(gint));
    *from_widget = AIRPCAP_ADVANCED_FROM_TOOLBAR;
    OBJECT_SET_DATA(airpcap_tb,AIRPCAP_ADVANCED_FROM_KEY,from_widget);

	display_airpcap_key_management_cb(w,data);
}
#endif

static void
create_main_window (gint pl_size, gint tv_size, gint bv_size, e_prefs *prefs)
{
    GtkWidget
                  *filter_bt, *filter_cm, *filter_te,
                  *filter_add_expr_bt,
                  *filter_apply,
                  *filter_reset;
    GList         *dfilter_list = NULL;
    GtkTooltips   *tooltips;

    GtkAccelGroup *accel;
    gchar         *title;

#ifdef HAVE_AIRPCAP
    GtkWidget *advanced_bt,
    		  *key_management_bt,
    		  *interface_lb,
    		  *channel_lb,
    		  *channel_cm,
    		  *wrong_crc_lb,
    		  *wrong_crc_cm;
                  
    GtkWidget *enable_decryption_lb;
    GtkWidget *enable_decryption_cb;
    GList     *enable_decryption_cb_items = NULL;
    GtkWidget *enable_decryption_en;

    GList	  *channel_list = NULL;
    GList	  *linktype_list = NULL;
    GList	  *link_list = NULL;
    GtkTooltips	  *airpcap_tooltips;
    gchar	  *if_label_text;
    gint          *from_widget = NULL;
#endif

    /* Display filter construct dialog has an Apply button, and "OK" not
       only sets our text widget, it activates it (i.e., it causes us to
       filter the capture). */
    static construct_args_t args = {
        "Wireshark: Display Filter",
        TRUE,
        TRUE,
        FALSE
    };

    /* use user-defined title if preference is set */
    title = create_user_window_title("The Wireshark Network Analyzer");

    /* Main window */
    top_level = window_new(GTK_WINDOW_TOPLEVEL, title);
    g_free(title);

    tooltips = gtk_tooltips_new();

#ifdef HAVE_AIRPCAP
	airpcap_tooltips = gtk_tooltips_new();
#endif

#ifdef _WIN32
#if GTK_MAJOR_VERSION < 2
    /* has to be done, after top_level window is created */
    app_font_gtk1_init(top_level);
#endif
#endif

    gtk_widget_set_name(top_level, "main window");
    SIGNAL_CONNECT(top_level, "delete_event", main_window_delete_event_cb,
                   NULL);
#if GTK_MAJOR_VERSION >= 2
    SIGNAL_CONNECT(GTK_OBJECT(top_level), "window_state_event",
                         G_CALLBACK (window_state_event_cb), NULL);
#endif

    gtk_window_set_policy(GTK_WINDOW(top_level), TRUE, TRUE, FALSE);

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
    main_pane_v1 = gtk_vpaned_new();
    gtk_widget_show(main_pane_v1);
    main_pane_v2 = gtk_vpaned_new();
    gtk_widget_show(main_pane_v2);
    main_pane_h1 = gtk_hpaned_new();
    gtk_widget_show(main_pane_h1);
    main_pane_h2 = gtk_hpaned_new();
    gtk_widget_show(main_pane_h2);

#ifdef HAVE_AIRPCAP
    /* airpcap toolbar */
#if GTK_MAJOR_VERSION < 2
    airpcap_tb = gtk_toolbar_new(GTK_ORIENTATION_HORIZONTAL,
                               GTK_TOOLBAR_BOTH);
#else
    airpcap_tb = gtk_toolbar_new();
    gtk_toolbar_set_orientation(GTK_TOOLBAR(airpcap_tb),
                                GTK_ORIENTATION_HORIZONTAL);
#endif /* GTK_MAJOR_VERSION */
       gtk_widget_show(airpcap_tb);

	/* Interface Label */
	if(airpcap_if_active != NULL)
		{
		if_label_text = g_strdup_printf("%s %s\t","Current Wireless Interface: #",airpcap_get_if_string_number(airpcap_if_active));
		interface_lb = gtk_label_new(if_label_text);
		g_free(if_label_text);
		}
	else
		{
		interface_lb = gtk_label_new("No Wireless Interface Found  ");
		}

	/* Add the label to the toolbar */
	gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), interface_lb,
        "Current Wireless Interface", "Private");
	OBJECT_SET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_INTERFACE_KEY,interface_lb);
	gtk_widget_show(interface_lb);
	gtk_toolbar_insert_space(GTK_TOOLBAR(airpcap_tb),1);


    /* Create the "802.11 Channel:" label */
	channel_lb = gtk_label_new(" 802.11 Channel: ");
	gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), channel_lb,
        "Current 802.11 Channel", "Private");
	gtk_widget_show(channel_lb);

	#if GTK_MAJOR_VERSION < 2
	gtk_widget_set_usize( GTK_WIDGET(channel_lb),
                                  100,
                                  28 );
	#else
	gtk_widget_set_size_request( GTK_WIDGET(channel_lb),
                                  100,
                                  28 );
    #endif

	/* Create the channel combo box */
    channel_cm = gtk_combo_new();
	gtk_editable_set_editable(GTK_EDITABLE(GTK_COMBO(channel_cm)->entry),FALSE);
	OBJECT_SET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_CHANNEL_KEY,channel_cm);

	channel_list = g_list_append(channel_list, "1");
    channel_list = g_list_append(channel_list, "2");
    channel_list = g_list_append(channel_list, "3");
    channel_list = g_list_append(channel_list, "4");
	channel_list = g_list_append(channel_list, "5");
	channel_list = g_list_append(channel_list, "6");
	channel_list = g_list_append(channel_list, "7");
	channel_list = g_list_append(channel_list, "8");
	channel_list = g_list_append(channel_list, "9");
	channel_list = g_list_append(channel_list, "10");
	channel_list = g_list_append(channel_list, "11");
	channel_list = g_list_append(channel_list, "12");
	channel_list = g_list_append(channel_list, "13");
	channel_list = g_list_append(channel_list, "14");

    gtk_combo_set_popdown_strings( GTK_COMBO(channel_cm), channel_list) ;

	gtk_tooltips_set_tip(airpcap_tooltips, GTK_WIDGET(GTK_COMBO(channel_cm)->entry),
		"Change the 802.11 RF channel",
        NULL);

	#if GTK_MAJOR_VERSION < 2
	gtk_widget_set_usize( GTK_WIDGET(channel_cm),
                                  90,
                                  28 );
	#else
	gtk_widget_set_size_request( GTK_WIDGET(channel_cm),
                                  90,
                                  28 );
    #endif

	if(airpcap_if_active != NULL)
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(channel_cm)->entry), airpcap_get_channel_name(airpcap_if_active->channel));
	else
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(channel_cm)->entry),"");

	/* callback for channel combo box */
	SIGNAL_CONNECT(GTK_COMBO(channel_cm)->entry,"changed",airpcap_toolbar_channel_changed_cb,GTK_COMBO(channel_cm)->entry);
    gtk_widget_show(channel_cm);

    gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), channel_cm,
        "802.11 Channel", "Private");

	gtk_toolbar_append_space(GTK_TOOLBAR(airpcap_tb));

	/* Wrong CRC Label */
	wrong_crc_lb = gtk_label_new(" FCS Filter: ");
	gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), wrong_crc_lb,
        "", "Private");
	gtk_widget_show(wrong_crc_lb);

	/* Wrong CRC combo */
	wrong_crc_cm = gtk_combo_new();
	gtk_editable_set_editable(GTK_EDITABLE(GTK_COMBO(wrong_crc_cm)->entry),FALSE);
	OBJECT_SET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_FCS_FILTER_KEY,wrong_crc_cm);
	gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), wrong_crc_cm,
        "", "Private");

	#if GTK_MAJOR_VERSION >= 2
    gtk_widget_set_size_request (wrong_crc_cm, 100, -1);
    #else
    gtk_widget_set_usize (wrong_crc_cm, 100, -1);
    #endif

	linktype_list = g_list_append(linktype_list, AIRPCAP_VALIDATION_TYPE_NAME_ALL);
	linktype_list = g_list_append(linktype_list, AIRPCAP_VALIDATION_TYPE_NAME_CORRECT);
    linktype_list = g_list_append(linktype_list, AIRPCAP_VALIDATION_TYPE_NAME_CORRUPT);

    gtk_combo_set_popdown_strings( GTK_COMBO(wrong_crc_cm), linktype_list) ;
	gtk_tooltips_set_tip(airpcap_tooltips, GTK_WIDGET(GTK_COMBO(wrong_crc_cm)->entry),
	"Select the 802.11 FCS filter that the wireless adapter will apply.",
    NULL);

	if(airpcap_if_active != NULL)
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(wrong_crc_cm)->entry), airpcap_get_validation_name(airpcap_if_active->CrcValidationOn));
	else
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(wrong_crc_cm)->entry),"");

	SIGNAL_CONNECT(GTK_COMBO(wrong_crc_cm)->entry,"changed",airpcap_toolbar_wrong_crc_combo_cb,airpcap_tb);
	gtk_widget_show(wrong_crc_cm);

	gtk_toolbar_append_space(GTK_TOOLBAR(airpcap_tb));

    /* Decryption mode combo box */
    enable_decryption_lb = gtk_label_new ("Decryption Mode: ");
    gtk_widget_set_name (enable_decryption_lb, "enable_decryption_lb");
    gtk_widget_show (enable_decryption_lb);
	gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), enable_decryption_lb,
    NULL, "Private");
        
    enable_decryption_cb = gtk_combo_new ();
    gtk_widget_set_name (enable_decryption_cb, "enable_decryption_cb");
    gtk_widget_show (enable_decryption_cb);
    #if GTK_MAJOR_VERSION >= 2
    gtk_widget_set_size_request (enable_decryption_cb, 83, -1);
    #else
    gtk_widget_set_usize (enable_decryption_cb, 83, -1);
    #endif
    enable_decryption_cb_items = g_list_append (enable_decryption_cb_items, AIRPCAP_DECRYPTION_TYPE_STRING_NONE);
    enable_decryption_cb_items = g_list_append (enable_decryption_cb_items, AIRPCAP_DECRYPTION_TYPE_STRING_WIRESHARK);
    enable_decryption_cb_items = g_list_append (enable_decryption_cb_items, AIRPCAP_DECRYPTION_TYPE_STRING_AIRPCAP);
    gtk_combo_set_popdown_strings (GTK_COMBO (enable_decryption_cb), enable_decryption_cb_items);
    g_list_free (enable_decryption_cb_items);
    
    enable_decryption_en = GTK_COMBO (enable_decryption_cb)->entry;
    gtk_widget_set_name (enable_decryption_en, "enable_decryption_en");
    gtk_widget_show (enable_decryption_en);
    gtk_editable_set_editable (GTK_EDITABLE (enable_decryption_en), FALSE);
    GTK_WIDGET_UNSET_FLAGS (enable_decryption_en, GTK_CAN_FOCUS);
    
	gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), enable_decryption_cb,
        "Choose a Decryption Mode", "Private");
   
    /* Set current decryption mode!!!! */
    update_decryption_mode_cm(enable_decryption_cb);
    SIGNAL_CONNECT (enable_decryption_en, "changed",on_enable_decryption_en_changed, airpcap_tb);
    OBJECT_SET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_DECRYPTION_KEY,enable_decryption_cb);

	gtk_toolbar_append_space(GTK_TOOLBAR(airpcap_tb));

	/* Advanced button */
	advanced_bt = gtk_button_new_with_label("Advanced Wireless Settings...");
	OBJECT_SET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_ADVANCED_KEY,advanced_bt);

	SIGNAL_CONNECT(advanced_bt, "clicked", toolbar_display_airpcap_advanced_cb, airpcap_tb);
	gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), advanced_bt,
        "Set Advanced Wireless Settings...", "Private");
	gtk_widget_show(advanced_bt);

	/* Key Management button */
	key_management_bt = gtk_button_new_with_label("Decryption Keys");
	OBJECT_SET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_KEY_MANAGEMENT_KEY,key_management_bt);

	SIGNAL_CONNECT(key_management_bt, "clicked", toolbar_display_airpcap_key_management_cb, airpcap_tb);
	gtk_toolbar_append_widget(GTK_TOOLBAR(airpcap_tb), key_management_bt,
        "Manage Decryption Keys...", "Private");
	gtk_widget_show(key_management_bt);

	/* select the default interface */
	airpcap_if_active = airpcap_get_default_if(airpcap_if_list);

	/* If no airpcap interface is present, gray everything */
	if(airpcap_if_active == NULL)
		{
    	if(airpcap_if_list == NULL)
			{
			/*No airpcap device found */
			gtk_widget_set_sensitive(airpcap_tb,FALSE);
			recent.airpcap_toolbar_show = FALSE;
			}
		else
			{
			/* default adapter is not airpcap... or is airpcap but is not found*/
			airpcap_set_toolbar_stop_capture(airpcap_if_active);
			gtk_widget_set_sensitive(airpcap_tb,FALSE);
			recent.airpcap_toolbar_show = TRUE;
			}
		}
    else
		{
        airpcap_set_toolbar_stop_capture(airpcap_if_active);
		recent.airpcap_toolbar_show = TRUE;
        }
        
#endif

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

    /* Create the "Filter:" button */
    filter_bt = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY);
    SIGNAL_CONNECT(filter_bt, "clicked", display_filter_construct_cb, &args);
    gtk_widget_show(filter_bt);
    OBJECT_SET_DATA(top_level, E_FILT_BT_PTR_KEY, filter_bt);

    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_bt,
        "Open the \"Display Filter\" dialog, to edit/apply filters", "Private");

    /* Create the filter combobox */
    filter_cm = gtk_combo_new();
    dfilter_list = NULL;
    gtk_combo_disable_activate(GTK_COMBO(filter_cm));
    gtk_combo_set_case_sensitive(GTK_COMBO(filter_cm), TRUE);
    OBJECT_SET_DATA(filter_cm, E_DFILTER_FL_KEY, dfilter_list);
    filter_te = GTK_COMBO(filter_cm)->entry;
    main_display_filter_widget=filter_te;
    OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, filter_te);
    OBJECT_SET_DATA(filter_te, E_DFILTER_CM_KEY, filter_cm);
    OBJECT_SET_DATA(top_level, E_DFILTER_CM_KEY, filter_cm);
    SIGNAL_CONNECT(filter_te, "activate", filter_activate_cb, filter_te);
    SIGNAL_CONNECT(filter_te, "changed", filter_te_syntax_check_cb, NULL);
    WIDGET_SET_SIZE(filter_cm, 400, -1);
    gtk_widget_show(filter_cm);
    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_cm,
        NULL, NULL);
    /* setting a tooltip for a combobox will do nothing, so add it to the corresponding text entry */
    gtk_tooltips_set_tip(tooltips, filter_te,
        "Enter a display filter, or choose one of your recently used filters. "
        "The background color of this field is changed by a continuous syntax check (green is valid, red is invalid).",
        NULL);

    /* Create the "Add Expression..." button, to pop up a dialog
       for constructing filter comparison expressions. */
    filter_add_expr_bt = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_ADD_EXPRESSION);
    OBJECT_SET_DATA(filter_tb, E_FILT_FILTER_TE_KEY, filter_te);
    SIGNAL_CONNECT(filter_add_expr_bt, "clicked", filter_add_expr_bt_cb, filter_tb);
    gtk_widget_show(filter_add_expr_bt);
    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_add_expr_bt,
        "Add an expression to this filter string", "Private");

    /* Create the "Clear" button */
    filter_reset = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLEAR);
    OBJECT_SET_DATA(filter_reset, E_DFILTER_TE_KEY, filter_te);
    SIGNAL_CONNECT(filter_reset, "clicked", filter_reset_cb, NULL);
    gtk_widget_show(filter_reset);
    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_reset,
        "Clear this filter string and update the display", "Private");

    /* Create the "Apply" button */
    filter_apply = BUTTON_NEW_FROM_STOCK(GTK_STOCK_APPLY);
    OBJECT_SET_DATA(filter_apply, E_DFILTER_CM_KEY, filter_cm);
    SIGNAL_CONNECT(filter_apply, "clicked", filter_activate_cb, filter_te);
    gtk_widget_show(filter_apply);
    gtk_toolbar_append_widget(GTK_TOOLBAR(filter_tb), filter_apply,
        "Apply this filter string to the display", "Private");

    /* Sets the text entry widget pointer as the E_DILTER_TE_KEY data
     * of any widget that ends up calling a callback which needs
     * that text entry pointer */
    set_menu_object_data("/File/Open...", E_DFILTER_TE_KEY, filter_te);
    set_menu_object_data("/Analyze/Display Filters...", E_FILT_TE_PTR_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Follow TCP Stream", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Follow SSL Stream", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/Not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/... and Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/... or Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/... and not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Apply as Filter/... or not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/Not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/... and Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/... or Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/... and not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Analyze/Prepare a Filter/... or not Selected", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Conversation Filter/Ethernet", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Conversation Filter/IP", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Conversation Filter/TCP", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Conversation Filter/UDP", E_DFILTER_TE_KEY,
                         filter_te);
    set_menu_object_data("/Conversation Filter/PN-CBA Server", E_DFILTER_TE_KEY,
                         filter_te);
    set_toolbar_object_data(E_DFILTER_TE_KEY, filter_te);
    OBJECT_SET_DATA(popup_menu_object, E_DFILTER_TE_KEY, filter_te);
    OBJECT_SET_DATA(popup_menu_object, E_MPACKET_LIST_KEY, packet_list);

    /* info (main) statusbar */
    info_bar = info_bar_new();
    gtk_widget_show(info_bar);

    /* packets statusbar */
    packets_bar = packets_bar_new();
    gtk_widget_show(packets_bar);

    /* Filter/status hbox */
    stat_hbox = gtk_hbox_new(FALSE, 1);
    gtk_container_border_width(GTK_CONTAINER(stat_hbox), 0);
    gtk_widget_show(stat_hbox);

    /* Pane for the statusbar */
    status_pane = gtk_hpaned_new();
    gtk_widget_show(status_pane);

    /* Pane for the welcome screen */
    welcome_pane = welcome_new();
    gtk_widget_show(welcome_pane);
}

static void
show_main_window(gboolean doing_work)
{
  main_set_for_capture_file(doing_work);

  /*** we have finished all init things, show the main window ***/
  gtk_widget_show(top_level);
  
  /* the window can be maximized only, if it's visible, so do it after show! */
  main_load_window_geometry(top_level);

  /* process all pending GUI events before continue */
  while (gtk_events_pending()) gtk_main_iteration();

  /* Pop up any queued-up alert boxes. */
  display_queued_messages();

#ifdef HAVE_AIRPCAP  
/* 
 * This will read the decryption keys from the preferences file, and will store 
 * them into the registry... 
 */
if(!airpcap_check_decryption_keys(airpcap_if_list))
    {
    /* Ask the user what to do ...*/
    airpcap_keys_check_w(NULL,NULL);
    }
else /* Keys from lists are equals, or wireshark has got no keys */
    {
    airpcap_load_decryption_keys(airpcap_if_list);    
    }
#endif
}
