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
#include <gdk/gdkkeysyms.h>
#if GTK_CHECK_VERSION(3,0,0)
# include <gdk/gdkkeysyms-compat.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
#include "wsutil/wsgetopt.h"
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
#include <wsutil/privileges.h>
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
#include <epan/frequency-utils.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/uat.h>
#include <epan/column.h>

/* general (not GTK specific) */
#include "../file.h"
#include "../summary.h"
#include "../filters.h"
#include "../disabled_protos.h"
#include "../color.h"
#include "../color_filters.h"
#include "../print.h"
#include "../simple_dialog.h"
#include "../main_statusbar.h"
#include "../register.h"
#include "../ringbuffer.h"
#include "../ui_util.h"
#include "../util.h"
#include "../clopts_common.h"
#include "../console_io.h"
#include "../cmdarg_err.h"
#include "../version_info.h"
#include "../merge.h"
#include "../alert_box.h"
#include "../log.h"
#include "../u3.h"
#include <wsutil/file_util.h>

#ifdef HAVE_LIBPCAP
#include "../capture_ui_utils.h"
#include "../capture-pcap-util.h"
#include "../capture_ifinfo.h"
#include "../capture.h"
#include "../capture_sync.h"
#endif

#ifdef _WIN32
#include "../capture-wpcap.h"
#include "../capture_wpcap_packet.h"
#include <tchar.h> /* Needed for Unicode */
#include <wsutil/unicode-utils.h>
#include <commctrl.h>
#include <shellapi.h>
#endif /* _WIN32 */

/* GTK related */
#include "gtk/file_dlg.h"
#include "gtk/gtkglobals.h"
#include "gtk/color_utils.h"
#include "gtk/gui_utils.h"
#include "gtk/color_dlg.h"
#include "gtk/filter_dlg.h"
#include "gtk/uat_gui.h"
#include "gtk/main.h"
#include "gtk/main_airpcap_toolbar.h"
#include "gtk/main_filter_toolbar.h"
#include "gtk/menus.h"
#include "gtk/macros_dlg.h"
#include "gtk/main_statusbar_private.h"
#include "gtk/main_toolbar.h"
#include "gtk/main_welcome.h"
#include "gtk/drag_and_drop.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/main_proto_draw.h"
#include "gtk/keys.h"
#include "gtk/packet_win.h"
#include "gtk/stock_icons.h"
#include "gtk/find_dlg.h"
#include "gtk/recent.h"
#include "gtk/follow_tcp.h"
#include "gtk/font_utils.h"
#include "gtk/about_dlg.h"
#include "gtk/help_dlg.h"
#include "gtk/decode_as_dlg.h"
#include "gtk/webbrowser.h"
#include "gtk/capture_dlg.h"
#include "gtk/capture_if_dlg.h"
#include "gtk/tap_param_dlg.h"
#include "gtk/prefs_column.h"
#include "gtk/prefs_dlg.h"
#include "gtk/proto_help.h"
#include "gtk/new_packet_list.h"

#ifdef HAVE_LIBPCAP
#include "../image/wsicon16.xpm"
#include "../image/wsicon32.xpm"
#include "../image/wsicon48.xpm"
#include "../image/wsicon64.xpm"
#include "../image/wsiconcap16.xpm"
#include "../image/wsiconcap32.xpm"
#include "../image/wsiconcap48.xpm"
#endif

#ifdef HAVE_AIRPCAP
#include <airpcap.h>
#include "airpcap_loader.h"
#include "airpcap_dlg.h"
#include "airpcap_gui_utils.h"
#endif

#include <epan/crypt/airpdcap_ws.h>


#ifdef HAVE_GTKOSXAPPLICATION
#include <igemacintegration/gtkosxapplication.h>
#endif

/*
 * Files under personal and global preferences directories in which
 * GTK settings for Wireshark are stored.
 */
#define RC_FILE "gtkrc"

capture_file cfile;

/* "exported" main widgets */
GtkWidget   *top_level = NULL, *pkt_scrollw, *tree_view_gbl, *byte_nb_ptr_gbl;

/* placement widgets (can be a bit confusing, because of the many layout possibilities */
static GtkWidget   *main_vbox, *main_pane_v1, *main_pane_v2, *main_pane_h1, *main_pane_h2;
static GtkWidget   *main_first_pane, *main_second_pane;

/* internally used widgets */
static GtkWidget   *menubar, *main_tb, *filter_tb, *tv_scrollw, *statusbar, *welcome_pane;

#ifdef HAVE_AIRPCAP
GtkWidget *airpcap_tb;
int    airpcap_dll_ret_val = -1;
#endif

GString *comp_info_str, *runtime_info_str;

static gboolean have_capture_file = FALSE; /* XXX - is there an equivalent in cfile? */

static guint  tap_update_timer_id;

#ifdef _WIN32
static gboolean has_console;	/* TRUE if app has console */
static gboolean console_wait;	/* "Press any key..." */
static void destroy_console(void);
static gboolean stdin_capture = FALSE; /* Don't grab stdin & stdout if TRUE */
#endif
static void console_log_handler(const char *log_domain,
    GLogLevelFlags log_level, const char *message, gpointer user_data);

#ifdef HAVE_LIBPCAP
capture_options global_capture_opts;
#endif


static void create_main_window(gint, gint, gint, e_prefs*);
static void show_main_window(gboolean);
static void file_quit_answered_cb(gpointer dialog, gint btn, gpointer data);
static void main_save_window_geometry(GtkWidget *widget);


/* Match selected byte pattern */
static void
match_selected_cb_do(gpointer data, int action, gchar *text)
{
    GtkWidget  *filter_te;
    char       *cur_filter, *new_filter;

    if ((!text) || (0 == strlen(text))) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not acquire information to build a filter!\nTry expanding or choosing another item.");
        return;
    }

    g_assert(data);
    filter_te = g_object_get_data(G_OBJECT(data), E_DFILTER_TE_KEY);
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

    /* Don't change the current display filter if we only want to copy the filter */
    if (action&MATCH_SELECTED_COPY_ONLY) {
        GString *gtk_text_str = g_string_new("");
        g_string_append(gtk_text_str, new_filter);
        copy_to_clipboard(gtk_text_str);
        g_string_free(gtk_text_str, TRUE);
    } else {
        /* create a new one and set the display filter entry accordingly */
        gtk_entry_set_text(GTK_ENTRY(filter_te), new_filter);

        /* Run the display filter so it goes in effect. */
        if (action&MATCH_SELECTED_APPLY_NOW)
            main_filter_packets(&cfile, new_filter, FALSE);
    }

    /* Free up the new filter text. */
    g_free(new_filter);
}

void
match_selected_ptree_cb(GtkWidget *w, gpointer data, MATCH_SELECTED_E action)
{
    char *filter = NULL;

    if (cfile.finfo_selected) {
        filter = proto_construct_match_selected_string(cfile.finfo_selected,
                                                       cfile.edt);
        match_selected_cb_do((data ? data : w), action, filter);
    }
}

void
colorize_selected_ptree_cb(GtkWidget *w _U_, gpointer data _U_, guint8 filt_nr)
{
    char *filter = NULL;

    if (cfile.finfo_selected) {
        filter = proto_construct_match_selected_string(cfile.finfo_selected,
                                                       cfile.edt);
        if ((!filter) || (0 == strlen(filter))) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "Could not acquire information to build a filter!\n"
                "Try expanding or choosing another item.");
            return;
        }

        if (filt_nr==0) {
            color_display_with_filter(filter);
        } else {
            if (filt_nr==255) {
                color_filters_reset_tmp();
            } else {
                color_filters_set_tmp(filt_nr,filter, FALSE);
            }
            new_packet_list_colorize_packets();
        }
    }
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

        if (!proto_is_private(field_id)) {
            /* ask the user if the wiki page really should be opened */
            dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_OK_CANCEL,
                    "%sOpen Wireshark Wiki page of protocol \"%s\"?%s\n"
                    "\n"
                    "This will open the \"%s\" related Wireshark Wiki page in your Web browser.\n"
                    "\n"
                    "The Wireshark Wiki is a collaborative approach to provide information "
                    "about Wireshark in several ways (not limited to protocol specifics).\n"
                    "\n"
                    "This Wiki is new, so the page of the selected protocol "
                    "may not exist and/or may not contain valuable information.\n"
                    "\n"
                    "As everyone can edit the Wiki and add new content (or extend existing), "
                    "you are encouraged to add information if you can.\n"
                    "\n"
                    "Hint 1: If you are new to wiki editing, try out editing the Sandbox first!\n"
                    "\n"
                    "Hint 2: If you want to add a new protocol page, you should use the ProtocolTemplate, "
                    "which will save you a lot of editing and will give a consistent look over the pages.",
                    simple_dialog_primary_start(), proto_abbrev, simple_dialog_primary_end(), proto_abbrev);
            simple_dialog_set_cb(dialog, selected_ptree_info_answered_cb, (gpointer)proto_abbrev);
        } else {
            /* appologize to the user that the wiki page cannot be opened */
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                    "%sCan't open Wireshark Wiki page of protocol \"%s\"%s\n"
                    "\n"
                    "This would open the \"%s\" related Wireshark Wiki page in your Web browser.\n"
                    "\n"
                    "Since this is a private protocol, such information is not available in "
                    "a public wiki. Therefore this wiki entry is blocked.\n"
                    "\n"
                    "Sorry for the inconvenience.\n",
                    simple_dialog_primary_start(), proto_abbrev, simple_dialog_primary_end(), proto_abbrev);
        }
    }
}

static void selected_ptree_ref_answered_cb(gpointer dialog _U_, gint btn, gpointer data)
{
    gchar *selected_proto_url;
    gchar *proto_abbrev = data;

    switch(btn) {
    case(ESD_BTN_OK):
        if (cfile.finfo_selected) {
            /* open reference page using the protocol abbreviation */
            selected_proto_url = g_strdup_printf("http://www.wireshark.org/docs/dfref/%c/%s", proto_abbrev[0], proto_abbrev);
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
selected_ptree_ref_cb(GtkWidget *widget _U_, gpointer data _U_)
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

        if (!proto_is_private(field_id)) {
            /* ask the user if the wiki page really should be opened */
            dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_OK_CANCEL,
                    "%sOpen Wireshark filter reference page of protocol \"%s\"?%s\n"
                    "\n"
                    "This will open the \"%s\" related Wireshark filter reference page in your Web browser.\n"
                    "\n",
                    simple_dialog_primary_start(), proto_abbrev, simple_dialog_primary_end(), proto_abbrev);
            simple_dialog_set_cb(dialog, selected_ptree_ref_answered_cb, (gpointer)proto_abbrev);
        } else {
            /* appologize to the user that the wiki page cannot be opened */
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                    "%sCan't open Wireshark filter reference page of protocol \"%s\"%s\n"
                    "\n"
                    "This would open the \"%s\" related Wireshark filter reference page in your Web browser.\n"
                    "\n"
                    "Since this is a private protocol, such information is not available on "
                    "a public website. Therefore this filter entry is blocked.\n"
                    "\n"
                    "Sorry for the inconvenience.\n",
                    simple_dialog_primary_start(), proto_abbrev, simple_dialog_primary_end(), proto_abbrev);
        }
    }
}

static gboolean
is_address_column (gint column)
{
  if (((cfile.cinfo.col_fmt[column] == COL_DEF_SRC) ||
       (cfile.cinfo.col_fmt[column] == COL_RES_SRC) ||
       (cfile.cinfo.col_fmt[column] == COL_DEF_DST) ||
       (cfile.cinfo.col_fmt[column] == COL_RES_DST)) &&
      strlen(cfile.cinfo.col_expr.col_expr_val[column]))
  {
    return TRUE;
  }

  return FALSE;
}

GList *
get_ip_address_list_from_packet_list_row(gpointer data)
{
    gint    row = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(data), E_MPACKET_LIST_ROW_KEY));
    gint    column = new_packet_list_get_column_id (GPOINTER_TO_INT(g_object_get_data(G_OBJECT(data), E_MPACKET_LIST_COL_KEY)));
    gint    col;
    frame_data *fdata;
    GList      *addr_list = NULL;

    fdata = (frame_data *) new_packet_list_get_row_data(row);

    if (fdata != NULL) {
        epan_dissect_t edt;

        if (!cf_read_frame (&cfile, fdata))
            return NULL; /* error reading the frame */

        epan_dissect_init(&edt, FALSE, FALSE);
        col_custom_prime_edt(&edt, &cfile.cinfo);

        epan_dissect_run(&edt, &cfile.pseudo_header, cfile.pd, fdata, &cfile.cinfo);
        epan_dissect_fill_in_columns(&edt, TRUE, TRUE);

	/* First check selected column */
	if (is_address_column (column)) {
	  addr_list = g_list_append (addr_list, se_strdup_printf("%s", cfile.cinfo.col_expr.col_expr_val[column]));
        }

	for (col = 0; col < cfile.cinfo.num_cols; col++) {
	  /* Then check all columns except the selected */
	  if ((col != column) && (is_address_column (col))) {
	    addr_list = g_list_append (addr_list, se_strdup_printf("%s", cfile.cinfo.col_expr.col_expr_val[col]));
	  }
	}

        epan_dissect_cleanup(&edt);
    }

    return addr_list;
}

static gchar *
get_filter_from_packet_list_row_and_column(gpointer data)
{
    gint    row = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(data), E_MPACKET_LIST_ROW_KEY));
    gint    column = new_packet_list_get_column_id (GPOINTER_TO_INT(g_object_get_data(G_OBJECT(data), E_MPACKET_LIST_COL_KEY)));
    frame_data *fdata;
    gchar      *buf=NULL;

    fdata = (frame_data *) new_packet_list_get_row_data(row);

    if (fdata != NULL) {
        epan_dissect_t edt;

        if (!cf_read_frame(&cfile, fdata))
            return NULL; /* error reading the frame */
        /* proto tree, visible. We need a proto tree if there's custom columns */
        epan_dissect_init(&edt, have_custom_cols(&cfile.cinfo), FALSE);
        col_custom_prime_edt(&edt, &cfile.cinfo);

        epan_dissect_run(&edt, &cfile.pseudo_header, cfile.pd, fdata,
                 &cfile.cinfo);
        epan_dissect_fill_in_columns(&edt, TRUE, TRUE);

        if ((cfile.cinfo.col_custom_occurrence[column]) ||
            (strchr (cfile.cinfo.col_expr.col_expr_val[column], ',') == NULL))
        {
            /* Only construct the filter when a single occurrence is displayed
             * otherwise we might end up with a filter like "ip.proto==1,6".
             *
             * Or do we want to be able to filter on multiple occurrences so that
             * the filter might be calculated as "ip.proto==1 && ip.proto==6"
             * instead?
             */
            if (strlen(cfile.cinfo.col_expr.col_expr[column]) != 0 &&
                strlen(cfile.cinfo.col_expr.col_expr_val[column]) != 0) {
                /* leak a little but safer than ep_ here */
                if (cfile.cinfo.col_fmt[column] == COL_CUSTOM) {
                    header_field_info *hfi = proto_registrar_get_byname(cfile.cinfo.col_custom_field[column]);
                    if (hfi->parent == -1) {
                        /* Protocol only */
                        buf = se_strdup(cfile.cinfo.col_expr.col_expr[column]);
                    } else if (hfi->type == FT_STRING) {
                        /* Custom string, add quotes */
                        buf = se_strdup_printf("%s == \"%s\"", cfile.cinfo.col_expr.col_expr[column],
                                               cfile.cinfo.col_expr.col_expr_val[column]);
                    }
                }
                if (buf == NULL) {
                    buf = se_strdup_printf("%s == %s", cfile.cinfo.col_expr.col_expr[column],
                                           cfile.cinfo.col_expr.col_expr_val[column]);
                }
            }
        }

        epan_dissect_cleanup(&edt);
    }

    return buf;
}

void
match_selected_plist_cb(GtkWidget *w _U_, gpointer data, MATCH_SELECTED_E action)
{
    match_selected_cb_do(data,
        action,
        get_filter_from_packet_list_row_and_column(data));
}

/* This function allows users to right click in the details window and copy the text
 * information to the operating systems clipboard.
 *
 * We first check to see if a string representation is setup in the tree and then
 * read the string. If not available then we try to grab the value. If all else
 * fails we display a message to the user to indicate the copy could not be completed.
 */
void
copy_selected_plist_cb(GtkWidget *w _U_, gpointer data _U_, COPY_SELECTED_E action)
{
    GString *gtk_text_str = g_string_new("");
    char labelstring[256];
    char *stringpointer = labelstring;

    switch(action)
    {
    case COPY_SELECTED_DESCRIPTION:
        if (cfile.finfo_selected->rep &&
            strlen (cfile.finfo_selected->rep->representation) > 0) {
            g_string_append(gtk_text_str, cfile.finfo_selected->rep->representation);
        }
        break;
    case COPY_SELECTED_FIELDNAME:
        if (cfile.finfo_selected->hfinfo->abbrev != 0) {
            g_string_append(gtk_text_str, cfile.finfo_selected->hfinfo->abbrev);
        }
        break;
    case COPY_SELECTED_VALUE:
        if (cfile.edt !=0 ) {
            g_string_append(gtk_text_str,
                    get_node_field_value(cfile.finfo_selected, cfile.edt));
        }
        break;
    default:
        break;
    }

    if (gtk_text_str->len == 0) {
        /* If no representation then... Try to read the value */
        proto_item_fill_label(cfile.finfo_selected, stringpointer);
        g_string_append(gtk_text_str, stringpointer);
    }

    if (gtk_text_str->len == 0) {
        /* Could not get item so display error msg */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not acquire information to copy, try expanding or choosing another item");
    } else {
        /* Copy string to clipboard */
        copy_to_clipboard(gtk_text_str);
    }
    g_string_free(gtk_text_str, TRUE);                       /* Free the memory */
}


/* mark as reference time frame */
void
set_frame_reftime(gboolean set, frame_data *frame, gint row) {
  if (row == -1)
    return;
  if (set) {
    frame->flags.ref_time=1;
	cfile.ref_time_count++;
  } else {
    frame->flags.ref_time=0;
    cfile.ref_time_count--;
  }
  cf_reftime_packets(&cfile);
  if (!frame->flags.ref_time && !frame->flags.passed_dfilter) {
    new_packet_list_freeze();
    cfile.displayed_count--;
    new_packet_list_recreate_visible_rows();
    new_packet_list_thaw();
  }
  new_packet_list_queue_draw();
}


static void reftime_answered_cb(gpointer dialog _U_, gint btn, gpointer data _U_)
{
    switch(btn) {
    case(ESD_BTN_YES):
        timestamp_set_type(TS_RELATIVE);
        recent.gui_time_format  = TS_RELATIVE;
		cf_timestamp_auto_precision(&cfile);
		new_packet_list_queue_draw();
        break;
    case(ESD_BTN_NO):
        break;
    default:
        g_assert_not_reached();
    }

    if (cfile.current_frame) {
      set_frame_reftime(!cfile.current_frame->flags.ref_time,
			cfile.current_frame, cfile.current_row);
    }
}


void
reftime_frame_cb(GtkWidget *w _U_, gpointer data _U_, REFTIME_ACTION_E action)
{
  static GtkWidget *reftime_dialog = NULL;

  switch(action){
  case REFTIME_TOGGLE:
    if (cfile.current_frame) {
        if(recent.gui_time_format != TS_RELATIVE && cfile.current_frame->flags.ref_time==0) {
            reftime_dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_YES_NO,
                "%sSwitch to the appropriate Time Display Format?%s\n\n"
                "Time References don't work well with the currently selected Time Display Format.\n\n"
                "Do you want to switch to \"Seconds Since Beginning of Capture\" now?",
                simple_dialog_primary_start(), simple_dialog_primary_end());
            simple_dialog_set_cb(reftime_dialog, reftime_answered_cb, NULL);
        } else {
            set_frame_reftime(!cfile.current_frame->flags.ref_time,
                              cfile.current_frame, cfile.current_row);
        }
    }
    break;
  case REFTIME_FIND_NEXT:
    cf_find_packet_time_reference(&cfile, SD_FORWARD);
    break;
  case REFTIME_FIND_PREV:
    cf_find_packet_time_reference(&cfile, SD_BACKWARD);
    break;
  }
}

void
find_next_mark_cb(GtkWidget *w _U_, gpointer data _U_, int action _U_)
{
    cf_find_packet_marked(&cfile, SD_FORWARD);
}

void
find_prev_mark_cb(GtkWidget *w _U_, gpointer data _U_, int action _U_)
{
    cf_find_packet_marked(&cfile, SD_BACKWARD);
}

static void
tree_view_selection_changed_cb(GtkTreeSelection *sel, gpointer user_data _U_)
{
    field_info   *finfo;
    gchar         len_str[2+10+1+5+1]; /* ", {N} bytes\0",
                                          N < 4294967296 */
    gboolean      has_blurb = FALSE;
    guint         length = 0, byte_len;
    GtkWidget    *byte_view;
    const guint8 *byte_data;
    gint          finfo_length;
    GtkTreeModel *model;
    GtkTreeIter   iter;

    /* if nothing is selected */
    if (!gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        /*
         * Which byte view is displaying the current protocol tree
         * row's data?
         */
        byte_view = get_notebook_bv_ptr(byte_nb_ptr_gbl);
        if (byte_view == NULL)
            return;	/* none */

        byte_data = get_byte_view_data_and_length(byte_view, &byte_len);
        if (byte_data == NULL)
            return;	/* none */

        cf_unselect_field(&cfile);
        packet_hex_print(byte_view, byte_data,
                         cfile.current_frame, NULL, byte_len);
        proto_help_menu_modify(sel, &cfile);
        return;
    }
    gtk_tree_model_get(model, &iter, 1, &finfo, -1);
    if (!finfo) return;

    set_notebook_page(byte_nb_ptr_gbl, finfo->ds_tvb);

    byte_view = get_notebook_bv_ptr(byte_nb_ptr_gbl);
    byte_data = get_byte_view_data_and_length(byte_view, &byte_len);
    g_assert(byte_data != NULL);

    cfile.finfo_selected = finfo;
    set_menus_for_selected_tree_row(&cfile);

    if (finfo->hfinfo) {
        if (finfo->hfinfo->blurb != NULL &&
            finfo->hfinfo->blurb[0] != '\0') {
            has_blurb = TRUE;
            length = (guint) strlen(finfo->hfinfo->blurb);
        } else {
            length = (guint) strlen(finfo->hfinfo->name);
        }
        finfo_length = finfo->length + finfo->appendix_length;

        if (finfo_length == 0) {
            len_str[0] = '\0';
        } else if (finfo_length == 1) {
            g_strlcpy (len_str, ", 1 byte", sizeof len_str);
        } else {
            g_snprintf (len_str, sizeof len_str, ", %d bytes", finfo_length);
        }
        statusbar_pop_field_msg();	/* get rid of current help msg */
        if (length) {
            statusbar_push_field_msg(" %s (%s)%s",
                    (has_blurb) ? finfo->hfinfo->blurb : finfo->hfinfo->name,
                    finfo->hfinfo->abbrev, len_str);
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
            statusbar_push_field_msg("%s", "");
        }
    }
    packet_hex_print(byte_view, byte_data, cfile.current_frame, finfo,
                     byte_len);
    proto_help_menu_modify(sel, &cfile);
}

void collapse_all_cb(GtkWidget *widget _U_, gpointer data _U_) {
  if (cfile.edt->tree)
    collapse_all_tree(cfile.edt->tree, tree_view_gbl);
}

void expand_all_cb(GtkWidget *widget _U_, gpointer data _U_) {
  if (cfile.edt->tree)
    expand_all_tree(cfile.edt->tree, tree_view_gbl);
}

void apply_as_custom_column_cb (GtkWidget *widget _U_, gpointer data _U_)
{
  if (cfile.finfo_selected) {
    column_prefs_add_custom(COL_CUSTOM, cfile.finfo_selected->hfinfo->name,
                            cfile.finfo_selected->hfinfo->abbrev,0);
    /* Recreate the packet list according to new preferences */
    new_packet_list_recreate ();
    if (!prefs.gui_use_pref_save) {
      prefs_main_write();
    }
    cfile.cinfo.columns_changed = FALSE; /* Reset value */
  }
}

void expand_tree_cb(GtkWidget *widget _U_, gpointer data _U_) {
  GtkTreePath  *path;

  path = tree_find_by_field_info(GTK_TREE_VIEW(tree_view_gbl), cfile.finfo_selected);
  if(path) {
    /* the mouse position is at an entry, expand that one */
    gtk_tree_view_expand_row(GTK_TREE_VIEW(tree_view_gbl), path, TRUE);
    gtk_tree_path_free(path);
  }
}

void resolve_name_cb(GtkWidget *widget _U_, gpointer data _U_) {
  if (cfile.edt->tree) {
    guint32 tmp = gbl_resolv_flags;
    gbl_resolv_flags = RESOLV_ALL;
    proto_tree_draw(cfile.edt->tree, tree_view_gbl);
    gbl_resolv_flags = tmp;
  }
}

static void
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
	write_profile_recent();
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
	capture_kill_child(&global_capture_opts);
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
    gtk_window_present(GTK_WINDOW(top_level));
    /* user didn't saved his current file, ask him */
    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_QUIT_DONTSAVE_CANCEL,
                "%sSave capture file before program quit?%s\n\n"
                "If you quit the program without saving, your capture data will be discarded.",
                simple_dialog_primary_start(), simple_dialog_primary_end());
    simple_dialog_set_cb(dialog, file_quit_answered_cb, NULL);
    return TRUE;
  } else {
    /* unchanged file, just exit */
    /* "main_do_quit()" indicates whether the main window should be deleted. */
    return main_do_quit();
  }
}


static void
main_pane_load_window_geometry(void)
{
    if (recent.has_gui_geometry_main_upper_pane && recent.gui_geometry_main_upper_pane)
        gtk_paned_set_position(GTK_PANED(main_first_pane), recent.gui_geometry_main_upper_pane);
    if (recent.has_gui_geometry_main_lower_pane && recent.gui_geometry_main_lower_pane) {
        gtk_paned_set_position(GTK_PANED(main_second_pane), recent.gui_geometry_main_lower_pane);
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

    main_pane_load_window_geometry();
    statusbar_load_window_geometry();
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
        recent.gui_geometry_main_width  = geom.width;
        recent.gui_geometry_main_height = geom.height;
    }

    if(prefs.gui_geometry_save_maximized) {
        recent.gui_geometry_main_maximized = geom.maximized;
    }

    recent.gui_geometry_main_upper_pane     = gtk_paned_get_position(GTK_PANED(main_first_pane));
    recent.gui_geometry_main_lower_pane     = gtk_paned_get_position(GTK_PANED(main_second_pane));
    statusbar_save_window_geometry();
}

static void file_quit_answered_cb(gpointer dialog _U_, gint btn, gpointer data _U_)
{
    switch(btn) {
    case(ESD_BTN_SAVE):
        /* save file first */
        file_save_as_cmd(after_save_exit, NULL);
        break;
    case(ESD_BTN_QUIT_DONT_SAVE):
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
    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_QUIT_DONTSAVE_CANCEL,
                "%sSave capture file before program quit?%s\n\n"
                "If you quit the program without saving, your capture data will be discarded.",
                simple_dialog_primary_start(), simple_dialog_primary_end());
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
	wireshark_svnversion, get_copyright_info());
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
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
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
  fprintf(output, "  -C <config profile>      start with specified configuration profile\n");
  fprintf(output, "  -g <packet number>       go to specified packet number after \"-r\"\n");
  fprintf(output, "  -J <jump filter>         jump to the first packet matching the (display)\n");
  fprintf(output, "                           filter\n");
  fprintf(output, "  -j                       search backwards for a matching packet after \"-J\"\n");
  fprintf(output, "  -m <font>                set the font name used for most text\n");
  fprintf(output, "  -t ad|a|r|d|dd|e         output format of time stamps (def: r: rel. to first)\n");
  fprintf(output, "  -u s|hms                 output format of seconds (def: s: seconds)\n");
  fprintf(output, "  -X <key>:<value>         eXtension options, see man page for details\n");
  fprintf(output, "  -z <statistics>          show various statistics, see man page for details\n");

  fprintf(output, "\n");
  fprintf(output, "Output:\n");
  fprintf(output, "  -w <outfile|->           set the output filename (or '-' for stdout)\n");

  fprintf(output, "\n");
  fprintf(output, "Miscellaneous:\n");
  fprintf(output, "  -h                       display this help and exit\n");
  fprintf(output, "  -v                       display version info and exit\n");
  fprintf(output, "  -P <key>:<path>          persconf:path - personal configuration files\n");
  fprintf(output, "                           persdata:path - personal data files\n");
  fprintf(output, "  -o <name>:<value> ...    override preference or recent setting\n");
  fprintf(output, "  -K <keytab>              keytab file to use for kerberos decryption\n");
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
      wireshark_svnversion, get_copyright_info(), comp_info_str->str,
      runtime_info_str->str);

#ifdef _WIN32
  destroy_console();
#endif
}

/*
 * Print to the standard error.  On Windows, create a console for the
 * standard error to show up on, if necessary.
 * XXX - pop this up in a window of some sort on UNIX+X11 if the controlling
 * terminal isn't the standard error?
 */
void
vfprintf_stderr(const char *fmt, va_list ap)
{
#ifdef _WIN32
  create_console();
#endif
  vfprintf(stderr, fmt, ap);
}

void
fprintf_stderr(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vfprintf_stderr(fmt, ap);
  va_end(ap);
}

/*
 * Report an error in command-line arguments.
 * Creates a console on Windows.
 */
void
cmdarg_err(const char *fmt, ...)
{
  va_list ap;

  fprintf_stderr("wireshark: ");
  va_start(ap, fmt);
  vfprintf_stderr(fmt, ap);
  va_end(ap);
  fprintf_stderr("\n");
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

  va_start(ap, fmt);
  vfprintf_stderr(fmt, ap);
  fprintf_stderr("\n");
  va_end(ap);
}

/*
   Once every 3 seconds we get a callback here which we use to update
   the tap extensions.
 */
static gboolean
tap_update_cb(gpointer data _U_)
{
	draw_tap_listeners(FALSE);
	return TRUE;
}

/* Restart the tap update display timer with new configured interval */
void reset_tap_update_timer(void)
{
    g_source_remove(tap_update_timer_id);
    tap_update_timer_id = g_timeout_add(prefs.tap_update_interval, tap_update_cb, NULL);
}

void
protect_thread_critical_region(void)
{
	/* Threading support for TAP:s removed
	 * http://www.wireshark.org/lists/wireshark-dev/200611/msg00199.html
	 * See the commit for removed code:
	 * http://anonsvn.wireshark.org/viewvc/viewvc.cgi?view=rev&revision=35027
	 */
}
void
unprotect_thread_critical_region(void)
{
	/* Threading support for TAP:s removed
	 * http://www.wireshark.org/lists/wireshark-dev/200611/msg00199.html
	 */

}

/*
 * Periodically process outstanding hostname lookups. If we have new items,
 * redraw the packet list and tree view.
 */

static gboolean
resolv_update_cb(gpointer data _U_)
{
  /* Anything new show up? */
  if (host_name_lookup_process(NULL)) {
#if GTK_CHECK_VERSION(2,14,0)
    if (gtk_widget_get_window(pkt_scrollw))
	gdk_window_invalidate_rect(gtk_widget_get_window(pkt_scrollw), NULL, TRUE);
    if (gtk_widget_get_window(tv_scrollw))
	gdk_window_invalidate_rect(gtk_widget_get_window(tv_scrollw), NULL, TRUE);
#else
    if (pkt_scrollw->window)
	gdk_window_invalidate_rect(pkt_scrollw->window, NULL, TRUE);
    if (tv_scrollw->window)
	gdk_window_invalidate_rect(tv_scrollw->window, NULL, TRUE);
#endif
  }

  /* Always check. Even if we don't do async lookups we could still get
     passive updates, e.g. from DNS packets. */
  return TRUE;
}


/* Set main_window_name and it's icon title to the capture filename */
static void
set_display_filename(capture_file *cf)
{
  gchar *window_name;

  if (cf->filename) {
    window_name = g_strdup_printf("%s", cf_get_display_name(cf));
    set_main_window_name(window_name);
    g_free(window_name);
  } else {
    set_main_window_name("The Wireshark Network Analyzer");
  }
}

static GtkWidget           *close_dlg = NULL;

static void
priv_warning_dialog_cb(gpointer dialog, gint btn _U_, gpointer data _U_)
{
    recent.privs_warn_if_elevated = !simple_dialog_check_get(dialog);
}

#ifdef _WIN32
static void
npf_warning_dialog_cb(gpointer dialog, gint btn _U_, gpointer data _U_)
{
    recent.privs_warn_if_no_npf = !simple_dialog_check_get(dialog);
}
#endif

static void
main_cf_cb_file_closing(capture_file *cf)
{

    /* if we have more than 10000 packets, show a splash screen while closing */
    /* XXX - don't know a better way to decide whether to show or not,
     * as most of the time is spend in a single eth_clist_clear function,
     * so we can't use a progress bar here! */
    if(cf->count > 10000) {
        close_dlg = simple_dialog(ESD_TYPE_STOP, ESD_BTN_NONE,
                                  "%sClosing file!%s\n\nPlease wait ...",
                                  simple_dialog_primary_start(),
                                  simple_dialog_primary_end());
        gtk_window_set_position(GTK_WINDOW(close_dlg), GTK_WIN_POS_CENTER_ON_PARENT);
    }

    /* Destroy all windows, which refer to the
       capture file we're closing. */
    destroy_packet_wins();
    file_save_as_destroy();

    /* Restore the standard title bar message. */
    set_main_window_name("The Wireshark Network Analyzer");

    /* Disable all menu items that make sense only if you have a capture. */
    set_menus_for_capture_file(NULL);
    set_menus_for_captured_packets(FALSE);
    set_menus_for_selected_packet(cf);
    set_menus_for_capture_in_progress(FALSE);
    set_capture_if_dialog_for_capture_in_progress(FALSE);
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
}


static void
main_cf_cb_file_read_started(capture_file *cf _U_)
{
  tap_param_dlg_update();

  /* Set up main window for a capture file. */
  main_set_for_capture_file(TRUE);
}

static void
main_cf_cb_file_read_finished(capture_file *cf)
{
    gchar *dir_path;

    if (!cf->is_tempfile && cf->filename) {
        /* Add this filename to the list of recent files in the "Recent Files" submenu */
        add_menu_recent_capture_file(cf->filename);

        /* Remember folder for next Open dialog and save it in recent */
	dir_path = get_dirname(g_strdup(cf->filename));
        set_last_open_dir(dir_path);
        g_free(dir_path);
    }
    set_display_filename(cf);

    /* Enable menu items that make sense if you have a capture file you've
       finished reading. */
    set_menus_for_capture_file(cf);

    /* Enable menu items that make sense if you have some captured packets. */
    set_menus_for_captured_packets(TRUE);
}

#ifdef HAVE_LIBPCAP
static GList *icon_list_create(
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

static void
main_capture_set_main_window_title(capture_options *capture_opts)
{
    GString *title = g_string_new("");

    g_string_append(title, "Capturing ");
    g_string_append_printf(title, "from %s ", cf_get_tempfile_source(capture_opts->cf));
    set_main_window_name(title->str);
    g_string_free(title, TRUE);
}

static void
main_capture_cb_capture_prepared(capture_options *capture_opts)
{
    static GList *icon_list = NULL;

    main_capture_set_main_window_title(capture_opts);

    if(icon_list == NULL) {
        icon_list = icon_list_create(wsiconcap16_xpm, wsiconcap32_xpm, wsiconcap48_xpm, NULL);
    }
    gtk_window_set_icon_list(GTK_WINDOW(top_level), icon_list);

    /* Disable menu items that make no sense if you're currently running
       a capture. */
    set_menus_for_capture_in_progress(TRUE);
    set_capture_if_dialog_for_capture_in_progress(TRUE);

    /* Don't set up main window for a capture file. */
    main_set_for_capture_file(FALSE);
}

static void
main_capture_cb_capture_update_started(capture_options *capture_opts)
{
    /* We've done this in "prepared" above, but it will be cleared while
       switching to the next multiple file. */
    main_capture_set_main_window_title(capture_opts);

    set_menus_for_capture_in_progress(TRUE);
    set_capture_if_dialog_for_capture_in_progress(TRUE);

    /* Enable menu items that make sense if you have some captured
       packets (yes, I know, we don't have any *yet*). */
    set_menus_for_captured_packets(TRUE);

    /* Set up main window for a capture file. */
    main_set_for_capture_file(TRUE);
}

static void
main_capture_cb_capture_update_finished(capture_options *capture_opts)
{
    capture_file *cf = capture_opts->cf;
    static GList *icon_list = NULL;

    if (!cf->is_tempfile && cf->filename) {
        /* Add this filename to the list of recent files in the "Recent Files" submenu */
        add_menu_recent_capture_file(cf->filename);
    }
    set_display_filename(cf);

    /* Enable menu items that make sense if you're not currently running
     a capture. */
    set_menus_for_capture_in_progress(FALSE);
    set_capture_if_dialog_for_capture_in_progress(FALSE);

    /* Enable menu items that make sense if you have a capture file
       you've finished reading. */
    set_menus_for_capture_file(cf);

    /* Set up main window for a capture file. */
    main_set_for_capture_file(TRUE);

    if(icon_list == NULL) {
        icon_list = icon_list_create(wsicon16_xpm, wsicon32_xpm, wsicon48_xpm, wsicon64_xpm);
    }
    gtk_window_set_icon_list(GTK_WINDOW(top_level), icon_list);

    if(global_capture_opts.quit_after_cap) {
        /* command line asked us to quit after the capture */
        /* don't pop up a dialog to ask for unsaved files etc. */
        main_do_quit();
    }
}

static void
main_capture_cb_capture_fixed_started(capture_options *capture_opts _U_)
{
    /* Don't set up main window for a capture file. */
    main_set_for_capture_file(FALSE);
}

static void
main_capture_cb_capture_fixed_finished(capture_options *capture_opts _U_)
{
#if 0
    capture_file *cf = capture_opts->cf;
#endif
    static GList *icon_list = NULL;

    /*set_display_filename(cf);*/

    /* Enable menu items that make sense if you're not currently running
     a capture. */
    set_menus_for_capture_in_progress(FALSE);
    set_capture_if_dialog_for_capture_in_progress(FALSE);

    /* Restore the standard title bar message */
    /* (just in case we have trouble opening the capture file). */
    set_main_window_name("The Wireshark Network Analyzer");

    if(icon_list == NULL) {
        icon_list = icon_list_create(wsicon16_xpm, wsicon32_xpm, wsicon48_xpm, wsicon64_xpm);
    }
    gtk_window_set_icon_list(GTK_WINDOW(top_level), icon_list);

    /* We don't have loaded the capture file, this will be done later.
     * For now we still have simply a blank screen. */

    if(global_capture_opts.quit_after_cap) {
        /* command line asked us to quit after the capture */
        /* don't pop up a dialog to ask for unsaved files etc. */
        main_do_quit();
    }
}

#endif  /* HAVE_LIBPCAP */

static void
main_cf_cb_packet_selected(gpointer data)
{
    capture_file *cf = data;

    /* Display the GUI protocol tree and packet bytes.
      XXX - why do we dump core if we call "proto_tree_draw()"
      before calling "add_byte_views()"? */
    add_main_byte_views(cf->edt);
    main_proto_tree_draw(cf->edt->tree);

    /* Note: Both string and hex value searches in the packet data produce a non-zero
       search_pos if successful */
    if(cf->search_in_progress &&
      (cf->search_pos != 0 || (cf->string && cf->decode_data))) {
        highlight_field(cf->edt->tvb, cf->search_pos,
                        (GtkTreeView *)tree_view_gbl, cf->edt->tree);
    }

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
    set_menus_for_selected_tree_row(cf);
}

static void
main_cf_cb_file_save_reload_finished(gpointer data _U_)
{
    set_display_filename(&cfile);
    set_menus_for_capture_file(&cfile);
}

static void
main_cf_callback(gint event, gpointer data, gpointer user_data _U_)
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
    case(cf_cb_file_read_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read started");
        main_cf_cb_file_read_started(data);
        break;
    case(cf_cb_file_read_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read finished");
        main_cf_cb_file_read_finished(data);
        break;
    case(cf_cb_packet_selected):
        main_cf_cb_packet_selected(data);
        break;
    case(cf_cb_packet_unselected):
        main_cf_cb_packet_unselected(data);
        break;
    case(cf_cb_field_unselected):
        main_cf_cb_field_unselected(data);
        break;
    case(cf_cb_file_save_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save started");
        break;
    case(cf_cb_file_save_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save finished");
        break;
    case(cf_cb_file_save_reload_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Reload finished");
        main_cf_cb_file_save_reload_finished(data);
        break;
    case(cf_cb_file_save_failed):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save failed");
        break;
    default:
        g_warning("main_cf_callback: event %u unknown", event);
        g_assert_not_reached();
    }
}

#ifdef HAVE_LIBPCAP
static void
main_capture_callback(gint event, capture_options *capture_opts, gpointer user_data _U_)
{
#ifdef HAVE_GTKOSXAPPLICATION
    GtkOSXApplication *theApp;
#endif
    switch(event) {
    case(capture_cb_capture_prepared):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture prepared");
        main_capture_cb_capture_prepared(capture_opts);
        break;
    case(capture_cb_capture_update_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update started");
        main_capture_cb_capture_update_started(capture_opts);
#ifdef HAVE_GTKOSXAPPLICATION
        theApp = g_object_new(GTK_TYPE_OSX_APPLICATION, NULL);
        gtk_osxapplication_set_dock_icon_pixbuf(theApp,gdk_pixbuf_new_from_xpm_data(wsiconcap48_xpm));
#endif
        break;
    case(capture_cb_capture_update_continue):
        /*g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update continue");*/
        break;
    case(capture_cb_capture_update_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update finished");
        main_capture_cb_capture_update_finished(capture_opts);
        break;
    case(capture_cb_capture_fixed_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed started");
        main_capture_cb_capture_fixed_started(capture_opts);
        break;
    case(capture_cb_capture_fixed_continue):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed continue");
        break;
    case(capture_cb_capture_fixed_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed finished");
        main_capture_cb_capture_fixed_finished(capture_opts);
        break;
    case(capture_cb_capture_stopping):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture stopping");
        /* Beware: this state won't be called, if the capture child
         * closes the capturing on it's own! */
#ifdef HAVE_GTKOSXAPPLICATION
        theApp = g_object_new(GTK_TYPE_OSX_APPLICATION, NULL);
        gtk_osxapplication_set_dock_icon_pixbuf(theApp,gdk_pixbuf_new_from_xpm_data(wsicon64_xpm));
#endif
        break;
    default:
        g_warning("main_capture_callback: event %u unknown", event);
        g_assert_not_reached();
    }
}
#endif

static void
get_gtk_compiled_info(GString *str)
{
  g_string_append(str, "with ");
  g_string_append_printf(str,
#ifdef GTK_MAJOR_VERSION
                    "GTK+ %d.%d.%d", GTK_MAJOR_VERSION, GTK_MINOR_VERSION,
                    GTK_MICRO_VERSION);
#else
                    "GTK+ (version unknown)");
#endif
  g_string_append(str, ", ");
}

static void
get_gui_compiled_info(GString *str)
{
  epan_get_compiled_version_info(str);

  g_string_append(str, ", ");
#ifdef HAVE_LIBPORTAUDIO
#ifdef PORTAUDIO_API_1
  g_string_append(str, "with PortAudio <= V18");
#else /* PORTAUDIO_API_1 */
  g_string_append(str, "with ");
  g_string_append(str, Pa_GetVersionText());
#endif /* PORTAUDIO_API_1 */
#else /* HAVE_LIBPORTAUDIO */
  g_string_append(str, "without PortAudio");
#endif /* HAVE_LIBPORTAUDIO */

  g_string_append(str, ", ");
#ifdef HAVE_AIRPCAP
  get_compiled_airpcap_version(str);
#else
  g_string_append(str, "without AirPcap");
#endif
}

static void
get_gui_runtime_info(GString *str)
{
  epan_get_runtime_version_info(str);

#ifdef HAVE_AIRPCAP
  g_string_append(str, ", ");
  get_runtime_airpcap_version(str);
#endif

  if(u3_active()) {
    g_string_append(str, ", ");
    u3_runtime_info(str);
  }
}

static e_prefs *
read_configuration_files(char **gdp_path, char **dp_path)
{
  int                  gpf_open_errno, gpf_read_errno;
  int                  cf_open_errno, df_open_errno;
  int                  gdp_open_errno, gdp_read_errno;
  int                  dp_open_errno, dp_read_errno;
  char                *gpf_path, *pf_path;
  char                *cf_path, *df_path;
  int                  pf_open_errno, pf_read_errno;
  e_prefs             *prefs_p;

  /* Read the preference files. */
  prefs_p = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
                     &pf_open_errno, &pf_read_errno, &pf_path);

  if (gpf_path != NULL) {
    if (gpf_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open global preferences file\n\"%s\": %s.", gpf_path,
        g_strerror(gpf_open_errno));
    }
    if (gpf_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "I/O error reading global preferences file\n\"%s\": %s.", gpf_path,
        g_strerror(gpf_read_errno));
    }
  }
  if (pf_path != NULL) {
    if (pf_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open your preferences file\n\"%s\": %s.", pf_path,
        g_strerror(pf_open_errno));
    }
    if (pf_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "I/O error reading your preferences file\n\"%s\": %s.", pf_path,
        g_strerror(pf_read_errno));
    }
    g_free(pf_path);
    pf_path = NULL;
  }

#ifdef _WIN32
  /* if the user wants a console to be always there, well, we should open one for him */
  if (prefs_p->gui_console_open == console_open_always) {
    create_console();
  }
#endif

  /* Read the capture filter file. */
  read_filter_list(CFILTER_LIST, &cf_path, &cf_open_errno);
  if (cf_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open your capture filter file\n\"%s\": %s.", cf_path,
        g_strerror(cf_open_errno));
      g_free(cf_path);
  }

  /* Read the display filter file. */
  read_filter_list(DFILTER_LIST, &df_path, &df_open_errno);
  if (df_path != NULL) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open your display filter file\n\"%s\": %s.", df_path,
        g_strerror(df_open_errno));
      g_free(df_path);
  }

  /* Read the disabled protocols file. */
  read_disabled_protos_list(gdp_path, &gdp_open_errno, &gdp_read_errno,
			    dp_path, &dp_open_errno, &dp_read_errno);
  if (*gdp_path != NULL) {
    if (gdp_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open global disabled protocols file\n\"%s\": %s.",
	*gdp_path, g_strerror(gdp_open_errno));
    }
    if (gdp_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "I/O error reading global disabled protocols file\n\"%s\": %s.",
	*gdp_path, g_strerror(gdp_read_errno));
    }
    g_free(*gdp_path);
    *gdp_path = NULL;
  }
  if (*dp_path != NULL) {
    if (dp_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "Could not open your disabled protocols file\n\"%s\": %s.", *dp_path,
        g_strerror(dp_open_errno));
    }
    if (dp_read_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
        "I/O error reading your disabled protocols file\n\"%s\": %s.", *dp_path,
        g_strerror(dp_read_errno));
    }
    g_free(*dp_path);
    *dp_path = NULL;
  }

  return prefs_p;
}

/*  Check if there's something important to tell the user during startup.
 *  We want to do this *after* showing the main window so that any windows
 *  we pop up will be above the main window.
 */
static void
#ifdef _WIN32
check_and_warn_user_startup(gchar *cf_name)
#else
check_and_warn_user_startup(gchar *cf_name _U_)
#endif
{
  gchar               *cur_user, *cur_group;
  gpointer             priv_warning_dialog;

  /* Tell the user not to run as root. */
  if (running_with_special_privs() && recent.privs_warn_if_elevated) {
    cur_user = get_cur_username();
    cur_group = get_cur_groupname();
    priv_warning_dialog = simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
      "Running as user \"%s\" and group \"%s\".\n"
      "This could be dangerous.", cur_user, cur_group);
    g_free(cur_user);
    g_free(cur_group);
    simple_dialog_check_set(priv_warning_dialog, "Don't show this message again.");
    simple_dialog_set_cb(priv_warning_dialog, priv_warning_dialog_cb, NULL);
  }

#ifdef _WIN32
  /* Warn the user if npf.sys isn't loaded. */
  if (!stdin_capture && !cf_name && !npf_sys_is_running() && recent.privs_warn_if_no_npf && get_os_major_version() >= 6) {
    priv_warning_dialog = simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
      "The NPF driver isn't running.  You may have trouble\n"
      "capturing or listing interfaces.");
    simple_dialog_check_set(priv_warning_dialog, "Don't show this message again.");
    simple_dialog_set_cb(priv_warning_dialog, npf_warning_dialog_cb, NULL);
  }
#endif

}


/* And now our feature presentation... [ fade to music ] */
int
main(int argc, char *argv[])
{
  char                *init_progfile_dir_error;
  char                *s;
  int                  opt;
  gboolean             arg_error = FALSE;

  extern int           info_update_freq;  /* Found in about_dlg.c. */
  const gchar         *filter;

#ifdef _WIN32
  WSADATA 	       wsaData;
#endif  /* _WIN32 */

  char                *rf_path;
  int                  rf_open_errno;
  char                *gdp_path, *dp_path;
  int                  err;
#ifdef HAVE_LIBPCAP
  gboolean             start_capture = FALSE;
  gboolean             list_link_layer_types = FALSE;
  GList               *if_list;
  gchar               *err_str;
#else
  gboolean             capture_option_specified = FALSE;
#ifdef _WIN32
#ifdef HAVE_AIRPCAP
  gchar               *err_str;
#endif
#endif
#endif
  gint                 pl_size = 280, tv_size = 95, bv_size = 75;
  gchar               *rc_file, *cf_name = NULL, *rfilter = NULL, *jfilter = NULL;
  dfilter_t           *rfcode = NULL;
  gboolean             rfilter_parse_failed = FALSE;
  e_prefs             *prefs_p;
  char                 badopt;
  GtkWidget           *splash_win = NULL;
  GLogLevelFlags       log_flags;
  guint                go_to_packet = 0;
  gboolean             jump_backwards = FALSE;
  dfilter_t           *jump_to_filter = NULL;
  int                  optind_initial;
  int                  status;
#ifdef HAVE_GTKOSXAPPLICATION
  GtkOSXApplication   *theApp;
#endif

#ifdef HAVE_LIBPCAP
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
#define OPTSTRING_B "B:"
#else
#define OPTSTRING_B ""
#endif  /* _WIN32 or HAVE_PCAP_CREATE */
#else /* HAVE_LIBPCAP */
#define OPTSTRING_B ""
#endif  /* HAVE_LIBPCAP */

#ifdef HAVE_PCAP_CREATE
#define OPTSTRING_I "I"
#else
#define OPTSTRING_I ""
#endif

#define OPTSTRING "a:b:" OPTSTRING_B "c:C:Df:g:Hhi:" OPTSTRING_I "jJ:kK:lLm:nN:o:P:pQr:R:Ss:t:u:vw:X:y:z:"

  static const char optstring[] = OPTSTRING;

  /* Set the C-language locale to the native environment. */
  setlocale(LC_ALL, "");
#ifdef _WIN32
  arg_list_utf_16to8(argc, argv);
#endif /* _WIN32 */

  /*
   * Get credential information for later use, and drop privileges
   * before doing anything else.
   * Let the user know if anything happened.
   */
  init_process_policies();
  relinquish_special_privs_perm();

  /*
   * Attempt to get the pathname of the executable file.
   */
  init_progfile_dir_error = init_progfile_dir(argv[0], main);

  /* initialize the funnel mini-api */
  initialize_funnel_ops();

  AirPDcapInitContext(&airpdcap_ctx);

#ifdef _WIN32
  /* Load wpcap if possible. Do this before collecting the run-time version information */
  load_wpcap();

  /* ... and also load the packet.dll from wpcap */
  wpcap_packet_load();

#ifdef HAVE_AIRPCAP
  /* Load the airpcap.dll.  This must also be done before collecting
   * run-time version information. */
  airpcap_dll_ret_val = load_airpcap();

  switch (airpcap_dll_ret_val) {
  case AIRPCAP_DLL_OK:
    /* load the airpcap interfaces */
    airpcap_if_list = get_airpcap_interface_list(&err, &err_str);

    if (airpcap_if_list == NULL || g_list_length(airpcap_if_list) == 0){
      if (err == CANT_GET_AIRPCAP_INTERFACE_LIST && err_str != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", "Failed to open Airpcap Adapters!");
        g_free(err_str);
      }
      airpcap_if_active = NULL;

    } else {

      /* select the first ad default (THIS SHOULD BE CHANGED) */
      airpcap_if_active = airpcap_get_default_if(airpcap_if_list);
          }
    break;
#if 0
    /*
     * XXX - Maybe we need to warn the user if one of the following happens???
     */
    case AIRPCAP_DLL_OLD:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s","AIRPCAP_DLL_OLD\n");
      break;

    case AIRPCAP_DLL_ERROR:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s","AIRPCAP_DLL_ERROR\n");
      break;

    case AIRPCAP_DLL_NOT_FOUND:
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s","AIRPCAP_DDL_NOT_FOUND\n");
      break;
#endif
  }
#endif /* HAVE_AIRPCAP */

  /* Start windows sockets */
  WSAStartup( MAKEWORD( 1, 1 ), &wsaData );
#endif  /* _WIN32 */

  profile_store_persconffiles (TRUE);

  /* Assemble the compile-time version information string */
  comp_info_str = g_string_new("Compiled ");

  get_compiled_version_info(comp_info_str, get_gtk_compiled_info, get_gui_compiled_info);

  /* Assemble the run-time version information string */
  runtime_info_str = g_string_new("Running ");
  get_runtime_version_info(runtime_info_str, get_gui_runtime_info);

  /* Read the profile independent recent file.  We have to do this here so we can */
  /* set the profile before it can be set from the command line parameterts */
  recent_read_static(&rf_path, &rf_open_errno);
  if (rf_path != NULL && rf_open_errno != 0) {
    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		  "Could not open common recent file\n\"%s\": %s.",
		  rf_path, g_strerror(rf_open_errno));
  }

  /* "pre-scan" the command line parameters, if we have "console only"
     parameters.  We do this so we don't start GTK+ if we're only showing
     command-line help or version information.

     XXX - this pre-scan is done before we start GTK+, so we haven't
     run gtk_init() on the arguments.  That means that GTK+ arguments
     have not been removed from the argument list; those arguments
     begin with "--", and will be treated as an error by getopt().

     We thus ignore errors - *and* set "opterr" to 0 to suppress the
     error messages. */
  opterr = 0;
  optind_initial = optind;
  while ((opt = getopt(argc, argv, optstring)) != -1) {
    switch (opt) {
      case 'C':        /* Configuration Profile */
	if (profile_exists (optarg, FALSE)) {
	  set_profile_name (optarg);
	} else {
	  cmdarg_err("Configuration Profile \"%s\" does not exist", optarg);
	  exit(1);
	}
	break;
      case 'D':        /* Print a list of capture devices and exit */
#ifdef HAVE_LIBPCAP
        if_list = capture_interface_list(&err, &err_str);
        if (if_list == NULL) {
          switch (err) {
          case CANT_GET_INTERFACE_LIST:
            cmdarg_err("%s", err_str);
            g_free(err_str);
            break;

          case NO_INTERFACES_FOUND:
            cmdarg_err("There are no interfaces on which a capture can be done");
            break;
          }
          exit(2);
        }
        capture_opts_print_interfaces(if_list);
        free_interface_list(if_list);
        exit(0);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'h':        /* Print help and exit */
        print_usage(TRUE);
        exit(0);
        break;
#ifdef _WIN32
      case 'i':
        if (strcmp(optarg, "-") == 0)
          stdin_capture = TRUE;
        break;
#endif
      case 'P':        /* Path settings - change these before the Preferences and alike are processed */
        status = filesystem_opt(opt, optarg);
        if(status != 0) {
            cmdarg_err("-P flag \"%s\" failed (hint: is it quoted and existing?)", optarg);
            exit(status);
        }
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

  /* Init the "Open file" dialog directory */
  /* (do this after the path settings are processed) */

  /* Read the profile dependent (static part) of the recent file. */
  /* Only the static part of it will be read, as we don't have the gui now to fill the */
  /* recent lists which is done in the dynamic part. */
  /* We have to do this already here, so command line parameters can overwrite these values. */
  recent_read_profile_static(&rf_path, &rf_open_errno);
  if (rf_path != NULL && rf_open_errno != 0) {
    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		  "Could not open recent file\n\"%s\": %s.",
		  rf_path, g_strerror(rf_open_errno));
  }

  if (recent.gui_fileopen_remembered_dir &&
      test_for_directory(recent.gui_fileopen_remembered_dir) == EISDIR) {
    set_last_open_dir(recent.gui_fileopen_remembered_dir);
  } else {
    set_last_open_dir(get_persdatafile_dir());
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
#ifdef HAVE_LIBPCAP
  capture_callback_add(main_capture_callback, NULL);
#endif
  cf_callback_add(statusbar_cf_callback, NULL);
#ifdef HAVE_LIBPCAP
  capture_callback_add(statusbar_capture_callback, NULL);
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

  /* Set the initial values in the capture options. This might be overwritten
     by preference settings and then again by the command line parameters. */
  capture_opts_init(&global_capture_opts, &cfile);
#endif

  /* Initialize whatever we need to allocate colors for GTK+ */
  colors_init();

  /* Non-blank filter means we're remote. Throttle splash screen and resolution updates. */
  filter = get_conn_cfilter();
  if ( *filter != '\0' ) {
    info_update_freq = 1000;  /* Milliseconds */
  }

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

  splash_update(RA_DISSECTORS, NULL, (gpointer)splash_win);

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps information registered by the
     dissectors, and we must do it before we read the preferences, in
     case any dissectors register preferences. */
  epan_init(register_all_protocols,register_all_protocol_handoffs,
	    splash_update, (gpointer) splash_win,
            failure_alert_box,open_failure_alert_box,read_failure_alert_box,
            write_failure_alert_box);

  splash_update(RA_LISTENERS, NULL, (gpointer)splash_win);

  /* Register all tap listeners; we do this before we parse the arguments,
     as the "-z" argument can specify a registered tap. */

  /* we register the plugin taps before the other taps because
	  stats_tree taps plugins will be registered as tap listeners
	  by stats_tree_stat.c and need to registered before that */

#ifdef HAVE_PLUGINS
  register_all_plugin_tap_listeners();
#endif

  register_all_tap_listeners();

  splash_update(RA_PREFERENCES, NULL, (gpointer)splash_win);

  /* Now register the preferences for any non-dissector modules.
     We must do that before we read the preferences as well. */
  prefs_register_modules();

  prefs_p = read_configuration_files (&gdp_path, &dp_path);
  /* Removed thread code:
   * http://anonsvn.wireshark.org/viewvc/viewvc.cgi?view=rev&revision=35027
   */

  /* this is to keep tap extensions updating once every 3 seconds */
  tap_update_timer_id = g_timeout_add(prefs_p->tap_update_interval, tap_update_cb, NULL);

  splash_update(RA_CONFIGURATION, NULL, (gpointer)splash_win);
  proto_help_init();
  cap_file_init(&cfile);

  /* Fill in capture options with values from the preferences */
  prefs_to_capture_opts();

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
#ifdef HAVE_PCAP_CREATE
      case 'I':        /* Capture in monitor mode, if available */
#endif
      case 'Q':        /* Quit after capture (just capture to file) */
      case 's':        /* Set the snapshot (capture) length */
      case 'S':        /* "Sync" mode: used for following file ala tail -f */
      case 'w':        /* Write to capture file xxx */
      case 'y':        /* Set the pcap data link type */
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
      case 'B':        /* Buffer size */
#endif /* _WIN32 or HAVE_PCAP_CREATE */
#ifdef HAVE_LIBPCAP
        status = capture_opts_add_opt(&global_capture_opts, opt, optarg,
                                      &start_capture);
        if(status != 0) {
            exit(status);
        }
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
      case 'K':        /* Kerberos keytab file */
        read_keytab_file(optarg);
        break;
#endif

      /*** all non capture option specific ***/
      case 'C':
        /* Configuration profile settings were already processed just ignore them this time*/
	break;
      case 'j':        /* Search backwards for a matching packet from filter in option J */
        jump_backwards = TRUE;
        break;
      case 'g':        /* Go to packet with the given packet number */
        go_to_packet = get_positive_int(optarg, "go to packet");
        break;
      case 'J':        /* Jump to the first packet which matches the filter criteria */
        jfilter = optarg;
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
        g_free(prefs_p->gui_font_name);
        prefs_p->gui_font_name = g_strdup(optarg);
        break;
      case 'n':        /* No name resolution */
        gbl_resolv_flags = RESOLV_NONE;
        break;
      case 'N':        /* Select what types of addresses/port #s to resolve */
        if (gbl_resolv_flags == RESOLV_ALL)
          gbl_resolv_flags = RESOLV_NONE;
        badopt = string_to_name_resolve(optarg, &gbl_resolv_flags);
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
      case 'P':
        /* Path settings were already processed just ignore them this time*/
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
      case 't':        /* Time stamp type */
        if (strcmp(optarg, "r") == 0)
          timestamp_set_type(TS_RELATIVE);
        else if (strcmp(optarg, "a") == 0)
          timestamp_set_type(TS_ABSOLUTE);
        else if (strcmp(optarg, "ad") == 0)
          timestamp_set_type(TS_ABSOLUTE_WITH_DATE);
        else if (strcmp(optarg, "d") == 0)
          timestamp_set_type(TS_DELTA);
        else if (strcmp(optarg, "dd") == 0)
          timestamp_set_type(TS_DELTA_DIS);
        else if (strcmp(optarg, "e") == 0)
          timestamp_set_type(TS_EPOCH);
        else if (strcmp(optarg, "u") == 0)
          timestamp_set_type(TS_UTC);
        else if (strcmp(optarg, "ud") == 0)
          timestamp_set_type(TS_UTC_WITH_DATE);
        else {
          cmdarg_err("Invalid time stamp type \"%s\"", optarg);
          cmdarg_err_cont("It must be \"r\" for relative, \"a\" for absolute,");
          cmdarg_err_cont("\"ad\" for absolute with date, or \"d\" for delta.");
          exit(1);
        }
        break;
      case 'u':        /* Seconds type */
        if (strcmp(optarg, "s") == 0)
          timestamp_set_seconds_type(TS_SECONDS_DEFAULT);
        else if (strcmp(optarg, "hms") == 0)
          timestamp_set_seconds_type(TS_SECONDS_HOUR_MIN_SEC);
        else {
          cmdarg_err("Invalid seconds type \"%s\"", optarg);
          cmdarg_err_cont("It must be \"s\" for seconds or \"hms\" for hours, minutes and seconds.");
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
  if (!arg_error) {
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
        cf_name = g_strdup(argv[0]);
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
    if (global_capture_opts.multi_files_on) {
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
    if (global_capture_opts.multi_files_on) {
      /* Ring buffer works only under certain conditions:
	 a) ring buffer does not work with temporary files;
	 b) real_time_mode and multi_files_on are mutually exclusive -
	    real_time_mode takes precedence;
	 c) it makes no sense to enable the ring buffer if the maximum
	    file size is set to "infinite". */
      if (global_capture_opts.save_file == NULL) {
	cmdarg_err("Ring buffer requested, but capture isn't being saved to a permanent file.");
	global_capture_opts.multi_files_on = FALSE;
      }
/*      if (global_capture_opts.real_time_mode) {
	cmdarg_err("Ring buffer requested, but an \"Update list of packets in real time\" capture is being done.");
	global_capture_opts.multi_files_on = FALSE;
      }*/
      if (!global_capture_opts.has_autostop_filesize && !global_capture_opts.has_file_duration) {
	cmdarg_err("Ring buffer requested, but no maximum capture file size or duration were specified.");
/* XXX - this must be redesigned as the conditions changed */
/*	global_capture_opts.multi_files_on = FALSE;*/
      }
    }
  }

  if (start_capture || list_link_layer_types) {
    /* Did the user specify an interface to use? */
    if (!capture_opts_trim_iface(&global_capture_opts,
        (prefs_p->capture_device) ? get_if_name(prefs_p->capture_device) : NULL)) {
        exit(2);
    }
  }

  if (list_link_layer_types) {
    /* Get the list of link-layer types for the capture devices. */
    if_capabilities_t *caps;
    guint i;
    interface_options interface_opts;

    for (i = 0; i < global_capture_opts.ifaces->len; i++) {

      interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
      caps = capture_get_if_capabilities(interface_opts.name, interface_opts.monitor_mode, &err_str);
      if (caps == NULL) {
        cmdarg_err("%s", err_str);
        g_free(err_str);
        exit(2);
      }
      if (caps->data_link_types == NULL) {
        cmdarg_err("The capture device \"%s\" has no data link types.", interface_opts.name);
        exit(2);
      }
      capture_opts_print_if_capabilities(caps, interface_opts.name, interface_opts.monitor_mode);
      free_if_capabilities(caps);
    }
    exit(0);
  }

  capture_opts_trim_snaplen(&global_capture_opts, MIN_PACKET_SIZE);
  capture_opts_trim_ring_num_files(&global_capture_opts);
#endif /* HAVE_LIBPCAP */

  /* Notify all registered modules that have had any of their preferences
     changed either from one of the preferences file or from the command
     line that their preferences have changed. */
  prefs_apply_all();

  /* disabled protocols as per configuration file */
  if (gdp_path == NULL && dp_path == NULL) {
    set_disabled_protos_list();
  }

  build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

  /* read in rc file from global and personal configuration paths. */
  rc_file = get_datafile_path(RC_FILE);
  gtk_rc_parse(rc_file);
  g_free(rc_file);
  rc_file = get_persconffile_path(RC_FILE, FALSE, FALSE);
  gtk_rc_parse(rc_file);
  g_free(rc_file);

  font_init();

  macros_init();

  stock_icons_init();

  /* close the splash screen, as we are going to open the main window now */
  splash_destroy(splash_win);

  /************************************************************************/
  /* Everything is prepared now, preferences and command line was read in */

  /* Pop up the main window. */
  create_main_window(pl_size, tv_size, bv_size, prefs_p);

  /* Read the dynamic part of the recent file, as we have the gui now ready for it. */
  recent_read_dynamic(&rf_path, &rf_open_errno);
  if (rf_path != NULL && rf_open_errno != 0) {
    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		  "Could not open recent file\n\"%s\": %s.",
		  rf_path, g_strerror(rf_open_errno));
  }

  color_filters_enable(recent.packet_list_colorize);

  /* rearrange all the widgets as we now have all recent settings ready for this */
  main_widgets_rearrange();

  /* Fill in column titles.  This must be done after the top level window
     is displayed.

     XXX - is that still true, with fixed-width columns? */

  menu_recent_read_finished();
#ifdef HAVE_LIBPCAP
  menu_auto_scroll_live_changed(auto_scroll_live);
#endif

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

  color_filters_init();
  decode_as_init();

  /* the window can be sized only, if it's not already shown, so do it now! */
  main_load_window_geometry(top_level);

  g_timeout_add(info_update_freq, resolv_update_cb, NULL);


  /* If we were given the name of a capture file, read it in now;
     we defer it until now, so that, if we can't open it, and pop
     up an alert box, the alert box is more likely to come up on
     top of the main window - but before the preference-file-error
     alert box, so, if we get one of those, it's more likely to come
     up on top of us. */
  if (cf_name) {
    show_main_window(TRUE);
    check_and_warn_user_startup(cf_name);
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
        switch (cf_read(&cfile, FALSE)) {

        case CF_READ_OK:
        case CF_READ_ERROR:
          /* Just because we got an error, that doesn't mean we were unable
             to read any of the file; we handle what we could get from the
             file. */
          /* if the user told us to jump to a specific packet, do it now */
          if(go_to_packet != 0) {
            /* Jump to the specified frame number, kept for backward
               compatibility. */
            cf_goto_frame(&cfile, go_to_packet);
          } else if (jfilter != NULL) {
            /* try to compile given filter */
            if (!dfilter_compile(jfilter, &jump_to_filter)) {
              bad_dfilter_alert_box(jfilter);
            } else {
              /* Filter ok, jump to the first packet matching the filter
                 conditions. Default search direction is forward, but if
                 option d was given, search backwards */
              cf_find_packet_dfilter(&cfile, jump_to_filter, jump_backwards);
            }
          }
          break;

        case CF_READ_ABORTED:
          /* Exit now. */
          exit(0);
          break;
        }

	/* If the filename is not the absolute path, prepend the current dir. This happens
	   when wireshark is invoked from a cmd shell (e.g.,'wireshark -r file.pcap'). */
	if (!g_path_is_absolute(cf_name)) {
	  char *old_cf_name = cf_name;
	  char *pwd = g_get_current_dir();
	  cf_name = g_strdup_printf("%s%s%s", pwd, G_DIR_SEPARATOR_S, cf_name);
	  g_free(old_cf_name);
	  g_free(pwd);
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
        show_main_window(FALSE);
	/* Don't call check_and_warn_user_startup(): we did it above */
        set_menus_for_capture_in_progress(FALSE);
        set_capture_if_dialog_for_capture_in_progress(FALSE);
      }
    }
  } else {
#ifdef HAVE_LIBPCAP
    if (start_capture) {
      if (global_capture_opts.save_file != NULL) {
        /* Save the directory name for future file dialogs. */
        /* (get_dirname overwrites filename) */
        s = get_dirname(g_strdup(global_capture_opts.save_file));
        set_last_open_dir(s);
        g_free(s);
      }
      /* "-k" was specified; start a capture. */
      show_main_window(TRUE);
      check_and_warn_user_startup(cf_name);
      if (capture_start(&global_capture_opts)) {
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
      check_and_warn_user_startup(cf_name);
      set_menus_for_capture_in_progress(FALSE);
      set_capture_if_dialog_for_capture_in_progress(FALSE);
    }

    /* if the user didn't supply a capture filter, use the one to filter out remote connections like SSH */
    if (!start_capture && !global_capture_opts.default_options.cfilter) {
      global_capture_opts.default_options.cfilter = g_strdup(get_conn_cfilter());
    }
#else /* HAVE_LIBPCAP */
    show_main_window(FALSE);
    check_and_warn_user_startup(cf_name);
    set_menus_for_capture_in_progress(FALSE);
    set_capture_if_dialog_for_capture_in_progress(FALSE);
#endif /* HAVE_LIBPCAP */
  }

  /* register our pid if we are being run from a U3 device */
  u3_register_pid();

  profile_store_persconffiles (FALSE);

#ifdef HAVE_GTKOSXAPPLICATION
  theApp = g_object_new(GTK_TYPE_OSX_APPLICATION, NULL);
  gtk_osxapplication_set_dock_icon_pixbuf(theApp,gdk_pixbuf_new_from_xpm_data(wsicon64_xpm));
  gtk_osxapplication_ready(theApp);
#endif

  g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "Wireshark is up and ready to go");

  /* we'll enter the GTK loop now and hand the control over to GTK ... */
  gtk_main();
  /* ... back from GTK, we're going down now! */

  /* deregister our pid */
  u3_deregister_pid();

  epan_cleanup();

  AirPDcapDestroyContext(&airpdcap_ctx);

#ifdef _WIN32
  /* hide the (unresponsive) main window, while asking the user to close the console window */
  gtk_widget_hide(top_level);

#ifdef HAVE_GTKOSXAPPLICATION
  g_object_unref(theApp);
#endif

  /* Shutdown windows sockets */
  WSACleanup();

  /* For some unknown reason, the "atexit()" call in "create_console()"
     doesn't arrange that "destroy_console()" be called when we exit,
     so we call it here if a console was created. */
  destroy_console();
#endif

  exit(0);
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
  INITCOMMONCONTROLSEX comm_ctrl;

  /*
   * Initialize our DLL search path. MUST be called before LoadLibrary
   * or g_module_open.
   */
  ws_init_dll_search_path();

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
  ws_load_library("riched20.dll");

  has_console = FALSE;
  console_wait = FALSE;
  return main (__argc, __argv);
}

/* The code to create and desstroy console windows should not be necessary,
   at least as I read the GLib source code, as it looks as if GLib is, on
   Win32, *supposed* to create a console window into which to display its
   output.

   That doesn't happen, however.  I suspect there's something completely
   broken about that code in GLib-for-Win32, and that it may be related
   to the breakage that forces us to just call "printf()" on the message
   rather than passing the message on to "g_log_default_handler()"
   (which is the routine that does the aforementioned non-functional
   console window creation).  */

/*
 * If this application has no console window to which its standard output
 * would go, create one.
 */
void
create_console(void)
{
  if (stdin_capture) {
    /* We've been handed "-i -". Don't mess with stdio. */
    return;
  }

  if (!has_console) {
    /* We have no console to which to print the version string, so
       create one and make it the standard input, output, and error. */

    /*
     * See if we have an existing console (i.e. we were run from a
     * command prompt)
     */
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
      if (AllocConsole()) {
        console_wait = TRUE;
        SetConsoleTitle(_T("Wireshark Debug Console"));
      } else {
        return;   /* couldn't create console */
      }
    }

    ws_freopen("CONIN$", "r", stdin);
    ws_freopen("CONOUT$", "w", stdout);
    ws_freopen("CONOUT$", "w", stderr);
    fprintf(stdout, "\n");
    fprintf(stderr, "\n");

    /* Now register "destroy_console()" as a routine to be called just
       before the application exits, so that we can destroy the console
       after the user has typed a key (so that the console doesn't just
       disappear out from under them, giving the user no chance to see
       the message(s) we put in there). */
    atexit(destroy_console);

    /* Well, we have a console now. */
    has_console = TRUE;
  }
}

static void
destroy_console(void)
{
  if (console_wait) {
    printf("\n\nPress any key to exit\n");
    _getch();
  }
  FreeConsole();
}
#endif /* _WIN32 */


static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
		    const char *message, gpointer user_data _U_)
{
  time_t curr;
  struct tm *today;
  const char *level;


  /* ignore log message, if log_level isn't interesting based
     upon the console log preferences.
     If the preferences haven't been loaded loaded yet, display the
     message anyway.

     The default console_log_level preference value is such that only
       ERROR, CRITICAL and WARNING level messages are processed;
       MESSAGE, INFO and DEBUG level messages are ignored.  */
  if((log_level & G_LOG_LEVEL_MASK & prefs.console_log_level) == 0 &&
     prefs.console_log_level != 0) {
    return;
  }

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

    /* create a "timestamp" */
    time(&curr);
    today = localtime(&curr);

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
    /* XXX - on UN*X, should we just use g_log_default_handler()?
       We want the error messages to go to the standard output;
       on Mac OS X, that will cause them to show up in various
       per-user logs accessible through Console (details depend
       on whether you're running 10.0 through 10.4 or running
       10.5 and later), and, on other UN*X desktop environments,
       if they don't show up in some form of console log, that's
       a deficiency in that desktop environment.  (Too bad
       Windows doesn't set the standard output and error for
       GUI apps to something that shows up in such a log.) */
    g_log_default_handler(log_domain, log_level, message, user_data);
  }
#endif
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
    case(layout_pane_content_plist):
        return pkt_scrollw;
    case(layout_pane_content_pdetails):
        return tv_scrollw;
    case(layout_pane_content_pbytes):
        return byte_nb_ptr_gbl;
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

    /* be sure we don't lose a widget while rearranging */
    g_object_ref(G_OBJECT(menubar));
    g_object_ref(G_OBJECT(main_tb));
    g_object_ref(G_OBJECT(filter_tb));
#ifdef HAVE_AIRPCAP
    g_object_ref(G_OBJECT(airpcap_tb));
#endif
    g_object_ref(G_OBJECT(pkt_scrollw));
    g_object_ref(G_OBJECT(tv_scrollw));
    g_object_ref(G_OBJECT(byte_nb_ptr_gbl));
    g_object_ref(G_OBJECT(statusbar));
    g_object_ref(G_OBJECT(main_pane_v1));
    g_object_ref(G_OBJECT(main_pane_v2));
    g_object_ref(G_OBJECT(main_pane_h1));
    g_object_ref(G_OBJECT(main_pane_h2));
    g_object_ref(G_OBJECT(welcome_pane));

    /* empty all containers participating */
    gtk_container_foreach(GTK_CONTAINER(main_vbox),     foreach_remove_a_child, main_vbox);
    gtk_container_foreach(GTK_CONTAINER(main_pane_v1),  foreach_remove_a_child, main_pane_v1);
    gtk_container_foreach(GTK_CONTAINER(main_pane_v2),  foreach_remove_a_child, main_pane_v2);
    gtk_container_foreach(GTK_CONTAINER(main_pane_h1),  foreach_remove_a_child, main_pane_h1);
    gtk_container_foreach(GTK_CONTAINER(main_pane_h2),  foreach_remove_a_child, main_pane_h2);

    statusbar_widgets_emptying(statusbar);

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

    /* statusbar */
    gtk_box_pack_start(GTK_BOX(main_vbox), statusbar, FALSE, TRUE, 0);

    /* filter toolbar in statusbar hbox */
    if (prefs.filter_toolbar_show_in_statusbar) {
        gtk_box_pack_start(GTK_BOX(statusbar), filter_tb, FALSE, TRUE, 1);
    }

    /* statusbar widgets */
    statusbar_widgets_pack(statusbar);

    /* hide widgets on users recent settings */
    main_widgets_show_or_hide();

    gtk_widget_show(main_vbox);
}

static void
is_widget_visible(GtkWidget *widget, gpointer data)
{
    gboolean *is_visible = data;

    if (!*is_visible) {
#if GTK_CHECK_VERSION(2,18,0)
        if (gtk_widget_get_visible(widget))
#else
        if (GTK_WIDGET_VISIBLE(widget))
#endif
            *is_visible = TRUE;
    }
}


void
main_widgets_show_or_hide(void)
{
    gboolean main_second_pane_show;

    if (recent.main_toolbar_show) {
        gtk_widget_show(main_tb);
    } else {
        gtk_widget_hide(main_tb);
    }

    statusbar_widgets_show_or_hide(statusbar);

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
        gtk_widget_show(byte_nb_ptr_gbl);
    } else {
        gtk_widget_hide(byte_nb_ptr_gbl);
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
            welcome_if_tree_load();
        }
    } else {
        gtk_widget_hide(welcome_pane);
    }
}


/* called, when the window state changes (minimized, maximized, ...) */
static gboolean
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



#define NO_SHIFT_MOD_MASK (GDK_MODIFIER_MASK & ~(GDK_SHIFT_MASK|GDK_MOD2_MASK|GDK_LOCK_MASK))
static gboolean
top_level_key_pressed_cb(GtkWidget *w _U_, GdkEventKey *event, gpointer user_data _U_)
{
    if (event->keyval == GDK_F8) {
	new_packet_list_next();
	return TRUE;
    } else if (event->keyval == GDK_F7) {
	new_packet_list_prev();
	return TRUE;
    } else if (event->state & NO_SHIFT_MOD_MASK) {
        return FALSE; /* Skip control, alt, and other modifiers */
    /*
     * A comment in gdkkeysyms.h says that it's autogenerated from
     * freedesktop.org/x.org's keysymdef.h.  Although the GDK docs
     * don't explicitly say so, isprint() should work as expected
     * for values < 127.
     */
    } else if (isascii(event->keyval) && isprint(event->keyval)) {
	/* Forward the keypress on to the display filter entry */
	if (main_display_filter_widget && !gtk_widget_is_focus(main_display_filter_widget)) {
	    gtk_window_set_focus(GTK_WINDOW(top_level), main_display_filter_widget);
            gtk_editable_set_position(GTK_EDITABLE(main_display_filter_widget), -1);
	}
	return FALSE;
    }
    return FALSE;
}

static void
create_main_window (gint pl_size, gint tv_size, gint bv_size, e_prefs *prefs_p)
{
    GtkAccelGroup *accel;

    /* Main window */
    top_level = window_new(GTK_WINDOW_TOPLEVEL, "");
    set_main_window_name("The Wireshark Network Analyzer");

    gtk_widget_set_name(top_level, "main window");
    g_signal_connect(top_level, "delete_event", G_CALLBACK(main_window_delete_event_cb),
                   NULL);
    g_signal_connect(GTK_OBJECT(top_level), "window_state_event",
                         G_CALLBACK(window_state_event_cb), NULL);
    g_signal_connect(GTK_OBJECT(top_level), "key-press-event",
                         G_CALLBACK(top_level_key_pressed_cb), NULL );

    /* Vertical container for menu bar, toolbar(s), paned windows and progress/info box */
    main_vbox = gtk_vbox_new(FALSE, 1);
    gtk_container_set_border_width(GTK_CONTAINER(main_vbox), 0);
    gtk_container_add(GTK_CONTAINER(top_level), main_vbox);
    gtk_widget_show(main_vbox);

    /* Menu bar */
    menubar = main_menu_new(&accel);

#if defined(HAVE_IGE_MAC_INTEGRATION) || defined (HAVE_GTKOSXAPPLICATION)
    /* Mac OS X native menus are created and displayed by main_menu_new() */
    if(!prefs_p->gui_macosx_style) {
#endif
    gtk_window_add_accel_group(GTK_WINDOW(top_level), accel);
    gtk_widget_show(menubar);
#if defined(HAVE_IGE_MAC_INTEGRATION) || defined(HAVE_GTKOSXAPPLICATION)
    }
#endif

    /* Main Toolbar */
    main_tb = toolbar_new();
    gtk_widget_show (main_tb);

    /* Filter toolbar */
    filter_tb = filter_toolbar_new();

    /* Packet list */
    pkt_scrollw = new_packet_list_create();
    gtk_widget_set_size_request(pkt_scrollw, -1, pl_size);
    gtk_widget_show_all(pkt_scrollw);

    /* Tree view */
    tv_scrollw = main_tree_view_new(prefs_p, &tree_view_gbl);
    gtk_widget_set_size_request(tv_scrollw, -1, tv_size);
    gtk_widget_show(tv_scrollw);

    g_signal_connect(gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view_gbl)),
                   "changed", G_CALLBACK(tree_view_selection_changed_cb), NULL);
    g_signal_connect(tree_view_gbl, "button_press_event", G_CALLBACK(popup_menu_handler),
                   g_object_get_data(G_OBJECT(popup_menu_object), PM_TREE_VIEW_KEY));
    gtk_widget_show(tree_view_gbl);

    /* Byte view. */
    byte_nb_ptr_gbl = byte_view_new();
    gtk_widget_set_size_request(byte_nb_ptr_gbl, -1, bv_size);
    gtk_widget_show(byte_nb_ptr_gbl);

    g_signal_connect(byte_nb_ptr_gbl, "button_press_event", G_CALLBACK(popup_menu_handler),
                   g_object_get_data(G_OBJECT(popup_menu_object), PM_BYTES_VIEW_KEY));

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
    airpcap_tb = airpcap_toolbar_new();
    gtk_widget_show(airpcap_tb);
#endif
    /* status bar */
    statusbar = statusbar_new();
    gtk_widget_show(statusbar);

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

  /* Move the main window to the front, in case it isn't already there */
#if GTK_CHECK_VERSION(2,14,0)
  gdk_window_raise(gtk_widget_get_window(top_level));
#else
  gdk_window_raise(top_level->window);
#endif

#ifdef HAVE_AIRPCAP
  airpcap_toolbar_show(airpcap_tb);
#endif /* HAVE_AIRPCAP */
}

/* Fill in capture options with values from the preferences */
void
prefs_to_capture_opts(void)
{
#ifdef HAVE_LIBPCAP
  /* Set promiscuous mode from the preferences setting. */
  /* the same applies to other preferences settings as well. */
    global_capture_opts.default_options.promisc_mode = prefs.capture_prom_mode;
    global_capture_opts.use_pcapng                   = prefs.capture_pcap_ng;
    global_capture_opts.show_info                    = prefs.capture_show_info;
    global_capture_opts.real_time_mode               = prefs.capture_real_time;
    auto_scroll_live                                 = prefs.capture_auto_scroll;
#endif /* HAVE_LIBPCAP */

  /* Set the name resolution code's flags from the preferences. */
    gbl_resolv_flags = prefs.name_resolve;
}

static void copy_global_profile (const gchar *profile_name)
{
   char  *pf_dir_path, *pf_dir_path2, *pf_filename;

   if (create_persconffile_profile(profile_name, &pf_dir_path) == -1) {
     simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		   "Can't create directory\n\"%s\":\n%s.",
		   pf_dir_path, g_strerror(errno));

     g_free(pf_dir_path);
   }

   if (copy_persconffile_profile(profile_name, profile_name, TRUE, &pf_filename,
				 &pf_dir_path, &pf_dir_path2) == -1) {
     simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		   "Can't copy file \"%s\" in directory\n\"%s\" to\n\"%s\":\n%s.",
		   pf_filename, pf_dir_path2, pf_dir_path, g_strerror(errno));

     g_free(pf_filename);
     g_free(pf_dir_path);
     g_free(pf_dir_path2);
   }
}

/* Change configuration profile */
void change_configuration_profile (const gchar *profile_name)
{
   char  *gdp_path, *dp_path;
   char  *rf_path;
   int    rf_open_errno;

   /* First check if profile exists */
   if (!profile_exists(profile_name, FALSE)) {
     if (profile_exists(profile_name, TRUE)) {
       /* Copy from global profile */
       copy_global_profile (profile_name);
     } else {
       /* No personal and no global profile exists */
       return;
     }
   }

   /* Then check if changing to another profile */
   if (profile_name && strcmp (profile_name, get_profile_name()) == 0) {
     return;
   }

   /* Get the current geometry, before writing it to disk */
   main_save_window_geometry(top_level);

   if (profile_exists(get_profile_name(), FALSE)) {
     /* Write recent file for profile we are leaving, if it still exists */
     write_profile_recent();
   }

   /* Set profile name and update the status bar */
   set_profile_name (profile_name);
   profile_bar_update ();

   /* Reset current preferences and apply the new */
   prefs_reset();
   menu_prefs_reset();

   (void) read_configuration_files (&gdp_path, &dp_path);

   recent_read_profile_static(&rf_path, &rf_open_errno);
   if (rf_path != NULL && rf_open_errno != 0) {
     simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		  "Could not open common recent file\n\"%s\": %s.",
		  rf_path, g_strerror(rf_open_errno));
   }
   if (recent.gui_fileopen_remembered_dir &&
       test_for_directory(recent.gui_fileopen_remembered_dir) == EISDIR) {
     set_last_open_dir(recent.gui_fileopen_remembered_dir);
   }
   timestamp_set_type (recent.gui_time_format);
   timestamp_set_seconds_type (recent.gui_seconds_format);
   color_filters_enable(recent.packet_list_colorize);

   prefs_to_capture_opts();
   prefs_apply_all();
   macros_post_update();

   /* Update window view and redraw the toolbar */
   update_main_window_title();
   toolbar_redraw_all();

   /* Enable all protocols and disable from the disabled list */
   proto_enable_all();
   if (gdp_path == NULL && dp_path == NULL) {
     set_disabled_protos_list();
   }

   /* Reload color filters */
   color_filters_reload();

   /* Reload list of interfaces on welcome page */
   welcome_if_panel_reload();

   /* Recreate the packet list according to new preferences */
   new_packet_list_recreate ();
   cfile.cinfo.columns_changed = FALSE; /* Reset value */
   user_font_apply();

   /* Update menus with new recent values */
   menu_recent_read_finished();

   /* Reload pane geometry, must be done after recreating the list */
   main_pane_load_window_geometry();
}

/** redissect packets and update UI */
void redissect_packets(void)
{
    cf_redissect_packets(&cfile);
    status_expert_update();
}
