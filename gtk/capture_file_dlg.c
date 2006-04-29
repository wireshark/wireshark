/* capture_file_dlg.c
 * Dialog boxes for handling capture files
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <gtk/gtk.h>

#include "packet-range.h"
#include <epan/filesystem.h>

#include "globals.h"
#include "gtkglobals.h"
#include <epan/addr_resolv.h>
#include "keys.h"
#include "filter_dlg.h"
#include "gui_utils.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include "menu.h"
#include "dlg_utils.h"
#include "capture_file_dlg.h"
#include "main.h"
#include "compat_macros.h"
#include <epan/prefs.h>
#include "recent.h"
#include "color.h"
#include "../ui_util.h"
#include "color_filters.h"
#include "gtk/color_dlg.h"
#ifdef HAVE_LIBPCAP
#include "capture_dlg.h"
#endif
#include "range_utils.h"
#include "merge.h"
#include "util.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if GTK_MAJOR_VERSION >= 2 && _WIN32
#include <gdk/gdkwin32.h>
#include <windows.h>
#include "win32-file-dlg.h"
#endif

static void file_open_ok_cb(GtkWidget *w, gpointer fs);
static void file_open_destroy_cb(GtkWidget *win, gpointer user_data);
static void file_merge_ok_cb(GtkWidget *w, gpointer fs);
static void file_merge_destroy_cb(GtkWidget *win, gpointer user_data);
static void select_file_type_cb(GtkWidget *w, gpointer data);
static void file_save_as_ok_cb(GtkWidget *w, gpointer fs);
static void file_save_as_destroy_cb(GtkWidget *win, gpointer user_data);
static void file_color_import_ok_cb(GtkWidget *w, gpointer fs);
static void file_color_import_destroy_cb(GtkWidget *win, gpointer user_data);
static void file_color_export_ok_cb(GtkWidget *w, gpointer fs);
static void file_color_export_destroy_cb(GtkWidget *win, gpointer user_data);
static void set_file_type_list(GtkWidget *option_menu);

#define E_FILE_M_RESOLVE_KEY	  "file_dlg_mac_resolve_key"
#define E_FILE_N_RESOLVE_KEY	  "file_dlg_network_resolve_key"
#define E_FILE_T_RESOLVE_KEY	  "file_dlg_transport_resolve_key"

#define E_MERGE_PREPEND_KEY 	  "merge_dlg_prepend_key"
#define E_MERGE_CHRONO_KEY 	      "merge_dlg_chrono_key"
#define E_MERGE_APPEND_KEY 	      "merge_dlg_append_key"

#define ARGUMENT_CL "argument_cl"


#define PREVIEW_TABLE_KEY       "preview_table_key"
#define PREVIEW_FILENAME_KEY    "preview_filename_key"
#define PREVIEW_FORMAT_KEY      "preview_format_key"
#define PREVIEW_SIZE_KEY        "preview_size_key"
#define PREVIEW_ELAPSED_KEY     "preview_elapsed_key"
#define PREVIEW_PACKETS_KEY     "preview_packets_key"
#define PREVIEW_FIRST_KEY       "preview_first_key"


/*
 * Keep a static pointer to the current "Save Capture File As" window, if
 * any, so that if somebody tries to do "File:Save" or "File:Save As"
 * while there's already a "Save Capture File As" window up, we just pop
 * up the existing one, rather than creating a new one.
 */
static GtkWidget *file_save_as_w;

/* XXX - can we make these not be static? */
static packet_range_t range;
static gboolean color_marked;
static int filetype;
static GtkWidget *cfmark_cb;
static GtkWidget *ft_om;
static GtkWidget *range_tb;

#define PREVIEW_STR_MAX         200


/* set a new filename for the preview widget */
static wtap *
preview_set_filename(GtkWidget *prev, const gchar *cf_name)
{
    GtkWidget  *label;
    wtap       *wth;
    int         err = 0;
    gchar      *err_info;
    gchar       string_buff[PREVIEW_STR_MAX];
    gint64      filesize;


    /* init preview labels */
    label = OBJECT_GET_DATA(prev, PREVIEW_FILENAME_KEY);
    gtk_label_set_text(GTK_LABEL(label), "-");
    label = OBJECT_GET_DATA(prev, PREVIEW_FORMAT_KEY);
    gtk_label_set_text(GTK_LABEL(label), "-");
    label = OBJECT_GET_DATA(prev, PREVIEW_SIZE_KEY);
    gtk_label_set_text(GTK_LABEL(label), "-");
    label = OBJECT_GET_DATA(prev, PREVIEW_ELAPSED_KEY);
    gtk_label_set_text(GTK_LABEL(label), "-");
    label = OBJECT_GET_DATA(prev, PREVIEW_PACKETS_KEY);
    gtk_label_set_text(GTK_LABEL(label), "-");
    label = OBJECT_GET_DATA(prev, PREVIEW_FIRST_KEY);
    gtk_label_set_text(GTK_LABEL(label), "-");

    if(!cf_name) {
        return NULL;
    }

    label = OBJECT_GET_DATA(prev, PREVIEW_FILENAME_KEY);
    gtk_label_set_text(GTK_LABEL(label), get_basename(cf_name));

    if (test_for_directory(cf_name) == EISDIR) {
        label = OBJECT_GET_DATA(prev, PREVIEW_FORMAT_KEY);
        gtk_label_set_text(GTK_LABEL(label), "directory");
        return NULL;
    }

    wth = wtap_open_offline(cf_name, &err, &err_info, TRUE);
    if (wth == NULL) {
        label = OBJECT_GET_DATA(prev, PREVIEW_FORMAT_KEY);
        if(err == WTAP_ERR_FILE_UNKNOWN_FORMAT) {
            gtk_label_set_text(GTK_LABEL(label), "unknown file format");
        } else {
            gtk_label_set_text(GTK_LABEL(label), "error opening file");
        }
        return NULL;
    }

    /* Find the size of the file. */
    filesize = wtap_file_size(wth, &err);
    if (filesize == -1) {
        gtk_label_set_text(GTK_LABEL(label), "error getting file size");
        wtap_close(wth);
        return NULL;
    }
    g_snprintf(string_buff, PREVIEW_STR_MAX, "%" PRId64 " bytes", filesize);
    label = OBJECT_GET_DATA(prev, PREVIEW_SIZE_KEY);
    gtk_label_set_text(GTK_LABEL(label), string_buff);

    /* type */
    g_snprintf(string_buff, PREVIEW_STR_MAX, "%s", wtap_file_type_string(wtap_file_type(wth)));
    label = OBJECT_GET_DATA(prev, PREVIEW_FORMAT_KEY);
    gtk_label_set_text(GTK_LABEL(label), string_buff);

    return wth;
}


/* do a preview run on the currently selected capture file */
static void
preview_do(GtkWidget *prev, wtap *wth)
{
    GtkWidget  *label;
    unsigned int elapsed_time;
    time_t      time_preview;
    time_t      time_current;
    int         err = 0;
    gchar      *err_info;
    long        data_offset;
    const struct wtap_pkthdr *phdr;
    double      start_time = 0;	/* seconds, with nsec resolution */
    double      stop_time = 0;	/* seconds, with nsec resolution */
    double      cur_time;
    unsigned int packets = 0;
    gboolean    is_breaked = FALSE;
    gchar       string_buff[PREVIEW_STR_MAX];
    time_t      ti_time;
    struct tm  *ti_tm;


    time(&time_preview);
    while ( (wtap_read(wth, &err, &err_info, &data_offset)) ) {
        phdr = wtap_phdr(wth);
        cur_time = nstime_to_sec( (const nstime_t *) &phdr->ts );
        if(packets == 0) {
            start_time 	= cur_time;
            stop_time = cur_time;
        }
        if (cur_time < start_time) {
            start_time = cur_time;
        }
        if (cur_time > stop_time){
            stop_time = cur_time;
        }

        packets++;
        if(packets%1000) {
            /* do we have a timeout? */
            time(&time_current);
            if(time_current-time_preview >= (time_t) prefs.gui_fileopen_preview) {
                is_breaked = TRUE;
                break;
            }
        }
    }

    if(err != 0) {
        g_snprintf(string_buff, PREVIEW_STR_MAX, "error after reading %u packets", packets);
        label = OBJECT_GET_DATA(prev, PREVIEW_PACKETS_KEY);
        gtk_label_set_text(GTK_LABEL(label), string_buff);
        wtap_close(wth);
        return;
    }

    /* packet count */
    if(is_breaked) {
        g_snprintf(string_buff, PREVIEW_STR_MAX, "more than %u packets (preview timeout)", packets);
    } else {
        g_snprintf(string_buff, PREVIEW_STR_MAX, "%u", packets);
    }
    label = OBJECT_GET_DATA(prev, PREVIEW_PACKETS_KEY);
    gtk_label_set_text(GTK_LABEL(label), string_buff);

    /* first packet */
    ti_time = (long)start_time;
    ti_tm = localtime( &ti_time );
	if(ti_tm) {
		g_snprintf(string_buff, PREVIEW_STR_MAX,
				 "%04d-%02d-%02d %02d:%02d:%02d",
				 ti_tm->tm_year + 1900,
				 ti_tm->tm_mon + 1,
				 ti_tm->tm_mday,
				 ti_tm->tm_hour,
				 ti_tm->tm_min,
				 ti_tm->tm_sec);
	} else {
		g_snprintf(string_buff, PREVIEW_STR_MAX, "?");
	}
    label = OBJECT_GET_DATA(prev, PREVIEW_FIRST_KEY);
    gtk_label_set_text(GTK_LABEL(label), string_buff);

    /* elapsed time */
    elapsed_time = (unsigned int)(stop_time-start_time);
    if(elapsed_time/86400) {
      g_snprintf(string_buff, PREVIEW_STR_MAX, "%02u days %02u:%02u:%02u",
        elapsed_time/86400, elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
    } else {
      g_snprintf(string_buff, PREVIEW_STR_MAX, "%02u:%02u:%02u",
        elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
    }
    if(is_breaked) {
      g_snprintf(string_buff, PREVIEW_STR_MAX, "unknown");
    }
    label = OBJECT_GET_DATA(prev, PREVIEW_ELAPSED_KEY);
    gtk_label_set_text(GTK_LABEL(label), string_buff);

    wtap_close(wth);
}

#if 0
/* as the dialog layout will look very ugly when using the file chooser preview mechanism,
   simply use the same layout as in GTK1 */
/* (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2 */
static void
update_preview_cb (GtkFileChooser *file_chooser, gpointer data)
{
    GtkWidget *prev = GTK_WIDGET (data);
    char *cf_name;
    gboolean have_preview;

    cf_name = gtk_file_chooser_get_preview_filename (file_chooser);

    have_preview = preview_set_filename(prev, cf_name);

    g_free (cf_name);

    have_preview = TRUE;
    gtk_file_chooser_set_preview_widget_active (file_chooser, have_preview);
}
#endif


/* the filename text entry changed */
static void
file_open_entry_changed(GtkWidget *w _U_, gpointer file_sel)
{
    GtkWidget *prev = OBJECT_GET_DATA(file_sel, PREVIEW_TABLE_KEY);
    const gchar* cf_name;
    gboolean have_preview;
    wtap       *wth;

    /* get the filename */
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
    cf_name = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_sel));
#else
    cf_name = gtk_file_selection_get_filename(GTK_FILE_SELECTION(file_sel));
#endif

    /* set the filename to the preview */
    wth = preview_set_filename(prev, cf_name);
    have_preview = (wth != NULL);

    /* make the preview widget sensitive */
    gtk_widget_set_sensitive(prev, have_preview);

    /* make the open/save/... dialog button sensitive */
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
    gtk_dialog_set_response_sensitive(file_sel, GTK_RESPONSE_ACCEPT, have_preview);
#else
    gtk_widget_set_sensitive(GTK_FILE_SELECTION(file_sel)->ok_button, have_preview);
#endif

    /* do the actual preview */
    if(have_preview)
        preview_do(prev, wth);
}


/* copied from summary_dlg.c */
static GtkWidget *
add_string_to_table_sensitive(GtkWidget *list, guint *row, const gchar *title, const gchar *value, gboolean sensitive)
{
    GtkWidget *label;
    gchar     *indent;

    if(strlen(value) != 0) {
        indent = g_strdup_printf("   %s", title);
    } else {
        indent = g_strdup(title);
    }
    label = gtk_label_new(indent);
    g_free(indent);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
    gtk_widget_set_sensitive(label, sensitive);
    gtk_table_attach_defaults(GTK_TABLE(list), label, 0, 1, *row, *row+1);

    label = gtk_label_new(value);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
    gtk_widget_set_sensitive(label, sensitive);
    gtk_table_attach_defaults(GTK_TABLE(list), label, 1, 2, *row, *row+1);

    *row = *row + 1;

    return label;
}

static GtkWidget *
add_string_to_table(GtkWidget *list, guint *row, const gchar *title, const gchar *value)
{
    return add_string_to_table_sensitive(list, row, title, value, TRUE);
}



static GtkWidget *
preview_new(void)
{
    GtkWidget *table, *label;
    guint         row;

    table = gtk_table_new(1, 2, FALSE);
    gtk_table_set_col_spacings(GTK_TABLE(table), 6);
    gtk_table_set_row_spacings(GTK_TABLE(table), 3);
    row = 0;

    label = add_string_to_table(table, &row, "Filename:", "-");
    WIDGET_SET_SIZE(label, DEF_WIDTH/3, -1);
    OBJECT_SET_DATA(table, PREVIEW_FILENAME_KEY, label);
    label = add_string_to_table(table, &row, "Format:", "-");
    OBJECT_SET_DATA(table, PREVIEW_FORMAT_KEY, label);
    label = add_string_to_table(table, &row, "Size:", "-");
    OBJECT_SET_DATA(table, PREVIEW_SIZE_KEY, label);
    label = add_string_to_table(table, &row, "Packets:", "-");
    OBJECT_SET_DATA(table, PREVIEW_PACKETS_KEY, label);
    label = add_string_to_table(table, &row, "First Packet:", "-");
    OBJECT_SET_DATA(table, PREVIEW_FIRST_KEY, label);
    label = add_string_to_table(table, &row, "Elapsed time:", "-");
    OBJECT_SET_DATA(table, PREVIEW_ELAPSED_KEY, label);

    return table;
}

/*
 * Keep a static pointer to the current "Open Capture File" window, if
 * any, so that if somebody tries to do "File:Open" while there's already
 * an "Open Capture File" window up, we just pop up the existing one,
 * rather than creating a new one.
 */
static GtkWidget *file_open_w;

/* Open a file */
static void
file_open_cmd(GtkWidget *w)
{
#if GTK_MAJOR_VERSION >= 2 && _WIN32
  win32_open_file(GDK_WINDOW_HWND(top_level->window));
#else /* GTK_MAJOR_VERSION >= 2 && _WIN32 */
  GtkWidget	*main_hb, *main_vb, *filter_hbox, *filter_bt, *filter_te,
  		*m_resolv_cb, *n_resolv_cb, *t_resolv_cb, *prev;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif

  /* No Apply button, and "OK" just sets our text widget, it doesn't
     activate it (i.e., it doesn't cause us to try to open the file). */
  static construct_args_t args = {
  	"Ethereal: Read Filter",
  	FALSE,
  	FALSE,
    TRUE
  };

  if (file_open_w != NULL) {
    /* There's already an "Open Capture File" dialog box; reactivate it. */
    reactivate_window(file_open_w);
    return;
  }

  file_open_w = file_selection_new("Ethereal: Open Capture File",
                                   FILE_SELECTION_OPEN);
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  /* it's annoying, that the file chooser dialog is already shown here,
     so we cannot use the correct gtk_window_set_default_size() to resize it */
  WIDGET_SET_SIZE(GTK_WINDOW(file_open_w), DEF_WIDTH, DEF_HEIGHT);
#else
  gtk_window_set_default_size(GTK_WINDOW(file_open_w), DEF_WIDTH, DEF_HEIGHT);
#endif

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(file_open_w), accel_group);
#endif

  switch (prefs.gui_fileopen_style) {

  case FO_STYLE_LAST_OPENED:
    /* The user has specified that we should start out in the last directory
       we looked in.  If we've already opened a file, use its containing
       directory, if we could determine it, as the directory, otherwise
       use the "last opened" directory saved in the preferences file if
       there was one. */
    /* This is now the default behaviour in file_selection_new() */
    break;

  case FO_STYLE_SPECIFIED:
    /* The user has specified that we should always start out in a
       specified directory; if they've specified that directory,
       start out by showing the files in that dir. */
    if (prefs.gui_fileopen_dir[0] != '\0')
      file_selection_set_current_folder(file_open_w, prefs.gui_fileopen_dir);
    break;
  }


  main_hb = gtk_hbox_new(FALSE, 3);
  file_selection_set_extra_widget(file_open_w, main_hb);
  gtk_widget_show(main_hb);

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_box_pack_start(GTK_BOX(main_hb), main_vb, FALSE, FALSE, 0);
  gtk_widget_show(main_vb);

  /* filter row */
  filter_hbox = gtk_hbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(filter_hbox), 0);
  gtk_box_pack_start(GTK_BOX(main_vb), filter_hbox, FALSE, FALSE, 0);
  gtk_widget_show(filter_hbox);

  filter_bt = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_DISPLAY_FILTER_ENTRY);
  SIGNAL_CONNECT(filter_bt, "clicked", display_filter_construct_cb, &args);
  SIGNAL_CONNECT(filter_bt, "destroy", filter_button_destroy_cb, NULL);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);

  filter_te = gtk_entry_new();
  OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_te, TRUE, TRUE, 3);
  SIGNAL_CONNECT(filter_te, "changed", filter_te_syntax_check_cb, NULL);
  gtk_widget_show(filter_te);

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  OBJECT_SET_DATA(file_open_w, E_RFILTER_TE_KEY, filter_te);
#else
  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_open_w)->ok_button,
                  E_RFILTER_TE_KEY, filter_te);
#endif

  /* resolve buttons */
  m_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Enable _MAC name resolution", accel_group);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(m_resolv_cb),
	g_resolv_flags & RESOLV_MAC);
  gtk_box_pack_start(GTK_BOX(main_vb), m_resolv_cb, FALSE, FALSE, 0);
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  OBJECT_SET_DATA(file_open_w,
                  E_FILE_M_RESOLVE_KEY, m_resolv_cb);
#else
  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_open_w)->ok_button,
                  E_FILE_M_RESOLVE_KEY, m_resolv_cb);
#endif
  gtk_widget_show(m_resolv_cb);

  n_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Enable _network name resolution", accel_group);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(n_resolv_cb),
	g_resolv_flags & RESOLV_NETWORK);
  gtk_box_pack_start(GTK_BOX(main_vb), n_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(n_resolv_cb);
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  OBJECT_SET_DATA(file_open_w, E_FILE_N_RESOLVE_KEY, n_resolv_cb);
#else
  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_open_w)->ok_button,
		  E_FILE_N_RESOLVE_KEY, n_resolv_cb);
#endif

  t_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Enable _transport name resolution", accel_group);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(t_resolv_cb),
	g_resolv_flags & RESOLV_TRANSPORT);
  gtk_box_pack_start(GTK_BOX(main_vb), t_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(t_resolv_cb);
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  OBJECT_SET_DATA(file_open_w, E_FILE_T_RESOLVE_KEY, t_resolv_cb);
#else
  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_open_w)->ok_button,
		  E_FILE_T_RESOLVE_KEY, t_resolv_cb);
#endif


  SIGNAL_CONNECT(file_open_w, "destroy", file_open_destroy_cb, NULL);

  /* preview widget */
  prev = preview_new();
  OBJECT_SET_DATA(file_open_w, PREVIEW_TABLE_KEY, prev);
  gtk_widget_show_all(prev);
  gtk_box_pack_start(GTK_BOX(main_hb), prev, TRUE, TRUE, 0);

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  SIGNAL_CONNECT(GTK_FILE_CHOOSER(file_open_w), "selection-changed",
      file_open_entry_changed, file_open_w);
  file_open_entry_changed(file_open_w, file_open_w);

  OBJECT_SET_DATA(file_open_w, E_DFILTER_TE_KEY,
                  OBJECT_GET_DATA(w, E_DFILTER_TE_KEY));
  if (gtk_dialog_run(GTK_DIALOG(file_open_w)) == GTK_RESPONSE_ACCEPT)
  {
    file_open_ok_cb(file_open_w, file_open_w);
  }
  else window_destroy(file_open_w);
#else /* (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2 */
  SIGNAL_CONNECT(GTK_FILE_SELECTION(file_open_w)->selection_entry, "changed",
      file_open_entry_changed, file_open_w);

  /* Connect the ok_button to file_open_ok_cb function and pass along a
     pointer to the file selection box widget */
  SIGNAL_CONNECT(GTK_FILE_SELECTION(file_open_w)->ok_button, "clicked",
                 file_open_ok_cb, file_open_w);

  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_open_w)->ok_button,
                  E_DFILTER_TE_KEY, OBJECT_GET_DATA(w, E_DFILTER_TE_KEY));

  /* Connect the cancel_button to destroy the widget */
  window_set_cancel_button(file_open_w,
      GTK_FILE_SELECTION(file_open_w)->cancel_button, window_cancel_button_cb);

  SIGNAL_CONNECT(file_open_w, "delete_event", window_delete_event_cb, NULL);

  gtk_widget_show(file_open_w);
  window_present(file_open_w);
#endif /* (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2 */
#endif /* GTK_MAJOR_VERSION >= 2 && _WIN32 */
}

static void file_open_answered_cb(gpointer dialog _U_, gint btn, gpointer data _U_)
{
    switch(btn) {
    case(ESD_BTN_SAVE):
        /* save file first */
        file_save_as_cmd(after_save_open_dialog, data);
        break;
    case(ESD_BTN_DONT_SAVE):
        cf_close(&cfile);
        file_open_cmd(data);
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}

void
file_open_cmd_cb(GtkWidget *widget, gpointer data _U_) {
  gpointer  dialog;

  if((cfile.state != FILE_CLOSED) && !cfile.user_saved && prefs.gui_ask_unsaved) {
    /* user didn't saved his current file, ask him */
    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_DONTSAVE_CANCEL,
                PRIMARY_TEXT_START "Save capture file before opening a new one?" PRIMARY_TEXT_END "\n\n"
                "If you open a new capture file without saving, your capture data will be discarded.");
    simple_dialog_set_cb(dialog, file_open_answered_cb, widget);
  } else {
    /* unchanged file, just open a new one */
    file_open_cmd(widget);
  }
}

/* user pressed "open" button */
static void
file_open_ok_cb(GtkWidget *w, gpointer fs) {
  gchar       *cf_name, *s;
  const gchar *rfilter;
  GtkWidget   *filter_te, *m_resolv_cb, *n_resolv_cb, *t_resolv_cb;
  dfilter_t   *rfcode = NULL;
  int          err;

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  cf_name = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs)));
#else
  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
#endif
  filter_te = OBJECT_GET_DATA(w, E_RFILTER_TE_KEY);
  rfilter = gtk_entry_get_text(GTK_ENTRY(filter_te));
  if (!dfilter_compile(rfilter, &rfcode)) {
    bad_dfilter_alert_box(rfilter);
    g_free(cf_name);
    return;
  }

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(cf_name) == EISDIR) {
	/* It's a directory - set the file selection box to display that
	   directory, don't try to open the directory as a capture file. */
        set_last_open_dir(cf_name);
        g_free(cf_name);
        file_selection_set_current_folder(fs, get_last_open_dir());
    	return;
  }

  /* Try to open the capture file. */
  if (cf_open(&cfile, cf_name, FALSE, &err) != CF_OK) {
    /* We couldn't open it; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the open error,
       try again. */
    if (rfcode != NULL)
      dfilter_free(rfcode);
    g_free(cf_name);
    return;
  }

  /* Attach the new read filter to "cf" ("cf_open()" succeeded, so
     it closed the previous capture file, and thus destroyed any
     previous read filter attached to "cf"). */
  cfile.rfcode = rfcode;

  /* Set the global resolving variable */
  g_resolv_flags = prefs.name_resolve;
  m_resolv_cb = OBJECT_GET_DATA(w, E_FILE_M_RESOLVE_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (m_resolv_cb)))
    g_resolv_flags |= RESOLV_MAC;
  else
    g_resolv_flags &= ~RESOLV_MAC;
  n_resolv_cb = OBJECT_GET_DATA(w, E_FILE_N_RESOLVE_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (n_resolv_cb)))
    g_resolv_flags |= RESOLV_NETWORK;
  else
    g_resolv_flags &= ~RESOLV_NETWORK;
  t_resolv_cb = OBJECT_GET_DATA(w, E_FILE_T_RESOLVE_KEY);
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (t_resolv_cb)))
    g_resolv_flags |= RESOLV_TRANSPORT;
  else
    g_resolv_flags &= ~RESOLV_TRANSPORT;

  /* We've crossed the Rubicon; get rid of the file selection box. */
  window_destroy(GTK_WIDGET (fs));

  switch (cf_read(&cfile)) {

  case CF_READ_OK:
  case CF_READ_ERROR:
    /* Just because we got an error, that doesn't mean we were unable
       to read any of the file; we handle what we could get from the
       file. */
    break;

  case CF_READ_ABORTED:
    /* The user bailed out of re-reading the capture file; the
       capture file has been closed - just free the capture file name
       string and return (without changing the last containing
       directory). */
    g_free(cf_name);
    return;
  }

  /* Save the name of the containing directory specified in the path name,
     if any; we can write over cf_name, which is a good thing, given that
     "get_dirname()" does write over its argument. */
  s = get_dirname(cf_name);
  set_last_open_dir(s);
  gtk_widget_grab_focus(packet_list);

  g_free(cf_name);
}

static void
file_open_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "Open Capture File" dialog box. */
  file_open_w = NULL;
}

/*
 * Keep a static pointer to the current "Merge Capture File" window, if
 * any, so that if somebody tries to do "File:Merge" while there's already
 * an "Merge Capture File" window up, we just pop up the existing one,
 * rather than creating a new one.
 */
static GtkWidget *file_merge_w;

/* Merge existing with another file */
static void
file_merge_cmd(GtkWidget *w)
{
#if GTK_MAJOR_VERSION >= 2 && _WIN32
  win32_merge_file(GDK_WINDOW_HWND(top_level->window));
  packet_list_freeze();
  packet_list_thaw();
#else /* GTK_MAJOR_VERSION >= 2 && _WIN32 */
  GtkWidget	*main_hb, *main_vb, *ft_hb, *ft_lb, *filter_hbox,
		*filter_bt, *filter_te, *prepend_rb, *chrono_rb,
		*append_rb, *prev;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif
  GtkTooltips *tooltips = gtk_tooltips_new();
  /* No Apply button, and "OK" just sets our text widget, it doesn't
     activate it (i.e., it doesn't cause us to try to open the file). */
  static construct_args_t args = {
  	"Ethereal: Read Filter",
  	FALSE,
  	FALSE,
    TRUE
  };

  if (file_merge_w != NULL) {
    /* There's already an "Merge Capture File" dialog box; reactivate it. */
    reactivate_window(file_merge_w);
    return;
  }

  /* Default to saving all packets, in the file's current format. */
  filetype = cfile.cd_t;

  file_merge_w = file_selection_new("Ethereal: Merge with Capture File",
                                   FILE_SELECTION_OPEN);
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  /* it's annoying, that the file chooser dialog is already shown here,
     so we cannot use the correct gtk_window_set_default_size() to resize it */
  WIDGET_SET_SIZE(GTK_WINDOW(file_merge_w), DEF_WIDTH, DEF_HEIGHT);
#else
  gtk_window_set_default_size(GTK_WINDOW(file_merge_w), DEF_WIDTH, DEF_HEIGHT);
#endif

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(file_merge_w), accel_group);
#endif

  switch (prefs.gui_fileopen_style) {

  case FO_STYLE_LAST_OPENED:
    /* The user has specified that we should start out in the last directory
       we looked in.  If we've already opened a file, use its containing
       directory, if we could determine it, as the directory, otherwise
       use the "last opened" directory saved in the preferences file if
       there was one. */
    /* This is now the default behaviour in file_selection_new() */
    break;

  case FO_STYLE_SPECIFIED:
    /* The user has specified that we should always start out in a
       specified directory; if they've specified that directory,
       start out by showing the files in that dir. */
    if (prefs.gui_fileopen_dir[0] != '\0')
      file_selection_set_current_folder(file_merge_w, prefs.gui_fileopen_dir);
    break;
  }

  main_hb = gtk_hbox_new(FALSE, 3);
  file_selection_set_extra_widget(file_merge_w, main_hb);
  gtk_widget_show(main_hb);

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_box_pack_start(GTK_BOX(main_hb), main_vb, FALSE, FALSE, 0);
  gtk_widget_show(main_vb);

  /* File type row */
  range_tb = NULL;
  ft_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), ft_hb);
  gtk_widget_show(ft_hb);

  ft_lb = gtk_label_new("Merged output file type:");
  gtk_box_pack_start(GTK_BOX(ft_hb), ft_lb, FALSE, FALSE, 0);
  gtk_widget_show(ft_lb);

  ft_om = gtk_option_menu_new();

  /* Generate the list of file types we can save. */
  set_file_type_list(ft_om);
  gtk_box_pack_start(GTK_BOX(ft_hb), ft_om, FALSE, FALSE, 0);
  gtk_widget_show(ft_om);

  filter_hbox = gtk_hbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(filter_hbox), 0);
  gtk_box_pack_start(GTK_BOX(main_vb), filter_hbox, FALSE, FALSE, 0);
  gtk_widget_show(filter_hbox);

  filter_bt = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_DISPLAY_FILTER_ENTRY);
  SIGNAL_CONNECT(filter_bt, "clicked", display_filter_construct_cb, &args);
  SIGNAL_CONNECT(filter_bt, "destroy", filter_button_destroy_cb, NULL);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);

  filter_te = gtk_entry_new();
  OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_te, TRUE, TRUE, 3);
  SIGNAL_CONNECT(filter_te, "changed", filter_te_syntax_check_cb, NULL);
  gtk_widget_show(filter_te);

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  OBJECT_SET_DATA(file_merge_w, E_RFILTER_TE_KEY, filter_te);
#else
  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_merge_w)->ok_button,
                  E_RFILTER_TE_KEY, filter_te);
#endif

  prepend_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(NULL, "Prepend packets to existing file", accel_group);
  gtk_tooltips_set_tip(tooltips, prepend_rb,
      "The resulting file contains the packets from the selected, followed by the packets from the currently loaded file,"
      " the packet timestamps will be ignored.", NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), prepend_rb, FALSE, FALSE, 0);
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  OBJECT_SET_DATA(file_merge_w,
                  E_MERGE_PREPEND_KEY, prepend_rb);
#else
  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_merge_w)->ok_button,
                  E_MERGE_PREPEND_KEY, prepend_rb);
#endif
  gtk_widget_show(prepend_rb);

  chrono_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(prepend_rb, "Merge packets chronologically", accel_group);
  gtk_tooltips_set_tip(tooltips, chrono_rb,
      "The resulting file contains all the packets from the currently loaded and the selected file,"
      " sorted by the packet timestamps.", NULL);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chrono_rb), TRUE);
  gtk_box_pack_start(GTK_BOX(main_vb), chrono_rb, FALSE, FALSE, 0);
  gtk_widget_show(chrono_rb);
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  OBJECT_SET_DATA(file_merge_w, E_MERGE_CHRONO_KEY, chrono_rb);
#else
  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_merge_w)->ok_button,
		  E_MERGE_CHRONO_KEY, chrono_rb);
#endif

  append_rb = RADIO_BUTTON_NEW_WITH_MNEMONIC(prepend_rb, "Append packets to existing file", accel_group);
  gtk_tooltips_set_tip(tooltips, append_rb,
      "The resulting file contains the packets from the currently loaded, followed by the packets from the selected file,"
      " the packet timestamps will be ignored.", NULL);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(append_rb),
	g_resolv_flags & RESOLV_TRANSPORT);
  gtk_box_pack_start(GTK_BOX(main_vb), append_rb, FALSE, FALSE, 0);
  gtk_widget_show(append_rb);
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  OBJECT_SET_DATA(file_merge_w, E_MERGE_APPEND_KEY, append_rb);
#else
  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_merge_w)->ok_button,
		  E_MERGE_APPEND_KEY, append_rb);
#endif


  SIGNAL_CONNECT(file_merge_w, "destroy", file_merge_destroy_cb, NULL);

  /* preview widget */
  prev = preview_new();
  OBJECT_SET_DATA(file_merge_w, PREVIEW_TABLE_KEY, prev);
  gtk_widget_show_all(prev);
  gtk_box_pack_start(GTK_BOX(main_hb), prev, TRUE, TRUE, 0);

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  SIGNAL_CONNECT(GTK_FILE_CHOOSER(file_merge_w), "selection-changed",
      file_open_entry_changed, file_merge_w);
  file_open_entry_changed(file_merge_w, file_merge_w);

  OBJECT_SET_DATA(file_merge_w, E_DFILTER_TE_KEY,
                  OBJECT_GET_DATA(w, E_DFILTER_TE_KEY));
  if (gtk_dialog_run(GTK_DIALOG(file_merge_w)) == GTK_RESPONSE_ACCEPT)
  {
    file_merge_ok_cb(file_merge_w, file_merge_w);
  }
  else window_destroy(file_merge_w);
#else /* (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2 */
  SIGNAL_CONNECT(GTK_FILE_SELECTION(file_merge_w)->selection_entry, "changed",
      file_open_entry_changed, file_merge_w);

  /* Connect the ok_button to file_merge_ok_cb function and pass along a
     pointer to the file selection box widget */
  SIGNAL_CONNECT(GTK_FILE_SELECTION(file_merge_w)->ok_button, "clicked",
                 file_merge_ok_cb, file_merge_w);

  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_merge_w)->ok_button,
                  E_DFILTER_TE_KEY, OBJECT_GET_DATA(w, E_DFILTER_TE_KEY));

  /* Connect the cancel_button to destroy the widget */
  window_set_cancel_button(file_merge_w,
      GTK_FILE_SELECTION(file_merge_w)->cancel_button, window_cancel_button_cb);

  SIGNAL_CONNECT(file_merge_w, "delete_event", window_delete_event_cb, NULL);

  gtk_widget_show(file_merge_w);
  window_present(file_merge_w);
#endif /* (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2 */
#endif /* GTK_MAJOR_VERSION >= 2 && _WIN32 */
}

static void file_merge_answered_cb(gpointer dialog _U_, gint btn, gpointer data _U_)
{
    switch(btn) {
    case(ESD_BTN_OK):
        /* save file first */
        file_save_as_cmd(after_save_merge_dialog, data);
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}

void
file_merge_cmd_cb(GtkWidget *widget, gpointer data _U_) {
  gpointer  dialog;

  if((cfile.state != FILE_CLOSED) && !cfile.user_saved && prefs.gui_ask_unsaved) {
    /* user didn't saved his current file, ask him */
    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_OK_CANCEL,
                PRIMARY_TEXT_START "Save the capture file before merging to another one?" PRIMARY_TEXT_END "\n\n"
                "A temporary capture file can't be merged.");
    simple_dialog_set_cb(dialog, file_merge_answered_cb, widget);
  } else {
    /* unchanged file, just start to merge */
    file_merge_cmd(widget);
  }
}


static void
file_merge_ok_cb(GtkWidget *w, gpointer fs) {
  gchar       *cf_name, *s;
  const gchar *rfilter;
  GtkWidget   *filter_te, *rb;
  dfilter_t   *rfcode = NULL;
  int          err;
  cf_status_t  merge_status;
  char        *in_filenames[2];
  char        *tmpname;

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  cf_name = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs)));
#else
  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
#endif
  filter_te = OBJECT_GET_DATA(w, E_RFILTER_TE_KEY);
  rfilter = gtk_entry_get_text(GTK_ENTRY(filter_te));
  if (!dfilter_compile(rfilter, &rfcode)) {
    bad_dfilter_alert_box(rfilter);
    g_free(cf_name);
    return;
  }

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(cf_name) == EISDIR) {
	/* It's a directory - set the file selection box to display that
	   directory, don't try to open the directory as a capture file. */
        set_last_open_dir(cf_name);
        g_free(cf_name);
        file_selection_set_current_folder(fs, get_last_open_dir());
    	return;
  }

  /* merge or append the two files */
  rb = OBJECT_GET_DATA(w, E_MERGE_CHRONO_KEY);
  tmpname = NULL;
  if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (rb))) {
      /* chronological order */
      in_filenames[0] = cfile.filename;
      in_filenames[1] = cf_name;
      merge_status = cf_merge_files(&tmpname, 2, in_filenames, filetype, FALSE);
  } else {
      rb = OBJECT_GET_DATA(w, E_MERGE_PREPEND_KEY);
      if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (rb))) {
          /* prepend file */
          in_filenames[0] = cfile.filename;
          in_filenames[1] = cf_name;
          merge_status = cf_merge_files(&tmpname, 2, in_filenames, filetype,
                                        TRUE);
      } else {
          /* append file */
          in_filenames[0] = cf_name;
          in_filenames[1] = cfile.filename;
          merge_status = cf_merge_files(&tmpname, 2, in_filenames, filetype,
                                        TRUE);
      }
  }

  g_free(cf_name);

  if (merge_status != CF_OK) {
    if (rfcode != NULL)
      dfilter_free(rfcode);
    g_free(tmpname);
    return;
  }

  cf_close(&cfile);

  /* We've crossed the Rubicon; get rid of the file selection box. */
  window_destroy(GTK_WIDGET (fs));

  /* Try to open the merged capture file. */
  if (cf_open(&cfile, tmpname, TRUE /* temporary file */, &err) != CF_OK) {
    /* We couldn't open it; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the open error,
       try again. */
    if (rfcode != NULL)
      dfilter_free(rfcode);
    g_free(tmpname);
    return;
  }
  g_free(tmpname);

  /* Attach the new read filter to "cf" ("cf_open()" succeeded, so
     it closed the previous capture file, and thus destroyed any
     previous read filter attached to "cf"). */
  cfile.rfcode = rfcode;

  switch (cf_read(&cfile)) {

  case CF_READ_OK:
  case CF_READ_ERROR:
    /* Just because we got an error, that doesn't mean we were unable
       to read any of the file; we handle what we could get from the
       file. */
    break;

  case CF_READ_ABORTED:
    /* The user bailed out of re-reading the capture file; the
       capture file has been closed - just free the capture file name
       string and return (without changing the last containing
       directory). */
    return;
  }

  /* Save the name of the containing directory specified in the path name,
     if any; we can write over cf_merged_name, which is a good thing, given that
     "get_dirname()" does write over its argument. */
  s = get_dirname(tmpname);
  set_last_open_dir(s);
  gtk_widget_grab_focus(packet_list);
}

static void
file_merge_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "Merge Capture File" dialog box. */
  file_merge_w = NULL;
}


static void file_close_answered_cb(gpointer dialog _U_, gint btn, gpointer data _U_)
{
    switch(btn) {
    case(ESD_BTN_SAVE):
        /* save file first */
        file_save_as_cmd(after_save_close_file, NULL);
        break;
    case(ESD_BTN_DONT_SAVE):
        cf_close(&cfile);
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}

/* Close a file */
void
file_close_cmd_cb(GtkWidget *widget _U_, gpointer data _U_) {
  gpointer  dialog;

  if((cfile.state != FILE_CLOSED) && !cfile.user_saved && prefs.gui_ask_unsaved) {
    /* user didn't saved his current file, ask him */
    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_DONTSAVE_CANCEL,
                PRIMARY_TEXT_START "Save capture file before closing it?" PRIMARY_TEXT_END "\n\n"
                "If you close without saving, your capture data will be discarded.");

    simple_dialog_set_cb(dialog, file_close_answered_cb, NULL);
  } else {
    /* unchanged file, just close it */
    cf_close(&cfile);
  }
}

void
file_save_cmd_cb(GtkWidget *w, gpointer data) {
  /* If the file's already been saved, do nothing.  */
  if (cfile.user_saved)
    return;

  /* Do a "Save As". */
  file_save_as_cmd_cb(w, data);
}

static gboolean
can_save_with_wiretap(int ft)
{
  /* To save a file with Wiretap, Wiretap has to handle that format,
     and its code to handle that format must be able to write a file
     with this file's encapsulation type. */
  return wtap_dump_can_open(ft) && wtap_dump_can_write_encap(ft, cfile.lnk_t);
}


/* Generate a list of the file types we can save this file as, by
   checking what Wiretap supports. */
static void
set_file_type_list(GtkWidget *option_menu)
{
  GtkWidget *ft_menu, *ft_menu_item;
  int ft;
  guint index;
  guint item_to_select;

  /* Default to the first supported file type, if the file's current
     type isn't supported. */
  item_to_select = 0;

  ft_menu = gtk_menu_new();

  /* Check all file types. */
  index = 0;
  for (ft = 0; ft < WTAP_NUM_FILE_TYPES; ft++) {
    if (can_save_with_wiretap(ft)) {
      /* OK, we can write it out in this type. */
      ft_menu_item = gtk_menu_item_new_with_label(wtap_file_type_string(ft));
      if (ft == filetype) {
        /* Default to the same format as the file, if it's supported. */
        item_to_select = index;
      }
      SIGNAL_CONNECT(ft_menu_item, "activate", select_file_type_cb,
                     GINT_TO_POINTER(ft));
      gtk_menu_append(GTK_MENU(ft_menu), ft_menu_item);
      gtk_widget_show(ft_menu_item);
      index++;
    }
  }

  gtk_option_menu_set_menu(GTK_OPTION_MENU(option_menu), ft_menu);
  gtk_option_menu_set_history(GTK_OPTION_MENU(option_menu), item_to_select);
}

static void
select_file_type_cb(GtkWidget *w _U_, gpointer data)
{
  int new_filetype = GPOINTER_TO_INT(data);
  GtkWidget *compressed_cb;

  if (filetype != new_filetype) {
    filetype = new_filetype;
    compressed_cb = OBJECT_GET_DATA(file_save_as_w, "compressed");
    gtk_widget_set_sensitive(compressed_cb, wtap_dump_can_compress(new_filetype));
  }
}


/*
 * Update various dynamic parts of the range controls; called from outside
 * the file dialog code whenever the packet counts change.
 */
void
file_save_update_dynamics(void)
{
  if (file_save_as_w == NULL) {
    /* We don't currently have a "Save As..." dialog box up. */
    return;
  }

  range_update_dynamics(range_tb);
}


action_after_save_e action_after_save_g;
gpointer            action_after_save_data_g;


void
file_save_as_cmd(action_after_save_e action_after_save, gpointer action_after_save_data)
{
#if GTK_MAJOR_VERSION >= 2 && _WIN32
  win32_save_as_file(GDK_WINDOW_HWND(top_level->window), action_after_save, action_after_save_data);
#else /* GTK_MAJOR_VERSION >= 2 && _WIN32 */
  GtkWidget     *main_vb, *ft_hb, *ft_lb, *range_fr, *compressed_cb;
  GtkTooltips   *tooltips;

#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif

  if (file_save_as_w != NULL) {
    /* There's already an "Save Capture File As" dialog box; reactivate it. */
    reactivate_window(file_save_as_w);
    return;
  }

  /* Default to saving all packets, in the file's current format. */
  filetype = cfile.cd_t;

  /* init the packet range */
  packet_range_init(&range);

  /* Enable tooltips */
  tooltips = gtk_tooltips_new();

  /* build the file selection */
  file_save_as_w = file_selection_new ("Ethereal: Save Capture File As",
                                       FILE_SELECTION_SAVE);

  /* as the dialog might already be gone, when using this values, we cannot
   * set data to the dialog object, but keep global values */
  action_after_save_g       = action_after_save;
  action_after_save_data_g  = action_after_save_data;

#if GTK_MAJOR_VERSION < 2
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(file_save_as_w), accel_group);
#endif

  /* Container for each row of widgets */

  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  file_selection_set_extra_widget(file_save_as_w, main_vb);
  gtk_widget_show(main_vb);

  /*** Packet Range frame ***/
  range_fr = gtk_frame_new("Packet Range");
  gtk_box_pack_start(GTK_BOX(main_vb), range_fr, FALSE, FALSE, 0);
  gtk_widget_show(range_fr);

  /* range table */
  range_tb = range_new(&range
#if GTK_MAJOR_VERSION < 2
  , accel_group
#endif
  );
  gtk_container_add(GTK_CONTAINER(range_fr), range_tb);
  gtk_widget_show(range_tb);

  /* File type row */
  ft_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), ft_hb);
  gtk_widget_show(ft_hb);

  ft_lb = gtk_label_new("File type:");
  gtk_box_pack_start(GTK_BOX(ft_hb), ft_lb, FALSE, FALSE, 0);
  gtk_widget_show(ft_lb);

  ft_om = gtk_option_menu_new();

  /* Generate the list of file types we can save. */
  set_file_type_list(ft_om);
  gtk_box_pack_start(GTK_BOX(ft_hb), ft_om, FALSE, FALSE, 0);
  gtk_widget_show(ft_om);

  /* dynamic values in the range frame */
  range_update_dynamics(range_tb);

  /* compressed */
  compressed_cb = gtk_check_button_new_with_label("Compress with gzip");
  gtk_container_add(GTK_CONTAINER(ft_hb), compressed_cb);
  /* XXX - disable output compression for now, as this doesn't work with the
   * current optimization to simply copy a capture file if it's using the same
   * encapsulation ... */
  /* the rest of the implementation is just working fine :-( */
  /*gtk_widget_show(compressed_cb);*/
  OBJECT_SET_DATA(file_save_as_w, "compressed", compressed_cb);
  gtk_widget_set_sensitive(compressed_cb, wtap_dump_can_compress(cfile.cd_t));

  SIGNAL_CONNECT(file_save_as_w, "destroy", file_save_as_destroy_cb, NULL);

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  if (gtk_dialog_run(GTK_DIALOG(file_save_as_w)) == GTK_RESPONSE_ACCEPT) {
    file_save_as_ok_cb(file_save_as_w, file_save_as_w);
  } else {
    window_destroy(file_save_as_w);
  }
#else /* (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2 */
  /* Connect the ok_button to file_save_as_ok_cb function and pass along a
     pointer to the file selection box widget */
  SIGNAL_CONNECT(GTK_FILE_SELECTION (file_save_as_w)->ok_button, "clicked",
                 file_save_as_ok_cb, file_save_as_w);

  window_set_cancel_button(file_save_as_w,
      GTK_FILE_SELECTION(file_save_as_w)->cancel_button, window_cancel_button_cb);

  SIGNAL_CONNECT(file_save_as_w, "delete_event", window_delete_event_cb, NULL);

  gtk_widget_show(file_save_as_w);
  window_present(file_save_as_w);
#endif /* (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2 */
#endif /* GTK_MAJOR_VERSION >= 2 && _WIN32 */
}

void
file_save_as_cmd_cb(GtkWidget *w _U_, gpointer data _U_)
{
  file_save_as_cmd(after_save_no_action, NULL);
}


/* all tests ok, we only have to save the file */
/* (and probably continue with a pending operation) */
static void
file_save_as_cb(GtkWidget *w _U_, gpointer fs) {
  gchar	*cf_name;
  gchar	*dirname;
  GtkWidget *compressed_cb;


#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  cf_name = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs)));
#else
  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
#endif

  compressed_cb = OBJECT_GET_DATA(file_save_as_w, "compressed");

  /* Write out the packets (all, or only the ones from the current
     range) to the file with the specified name. */
  if (cf_save(&cfile, cf_name, &range, filetype,
	  gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(compressed_cb))) != CF_OK) {
    /* The write failed; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the error, try again. */
    g_free(cf_name);
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
    /* XXX - as we cannot start a new event loop (using gtk_dialog_run()),
     * as this will prevent the user from closing the now existing error
     * message, simply close the dialog (this is the best we can do here). */
    if (file_save_as_w)
      window_destroy(GTK_WIDGET (fs));
#else
    gtk_widget_show(GTK_WIDGET (fs));
#endif
    return;
  }

  /* The write succeeded; get rid of the file selection box. */
  /* cf_save() might already closed our dialog! */
  if (file_save_as_w)
    window_destroy(GTK_WIDGET (fs));

  /* Save the directory name for future file dialogs. */
  dirname = get_dirname(cf_name);  /* Overwrites cf_name */
  set_last_open_dir(dirname);
  g_free(cf_name);

  /* we have finished saving, do we have pending things to do? */
  switch(action_after_save_g) {
  case(after_save_no_action):
      break;
  case(after_save_open_dialog):
      file_open_cmd(action_after_save_data_g);
      break;
  case(after_save_open_recent_file):
      menu_open_recent_file_cmd(action_after_save_data_g);
      break;
  case(after_save_open_dnd_file):
      dnd_open_file_cmd(action_after_save_data_g);
      break;
  case(after_save_merge_dialog):
      file_merge_cmd(action_after_save_data_g);
      break;
#ifdef HAVE_LIBPCAP
  case(after_save_capture_dialog):
      capture_start_confirmed();
      break;
#endif
  case(after_save_close_file):
      cf_close(&cfile);
      break;
  case(after_save_exit):
      main_do_quit();
      break;
  default:
      g_assert_not_reached();
  }

  action_after_save_g = after_save_no_action;
}


static void file_save_as_exists_answered_cb(gpointer dialog _U_, gint btn, gpointer data)
{
    gchar	*cf_name;

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
    cf_name = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(data)));
#else
    cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(data)));
#endif

    switch(btn) {
    case(ESD_BTN_OK):
        /* save file */
        unlink(cf_name);
        file_save_as_cb(NULL, data);
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}


/* user pressed "Save" dialog "Ok" button */
static void
file_save_as_ok_cb(GtkWidget *w _U_, gpointer fs) {
  gchar	*cf_name;
  gpointer  dialog;

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  cf_name = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs)));
#else
  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
#endif

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(cf_name) == EISDIR) {
        /* It's a directory - set the file selection box to display that
           directory, and leave the selection box displayed. */
        set_last_open_dir(cf_name);
        g_free(cf_name);
        file_selection_set_current_folder(fs, get_last_open_dir());
        return;
  }

  /* Check whether the range is valid. */
  if (!range_check_validity(&range)) {
    /* The range isn't valid; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the error, try again. */
    g_free(cf_name);
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
    /* XXX - as we cannot start a new event loop (using gtk_dialog_run()),
     * as this will prevent the user from closing the now existing error
     * message, simply close the dialog (this is the best we can do here). */
    if (file_save_as_w)
      window_destroy(GTK_WIDGET (fs));
#else
    gtk_widget_show(GTK_WIDGET (fs));
#endif
    return;
  }

  /*
   * Check that the from file is not the same as to file
   * We do it here so we catch all cases ...
   * Unfortunately, the file requester gives us an absolute file
   * name and the read file name may be relative (if supplied on
   * the command line). From Joerg Mayer.
   */
  if (files_identical(cfile.filename, cf_name)) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "%sCapture file: \"%s\" identical to loaded file!%s\n\n"
      "Please choose a different filename.",
      simple_dialog_primary_start(), cf_name, simple_dialog_primary_end());
    g_free(cf_name);
#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
    /* XXX - as we cannot start a new event loop (using gtk_dialog_run()),
     * as this will prevent the user from closing the now existing error
     * message, simply close the dialog (this is the best we can do here). */
    if (file_save_as_w)
      window_destroy(GTK_WIDGET (fs));
#else
    gtk_widget_show(GTK_WIDGET (fs));
#endif
    return;
  }

  /* don't show the dialog while saving (or asking) */
  gtk_widget_hide(GTK_WIDGET (fs));

  /* it the file doesn't exist, simply try to save it */
  if (!file_exists(cf_name)) {
    file_save_as_cb(NULL, fs);
    g_free(cf_name);
    return;
  }

  /* the file exists, ask the user to remove it first */
  dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_OK_CANCEL,
      PRIMARY_TEXT_START "A file named \"%s\" already exists."
      PRIMARY_TEXT_END "\n\n"
      "Do you want to replace it with the capture you are saving?", cf_name);
  simple_dialog_set_cb(dialog, file_save_as_exists_answered_cb, fs);

  g_free(cf_name);
}

void
file_save_as_destroy(void)
{
  if (file_save_as_w)
    window_destroy(file_save_as_w);
}

static void
file_save_as_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "Save Capture File As" dialog box. */
  file_save_as_w = NULL;
}

/* Reload a file using the current read and display filters */
void
file_reload_cmd_cb(GtkWidget *w _U_, gpointer data _U_) {
  cf_reload(&cfile);
}

/******************** Color Filters *********************************/
/*
 * Keep a static pointer to the current "Color Export" window, if
 * any, so that if somebody tries to do "Export"
 * while there's already a "Color Export" window up, we just pop
 * up the existing one, rather than creating a new one.
 */
static GtkWidget *file_color_import_w;

/* sets the file path to the global color filter file.
   WARNING: called by both the import and the export dialog.
*/
static void
color_global_cb(GtkWidget *widget _U_, gpointer data)
{
  GtkWidget *fs_widget = data;
  gchar *path;

  /* decide what file to open (from dfilter code) */
  path = get_datafile_path("colorfilters");

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  gtk_file_chooser_select_filename(GTK_FILE_CHOOSER(fs_widget), path);
#else
  file_selection_set_current_folder(fs_widget, path);
#endif
  g_free((gchar *)path);
}

/* Import color filters */
void
file_color_import_cmd_cb(GtkWidget *w _U_, gpointer data)
{
#if GTK_MAJOR_VERSION >= 2 && _WIN32
  win32_import_color_file(GDK_WINDOW_HWND(top_level->window));
#else /* GTK_MAJOR_VERSION >= 2 && _WIN32 */
  GtkWidget	*main_vb, *cfglobal_but;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif

  /* No Apply button, and "OK" just sets our text widget, it doesn't
     activate it (i.e., it doesn't cause us to try to open the file). */

  if (file_color_import_w != NULL) {
    /* There's already an "Import Color Filters" dialog box; reactivate it. */
    reactivate_window(file_color_import_w);
    return;
  }

  file_color_import_w = file_selection_new("Ethereal: Import Color Filters",
                                           FILE_SELECTION_OPEN);

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(file_color_import_w), accel_group);
#endif

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  file_selection_set_extra_widget(file_color_import_w, main_vb);
  gtk_widget_show(main_vb);


  cfglobal_but = gtk_button_new_with_label("Global Color Filter File");
  gtk_container_add(GTK_CONTAINER(main_vb), cfglobal_but);
  SIGNAL_CONNECT(cfglobal_but, "clicked", color_global_cb, file_color_import_w);
  gtk_widget_show(cfglobal_but);

  SIGNAL_CONNECT(file_color_import_w, "destroy", file_color_import_destroy_cb, NULL);

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  OBJECT_SET_DATA(file_color_import_w, ARGUMENT_CL, data);

  if (gtk_dialog_run(GTK_DIALOG(file_color_import_w)) == GTK_RESPONSE_ACCEPT)
  {
      file_color_import_ok_cb(file_color_import_w, file_color_import_w);
  }
  else window_destroy(file_color_import_w);
#else /* (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2 */
  /* Connect the ok_button to file_open_ok_cb function and pass along a
     pointer to the file selection box widget */
  SIGNAL_CONNECT(GTK_FILE_SELECTION(file_color_import_w)->ok_button, "clicked",
                 file_color_import_ok_cb, file_color_import_w);

  OBJECT_SET_DATA(GTK_FILE_SELECTION(file_color_import_w)->ok_button,
                  ARGUMENT_CL, data);

  window_set_cancel_button(file_color_import_w,
      GTK_FILE_SELECTION(file_color_import_w)->cancel_button, window_cancel_button_cb);

  SIGNAL_CONNECT(file_color_import_w, "delete_event", window_delete_event_cb, NULL);


  gtk_widget_show(file_color_import_w);
  window_present(file_color_import_w);
#endif /* (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2 */
#endif /* GTK_MAJOR_VERSION >= 2 && _WIN32 */
}

static void
file_color_import_ok_cb(GtkWidget *w, gpointer fs) {
  gchar     *cf_name, *s;
  gpointer  argument;

  argument = OBJECT_GET_DATA(w, ARGUMENT_CL);     /* to be passed back into color_filters_import */

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  cf_name = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs)));
#else
  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
#endif
  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(cf_name) == EISDIR) {
	/* It's a directory - set the file selection box to display that
	   directory, don't try to open the directory as a color filter file. */
        set_last_open_dir(cf_name);
        g_free(cf_name);
        file_selection_set_current_folder(fs, get_last_open_dir());
    	return;
  }

  /* Try to open the color filter file. */

  if (!color_filters_import(cf_name, argument)) {
    /* We couldn't open it; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the open error,
       try again. */
    g_free(cf_name);
    return;
  }

  /* We've crossed the Rubicon; get rid of the file selection box. */
  window_destroy(GTK_WIDGET (fs));

  /* Save the name of the containing directory specified in the path name,
     if any; we can write over cf_name, which is a good thing, given that
     "get_dirname()" does write over its argument. */
  s = get_dirname(cf_name);
  set_last_open_dir(s);
  gtk_widget_grab_focus(packet_list);

  g_free(cf_name);
}

static void
file_color_import_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a "Open Capture File" dialog box. */
  file_color_import_w = NULL;
}

static GtkWidget *file_color_export_w;
/*
 * Set the "Export only marked filters" toggle button as appropriate for
 * the current output file type and count of marked filters.
 *
 * Called when the "Export" dialog box is created and when the marked
 * count changes.
 */
static void
color_set_export_marked_sensitive(GtkWidget * cfmark_cb)
{
  if (file_color_export_w == NULL) {
    /* We don't currently have an "Export" dialog box up. */
    return;
  }

  /* We can request that only the marked filters be saved only if
        there *are* marked filters. */
  if (color_marked_count() != 0)
    gtk_widget_set_sensitive(cfmark_cb, TRUE);
  else {
    /* Force the "Export only marked filters" toggle to "false", turn
       off the flag it controls. */
    color_marked = FALSE;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cfmark_cb), FALSE);
    gtk_widget_set_sensitive(cfmark_cb, FALSE);
  }
}

static void
color_toggle_marked_cb(GtkWidget *widget, gpointer data _U_)
{
  color_marked = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));
}

void
file_color_export_cmd_cb(GtkWidget *w _U_, gpointer data _U_)
{
#if GTK_MAJOR_VERSION >= 2 && _WIN32
  win32_export_color_file(GDK_WINDOW_HWND(top_level->window));
#else /* GTK_MAJOR_VERSION >= 2 && _WIN32 */
  GtkWidget *main_vb, *cfglobal_but;

  if (file_color_export_w != NULL) {
    /* There's already an "Color Filter Export" dialog box; reactivate it. */
    reactivate_window(file_color_export_w);
    return;
  }

  /* Default to saving all packets, in the file's current format. */
  color_marked   = FALSE;
  filetype = cfile.cd_t;

  file_color_export_w = file_selection_new("Ethereal: Export Color Filters",
                                           FILE_SELECTION_SAVE);

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  file_selection_set_extra_widget(file_color_export_w, main_vb);
  gtk_widget_show(main_vb);

  cfmark_cb = gtk_check_button_new_with_label("Export only marked filters");
  gtk_container_add(GTK_CONTAINER(main_vb), cfmark_cb);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cfmark_cb), FALSE);
  SIGNAL_CONNECT(cfmark_cb, "toggled", color_toggle_marked_cb, NULL);
  gtk_widget_show(cfmark_cb);
  color_set_export_marked_sensitive(cfmark_cb);

  cfglobal_but = gtk_button_new_with_label("Global Color Filter File");
  gtk_container_add(GTK_CONTAINER(main_vb), cfglobal_but);
  SIGNAL_CONNECT(cfglobal_but, "clicked", color_global_cb, file_color_export_w);
  gtk_widget_show(cfglobal_but);

  SIGNAL_CONNECT(file_color_export_w, "destroy", file_color_export_destroy_cb, NULL);

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  if (gtk_dialog_run(GTK_DIALOG(file_color_export_w)) == GTK_RESPONSE_ACCEPT)
  {
      file_color_export_ok_cb(file_color_export_w, file_color_export_w);
  }
  else window_destroy(file_color_export_w);
#else /* (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2 */
  /* Connect the ok_button to file_export_ok_cb function and pass along a
     pointer to the file selection box widget */
  SIGNAL_CONNECT(GTK_FILE_SELECTION (file_color_export_w)->ok_button, "clicked",
                 file_color_export_ok_cb, file_color_export_w);

  window_set_cancel_button(file_color_export_w,
      GTK_FILE_SELECTION(file_color_export_w)->cancel_button, window_cancel_button_cb);

  SIGNAL_CONNECT(file_color_export_w, "delete_event", window_delete_event_cb, NULL);


  gtk_file_selection_set_filename(GTK_FILE_SELECTION(file_color_export_w), "");

  gtk_widget_show(file_color_export_w);
  window_present(file_color_export_w);
#endif /* (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2 */
#endif /* GTK_MAJOR_VERSION >= 2 && _WIN32 */
}

static void
file_color_export_ok_cb(GtkWidget *w _U_, gpointer fs) {
  gchar	*cf_name;
  gchar	*dirname;

#if (GTK_MAJOR_VERSION == 2 && GTK_MINOR_VERSION >= 4) || GTK_MAJOR_VERSION > 2
  cf_name = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs)));
#else
  cf_name = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(fs)));
#endif

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(cf_name) == EISDIR) {
        /* It's a directory - set the file selection box to display that
           directory, and leave the selection box displayed. */
        set_last_open_dir(cf_name);
        g_free(cf_name);
        file_selection_set_current_folder(fs, get_last_open_dir());
        return;
  }

  /* Write out the filters (all, or only the ones that are currently
     displayed or marked) to the file with the specified name. */

   if (!color_filters_export(cf_name, color_marked))
   {
    /* The write failed; don't dismiss the open dialog box,
       just leave it around so that the user can, after they
       dismiss the alert box popped up for the error, try again. */

       g_free(cf_name);
       return;
   }

  /* The write succeeded; get rid of the file selection box. */
  window_destroy(GTK_WIDGET (fs));

  /* Save the directory name for future file dialogs. */
  dirname = get_dirname(cf_name);  /* Overwrites cf_name */
  set_last_open_dir(dirname);
  g_free(cf_name);
}

static void
file_color_export_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  file_color_export_w = NULL;
}
