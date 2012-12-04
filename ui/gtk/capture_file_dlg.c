/* capture_file_dlg.c
 * Dialog boxes for handling capture files
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>

#include <gtk/gtk.h>

#include <epan/filesystem.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>

#include "packet-range.h"
#include "globals.h"
#include "color.h"
#include "color_filters.h"
#include "merge.h"

#include "ui/util.h"
#include <wsutil/file_util.h>

#include "ui/alert_box.h"
#include "ui/file_dialog.h"
#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/ui_util.h"

#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/filter_dlg.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/file_dlg.h"
#include "ui/gtk/capture_file_dlg.h"
#include "ui/gtk/drag_and_drop.h"
#include "ui/gtk/main.h"
#include "ui/gtk/color_dlg.h"
#include "ui/gtk/packet_list.h"
#ifdef HAVE_LIBPCAP
#include "ui/gtk/capture_dlg.h"
#endif
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/range_utils.h"
#include "ui/gtk/filter_autocomplete.h"

#ifdef _WIN32
#define USE_WIN32_FILE_DIALOGS
#endif

#ifdef USE_WIN32_FILE_DIALOGS
#include <gdk/gdkwin32.h>
#include <windows.h>
#include "ui/win32/file_dlg_win32.h"
#endif

static void do_file_save(capture_file *cf, gboolean dont_reopen);
static void file_save_as_cmd(capture_file *cf, gboolean must_support_comments,
                            gboolean dont_reopen);
static void file_select_file_type_cb(GtkWidget *w, gpointer data);
static int set_file_type_list(GtkWidget *combo_box, capture_file *cf,
                              gboolean must_support_comments);
static gboolean test_file_close(capture_file *cf, gboolean from_quit,
                                const char *before_what);

#define E_FILE_TYPE_COMBO_BOX_KEY "file_type_combo_box"
#define E_COMPRESSED_CB_KEY       "compressed_cb"

#define PREVIEW_TABLE_KEY       "preview_table_key"
#define PREVIEW_FORMAT_KEY      "preview_format_key"
#define PREVIEW_SIZE_KEY        "preview_size_key"
#define PREVIEW_ELAPSED_KEY     "preview_elapsed_key"
#define PREVIEW_PACKETS_KEY     "preview_packets_key"
#define PREVIEW_FIRST_KEY       "preview_first_key"

/* XXX - can we make these not be static? */
static gboolean        color_selected;

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
    label = (GtkWidget *)g_object_get_data(G_OBJECT(prev), PREVIEW_FORMAT_KEY);
    gtk_label_set_text(GTK_LABEL(label), "-");
    label = (GtkWidget *)g_object_get_data(G_OBJECT(prev), PREVIEW_SIZE_KEY);
    gtk_label_set_text(GTK_LABEL(label), "-");
    label = (GtkWidget *)g_object_get_data(G_OBJECT(prev), PREVIEW_ELAPSED_KEY);
    gtk_label_set_text(GTK_LABEL(label), "-");
    label = (GtkWidget *)g_object_get_data(G_OBJECT(prev), PREVIEW_PACKETS_KEY);
    gtk_label_set_text(GTK_LABEL(label), "-");
    label = (GtkWidget *)g_object_get_data(G_OBJECT(prev), PREVIEW_FIRST_KEY);
    gtk_label_set_text(GTK_LABEL(label), "-");

    if(!cf_name) {
        return NULL;
    }

    if (test_for_directory(cf_name) == EISDIR) {
        label = (GtkWidget *)g_object_get_data(G_OBJECT(prev), PREVIEW_FORMAT_KEY);
        gtk_label_set_text(GTK_LABEL(label), "directory");
        return NULL;
    }

    wth = wtap_open_offline(cf_name, &err, &err_info, TRUE);
    if (wth == NULL) {
        label = (GtkWidget *)g_object_get_data(G_OBJECT(prev), PREVIEW_FORMAT_KEY);
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
    g_snprintf(string_buff, PREVIEW_STR_MAX, "%" G_GINT64_MODIFIER "d bytes", filesize);
    label = (GtkWidget *)g_object_get_data(G_OBJECT(prev), PREVIEW_SIZE_KEY);
    gtk_label_set_text(GTK_LABEL(label), string_buff);

    /* type */
    g_strlcpy(string_buff, wtap_file_type_string(wtap_file_type(wth)), PREVIEW_STR_MAX);
    label = (GtkWidget *)g_object_get_data(G_OBJECT(prev), PREVIEW_FORMAT_KEY);
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
    gint64      data_offset;
    const struct wtap_pkthdr *phdr;
    double      start_time = 0; /* seconds, with nsec resolution */
    double      stop_time = 0;  /* seconds, with nsec resolution */
    double      cur_time;
    unsigned int packets = 0;
    gboolean    is_breaked = FALSE;
    gchar       string_buff[PREVIEW_STR_MAX];
    time_t      ti_time;
    struct tm  *ti_tm;


    time(&time_preview);
    while ( (wtap_read(wth, &err, &err_info, &data_offset)) ) {
        phdr = wtap_phdr(wth);
        cur_time = wtap_nstime_to_sec(&phdr->ts);
        if(packets == 0) {
            start_time = cur_time;
            stop_time = cur_time;
        }
        if (cur_time < start_time) {
            start_time = cur_time;
        }
        if (cur_time > stop_time){
            stop_time = cur_time;
        }

        packets++;
        if(packets%1000 == 0) {
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
        label = (GtkWidget *)g_object_get_data(G_OBJECT(prev), PREVIEW_PACKETS_KEY);
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
    label = g_object_get_data(G_OBJECT(prev), PREVIEW_PACKETS_KEY);
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
    label = g_object_get_data(G_OBJECT(prev), PREVIEW_FIRST_KEY);
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
    label = (GtkWidget *)g_object_get_data(G_OBJECT(prev), PREVIEW_ELAPSED_KEY);
    gtk_label_set_text(GTK_LABEL(label), string_buff);

    wtap_close(wth);
}

#if 0
/* as the dialog layout will look very ugly when using the file chooser preview mechanism,
   simply use the same layout as in GTK2.0 */
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
    GtkWidget *prev = (GtkWidget *)g_object_get_data(G_OBJECT(file_sel), PREVIEW_TABLE_KEY);
    gchar *cf_name;
    gboolean have_preview;
    wtap       *wth;

    /* get the filename */
    cf_name = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_sel));

    /* set the filename to the preview */
    wth = preview_set_filename(prev, cf_name);
    have_preview = (wth != NULL);

    g_free(cf_name);

    /* make the preview widget sensitive */
    gtk_widget_set_sensitive(prev, have_preview);

    /*
     * XXX - if the Open button isn't sensitive, you can't type into
     * the location bar and select the file or directory you've typed.
     * See
     *
     *    https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=1791
     *
     * It's not as if allowing users to click Open when they've
     * selected a file that's not a valid capture file will cause
     * anything worse than an error dialog, so we'll leave the Open
     * button sensitive for now.  Perhaps making it sensitive if
     * cf_name is NULL would also work, although I don't know whether
     * there are any cases where it would be non-null when you've
     * typed in the location bar.
     *
     * XXX - Bug 1791 also notes that, with the line removed, Bill
     * Meier "somehow managed to get the file chooser window somewhat
     * wedged in that neither the cancel or open buttons were responsive".
     * That seems a bit odd, given that, without this line, we're not
     * monkeying with the Open button's sensitivity, but...
     */
#if 0
    /* make the open/save/... dialog button sensitive */

    gtk_dialog_set_response_sensitive(file_sel, GTK_RESPONSE_ACCEPT, have_preview);
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
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_widget_set_sensitive(label, sensitive);
    gtk_table_attach_defaults(GTK_TABLE(list), label, 0, 1, *row, *row+1);

    label = gtk_label_new(value);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
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

    label = add_string_to_table(table, &row, "Format:", "-");
    g_object_set_data(G_OBJECT(table), PREVIEW_FORMAT_KEY, label);
    label = add_string_to_table(table, &row, "Size:", "-");
    g_object_set_data(G_OBJECT(table), PREVIEW_SIZE_KEY, label);
    label = add_string_to_table(table, &row, "Packets:", "-");
    g_object_set_data(G_OBJECT(table), PREVIEW_PACKETS_KEY, label);
    label = add_string_to_table(table, &row, "First Packet:", "-");
    g_object_set_data(G_OBJECT(table), PREVIEW_FIRST_KEY, label);
    label = add_string_to_table(table, &row, "Elapsed time:", "-");
    g_object_set_data(G_OBJECT(table), PREVIEW_ELAPSED_KEY, label);

    return table;
}

#ifndef USE_WIN32_FILE_DIALOGS
/* Open a file */
static gboolean
gtk_open_file(GtkWidget *w, GString *file_name, GString *display_filter)
{
  GtkWidget     *file_open_w;
  GtkWidget     *main_hb, *main_vb, *filter_hbox, *filter_bt, *filter_te,
                *m_resolv_cb, *n_resolv_cb, *t_resolv_cb, *e_resolv_cb, *prev;
  /* No Apply button, and "OK" just sets our text widget, it doesn't
     activate it (i.e., it doesn't cause us to try to open the file). */
  static construct_args_t args = {
      "Wireshark: Display Filter",
      FALSE,
      FALSE,
    TRUE
  };
  gchar         *cf_name;

  if (!file_name || !display_filter)
    return FALSE;

  file_open_w = file_selection_new("Wireshark: Open Capture File",
                                   FILE_SELECTION_OPEN);
  /* it's annoying, that the file chooser dialog is already shown here,
     so we cannot use the correct gtk_window_set_default_size() to resize it */
  gtk_widget_set_size_request(file_open_w, DEF_WIDTH, DEF_HEIGHT);

  if (file_name->len > 0) {
    gchar *dirname = g_path_get_dirname(file_name->str);

    file_selection_set_current_folder(file_open_w, dirname);
    g_free(dirname);
  } else {
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
  }

  main_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);
  file_selection_set_extra_widget(file_open_w, main_hb);
  gtk_widget_show(main_hb);

  /* Container for each row of widgets */
  main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_box_pack_start(GTK_BOX(main_hb), main_vb, FALSE, FALSE, 0);
  gtk_widget_show(main_vb);

  /* Filter row */
  filter_hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(filter_hbox), 0);
  gtk_box_pack_start(GTK_BOX(main_vb), filter_hbox, FALSE, FALSE, 0);
  gtk_widget_show(filter_hbox);

  filter_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY);
  g_signal_connect(filter_bt, "clicked",
                   G_CALLBACK(display_filter_construct_cb), &args);
  g_signal_connect(filter_bt, "destroy",
                   G_CALLBACK(filter_button_destroy_cb), NULL);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);
  gtk_widget_set_tooltip_text(filter_bt, "Open the \"Display Filter\" dialog to edit/apply filters");

  filter_te = gtk_entry_new();
  g_object_set_data(G_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_te, TRUE, TRUE, 3);
  g_signal_connect(filter_te, "changed",
                   G_CALLBACK(filter_te_syntax_check_cb), NULL);
  g_object_set_data(G_OBJECT(filter_hbox), E_FILT_AUTOCOMP_PTR_KEY, NULL);
  g_signal_connect(filter_te, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
  g_signal_connect(file_open_w, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);
  colorize_filter_te_as_empty(filter_te);
  gtk_entry_set_text(GTK_ENTRY(filter_te), display_filter->str);
  gtk_widget_show(filter_te);
  gtk_widget_set_tooltip_text(filter_te, "Enter a display filter.");

  g_object_set_data(G_OBJECT(file_open_w), E_RFILTER_TE_KEY, filter_te);

  /* Resolve buttons */
  m_resolv_cb = gtk_check_button_new_with_mnemonic("Enable _MAC name resolution");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(m_resolv_cb),
                               gbl_resolv_flags.mac_name);
  gtk_box_pack_start(GTK_BOX(main_vb), m_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(m_resolv_cb);

  t_resolv_cb = gtk_check_button_new_with_mnemonic("Enable _transport name resolution");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(t_resolv_cb),
                               gbl_resolv_flags.transport_name);
  gtk_box_pack_start(GTK_BOX(main_vb), t_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(t_resolv_cb);

  n_resolv_cb = gtk_check_button_new_with_mnemonic("Enable _network name resolution");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(n_resolv_cb),
                               gbl_resolv_flags.network_name);
  gtk_box_pack_start(GTK_BOX(main_vb), n_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(n_resolv_cb);

  e_resolv_cb = gtk_check_button_new_with_mnemonic("Use _external network name resolver");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(e_resolv_cb),
                               gbl_resolv_flags.use_external_net_name_resolver);
  gtk_box_pack_start(GTK_BOX(main_vb), e_resolv_cb, FALSE, FALSE, 0);
  gtk_widget_show(e_resolv_cb);

  /* Preview widget */
  prev = preview_new();
  g_object_set_data(G_OBJECT(file_open_w), PREVIEW_TABLE_KEY, prev);
  gtk_widget_show_all(prev);
  gtk_box_pack_start(GTK_BOX(main_hb), prev, TRUE, TRUE, 0);

  g_signal_connect(GTK_FILE_CHOOSER(file_open_w), "selection-changed",
                   G_CALLBACK(file_open_entry_changed), file_open_w);
  file_open_entry_changed(file_open_w, file_open_w);

  g_object_set_data(G_OBJECT(file_open_w), E_DFILTER_TE_KEY,
                    g_object_get_data(G_OBJECT(w), E_DFILTER_TE_KEY));

  cf_name = file_selection_run(file_open_w);

  if (cf_name == NULL) {
    /* User cancelled or closed the dialog. */
    return FALSE;
  }

  g_string_printf(file_name, "%s", cf_name);
  g_free(cf_name);
  g_string_printf(display_filter, "%s", gtk_entry_get_text(GTK_ENTRY(filter_te)));

  /* Set the global resolving variable */
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(m_resolv_cb)))
    gbl_resolv_flags.mac_name = TRUE;
  else
    gbl_resolv_flags.mac_name = FALSE;
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(n_resolv_cb)))
   gbl_resolv_flags.network_name = TRUE;
  else
   gbl_resolv_flags.network_name = FALSE;
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(t_resolv_cb)))
    gbl_resolv_flags.transport_name = TRUE;
  else
    gbl_resolv_flags.transport_name = FALSE;
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(e_resolv_cb)))
    gbl_resolv_flags.use_external_net_name_resolver = TRUE;
  else
    gbl_resolv_flags.use_external_net_name_resolver = FALSE;

  /* We've crossed the Rubicon; get rid of the file selection box. */
  window_destroy(GTK_WIDGET(file_open_w));

  return TRUE;
}
#endif /* USE_WIN32_FILE_DIALOGS */

/* Open a file */

/*
 * <platform/>_open_file routines should upon entry...
 *   Set the path and fill in the filename if the path+filename is provided.
 *   Set the display filter if provided. Filter syntax should be checked.
 *   Set the name resolution check boxes to match the global settings.
 * ...and upon exit...
 *   Return TRUE on "OK" and "FALSE" on "Cancel".
 *   Set the global name resolution preferences on "OK".
 *   Close the window.
 */

static void
file_open_cmd(capture_file *cf, GtkWidget *w _U_)
{
  GString   *file_name = g_string_new("");
  GString   *display_filter = g_string_new("");
  dfilter_t *rfcode = NULL;
  int        err;

  /*
   * Loop until the user either selects a file or gives up.
   */
  for (;;) {
#ifdef USE_WIN32_FILE_DIALOGS
    if (win32_open_file(GDK_WINDOW_HWND(gtk_widget_get_window(top_level)), file_name, display_filter)) {
#else /* USE_WIN32_FILE_DIALOGS */
    if (gtk_open_file(top_level, file_name, display_filter)) {
#endif /* USE_WIN32_FILE_DIALOGS */

      /* Only close the old file now that we know we want to open another one. */
      cf_close(cf);
      /* apply our filter */
      if (dfilter_compile(display_filter->str, &rfcode)) {
        cf_set_rfcode(&cfile, rfcode);
      } else {
        /* Not valid.  Tell the user, and go back and run the file
           selection box again once they dismiss the alert. */
        bad_dfilter_alert_box(top_level, display_filter->str);
        continue;
      }

      /* Try to open the capture file. */
      if (cf_open(&cfile, file_name->str, FALSE, &err) != CF_OK) {
        /* We couldn't open it; don't dismiss the open dialog box,
           just leave it around so that the user can, after they
           dismiss the alert box popped up for the open error,
           try again. */
        if (rfcode != NULL)
          dfilter_free(rfcode);
          rfcode = NULL;
        continue;
      }

      switch (cf_read(&cfile, FALSE)) {

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
          g_string_free(file_name, TRUE);
          g_string_free(display_filter, TRUE);
          return;
      }
      /* Save the name of the containing directory specified in the path name,
         if any; we can write over cf_name, which is a good thing, given that
         "get_dirname()" does write over its argument. */
      set_last_open_dir(get_dirname(file_name->str));
      gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), display_filter->str);
    }
    g_string_free(file_name, TRUE);
    g_string_free(display_filter, TRUE);
    return;
  }
}

void
file_open_cmd_cb(GtkWidget *widget, gpointer data _U_) {
  /* If there's unsaved data, let the user save it first.
     If they cancel out of it, don't quit. */
  if (test_file_close(&cfile, FALSE, " before opening a new capture file"))
    file_open_cmd(&cfile, widget);
}

#ifndef USE_WIN32_FILE_DIALOGS
static gboolean
gtk_merge_file(GtkWidget *w, GString *file_name, GString *display_filter, int *merge_type)
{
  GtkWidget     *file_merge_w;
  GtkWidget     *main_hb, *main_vb, *filter_hbox, *filter_bt, *filter_te,
                *prepend_rb, *chrono_rb, *append_rb, *prev;

  /* No Apply button, and "OK" just sets our text widget, it doesn't
     activate it (i.e., it doesn't cause us to try to open the file). */
  static construct_args_t args = {
    "Wireshark: Display Filter",
    FALSE,
    FALSE,
    TRUE
  };
  gchar       *cf_name;

  if (!file_name || !display_filter || !merge_type)
    return FALSE;

  /* Default to saving all packets, in the file's current format. */

  file_merge_w = file_selection_new("Wireshark: Merge with Capture File",
                                   FILE_SELECTION_OPEN);
  /* it's annoying, that the file chooser dialog is already shown here,
     so we cannot use the correct gtk_window_set_default_size() to resize it */
  gtk_widget_set_size_request(file_merge_w, DEF_WIDTH, DEF_HEIGHT);

  if (file_name->len > 0) {
    gchar *dirname = g_path_get_dirname(file_name->str);

    file_selection_set_current_folder(file_merge_w, dirname);
    g_free(dirname);
  } else {
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
  }

  main_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);
  file_selection_set_extra_widget(file_merge_w, main_hb);
  gtk_widget_show(main_hb);

  /* Container for each row of widgets */
  main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_box_pack_start(GTK_BOX(main_hb), main_vb, FALSE, FALSE, 0);
  gtk_widget_show(main_vb);

  /* Filter row */
  filter_hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(filter_hbox), 0);
  gtk_box_pack_start(GTK_BOX(main_vb), filter_hbox, FALSE, FALSE, 0);
  gtk_widget_show(filter_hbox);

  filter_bt = gtk_button_new_from_stock(WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY);
  g_signal_connect(filter_bt, "clicked",
                   G_CALLBACK(display_filter_construct_cb), &args);
  g_signal_connect(filter_bt, "destroy",
                   G_CALLBACK(filter_button_destroy_cb), NULL);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);
  gtk_widget_set_tooltip_text(filter_bt, "Open the \"Display Filter\" dialog to edit/apply filters");

  filter_te = gtk_entry_new();
  g_object_set_data(G_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hbox), filter_te, TRUE, TRUE, 3);
  g_signal_connect(filter_te, "changed",
                   G_CALLBACK(filter_te_syntax_check_cb), NULL);
  g_object_set_data(G_OBJECT(filter_hbox), E_FILT_AUTOCOMP_PTR_KEY, NULL);
  g_signal_connect(filter_te, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
  g_signal_connect(file_merge_w, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);
  colorize_filter_te_as_empty(filter_te);
  gtk_entry_set_text(GTK_ENTRY(filter_te), display_filter->str);
  gtk_widget_show(filter_te);
  gtk_widget_set_tooltip_text(filter_te, "Enter a display filter.");

  g_object_set_data(G_OBJECT(file_merge_w), E_RFILTER_TE_KEY, filter_te);

  /* Merge type */
  prepend_rb = gtk_radio_button_new_with_mnemonic_from_widget(NULL,
      "Prepend packets");
  gtk_widget_set_tooltip_text(prepend_rb, "Insert packets from the selected file before the current file. Packet timestamps will be ignored.");
  gtk_box_pack_start(GTK_BOX(main_vb), prepend_rb, FALSE, FALSE, 0);
  gtk_widget_show(prepend_rb);

  chrono_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(prepend_rb), "Merge chronologically");
  gtk_widget_set_tooltip_text(chrono_rb, "Insert packets in chronological order.");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chrono_rb), TRUE);
  gtk_box_pack_start(GTK_BOX(main_vb), chrono_rb, FALSE, FALSE, 0);
  gtk_widget_show(chrono_rb);

  append_rb = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(prepend_rb), "Append packets");
  gtk_widget_set_tooltip_text(append_rb, "Insert packets from the selected file after the current file. Packet timestamps will be ignored.");
  gtk_box_pack_start(GTK_BOX(main_vb), append_rb, FALSE, FALSE, 0);
  gtk_widget_show(append_rb);

  /* Preview widget */
  prev = preview_new();
  g_object_set_data(G_OBJECT(file_merge_w), PREVIEW_TABLE_KEY, prev);
  gtk_widget_show_all(prev);
  gtk_box_pack_start(GTK_BOX(main_hb), prev, TRUE, TRUE, 0);

  g_signal_connect(GTK_FILE_CHOOSER(file_merge_w), "selection-changed",
                   G_CALLBACK(file_open_entry_changed), file_merge_w);
  file_open_entry_changed(file_merge_w, file_merge_w);

  g_object_set_data(G_OBJECT(file_merge_w), E_DFILTER_TE_KEY,
                    g_object_get_data(G_OBJECT(w), E_DFILTER_TE_KEY));

    cf_name = file_selection_run(file_merge_w);
  if (cf_name == NULL) {
    /* User cancelled or closed the dialog. */
    return FALSE;
  }

  g_string_printf(file_name, "%s", cf_name);
  g_free(cf_name);
  g_string_printf(display_filter, "%s", gtk_entry_get_text(GTK_ENTRY(filter_te)));

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chrono_rb))) {
    *merge_type = 0;
  } else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(prepend_rb))) {
    *merge_type = -1;
  } else {
    *merge_type = 1;
  }

  /* We've crossed the Rubicon; get rid of the file selection box. */
  window_destroy(GTK_WIDGET(file_merge_w));

  return TRUE;
}
#endif /* USE_WIN32_FILE_DIALOGS */

/* Merge existing with another file */

/*
 * <platform/>_merge_file routines should upon entry...
 *   Set the path and fill in the filename if the path+filename is provided.
 *   Set the display filter if provided. Filter syntax should be checked.
 * ...and upon exit...
 *   Return TRUE on "OK" and "FALSE" on "Cancel".
 *   Close the window.
 */

static void
file_merge_cmd(GtkWidget *w _U_)
{
  GString     *file_name = g_string_new("");
  GString     *display_filter = g_string_new("");
  int          merge_type;
  dfilter_t   *rfcode = NULL;
  int          err;
  int          file_type;
  cf_status_t  merge_status;
  char        *in_filenames[2];
  char        *tmpname = NULL;

  /*
   * Loop until the user either selects a file or gives up.
   */
  for (;;) {
    g_string_truncate(file_name, 0);
    g_string_truncate(display_filter, 0);
#ifdef USE_WIN32_FILE_DIALOGS
    if (win32_merge_file(GDK_WINDOW_HWND(gtk_widget_get_window(top_level)), file_name, display_filter, &merge_type)) {
#else /* USE_WIN32_FILE_DIALOGS */
    if (gtk_merge_file(top_level, file_name, display_filter, &merge_type)) {
#endif /* USE_WIN32_FILE_DIALOGS */

      /* Get the specified read filter and try to compile it. */
      if (!dfilter_compile(display_filter->str, &rfcode)) {
        /* Not valid.  Tell the user, and go back and run the file
           selection box again once they dismiss the alert. */
        bad_dfilter_alert_box(top_level, display_filter->str);
        continue;
      }

      file_type = cfile.cd_t;

      /* Try to merge or append the two files */
      tmpname = NULL;
      if (merge_type == 0) {
        /* chronological order */
        in_filenames[0] = cfile.filename;
        in_filenames[1] = file_name->str;
        merge_status = cf_merge_files(&tmpname, 2, in_filenames, file_type, FALSE);
      } else if (merge_type < 0) {
        /* prepend file */
        in_filenames[0] = file_name->str;
        in_filenames[1] = cfile.filename;
        merge_status = cf_merge_files(&tmpname, 2, in_filenames, file_type, TRUE);
      } else {
        /* append file */
        in_filenames[0] = cfile.filename;
        in_filenames[1] = file_name->str;
        merge_status = cf_merge_files(&tmpname, 2, in_filenames, file_type, TRUE);
      }

      if (merge_status != CF_OK) {
        if (rfcode != NULL)
          dfilter_free(rfcode);
        g_free(tmpname);
        continue;
      }

      cf_close(&cfile);

      /* Try to open the merged capture file. */
      if (cf_open(&cfile, tmpname, TRUE /* temporary file */, &err) != CF_OK) {
        /* We couldn't open it; fail. */
        if (rfcode != NULL)
          dfilter_free(rfcode);
        g_free(tmpname);
        g_string_free(file_name, TRUE);
        g_string_free(display_filter, TRUE);
        return;
      }

      /* Attach the new read filter to "cf" ("cf_open()" succeeded, so
         it closed the previous capture file, and thus destroyed any
         previous read filter attached to "cf"). */
      cfile.rfcode = rfcode;

      switch (cf_read(&cfile, FALSE)) {

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
        g_free(tmpname);
        g_string_free(file_name, TRUE);
        g_string_free(display_filter, TRUE);
        return;
      }
    }

    /* Save the name of the containing directory specified in the path name,
       if any; we can write over cf_merged_name, which is a good thing, given that
       "get_dirname()" does write over its argument. */
    if (tmpname) {
        set_last_open_dir(get_dirname(tmpname));
        g_free(tmpname);
    }
    g_string_free(file_name, TRUE);
    g_string_free(display_filter, TRUE);
    return;
  }
}

void
file_merge_cmd_cb(GtkWidget *widget, gpointer data _U_) {
  /* If there's unsaved data, let the user save it first.
     If they cancel out of it, don't merge. */
  GtkWidget *msg_dialog;
  gchar     *display_basename;
  gint       response;

  if (prefs.gui_ask_unsaved) {
    if (cfile.is_tempfile || cfile.unsaved_changes) {
      /* This is a temporary capture file or has unsaved changes; ask the
         user whether to save the capture. */
      if (cfile.is_tempfile) {
        msg_dialog = gtk_message_dialog_new(GTK_WINDOW(top_level),
                                            GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,
                                            GTK_MESSAGE_QUESTION,
                                            GTK_BUTTONS_NONE,
                                            "Do you want to save the captured packets before merging another capture file into it?");

        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(msg_dialog),
             "A temporary capture file can't be merged.");
      } else {
        /*
         * Format the message.
         */
        display_basename = g_filename_display_basename(cfile.filename);
        msg_dialog = gtk_message_dialog_new(GTK_WINDOW(top_level),
                                            GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,
                                            GTK_MESSAGE_QUESTION,
                                            GTK_BUTTONS_NONE,
                                            "Do you want to save the changes you've made "
                                            "to the capture file \"%s\" before merging another capture file into it?",
                                            display_basename);
        g_free(display_basename);
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(msg_dialog),
             "The changes must be saved before the files are merged.");
      }

#ifndef _WIN32
      gtk_dialog_add_button(GTK_DIALOG(msg_dialog),
                            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL);
      gtk_dialog_add_button(GTK_DIALOG(msg_dialog),
                            WIRESHARK_STOCK_FILE, GTK_RESPONSE_ACCEPT);
#else
      gtk_dialog_add_button(GTK_DIALOG(msg_dialog),
                            WIRESHARK_STOCK_FILE, GTK_RESPONSE_ACCEPT);
      gtk_dialog_add_button(GTK_DIALOG(msg_dialog),
                            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL);
#endif
      gtk_dialog_set_default_response(GTK_DIALOG(msg_dialog), GTK_RESPONSE_ACCEPT);

      response = gtk_dialog_run(GTK_DIALOG(msg_dialog));
      gtk_widget_destroy(msg_dialog);

      switch (response) {

      case GTK_RESPONSE_ACCEPT:
        /* Save the file but don't close it */
        do_file_save(&cfile, FALSE);
        break;

      case GTK_RESPONSE_CANCEL:
      case GTK_RESPONSE_NONE:
      case GTK_RESPONSE_DELETE_EVENT:
      default:
        /* Don't do the merge. */
        return;
      }
    }
  }

  /* Do the merge. */
  file_merge_cmd(widget);
}

#ifdef HAVE_LIBPCAP
static void
do_capture_stop(capture_file *cf)
{
  /* Stop the capture (complete with UI updates). */
  capture_stop_cb(NULL, NULL);

  /* Now run the main loop until the capture stops and we finish
     reading it; we need to run the main loop so we respond to
     messages on the sync pipe and the sync pipe being closed. */
  while (cf->state == FILE_READ_IN_PROGRESS)
    gtk_main_iteration();
}
#endif

/* Returns true if the current file has been saved or if the user has chosen
 * to discard it, ie if it is safe to continue with the call to close, and
 * false otherwise. */
gboolean
test_file_close(capture_file *cf, gboolean from_quit, const char *before_what)
{
  GtkWidget *msg_dialog;
  gchar     *display_basename;
  gint       response;
  gboolean   capture_in_progress;

  if (cf->state == FILE_CLOSED)
    return TRUE; /* already closed, nothing to do */

#ifdef HAVE_LIBPCAP
  if (cf->state == FILE_READ_IN_PROGRESS) {
    /* This is true if we're reading a capture file *or* if we're doing
       a live capture.  If we're reading a capture file, the main loop
       is busy reading packets, and only accepting input from the
       progress dialog, so we can't get here, so this means we're
       doing a capture. */
    capture_in_progress = TRUE;
  } else
#endif
    capture_in_progress = FALSE;

  if (prefs.gui_ask_unsaved) {
    if (cf->is_tempfile || capture_in_progress || cf->unsaved_changes) {
      /* This is a temporary capture file, or there's a capture in
         progress, or the file has unsaved changes; ask the user whether
         to save the data. */
      if (cf->is_tempfile) {
        msg_dialog = gtk_message_dialog_new(GTK_WINDOW(top_level),
                                            GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,
                                            GTK_MESSAGE_QUESTION,
                                            GTK_BUTTONS_NONE,
                                            capture_in_progress ?
                                                "Do you want to stop the capture and save the captured packets%s?" :
                                                "Do you want to save the captured packets%s?",
                                            before_what);

        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(msg_dialog),
             "Your captured packets will be lost if you don't save them.");
      } else {
        /*
         * Format the message.
         */
        display_basename = g_filename_display_basename(cf->filename);
        if (capture_in_progress) {
          msg_dialog = gtk_message_dialog_new(GTK_WINDOW(top_level),
                                              GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,
                                              GTK_MESSAGE_QUESTION,
                                              GTK_BUTTONS_NONE,
                                              "Do you want to stop the capture and save the captured packets%s?",
                                              before_what);
        } else {
          msg_dialog = gtk_message_dialog_new(GTK_WINDOW(top_level),
                                              GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,
                                              GTK_MESSAGE_QUESTION,
                                              GTK_BUTTONS_NONE,
                                              "Do you want to save the changes you've made "
                                              "to the capture file \"%s\"%s?",
                                              display_basename, before_what);
        }
        g_free(display_basename);
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(msg_dialog),
                                                 capture_in_progress ?
             "Your captured packets will be lost if you don't save them." :
             "Your changes will be lost if you don't save them.");
      }

#ifndef _WIN32
      /* If this is from a Quit operation, use "quit and don't save"
         rather than just "don't save". */
      gtk_dialog_add_button(GTK_DIALOG(msg_dialog),
                            (from_quit ?
                                (cf->state == FILE_READ_IN_PROGRESS ?
                                    WIRESHARK_STOCK_STOP_QUIT_DONT_SAVE :
                                    WIRESHARK_STOCK_QUIT_DONT_SAVE) :
                                (capture_in_progress ?
                                    WIRESHARK_STOCK_STOP_DONT_SAVE :
                                    WIRESHARK_STOCK_DONT_SAVE)),
                            GTK_RESPONSE_REJECT);
      gtk_dialog_add_button(GTK_DIALOG(msg_dialog),
                            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL);
      gtk_dialog_add_button(GTK_DIALOG(msg_dialog),
                            (capture_in_progress ?
                                WIRESHARK_STOCK_STOP_SAVE :
                                WIRESHARK_STOCK_FILE),
                            GTK_RESPONSE_ACCEPT);
#else
      gtk_dialog_add_button(GTK_DIALOG(msg_dialog),
                            (capture_in_progress ?
                                WIRESHARK_STOCK_STOP_SAVE :
                                WIRESHARK_STOCK_FILE),
                            GTK_RESPONSE_ACCEPT);
      gtk_dialog_add_button(GTK_DIALOG(msg_dialog),
                            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL);
      gtk_dialog_add_button(GTK_DIALOG(msg_dialog),
                            (from_quit ?
                                (capture_in_progress ?
                                    WIRESHARK_STOCK_STOP_QUIT_DONT_SAVE :
                                    WIRESHARK_STOCK_QUIT_DONT_SAVE) :
                                (capture_in_progress ?
                                    WIRESHARK_STOCK_STOP_DONT_SAVE :
                                    WIRESHARK_STOCK_DONT_SAVE)),
                            GTK_RESPONSE_REJECT);
#endif
      gtk_dialog_set_default_response(GTK_DIALOG(msg_dialog), GTK_RESPONSE_ACCEPT);

      response = gtk_dialog_run(GTK_DIALOG(msg_dialog));
      gtk_widget_destroy(msg_dialog);

      switch (response) {

      case GTK_RESPONSE_ACCEPT:
#ifdef HAVE_LIBPCAP
        /* If there's a capture in progress, we have to stop the capture
           and then do the save. */
        if (capture_in_progress)
          do_capture_stop(cf);
#endif
        /* Save the file and close it */
        do_file_save(cf, TRUE);
        break;

      case GTK_RESPONSE_REJECT:
#ifdef HAVE_LIBPCAP
        /* If there's a capture in progress; we have to stop the capture
           and then do the close. */
        if (capture_in_progress)
          do_capture_stop(cf);
#endif
        break;

      case GTK_RESPONSE_CANCEL:
      case GTK_RESPONSE_NONE:
      case GTK_RESPONSE_DELETE_EVENT:
      default:
        /* Don't close the file (and don't stop any capture in progress). */
        return FALSE; /* file not closed */
      }
    } else {
      /* unchanged file, safe to close */
      return TRUE;
    }
  } else {
    /* User asked not to be bothered by those prompts, just close it.
       XXX - should that apply only to saving temporary files? */
#ifdef HAVE_LIBPCAP
      /* If there's a capture in progress, we have to stop the capture
         and then do the close. */
    if (capture_in_progress)
      do_capture_stop(cf);
#endif
    return TRUE;
  }
  return TRUE; /* shouldn't get here? */
}

gboolean
do_file_close(capture_file *cf, gboolean from_quit, const char *before_what)
{
  if (test_file_close(cf, from_quit, before_what)) {
    cf_close(cf);
    return TRUE;
  }
  return FALSE;
}

/* Close a file */
void
file_close_cmd_cb(GtkWidget *widget _U_, gpointer data _U_) {
  do_file_close(&cfile, FALSE, "");
}

#define RESPONSE_DISCARD_COMMENTS_AND_SAVE 1
#define RESPONSE_SAVE_IN_ANOTHER_FORMAT    2

static check_savability_t
check_save_with_comments(capture_file *cf)
{
  GtkWidget     *msg_dialog;
  gint           response;

  /* Do we have any comments? */
  if (!cf_has_comments(cf)) {
    /* No.  Let the save happen; no comments to delete. */
    return SAVE;
  }

  /* OK, we have comments.  Can we write them out in the file's format?

     XXX - for now, we "know" that pcap-ng is the only format for which
     we support comments.  We should really ask Wiretap what the
     format in question supports (and handle different types of
     comments, some but not all of which some file formats might
     not support). */
  if (cf->cd_t == WTAP_FILE_PCAPNG) {
    /* Yes - the file is a pcap-ng file.  Let the save happen; we can
       save the comments, so no need to delete them. */
    return SAVE;
  }

  /* Is pcap-ng one of the formats in which we can write this file? */
  if (wtap_dump_can_write_encaps(WTAP_FILE_PCAPNG, cf->linktypes)) {
    /* Yes.  Ooffer the user a choice of "Save in a format that
       supports comments", "Discard comments and save in the
       file's own format", or "Cancel", meaning "don't bother
       saving the file at all". */
    msg_dialog = gtk_message_dialog_new(GTK_WINDOW(top_level),
                                        GTK_DIALOG_DESTROY_WITH_PARENT,
                                        GTK_MESSAGE_QUESTION,
                                        GTK_BUTTONS_NONE,
  "The capture has comments, but the file's format "
  "doesn't support comments.  Do you want to save the capture "
  "in a format that supports comments, or discard the comments "
  "and save in the file's format?");
#ifndef _WIN32
    gtk_dialog_add_buttons(GTK_DIALOG(msg_dialog),
                           "Discard comments and save",
                           RESPONSE_DISCARD_COMMENTS_AND_SAVE,
                           GTK_STOCK_CANCEL,
                           GTK_RESPONSE_CANCEL,
                           "Save in another format",
                           RESPONSE_SAVE_IN_ANOTHER_FORMAT,
                           NULL);
#else
    gtk_dialog_add_buttons(GTK_DIALOG(msg_dialog),
                           "Save in another format",
                           RESPONSE_SAVE_IN_ANOTHER_FORMAT,
                           GTK_STOCK_CANCEL,
                           GTK_RESPONSE_CANCEL,
                           "Discard comments and save",
                           RESPONSE_DISCARD_COMMENTS_AND_SAVE,
                           NULL);
#endif
    gtk_dialog_set_default_response(GTK_DIALOG(msg_dialog),
                                    RESPONSE_SAVE_IN_ANOTHER_FORMAT);
  } else {
    /* No.  Offer the user a choice of "Discard comments and
       save in the file's format" or "Cancel". */
    msg_dialog = gtk_message_dialog_new(GTK_WINDOW(top_level),
                                        GTK_DIALOG_DESTROY_WITH_PARENT,
                                        GTK_MESSAGE_QUESTION,
                                        GTK_BUTTONS_NONE,
  "The capture has comments, but no file format in which it "
  "can be saved supports comments.  Do you want to discard "
  "the comments and save in the file's format?");
#ifndef _WIN32
    gtk_dialog_add_buttons(GTK_DIALOG(msg_dialog),
                           "Discard comments and save",
                           RESPONSE_DISCARD_COMMENTS_AND_SAVE,
                           GTK_STOCK_CANCEL,
                           GTK_RESPONSE_CANCEL,
                           NULL);
#else
    gtk_dialog_add_buttons(GTK_DIALOG(msg_dialog),
                           GTK_STOCK_CANCEL,
                           GTK_RESPONSE_CANCEL,
                           "Discard comments and save",
                           RESPONSE_DISCARD_COMMENTS_AND_SAVE,
                           NULL);
#endif
    gtk_dialog_set_default_response(GTK_DIALOG(msg_dialog),
                                    GTK_RESPONSE_CANCEL);
  }

  response = gtk_dialog_run(GTK_DIALOG(msg_dialog));
  gtk_widget_destroy(msg_dialog);

  switch (response) {

  case RESPONSE_SAVE_IN_ANOTHER_FORMAT:
    /* Let the user select another format. */
    return SAVE_IN_ANOTHER_FORMAT;

  case RESPONSE_DISCARD_COMMENTS_AND_SAVE:
    /* Save without the comments and, if that succeeds, delete the
       comments. */
    return SAVE_WITHOUT_COMMENTS;

  case GTK_RESPONSE_CANCEL:
  case GTK_RESPONSE_NONE:
  case GTK_RESPONSE_DELETE_EVENT:
  default:
    /* Just give up. */
    return CANCELLED;
  }
}

/*
 * Save the capture file in question, prompting the user for a file
 * name to save to if necessary.
 */
static void
do_file_save(capture_file *cf, gboolean dont_reopen)
{
  char *fname;
  gboolean discard_comments;
  cf_write_status_t status;

  if (cf->is_tempfile) {
    /* This is a temporary capture file, so saving it means saving
       it to a permanent file.  Prompt the user for a location
       to which to save it.  Don't require that the file format
       support comments - if it's a temporary capture file, it's
       probably pcap-ng, which supports comments and, if it's
       not pcap-ng, let the user decide what they want to do
       if they've added comments. */
    file_save_as_cmd(cf, FALSE, dont_reopen);
  } else {
    if (cf->unsaved_changes) {
      /* This is not a temporary capture file, but it has unsaved
         changes, so saving it means doing a "safe save" on top
         of the existing file, in the same format - no UI needed
         unless the file has comments and the file's format doesn't
         support them.

         If the file has comments, does the file's format support them?
         If not, ask the user whether they want to discard the comments
         or choose a different format. */
      switch (check_save_with_comments(cf)) {

      case SAVE:
        /* The file can be saved in the specified format as is;
           just drive on and save in the format they selected. */
        discard_comments = FALSE;
        break;

      case SAVE_WITHOUT_COMMENTS:
        /* The file can't be saved in the specified format as is,
           but it can be saved without the comments, and the user
           said "OK, discard the comments", so save it in the
           format they specified without the comments. */
        discard_comments = TRUE;
        break;

      case SAVE_IN_ANOTHER_FORMAT:
        /* There are file formats in which we can save this that
           support comments, and the user said not to delete the
           comments.  Do a "Save As" so the user can select
           one of those formats and choose a file name. */
        file_save_as_cmd(cf, TRUE, dont_reopen);
        return;

      case CANCELLED:
        /* The user said "forget it".  Just return. */
        return;

      default:
        /* Squelch warnings that discard_comments is being used
           uninitialized. */
        g_assert_not_reached();
        return;
      }

      /* XXX - cf->filename might get freed out from under us, because
         the code path through which cf_save_packets() goes currently
         closes the current file and then opens and reloads the saved file,
         so make a copy and free it later. */
      fname = g_strdup(cf->filename);
      status = cf_save_packets(cf, fname, cf->cd_t, cf->iscompressed,
                               discard_comments, dont_reopen);
      switch (status) {

      case CF_WRITE_OK:
        /* The save succeeded; we're done.
           If we discarded comments, redraw the packet list to reflect
           any packets that no longer have comments. */
        if (discard_comments)
          packet_list_queue_draw();
        break;

      case CF_WRITE_ERROR:
        /* The write failed.
           XXX - OK, what do we do now?  Let them try a
           "Save As", in case they want to try to save to a
           different directory r file system? */
        break;

      case CF_WRITE_ABORTED:
        /* The write was aborted; just drive on. */
        break;
      }
      g_free(fname);
    }
    /* Otherwise just do nothing. */
  }
}

void
file_save_cmd_cb(GtkWidget *w _U_, gpointer data _U_) {
  do_file_save(&cfile, FALSE);
}

/* Attach a list of the valid 'save as' file types to a combo_box by
   checking what Wiretap supports.  Make the default type the first
   in the list.  If must_supprt_comments is true, restrict the list
   to those formats that support comments (currently, just pcap-ng).

   Returns the default file type. */
static int
set_file_type_list(GtkWidget *combo_box, capture_file *cf,
                   gboolean must_support_comments)
{
  GArray *savable_file_types;
  guint i;
  int ft;
  int default_ft = -1;

  savable_file_types = wtap_get_savable_file_types(cf->cd_t, cf->linktypes);

  if (savable_file_types != NULL) {
    /* OK, we have at least one file type we can save this file as.
       (If we didn't, we shouldn't have gotten here in the first
       place.)  Add them all to the combo box.  */
    for (i = 0; i < savable_file_types->len; i++) {
      ft = g_array_index(savable_file_types, int, i);
      if (must_support_comments) {
        if (ft != WTAP_FILE_PCAPNG)
          continue;
      }
      if (default_ft == -1)
        default_ft = ft; /* first file type is the default */
      ws_combo_box_append_text_and_pointer(GTK_COMBO_BOX(combo_box),
                                           wtap_file_type_string(ft),
                                           GINT_TO_POINTER(ft));
    }
    g_array_free(savable_file_types, TRUE);
  }

  return default_ft;
}

static void
file_select_file_type_cb(GtkWidget *w, gpointer parent_arg)
{
  GtkWidget *parent = parent_arg;
  int new_file_type;
  gpointer ptr;
  GtkWidget *compressed_cb;

  compressed_cb = (GtkWidget *)g_object_get_data(G_OBJECT(parent), E_COMPRESSED_CB_KEY);
  if (! ws_combo_box_get_active_pointer(GTK_COMBO_BOX(w), &ptr)) {
    /* XXX - this can happen when we clear the list of file types
       and then reconstruct it. */
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(compressed_cb), FALSE);
    gtk_widget_set_sensitive(compressed_cb, FALSE);
    return;
  }
  new_file_type = GPOINTER_TO_INT(ptr);

  if (!wtap_dump_can_compress(new_file_type)) {
    /* Can't compress this file type; turn off compression and make
       the compression checkbox insensitive. */
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(compressed_cb), FALSE);
    gtk_widget_set_sensitive(compressed_cb, FALSE);
  } else
    gtk_widget_set_sensitive(compressed_cb, TRUE);
}

static check_savability_t
gtk_check_save_as_with_comments(GtkWidget *w, capture_file *cf, int file_type)
{
  GtkWidget     *msg_dialog;
  gint           response;

  /* Do we have any comments? */
  if (!cf_has_comments(cf)) {
    /* No.  Let the save happen; no comments to delete. */
    return SAVE;
  }

  /* XXX - for now, we "know" that pcap-ng is the only format for which
     we support comments.  We should really ask Wiretap what the
     format in question supports (and handle different types of
     comments, some but not all of which some file formats might
     not support). */
  if (file_type == WTAP_FILE_PCAPNG) {
    /* Yes - they selected pcap-ng.  Let the save happen; we can
       save the comments, so no need to delete them. */
    return SAVE;
  }
  /* No. Is pcap-ng one of the formats in which we can write this file? */
  if (wtap_dump_can_write_encaps(WTAP_FILE_PCAPNG, cf->linktypes)) {
    /* Yes.  Offer the user a choice of "Save in a format that
       supports comments", "Discard comments and save in the
       format you selected", or "Cancel", meaning "don't bother
       saving the file at all". */
    msg_dialog = gtk_message_dialog_new(GTK_WINDOW(w),
                                        GTK_DIALOG_DESTROY_WITH_PARENT,
                                        GTK_MESSAGE_QUESTION,
                                        GTK_BUTTONS_NONE,
  "The capture has comments, but the file format you chose "
  "doesn't support comments.  Do you want to save the capture "
  "in a format that supports comments, or discard the comments "
  "and save in the format you chose?");
#ifndef _WIN32
    gtk_dialog_add_buttons(GTK_DIALOG(msg_dialog),
                           "Discard comments and save",
                           RESPONSE_DISCARD_COMMENTS_AND_SAVE,
                           GTK_STOCK_CANCEL,
                           GTK_RESPONSE_CANCEL,
                           "Save in another format",
                           RESPONSE_SAVE_IN_ANOTHER_FORMAT,
                           NULL);
#else
    gtk_dialog_add_buttons(GTK_DIALOG(msg_dialog),
                           "Save in another format",
                           RESPONSE_SAVE_IN_ANOTHER_FORMAT,
                           GTK_STOCK_CANCEL,
                           GTK_RESPONSE_CANCEL,
                           "Discard comments and save",
                           RESPONSE_DISCARD_COMMENTS_AND_SAVE,
                           NULL);
#endif
    gtk_dialog_set_default_response(GTK_DIALOG(msg_dialog),
                                    RESPONSE_SAVE_IN_ANOTHER_FORMAT);
  } else {
    /* No.  Offer the user a choice of "Discard comments and
       save in the format you selected" or "Cancel". */
    msg_dialog = gtk_message_dialog_new(GTK_WINDOW(w),
                                        GTK_DIALOG_DESTROY_WITH_PARENT,
                                        GTK_MESSAGE_QUESTION,
                                        GTK_BUTTONS_NONE,
  "The capture has comments, but no file format in which it "
  "can be saved supports comments.  Do you want to discard "
  "the comments and save in the format you chose?");
#ifndef _WIN32
    gtk_dialog_add_buttons(GTK_DIALOG(msg_dialog),
                           "Discard comments and save",
                           RESPONSE_DISCARD_COMMENTS_AND_SAVE,
                           GTK_STOCK_CANCEL,
                           GTK_RESPONSE_CANCEL,
                           NULL);
#else
    gtk_dialog_add_buttons(GTK_DIALOG(msg_dialog),
                           GTK_STOCK_CANCEL,
                           GTK_RESPONSE_CANCEL,
                           "Discard comments and save",
                           RESPONSE_DISCARD_COMMENTS_AND_SAVE,
                           NULL);
#endif
    gtk_dialog_set_default_response(GTK_DIALOG(msg_dialog),
                                    GTK_RESPONSE_CANCEL);
  }

  response = gtk_dialog_run(GTK_DIALOG(msg_dialog));
  gtk_widget_destroy(msg_dialog);

  switch (response) {

  case RESPONSE_SAVE_IN_ANOTHER_FORMAT:
    /* OK, the only other format we support is pcap-ng.  Make that
       the one and only format in the combo box, and return to
       let the user continue with the dialog.

       XXX - removing all the formats from the combo box will clear
       the compressed checkbox; get the current value and restore
       it.

       XXX - we know pcap-ng can be compressed; if we ever end up
       supporting saving comments in a format that *can't* be
       compressed, such as NetMon format, we must check this. */
    /* XXX - need a compressed checkbox here! */
    return SAVE_IN_ANOTHER_FORMAT;

  case RESPONSE_DISCARD_COMMENTS_AND_SAVE:
    /* Save without the comments and, if that succeeds, delete the
       comments. */
    return SAVE_WITHOUT_COMMENTS;

  case GTK_RESPONSE_CANCEL:
  case GTK_RESPONSE_NONE:
  case GTK_RESPONSE_DELETE_EVENT:
  default:
    /* Just give up. */
    return CANCELLED;
  }
}

#ifndef USE_WIN32_FILE_DIALOGS
/* "Save as" */
static gboolean
gtk_save_as_file(GtkWidget *w _U_, capture_file *cf, GString *file_name, int *file_type,
                 gboolean *compressed, gboolean must_support_comments)
{
  GtkWidget     *file_save_as_w;
  GtkWidget     *main_vb, *ft_hb, *ft_lb, *ft_combo_box, *compressed_cb;
  int            default_ft;
  char          *cf_name;
  gpointer       ptr;

  if (!file_name || !file_type || !compressed)
    return FALSE;

  /* Default to saving in the file's current format. */

  /* build the file selection */
  file_save_as_w = file_selection_new("Wireshark: Save Capture File As",
                                      FILE_SELECTION_SAVE);
  gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(file_save_as_w),
                                                 TRUE);

  /* Container for each row of widgets */

  main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 5, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  file_selection_set_extra_widget(file_save_as_w, main_vb);
  gtk_widget_show(main_vb);

  /* File type row */
  ft_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);
  gtk_box_pack_start(GTK_BOX (main_vb), ft_hb, TRUE, TRUE, 0);
  gtk_widget_show(ft_hb);

  ft_lb = gtk_label_new("File type:");
  gtk_box_pack_start(GTK_BOX(ft_hb), ft_lb, FALSE, FALSE, 0);
  gtk_widget_show(ft_lb);

  ft_combo_box = ws_combo_box_new_text_and_pointer();

  /* Generate the list of file types we can save. */
  default_ft = set_file_type_list(ft_combo_box, cf, must_support_comments);
  gtk_box_pack_start(GTK_BOX(ft_hb), ft_combo_box, FALSE, FALSE, 0);
  gtk_widget_show(ft_combo_box);
  g_object_set_data(G_OBJECT(file_save_as_w), E_FILE_TYPE_COMBO_BOX_KEY, ft_combo_box);

  /* compressed - if the file is currently compressed, and the default
     file type supports compression, turn the checkbox on */
  compressed_cb = gtk_check_button_new_with_label("Compress with gzip");
  gtk_box_pack_start(GTK_BOX (ft_hb), compressed_cb, TRUE, TRUE, 0);
  if (cf->iscompressed && wtap_dump_can_compress(default_ft))
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(compressed_cb), TRUE);
  gtk_widget_show(compressed_cb);
  g_object_set_data(G_OBJECT(file_save_as_w), E_COMPRESSED_CB_KEY, compressed_cb);

  /* Ok: now "select" the default filetype which invokes file_select_file_type_cb */
  g_signal_connect(ft_combo_box, "changed", G_CALLBACK(file_select_file_type_cb), file_save_as_w);
  ws_combo_box_set_active(GTK_COMBO_BOX(ft_combo_box), 0);

  cf_name = file_selection_run(file_save_as_w);

  if (cf_name == NULL) {
    /* User cancelled or closed the dialog. */
    return FALSE;
  }

  if (! ws_combo_box_get_active_pointer(GTK_COMBO_BOX(ft_combo_box), &ptr)) {
      g_assert_not_reached();  /* Programming error: somehow nothing is active */
  }
  *file_type = GPOINTER_TO_INT(ptr);
  *compressed = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(compressed_cb));

  /* We've crossed the Rubicon; get rid of the file selection box. */
  window_destroy(GTK_WIDGET(file_save_as_w));

  g_string_printf(file_name, "%s", cf_name);
  g_free(cf_name);
  return TRUE;
}
#endif /* USE_WIN32_FILE_DIALOGS */

static void
file_add_extension(GString *file_name, int file_type, gboolean compressed) {
  gchar   *file_name_lower;
  GString *file_suffix;
  GSList  *extensions_list, *extension;
  gboolean add_extension;

  /*
   * Append the default file extension if there's none given by
   * the user or if they gave one that's not one of the valid
   * extensions for the file type.
   */
  file_name_lower = g_utf8_strdown(file_name->str, -1);
  file_suffix = g_string_new("");
  extensions_list = wtap_get_file_extensions_list(file_type, FALSE);
  if (extensions_list != NULL) {
    /* We have one or more extensions for this file type.
       Start out assuming we need to add the default one. */
    add_extension = TRUE;

    /* OK, see if the file has one of those extensions. */
    for (extension = extensions_list; extension != NULL;
         extension = g_slist_next(extension)) {
      g_string_printf(file_suffix, ".%s", (char *)extension->data);
      if (g_str_has_suffix(file_name_lower, file_suffix->str)) {
        /*
         * The file name has one of the extensions for
         * this file type.
         */
        add_extension = FALSE;
        break;
      }
      g_string_append(file_suffix, ".gz");
      if (g_str_has_suffix(file_name_lower, file_suffix->str)) {
        /*
         * The file name has one of the extensions for
         * this file type.
         */
        add_extension = FALSE;
        break;
      }
    }
  } else {
    /* We have no extensions for this file type.  Don't add one. */
    add_extension = FALSE;
  }
  g_free(file_name_lower);
  g_string_free(file_suffix, TRUE);
  if (add_extension) {
    if (wtap_default_file_extension(file_type) != NULL) {
      g_string_append_printf(file_name, ".%s",
                             wtap_default_file_extension(file_type));
      if (compressed) {
        g_string_append(file_name, ".gz");
      }
    }
  }
}

/* Save a file with a user-specified name */

/*
 * <platform/>_save_as_file routines should upon entry...
 *   Set the path and fill in the filename if the path+filename is provided.
 * ...and upon exit...
 *   Return TRUE on "OK" and "FALSE" on "Cancel".
 *   Close the window.
 */

static void
file_save_as_cmd(capture_file *cf, gboolean must_support_comments,
                gboolean dont_reopen)
{
  GString *file_name = g_string_new("");
  int file_type;
  gboolean compressed;
  cf_write_status_t status;
  gchar   *dirname;
  gboolean discard_comments = FALSE;

  /*
   * Loop until the user either selects a file or gives up.
   */
  for (;;) {
#ifdef USE_WIN32_FILE_DIALOGS
    if (win32_save_as_file(GDK_WINDOW_HWND(gtk_widget_get_window(top_level)), cf,
                           file_name, &file_type, &compressed, must_support_comments)) {
      /* They discarded comments, so redraw the packet details window
         to reflect any packets that no longer have comments. */
      packet_list_queue_draw();
#else /* USE_WIN32_FILE_DIALOGS */
    if (gtk_save_as_file(top_level, cf, file_name, &file_type, &compressed, must_support_comments)) {
#endif /* USE_WIN32_FILE_DIALOGS */

      /* If the file has comments, does the format the user selected
         support them?  If not, ask the user whether they want to
         discard the comments or choose a different format. */
#ifdef USE_WIN32_FILE_DIALOGS
      switch (win32_check_save_as_with_comments(GDK_WINDOW_HWND(gtk_widget_get_window(top_level)), cf, file_type)) {
#else /* USE_WIN32_FILE_DIALOGS */
      switch (gtk_check_save_as_with_comments(top_level, cf, file_type)) {
#endif /* USE_WIN32_FILE_DIALOGS */

      case SAVE:
        /* The file can be saved in the specified format as is;
           just drive on and save in the format they selected. */
        discard_comments = FALSE;
        break;

      case SAVE_WITHOUT_COMMENTS:
        /* The file can't be saved in the specified format as is,
           but it can be saved without the comments, and the user
           said "OK, discard the comments", so save it in the
           format they specified without the comments. */
        discard_comments = TRUE;
        break;

      case SAVE_IN_ANOTHER_FORMAT:
        /* There are file formats in which we can save this that
           support comments, and the user said not to delete the
           comments.  The combo box of file formats has had the
           formats that don't support comments trimmed from it,
           so run the dialog again, to let the user decide
           whether to save in one of those formats or give up. */
        discard_comments = FALSE;
        must_support_comments = TRUE;
        continue;

      case CANCELLED:
        /* The user said "forget it".  Just get rid of the dialog box
           and return. */
        g_string_free(file_name, TRUE);
        return;
      }

      file_add_extension(file_name, file_type, compressed);

#ifndef _WIN32
      /* If the file exists and it's user-immutable or not writable,
         ask the user whether they want to override that. */
      if (!file_target_unwritable_ui(top_level, file_name->str)) {
        /* They don't.  Let them try another file name or cancel. */
        continue;
      }
#endif

      /* Attempt to save the file */
      status = cf_save_packets(&cfile, file_name->str, file_type, compressed,
                             discard_comments, dont_reopen);
      switch (status) {

      case CF_WRITE_OK:
        /* The save succeeded; we're done. */
        /* Save the directory name for future file dialogs. */
        dirname = get_dirname(file_name->str);  /* Overwrites file_name->str */
        set_last_open_dir(dirname);
        /* If we discarded comments, redraw the packet list to reflect
           any packets that no longer have comments. */
        if (discard_comments)
          packet_list_queue_draw();
        break;

      case CF_WRITE_ERROR:
        /* The save failed; let the user try again. */
        continue;

      case CF_WRITE_ABORTED:
        /* The user aborted the save; just return. */
        g_string_free(file_name, TRUE);
        return;
      }
    }
    g_string_free(file_name, TRUE);
    return;
  }
}

void
file_save_as_cmd_cb(GtkWidget *w _U_, gpointer data _U_)
{
  file_save_as_cmd(&cfile, FALSE, FALSE);
}

#ifndef USE_WIN32_FILE_DIALOGS
static gboolean
gtk_export_specified_packets_file(GtkWidget *w _U_, GString *file_name, int *file_type,
                                  gboolean *compressed, packet_range_t *range)
{
  GtkWidget     *file_export_specified_packets_w;
  GtkWidget     *main_vb, *ft_hb, *ft_lb, *ft_combo_box, *range_fr, *range_tb,
                *compressed_cb;
  char          *cf_name;
  gpointer       ptr;

  if (!file_name || !file_type || !compressed || !range)
    return FALSE;

  /* Default to writing out all displayed packets, in the file's current format. */

  /* build the file selection */
  file_export_specified_packets_w = file_selection_new("Wireshark: Export Specified Packets",
                                                       FILE_SELECTION_SAVE);
  gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(file_export_specified_packets_w),
                                                 TRUE);

  /* Container for each row of widgets */

  main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 5, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  file_selection_set_extra_widget(file_export_specified_packets_w, main_vb);
  gtk_widget_show(main_vb);

  /*** Packet Range frame ***/
  range_fr = gtk_frame_new("Packet Range");
  gtk_box_pack_start(GTK_BOX(main_vb), range_fr, FALSE, FALSE, 0);
  gtk_widget_show(range_fr);

  /* range table */
  range_tb = range_new(range, TRUE);
  gtk_container_add(GTK_CONTAINER(range_fr), range_tb);
  gtk_widget_show(range_tb);

  /* File type row */
  ft_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);
  gtk_box_pack_start(GTK_BOX (main_vb), ft_hb, TRUE, TRUE, 0);

  gtk_widget_show(ft_hb);

  ft_lb = gtk_label_new("File type:");
  gtk_box_pack_start(GTK_BOX(ft_hb), ft_lb, FALSE, FALSE, 0);
  gtk_widget_show(ft_lb);

  ft_combo_box = ws_combo_box_new_text_and_pointer();

  /* Generate the list of file types we can save. */
  set_file_type_list(ft_combo_box, &cfile, FALSE);
  gtk_box_pack_start(GTK_BOX(ft_hb), ft_combo_box, FALSE, FALSE, 0);
  gtk_widget_show(ft_combo_box);
  g_object_set_data(G_OBJECT(file_export_specified_packets_w), E_FILE_TYPE_COMBO_BOX_KEY, ft_combo_box);

  /* dynamic values in the range frame */
  range_update_dynamics(range_tb);

  /* compressed */
  compressed_cb = gtk_check_button_new_with_label("Compress with gzip");
  gtk_box_pack_start(GTK_BOX (ft_hb), compressed_cb, TRUE, TRUE, 0);
  gtk_widget_show(compressed_cb);
  g_object_set_data(G_OBJECT(file_export_specified_packets_w), E_COMPRESSED_CB_KEY, compressed_cb);

  /* Ok: now "select" the default filetype which invokes file_select_file_type_cb */
  g_signal_connect(ft_combo_box, "changed", G_CALLBACK(file_select_file_type_cb), file_export_specified_packets_w);
  ws_combo_box_set_active(GTK_COMBO_BOX(ft_combo_box), 0);

  cf_name = file_selection_run(file_export_specified_packets_w);
  if (cf_name == NULL) {
    /* User cancelled or closed the dialog. */
    return FALSE;
  }

  if (! ws_combo_box_get_active_pointer(GTK_COMBO_BOX(ft_combo_box), &ptr)) {
      g_assert_not_reached();  /* Programming error: somehow nothing is active */
  }
  *file_type = GPOINTER_TO_INT(ptr);
  *compressed = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(compressed_cb));

  /* We've crossed the Rubicon; get rid of the file export box. */
  window_destroy(GTK_WIDGET(file_export_specified_packets_w));

  g_string_printf(file_name, "%s", cf_name);
  g_free(cf_name);
  return TRUE;
}
#endif /* USE_WIN32_FILE_DIALOGS */

/*
 * <platform/>_export_specified_packets_file routines should upon entry...
 *   Set the path and fill in the filename if the path+filename is provided.
 * ...and upon exit...
 *   Not initialize range.
 *   Return TRUE on "OK" and "FALSE" on "Cancel".
 *   Close the window.
 */

void
file_export_specified_packets_cmd_cb(GtkWidget *w _U_, gpointer data _U_) {
  GString *file_name = g_string_new("");
  int file_type;
  gboolean compressed;
  packet_range_t range;
  cf_write_status_t status;
  gchar *dirname;
  gchar *display_basename;
  GtkWidget *msg_dialog;

  /* init the packet range */
  packet_range_init(&range, &cfile);
  range.process_filtered = TRUE;
  range.include_dependents = TRUE;

  /*
   * Loop until the user either selects a file or gives up.
   */
  for (;;) {
#ifdef USE_WIN32_FILE_DIALOGS
    if (win32_export_specified_packets_file(GDK_WINDOW_HWND(gtk_widget_get_window(top_level)),
                                            file_name, &file_type, &compressed, &range)) {
#else /* USE_WIN32_FILE_DIALOGS */
    if (gtk_export_specified_packets_file(w, file_name, &file_type, &compressed, &range)) {
#endif /* USE_WIN32_FILE_DIALOGS */

      /* Check whether the range is valid. */
      if (!range_check_validity_modal(top_level, &range)) {
        /* The range isn't valid; the user was told that, and dismissed
           the dialog telling them that, so let them fix the range
           and try again, or cancel. */
        continue;
      }

      /* XXX - Check for comments? */

      /*
       * Check that we're not going to save on top of the current
       * capture file.
       * We do it here so we catch all cases ...
       * Unfortunately, the file requester gives us an absolute file
       * name and the read file name may be relative (if supplied on
       * the command line). From Joerg Mayer.
       */
      if (files_identical(cfile.filename, file_name->str)) {
        display_basename = g_filename_display_basename(file_name->str);
        msg_dialog = gtk_message_dialog_new(GTK_WINDOW(top_level),
                                            GTK_DIALOG_DESTROY_WITH_PARENT,
                                            GTK_MESSAGE_ERROR,
                                            GTK_BUTTONS_OK,
        "The file \"%s\" is the capture file from which you're exporting the packets.",
                                            display_basename);
        g_free(display_basename);
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(msg_dialog),
             "You cannot export packets on top of the current capture file.");
        gtk_dialog_run(GTK_DIALOG(msg_dialog));
        gtk_widget_destroy(msg_dialog);
        continue;
      }

      file_add_extension(file_name, file_type, compressed);

#ifndef _WIN32
      /* If the file exists and it's user-immutable or not writable,
         ask the user whether they want to override that. */
      if (!file_target_unwritable_ui(top_level, file_name->str)) {
        /* They don't.  Let them try another file name or cancel. */
        continue;
      }
#endif

      /* Attempt to export the file */
      status = cf_export_specified_packets(&cfile, file_name->str, &range, file_type,
                                         compressed);
      switch (status) {

      case CF_WRITE_OK:
        /* The write succeeded; get rid of the file selection box. */
        /* cf_export_specified_packets() might already closed our dialog! */

        /* Save the directory name for future file dialogs.
           XXX - should there be separate ones for "Save As" and
           "Export Specified Packets"? */
        dirname = get_dirname(file_name->str);  /* Overwrites file_name->str */
        set_last_open_dir(dirname);
        break;

      case CF_WRITE_ERROR:
        /* The save failed; let the user try again. */
        continue;

      case CF_WRITE_ABORTED:
        /* The user aborted the save; just return. */
        g_string_free(file_name, TRUE);
        return;
      }
    }
    g_string_free(file_name, TRUE);
    return;
  }
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
  GtkWidget *fs_widget = (GtkWidget *)data;
  gchar *path;

  /* decide what file to open (from dfilter code) */
  path = get_datafile_path("colorfilters");

  gtk_file_chooser_select_filename(GTK_FILE_CHOOSER(fs_widget), path);

  g_free(path);
}

/* Import color filters */
void
file_color_import_cmd_cb(GtkWidget *color_filters, gpointer filter_list _U_)
{
#ifdef USE_WIN32_FILE_DIALOGS
  win32_import_color_file(GDK_WINDOW_HWND(gtk_widget_get_window(top_level)), color_filters);
#else /* USE_WIN32_FILE_DIALOGS */
  GtkWidget     *main_vb, *cfglobal_but;
  gchar         *cf_name, *s;

  /* No Apply button, and "OK" just sets our text widget, it doesn't
     activate it (i.e., it doesn't cause us to try to open the file). */

  file_color_import_w = file_selection_new("Wireshark: Import Color Filters",
                                           FILE_SELECTION_OPEN);

  /* Container for each row of widgets */
  main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  file_selection_set_extra_widget(file_color_import_w, main_vb);
  gtk_widget_show(main_vb);

  cfglobal_but = gtk_button_new_with_label("Global Color Filter File");
  gtk_box_pack_start(GTK_BOX (main_vb), cfglobal_but, TRUE, TRUE, 0);
  g_signal_connect(cfglobal_but, "clicked",
                   G_CALLBACK(color_global_cb), file_color_import_w);
  gtk_widget_show(cfglobal_but);

  /*
   * Loop until the user either selects a file or gives up.
   */
  for (;;) {
    cf_name = file_selection_run(file_color_import_w);
    if (cf_name == NULL) {
      /* User cancelled or closed the dialog. */
      return;
    }

    /* Try to open the color filter file. */
    if (!color_filters_import(cf_name, color_filters)) {
      /* We couldn't open it; don't dismiss the open dialog box,
         just leave it around so that the user can, after they
         dismiss the alert box popped up for the open error,
         try again. */
      g_free(cf_name);
      continue;
    }

    /* We've crossed the Rubicon; get rid of the file selection box. */
    window_destroy(GTK_WIDGET(file_color_import_w));

    /* Save the name of the containing directory specified in the path name,
       if any; we can write over cf_name, which is a good thing, given that
       "get_dirname()" does write over its argument. */
    s = get_dirname(cf_name);
    set_last_open_dir(s);

    g_free(cf_name);
    return;
  }
#endif /* USE_WIN32_FILE_DIALOGS */
}

/*
 * Set the "Export only selected filters" toggle button as appropriate for
 * the current output file type and count of selected filters.
 *
 * Called when the "Export" dialog box is created and when the selected
 * count changes.
 */
static void
color_set_export_selected_sensitive(GtkWidget * cfselect_cb)
{
  /* We can request that only the selected filters be saved only if
        there *are* selected filters. */
  if (color_selected_count() != 0)
    gtk_widget_set_sensitive(cfselect_cb, TRUE);
  else {
    /* Force the "Export only selected filters" toggle to "false", turn
       off the flag it controls. */
    color_selected = FALSE;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cfselect_cb), FALSE);
    gtk_widget_set_sensitive(cfselect_cb, FALSE);
  }
}

static void
color_toggle_selected_cb(GtkWidget *widget, gpointer data _U_)
{
  color_selected = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget));
}

void
file_color_export_cmd_cb(GtkWidget *w _U_, gpointer filter_list)
{
#ifdef USE_WIN32_FILE_DIALOGS
  win32_export_color_file(GDK_WINDOW_HWND(gtk_widget_get_window(top_level)), filter_list);
#else /* USE_WIN32_FILE_DIALOGS */
  GtkWidget *file_color_export_w;
  GtkWidget *main_vb, *cfglobal_but;
  GtkWidget *cfselect_cb;
  gchar     *cf_name;
  gchar     *dirname;

  color_selected   = FALSE;

  file_color_export_w = file_selection_new("Wireshark: Export Color Filters",
                                           FILE_SELECTION_SAVE);
  gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(file_color_export_w),
                                                 TRUE);

  /* Container for each row of widgets */
  main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  file_selection_set_extra_widget(file_color_export_w, main_vb);
  gtk_widget_show(main_vb);

  cfselect_cb = gtk_check_button_new_with_label("Export only selected filters");
  gtk_box_pack_start(GTK_BOX (main_vb), cfselect_cb, TRUE, TRUE, 0);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cfselect_cb), FALSE);
  g_signal_connect(cfselect_cb, "toggled",
                   G_CALLBACK(color_toggle_selected_cb), NULL);
  gtk_widget_show(cfselect_cb);
  color_set_export_selected_sensitive(cfselect_cb);

  cfglobal_but = gtk_button_new_with_label("Global Color Filter File");
  gtk_box_pack_start(GTK_BOX (main_vb), cfglobal_but, TRUE, TRUE, 0);
  g_signal_connect(cfglobal_but, "clicked",
                   G_CALLBACK(color_global_cb), file_color_export_w);
  gtk_widget_show(cfglobal_but);

  /*
   * Loop until the user either selects a file or gives up.
   */
  for (;;) {
    cf_name = file_selection_run(file_color_export_w);
    if (cf_name == NULL) {
      /* User cancelled or closed the dialog. */
      return;
    }

#ifndef _WIN32
    /* If the file exists and it's user-immutable or not writable,
       ask the user whether they want to override that. */
    if (!file_target_unwritable_ui(file_color_export_w, cf_name)) {
      /* They don't.  Let them try another file name or cancel. */
      g_free(cf_name);
      continue;
    }
#endif

    /* Write out the filters (all, or only the ones that are currently
       displayed or selected) to the file with the specified name. */
    if (!color_filters_export(cf_name, filter_list, color_selected)) {
      /* The write failed; don't dismiss the open dialog box,
         just leave it around so that the user can, after they
         dismiss the alert box popped up for the error, try again. */
      g_free(cf_name);
      continue;
    }

    /* The write succeeded; get rid of the file selection box. */
    window_destroy(GTK_WIDGET(file_color_export_w));

    /* Save the directory name for future file dialogs. */
    dirname = get_dirname(cf_name);  /* Overwrites cf_name */
    set_last_open_dir(dirname);
    g_free(cf_name);
  }
#endif /* USE_WIN32_FILE_DIALOGS */
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
