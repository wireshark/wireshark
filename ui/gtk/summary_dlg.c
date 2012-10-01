/* summary_dlg.c
 * Routines for capture file summary window
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

#include <string.h>
#include <time.h>

#include <gtk/gtk.h>

#include <epan/strutil.h>

#include <wiretap/wtap.h>

#include "../globals.h"
#include "../file.h"
#include "../summary.h"
#include "../capture-pcap-util.h"
#ifdef HAVE_LIBPCAP
#include "../capture.h"
#include "ui/capture_globals.h"
#endif
#include "ui/main_statusbar.h"
#include "ui/gtk/main.h"
#include "ui/gtk/summary_dlg.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/help_dlg.h"

#define SUM_STR_MAX     1024
#define FILTER_SNIP_LEN 50
#define SHB_STR_SNIP_LEN 50

static GtkWidget *summary_dlg = NULL;

static void
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
    if (strlen(value) == 0) {
      gchar *message = g_strdup_printf("<span weight=\"bold\">%s</span>", title);
      gtk_label_set_markup(GTK_LABEL(label), message);
      g_free (message);
    }
    g_free(indent);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_widget_set_sensitive(label, sensitive);
    gtk_table_attach_defaults(GTK_TABLE(list), label, 0, 1, *row, *row+1);

    label = gtk_label_new(value);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0f, 0.5f);
    gtk_widget_set_sensitive(label, sensitive);
    gtk_table_attach_defaults(GTK_TABLE(list), label, 1, 2, *row, *row+1);

    *row = *row + 1;
}

static void
add_string_to_table(GtkWidget *list, guint *row, const gchar *title, const gchar *value)
{
    add_string_to_table_sensitive(list, row, title, value, TRUE);
}


static void
add_string_to_list(GtkWidget *list, const gchar *title, gchar *captured,
                   gchar *displayed, gchar *pct_displayed, gchar *marked,
                   gchar *pct_marked)
{
    simple_list_append(list,
                       0, title,
                       1, captured,
                       2, displayed,
                       3, pct_displayed,
                       4, marked,
                       5, pct_marked,
                       -1);
}

static void
time_to_string(char *string_buff, gulong string_buff_size, time_t ti_time)
{
  struct tm *ti_tm;

#ifdef _MSC_VER
  /* calling localtime() on MSVC 2005 with huge values causes it to crash */
  /* XXX - find the exact value that still does work */
  /* XXX - using _USE_32BIT_TIME_T might be another way to circumvent this problem */
  if (ti_time > 2000000000) {
      ti_tm = NULL;
  } else
#endif
  ti_tm = localtime(&ti_time);
  if (ti_tm == NULL) {
    g_snprintf(string_buff, string_buff_size, "Not representable");
    return;
  }
  g_snprintf(string_buff, string_buff_size,
             "%04d-%02d-%02d %02d:%02d:%02d",
             ti_tm->tm_year + 1900,
             ti_tm->tm_mon + 1,
             ti_tm->tm_mday,
             ti_tm->tm_hour,
             ti_tm->tm_min,
             ti_tm->tm_sec);
}

static void
summary_ok_cb(GtkWidget *w _U_, GtkWidget *view)
{
  GtkTextBuffer *buffer;
  GtkTextIter start_iter;
  GtkTextIter end_iter;
  gchar *new_comment = NULL;

  buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));
  gtk_text_buffer_get_start_iter (buffer, &start_iter);
  gtk_text_buffer_get_end_iter (buffer, &end_iter);

  new_comment = gtk_text_buffer_get_text (buffer, &start_iter, &end_iter, FALSE /* whether to include invisible text */);

  cf_update_capture_comment(&cfile, new_comment);

  /* Update the main window */
  main_update_for_unsaved_changes(&cfile);

  status_capture_comment_update();

  window_destroy(summary_dlg);
}

static void
summary_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
  /* Note that we no longer have a Summary dialog box. */
  summary_dlg = NULL;
}

void
summary_open_cb(GtkWidget *w _U_, gpointer d _U_)
{
  summary_tally summary;
  GtkWidget     *main_vb, *bbox, *cancel_bt, *ok_bt, *help_bt;
  GtkWidget     *table, *scrolled_window;
  GtkWidget     *list, *treeview;
  GtkWidget     *comment_view, *comment_frame, *comment_vbox;
  GtkTextBuffer *buffer = NULL;
  gchar *buf_str;
  GtkListStore  *store;
  GtkTreeIter    iter;
  GtkCellRenderer *renderer;
  GtkTreeViewColumn *column;
  static const char *titles[] = {
    "Traffic", "Captured", "Displayed", "Displayed %", "Marked", "Marked %" };

  gchar         string_buff[SUM_STR_MAX];
  gchar         string_buff2[SUM_STR_MAX];
  gchar         string_buff3[SUM_STR_MAX];
  gchar         string_buff4[SUM_STR_MAX];
  gchar         string_buff5[SUM_STR_MAX];

  double        seconds;
  double        disp_seconds;
  double        marked_seconds;
  guint         offset;
  guint         snip;
  guint         row;
  gchar        *str_dup;
  gchar        *str_work;

  unsigned int  elapsed_time;
  iface_options iface;
  unsigned int  i;

  if (summary_dlg != NULL) {
    /* There's already a Summary dialog box; reactivate it. */
    reactivate_window(summary_dlg);
    return;
  }

  /* initial computations */
  summary_fill_in(&cfile, &summary);
#ifdef HAVE_LIBPCAP
  summary_fill_in_capture(&cfile, &global_capture_opts, &summary);
#endif
  /*
   * Note: the start and stop times are initialized to 0, so if we
   * have zero or one packets of the type in question that have
   * time stamps, the elapsed times will be zero, just as if we
   * have both start and stop time stamps but they're the same.
   * That means we can avoid some checks for whether we have more
   * than one packet of the type in question with time stamps.
   */
  seconds = summary.stop_time - summary.start_time;
  disp_seconds = summary.filtered_stop - summary.filtered_start;
  marked_seconds = summary.marked_stop - summary.marked_start;

  summary_dlg = window_new(GTK_WINDOW_TOPLEVEL, "Wireshark: Summary");

  /* Container for each row of widgets */
  main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 12, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 12);
  gtk_container_add(GTK_CONTAINER(summary_dlg), main_vb);

  /* table */
  table = gtk_table_new(1, 2, FALSE);
  gtk_table_set_col_spacings(GTK_TABLE(table), 6);
  gtk_table_set_row_spacings(GTK_TABLE(table), 3);
  gtk_box_pack_start(GTK_BOX(main_vb), table, TRUE, TRUE, 0);
  row = 0;


  /* File */
  add_string_to_table(table, &row, "File", "");

  /* filename */
  g_snprintf(string_buff, SUM_STR_MAX, "%s", summary.filename);
  add_string_to_table(table, &row, "Name:", string_buff);

  /* length */
  g_snprintf(string_buff, SUM_STR_MAX, "%" G_GINT64_MODIFIER "d bytes",
             summary.file_length);
  add_string_to_table(table, &row, "Length:", string_buff);

  /* format */
  g_snprintf(string_buff, SUM_STR_MAX, "%s%s",
             wtap_file_type_string(summary.file_type),
             summary.iscompressed? " (gzip compressed)" : "");
  add_string_to_table(table, &row, "Format:", string_buff);

  /* encapsulation */
  if (summary.file_encap_type == WTAP_ENCAP_PER_PACKET) {
    for (i = 0; i < summary.packet_encap_types->len; i++) {
      g_snprintf(string_buff, SUM_STR_MAX, "%s",
                 wtap_encap_string(g_array_index(summary.packet_encap_types, int, i)));
      add_string_to_table(table, &row, (i == 0) ? "Encapsulation:" : "",
                          string_buff);
    }
  } else {
    g_snprintf(string_buff, SUM_STR_MAX, "%s", wtap_encap_string(summary.file_encap_type));
    add_string_to_table(table, &row, "Encapsulation:", string_buff);
  }
  if (summary.has_snap) {
    /* snapshot length */
    g_snprintf(string_buff, SUM_STR_MAX, "%u bytes", summary.snap);
    add_string_to_table(table, &row, "Packet size limit:", string_buff);
  }

  /* Capture file comment area */
  comment_frame = gtk_frame_new("Capture file comments");
  gtk_frame_set_shadow_type(GTK_FRAME(comment_frame), GTK_SHADOW_ETCHED_IN);
  gtk_box_pack_start(GTK_BOX(main_vb), comment_frame, TRUE, TRUE, 0);
  gtk_widget_show(comment_frame);

  comment_vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
  gtk_container_add(GTK_CONTAINER(comment_frame), comment_vbox);
  gtk_widget_show(comment_vbox);

  comment_view = gtk_text_view_new();
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(comment_view), GTK_WRAP_WORD);
  buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (comment_view));
  if(summary.opt_comment == NULL) {
    gtk_text_buffer_set_text (buffer, "", -1);
  } else {
    buf_str = g_strdup_printf("%s", summary.opt_comment);
    gtk_text_buffer_set_text (buffer, buf_str, -1);
    g_free(buf_str);
  }
  gtk_box_pack_start(GTK_BOX(comment_vbox), comment_view, TRUE, TRUE, 0);
  gtk_widget_show (comment_view);

  /*
   * We must have no un-time-stamped packets (i.e., the number of
   * time-stamped packets must be the same as the number of packets),
   * and at least one time-stamped packet, in order for the start
   * and stop times to be valid.
   */
  if (summary.packet_count_ts == summary.packet_count &&
      summary.packet_count >= 1) {
    /* Time */
    add_string_to_table(table, &row, "", "");
    add_string_to_table(table, &row, "Time", "");

    /* start time */
    time_to_string(string_buff, SUM_STR_MAX, (time_t)summary.start_time);
    add_string_to_table(table, &row, "First packet:", string_buff);

    /* stop time */
    time_to_string(string_buff, SUM_STR_MAX, (time_t)summary.stop_time);
    add_string_to_table(table, &row, "Last packet:", string_buff);

    /*
     * We must have at least two time-stamped packets for the elapsed time
     * to be valid.
     */
    if (summary.packet_count_ts >= 2) {
      /* elapsed seconds */
      elapsed_time = (unsigned int)summary.elapsed_time;
      if(elapsed_time/86400) {
          g_snprintf(string_buff, SUM_STR_MAX, "%02u days %02u:%02u:%02u",
            elapsed_time/86400, elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
      } else {
          g_snprintf(string_buff, SUM_STR_MAX, "%02u:%02u:%02u",
            elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
      }
      add_string_to_table(table, &row, "Elapsed:", string_buff);
    }
  }

  /* Capture */
  add_string_to_table(table, &row, "", "");
  add_string_to_table_sensitive(table, &row, "Capture", "", (summary.ifaces->len > 0));
  if(summary.shb_hardware){
    /* truncate the string to a reasonable length */
    g_snprintf(string_buff, SHB_STR_SNIP_LEN, "%s",summary.shb_hardware);
    add_string_to_table(table, &row, "Capture HW:",string_buff);
  }
  if(summary.shb_os){
    /* truncate the strings to a reasonable length */
    g_snprintf(string_buff, SHB_STR_SNIP_LEN, "%s",summary.shb_os);
    add_string_to_table(table, &row, "OS:", string_buff);
  }
  if(summary.shb_user_appl){
    /* truncate the string to a reasonable length */
    g_snprintf(string_buff, SHB_STR_SNIP_LEN, "%s",summary.shb_user_appl);
    add_string_to_table(table, &row, "Capture application:", string_buff);
  }
  scrolled_window = gtk_scrolled_window_new (NULL, NULL);
  gtk_container_set_border_width (GTK_CONTAINER (scrolled_window), 5);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled_window),
                                  GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_widget_set_size_request(scrolled_window, -1, 120);

  treeview = gtk_tree_view_new();
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Interface", renderer, "text", 0, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Dropped Packets", renderer, "text", 1, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Capture Filter", renderer, "text", 2, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Link type", renderer, "text", 3, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);
  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Packet size limit", renderer, "text", 4, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);

  store = gtk_list_store_new(5, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
  for (i = 0; i < summary.ifaces->len; i++) {
    iface = g_array_index(summary.ifaces, iface_options, i);
    /* interface */
    if (iface.descr) {
      g_snprintf(string_buff, SUM_STR_MAX, "%s", iface.descr);
    } else if (iface.name) {
      g_snprintf(string_buff, SUM_STR_MAX, "%s", iface.name);
    } else {
      g_snprintf(string_buff, SUM_STR_MAX, "unknown");
    }
    /* Dropped count */
    if (iface.drops_known) {
      g_snprintf(string_buff2, SUM_STR_MAX, "%" G_GINT64_MODIFIER "u (%.3f%%)",
                 iface.drops, summary.packet_count ? (100.0 * iface.drops)/summary.packet_count : 0.0);
    } else {
      g_snprintf(string_buff2, SUM_STR_MAX, "unknown");
    }
    /* Capture filter */
    if (iface.cfilter && iface.cfilter[0] != '\0') {
      g_snprintf(string_buff3, SUM_STR_MAX, "%s", iface.cfilter);
    } else {
      if (iface.name) {
        g_snprintf(string_buff3, SUM_STR_MAX, "none");
      } else {
        g_snprintf(string_buff3, SUM_STR_MAX, "unknown");
      }
    }
    g_snprintf(string_buff4, SUM_STR_MAX, "%s", wtap_encap_string(iface.encap_type));
    g_snprintf(string_buff5, SUM_STR_MAX, "%u bytes", iface.snap);
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, 0, string_buff, 1, string_buff2, 2, string_buff3, 3, string_buff4, 4, string_buff5,-1);
  }
  gtk_tree_view_set_model(GTK_TREE_VIEW(treeview), GTK_TREE_MODEL(store));
  g_object_unref (store);
  gtk_container_add(GTK_CONTAINER(scrolled_window), treeview);
  gtk_box_pack_start(GTK_BOX(main_vb), scrolled_window, TRUE, TRUE, 0);
  gtk_widget_show_all(scrolled_window);
  table = gtk_table_new(1, 2, FALSE);
  gtk_table_set_col_spacings(GTK_TABLE(table), 6);
  gtk_table_set_row_spacings(GTK_TABLE(table), 3);
  gtk_box_pack_start(GTK_BOX(main_vb), table, TRUE, TRUE, 0);
  row = 0;


  /* Data */
  add_string_to_table(table, &row, "", "");
  add_string_to_table(table, &row, "Display", "");

  if (summary.dfilter) {
    /* Display filter */
    /* limit each row to some reasonable length */
    str_dup = g_strdup_printf("%s", summary.dfilter);
    str_work = g_strdup(str_dup);
    offset = 0;
    snip = 0;
    while(strlen(str_work) > FILTER_SNIP_LEN) {
        str_work[FILTER_SNIP_LEN] = '\0';
        add_string_to_table(table, &row, (snip == 0) ? "Display filter:" : "", str_work);
        g_free(str_work);
        offset+=FILTER_SNIP_LEN;
        str_work = g_strdup(&str_dup[offset]);
        snip++;
    }

    add_string_to_table(table, &row, (snip == 0) ? "Display filter:" : "", str_work);
    g_free(str_work);
    g_free(str_dup);
  } else {
    /* Display filter */
    add_string_to_table(table, &row, "Display filter:", "none");
  }

  /* Ignored packet count */
  g_snprintf(string_buff, SUM_STR_MAX, "%i (%.3f%%)", summary.ignored_count,
             summary.packet_count ? (100.0 * summary.ignored_count)/summary.packet_count : 0.0);
  add_string_to_table(table, &row, "Ignored packets:", string_buff);

  /* Traffic */
  list = simple_list_new(6, titles);
  gtk_box_pack_start(GTK_BOX(main_vb), list, TRUE, TRUE, 0);

#define cap_buf         string_buff
#define disp_buf        string_buff2
#define disp_pct_buf    string_buff3
#define mark_buf        string_buff4
#define mark_pct_buf    string_buff5

  /* Packet count */
  g_snprintf(cap_buf, SUM_STR_MAX, "%i", summary.packet_count);
  if (summary.dfilter) {
    g_snprintf(disp_buf, SUM_STR_MAX, "%i", summary.filtered_count);
    g_snprintf(disp_pct_buf, SUM_STR_MAX, "%.3f%%", summary.packet_count ?
               (100.0 * summary.filtered_count)/summary.packet_count : 0.0);
  } else {
    g_strlcpy(disp_buf, cap_buf, SUM_STR_MAX);
    g_strlcpy(disp_pct_buf, "100.000%", SUM_STR_MAX);
  }
  g_snprintf(mark_buf, SUM_STR_MAX, "%i", summary.marked_count);
  g_snprintf(mark_pct_buf, SUM_STR_MAX, "%.3f%%", summary.packet_count ?
             (100.0 * summary.marked_count)/summary.packet_count : 0.0);
  add_string_to_list(list, "Packets", cap_buf,
                     disp_buf, disp_pct_buf, mark_buf, mark_pct_buf);

  /* Time between first and last */
  if (seconds > 0) {
    g_snprintf(cap_buf, SUM_STR_MAX, "%.3f sec", seconds);
  } else {
    cap_buf[0] = '\0';
  }
  if (summary.dfilter && disp_seconds > 0) {
    g_snprintf(disp_buf, SUM_STR_MAX, "%.3f sec", disp_seconds);
  } else {
    disp_buf[0] = '\0';
  }
  disp_pct_buf[0] = '\0';
  if (summary.marked_count && marked_seconds > 0) {
    g_snprintf(mark_buf, SUM_STR_MAX, "%.3f sec", marked_seconds);
  } else {
    mark_buf[0] = '\0';
  }
  mark_pct_buf[0] = '\0';
  if (cap_buf[0] != '\0' || disp_buf[0] != '\0' || mark_buf[0] != '\0') {
    add_string_to_list(list, "Between first and last packet", cap_buf,
                       disp_buf, disp_pct_buf, mark_buf, mark_pct_buf);
  }

  /* Average packets per second */
  if (seconds > 0) {
    g_snprintf(cap_buf, SUM_STR_MAX, "%.3f", summary.packet_count/seconds);
  } else {
    cap_buf[0] = '\0';
  }
  if(summary.dfilter && disp_seconds > 0) {
    g_snprintf(disp_buf, SUM_STR_MAX, "%.3f", summary.filtered_count/disp_seconds);
  } else {
    disp_buf[0] = '\0';
  }
  disp_pct_buf[0] = '\0';
  if(summary.marked_count && marked_seconds > 0) {
    g_snprintf(mark_buf, SUM_STR_MAX, "%.3f", summary.marked_count/marked_seconds);
  } else {
    mark_buf[0] = '\0';
  }
  mark_pct_buf[0] = '\0';
  if (cap_buf[0] != '\0' || disp_buf[0] != '\0' || mark_buf[0] != '\0') {
    add_string_to_list(list, "Avg. packets/sec", cap_buf,
                       disp_buf, disp_pct_buf, mark_buf, mark_pct_buf);
  }

  /* Average packet size */
  if (summary.packet_count > 1) {
    g_snprintf(cap_buf, SUM_STR_MAX, "%.3f bytes",
               /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
               (float) ((gint64) summary.bytes)/summary.packet_count);
  } else {
    cap_buf[0] = '\0';
  }
  if (summary.dfilter && summary.filtered_count > 1) {
    g_snprintf(disp_buf, SUM_STR_MAX, "%.3f bytes",
               /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
               (float) ((gint64) summary.filtered_bytes)/summary.filtered_count);
  } else {
    disp_buf[0] = '\0';
  }
  disp_pct_buf[0] = '\0';
  if (summary.marked_count > 1) {
    g_snprintf(mark_buf, SUM_STR_MAX, "%.3f bytes",
               /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
               (float) ((gint64) summary.marked_bytes)/summary.marked_count);
  } else {
    mark_buf[0] = '\0';
  }
  mark_pct_buf[0] = '\0';
  if (cap_buf[0] != '\0' || disp_buf[0] != '\0' || mark_buf[0] != '\0') {
    add_string_to_list(list, "Avg. packet size", cap_buf,
                       disp_buf, disp_pct_buf, mark_buf, mark_pct_buf);
  }

  /* Byte count */
  g_snprintf(cap_buf, SUM_STR_MAX, "%" G_GINT64_MODIFIER "u", summary.bytes);
  if (summary.dfilter) {
    g_snprintf(disp_buf, SUM_STR_MAX, "%" G_GINT64_MODIFIER "u", summary.filtered_bytes);
    g_snprintf(disp_pct_buf, SUM_STR_MAX, "%.3f%%", summary.bytes ?
               /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
               (100.0 * (gint64) summary.filtered_bytes)/summary.bytes : 0.0);
  } else {
    g_strlcpy(disp_buf, cap_buf, SUM_STR_MAX);
    g_strlcpy(disp_pct_buf, "100.000%", SUM_STR_MAX);
  }
  if (summary.marked_count) {
    g_snprintf(mark_buf, SUM_STR_MAX, "%" G_GINT64_MODIFIER "u", summary.marked_bytes);
    g_snprintf(mark_pct_buf, SUM_STR_MAX, "%.3f%%", summary.bytes ?
               /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
               (100.0 * (gint64) summary.marked_bytes)/summary.bytes : 0.0);
  } else {
    g_strlcpy(mark_buf, "0", SUM_STR_MAX);
    g_strlcpy(mark_pct_buf, "0.000%", SUM_STR_MAX);
  }
  if (cap_buf[0] != '\0' || disp_buf[0] != '\0' || mark_buf[0] != '\0') {
    add_string_to_list(list, "Bytes", cap_buf,
                       disp_buf, disp_pct_buf, mark_buf, mark_pct_buf);
  }

  /* Bytes per second */
  if (seconds > 0){
    /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
    g_snprintf(cap_buf, SUM_STR_MAX, "%.3f", ((gint64) summary.bytes)/seconds);
  } else {
    cap_buf[0] = '\0';
  }
  if (summary.dfilter && disp_seconds > 0) {
    /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
    g_snprintf(disp_buf, SUM_STR_MAX, "%.3f", ((gint64) summary.filtered_bytes)/disp_seconds);
  } else {
    disp_buf[0] = '\0';
  }
  disp_pct_buf[0] = '\0';
  if (summary.marked_count && marked_seconds > 0) {
    /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
    g_snprintf(mark_buf, SUM_STR_MAX, "%.3f", ((gint64) summary.marked_bytes)/marked_seconds);
  } else {
    mark_buf[0] = '\0';
  }
  mark_pct_buf[0] = '\0';
  if (cap_buf[0] != '\0' || disp_buf[0] != '\0' || mark_buf[0] != '\0') {
    add_string_to_list(list, "Avg. bytes/sec", cap_buf,
                       disp_buf, disp_pct_buf, mark_buf, mark_pct_buf);
  }

  /* MBit per second */
  if (seconds > 0) {
    g_snprintf(cap_buf, SUM_STR_MAX, "%.3f",
               /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
               ((gint64) summary.bytes) * 8.0 / (seconds * 1000.0 * 1000.0));
  } else {
    cap_buf[0] = '\0';
  }
  if (summary.dfilter && disp_seconds > 0) {
    g_snprintf(disp_buf, SUM_STR_MAX, "%.3f",
               /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
               ((gint64) summary.filtered_bytes) * 8.0 / (disp_seconds * 1000.0 * 1000.0));
  } else {
    disp_buf[0] = '\0';
  }
  disp_pct_buf[0] = '\0';
  if (summary.marked_count && marked_seconds > 0) {
    g_snprintf(mark_buf, SUM_STR_MAX, "%.3f",
               /* MSVC cannot convert from unsigned __int64 to float, so first convert to signed __int64 */
               ((gint64) summary.marked_bytes) * 8.0 / (marked_seconds * 1000.0 * 1000.0));
  } else {
    mark_buf[0] = '\0';
  }
  mark_pct_buf[0] = '\0';
  if (cap_buf[0] != '\0' || disp_buf[0] != '\0' || mark_buf[0] != '\0') {
    add_string_to_list(list, "Avg. MBit/sec", cap_buf,
                       disp_buf, disp_pct_buf, mark_buf, mark_pct_buf);
  }


  /* Button row. */
  bbox = dlg_button_row_new(GTK_STOCK_CANCEL, GTK_STOCK_OK, GTK_STOCK_HELP, NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, TRUE, TRUE, 0);

  cancel_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
  window_set_cancel_button(summary_dlg, cancel_bt, window_cancel_button_cb);

  ok_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
  g_signal_connect (ok_bt, "clicked",
                    G_CALLBACK(summary_ok_cb), comment_view);
  gtk_widget_grab_focus(ok_bt);

  help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
  g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_SUMMARY_DIALOG);


  g_signal_connect(summary_dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
  g_signal_connect(summary_dlg, "destroy", G_CALLBACK(summary_destroy_cb), NULL);

  gtk_widget_show_all(summary_dlg);
  window_present(summary_dlg);
}
