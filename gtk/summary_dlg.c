/* summary_dlg.c
 * Routines for capture file summary window
 *
 * $Id: summary_dlg.c,v 1.30 2004/05/21 06:39:25 guy Exp $
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
# include "config.h"
#endif

#include <string.h>

#include <gtk/gtk.h>

#include <wtap.h>

#include "summary.h"
#include "summary_dlg.h"
#include "dlg_utils.h"
#include "ui_util.h"
#include "compat_macros.h"

#define SUM_STR_MAX     1024
#define FILTER_SNIP_LEN 50


static void
add_string_to_table_sensitive(GtkWidget *list, guint *row, gchar *title, gchar *value, gboolean sensitive)
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
}

static void
add_string_to_table(GtkWidget *list, guint *row, gchar *title, gchar *value)
{
    add_string_to_table_sensitive(list, row, title, value, TRUE);
}


static void
add_string_to_list(GtkWidget *list, guint *row, gchar *title, gchar *captured, gchar *displayed)
{
    simple_list_append(list, 0, title, 1, captured, 2, displayed, -1);
}

void
summary_open_cb(GtkWidget *w _U_, gpointer d _U_)
{
  summary_tally summary;
  GtkWidget     *sum_open_w,
                *main_vb, *bbox, *close_bt;
  GtkWidget     *table;
  GtkWidget     *list;
  char          *titles[] = { "Traffic", "Captured", "Displayed" };

  gchar         string_buff[SUM_STR_MAX];
  gchar         string_buff2[SUM_STR_MAX];

  double        seconds;
  double        disp_seconds;
  guint         offset;
  guint         snip;
  guint         row;
  gchar        *str_dup;
  gchar        *str_work;


  /* initial computations */
  summary_fill_in(&summary);
  seconds = summary.stop_time - summary.start_time;
  disp_seconds = summary.filtered_stop - summary.filtered_start;

  sum_open_w = dlg_window_new("Ethereal: Summary");

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 12);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 12);
  gtk_container_add(GTK_CONTAINER(sum_open_w), main_vb);

  /* table */
  table = gtk_table_new(1, 2, FALSE);
  gtk_table_set_col_spacings(GTK_TABLE(table), 6);
  gtk_table_set_row_spacings(GTK_TABLE(table), 3);
  gtk_container_add(GTK_CONTAINER(main_vb), table);
  row = 0;


  /* File */
  add_string_to_table(table, &row, "File", "");

  /* filename */
  g_snprintf(string_buff, SUM_STR_MAX, "%s", summary.filename);
  add_string_to_table(table, &row, "Name:", string_buff);

  /* length */
  g_snprintf(string_buff, SUM_STR_MAX, "%lu bytes", summary.file_length);
  add_string_to_table(table, &row, "Length:", string_buff);

  /* seconds */
  g_snprintf(string_buff, SUM_STR_MAX, "%.3f sec", summary.elapsed_time);
  add_string_to_table(table, &row, "Elapsed time:", string_buff);

  /* format */
  g_snprintf(string_buff, SUM_STR_MAX, "%s", wtap_file_type_string(summary.encap_type));
  add_string_to_table(table, &row, "Format:", string_buff);

  if (summary.has_snap) {
    /* snapshot length */
    g_snprintf(string_buff, SUM_STR_MAX, "%u bytes", summary.snap);
    add_string_to_table(table, &row, "Packet size limit:", string_buff);
  }


  /* Capture */
  add_string_to_table(table, &row, "", "");
  add_string_to_table_sensitive(table, &row, "Capture", "", (gboolean) summary.iface);

  /* interface */
  if (summary.iface) {
    g_snprintf(string_buff, SUM_STR_MAX, "%s", summary.iface);
  } else {
    g_snprintf(string_buff, SUM_STR_MAX, "unknown");
  }
  add_string_to_table_sensitive(table, &row, "Interface:", string_buff, (gboolean) summary.iface);

  /* Dropped count */
  if (summary.drops_known) {
    g_snprintf(string_buff, SUM_STR_MAX, "%u", summary.drops);
  } else {
    g_snprintf(string_buff, SUM_STR_MAX, "unknown");
  }
  add_string_to_table_sensitive(table, &row, "Dropped packets:", string_buff, (gboolean) summary.iface);

#ifdef HAVE_LIBPCAP
  /* Capture filter */
  if (summary.cfilter && summary.cfilter[0] != '\0') {
    g_snprintf(string_buff, SUM_STR_MAX, "%s", summary.cfilter);
  } else {
    g_snprintf(string_buff, SUM_STR_MAX, "none");
  }
  add_string_to_table_sensitive(table, &row, "Capture filter:", string_buff, (gboolean) summary.iface);
#endif


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

  /* Marked Packet count */
  g_snprintf(string_buff, SUM_STR_MAX, "%i", summary.marked_count);
  add_string_to_table(table, &row, "Marked packets:", string_buff);


  /* Traffic */
  list = simple_list_new(3, titles);
  gtk_container_add(GTK_CONTAINER(main_vb), list);

  g_snprintf(string_buff, SUM_STR_MAX, "%.3f sec", seconds);
  if(summary.dfilter) {
    g_snprintf(string_buff2, SUM_STR_MAX, "%.3f sec", disp_seconds);
  } else {
    strcpy(string_buff2, "");
  }
  add_string_to_list(list, &row, "Between first and last packet", string_buff, string_buff2);

  /* Packet count */
  g_snprintf(string_buff, SUM_STR_MAX, "%i", summary.packet_count);
  if(summary.dfilter) {
    g_snprintf(string_buff2, SUM_STR_MAX, "%i", summary.filtered_count);
  } else {
    strcpy(string_buff2, "");
  }
  add_string_to_list(list, &row, "Packets", string_buff, string_buff2);

  /* Packets per second */
  if (seconds > 0){
    g_snprintf(string_buff, SUM_STR_MAX, "%.3f", summary.packet_count/seconds);
  } else {
    strcpy(string_buff, "");
  }
  if(summary.dfilter && disp_seconds > 0){
    g_snprintf(string_buff2, SUM_STR_MAX, "%.3f", summary.filtered_count/disp_seconds);
  } else {
    strcpy(string_buff2, "");
  }
  add_string_to_list(list, &row, "Avg. packets/sec", string_buff, string_buff2);

  /* Packet size */
  if (summary.packet_count > 0){
    g_snprintf(string_buff, SUM_STR_MAX, "%.3f bytes",
      (float)summary.bytes/summary.packet_count);
  } else {
    strcpy(string_buff, "");
  }
  if (summary.dfilter && summary.filtered_count > 0){
    g_snprintf(string_buff2, SUM_STR_MAX, "%.3f bytes",
          (float) summary.filtered_bytes/summary.filtered_count);
  } else {
    strcpy(string_buff2, "");
  }
  add_string_to_list(list, &row, "Avg. packet size", string_buff, string_buff2);

  /* Byte count */
  g_snprintf(string_buff, SUM_STR_MAX, "%d", summary.bytes);
  if (summary.dfilter && summary.filtered_count > 0){
    g_snprintf(string_buff2, SUM_STR_MAX, "%d", summary.filtered_bytes);
  } else {
    strcpy(string_buff2, "");
  }
  add_string_to_list(list, &row, "Bytes", string_buff, string_buff2);

  /* Bytes per second */
  if (seconds > 0){
    g_snprintf(string_buff, SUM_STR_MAX, "%.3f", summary.bytes/seconds);
  } else {
    strcpy(string_buff, "");
  }
  if (summary.dfilter && disp_seconds > 0){
    g_snprintf(string_buff2, SUM_STR_MAX, "%.3f", summary.filtered_bytes/disp_seconds);
  } else {
    strcpy(string_buff2, "");
  }
  add_string_to_list(list, &row, "Avg. bytes/sec", string_buff, string_buff2);

  /* MBit per second */
  if (seconds > 0){
    g_snprintf(string_buff, SUM_STR_MAX, "%.3f", summary.bytes * 8.0 / (seconds * 1000.0 * 1000.0));
  } else {
    strcpy(string_buff, "");
  }
  if (summary.dfilter && disp_seconds > 0){
    g_snprintf(string_buff2, SUM_STR_MAX, "%.3f", 
          summary.filtered_bytes * 8.0 / (disp_seconds * 1000.0 * 1000.0));
  } else {
    strcpy(string_buff2, "");
  }
  add_string_to_list(list, &row, "Avg. MBit/sec", string_buff, string_buff2);

  
  /* Button row. */
  bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);

  close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
  SIGNAL_CONNECT_OBJECT(close_bt, "clicked", gtk_widget_destroy, sum_open_w);
  gtk_widget_grab_default(close_bt);
  gtk_widget_grab_focus(close_bt);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Close" button had
     been selected. */
  dlg_set_cancel(sum_open_w, close_bt);

  gtk_window_set_position(GTK_WINDOW(sum_open_w), GTK_WIN_POS_MOUSE);
  gtk_widget_show_all(sum_open_w);
}
