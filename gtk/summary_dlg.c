/* summary_dlg.c
 * Routines for capture file summary window
 *
 * $Id: summary_dlg.c,v 1.3 2000/04/13 09:17:09 guy Exp $
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
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <stdio.h>
#include <string.h>
#include <wtap.h>

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include "summary.h"
#include "summary_dlg.h"

#define SUM_STR_MAX 1024


static void
add_string_to_box(gchar *str, GtkWidget *box)
{
  GtkWidget *lb;
  lb = gtk_label_new(str);
  gtk_misc_set_alignment(GTK_MISC(lb), 0.0, 0.5);
  gtk_box_pack_start(GTK_BOX(box), lb,FALSE,FALSE, 0);
  gtk_widget_show(lb);
}


void
summary_open_cb(GtkWidget *w, gpointer d)
{
  summary_tally summary;
  GtkWidget     *sum_open_w,
                *main_vb, *file_fr, *data_fr, *capture_fr, *file_box, 
		*data_box, *capture_box, *close_bt;

  gchar          string_buff[SUM_STR_MAX];

  double         seconds;

 /* initialize the tally */
  summary_fill_in(&summary);

  /* initial compututations */
  seconds = summary.stop_time - summary.start_time;
  sum_open_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(sum_open_w), "Ethereal: Summary");

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(sum_open_w), main_vb);
  gtk_widget_show(main_vb);

  /* File frame */
  file_fr = gtk_frame_new("File");
  gtk_container_add(GTK_CONTAINER(main_vb), file_fr);
  gtk_widget_show(file_fr);

  file_box = gtk_vbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(file_fr), file_box);
  gtk_widget_show(file_box);

  /* filename */
  snprintf(string_buff, SUM_STR_MAX, "Name: %s", summary.filename);
  add_string_to_box(string_buff, file_box);

  /* length */
  snprintf(string_buff, SUM_STR_MAX, "Length: %lu", summary.file_length);
  add_string_to_box(string_buff, file_box);

  /* format */
  snprintf(string_buff, SUM_STR_MAX, "Format: %s", wtap_file_type_string(summary.encap_type));
  add_string_to_box(string_buff, file_box);

  /* snapshot length */
  snprintf(string_buff, SUM_STR_MAX, "Snapshot length: %u", summary.snap);
  add_string_to_box(string_buff, file_box);

  /* Data frame */
  data_fr = gtk_frame_new("Data");
  gtk_container_add(GTK_CONTAINER(main_vb), data_fr);
  gtk_widget_show(data_fr);

  data_box = gtk_vbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(data_fr), data_box);
  gtk_widget_show(data_box);

  /* seconds */
  snprintf(string_buff, SUM_STR_MAX, "Elapsed time: %.3f seconds", summary.elapsed_time);
  add_string_to_box(string_buff, data_box);

  snprintf(string_buff, SUM_STR_MAX, "Between first and last packet: %.3f seconds", seconds);
  add_string_to_box(string_buff, data_box);

  /* Packet count */
  snprintf(string_buff, SUM_STR_MAX, "Packet count: %i", summary.packet_count);
  add_string_to_box(string_buff, data_box);

  /* Filtered Packet count */
  snprintf(string_buff, SUM_STR_MAX, "Filtered packet count: %i", summary.filtered_count);
  add_string_to_box(string_buff, data_box);

  /* Packets per second */
  if (seconds > 0){
    snprintf(string_buff, SUM_STR_MAX, "Avg. packets/sec: %.3f", summary.packet_count/seconds);
    add_string_to_box(string_buff, data_box);
  }

  /* Dropped count */
  snprintf(string_buff, SUM_STR_MAX, "Dropped packets: %i", summary.drops);
  add_string_to_box(string_buff, data_box);

  /* Byte count */
  snprintf(string_buff, SUM_STR_MAX, "Bytes of traffic: %d", summary.bytes);
  add_string_to_box(string_buff, data_box);

  /* Bytes per second */
  if (seconds > 0){
    snprintf(string_buff, SUM_STR_MAX, "Avg. bytes/sec: %.3f", summary.bytes/seconds);
    add_string_to_box(string_buff, data_box);
  }

  /* Capture frame */
  capture_fr = gtk_frame_new("Capture");
  gtk_container_add(GTK_CONTAINER(main_vb), capture_fr);
  gtk_widget_show(capture_fr);

  capture_box = gtk_vbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(capture_fr), capture_box);
  gtk_widget_show(capture_box);


  /* interface */
  if (summary.iface) {
    snprintf(string_buff, SUM_STR_MAX, "Interface: %s", summary.iface);
  } else {
    sprintf(string_buff, "Interface: unknown");
  }
  add_string_to_box(string_buff, capture_box);

  /* Display filter */
  if (summary.dfilter) {
    snprintf(string_buff, SUM_STR_MAX, "Display filter: %s", summary.dfilter);
  } else {
    sprintf(string_buff, "Display filter: none");
  }
  add_string_to_box(string_buff, capture_box);

#ifdef HAVE_LIBPCAP
  /* Capture filter */
  if (summary.cfilter && summary.cfilter[0] != '\0') {
    snprintf(string_buff, SUM_STR_MAX, "Capture filter: %s", summary.cfilter);
  } else {
    sprintf(string_buff, "Capture filter: none");
  }
  add_string_to_box(string_buff, capture_box);
#endif

  /* Create Close Button */
  close_bt = gtk_button_new_with_label("Close");
  gtk_signal_connect_object(GTK_OBJECT(close_bt), "clicked",
    GTK_SIGNAL_FUNC(gtk_widget_destroy),
    GTK_OBJECT(sum_open_w));
  gtk_box_pack_start(GTK_BOX(main_vb), close_bt, FALSE,FALSE, 0);
  gtk_widget_show( close_bt );

  gtk_window_set_position(GTK_WINDOW(sum_open_w), GTK_WIN_POS_MOUSE);
  gtk_widget_show(sum_open_w);
}
