/* summary.c
 * Routines for capture file summary window
 *
 * $Id: summary.c,v 1.12 1999/09/09 02:42:26 gram Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif

#include "gtk/main.h"
#include "packet.h"
#include "file.h"
#include "summary.h"
#include "capture.h"
#include "util.h"
#include "prefs.h"

extern capture_file  cf;

/* File selection data keys */
#define E_SUM_PREP_FS_KEY "sum_prep_fs"
#define E_SUM_PREP_TE_KEY "sum_prep_te"

/* Summary callback data keys */
#define E_SUM_IFACE_KEY "sum_iface"
#define E_SUM_FILT_KEY  "sum_filter"
#define E_SUM_COUNT_KEY "sum_count"
#define E_SUM_OPEN_KEY  "sum_open"
#define E_SUM_SNAP_KEY  "sum_snap"

#define SUM_STR_MAX 1024

/* Summary filter key */
#define E_SUM_FILT_TE_KEY "sum_filt_te"

double
secs_usecs( guint32 s, guint32 us) {
  return (us / 1000000.0) + (double)s;
}

void
tally_frame_data(gpointer cf, gpointer st) {
  double cur_time;
  summary_tally * sum_tally = (summary_tally *)st;
  frame_data *cur_frame = (frame_data *)cf;

  cur_time = secs_usecs(cur_frame->abs_secs, cur_frame->abs_usecs);
    if (cur_time < sum_tally->start_time) {
      sum_tally->start_time = cur_time;
    }
    if (cur_time > sum_tally->stop_time){
    sum_tally->stop_time = cur_time;
  }
  sum_tally->bytes += cur_frame->pkt_len;
  if (cur_frame->passed_dfilter)
	  sum_tally->filtered_count++;
}

void
add_string_to_box(gchar *str, GtkWidget *box) {
  GtkWidget *lb;
  lb = gtk_label_new(str);
  gtk_misc_set_alignment(GTK_MISC(lb), 0.0, 0.5);
  gtk_box_pack_start(GTK_BOX(box), lb,FALSE,FALSE, 0);
  gtk_widget_show(lb);
}

void
summary_prep_cb(GtkWidget *w, gpointer d) {
  frame_data    *first_frame, *cur_frame;
  summary_tally *st;
  GtkWidget     *sum_open_w,
                *main_vb, *file_fr, *data_fr, *capture_fr, *file_box, 
*data_box,
                *capture_box;

 gchar          string_buff[SUM_STR_MAX];

 guint32        traffic_bytes, i;
 double         seconds;
 frame_data    *cur_glist;

 /* initialize the tally */
  first_frame = cf.plist;
  st = (summary_tally *)g_malloc(sizeof(summary_tally));
  st->start_time = secs_usecs(first_frame->abs_secs,first_frame->abs_usecs) 
;
  st->stop_time = secs_usecs(first_frame->abs_secs,first_frame->abs_usecs) 
;
  st->bytes = 0;
  st->filtered_count = 0;
  cur_glist = cf.plist;

  for (i = 0; i < cf.count; i++){
    cur_frame = cur_glist;
    tally_frame_data(cur_frame, st);
    cur_glist = cur_glist->next;
  }

  /* traffic_bytes will be computed here */
  traffic_bytes = st->bytes;
  seconds = st->stop_time - st->start_time;
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
  snprintf(string_buff, SUM_STR_MAX, "Name: %s", cf.filename);
  add_string_to_box(string_buff, file_box);

  /* length */
  snprintf(string_buff, SUM_STR_MAX, "Length: %lu", cf.f_len);
  add_string_to_box(string_buff, file_box);

  /* format */
  snprintf(string_buff, SUM_STR_MAX, "Format: %s", cf.cd_t_desc);
  add_string_to_box(string_buff, file_box);

  /* snapshot length */
  snprintf(string_buff, SUM_STR_MAX, "Snapshot length: %u", cf.snap);
  add_string_to_box(string_buff, file_box);

  /* Data frame */
  data_fr = gtk_frame_new("Data");
  gtk_container_add(GTK_CONTAINER(main_vb), data_fr);
  gtk_widget_show(data_fr);

  data_box = gtk_vbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(data_fr), data_box);
  gtk_widget_show(data_box);

  /* seconds */
  snprintf(string_buff, SUM_STR_MAX, "Elapsed time: %.3f seconds", 
secs_usecs(cf.esec,cf.eusec));
  add_string_to_box(string_buff, data_box);

  snprintf(string_buff, SUM_STR_MAX, "Between first and last packet: %.3f seconds", seconds);
  add_string_to_box(string_buff, data_box);

  /* Packet count */
  snprintf(string_buff, SUM_STR_MAX, "Packet count: %i", cf.count);
  add_string_to_box(string_buff, data_box);

  /* Filtered Packet count */
  snprintf(string_buff, SUM_STR_MAX, "Filtered packet count: %i", st->filtered_count);
  add_string_to_box(string_buff, data_box);

  /* Packets per second */
  if (seconds > 0){
    snprintf(string_buff, SUM_STR_MAX, "Avg. packets/sec: %.3f", 
cf.count/seconds);
    add_string_to_box(string_buff, data_box);
  }

  /* Dropped count */
  snprintf(string_buff, SUM_STR_MAX, "Dropped packets: %i", cf.drops);
  add_string_to_box(string_buff, data_box);

  /* Byte count */
  snprintf(string_buff, SUM_STR_MAX, "Bytes of traffic: %d", 
traffic_bytes);
  add_string_to_box(string_buff, data_box);

  /* Bytes per second */
  if (seconds > 0){
    snprintf(string_buff, SUM_STR_MAX, "Avg. bytes/sec: %.3f", 
traffic_bytes/seconds);
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
  if (cf.iface) {
    snprintf(string_buff, SUM_STR_MAX, "Interface: %s", cf.iface);
  } else {
    sprintf(string_buff, "Interface: unknown");
  }
  add_string_to_box(string_buff, capture_box);

  /* Display filter */
  if (DFILTER_CONTAINS_FILTER(cf.dfcode)) {
    snprintf(string_buff, SUM_STR_MAX, "Display filter: %s", cf.dfcode->dftext);
  } else {
    sprintf(string_buff, "Display filter: none");
  }
  add_string_to_box(string_buff, capture_box);

#ifdef HAVE_LIBPCAP
  /* Capture filter */
  if (cf.cfilter) {
    snprintf(string_buff, SUM_STR_MAX, "Capture filter: %s", cf.cfilter);
  } else {
    sprintf(string_buff, "Capture filter: none");
  }
  add_string_to_box(string_buff, capture_box);
#endif

  gtk_window_set_position(GTK_WINDOW(sum_open_w), GTK_WIN_POS_MOUSE);
  gtk_widget_show(sum_open_w);
}

/* this is never called 
void
summary_prep_close_cb(GtkWidget *w, gpointer win) {

  gtk_grab_remove(GTK_WIDGET(win));
  gtk_widget_destroy(GTK_WIDGET(win));
} */
