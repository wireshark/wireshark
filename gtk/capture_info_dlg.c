/* capture_info_dlg.c
 * Routines for packet capture info dialog
 *
 * $Id: capture_info_dlg.c,v 1.7 2003/12/16 18:43:33 oabad Exp $
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

#ifdef HAVE_LIBPCAP

#include <gtk/gtk.h>
#include "gtk/compat_macros.h"

#include <time.h>

#include <pcap.h>

#include <epan/packet.h>
#include "../capture.h"
#include "globals.h"
#include "capture_combo_utils.h"
#include "dlg_utils.h"

/* a single capture counter value (with title, pointer to value and GtkWidgets) */
/* as the packet_counts is a struct, not an array, keep a pointer to the */
/* corresponding value packet_counts, to speed up (and simplify) output of values */
typedef struct {
    const gchar *title;
    gint        *value_ptr;
    GtkWidget   *label, *value_lb, *percent_pb, *percent_lb;
} capture_info_counts_t;

/* all data we need to know of this dialog, after creation finished */
typedef struct {
    GtkWidget               *cap_w;
    GtkWidget               *running_time_lb;
    capture_info_counts_t   counts[CAPTURE_PACKET_COUNTS];
} capture_info_ui_t;



/* calculate the percentage of the current packet type */
static float
pct(gint num, gint denom) {
  if (denom) {
    return (float) (num * 100.0 / denom);
  } else {
    return 0.0;
  }
}

/* stop button (or ESC key) was pressed */
static void
capture_info_stop_cb(GtkWidget *w _U_, gpointer data) {
  capture_ui_stop_callback(data);
}


static void
capture_info_delete_cb(GtkWidget *w _U_, GdkEvent *event _U_, gpointer data) {
  capture_ui_stop_callback(data);
}


/* create the capture info dialog */
/* will keep pointers to the fields in the counts parameter */
void capture_info_create(
capture_info    *cinfo)
{
  unsigned int      i;
  GtkWidget         *main_vb, *stop_bt, *counts_tb;
  GtkWidget         *counts_fr, *running_tb, *running_label;
  capture_info_ui_t *info;

  info = g_malloc0(sizeof(capture_info_ui_t));
  info->counts[0].title = "Total";
  info->counts[0].value_ptr = &(cinfo->counts->total);
  info->counts[1].title = "SCTP";
  info->counts[1].value_ptr = &(cinfo->counts->sctp);
  info->counts[2].title = "TCP";
  info->counts[2].value_ptr = &(cinfo->counts->tcp);
  info->counts[3].title = "UDP";
  info->counts[3].value_ptr = &(cinfo->counts->udp);
  info->counts[4].title = "ICMP";
  info->counts[4].value_ptr = &(cinfo->counts->icmp);
  info->counts[5].title = "ARP";
  info->counts[5].value_ptr = &(cinfo->counts->arp);
  info->counts[6].title = "OSPF";
  info->counts[6].value_ptr = &(cinfo->counts->ospf);
  info->counts[7].title = "GRE";
  info->counts[7].value_ptr = &(cinfo->counts->gre);
  info->counts[8].title = "NetBIOS";
  info->counts[8].value_ptr = &(cinfo->counts->netbios);
  info->counts[9].title = "IPX";
  info->counts[9].value_ptr = &(cinfo->counts->ipx);
  info->counts[10].title = "VINES";
  info->counts[10].value_ptr = &(cinfo->counts->vines);
  info->counts[11].title = "Other";
  info->counts[11].value_ptr = &(cinfo->counts->other);

  info->cap_w = dlg_window_new("Ethereal: Capture");
  gtk_window_set_modal(GTK_WINDOW(info->cap_w), TRUE);

  /* Container for capture display widgets */
  main_vb = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(info->cap_w), main_vb);
  gtk_widget_show(main_vb);

  counts_fr = gtk_frame_new("Captured Packets");
  gtk_box_pack_start(GTK_BOX(main_vb), counts_fr, FALSE, FALSE, 3);
  gtk_widget_show(counts_fr);

  /* Individual statistic elements */
  counts_tb = gtk_table_new(CAPTURE_PACKET_COUNTS, 4, TRUE);
  gtk_container_add(GTK_CONTAINER(counts_fr), counts_tb);
  gtk_container_border_width(GTK_CONTAINER(counts_tb), 5);
  gtk_widget_show(counts_tb);

  gtk_table_set_row_spacings(GTK_TABLE(counts_tb), 0);
  gtk_table_set_col_spacings(GTK_TABLE(counts_tb), 5);

  for (i = 0; i < CAPTURE_PACKET_COUNTS; i++) {
      info->counts[i].label = gtk_label_new(info->counts[i].title);
      gtk_misc_set_alignment(GTK_MISC(info->counts[i].label), 0.0f, 0.5f);

      info->counts[i].value_lb = gtk_label_new("0");
      gtk_misc_set_alignment(GTK_MISC(info->counts[i].value_lb), 0.5f, 0.5f);

      if (i == 0) {
          /* do not build a progress bar for the "total" row */
          /* (as this could suggest a "buffer full" to the user) */
          /* simply put a label here */
          info->counts[i].percent_pb = gtk_label_new("% of total");
      } else {
          /* build a progress bar in the other rows */
          info->counts[i].percent_pb = gtk_progress_bar_new();

          /* downsize the default size of this progress bar in x direction (def:150), */
          /* otherwise it will become too large and the dialog will look ugly */
          /* XXX: use a TreeView instead of a table in order to fix this */
          WIDGET_SET_SIZE(info->counts[i].percent_pb, 70, -1);
      }

      info->counts[i].percent_lb = gtk_label_new("0.0%");
      gtk_misc_set_alignment(GTK_MISC(info->counts[i].percent_lb), 1.0f, 0.5f);

      gtk_table_attach_defaults(GTK_TABLE(counts_tb),
                                info->counts[i].label, 0, 1, i, i + 1);
      gtk_table_attach_defaults(GTK_TABLE(counts_tb),
                                info->counts[i].value_lb, 1, 2, i, i + 1);
	  gtk_table_attach_defaults(GTK_TABLE(counts_tb),
								info->counts[i].percent_pb, 2, 3, i, i + 1);
	  gtk_table_attach_defaults(GTK_TABLE(counts_tb),
								info->counts[i].percent_lb, 3, 4, i, i + 1);

      gtk_widget_show(info->counts[i].label);
      gtk_widget_show(info->counts[i].value_lb);
      gtk_widget_show(info->counts[i].percent_pb);
      /* don't show percentages for the "total" row */
      if (i != 0) {
        gtk_widget_show(info->counts[i].percent_lb);
      }
  }

  /* Running time */
  running_tb = gtk_table_new(1, 4, TRUE);
  gtk_box_pack_start(GTK_BOX(main_vb), running_tb, FALSE, FALSE, 3);
  gtk_widget_show(running_tb);

  running_label = gtk_label_new("Running");
  gtk_misc_set_alignment(GTK_MISC(running_label), 0.0f, 0.0f);
  gtk_widget_show(running_label);
  gtk_table_attach_defaults(GTK_TABLE(running_tb),
                                running_label, 0, 1, 0, 1);

  info->running_time_lb = gtk_label_new("00:00:00");
  gtk_misc_set_alignment(GTK_MISC(info->running_time_lb), 0.0f, 0.0f);
  gtk_widget_show(info->running_time_lb);
  gtk_table_attach(GTK_TABLE(running_tb),
                       info->running_time_lb,
                       1, 2, 0, 1, 0, 0, 5, 0);

  /* allow user to either click a stop button, or the close button on
	the window to stop a capture in progress. */
#if GTK_MAJOR_VERSION < 2
  stop_bt = gtk_button_new_with_label ("Stop");
#else
  stop_bt = gtk_button_new_from_stock(GTK_STOCK_STOP);
#endif
  SIGNAL_CONNECT(stop_bt, "clicked", capture_info_stop_cb,
                 cinfo->callback_data);
  SIGNAL_CONNECT(info->cap_w, "delete_event", capture_info_delete_cb,
                 cinfo->callback_data);
  gtk_box_pack_start(GTK_BOX(main_vb), stop_bt, FALSE, FALSE, 3);
  GTK_WIDGET_SET_FLAGS(stop_bt, GTK_CAN_DEFAULT);
  gtk_widget_grab_default(stop_bt);
  GTK_WIDGET_SET_FLAGS(stop_bt, GTK_CAN_DEFAULT);
  gtk_widget_grab_default(stop_bt);
  gtk_widget_show(stop_bt);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Stop" button had
     been selected. */
  dlg_set_cancel(info->cap_w, stop_bt);

  gtk_widget_show(info->cap_w);

  cinfo->ui = info;
}


/* update the capture info dialog */
/* As this function is a bit time critical while capturing, */
/* prepare everything possible in the capture_info_create() function above! */
void capture_info_update(
capture_info    *cinfo)
{
  unsigned int      i;
  gchar             label_str[64];
  capture_info_ui_t *info = cinfo->ui;


  /* calculate and display running time */
  snprintf(label_str, sizeof(label_str), "%02ld:%02ld:%02ld", 
           (long)(cinfo->running_time/3600), (long)((cinfo->running_time%3600)/60),
           (long)(cinfo->running_time%60));
  gtk_label_set(GTK_LABEL(info->running_time_lb), label_str);

  if (cinfo->new_packets) {

    for (i = 0; i < CAPTURE_PACKET_COUNTS; i++) {
        snprintf(label_str, sizeof(label_str), "%d",
                 *info->counts[i].value_ptr);
        gtk_label_set(GTK_LABEL(info->counts[i].value_lb), label_str);

        /* don't try to update the "total" row progress bar */
        if (i != 0) {
            gtk_progress_bar_update(GTK_PROGRESS_BAR(info->counts[i].percent_pb),
                     pct(*info->counts[i].value_ptr, *info->counts[0].value_ptr) / 100.0);
        }

        g_snprintf(label_str, sizeof(label_str), "%.1f%%",
                 pct(*info->counts[i].value_ptr, *info->counts[0].value_ptr));

        gtk_label_set(GTK_LABEL(info->counts[i].percent_lb), label_str);
    }
  }
}


/* destroy the capture info dialog again */
void capture_info_destroy(
capture_info    *cinfo)
{
  capture_info_ui_t *info = cinfo->ui;

  gtk_grab_remove(GTK_WIDGET(info->cap_w));
  gtk_widget_destroy(GTK_WIDGET(info->cap_w));
  g_free(info);
}


#endif /* HAVE_LIBPCAP */
