/* capture_info_dlg.c
 * Routines for packet capture info dialog
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#ifdef HAVE_LIBPCAP

#include <gtk/gtk.h>
#include "gtk/compat_macros.h"

#include <time.h>

#include <epan/packet.h>
#include "capture.h"
#include "capture_info.h"
#include "globals.h"
#include "capture_ui_utils.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "main.h"
#include "capture-pcap-util.h"


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
    capture_info_counts_t   counts[PACKET_COUNTS_SIZE];
    guint                   timer_id;
    time_t                  start_time;
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

static void
capture_info_delete_cb(GtkWidget *w _U_, GdkEvent *event _U_, gpointer data _U_) {
  capture_stop(capture_opts);
}

static gint
capture_info_ui_update_cb(gpointer data)
{
  capture_info *cinfo = data;
  capture_info_ui_t *info = cinfo->ui;

  cinfo->running_time = time(NULL) - info->start_time;
  capture_info_ui_update(cinfo);
  return 1;   /* call the timer again */
}


/* create the capture info dialog */
/* will keep pointers to the fields in the counts parameter */
void capture_info_ui_create(
capture_info    *cinfo,
const gchar     *iface)
{
  unsigned int      i;
  GtkWidget         *main_vb, *stop_bt, *counts_tb;
  GtkWidget         *counts_fr, *running_tb, *running_label, *bbox;
  capture_info_ui_t *info;
  gchar             *cap_w_title;
  gchar             *title_iface;
  gchar             *descr;

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

  /*
   * Create the dialog window, with a title that includes the interface.
   *
   * If we have a descriptive name for the interface, show that,
   * rather than its raw name.  On NT 5.x (2K/XP/Server2K3), the
   * interface name is something like "\Device\NPF_{242423..." 
   * which is pretty useless to the normal user.  On other platforms,
   * it might be less cryptic, but if a more descriptive name is
   * available, we should still use that.
   */
  descr = get_interface_descriptive_name(iface);
  title_iface = g_strdup_printf("Ethereal: Capture from %s", descr);
  g_free(descr);
  cap_w_title = create_user_window_title(title_iface);
  g_free(title_iface);
  info->cap_w = dlg_window_new(cap_w_title);
  g_free(cap_w_title);

  /* Container for capture display widgets */
  main_vb = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(info->cap_w), main_vb);
  gtk_widget_show(main_vb);

  counts_fr = gtk_frame_new("Captured Packets");
  gtk_box_pack_start(GTK_BOX(main_vb), counts_fr, FALSE, FALSE, 3);
  gtk_widget_show(counts_fr);

  /* Individual statistic elements */
  counts_tb = gtk_table_new(PACKET_COUNTS_SIZE, 4, TRUE);
  gtk_container_add(GTK_CONTAINER(counts_fr), counts_tb);
  gtk_container_border_width(GTK_CONTAINER(counts_tb), 5);
  gtk_widget_show(counts_tb);

  gtk_table_set_row_spacings(GTK_TABLE(counts_tb), 0);
  gtk_table_set_col_spacings(GTK_TABLE(counts_tb), 5);

  for (i = 0; i < PACKET_COUNTS_SIZE; i++) {
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
  bbox = dlg_button_row_new(GTK_STOCK_STOP, NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 3);
  gtk_widget_show(bbox);

  stop_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_STOP);
  window_set_cancel_button(info->cap_w, stop_bt, NULL);
  SIGNAL_CONNECT(stop_bt, "clicked", capture_info_delete_cb, capture_opts);

  SIGNAL_CONNECT(info->cap_w, "delete_event", capture_info_delete_cb,
                 capture_opts);

  gtk_widget_show(info->cap_w);
  window_present(info->cap_w);

  info->start_time = time(NULL);

  cinfo->ui = info;

  /* update the dialog once a second, even if no packets rushing in */
  info->timer_id = gtk_timeout_add(1000, (GtkFunction)capture_info_ui_update_cb,(gpointer)cinfo);
}


/* update the capture info dialog */
/* As this function is a bit time critical while capturing, */
/* prepare everything possible in the capture_info_ui_create() function above! */
void capture_info_ui_update(
capture_info    *cinfo)
{
  unsigned int      i;
  gchar             label_str[64];
  capture_info_ui_t *info = cinfo->ui;


  /* display running time */
  g_snprintf(label_str, sizeof(label_str), "%02ld:%02ld:%02ld", 
           (long)(cinfo->running_time/3600), (long)((cinfo->running_time%3600)/60),
           (long)(cinfo->running_time%60));
  gtk_label_set(GTK_LABEL(info->running_time_lb), label_str);

  /* if we have new packets, update all rows */
  if (cinfo->new_packets) {

    for (i = 0; i < PACKET_COUNTS_SIZE; i++) {
        g_snprintf(label_str, sizeof(label_str), "%d",
                 *info->counts[i].value_ptr);
        gtk_label_set(GTK_LABEL(info->counts[i].value_lb), label_str);

        /* don't try to update the "total" row progress bar */
        if (i != 0) {
            gtk_progress_bar_update(GTK_PROGRESS_BAR(info->counts[i].percent_pb),
                     (gfloat) (pct(*info->counts[i].value_ptr, *info->counts[0].value_ptr) / 100.0));
        }

        g_snprintf(label_str, sizeof(label_str), "%.1f%%",
                 pct(*info->counts[i].value_ptr, *info->counts[0].value_ptr));

        gtk_label_set(GTK_LABEL(info->counts[i].percent_lb), label_str);
    }
  }
}


/* destroy the capture info dialog again */
void capture_info_ui_destroy(
capture_info    *cinfo)
{
  capture_info_ui_t *info = cinfo->ui;

  gtk_timeout_remove(info->timer_id);

  /* called from capture engine, so it's ok to destroy the dialog here */
  gtk_grab_remove(GTK_WIDGET(info->cap_w));
  window_destroy(GTK_WIDGET(info->cap_w));
  g_free(info);
}


#endif /* HAVE_LIBPCAP */
