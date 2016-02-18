/* capture_info_dlg.c
 * Routines for packet capture info dialog
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

#ifdef HAVE_LIBPCAP

#include <time.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/capture_dissectors.h>

#include "ui/capture.h"
#include "../../capture_info.h"

#include "ui/capture_ui_utils.h"

#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/main.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/stock_icons.h"

#ifdef HAVE_AIRPCAP
#include <caputils/airpcap.h>
#include <caputils/airpcap_loader.h>
#include "airpcap_gui_utils.h"
#include "airpcap_dlg.h"
#endif


/* a single capture counter value (with title, pointer to value and GtkWidgets)   */
/* as the packet_counts is a struct, not an array, keep a pointer to the          */
/* corresponding value packet_counts, to speed up (and simplify) output of values */
typedef struct {
  const gchar *title;
  int         proto;
  GtkWidget   *label, *value_lb, *percent_pb, *percent_lb;
} capture_info_counts_t;

/** Number of packet counts. */
#define PACKET_COUNTS_SIZE 12

/* all data we need to know of this dialog, after creation finished */
typedef struct {
  GtkWidget             *cap_w;
  GtkWidget             *running_time_lb;
  capture_info_counts_t  total_count;
  capture_info_counts_t  other_count;
  capture_info_counts_t  counts[PACKET_COUNTS_SIZE];
  guint                  timer_id;
  time_t                 start_time;
} capture_info_ui_t;


/* Workhorse for stopping capture */
static void
capture_info_stop(capture_session *cap_session)
{
#ifdef HAVE_AIRPCAP
  airpcap_set_toolbar_stop_capture(airpcap_if_active);
#endif
  capture_stop(cap_session);
}

/* "delete-event" signal callback. Note different signature than "clicked" signal callback */
static gboolean
capture_info_delete_cb(GtkWidget *w _U_, GdkEvent *event _U_, gpointer data) {
  capture_info_stop((capture_session *)data);
  return TRUE;
}

/* "clicked" signal callback */
static void
capture_info_stop_clicked_cb(GtkButton *w _U_, gpointer data) {
  capture_info_stop((capture_session *)data);
}

static gboolean
capture_info_ui_update_cb(gpointer data)
{
  capture_info      *cinfo = (capture_info *)data;
  capture_info_ui_t *info  = (capture_info_ui_t *)cinfo->ui;

  if (!info) /* ...which might happen on slow displays? */
    return TRUE;

  cinfo->running_time = time(NULL) - info->start_time;
  capture_info_ui_update(cinfo);
  return TRUE;   /* call the timer again */
}

static void
capture_info_count_init(capture_info_counts_t* count, int idx, GtkWidget *percent_pb, gboolean show, GtkWidget *counts_grid)
{
  count->label = gtk_label_new(count->title);
  gtk_misc_set_alignment(GTK_MISC(count->label), 0.0f, 0.5f);

  count->value_lb = gtk_label_new("0");
  gtk_misc_set_alignment(GTK_MISC(count->value_lb), 0.5f, 0.5f);

  count->percent_pb = percent_pb;

  if (!show) /* Do for all but "total" */
  {
    /* downsize the default size of this progress bar in x direction (def:150), */
    /* otherwise it will become too large and the dialog will look ugly */
    /* XXX: use a TreeView instead of a grid in order to fix this */
    gtk_widget_set_size_request(count->percent_pb, 70, -1);
  }

  count->percent_lb = gtk_label_new("0.0%");
  gtk_misc_set_alignment(GTK_MISC(count->percent_lb), 1.0f, 0.5f);

  ws_gtk_grid_attach_extended(GTK_GRID(counts_grid), count->label,
                                0, idx, 1, 1, (GtkAttachOptions)(GTK_EXPAND|GTK_FILL), (GtkAttachOptions)0, 0, 0);
  ws_gtk_grid_attach_extended(GTK_GRID(counts_grid), count->value_lb,
                                1, idx, 1, 1, (GtkAttachOptions)(GTK_EXPAND|GTK_FILL), (GtkAttachOptions)0, 0, 0);
  ws_gtk_grid_attach_extended(GTK_GRID(counts_grid), count->percent_pb,
                                2, idx, 1, 1, (GtkAttachOptions)(GTK_EXPAND|GTK_FILL), (GtkAttachOptions)0, 0, 0);
  ws_gtk_grid_attach_extended(GTK_GRID(counts_grid), count->percent_lb,
                                3, idx, 1, 1, (GtkAttachOptions)(GTK_EXPAND|GTK_FILL), (GtkAttachOptions)0, 0, 0);

  gtk_widget_show(count->label);
  gtk_widget_show(count->value_lb);
  gtk_widget_show(count->percent_pb);
  /* don't show percentages for the "total" row */
  if (show) {
    gtk_widget_show(count->percent_lb);
  }
}

/* create the capture info dialog */
/* will keep pointers to the fields in the counts parameter */
void
capture_info_ui_create(capture_info *cinfo, capture_session *cap_session)
{
  capture_options  *capture_opts = cap_session->capture_opts;
  unsigned int      i;
  GtkWidget         *main_vb, *stop_bt, *counts_grid;
  GtkWidget         *counts_fr, *running_grid, *running_label, *lb, *bbox, *ci_help;
  capture_info_ui_t *info;
  gchar             *cap_w_title;
  gchar             *title_iface;
  GString           *str;

  info = g_new0(capture_info_ui_t,1);
  info->total_count.title      = "Total";
  info->other_count.title      = "Other";

  info->counts[0].title      = "SCTP";
  info->counts[0].proto      = proto_get_id_by_short_name(info->counts[0].title);
  info->counts[1].title      = "TCP";
  info->counts[1].proto      = proto_get_id_by_short_name(info->counts[1].title);
  info->counts[2].title      = "UDP";
  info->counts[2].proto      = proto_get_id_by_short_name(info->counts[2].title);
  info->counts[3].title      = "ICMP";
  info->counts[3].proto      = proto_get_id_by_short_name(info->counts[3].title);
  info->counts[4].title      = "ARP";
  info->counts[4].proto      = proto_get_id_by_short_name(info->counts[4].title);
  info->counts[5].title      = "OSPF";
  info->counts[5].proto      = proto_get_id_by_short_name(info->counts[5].title);
  info->counts[6].title      = "GRE";
  info->counts[6].proto      = proto_get_id_by_short_name(info->counts[6].title);
  info->counts[7].title      = "NetBIOS";
  info->counts[7].proto      = proto_get_id_by_short_name(info->counts[7].title);
  info->counts[8].title      = "IPX";
  info->counts[8].proto      = proto_get_id_by_short_name(info->counts[8].title);
  info->counts[9].title     = "VINES";
  info->counts[9].proto      = proto_get_id_by_short_name(info->counts[9].title);
  info->counts[10].title     = "I2C Events";
  info->counts[10].proto      = proto_get_id_by_short_name(info->counts[10].title);
  info->counts[11].title     = "I2C Data";
  info->counts[11].proto      = proto_get_id_by_short_name(info->counts[11].title);

  /*
   * Create the dialog window, with a title that includes the interfaces
   * on which we're capturing.
   */
  str = get_iface_list_string(capture_opts, 0);
  title_iface = g_strdup_printf("Wireshark: Capture from %s", str->str);
  g_string_free(str, TRUE);
  cap_w_title = create_user_window_title(title_iface);
  g_free(title_iface);
  info->cap_w = dlg_window_new(cap_w_title);
  g_free(cap_w_title);

  /* Container for capture display widgets */
  main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 1, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(info->cap_w), main_vb);
  gtk_widget_show(main_vb);

  counts_fr = gtk_frame_new("Captured Packets");
  gtk_box_pack_start(GTK_BOX(main_vb), counts_fr, FALSE, FALSE, 3);
  gtk_widget_show(counts_fr);

  /* Individual statistic elements */
  counts_grid = ws_gtk_grid_new();
  ws_gtk_grid_set_homogeneous(GTK_GRID(counts_grid), TRUE);
  gtk_container_add(GTK_CONTAINER(counts_fr), counts_grid);
  gtk_container_set_border_width(GTK_CONTAINER(counts_grid), 5);
  gtk_widget_show(counts_grid);

  ws_gtk_grid_set_row_spacing(GTK_GRID(counts_grid), 0);
  ws_gtk_grid_set_column_spacing(GTK_GRID(counts_grid), 5);

  capture_info_count_init(&info->total_count, 0, gtk_label_new("% of total"), FALSE, counts_grid);

  for (i = 0; i < PACKET_COUNTS_SIZE; i++) {
    capture_info_count_init(&info->counts[i], i+1, gtk_progress_bar_new(), TRUE, counts_grid);
  }

  capture_info_count_init(&info->other_count, i+1, gtk_progress_bar_new(), TRUE, counts_grid);

  /* Running time */
  running_grid = ws_gtk_grid_new();
  ws_gtk_grid_set_homogeneous(GTK_GRID(running_grid), TRUE);

  running_label = gtk_label_new("Running");
  gtk_misc_set_alignment(GTK_MISC(running_label), 0.0f, 0.0f);
  gtk_widget_show(running_label);
  ws_gtk_grid_attach_extended(GTK_GRID(running_grid), running_label,
                              0, 0, 1, 1, (GtkAttachOptions)(GTK_EXPAND|GTK_FILL), (GtkAttachOptions)0, 0, 0);

  info->running_time_lb = gtk_label_new("00:00:00");
  gtk_misc_set_alignment(GTK_MISC(info->running_time_lb), 0.5f, 0.0f);
  gtk_widget_show(info->running_time_lb);
  ws_gtk_grid_attach_extended(GTK_GRID(running_grid), info->running_time_lb,
                              1, 0, 1, 1, (GtkAttachOptions)(GTK_EXPAND|GTK_FILL), (GtkAttachOptions)0, 5, 0);  /* effect: pads *all* the columns ?? */

  /* two dummy cols to match the 4 cols above */
  lb = gtk_label_new("");
  gtk_widget_show(lb);
  ws_gtk_grid_attach_extended(GTK_GRID(running_grid), lb,
                              2, 0, 1, 1, (GtkAttachOptions)(GTK_EXPAND|GTK_FILL), (GtkAttachOptions)0, 0, 0);
  lb = gtk_label_new("");
  gtk_widget_show(lb);
  ws_gtk_grid_attach_extended(GTK_GRID(running_grid), lb,
                              3, 0, 1, 1, (GtkAttachOptions)(GTK_EXPAND|GTK_FILL), (GtkAttachOptions)0, 0, 0);

  gtk_box_pack_start(GTK_BOX(main_vb), running_grid, FALSE, FALSE, 3);
  gtk_widget_show(running_grid);

  /* allow user to either click a stop button, or the close button on
     the window to stop a capture in progress. */
  bbox = dlg_button_row_new(WIRESHARK_STOCK_CAPTURE_STOP, GTK_STOCK_HELP, NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 3);
  gtk_widget_show(bbox);

  stop_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_CAPTURE_STOP);
  window_set_cancel_button(info->cap_w, stop_bt, NULL);
  g_signal_connect(stop_bt, "clicked", G_CALLBACK(capture_info_stop_clicked_cb), cap_session);
  g_signal_connect(info->cap_w, "delete_event", G_CALLBACK(capture_info_delete_cb), cap_session);

  ci_help = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
  gtk_widget_set_tooltip_text(ci_help, "Get help about this dialog");
  g_signal_connect(ci_help, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_CAPTURE_INFO_DIALOG);

  gtk_widget_show(info->cap_w);
  window_present(info->cap_w);

  info->start_time = time(NULL);

  cinfo->ui = info;

  /* update the dialog once a second, even if no packets rushing in */
  info->timer_id = g_timeout_add(1000, capture_info_ui_update_cb,cinfo);
}

static void
capture_info_count_update(capture_info_counts_t* count, capture_info *cinfo)
{
  gchar label_str[64];
  float pb_frac;
  guint32 proto_count;

  proto_count = capture_dissector_get_count(cinfo->counts, count->proto);

  g_snprintf(label_str, sizeof(label_str), "%d", proto_count);
  gtk_label_set_text(GTK_LABEL(count->value_lb), label_str);

  pb_frac = (cinfo->counts->total != 0) ?
     ((float)proto_count / cinfo->counts->total) : 0.0f;

  /* don't try to update the "total" row progress bar */
  gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(count->percent_pb), pb_frac);
  g_snprintf(label_str, sizeof(label_str), "%.1f%%", pb_frac * 100.0);
  gtk_label_set_text(GTK_LABEL(count->percent_lb), label_str);
}

/* update the capture info dialog */
/* As this function is a bit time critical while capturing, */
/* prepare everything possible in the capture_info_ui_create() function above! */
void capture_info_ui_update(
capture_info    *cinfo)
{
  unsigned int      i;
  gchar             label_str[64];
  capture_info_ui_t *info = (capture_info_ui_t *)cinfo->ui;

  if (!info) /* ...which might happen on slow displays? */
    return;

  /* display running time */
  g_snprintf(label_str, sizeof(label_str), "%02ld:%02ld:%02ld",
             (long)(cinfo->running_time/3600), (long)((cinfo->running_time%3600)/60),
             (long)(cinfo->running_time%60));
  gtk_label_set_text(GTK_LABEL(info->running_time_lb), label_str);

  /* if we have new packets, update all rows */
  if (cinfo->new_packets) {
    float pb_frac;

    /* First setup total */
    g_snprintf(label_str, sizeof(label_str), "%d", cinfo->counts->total);
    gtk_label_set_text(GTK_LABEL(info->total_count.value_lb), label_str);

    for (i = 0; i < PACKET_COUNTS_SIZE; i++) {
      capture_info_count_update(&info->counts[i], cinfo);
    }

    /* Now handle "other" packets */
    g_snprintf(label_str, sizeof(label_str), "%d", cinfo->counts->other);
    gtk_label_set_text(GTK_LABEL(info->other_count.value_lb), label_str);

    pb_frac = (cinfo->counts->total != 0) ?
        ((float)cinfo->counts->other / cinfo->counts->total) : 0.0f;

    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(info->other_count.percent_pb), pb_frac);
    g_snprintf(label_str, sizeof(label_str), "%.1f%%", pb_frac * 100.0);
    gtk_label_set_text(GTK_LABEL(info->other_count.percent_lb), label_str);
  }
}

/* destroy the capture info dialog again */
void capture_info_ui_destroy(
capture_info    *cinfo)
{
  capture_info_ui_t *info = (capture_info_ui_t *)cinfo->ui;

  if (!info) /* ...which probably shouldn't happen */
    return;

  g_source_remove(info->timer_id);

  /* called from capture engine, so it's ok to destroy the dialog here */
  gtk_grab_remove(GTK_WIDGET(info->cap_w));
  window_destroy(GTK_WIDGET(info->cap_w));
  g_free(info);
  cinfo->ui = NULL;
}


#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
