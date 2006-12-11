/* capture_if_dlg.c
 * Routines for the capture interface dialog
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

#ifdef HAVE_LIBPCAP

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif


#include <gtk/gtk.h>

#include "globals.h"
#include "capture-pcap-util.h"

#ifdef _WIN32
#include "capture-wpcap.h"
#endif

#include "compat_macros.h"
#include "simple_dialog.h"
#include "capture.h"
#include "capture_dlg.h"
#include "capture_if_details_dlg.h"
#include "capture_errs.h"
#include "recent.h"
#include <epan/prefs.h>

#include "gui_utils.h"
#include "dlg_utils.h"

#include "main.h"
#include "wtap.h"
#include "help_dlg.h"
#include "toolbar.h"
#include "keys.h"

#include "webbrowser.h"

#ifdef HAVE_AIRPCAP
#include "../image/toolbar/capture_airpcap_16.xpm"
#endif
#include "../image/toolbar/capture_ethernet_16.xpm"

/* new buttons to be used instead of labels for 'Capture','Prepare',' */
#include "../image/toolbar/capture_capture_16.xpm"
#include "../image/toolbar/capture_prepare_16.xpm"
#include "../image/toolbar/capture_details_16.xpm"


#ifdef HAVE_AIRPCAP
#include <airpcap.h>
#include "airpcap_loader.h"
#include "airpcap_gui_utils.h"
#include "airpcap_dlg.h"
#endif

/*
 * Keep a static pointer to the current "Capture Interfaces" window, if
 * any, so that if somebody tries to do "Capture:Start" while there's
 * already a "Capture Interfaces" window up, we just pop up the existing
 * one, rather than creating a new one.
 */
static GtkWidget *cap_if_w;
#ifdef HAVE_AIRPCAP
static GtkWidget *cap_air_w;
#endif

GList           *if_data = NULL;

guint           timer_id;

GtkWidget       *stop_bt;

GList           *if_list;

/*
 * Timeout, in milliseconds, for reads from the stream of captured packets.
 */
#define	CAP_READ_TIMEOUT	250


/* the "runtime" data of one interface */
typedef struct if_dlg_data_s {
    pcap_t      *pch;
    GtkWidget   *device_lb;
    GtkWidget   *descr_lb;
    GtkWidget   *ip_lb;
    GtkWidget   *curr_lb;
    GtkWidget   *last_lb;
    GtkWidget   *capture_bt;
    GtkWidget   *prepare_bt;
#ifdef _WIN32
    GtkWidget   *details_bt;
#endif
    guint32     last_packets;
    gchar       *device;
} if_dlg_data_t;

void update_if(if_dlg_data_t *if_dlg_data);


/* start capture button was pressed */
static void
capture_do_cb(GtkWidget *capture_bt _U_, gpointer if_data)
{
  if_dlg_data_t *if_dlg_data = if_data;

#ifdef HAVE_AIRPCAP
  airpcap_if_active = get_airpcap_if_from_description(airpcap_if_list, GTK_LABEL(if_dlg_data->descr_lb)->label);
  airpcap_if_selected = airpcap_if_active;
#endif

  if (capture_opts->iface)
    g_free(capture_opts->iface);

  capture_opts->iface = g_strdup(if_dlg_data->device);

  /* XXX - remove this? */
  if (capture_opts->save_file) {
    g_free(capture_opts->save_file);
    capture_opts->save_file = NULL;
  }

  /* stop capturing from all interfaces, we are going to do real work now ... */
  window_destroy(cap_if_w);

  capture_start_cb(NULL, NULL);
}


/* prepare capture button was pressed */
static void
capture_prepare_cb(GtkWidget *prepare_bt _U_, gpointer if_data)
{
  if_dlg_data_t *if_dlg_data = if_data;

  if (capture_opts->iface)
    g_free(capture_opts->iface);

  capture_opts->iface = g_strdup(if_dlg_data->device);

  /* stop capturing from all interfaces, we are going to do real work now ... */
  window_destroy(cap_if_w);

  capture_prep_cb(NULL, NULL);
}


#ifdef _WIN32
/* capture details button was pressed */
static void
capture_details_cb(GtkWidget *details_bt _U_, gpointer if_data)
{
  if_dlg_data_t *if_dlg_data = if_data;


  capture_if_details_open(if_dlg_data->device);
}
#endif


/* open a single interface */
static void
open_if(gchar *name, if_dlg_data_t *if_dlg_data)
{
  gchar       open_err_str[CAPTURE_PCAP_ERRBUF_SIZE];

  /*
   * XXX - on systems with BPF, the number of BPF devices limits the
   * number of devices on which you can capture simultaneously.
   *
   * This means that
   *
   *	1) this might fail if you run out of BPF devices
   *
   * and
   *
   *	2) opening every interface could leave too few BPF devices
   *	   for *other* programs.
   *
   * It also means the system could end up getting a lot of traffic
   * that it has to pass through the networking stack and capture
   * mechanism, so opening all the devices and presenting packet
   * counts might not always be a good idea.
   */
  if_dlg_data->pch = pcap_open_live(name,
		       MIN_PACKET_SIZE,
		       capture_opts->promisc_mode, CAP_READ_TIMEOUT,
		       open_err_str);

  if (if_dlg_data->pch != NULL) {
    update_if(if_dlg_data);
  } else {
    printf("open_if: %s\n", open_err_str);
    gtk_label_set_text(GTK_LABEL(if_dlg_data->curr_lb), "error");
    gtk_label_set_text(GTK_LABEL(if_dlg_data->last_lb), "error");
  }
}

/* update a single interface */
void
update_if(if_dlg_data_t *if_dlg_data)
{
  struct pcap_stat stats;
  gchar *str;
  guint diff;


  /* pcap_stats() stats values differ on libpcap and winpcap!
   * libpcap: returns the number of packets since pcap_open_live
   * winpcap: returns the number of packets since the last pcap_stats call
   * XXX - if that's true, that's a bug, and should be fixed; "pcap_stats()"
   * is supposed to work the same way on all platforms, including Windows.
   * Note that the WinPcap 3.0 documentation says "The values represent
   * packet statistics from the start of the run to the time of the call."
   * (Note also that some versions of libpcap, on some versions of UN*X,
   * have the same bug.)
   */
  if (if_dlg_data->pch) {
    if(pcap_stats(if_dlg_data->pch, &stats) >= 0) {
#ifdef _WIN32
      diff = stats.ps_recv - if_dlg_data->last_packets;
      if_dlg_data->last_packets = stats.ps_recv;
#else
      diff = stats.ps_recv;
      if_dlg_data->last_packets = stats.ps_recv + if_dlg_data->last_packets;
#endif

      str = g_strdup_printf("%u", if_dlg_data->last_packets);
      gtk_label_set_text(GTK_LABEL(if_dlg_data->curr_lb), str);
      g_free(str);
      str = g_strdup_printf("%u", diff);
      gtk_label_set_text(GTK_LABEL(if_dlg_data->last_lb), str);
      g_free(str);

      gtk_widget_set_sensitive(if_dlg_data->curr_lb, diff);
      gtk_widget_set_sensitive(if_dlg_data->last_lb, diff);
    } else {
      gtk_label_set_text(GTK_LABEL(if_dlg_data->curr_lb), "error");
      gtk_label_set_text(GTK_LABEL(if_dlg_data->last_lb), "error");
    }
  }
}


/* close a single interface */
static void
close_if(if_dlg_data_t *if_dlg_data)
{
    if(if_dlg_data->pch)
        pcap_close(if_dlg_data->pch);
}



/* update all interfaces */
static gboolean
update_all(gpointer data)
{
    GList *curr;
    int ifs;


    if(!cap_if_w) {
        return FALSE;
    }

    for(ifs = 0; (curr = g_list_nth(data, ifs)); ifs++) {
        update_if(curr->data);
    }

    return TRUE;
}


/* a live capture has started or stopped */
void
set_capture_if_dialog_for_capture_in_progress(gboolean capture_in_progress)
{
    GList *curr;
    int ifs;

    if(cap_if_w) {
        gtk_widget_set_sensitive(stop_bt, capture_in_progress);

        for(ifs = 0; (curr = g_list_nth(if_data, ifs)); ifs++) {
            if_dlg_data_t *if_dlg_data = curr->data;

            gtk_widget_set_sensitive(if_dlg_data->capture_bt, !capture_in_progress);
            gtk_widget_set_sensitive(if_dlg_data->prepare_bt, !capture_in_progress);
        }
    }
}


/* the window was closed, cleanup things */
static void
capture_if_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
    GList *curr;
    int ifs;

    gtk_timeout_remove(timer_id);

    for(ifs = 0; (curr = g_list_nth(if_data, ifs)); ifs++) {
        if_dlg_data_t *if_dlg_data = curr->data;

        close_if(if_dlg_data);
        g_free(curr->data);
    }

    if_data = NULL;

    free_interface_list(if_list);

    /* Note that we no longer have a "Capture Options" dialog box. */
    cap_if_w = NULL;

#ifdef HAVE_AIRPCAP
	airpcap_set_toolbar_stop_capture(airpcap_if_active);
#endif
}

GtkWidget*
combo_channel_new(void)
{
	  GtkWidget* channel_cb;
	  GList*     popdown;


      channel_cb = gtk_combo_new();
	  gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(channel_cb)->entry), "1");

	  popdown = NULL;

	  popdown = g_list_append(popdown, "1");
      popdown = g_list_append(popdown, "2");
      popdown = g_list_append(popdown, "3");
      popdown = g_list_append(popdown, "4");
	  popdown = g_list_append(popdown, "5");
	  popdown = g_list_append(popdown, "6");
	  popdown = g_list_append(popdown, "7");
	  popdown = g_list_append(popdown, "8");
	  popdown = g_list_append(popdown, "9");
	  popdown = g_list_append(popdown, "10");
	  popdown = g_list_append(popdown, "11");
	  popdown = g_list_append(popdown, "12");
	  popdown = g_list_append(popdown, "13");
	  popdown = g_list_append(popdown, "14");

      gtk_combo_set_popdown_strings( GTK_COMBO(channel_cb), popdown) ;

	  #if GTK_MAJOR_VERSION < 2
	  gtk_widget_set_usize( GTK_WIDGET(channel_cb),
                                  45,
                                  10 );
	  #else
	  gtk_widget_set_size_request( GTK_WIDGET(channel_cb),
                                  45,
                                  10 );
      #endif


	  return channel_cb;
}

/* start getting capture stats from all interfaces */
void
capture_if_cb(GtkWidget *w _U_, gpointer d _U_)
{
  GtkWidget     *main_vb,
				*main_sw,
				*bbox,
				*close_bt,
				*help_bt,
				*icon;

#ifdef HAVE_AIRPCAP
  GtkWidget		*decryption_cm;
#endif

  GtkWidget     *if_tb;
  GtkWidget     *if_lb;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif
  GtkTooltips   *tooltips;
  int           err;
  char          err_str[CAPTURE_PCAP_ERRBUF_SIZE];
  gchar         *cant_get_if_list_errstr;
  GtkRequisition requisition;
  int           row, height;
  if_dlg_data_t *if_dlg_data;
  int           ifs;
  GList         *curr;
  if_info_t     *if_info;
  GSList        *curr_ip;
  if_addr_t     *ip_addr;
  GString       *if_tool_str = g_string_new("");
  gchar         *tmp_str;

  if (cap_if_w != NULL) {
    /* There's already a "Capture Interfaces" dialog box; reactivate it. */
    reactivate_window(cap_if_w);
    return;
  }

#ifdef _WIN32
  /* Is WPcap loaded? */
  if (!has_wpcap) {
    char *detailed_err;

    detailed_err = cant_load_winpcap_err("Wireshark");
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", detailed_err);
    g_free(detailed_err);
    return;
  }
#endif

  /* LOAD THE INTERFACES */
  if_list = get_interface_list(&err, err_str);
  if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
    cant_get_if_list_errstr = cant_get_if_list_error_message(err_str);
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s",
                  cant_get_if_list_errstr);
    g_free(cant_get_if_list_errstr);
    return;
  }

#ifdef HAVE_AIRPCAP
  /* LOAD AIRPCAP INTERFACES */
	/* load the airpcap interfaces */
	airpcap_if_list = get_airpcap_interface_list(&err, err_str);
	if(airpcap_if_list == NULL) airpcap_if_active = airpcap_if_selected = NULL;

	decryption_cm = OBJECT_GET_DATA(airpcap_tb,AIRPCAP_TOOLBAR_DECRYPTION_KEY);
	update_decryption_mode_list(decryption_cm);

	if (airpcap_if_list == NULL && err == CANT_GET_AIRPCAP_INTERFACE_LIST) {
	cant_get_if_list_errstr = cant_get_airpcap_if_list_error_message(err_str);
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s",
				  cant_get_if_list_errstr);
	g_free(cant_get_if_list_errstr);
	}

	/* If no airpcap interface is present, gray everything */
	if(airpcap_if_active == NULL)
		{
		if(airpcap_if_list == NULL)
			{
			/*No airpcap device found */
			airpcap_enable_toolbar_widgets(airpcap_tb,FALSE);
			}
		else
			{
			/* default adapter is not airpcap... or is airpcap but is not found*/
			airpcap_set_toolbar_stop_capture(airpcap_if_active);
			airpcap_enable_toolbar_widgets(airpcap_tb,FALSE);
			}
		}

  airpcap_set_toolbar_start_capture(airpcap_if_active);
#endif

  cap_if_w = window_new(GTK_WINDOW_TOPLEVEL, "Wireshark: Capture Interfaces");

  tooltips = gtk_tooltips_new();

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(cap_if_w), accel_group);
#endif

  main_sw = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(main_sw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
  gtk_container_add(GTK_CONTAINER(cap_if_w), main_sw);

  main_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(main_sw), main_vb);


  if_tb = gtk_table_new(1,9, FALSE);
  gtk_table_set_row_spacings(GTK_TABLE(if_tb), 3);
  gtk_table_set_col_spacings(GTK_TABLE(if_tb), 3);
  gtk_box_pack_start(GTK_BOX(main_vb), if_tb, FALSE, FALSE, 0);

  row = 0;
  height = 0;

  /* This is the icon column, used to display which kind of interface we have */
  if_lb = gtk_label_new("");
  gtk_table_attach_defaults(GTK_TABLE(if_tb), if_lb, 0, 1, row, row+1);

#ifndef _WIN32
  /*
   * On Windows, device names are generally not meaningful - NT 5
   * uses long blobs with GUIDs in them, for example - so we don't
   * bother showing them.
   */
  if_lb = gtk_label_new("Device");
  gtk_table_attach_defaults(GTK_TABLE(if_tb), if_lb, 1, 2, row, row+1);
#endif

  if_lb = gtk_label_new("Description");
  gtk_table_attach_defaults(GTK_TABLE(if_tb), if_lb, 2, 3, row, row+1);

  if_lb = gtk_label_new(" IP ");
  gtk_table_attach_defaults(GTK_TABLE(if_tb), if_lb, 3, 4, row, row+1);

  if_lb = gtk_label_new("Packets");
  gtk_table_attach_defaults(GTK_TABLE(if_tb), if_lb, 4, 5, row, row+1);

  if_lb = gtk_label_new(" Packets/s ");
  gtk_table_attach_defaults(GTK_TABLE(if_tb), if_lb, 5, 6, row, row+1);

  stop_bt = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_CAPTURE_STOP);
  gtk_tooltips_set_tip(tooltips, stop_bt,
          "Stop a running capture.", NULL);
#ifdef _WIN32
  gtk_table_attach_defaults(GTK_TABLE(if_tb), stop_bt, 6, 9, row, row+1);
#else
  gtk_table_attach_defaults(GTK_TABLE(if_tb), stop_bt, 6, 8, row, row+1);
#endif
  SIGNAL_CONNECT(stop_bt, "clicked", capture_stop_cb, NULL);

  row++;
  gtk_widget_size_request(stop_bt, &requisition);
  height += requisition.height + 15;

  for(ifs = 0; (curr = g_list_nth(if_list, ifs)); ifs++) {
      g_string_assign(if_tool_str, "");
      if_info = curr->data;
      if_dlg_data = g_malloc0(sizeof(if_dlg_data_t));

      /* Kind of adaptor (icon) */
#ifdef HAVE_AIRPCAP
      if(get_airpcap_if_from_description(airpcap_if_list,if_info->description) != NULL)
        icon = xpm_to_widget(capture_airpcap_16_xpm);
      else
        icon = xpm_to_widget(capture_ethernet_16_xpm);
#else
      icon = xpm_to_widget(capture_ethernet_16_xpm);
#endif

      gtk_table_attach_defaults(GTK_TABLE(if_tb), icon, 0, 1, row, row+1);

      /* device name */
      if_dlg_data->device_lb = gtk_label_new(if_info->name);
      if_dlg_data->device = if_info->name;
#ifndef _WIN32
      gtk_misc_set_alignment(GTK_MISC(if_dlg_data->device_lb), 0.0, 0.5);
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->device_lb, 1, 2, row, row+1);
#endif
      g_string_append(if_tool_str, "Device: ");
      g_string_append(if_tool_str, if_info->name);
      g_string_append(if_tool_str, "\n");

      /* description */
      if (if_info->description != NULL)
        if_dlg_data->descr_lb = gtk_label_new(if_info->description);
      else
        if_dlg_data->descr_lb = gtk_label_new("");
      gtk_misc_set_alignment(GTK_MISC(if_dlg_data->descr_lb), 0.0, 0.5);
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->descr_lb, 2, 3, row, row+1);

      if (if_info->description) {
        g_string_append(if_tool_str, "Description: ");
        g_string_append(if_tool_str, if_info->description);
        g_string_append(if_tool_str, "\n");
      }

      /* IP address */
      /* only the first IP address will be shown */
      g_string_append(if_tool_str, "IP: ");
      curr_ip = g_slist_nth(if_info->ip_addr, 0);
      if(curr_ip) {
        ip_addr = (if_addr_t *)curr_ip->data;
        switch (ip_addr->type) {

        case AT_IPv4:
          tmp_str = ip_to_str((guint8 *)&ip_addr->ip_addr.ip4_addr);
          break;

        case AT_IPv6:
          tmp_str = ip6_to_str((struct e_in6_addr *)&ip_addr->ip_addr.ip6_addr);
          break;

        default:
          g_assert_not_reached();
          tmp_str = NULL;
        }
        if_dlg_data->ip_lb = gtk_label_new(tmp_str);
        gtk_widget_set_sensitive(if_dlg_data->ip_lb, TRUE);
        g_string_append(if_tool_str, tmp_str);
      } else {
        if_dlg_data->ip_lb = gtk_label_new("unknown");
        gtk_widget_set_sensitive(if_dlg_data->ip_lb, FALSE);
        g_string_append(if_tool_str, "unknown");
      }
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->ip_lb, 3, 4, row, row+1);
      g_string_append(if_tool_str, "\n");

      /* packets */
      if_dlg_data->curr_lb = gtk_label_new("-");
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->curr_lb, 4, 5, row, row+1);

      /* packets/s */
      if_dlg_data->last_lb = gtk_label_new("-");
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->last_lb, 5, 6, row, row+1);

      /* capture button */
      if_dlg_data->capture_bt = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_CAPTURE_START);
	  SIGNAL_CONNECT(if_dlg_data->capture_bt, "clicked", capture_do_cb, if_dlg_data);
      tmp_str = g_strdup_printf("Immediately start a capture from this interface:\n\n%s", if_tool_str->str);
      gtk_tooltips_set_tip(tooltips, if_dlg_data->capture_bt,
          tmp_str, NULL);
      g_free(tmp_str);
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->capture_bt, 6, 7, row, row+1);

      /* prepare button */
      if_dlg_data->prepare_bt = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_CAPTURE_OPTIONS);
      SIGNAL_CONNECT(if_dlg_data->prepare_bt, "clicked", capture_prepare_cb, if_dlg_data);
      gtk_tooltips_set_tip(tooltips, if_dlg_data->prepare_bt,
          "Open the capture options dialog with this interface selected.", NULL);
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->prepare_bt, 7, 8, row, row+1);

      /* details button */
#ifdef _WIN32
      if_dlg_data->details_bt = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_CAPTURE_DETAILS);
	  SIGNAL_CONNECT(if_dlg_data->details_bt, "clicked", capture_details_cb, if_dlg_data);
      gtk_tooltips_set_tip(tooltips, if_dlg_data->details_bt,
          "Open the capture details dialog of this interface.", NULL);
      gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->details_bt, 8, 9, row, row+1);
#endif

      open_if(if_info->name, if_dlg_data);

      if_data = g_list_append(if_data, if_dlg_data);

      row++;
      if (row <= 10) {
          /* Lets add up 10 rows of interfaces, otherwise the window may become too high */
          gtk_widget_size_request(GTK_WIDGET(if_dlg_data->prepare_bt), &requisition);
          height += requisition.height;
      }
  }

  g_string_free(if_tool_str, TRUE);

  /* Button row: close button */
  if(topic_available(HELP_CAPTURE_INTERFACES_DIALOG)) {
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
  } else {
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
  }
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 5);

  close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
  window_set_cancel_button(cap_if_w, close_bt, window_cancel_button_cb);
  gtk_tooltips_set_tip(tooltips, close_bt, "Close this window.", NULL);

  if(topic_available(HELP_CAPTURE_INTERFACES_DIALOG)) {
    help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
    SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_CAPTURE_INTERFACES_DIALOG);
  }

  gtk_widget_size_request(GTK_WIDGET(close_bt), &requisition);
  /* height + static offset + what GTK-Wimp needs in addition per interface */
  height += requisition.height + 20 + ifs;
  gtk_window_set_default_size(GTK_WINDOW(cap_if_w), -1, height);

  gtk_widget_grab_default(close_bt);

  SIGNAL_CONNECT(cap_if_w, "delete_event", window_delete_event_cb, NULL);
  SIGNAL_CONNECT(cap_if_w, "destroy", capture_if_destroy_cb, NULL);

  gtk_widget_show_all(cap_if_w);
  window_present(cap_if_w);

  set_capture_if_dialog_for_capture_in_progress(is_capture_in_progress());

    /* update the interface list every 1000ms */
  timer_id = gtk_timeout_add(1000, update_all, if_data);
}


#endif /* HAVE_LIBPCAP */
